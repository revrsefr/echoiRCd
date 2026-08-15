//! Channels: the `Channel` record, membership, channel modes, bans, invites and
//! JOIN/NAMES.

use std::collections::{HashMap, HashSet};

use crate::module::Hook;
use crate::modules::chathistory::{HistMsg, History};
use crate::numeric::*;
use crate::server::{iso_time, now, Server};
use crate::Uid;

/// Per-member prefix modes (+q/+a/+o/+h/+v). Flag modes live in [`ChanModes`].
#[derive(Default)]
pub struct Member {
    pub oprefix: bool,            // operprefix/ojoin: server oper prefix (!), highest rank
    pub owner: bool,              // +q (~)
    pub admin: bool,              // +a (&)
    pub op: bool,                 // +o (@)
    pub halfop: bool,             // +h (%)
    pub voice: bool,              // +v (+)
    pub custom_prefixes: Vec<char>, // config-defined prefix mode letters held (customprefix)
    pub joined: u64,              // unix ts this member joined (for +d delaymsg; 0 = unknown)
    pub recent_msgs: Vec<String>, // +K repeat: this member's last few lines here
    pub hidden: bool,             // +D delayjoin: JOIN withheld until they reveal themselves
}

/// Prefix ranks, high→low — gate who may grant a prefix / kick whom. Spaced ×10 so
/// config-defined custom prefixes (modules::customprefix) can slot in between.
pub const RANK_OPER: u8 = 60; // operprefix/ojoin — above channel owner (network staff)
pub const RANK_OWNER: u8 = 50;
pub const RANK_ADMIN: u8 = 40;
pub const RANK_OP: u8 = 30;
pub const RANK_HALFOP: u8 = 20;
pub const RANK_VOICE: u8 = 10;

impl Member {
    /// This member's numeric rank (0 = plain member).
    /// Built-in tier rank from the fixed booleans (0 = none), ignoring custom prefixes.
    fn builtin_rank(&self) -> u8 {
        if self.oprefix {
            RANK_OPER
        } else if self.owner {
            RANK_OWNER
        } else if self.admin {
            RANK_ADMIN
        } else if self.op {
            RANK_OP
        } else if self.halfop {
            RANK_HALFOP
        } else if self.voice {
            RANK_VOICE
        } else {
            0
        }
    }

    pub fn rank(&self) -> u8 {
        let mut r = self.builtin_rank();
        for &c in &self.custom_prefixes {
            if let Some(d) = crate::modules::customprefix::def_for_letter(c) {
                r = r.max(d.rank);
            }
        }
        r
    }

    /// Every (rank, sigil) prefix this member holds, high→low. Only allocates when
    /// custom prefixes are actually present.
    fn held(&self) -> Vec<(u8, &'static str)> {
        use crate::modules::customprefix::{def_for_letter, sigil};
        let mut v: Vec<(u8, &'static str)> = Vec::new();
        for (on, r, i) in [
            (self.oprefix, RANK_OPER, 0),
            (self.owner, RANK_OWNER, 1),
            (self.admin, RANK_ADMIN, 2),
            (self.op, RANK_OP, 3),
            (self.halfop, RANK_HALFOP, 4),
            (self.voice, RANK_VOICE, 5),
        ] {
            if on {
                v.push((r, sigil(i)));
            }
        }
        for &c in &self.custom_prefixes {
            if let Some(d) = def_for_letter(c) {
                v.push((d.rank, d.sigil.as_str()));
            }
        }
        v.sort_by(|a, b| b.0.cmp(&a.0));
        v
    }

    /// Highest prefix char for NAMES (`""` for a plain member). Sigils are
    /// config-overridable via [`crate::modules::customprefix`].
    pub fn prefix_char(&self) -> &'static str {
        use crate::modules::customprefix::sigil;
        if self.custom_prefixes.is_empty() {
            // fast path: built-in tiers only
            if self.oprefix {
                sigil(0)
            } else if self.owner {
                sigil(1)
            } else if self.admin {
                sigil(2)
            } else if self.op {
                sigil(3)
            } else if self.halfop {
                sigil(4)
            } else if self.voice {
                sigil(5)
            } else {
                ""
            }
        } else {
            self.held().first().map(|(_, s)| *s).unwrap_or("")
        }
    }

    /// Set/clear a prefix mode by its letter — built-in booleans or, for a
    /// config-defined letter, the custom-prefix set (used by the S2S mode applier).
    pub fn set_prefix(&mut self, letter: char, on: bool) {
        match letter {
            'y' => self.oprefix = on,
            'q' => self.owner = on,
            'a' => self.admin = on,
            'o' => self.op = on,
            'h' => self.halfop = on,
            'v' => self.voice = on,
            _ => {
                if crate::modules::customprefix::def_for_letter(letter).is_some() {
                    self.custom_prefixes.retain(|&c| c != letter);
                    if on {
                        self.custom_prefixes.push(letter);
                    }
                }
            }
        }
    }

    /// Every prefix char this member holds, high→low (for the `multi-prefix` cap).
    pub fn all_prefixes(&self) -> String {
        use crate::modules::customprefix::sigil;
        if self.custom_prefixes.is_empty() {
            let mut s = String::new();
            for (on, i) in [
                (self.oprefix, 0),
                (self.owner, 1),
                (self.admin, 2),
                (self.op, 3),
                (self.halfop, 4),
                (self.voice, 5),
            ] {
                if on {
                    s.push_str(sigil(i));
                }
            }
            s
        } else {
            self.held().iter().map(|(_, s)| *s).collect()
        }
    }

    /// Every status mode *letter* this member holds (`o`, `v`, custom letters),
    /// high→low. The server-to-server membership burst lists members as
    /// `<letters>,<uuid>`, so this is the letter form of `all_prefixes`.
    pub fn mode_letters(&self) -> String {
        use crate::modules::customprefix::def_for_letter;
        let mut s = String::new();
        for (on, l) in [
            (self.oprefix, 'y'),
            (self.owner, 'q'),
            (self.admin, 'a'),
            (self.op, 'o'),
            (self.halfop, 'h'),
            (self.voice, 'v'),
        ] {
            if on {
                s.push(l);
            }
        }
        for &c in &self.custom_prefixes {
            if def_for_letter(c).is_some() {
                s.push(c);
            }
        }
        s
    }
}

pub struct Topic {
    pub text: String,
    pub setter: String,
    pub ts: u64,
}

/// A +b ban: a `nick!user@host` glob, who set it and when.
pub struct Ban {
    pub mask: String,
    pub setter: String,
    pub ts: u64,
    pub expires: Option<u64>, // TBAN: unix ts to auto-lift at (None = permanent)
}

/// +f message flood: `[*]lines:secs` — kick past `lines` msgs in `secs` (and set
/// a +b ban too when `ban`, from the leading `*`).
#[derive(Clone)]
pub struct MsgFlood {
    pub lines: u32,
    pub secs: u64,
    pub ban: bool,
}

/// A `count:secs` rate, shared by +j (join flood) and +F (nick-change flood).
#[derive(Clone)]
pub struct Rate {
    pub count: u32,
    pub secs: u64,
}

/// Channel modes other than the per-member prefixes.
#[derive(Default)]
pub struct ChanModes {
    pub moderated: bool,             // +m — only +o/+v may speak
    pub topic_ops: bool,             // +t — only ops may set the topic
    pub no_external: bool,           // +n — must be a member to message it
    pub invite_only: bool,           // +i
    pub secret: bool,                // +s
    pub key: Option<String>,         // +k <key>
    pub limit: Option<u32>,          // +l <n>
    pub secure_only: bool,           // +z — only TLS-connected users may join
    pub private: bool,               // +p — private (hidden from WHOIS channel list)
    pub oper_only: bool,             // +O — only IRC operators may join
    pub no_nick: bool,               // +N — members can't change nick while here
    pub no_ctcp: bool,               // +C — block CTCP to the channel
    pub no_notice: bool,             // +T — block NOTICEs to the channel
    pub no_color: bool,              // +c — reject messages with formatting/colour
    pub strip_color: bool,           // +S — strip formatting/colour from messages
    pub reg_only: bool,              // +R — only logged-in (account) users may join
    pub reg_moderated: bool,         // +M — only logged-in users may speak
    pub censor: bool,                // +G — replace configured bad words
    pub auditorium: bool,            // +u — hide non-ops from non-ops
    pub flood: Option<MsgFlood>,     // +f
    pub joinflood: Option<Rate>,     // +j
    pub nickflood: Option<Rate>,     // +F
    pub redirect: Option<String>,    // +L <#target> — when full, send there
    pub history: Option<(u32, u64)>, // +H <lines>:<secs> — replay recent messages to joiners
    pub anticaps: Option<u8>,        // +B <percent> — block messages that are mostly CAPS
    pub nokicks: bool,               // +Q — KICK is disabled on the channel
    pub allowinvite: bool,           // +A — any member (not just ops) may INVITE
    pub permanent: bool,             // +P — channel persists with zero members
    pub kicknorejoin: Option<u32>,   // +J <secs> — block rejoin for N secs after a kick
    pub opmoderated: bool,           // +U — unprivileged users' messages go to ops only
    pub delaymsg: Option<u32>,       // +d <secs> — new joiners can't speak for N secs
    pub repeat: Option<u32>,         // +K <n> — block a line repeated within your last n
    pub delayjoin: bool,             // +D — hide JOINs until the user speaks/reveals
    pub registered: bool,            // +r — set by services on a registered channel
                                     // (server/services-only; not user-settable)
}

impl ChanModes {
    /// Set/clear a no-parameter flag mode by its letter (the S2S mode applier).
    pub fn set_by_letter(&mut self, c: char, on: bool) {
        match c {
            'm' => self.moderated = on,
            'n' => self.no_external = on,
            't' => self.topic_ops = on,
            'i' => self.invite_only = on,
            's' => self.secret = on,
            'z' => self.secure_only = on,
            'p' => self.private = on,
            'O' => self.oper_only = on,
            'N' => self.no_nick = on,
            'C' => self.no_ctcp = on,
            'T' => self.no_notice = on,
            'c' => self.no_color = on,
            'S' => self.strip_color = on,
            'R' => self.reg_only = on,
            'M' => self.reg_moderated = on,
            'G' => self.censor = on,
            'u' => self.auditorium = on,
            'Q' => self.nokicks = on,
            'A' => self.allowinvite = on,
            'P' => self.permanent = on,
            'U' => self.opmoderated = on,
            'D' => self.delayjoin = on,
            'r' => self.registered = on,
            _ => {}
        }
    }

    /// `+mnt`, or with `params` the +k/+l arguments too: `+ntkl secret 20`.
    pub fn render(&self, params: bool) -> String {
        let mut s = String::from("+");
        for (on, ch) in [
            (self.registered, 'r'),
            (self.invite_only, 'i'),
            (self.moderated, 'm'),
            (self.no_external, 'n'),
            (self.secret, 's'),
            (self.topic_ops, 't'),
            (self.secure_only, 'z'),
            (self.private, 'p'),
            (self.oper_only, 'O'),
            (self.no_nick, 'N'),
            (self.no_ctcp, 'C'),
            (self.no_notice, 'T'),
            (self.no_color, 'c'),
            (self.strip_color, 'S'),
            (self.reg_only, 'R'),
            (self.reg_moderated, 'M'),
            (self.censor, 'G'),
            (self.auditorium, 'u'),
            (self.permanent, 'P'),
            (self.nokicks, 'Q'),
            (self.allowinvite, 'A'),
            (self.opmoderated, 'U'),
            (self.delayjoin, 'D'),
        ] {
            if on {
                s.push(ch);
            }
        }
        if self.key.is_some() {
            s.push('k');
        }
        if self.limit.is_some() {
            s.push('l');
        }
        if self.flood.is_some() {
            s.push('f');
        }
        if self.joinflood.is_some() {
            s.push('j');
        }
        if self.nickflood.is_some() {
            s.push('F');
        }
        if self.redirect.is_some() {
            s.push('L');
        }
        if self.history.is_some() {
            s.push('H');
        }
        if self.anticaps.is_some() {
            s.push('B');
        }
        if self.kicknorejoin.is_some() {
            s.push('J');
        }
        if self.delaymsg.is_some() {
            s.push('d');
        }
        if self.repeat.is_some() {
            s.push('K');
        }
        if params {
            if let Some(k) = &self.key {
                s.push(' ');
                s.push_str(k);
            }
            if let Some(l) = self.limit {
                s.push(' ');
                s.push_str(&l.to_string());
            }
            if let Some(f) = &self.flood {
                let star = if f.ban { "*" } else { "" };
                s.push_str(&format!(" {star}{}:{}", f.lines, f.secs));
            }
            if let Some(j) = &self.joinflood {
                s.push_str(&format!(" {}:{}", j.count, j.secs));
            }
            if let Some(n) = &self.nickflood {
                s.push_str(&format!(" {}:{}", n.count, n.secs));
            }
            if let Some(t) = &self.redirect {
                s.push(' ');
                s.push_str(t);
            }
            if let Some((n, t)) = &self.history {
                s.push_str(&format!(" {n}:{t}"));
            }
            if let Some(p) = self.anticaps {
                s.push_str(&format!(" {p}"));
            }
            if let Some(secs) = self.kicknorejoin {
                s.push_str(&format!(" {secs}"));
            }
            if let Some(secs) = self.delaymsg {
                s.push_str(&format!(" {secs}"));
            }
            if let Some(n) = self.repeat {
                s.push_str(&format!(" {n}"));
            }
        }
        s
    }
}

pub struct Channel {
    pub name: String, // display casing
    pub topic: Option<Topic>,
    pub members: HashMap<Uid, Member>,
    pub rmembers: HashMap<String, Member>, // remote members, by network uuid (S2S)
    pub modes: ChanModes,
    pub bans: Vec<Ban>,
    pub excepts: Vec<Ban>,       // +e ban exceptions
    pub invex: Vec<Ban>,         // +I invite exceptions
    pub filters: Vec<Ban>,       // +g word/glob message filters (mask = the glob)
    pub exemptchanops: Vec<Ban>, // +X exemptions (mask = "restriction:rankchar")
    pub autoop: Vec<Ban>,        // +w auto-status (mask = "prefixchar:hostmask")
    pub invites: HashSet<Uid>,   // uids allowed past +i
    pub created: u64,
    // --- ephemeral flood counters (not modes; never rendered or synced) -------
    pub msgflood_hits: HashMap<Uid, Vec<u64>>, // +f per-user message times
    pub joinflood_hits: Vec<u64>,              // +j recent join times
    pub joinflood_until: u64,                  // +j locked out until this unix ts
    pub nickflood_hits: Vec<u64>,              // +F recent nick-change times
    pub nickflood_until: u64,                  // +F locked out until this unix ts
    pub recent_kicks: HashMap<Uid, u64>,       // +J uid -> unix ts of last kick (rejoin delay)
}

impl Channel {
    /// A fresh channel with the default `+nt` modes.
    pub fn new(name: &str) -> Channel {
        Channel {
            name: name.to_string(),
            topic: None,
            members: HashMap::new(),
            rmembers: HashMap::new(),
            modes: ChanModes {
                no_external: true,
                topic_ops: true,
                ..Default::default()
            },
            bans: Vec::new(),
            excepts: Vec::new(),
            invex: Vec::new(),
            filters: Vec::new(),
            exemptchanops: Vec::new(),
            autoop: Vec::new(),
            invites: HashSet::new(),
            created: now(),
            msgflood_hits: HashMap::new(),
            joinflood_hits: Vec::new(),
            joinflood_until: 0,
            nickflood_hits: Vec::new(),
            nickflood_until: 0,
            recent_kicks: HashMap::new(),
        }
    }

    /// True once no local *and* no remote members remain (safe to drop).
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.rmembers.is_empty()
    }

    /// Keep this channel in the table: it has members, or it's +P (permanent).
    pub fn keep_alive(&self) -> bool {
        // A registered (+r) channel persists with zero members, like +P: otherwise a
        // sole user leaving destroys it, and their rejoin recreates it with a new TS —
        // which makes linked services re-assert the +r lock (and re-op) on every visit.
        !self.is_empty() || self.modes.permanent || self.modes.registered
    }
}

impl Server {
    /// A member's channel rank (0 if not a member).
    pub fn rank(&self, uid: Uid, key: &str) -> u8 {
        // SAMODE/SAKICK: mode_sudo makes every rank() check pass, bypassing the ladder.
        if self.mode_sudo {
            return RANK_OWNER;
        }
        self.channels
            .get(key)
            .and_then(|c| c.members.get(&uid))
            .map(|m| m.rank())
            .unwrap_or(0)
    }

    pub fn is_op(&self, uid: Uid, key: &str) -> bool {
        self.rank(uid, key) >= RANK_OP
    }

    pub fn is_member(&self, uid: Uid, key: &str) -> bool {
        self.channels
            .get(key)
            .map(|c| c.members.contains_key(&uid))
            .unwrap_or(false)
    }

    /// +D delayjoin: announce a hidden member's withheld JOIN now (they revealed
    /// themselves by speaking / being opped / changing nick). No-op if not hidden.
    pub fn reveal_member(&mut self, uid: Uid, key: &str) {
        let hidden = self
            .channels
            .get(key)
            .and_then(|c| c.members.get(&uid))
            .map(|m| m.hidden)
            .unwrap_or(false);
        if !hidden {
            return;
        }
        if let Some(m) = self
            .channels
            .get_mut(key)
            .and_then(|c| c.members.get_mut(&uid))
        {
            m.hidden = false;
        }
        let name = self
            .channels
            .get(key)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| key.to_string());
        let aud = self
            .channels
            .get(key)
            .map(|c| c.modes.auditorium)
            .unwrap_or(false);
        let (prefix, acct, realname) = match self.users.get(&uid) {
            Some(u) => (
                u.prefix(),
                u.account.clone().unwrap_or_else(|| "*".to_string()),
                u.realname.clone(),
            ),
            None => return,
        };
        let plain = format!(":{prefix} JOIN {name}");
        let extended = format!(":{prefix} JOIN {name} {acct} :{realname}");
        let members: Vec<Uid> = self
            .channels
            .get(key)
            .map(|c| c.members.keys().copied().collect())
            .unwrap_or_default();
        for m in members {
            if m == uid {
                continue; // they already saw their own JOIN
            }
            if aud && self.rank(m, key) < RANK_OP {
                continue; // +u auditorium still hides them from non-ops
            }
            let ext = self
                .users
                .get(&m)
                .map(|u| u.caps.extended_join)
                .unwrap_or(false);
            self.send(m, if ext { extended.clone() } else { plain.clone() });
        }
    }

    /// +X exemptchanops — is `uid` exempt from `restriction` in this channel? True
    /// when a `+X <restriction>:<rankchar>` entry names a rank they meet or exceed.
    pub fn chanop_exempt(&self, uid: Uid, key: &str, restriction: &str) -> bool {
        let Some(ch) = self.channels.get(key) else {
            return false;
        };
        let rank = self.rank(uid, key);
        ch.exemptchanops.iter().any(|e| {
            let Some((r, prefix)) = e.mask.split_once(':') else {
                return false;
            };
            if !r.eq_ignore_ascii_case(restriction) {
                return false;
            }
            let need = match prefix.chars().next() {
                Some('q') => RANK_OWNER,
                Some('a') => RANK_ADMIN,
                Some('o') => RANK_OP,
                Some('h') => RANK_HALFOP,
                Some('v') => RANK_VOICE,
                _ => return false,
            };
            rank >= need
        })
    }

    /// Lift any expired TBAN timed bans, announcing `MODE -b` to each channel.
    /// Called from the background tick.
    pub fn purge_tbans(&mut self) {
        let now = now();
        let mut expired: Vec<(String, String, String)> = Vec::new(); // (key, name, mask)
        for (key, ch) in &self.channels {
            for b in &ch.bans {
                if b.expires.is_some_and(|e| e <= now) {
                    expired.push((key.clone(), ch.name.clone(), b.mask.clone()));
                }
            }
        }
        for (key, name, mask) in expired {
            if let Some(ch) = self.channels.get_mut(&key) {
                ch.bans.retain(|b| b.mask != mask);
            }
            self.to_channel(&key, &format!(":{} MODE {name} -b {mask}", self.name), None);
        }
    }

    /// Force `uid` out of `chan` (SAPART / SVSPART enforcement): announce the PART
    /// to the channel and to links, drop the membership, reap the channel if empty.
    /// No-op if the user isn't a member.
    pub fn force_part(&mut self, uid: Uid, chan: &str, reason: &str) {
        let key = chan.to_ascii_lowercase();
        if !self.is_member(uid, &key) {
            return;
        }
        let prefix = self.users[&uid].prefix();
        // +D delayjoin: a still-hidden member's PART is shown only to themselves
        let hidden = self
            .channels
            .get(&key)
            .and_then(|c| c.members.get(&uid))
            .map(|m| m.hidden)
            .unwrap_or(false);
        let line = format!(":{prefix} PART {chan} :{reason}");
        if hidden {
            self.send(uid, line);
        } else {
            self.to_channel(&key, &line, None);
        }
        self.propagate_part(uid, chan, reason);
        if let Some(ch) = self.channels.get_mut(&key) {
            ch.members.remove(&uid);
        }
        if let Some(u) = self.users.get_mut(&uid) {
            u.channels.remove(&key);
        }
        self.channels.retain(|_, c| c.keep_alive());
    }

    /// Join a user to a channel (creating it if new, giving the creator +o),
    /// then broadcast JOIN and send TOPIC + NAMES. Queues the join hook.
    pub fn join(&mut self, uid: Uid, name: &str, key_arg: Option<&str>) {
        if !valid_chan(name, self.conf_num("maxchannel", 50usize)) {
            self.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{name} :No such channel"));
            return;
        }
        let key = name.to_ascii_lowercase();
        if self
            .users
            .get(&uid)
            .map(|u| u.channels.contains(&key))
            .unwrap_or(true)
        {
            return; // unknown user, or already joined
        }
        // IRC operators override the join restrictions below; each bypass sets
        // `overrode`, snoticed once the join succeeds.
        let is_oper = self.users.get(&uid).map(|u| u.flags.oper).unwrap_or(false);
        let mut overrode = false;
        // connectclass max-channels cap (opers exempt)
        if !is_oper {
            if let Some(max) = crate::modules::connclass::max_chans(self, uid) {
                if self.users.get(&uid).map(|u| u.channels.len()).unwrap_or(0) >= max {
                    self.numeric(
                        uid,
                        ERR_TOOMANYCHANNELS,
                        &format!("{name} :You have joined too many channels"),
                    );
                    return;
                }
            }
        }
        // CBAN — a forbidden channel name (opers bypass)
        if !is_oper {
            if let Some(reason) = self.matched_cban(&key) {
                self.numeric(
                    uid,
                    ERR_BADCHANNEL,
                    &format!("{name} :Channel is CBAN'd: {reason}"),
                );
                return;
            }
        }
        // denychans — a configured forbidden channel name (opers bypass per badchan)
        if crate::modules::denychans::intercept(self, uid, name, is_oper) {
            return;
        }
        // restrictchans — only opers may create new channels (unless whitelisted)
        if crate::modules::restrictchans::intercept(self, uid, name, is_oper) {
            return;
        }
        // channames — forbidden characters in new channel names
        if crate::modules::channames::intercept(self, uid, name) {
            return;
        }
        // an existing channel can refuse the join (+k / +b / +i / +z / +R / +J)
        if let Some(ch) = self.channels.get(&key) {
            if let Some(k) = &ch.modes.key {
                if key_arg != Some(k.as_str()) {
                    if !is_oper {
                        self.numeric(
                            uid,
                            ERR_BADCHANNELKEY,
                            &format!("{name} :Cannot join channel (+k)"),
                        );
                        return;
                    }
                    overrode = true;
                }
            }
            // +b — bans block even an invited user, unless a +e exception matches
            // (both honour the g: security-group extban)
            if self.ban_list_hit(uid, &ch.bans) && !self.ban_list_hit(uid, &ch.excepts) {
                if !is_oper {
                    // banredirect: `+b mask$#chan` bounces the user into #chan (once)
                    if let Some(t) = crate::modules::banredirect::redirect_target(self, uid, &key) {
                        let tl = t.to_ascii_lowercase();
                        if !self.in_redirect && tl != key && !self.is_member(uid, &tl) {
                            self.numeric(
                                uid,
                                ERR_LINKCHANNEL,
                                &format!("{name} {t} :Cannot join channel (+b), redirecting"),
                            );
                            self.in_redirect = true;
                            self.join(uid, &t, None);
                            self.in_redirect = false;
                            return;
                        }
                    }
                    self.numeric(
                        uid,
                        ERR_BANNEDFROMCHAN,
                        &format!("{name} :Cannot join channel (+b)"),
                    );
                    return;
                }
                overrode = true;
            }
            // +i — unless invited or matched by a +I invite exception
            if ch.modes.invite_only
                && !ch.invites.contains(&uid)
                && !self.ban_list_hit(uid, &ch.invex)
            {
                if !is_oper {
                    self.numeric(
                        uid,
                        ERR_INVITEONLYCHAN,
                        &format!("{name} :Cannot join channel (+i)"),
                    );
                    return;
                }
                overrode = true;
            }
            // +z — TLS-connected users only
            if ch.modes.secure_only && !self.users.get(&uid).map(|u| u.secure).unwrap_or(false) {
                if !is_oper {
                    self.numeric(
                        uid,
                        ERR_SECUREONLYCHAN,
                        &format!("{name} :Cannot join channel; TLS users only (+z is set)"),
                    );
                    return;
                }
                overrode = true;
            }
            // +O — IRC operators only (opers are allowed by definition)
            if ch.modes.oper_only && !is_oper {
                self.numeric(
                    uid,
                    ERR_CANTJOINOPERSONLY,
                    &format!("{name} :Cannot join channel; IRC operators only (+O is set)"),
                );
                return;
            }
            // +R — must be logged into an account (services-registered)
            if ch.modes.reg_only
                && self
                    .users
                    .get(&uid)
                    .map(|u| u.account.is_none())
                    .unwrap_or(true)
            {
                if !is_oper {
                    self.numeric(
                        uid,
                        ERR_NEEDREGGEDNICK,
                        &format!("{name} :Cannot join channel; you must be logged in (+R is set)"),
                    );
                    return;
                }
                overrode = true;
            }
            // +J <secs> — can't rejoin within N seconds of being kicked
            if let Some(secs) = ch.modes.kicknorejoin {
                if let Some(&kt) = ch.recent_kicks.get(&uid) {
                    if now().saturating_sub(kt) < secs as u64 {
                        if !is_oper {
                            self.numeric(
                                uid,
                                ERR_DELAYREJOIN,
                                &format!(
                                    "{name} :You must wait {secs}s after a kick to rejoin (+J)"
                                ),
                            );
                            return;
                        }
                        overrode = true;
                    }
                }
            }
        }
        // +l full — with +L redirect, bounce the user to the target instead (opers override)
        if let Some(ch) = self.channels.get(&key) {
            let full = ch.modes.limit.is_some_and(|l| ch.members.len() as u32 >= l);
            let redirect = ch.modes.redirect.clone();
            if full && is_oper {
                overrode = true;
            } else if full {
                match redirect {
                    Some(t)
                        if !self.in_redirect
                            && t.to_ascii_lowercase() != key
                            && !self.is_member(uid, &t.to_ascii_lowercase()) =>
                    {
                        self.numeric(
                            uid,
                            ERR_LINKCHANNEL,
                            &format!("{name} {t} :Cannot join channel (+l), redirecting"),
                        );
                        self.in_redirect = true;
                        self.join(uid, &t, None);
                        self.in_redirect = false;
                        return;
                    }
                    _ => {
                        self.numeric(
                            uid,
                            ERR_CHANNELISFULL,
                            &format!("{name} :Cannot join channel (+l)"),
                        );
                        return;
                    }
                }
            }
        }
        // +j join flood — once tripped, the channel locks new joins out for 60s (opers exempt)
        if !is_oper && self.channels.contains_key(&key) && self.joinflood_check(&key) {
            self.numeric(
                uid,
                ERR_UNAVAILRESOURCE,
                &format!("{name} :This channel is temporarily unavailable (+j join flood)"),
            );
            return;
        }
        if overrode {
            let nick = self
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            self.snotice(&format!("{nick} used oper override to join {name}"));
        }
        let is_new = !self.channels.contains_key(&key);
        let ch = self
            .channels
            .entry(key.clone())
            .or_insert_with(|| Channel::new(name));
        ch.members.insert(
            uid,
            Member {
                op: is_new,
                joined: now(),
                ..Default::default()
            },
        );
        ch.invites.remove(&uid); // consume any pending invite
        ch.recent_kicks.remove(&uid); // they got back in; clear any +J rejoin timer
        if let Some(u) = self.users.get_mut(&uid) {
            u.channels.insert(key.clone());
        }
        // chancreate: snotice when a brand-new channel comes into being
        if is_new
            && (self.conf_bool("chancreate", false) || self.conf_bool("announce_channels", false))
        {
            let who = self
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            self.snotice(&format!("{who} created channel {name}"));
        }

        // JOIN broadcast — extended-join clients also get the account + realname
        let (prefix, acct, realname) = {
            let u = &self.users[&uid];
            (
                u.prefix(),
                u.account.clone().unwrap_or_else(|| "*".to_string()),
                u.realname.clone(),
            )
        };
        let plain = format!(":{prefix} JOIN {name}");
        let extended = format!(":{prefix} JOIN {name} {acct} :{realname}");
        let aud = self.channels[&key].modes.auditorium;
        // +D delayjoin: withhold the JOIN from everyone else until they speak/reveal
        let delayjoin = self.channels[&key].modes.delayjoin;
        if delayjoin {
            if let Some(m) = self
                .channels
                .get_mut(&key)
                .and_then(|c| c.members.get_mut(&uid))
            {
                m.hidden = true;
            }
        }
        let members: Vec<Uid> = self.channels[&key].members.keys().copied().collect();
        for m in members {
            // +u auditorium: non-op members don't see other users join
            if aud && m != uid && self.rank(m, &key) < RANK_OP {
                continue;
            }
            // +D: only the joining user sees their own JOIN for now
            if delayjoin && m != uid {
                continue;
            }
            let ext = self
                .users
                .get(&m)
                .map(|u| u.caps.extended_join)
                .unwrap_or(false);
            self.send(m, if ext { extended.clone() } else { plain.clone() });
        }
        if let Some(t) = self.channels[&key].topic.as_ref() {
            let text = t.text.clone();
            self.numeric(uid, RPL_TOPIC, &format!("{name} :{text}"));
        }
        self.send_names(uid, &key);
        self.replay_chanhistory(uid, &key); // +H: replay recent messages to the joiner
        self.propagate_join(uid, name, is_new); // tell linked servers this user joined
        self.events.push_back(Hook::Join(uid, key));
    }

    /// +H chanhistory: replay a channel's recent messages to a user who just
    /// joined — the last `<lines>` (within `<secs>`, 0 = no limit) from the store,
    /// wrapped in a `chathistory` batch for batch-capable clients.
    fn replay_chanhistory(&mut self, uid: Uid, key: &str) {
        let Some((lines, secs)) = self.channels.get(key).and_then(|c| c.modes.history) else {
            return;
        };
        let Some(name) = self.channels.get(key).map(|c| c.name.clone()) else {
            return;
        };
        let batch = self.users.get(&uid).map(|u| u.caps.batch).unwrap_or(false);
        let cutoff = if secs > 0 {
            now().saturating_sub(secs)
        } else {
            0
        };
        let bref = if batch {
            Some(self.next_msgid().replace('-', ""))
        } else {
            None
        };
        let out: Vec<String> = match self.ext.get::<History>().and_then(|h| h.0.get(key)) {
            Some(buf) => {
                let mut recent: Vec<&HistMsg> = buf.iter().filter(|m| m.ts >= cutoff).collect();
                let start = recent.len().saturating_sub(lines as usize);
                recent.drain(..start);
                recent
                    .iter()
                    .map(|m| {
                        let mut tags = format!("time={};msgid={}", iso_time(m.ts), m.msgid);
                        if let Some(b) = &bref {
                            tags.push_str(&format!(";batch={b}"));
                        }
                        format!("@{tags} :{} {} {name} :{}", m.prefix, m.verb, m.text)
                    })
                    .collect()
            }
            None => return,
        };
        if out.is_empty() {
            return;
        }
        if let Some(b) = &bref {
            self.send(uid, format!(":{} BATCH +{b} chathistory {name}", self.name));
        }
        for l in out {
            self.send(uid, l);
        }
        if let Some(b) = &bref {
            self.send(uid, format!(":{} BATCH -{b}", self.name));
        }
    }

    pub fn send_names(&self, uid: Uid, key: &str) {
        let Some(ch) = self.channels.get(key) else {
            self.numeric(uid, RPL_ENDOFNAMES, &format!("{key} :End of /NAMES list"));
            return;
        };
        // +s (secret) / +p (private): members are hidden from non-members. Reply as
        // if the channel were empty (opers still see it).
        if (ch.modes.secret || ch.modes.private)
            && !ch.members.contains_key(&uid)
            && !self.is_oper(uid)
        {
            self.numeric(
                uid,
                RPL_ENDOFNAMES,
                &format!("{} :End of /NAMES list", ch.name),
            );
            return;
        }
        // multi-prefix → all prefixes; userhost-in-names → full nick!user@host
        let (multi, uhost) = self
            .users
            .get(&uid)
            .map(|u| (u.caps.multi_prefix, u.caps.userhost_in_names))
            .unwrap_or((false, false));
        // +u auditorium: a non-op viewer only sees ops (plus themselves)
        let hide =
            ch.modes.auditorium && ch.members.get(&uid).map(|m| m.rank()).unwrap_or(0) < RANK_OP;
        let mut names = String::new();
        for (m, flags) in &ch.members {
            if hide && *m != uid && flags.rank() < RANK_OP {
                continue;
            }
            // +D delayjoin: a still-hidden member isn't shown to anyone but themselves
            if flags.hidden && *m != uid {
                continue;
            }
            let p = if multi {
                flags.all_prefixes()
            } else {
                flags.prefix_char().to_string()
            };
            if let Some(u) = self.users.get(m) {
                names.push_str(&p);
                let shown = if uhost { u.prefix() } else { u.nick.clone() };
                names.push_str(&shown);
                names.push(' ');
            }
        }
        // remote members (users on linked servers)
        for (ruuid, mem) in &ch.rmembers {
            if hide && mem.rank() < RANK_OP {
                continue;
            }
            if let Some(ru) = self.remote_users.get(ruuid) {
                let p = if multi {
                    mem.all_prefixes()
                } else {
                    mem.prefix_char().to_string()
                };
                names.push_str(&p);
                let shown = if uhost { ru.prefix() } else { ru.nick.clone() };
                names.push_str(&shown);
                names.push(' ');
            }
        }
        self.numeric(
            uid,
            RPL_NAMREPLY,
            &format!("= {} :{}", ch.name, names.trim_end()),
        );
        self.numeric(
            uid,
            RPL_ENDOFNAMES,
            &format!("{} :End of /NAMES list", ch.name),
        );
    }

    /// Whether any entry in `list` catches `uid`: a plain `nick!user@host` glob, or
    /// a matching extban (`g:` group, `y:` reputation, `r:` realname, `j:` channel,
    /// `s:` server, `G:` geoip, `b:` banlist). Acting extbans (`m:`/`c:`/`n:`) never
    /// match here — they restrict actions, not join/ban membership.
    pub fn ban_list_hit(&self, uid: Uid, list: &[Ban]) -> bool {
        let who = self.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
        list.iter().any(|b| {
            if b.mask.as_bytes().get(1) == Some(&b':') {
                match b.mask.as_bytes().first() {
                    Some(b'g') => crate::modules::securitygroups::in_group(self, uid, &b.mask[2..]),
                    Some(b'y') => {
                        crate::modules::reputation::score_ban_match(self, uid, &b.mask[2..])
                    }
                    Some(b'r') => crate::modules::realnameban::matches(self, uid, &b.mask[2..]),
                    Some(b'j') => crate::modules::channelban::matches(self, uid, &b.mask[2..]),
                    Some(b's') => crate::modules::serverban::matches(self, uid, &b.mask[2..]),
                    Some(b'G') => crate::modules::geoip::geoban_match(self, uid, &b.mask[2..]),
                    Some(b'b') => crate::modules::extbanbanlist::matches(self, uid, &b.mask[2..]),
                    _ => false,
                }
            } else {
                // strip any `$#chan` banredirect suffix before matching the mask
                glob_match(crate::modules::banredirect::mask_part(&b.mask), &who)
            }
        })
    }

    pub fn extban_active(&self, uid: Uid, key: &str, kind: char) -> bool {
        let Some(ch) = self.channels.get(key) else {
            return false;
        };
        let Some(who) = self.users.get(&uid).map(|u| u.prefix()) else {
            return false;
        };
        let pfx = format!("{kind}:");
        let hit = |list: &Vec<Ban>| {
            list.iter()
                .filter(|b| b.mask.starts_with(&pfx))
                .any(|b| glob_match(&b.mask[2..], &who))
        };
        hit(&ch.bans) && !hit(&ch.excepts)
    }

    /// Broadcast a membership line, honouring +u auditorium: when set, non-op
    /// members other than `actor` don't see it. `actor` always receives it.
    pub fn to_channel_vis(&self, key: &str, line: &str, actor: Uid) {
        if let Some(ch) = self.channels.get(key) {
            let aud = ch.modes.auditorium;
            for (&uid, m) in &ch.members {
                if aud && uid != actor && m.rank() < RANK_OP {
                    continue;
                }
                self.send(uid, line.to_string());
            }
        }
    }

    /// +f: record a channel message from `uid`; `Some(ban)` when they just went
    /// over the limit (ban ⇒ also set a +b). Members at half-op+ and opers are
    /// exempt (checked by the caller).
    pub fn messageflood_hit(&mut self, uid: Uid, key: &str) -> Option<bool> {
        let n = now();
        let ch = self.channels.get_mut(key)?;
        let f = ch.modes.flood.clone()?;
        let v = ch.msgflood_hits.entry(uid).or_default();
        v.retain(|&t| n.saturating_sub(t) < f.secs);
        v.push(n);
        if v.len() as u32 > f.lines {
            ch.msgflood_hits.remove(&uid);
            Some(f.ban)
        } else {
            None
        }
    }

    /// Kick `uid` from `key` for flooding (optionally banning `*!*@host` first),
    /// broadcasting the KICK and queuing the part hook.
    pub fn flood_kick(&mut self, uid: Uid, key: &str, ban: bool) {
        let (nick, host) = match self.users.get(&uid) {
            Some(u) => (u.nick.clone(), u.host_display().to_string()),
            None => return,
        };
        let cname = self
            .channels
            .get(key)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| key.to_string());
        if ban {
            let mask = format!("*!*@{host}");
            if let Some(c) = self.channels.get_mut(key) {
                if !c.bans.iter().any(|b| b.mask == mask) {
                    c.bans.push(Ban {
                        mask,
                        setter: self.name.clone(),
                        ts: now(),
                        expires: None,
                    });
                }
            }
        }
        self.to_channel(
            key,
            &format!(":{} KICK {cname} {nick} :Flood", self.name),
            None,
        );
        self.propagate_kick(uid, &cname, &nick, "Flood");
        if let Some(c) = self.channels.get_mut(key) {
            c.members.remove(&uid);
        }
        if let Some(u) = self.users.get_mut(&uid) {
            u.channels.remove(key);
        }
        self.channels.retain(|_, c| c.keep_alive());
        self.events
            .push_back(Hook::Part(uid, key.to_string(), "flood".to_string()));
    }

    /// +j: record a join attempt on `key`; true if joins are (now) locked out.
    pub fn joinflood_check(&mut self, key: &str) -> bool {
        let n = now();
        let Some(ch) = self.channels.get_mut(key) else {
            return false;
        };
        let Some(f) = ch.modes.joinflood.clone() else {
            return false;
        };
        if n < ch.joinflood_until {
            return true; // still locked out
        }
        ch.joinflood_hits.retain(|&t| n.saturating_sub(t) < f.secs);
        ch.joinflood_hits.push(n);
        if ch.joinflood_hits.len() as u32 > f.count {
            ch.joinflood_until = n + 60; // lock the channel for 60s
            ch.joinflood_hits.clear();
            return true;
        }
        false
    }

    /// +F: record a nick change and return the display name of any channel that
    /// is (now) locked out — the caller denies the change if so. Opers exempt.
    pub fn nickflood_blocked(&mut self, uid: Uid) -> Option<String> {
        let n = now();
        let keys: Vec<String> = self
            .users
            .get(&uid)
            .map(|u| u.channels.iter().cloned().collect())
            .unwrap_or_default();
        let mut blocked = None;
        for key in keys {
            let Some(ch) = self.channels.get_mut(&key) else {
                continue;
            };
            let Some(f) = ch.modes.nickflood.clone() else {
                continue;
            };
            if n < ch.nickflood_until {
                blocked.get_or_insert_with(|| ch.name.clone());
                continue;
            }
            ch.nickflood_hits.retain(|&t| n.saturating_sub(t) < f.secs);
            ch.nickflood_hits.push(n);
            if ch.nickflood_hits.len() as u32 > f.count {
                ch.nickflood_until = n + 60;
                ch.nickflood_hits.clear();
                blocked.get_or_insert_with(|| ch.name.clone());
            }
        }
        blocked
    }
}

/// A channel name starts with `#`, is ≤ 50 chars, and has no space/comma/control.
pub fn valid_chan(name: &str, maxlen: usize) -> bool {
    name.starts_with('#')
        && name.len() > 1
        && name.len() <= maxlen
        && !name
            .chars()
            .any(|c| c == ' ' || c == ',' || (c as u32) < 0x20)
}

/// Case-insensitive glob (`*` = any run, `?` = one char) — for +b mask matching.
pub fn glob_match(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let t: Vec<char> = s.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Fill out a ban mask to `nick!user@host` form (`bob` → `bob!*@*`).
pub fn normalize_mask(m: &str) -> String {
    match (m.contains('!'), m.contains('@')) {
        (true, true) => m.to_string(),
        (false, true) => format!("*!{m}"),
        (true, false) => format!("{m}@*"),
        (false, false) => format!("{m}!*@*"),
    }
}

/// Like [`normalize_mask`] but aware of extbans: `m:bob` normalises only the
/// value after the `X:` prefix, so acting bans (`m:` mute, `c:` nocolor,
/// `n:` nonick) keep their type while their hostmask is filled out.
pub fn normalize_ban_mask(m: &str) -> String {
    let b = m.as_bytes();
    if b.len() >= 2 && b[1] == b':' && (b[0] as char).is_ascii_alphabetic() {
        // These extbans carry a name / spec / channel / server, not a host mask,
        // so they must not be host-normalised: g: (security group), y: (reputation
        // score), r: (realname), j: (channel), s: (server name).
        if matches!(b[0], b'g' | b'y' | b'r' | b'j' | b's' | b'G' | b'b') {
            return m.to_string();
        }
        return format!("{}:{}", &m[..1], normalize_mask(&m[2..]));
    }
    normalize_mask(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_rank_and_prefix_char_take_the_highest() {
        let mut m = Member::default();
        assert_eq!(m.rank(), 0);
        assert_eq!(m.prefix_char(), "");
        m.voice = true;
        assert_eq!((m.rank(), m.prefix_char()), (RANK_VOICE, "+"));
        m.halfop = true;
        assert_eq!((m.rank(), m.prefix_char()), (RANK_HALFOP, "%"));
        m.op = true;
        assert_eq!((m.rank(), m.prefix_char()), (RANK_OP, "@"));
        m.admin = true;
        assert_eq!((m.rank(), m.prefix_char()), (RANK_ADMIN, "&"));
        m.owner = true;
        assert_eq!((m.rank(), m.prefix_char()), (RANK_OWNER, "~"));
    }
}
