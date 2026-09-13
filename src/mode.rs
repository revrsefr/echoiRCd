//! Mode handlers.
//!
//! Channel modes implement [`ChanMode`] and user modes implement [`UserMode`];
//! the MODE command parses the modestring and dispatches to the handler for each
//! letter, so adding a mode is a new handler + one line in a table — never an
//! edit to the parser. The handler set is an ordinary slice of zero-sized
//! `&'static` values: no fixed cap, no per-mode allocation, no mutable registry.

use std::sync::OnceLock;

use crate::channels::{
    normalize_ban_mask, Ban, ChanModes, Channel, MsgFlood, Rate, RANK_ADMIN, RANK_HALFOP, RANK_OP,
    RANK_OWNER, RANK_VOICE,
};
use crate::numeric::*;
use crate::server::{now, Server};
use crate::users::UserFlags;
use crate::Uid;

/// Outcome of applying one mode letter.
pub enum Applied {
    /// Nothing to echo (a no-op, a rejected change, or a list query).
    No,
    /// Echo this change back to the channel; `Some(param)` appends a parameter.
    Yes(Option<String>),
}

pub trait ChanMode: Sync {
    fn letter(&self) -> char;
    /// Whether to consume an argument for this sign (taken only if one remains).
    fn wants_param(&self, adding: bool) -> bool;
    /// A list mode (+b/+e/+I/+g/+X/+w): a query with no argument is just viewing,
    /// so it needn't require channel-operator rank (unlike setting an entry).
    fn is_list(&self) -> bool {
        false
    }
    /// Apply `+`/`-` to channel `key` (display name `chan`) on behalf of `uid`.
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied;
}

/// Dynamic handlers for config-defined custom prefix modes (see modules::customprefix).
static CUSTOM_PREFIX_HANDLERS: OnceLock<Vec<Prefix>> = OnceLock::new();

/// Build the custom-prefix handlers once, at boot, after `customprefix::init`.
pub fn init_custom_prefixes() {
    let v: Vec<Prefix> = crate::modules::customprefix::custom_defs()
        .iter()
        .map(|d| Prefix {
            ch: d.letter,
            rank: d.rank,
        })
        .collect();
    let _ = CUSTOM_PREFIX_HANDLERS.set(v);
}

/// Look up the handler for a channel-mode letter (built-in, then custom prefixes).
pub fn chan_mode(c: char) -> Option<&'static (dyn ChanMode + Sync)> {
    if let Some(m) = CHAN_MODES.iter().copied().find(|m| m.letter() == c) {
        return Some(m);
    }
    CUSTOM_PREFIX_HANDLERS
        .get()?
        .iter()
        .find(|p| p.ch == c)
        .map(|p| p as &(dyn ChanMode + Sync))
}

/// The registered channel modes. Add a mode by adding its handler here.
static CHAN_MODES: &[&(dyn ChanMode + Sync)] = &[
    &OWNER,
    &ADMIN,
    &OP,
    &HALFOP,
    &VOICE,
    &BAN,
    &EXCEPT,
    &INVEX,
    &KEY,
    &LIMIT,
    &REGISTERED_CHAN,
    &MODERATED,
    &NOEXTERNAL,
    &TOPICLOCK,
    &INVITEONLY,
    &SECRET,
    &SECUREONLY,
    &PRIVATE,
    &OPERONLY,
    &NONICK,
    &NOCTCP,
    &NONOTICE,
    &NOCOLOR,
    &STRIPCOLOR,
    &REGONLY,
    &REGMODERATED,
    &CENSOR,
    &AUDITORIUM,
    &ENCRYPTED,
    &FILTER,
    &MSGFLOOD,
    &JOINFLOOD,
    &NICKFLOOD,
    &REDIRECT,
    &CHANHISTORY,
    &ANTICAPS,
    &NOKICKS,
    &ALLOWINVITE,
    &PERMANENT,
    &KICKNOREJOIN,
    &OPMODERATED,
    &DELAYMSG,
    &REPEAT,
    &EXEMPTCHANOPS,
    &AUTOOP,
    &DELAYJOIN,
];

// --- prefix modes (+q/+a/+o/+h/+v): a per-member rank, needs a nick ----------

struct Prefix {
    ch: char,
    rank: u8, // the rank this prefix grants
}
static OWNER: Prefix = Prefix {
    ch: 'q',
    rank: RANK_OWNER,
};
static ADMIN: Prefix = Prefix {
    ch: 'a',
    rank: RANK_ADMIN,
};
static OP: Prefix = Prefix {
    ch: 'o',
    rank: RANK_OP,
};
static HALFOP: Prefix = Prefix {
    ch: 'h',
    rank: RANK_HALFOP,
};
static VOICE: Prefix = Prefix {
    ch: 'v',
    rank: RANK_VOICE,
};

impl ChanMode for Prefix {
    fn letter(&self) -> char {
        self.ch
    }
    fn wants_param(&self, _adding: bool) -> bool {
        true
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        let Some(pn) = param else {
            return Applied::No;
        };
        let Some(tuid) = s.find_nick(pn) else {
            s.numeric(uid, ERR_NOSUCHNICK, &format!("{pn} :No such nick/channel"));
            return Applied::No;
        };
        let target_rank = match s.channels.get(key).and_then(|c| c.members.get(&tuid)) {
            Some(m) => m.rank(),
            None => {
                s.numeric(
                    uid,
                    ERR_USERNOTINCHANNEL,
                    &format!("{pn} {chan} :They aren't on that channel"),
                );
                return Applied::No;
            }
        };
        // customprefix depriv=no: a member may not remove this prefix from themselves
        if !adding && tuid == uid && !crate::modules::customprefix::can_depriv(self.ch) {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You may not remove +{} from yourself", self.ch),
            );
            return Applied::No;
        }
        // must out-rank (or match) both the rank needed to set/unset this prefix
        // (customprefix ranktoset/ranktounset, default the prefix's own rank) and the
        // target's current top rank — no de-opping someone above you.
        let needed = if adding {
            crate::modules::customprefix::rank_to_set(self.ch).unwrap_or(self.rank)
        } else {
            crate::modules::customprefix::rank_to_unset(self.ch).unwrap_or(self.rank)
        };
        let src = s.rank(uid, key);
        if src < needed || src < target_rank {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You lack the channel rank to set +{}", self.ch),
            );
            return Applied::No;
        }
        if let Some(m) = s
            .channels
            .get_mut(key)
            .and_then(|c| c.members.get_mut(&tuid))
        {
            m.set_prefix(self.ch, adding); // routes built-in booleans + custom prefixes
        }
        // +D delayjoin: gaining a prefix reveals a hidden member
        if adding {
            s.reveal_member(tuid, key);
        }
        Applied::Yes(Some(pn.to_string()))
    }
}

// --- simple flag modes (+m +n +t +i +s): one bool, no param -----------------

struct Flag {
    ch: char,
    set: fn(&mut ChanModes, bool),
}
fn set_moderated(m: &mut ChanModes, v: bool) {
    m.moderated = v;
}
fn set_noexternal(m: &mut ChanModes, v: bool) {
    m.no_external = v;
}
fn set_topiclock(m: &mut ChanModes, v: bool) {
    m.topic_ops = v;
}
fn set_inviteonly(m: &mut ChanModes, v: bool) {
    m.invite_only = v;
}
fn set_secret(m: &mut ChanModes, v: bool) {
    m.secret = v;
}
static MODERATED: Flag = Flag {
    ch: 'm',
    set: set_moderated,
};
static NOEXTERNAL: Flag = Flag {
    ch: 'n',
    set: set_noexternal,
};
static TOPICLOCK: Flag = Flag {
    ch: 't',
    set: set_topiclock,
};
static INVITEONLY: Flag = Flag {
    ch: 'i',
    set: set_inviteonly,
};
static SECRET: Flag = Flag {
    ch: 's',
    set: set_secret,
};
fn set_private(m: &mut ChanModes, v: bool) {
    m.private = v;
}
fn set_operonly(m: &mut ChanModes, v: bool) {
    m.oper_only = v;
}
fn set_nonick(m: &mut ChanModes, v: bool) {
    m.no_nick = v;
}
fn set_noctcp(m: &mut ChanModes, v: bool) {
    m.no_ctcp = v;
}
fn set_nonotice(m: &mut ChanModes, v: bool) {
    m.no_notice = v;
}
fn set_nocolor(m: &mut ChanModes, v: bool) {
    m.no_color = v;
}
fn set_stripcolor(m: &mut ChanModes, v: bool) {
    m.strip_color = v;
}
static PRIVATE: Flag = Flag {
    ch: 'p',
    set: set_private,
};
static OPERONLY: OperFlagChan = OperFlagChan {
    ch: 'O',
    set: set_operonly,
};
static NONICK: Flag = Flag {
    ch: 'N',
    set: set_nonick,
};
static NOCTCP: Flag = Flag {
    ch: 'C',
    set: set_noctcp,
};
static NONOTICE: Flag = Flag {
    ch: 'T',
    set: set_nonotice,
};
static NOCOLOR: Flag = Flag {
    ch: 'c',
    set: set_nocolor,
};
static STRIPCOLOR: Flag = Flag {
    ch: 'S',
    set: set_stripcolor,
};
fn set_regonly(m: &mut ChanModes, v: bool) {
    m.reg_only = v;
}
fn set_regmoderated(m: &mut ChanModes, v: bool) {
    m.reg_moderated = v;
}
static REGONLY: Flag = Flag {
    ch: 'R',
    set: set_regonly,
};
static REGMODERATED: Flag = Flag {
    ch: 'M',
    set: set_regmoderated,
};
fn set_censor(m: &mut ChanModes, v: bool) {
    m.censor = v;
}
fn set_auditorium(m: &mut ChanModes, v: bool) {
    m.auditorium = v;
}
static CENSOR: Flag = Flag {
    ch: 'G',
    set: set_censor,
};
static AUDITORIUM: Flag = Flag {
    ch: 'u',
    set: set_auditorium,
};
fn set_encrypted(m: &mut ChanModes, v: bool) {
    m.encrypted = v;
}
static ENCRYPTED: Flag = Flag {
    ch: 'E',
    set: set_encrypted,
};
fn set_nokicks(m: &mut ChanModes, v: bool) {
    m.nokicks = v;
}
fn set_allowinvite(m: &mut ChanModes, v: bool) {
    m.allowinvite = v;
}
fn set_permanent(m: &mut ChanModes, v: bool) {
    m.permanent = v;
}
fn set_opmoderated(m: &mut ChanModes, v: bool) {
    m.opmoderated = v;
}
fn set_delayjoin(m: &mut ChanModes, v: bool) {
    m.delayjoin = v;
}
static NOKICKS: Flag = Flag {
    ch: 'Q',
    set: set_nokicks,
};
static ALLOWINVITE: Flag = Flag {
    ch: 'A',
    set: set_allowinvite,
};
static PERMANENT: OperFlagChan = OperFlagChan {
    ch: 'P',
    set: set_permanent,
};
static OPMODERATED: Flag = Flag {
    ch: 'U',
    set: set_opmoderated,
};
static DELAYJOIN: Flag = Flag {
    ch: 'D',
    set: set_delayjoin,
};

impl ChanMode for Flag {
    fn letter(&self) -> char {
        self.ch
    }
    fn wants_param(&self, _adding: bool) -> bool {
        false
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        _param: Option<&str>,
    ) -> Applied {
        if let Some(c) = s.channels.get_mut(key) {
            (self.set)(&mut c.modes, adding);
        }
        Applied::Yes(None)
    }
}

/// A channel flag only an IRC operator may **set** — for modes that reach past a
/// single channel (a network resource, or a staff-only policy) where chan-op rank
/// isn't enough. Anyone with the usual rank may clear it. Server / services authority
/// (`mode_sudo`, used by SAMODE and the RPC/S2S appliers) bypasses the oper check.
struct OperFlagChan {
    ch: char,
    set: fn(&mut ChanModes, bool),
}
impl ChanMode for OperFlagChan {
    fn letter(&self) -> char {
        self.ch
    }
    fn wants_param(&self, _adding: bool) -> bool {
        false
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        _param: Option<&str>,
    ) -> Applied {
        if adding && !s.mode_sudo && !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                &format!(
                    "{chan} :Only IRC operators may set channel mode +{}",
                    self.ch
                ),
            );
            return Applied::No;
        }
        // per-oper-type chanmode allowlist (services under sudo pass through)
        if adding && !s.mode_sudo && !crate::modules::opertypes::can_use_mode(s, uid, self.ch, true)
        {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                &format!(
                    "{chan} :Your oper type may not set channel mode +{}",
                    self.ch
                ),
            );
            return Applied::No;
        }
        if let Some(c) = s.channels.get_mut(key) {
            (self.set)(&mut c.modes, adding);
        }
        Applied::Yes(None)
    }
}

// --- +r registered (services-only) ------------------------------------------

/// `+r` — a registered channel. Set only by services (under `mode_sudo`, e.g. a
/// ChanServ FMODE); a client that tries it gets a clean "services-only" rejection
/// instead of "unknown mode char".
struct RegisteredChan;
static REGISTERED_CHAN: RegisteredChan = RegisteredChan;
impl ChanMode for RegisteredChan {
    fn letter(&self) -> char {
        'r'
    }
    fn wants_param(&self, _adding: bool) -> bool {
        false
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        _param: Option<&str>,
    ) -> Applied {
        if !s.mode_sudo {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                &format!("{chan} :Channel mode +r may only be set by services"),
            );
            return Applied::No;
        }
        if let Some(c) = s.channels.get_mut(key) {
            c.modes.registered = adding;
        }
        Applied::Yes(None)
    }
}

// --- +k channel key ---------------------------------------------------------

struct Key;
static KEY: Key = Key;
impl ChanMode for Key {
    fn letter(&self) -> char {
        'k'
    }
    fn wants_param(&self, _adding: bool) -> bool {
        true // take the key on set; consume (and ignore) it on unset
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            // a key is one non-empty token: reject space/comma/':'/empty, else the
            // MODE/FMODE wire line splits and peers parse only the first word.
            let Some(k) = param.filter(|k| !k.is_empty() && !k.contains([' ', ',', ':'])) else {
                return Applied::No;
            };
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.key = Some(k.to_string());
            }
            Applied::Yes(Some(k.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.key = None;
            }
            Applied::Yes(Some("*".to_string()))
        }
    }
}

// --- +l user limit ----------------------------------------------------------

struct Limit;
static LIMIT: Limit = Limit;
impl ChanMode for Limit {
    fn letter(&self) -> char {
        'l'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding // +l takes a number; -l takes nothing
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            // reject +l 0 and non-numeric: a zero limit would seal the channel.
            let Some(n) = param.and_then(|p| p.parse::<u32>().ok()).filter(|&n| n > 0) else {
                return Applied::No;
            };
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.limit = Some(n);
            }
            Applied::Yes(Some(n.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.limit = None;
            }
            Applied::Yes(None)
        }
    }
}

// --- +H chanhistory: replay recent messages to joiners ----------------------

struct ChanHistory;
static CHANHISTORY: ChanHistory = ChanHistory;
impl ChanMode for ChanHistory {
    fn letter(&self) -> char {
        'H'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding // +H <lines>[:<secs>]; -H takes nothing
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(p) = param else {
                return Applied::No;
            };
            let (lines_s, secs_s) = p.split_once(':').unwrap_or((p, "0"));
            let Some(lines) = lines_s.parse::<u32>().ok().filter(|&n| n > 0) else {
                return Applied::No;
            };
            let lines = lines.min(crate::modules::chathistory::HISTORY_CAP as u32);
            let secs = secs_s.parse::<u64>().unwrap_or(0);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.history = Some((lines, secs));
            }
            Applied::Yes(Some(format!("{lines}:{secs}")))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.history = None;
            }
            Applied::Yes(None)
        }
    }
}

// --- list modes (+b bans, +e ban exceptions, +I invite exceptions) ----------

#[derive(Clone, Copy)]
enum ListKind {
    Ban,
    Except,
    Invex,
    Filter,        // +g — message word/glob filters (not host masks)
    ExemptChanOps, // +X — "restriction:rankchar" exemptions
    AutoOp,        // +w — "prefixchar:hostmask" auto-status on join
}
impl ListKind {
    fn list<'a>(&self, c: &'a Channel) -> &'a Vec<Ban> {
        match self {
            ListKind::Ban => &c.bans,
            ListKind::Except => &c.excepts,
            ListKind::Invex => &c.invex,
            ListKind::Filter => &c.filters,
            ListKind::ExemptChanOps => &c.exemptchanops,
            ListKind::AutoOp => &c.autoop,
        }
    }
    fn list_mut<'a>(&self, c: &'a mut Channel) -> &'a mut Vec<Ban> {
        match self {
            ListKind::Ban => &mut c.bans,
            ListKind::Except => &mut c.excepts,
            ListKind::Invex => &mut c.invex,
            ListKind::Filter => &mut c.filters,
            ListKind::ExemptChanOps => &mut c.exemptchanops,
            ListKind::AutoOp => &mut c.autoop,
        }
    }
    /// (per-entry numeric, end-of-list numeric, name for the "End of …" line)
    fn numerics(&self) -> (u16, u16, &'static str) {
        match self {
            ListKind::Ban => (RPL_BANLIST, RPL_ENDOFBANLIST, "ban list"),
            ListKind::Except => (RPL_EXCEPTLIST, RPL_ENDOFEXCEPTLIST, "exception list"),
            ListKind::Invex => (RPL_INVEXLIST, RPL_ENDOFINVEXLIST, "invite list"),
            ListKind::Filter => (RPL_SPAMFILTER, RPL_ENDOFSPAMFILTER, "spamfilter list"),
            ListKind::ExemptChanOps => (
                RPL_EXEMPTIONLIST,
                RPL_ENDOFEXEMPTIONLIST,
                "exemptchanops list",
            ),
            ListKind::AutoOp => (RPL_AUTOOPLIST, RPL_ENDOFAUTOOP, "autoop list"),
        }
    }
    /// Ban-style lists hold host masks and get filled out to `nick!user@host`;
    /// the +g filter and +X lists hold literal strings and are stored verbatim.
    fn normalizes(&self) -> bool {
        matches!(self, ListKind::Ban | ListKind::Except | ListKind::Invex)
    }
}

struct ListMode {
    ch: char,
    kind: ListKind,
}
static BAN: ListMode = ListMode {
    ch: 'b',
    kind: ListKind::Ban,
};
static EXCEPT: ListMode = ListMode {
    ch: 'e',
    kind: ListKind::Except,
};
static INVEX: ListMode = ListMode {
    ch: 'I',
    kind: ListKind::Invex,
};
static FILTER: ListMode = ListMode {
    ch: 'g',
    kind: ListKind::Filter,
};
static EXEMPTCHANOPS: ListMode = ListMode {
    ch: 'X',
    kind: ListKind::ExemptChanOps,
};
static AUTOOP: ListMode = ListMode {
    ch: 'w',
    kind: ListKind::AutoOp,
};

impl ChanMode for ListMode {
    fn letter(&self) -> char {
        self.ch
    }
    fn is_list(&self) -> bool {
        true
    }
    fn wants_param(&self, _adding: bool) -> bool {
        true // a mask to add/remove; absent ⇒ list query
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        let (entry_num, end_num, noun) = self.kind.numerics();
        // no mask ⇒ list query
        let Some(mask) = param else {
            // hidelist: low-rank members may be barred from viewing this list
            if crate::modules::hidelist::denied(s, uid, key, self.ch) {
                s.numeric(
                    uid,
                    ERR_CHANOPRIVSNEEDED,
                    &format!("{chan} :You do not have access to view the {noun}"),
                );
                return Applied::No;
            }
            let rows: Vec<(String, String, u64)> = s
                .channels
                .get(key)
                .map(|c| {
                    self.kind
                        .list(c)
                        .iter()
                        .map(|b| (b.mask.clone(), b.setter.clone(), b.ts))
                        .collect()
                })
                .unwrap_or_default();
            for (m, setter, ts) in rows {
                s.numeric(uid, entry_num, &format!("{chan} {m} {setter} {ts}"));
            }
            let m = s.trf("End of channel {0}", &[noun]);
            s.numeric(uid, end_num, &format!("{chan} :{m}"));
            return Applied::No;
        };
        // autoop (+w) embeds a status prefix to grant on join, applied under server
        // authority — so adding an entry that grants a prefix the setter couldn't grant
        // by hand would let e.g. a half-op auto-op itself. Gate it by the rank the
        // prefix needs (SAMODE / services authority bypasses via mode_sudo).
        if adding && matches!(self.kind, ListKind::AutoOp) && !s.mode_sudo {
            let pfx = mask.split_once(':').and_then(|(p, _)| p.chars().next());
            let needed = match pfx {
                Some('q') => RANK_OWNER,
                Some('a') => RANK_ADMIN,
                Some('o') => RANK_OP,
                Some('h') => RANK_HALFOP,
                Some('v') => RANK_VOICE,
                _ => 0,
            };
            if s.rank(uid, key) < needed {
                s.numeric(
                    uid,
                    ERR_CHANOPRIVSNEEDED,
                    &format!(
                        "{chan} :You lack the channel rank to auto-grant +{}",
                        pfx.unwrap_or('?')
                    ),
                );
                return Applied::No;
            }
        }
        let mask = if self.kind.normalizes() {
            normalize_ban_mask(mask)
        } else {
            mask.to_string()
        };
        if adding {
            let setter = s
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            let sudo = s.mode_sudo;
            let maxlist = s.conf_num("maxbans", 100usize);
            let mut full = false;
            if let Some(c) = s.channels.get_mut(key) {
                let list = self.kind.list_mut(c);
                // dedup case-insensitively: glob_match lowercases at match time, so
                // `*!*@Host` and `*!*@host` catch the same users — store only one.
                if list.iter().any(|b| b.mask.eq_ignore_ascii_case(&mask)) {
                    return Applied::No; // already present
                }
                // cap the list for local users; a burst / services set bypasses it.
                if !sudo && list.len() >= maxlist {
                    full = true;
                } else {
                    list.push(Ban {
                        mask: mask.clone(),
                        setter,
                        ts: now(),
                        expires: None,
                    });
                }
            }
            if full {
                s.numeric(
                    uid,
                    ERR_BANLISTFULL,
                    &format!("{chan} {mask} :Channel list is full"),
                );
                return Applied::No;
            }
            Applied::Yes(Some(mask))
        } else {
            let mut removed = false;
            if let Some(c) = s.channels.get_mut(key) {
                let list = self.kind.list_mut(c);
                let before = list.len();
                list.retain(|b| !b.mask.eq_ignore_ascii_case(&mask));
                removed = list.len() < before;
            }
            if removed {
                Applied::Yes(Some(mask))
            } else {
                Applied::No
            }
        }
    }
}

// --- +z secure-only ---------------------------------------------------------

/// `+z` — only TLS-connected users may join. It can only be *set* when every
/// current member is already on TLS (else `ERR_ALLMUSTSSL`); the join-time block
/// for non-secure users lives in [`crate::channels::Server::join`].
struct SecureOnly;
static SECUREONLY: SecureOnly = SecureOnly;
impl ChanMode for SecureOnly {
    fn letter(&self) -> char {
        'z'
    }
    fn wants_param(&self, _adding: bool) -> bool {
        false
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        uid: Uid,
        adding: bool,
        _param: Option<&str>,
    ) -> Applied {
        if adding {
            let members: Vec<Uid> = s
                .channels
                .get(key)
                .map(|c| c.members.keys().copied().collect())
                .unwrap_or_default();
            let total = members.len();
            let nonssl = members
                .iter()
                .filter(|m| !s.users.get(m).map(|u| u.secure).unwrap_or(false))
                .count();
            if nonssl > 0 {
                s.numeric(
                    uid,
                    ERR_ALLMUSTSSL,
                    &format!(
                        "{chan} :All members of the channel must be connected using TLS ({nonssl}/{total} are non-TLS)"
                    ),
                );
                return Applied::No;
            }
        }
        if let Some(c) = s.channels.get_mut(key) {
            c.modes.secure_only = adding;
        }
        Applied::Yes(None)
    }
}

// --- flood / rate modes (+f message, +j join, +F nick) and +L redirect ------

/// Parse a `count:secs` rate; both parts must be positive.
fn parse_rate(p: &str) -> Option<Rate> {
    let (a, b) = p.split_once(':')?;
    let count = a.parse::<u32>().ok()?;
    let secs = b.parse::<u64>().ok()?;
    (count > 0 && secs > 0).then_some(Rate { count, secs })
}

/// `+f [*]lines:secs` — kick a user who sends more than `lines` messages in
/// `secs`; a leading `*` also sets a +b ban on them. Enforced in the PRIVMSG path.
struct MsgFloodMode;
static MSGFLOOD: MsgFloodMode = MsgFloodMode;
impl ChanMode for MsgFloodMode {
    fn letter(&self) -> char {
        'f'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(p) = param else {
                return Applied::No;
            };
            let ban = p.starts_with('*');
            let Some(r) = parse_rate(if ban { &p[1..] } else { p }) else {
                return Applied::No;
            };
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.flood = Some(MsgFlood {
                    lines: r.count,
                    secs: r.secs,
                    ban,
                });
            }
            Applied::Yes(Some(p.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.flood = None;
            }
            Applied::Yes(None)
        }
    }
}

/// `+j joins:secs` — after that many joins in the window, the channel locks new
/// joins out for 60s. Enforced in [`crate::channels::Server::join`].
struct JoinFloodMode;
static JOINFLOOD: JoinFloodMode = JoinFloodMode;
impl ChanMode for JoinFloodMode {
    fn letter(&self) -> char {
        'j'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(r) = param.and_then(parse_rate) else {
                return Applied::No;
            };
            let echo = format!("{}:{}", r.count, r.secs);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.joinflood = Some(r);
            }
            Applied::Yes(Some(echo))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.joinflood = None;
            }
            Applied::Yes(None)
        }
    }
}

/// `+F changes:secs` — after that many nick changes in the window, nick changes
/// on the channel are blocked for 60s. Enforced in the NICK path.
struct NickFloodMode;
static NICKFLOOD: NickFloodMode = NickFloodMode;
impl ChanMode for NickFloodMode {
    fn letter(&self) -> char {
        'F'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(r) = param.and_then(parse_rate) else {
                return Applied::No;
            };
            let echo = format!("{}:{}", r.count, r.secs);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.nickflood = Some(r);
            }
            Applied::Yes(Some(echo))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.nickflood = None;
            }
            Applied::Yes(None)
        }
    }
}

/// `+L #target` — when the channel is full (+l) new joiners are sent to
/// `#target` instead. Enforced in [`crate::channels::Server::join`].
struct RedirectMode;
static REDIRECT: RedirectMode = RedirectMode;
impl ChanMode for RedirectMode {
    fn letter(&self) -> char {
        'L'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(t) = param else {
                return Applied::No;
            };
            if !t.starts_with('#') || t.eq_ignore_ascii_case(chan) {
                return Applied::No; // must be another channel
            }
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.redirect = Some(t.to_string());
            }
            Applied::Yes(Some(t.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.redirect = None;
            }
            Applied::Yes(None)
        }
    }
}

/// +B `<percent>` — reject channel messages that are at least `<percent>` uppercase.
/// Enforced in the message path; ops are exempt.
struct AntiCapsMode;
static ANTICAPS: AntiCapsMode = AntiCapsMode;
impl ChanMode for AntiCapsMode {
    fn letter(&self) -> char {
        'B'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let pct = param.and_then(|p| p.parse::<u8>().ok()).filter(|&p| p >= 1);
            let Some(pct) = pct.map(|p| p.min(100)) else {
                return Applied::No; // needs a 1..=100 percentage
            };
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.anticaps = Some(pct);
            }
            Applied::Yes(Some(pct.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.anticaps = None;
            }
            Applied::Yes(None)
        }
    }
}

/// +J `<secs>` — after being kicked, a user can't rejoin for `<secs>` seconds.
/// Enforced in `Server::join`.
struct KickNoRejoinMode;
static KICKNOREJOIN: KickNoRejoinMode = KickNoRejoinMode;
impl ChanMode for KickNoRejoinMode {
    fn letter(&self) -> char {
        'J'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(secs) = param
                .and_then(|p| p.parse::<u32>().ok())
                .filter(|&n| n >= 1)
            else {
                return Applied::No; // needs a positive seconds value
            };
            let secs = secs.min(3600);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.kicknorejoin = Some(secs);
            }
            Applied::Yes(Some(secs.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.kicknorejoin = None;
            }
            Applied::Yes(None)
        }
    }
}

/// +d `<secs>` — a newly-joined member can't speak for `<secs>` seconds.
/// Enforced in the message path; voiced-or-above are exempt.
struct DelayMsgMode;
static DELAYMSG: DelayMsgMode = DelayMsgMode;
impl ChanMode for DelayMsgMode {
    fn letter(&self) -> char {
        'd'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(secs) = param
                .and_then(|p| p.parse::<u32>().ok())
                .filter(|&n| n >= 1)
            else {
                return Applied::No;
            };
            let secs = secs.min(3600);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.delaymsg = Some(secs);
            }
            Applied::Yes(Some(secs.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.delaymsg = None;
            }
            Applied::Yes(None)
        }
    }
}

/// +K `<n>` — block a message identical to one of the sender's previous `<n>`
/// lines in this channel. Ops are exempt.
struct RepeatMode;
static REPEAT: RepeatMode = RepeatMode;
impl ChanMode for RepeatMode {
    fn letter(&self) -> char {
        'K'
    }
    fn wants_param(&self, adding: bool) -> bool {
        adding
    }
    fn apply(
        &self,
        s: &mut Server,
        _chan: &str,
        key: &str,
        _uid: Uid,
        adding: bool,
        param: Option<&str>,
    ) -> Applied {
        if adding {
            let Some(n) = param
                .and_then(|p| p.parse::<u32>().ok())
                .filter(|&n| n >= 1)
            else {
                return Applied::No;
            };
            let n = n.min(20);
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.repeat = Some(n);
            }
            Applied::Yes(Some(n.to_string()))
        } else {
            if let Some(c) = s.channels.get_mut(key) {
                c.modes.repeat = None;
            }
            Applied::Yes(None)
        }
    }
}

// === user modes ============================================================

/// A user mode (+i/+w/+o) — same handler-object shape as [`ChanMode`]: an
/// unbounded slice of zero-sized `&'static` handlers.
pub trait UserMode: Sync {
    fn letter(&self) -> char;
    /// Apply `+`/`-` to the user; return `true` if it took effect (echo it).
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool;
}

/// Look up the handler for a user-mode letter.
pub fn user_mode(c: char) -> Option<&'static (dyn UserMode + Sync)> {
    USER_MODES.iter().copied().find(|m| m.letter() == c)
}

static USER_MODES: &[&(dyn UserMode + Sync)] = &[
    &INVISIBLE,
    &WALLOPS,
    &HELPOP,
    &OPER,
    &CLOAK,
    &BOT,
    &DEAF,
    &HIDECHANS,
    &HIDEOPER,
    &REGDEAF,
    &REGISTERED,
    &SERVPROTECT,
    &SSLPM,
    &SNOMASK,
    &CALLERID,
    &SHOWWHOIS,
    &COMMONCHANS,
];

/// A simple boolean user flag (+i / +w).
struct UFlag {
    ch: char,
    set: fn(&mut UserFlags, bool),
}
fn set_invisible(f: &mut UserFlags, v: bool) {
    f.invisible = v;
}
fn set_wallops(f: &mut UserFlags, v: bool) {
    f.wallops = v;
}
static INVISIBLE: UFlag = UFlag {
    ch: 'i',
    set: set_invisible,
};
static WALLOPS: UFlag = UFlag {
    ch: 'w',
    set: set_wallops,
};
fn set_bot(f: &mut UserFlags, v: bool) {
    f.bot = v;
}
fn set_deaf(f: &mut UserFlags, v: bool) {
    f.deaf = v;
}
fn set_hidechans(f: &mut UserFlags, v: bool) {
    f.hidechans = v;
}
fn set_hideoper(f: &mut UserFlags, v: bool) {
    f.hideoper = v;
}
fn set_regdeaf(f: &mut UserFlags, v: bool) {
    f.reg_only_pm = v;
}
fn set_sslpm(f: &mut UserFlags, v: bool) {
    f.ssl_pm = v;
}
fn set_callerid(f: &mut UserFlags, v: bool) {
    f.callerid = v;
}
fn set_showwhois(f: &mut UserFlags, v: bool) {
    f.showwhois = v;
}
fn set_commonchans(f: &mut UserFlags, v: bool) {
    f.deny_uncommon = v;
}
static BOT: UFlag = UFlag {
    ch: 'B',
    set: set_bot,
};
static DEAF: UFlag = UFlag {
    ch: 'D',
    set: set_deaf,
};
static HIDECHANS: UFlag = UFlag {
    ch: 'I',
    set: set_hidechans,
};
static HIDEOPER: OperFlag = OperFlag {
    ch: 'H',
    set: set_hideoper,
};
static REGDEAF: UFlag = UFlag {
    ch: 'R',
    set: set_regdeaf,
};
static SSLPM: UFlag = UFlag {
    ch: 'z',
    set: set_sslpm,
};
static CALLERID: UFlag = UFlag {
    ch: 'g',
    set: set_callerid,
};
static SHOWWHOIS: OperFlag = OperFlag {
    ch: 'W',
    set: set_showwhois,
};
static COMMONCHANS: UFlag = UFlag {
    ch: 'c',
    set: set_commonchans,
};

impl UserMode for UFlag {
    fn letter(&self) -> char {
        self.ch
    }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        if let Some(u) = s.users.get_mut(&uid) {
            (self.set)(&mut u.flags, adding);
            true
        } else {
            false
        }
    }
}

fn set_helpop(f: &mut UserFlags, v: bool) {
    f.helpop = v;
}
fn set_snomask(f: &mut UserFlags, v: bool) {
    // the plain `+s`/`-s` path (services, or a client giving no mask) toggles the
    // full default set; the client `+s <mask>` path in apply_user_modes refines it
    f.snomask = v;
    f.snomask_cats = if v {
        crate::users::DEFAULT_SNOMASK.to_string()
    } else {
        String::new()
    };
}

/// An oper-only boolean flag (+H / +W / +h / +s): only an operator may **set** it;
/// anyone may clear it. A non-oper who tries to set it is told they aren't an
/// operator (`ERR_NOPRIVILEGES`) and the flag is left off — it never silently
/// "sticks" with no effect.
struct OperFlag {
    ch: char,
    set: fn(&mut UserFlags, bool),
}
impl UserMode for OperFlag {
    fn letter(&self) -> char {
        self.ch
    }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        if adding && !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return false;
        }
        // per-oper-type usermode allowlist (services under sudo pass through)
        if adding
            && !s.mode_sudo
            && !crate::modules::opertypes::can_use_mode(s, uid, self.ch, false)
        {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- your oper type may not set that user mode",
            );
            return false;
        }
        if let Some(u) = s.users.get_mut(&uid) {
            (self.set)(&mut u.flags, adding);
            true
        } else {
            false
        }
    }
}

/// `+o` is granted only by OPER; a user may `-o` (de-oper) themselves.
struct OperMode;
static OPER: OperMode = OperMode;
impl UserMode for OperMode {
    fn letter(&self) -> char {
        'o'
    }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        if adding {
            return false; // never self-granted
        }
        if s.users.get(&uid).is_none() {
            return false;
        }
        if let Some(u) = s.users.get_mut(&uid) {
            u.flags.oper = false;
        }
        // operprefix: drop the ! prefix in every channel now that they're not staff
        crate::modules::operprefix::clear_all(s, uid);
        true
    }
}

/// `+h` — helpop: marks a user as available for help (shown in WHOIS). Oper-only to
/// set; anyone may clear it.
static HELPOP: OperFlag = OperFlag {
    ch: 'h',
    set: set_helpop,
};

/// `+x` — host cloaking. The cloak string is computed once at connect by
/// [`crate::modules::cloak`]; this handler only toggles whether it's shown.
/// `-x` (revealing the real host) is oper-only, so +x can't be flipped to dodge
/// a channel ban that was set on the cloak.
struct CloakMode;
static CLOAK: CloakMode = CloakMode;
impl UserMode for CloakMode {
    fn letter(&self) -> char {
        'x'
    }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        // No-op unless a cloak was actually computed (i.e. a cloak_key is set).
        let has_cloak = s
            .users
            .get(&uid)
            .map(|u| !u.cloak.is_empty())
            .unwrap_or(false);
        if !has_cloak {
            return false;
        }
        if !adding && !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Only operators may remove the +x host cloak",
            );
            return false;
        }
        let old_prefix = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
        if let Some(u) = s.users.get_mut(&uid) {
            u.flags.cloak = adding;
        }
        let (ident, disp) = s
            .users
            .get(&uid)
            .map(|u| (u.ident.clone(), u.host_display().to_string()))
            .unwrap_or_default();
        // chghost: tell capable peers the displayed host changed
        s.notify_peers(uid, &format!(":{old_prefix} CHGHOST {ident} {disp}"), |c| {
            c.chghost
        });
        s.numeric(
            uid,
            RPL_HOSTHIDDEN,
            &format!("{disp} :is now your displayed host"),
        );
        true
    }
}

/// `+r` — "logged into an account". Set/cleared only by **services** (via
/// [`crate::server::Server::set_login`]); the user can never toggle it by hand.
struct RegisteredMode;
static REGISTERED: RegisteredMode = RegisteredMode;
impl UserMode for RegisteredMode {
    fn letter(&self) -> char {
        'r'
    }
    fn apply(&self, _s: &mut Server, _uid: Uid, _adding: bool) -> bool {
        false // services-managed; not user-settable
    }
}

/// `+k` — servprotect. Set only by a linked server / services (under `mode_sudo`);
/// a client can never toggle it. Marks the user as protected from KILL/KICK/SA*.
struct ServProtect;
static SERVPROTECT: ServProtect = ServProtect;
impl UserMode for ServProtect {
    fn letter(&self) -> char {
        'k'
    }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        if !s.mode_sudo {
            return false; // server/services-only
        }
        if let Some(u) = s.users.get_mut(&uid) {
            u.flags.servprotect = adding;
            return true;
        }
        false
    }
}

/// `+s` — server-notice (snomask) receiver. Oper-only to set; anyone may drop it.
static SNOMASK: OperFlag = OperFlag {
    ch: 's',
    set: set_snomask,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_covers_all_channel_modes() {
        for c in "qaohvbeIklmntiszpONCTcSRMfjFLgGuBQAPJUdKXwDr".chars() {
            assert!(chan_mode(c).is_some(), "missing handler for +{c}");
        }
        assert!(chan_mode('y').is_none());
    }

    #[test]
    fn rate_parsing() {
        assert!(parse_rate("5:10").is_some());
        assert!(parse_rate("0:10").is_none()); // zero count rejected
        assert!(parse_rate("5:0").is_none()); // zero window rejected
        assert!(parse_rate("bad").is_none());
    }

    #[test]
    fn registry_covers_all_user_modes() {
        for c in "iwoxBDIHrRzsgWhc".chars() {
            assert!(user_mode(c).is_some(), "missing umode +{c}");
        }
        assert!(user_mode('Q').is_none());
    }

    #[test]
    fn masks_are_normalized() {
        assert_eq!(normalize_ban_mask("bob"), "bob!*@*");
        assert_eq!(normalize_ban_mask("bob@evil.host"), "*!bob@evil.host"); // user@host
        assert_eq!(normalize_ban_mask("a!b@c"), "a!b@c");
        // extbans keep their type; only the hostmask part is filled out
        assert_eq!(normalize_ban_mask("m:bob"), "m:bob!*@*");
        assert_eq!(normalize_ban_mask("c:*@evil"), "c:*!*@evil");
    }
}
