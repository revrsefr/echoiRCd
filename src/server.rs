//! The engine core: the `Server` struct that owns all state, the output
//! primitives (send / numeric / to_channel) and the connection lifecycle.
//! Per-subsystem behaviour lives beside its data — [`crate::users`] and
//! [`crate::channels`] add their own `impl Server` blocks, the way InspIRCd
//! keeps usermanager / channelmanager separate from the core. No locks: only the
//! single core thread ever holds a `Server`.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::channels::Channel;
use crate::config::{Config, LinkBlock};
use crate::extensible::Extensible;
use crate::ircd::Event;
use crate::link::{Link, RemoteServer, RemoteUser};
use crate::module::Hook;
use crate::modules::dnsbl;
use crate::resolver;
use crate::socketengine::OutSink;
use crate::users::{Caps, User, UserFlags};
use crate::xline::XLine;
use crate::Uid;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Background timer cadence + idle/ping timeouts, in seconds.
pub const TICK_SECS: u64 = 15;
pub const PING_AFTER: u64 = 90;
pub const PING_TIMEOUT: u64 = 60;
pub const REG_TIMEOUT: u64 = 60;
/// Recent messages CHATHISTORY keeps per channel.
pub const HISTORY_CAP: usize = 256;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a unix timestamp as an IRCv3 `server-time` tag value
/// (`2026-08-05T07:58:03.000Z`), computing the civil date with std only.
pub fn iso_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let (h, mi, s) = ((secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm)
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
}

/// Parse an IRCv3 `server-time` value (`2026-08-08T19:52:42.000Z`) back to unix
/// seconds — the inverse of [`iso_time`], for CHATHISTORY `timestamp=` selectors.
pub fn parse_iso(s: &str) -> Option<u64> {
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: i64 = d.next()?.parse().ok()?;
    let da: i64 = d.next()?.parse().ok()?;
    let time = time.trim_end_matches('Z').split('.').next()?;
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let se: i64 = t.next().unwrap_or("0").parse().ok()?;
    // civil date -> days since 1970-01-01 (inverse Howard Hinnant)
    let yy = y - i64::from(mo <= 2);
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se).max(0) as u64)
}

/// One stored message, replayed by CHATHISTORY.
pub struct HistMsg {
    pub ts: u64,
    pub msgid: String,
    pub prefix: String,     // sender's nick!user@host at send time
    pub verb: &'static str, // "PRIVMSG" or "NOTICE"
    pub target: String,     // original target (channel, or the DM recipient)
    pub text: String,
}

/// Limits advertised in the `draft/multiline` cap and enforced while buffering.
pub const MLINE_MAX_BYTES: usize = 4096;
pub const MLINE_MAX_LINES: usize = 24;

/// An in-progress inbound draft/multiline batch — one long client message being
/// assembled from several `@batch=`-tagged PRIVMSG/NOTICE lines.
pub struct MlineBatch {
    pub bref: String,
    pub target: String,
    pub notice: bool,
    pub parts: Vec<(String, bool)>, // (text, concat-with-previous-part)
    pub bytes: usize,
}

/// A recently-departed identity, kept for WHOWAS.
pub struct WhowasEntry {
    pub nick: String,
    pub ident: String,
    pub host: String,
    pub realname: String,
    pub account: Option<String>,
    pub ts: u64,
}

pub struct Server {
    pub name: String,
    pub network: String,
    pub created: u64,
    pub motd: Vec<String>,
    pub users: HashMap<Uid, User>,
    pub nick_index: HashMap<String, Uid>,   // lower nick -> uid
    pub channels: HashMap<String, Channel>, // lower name -> channel
    pub events: VecDeque<Hook>,
    pub opers: Vec<(String, String)>, // (name, password) from config
    pub cloak_key: Option<String>,    // host-cloaking key (see modules::cloak)
    pub line_ctags: String,           // client-only tags of the line being handled
    // --- server-to-server (see crate::link) ---
    pub sid: String,                               // our 3-char server id
    pub server_desc: String,                       // our description
    pub link_blocks: Vec<LinkBlock>,               // peers we accept / dial
    pub links: HashMap<Uid, Link>,                 // local link connections
    pub servers: HashMap<String, RemoteServer>,    // sid -> linked server
    pub uuid_counter: u64,                         // mints local user UIDs
    pub msgid_counter: u64,                        // mints IRCv3 `msgid` message tags
    pub uuid_local: HashMap<String, Uid>,          // our users, by network uuid
    pub remote_users: HashMap<String, RemoteUser>, // users on other servers
    pub remote_nick: HashMap<String, String>,      // lower nick -> remote uuid
    pub whowas: VecDeque<WhowasEntry>,             // recent nick history (WHOWAS)
    pub conf_path: String,                         // config path, for REHASH
    pub xlines: Vec<XLine>,                        // server bans (KLINE/GLINE/ZLINE)
    pub mode_sudo: bool,                           // SAMODE/SAKICK: bypass rank checks
    pub in_redirect: bool,                         // +L: guards against redirect loops
    pub censor: Vec<(String, String)>,             // +G bad words: (find, replace)
    pub amu: crate::config::AntiMixedCfg,          // antimixedutf8 module config
    pub resolve_hosts: bool,                       // reverse-DNS clients on connect
    pub use_resolved_host: bool,                   // apply the resolved name to the hostmask
    pub dnsbl_zones: Vec<String>,                  // DNS blocklist zones checked on connect
    pub dnsbl_action: String,                      // mark | kline | gline | zline
    pub dnsbl_reason: String,                      // ban reason on a DNSBL hit
    pub sasl_server: String,                       // services server that handles SASL
    pub webirc: Vec<(String, String, String)>,     // web gateways: (password, name, ip-mask)
    // labeled-response: while Some((uid, buf)), that client's own responses are
    // diverted into `buf` instead of the socket, so `on_line` can wrap them with
    // the command's `label` (single tag, BATCH, or ACK). RefCell because the
    // output primitives are `&self`.
    pub label_capture: RefCell<Option<(Uid, Vec<String>)>>,
    pub history: HashMap<String, VecDeque<HistMsg>>, // channel key -> recent messages (CHATHISTORY)
    pub mline: HashMap<Uid, MlineBatch>, // in-progress inbound multiline batches
    pub event_tx: Sender<Event>,         // self-inject events (DNS results)
    pub conn_counter: Arc<AtomicU64>,    // mints connection uids (for CONNECT dials)
    /// Module-owned server state, keyed by type — the InspIRCd `ExtensionItem`
    /// equivalent. Each `modules/*.rs` stores its own struct here so features live
    /// in their own file instead of bloating this one.
    pub ext: Extensible,
}

impl Server {
    pub fn new(cfg: Config, event_tx: Sender<Event>, conn_counter: Arc<AtomicU64>) -> Server {
        Server {
            name: cfg.servername,
            network: cfg.network,
            created: now(),
            motd: cfg.motd,
            users: HashMap::new(),
            nick_index: HashMap::new(),
            channels: HashMap::new(),
            events: VecDeque::new(),
            opers: cfg.opers,
            cloak_key: cfg.cloak_key,
            line_ctags: String::new(),
            sid: cfg.sid,
            server_desc: cfg.serverdesc,
            link_blocks: cfg.links,
            links: HashMap::new(),
            servers: HashMap::new(),
            uuid_counter: 0,
            msgid_counter: 0,
            uuid_local: HashMap::new(),
            remote_users: HashMap::new(),
            remote_nick: HashMap::new(),
            whowas: VecDeque::new(),
            conf_path: cfg.conf_path,
            xlines: Vec::new(),
            mode_sudo: false,
            in_redirect: false,
            censor: cfg.censor,
            amu: cfg.amu,
            resolve_hosts: cfg.resolve_hosts,
            use_resolved_host: cfg.use_resolved_host,
            dnsbl_zones: cfg.dnsbl_zones,
            dnsbl_action: cfg.dnsbl_action,
            dnsbl_reason: cfg.dnsbl_reason,
            sasl_server: cfg.sasl_server,
            webirc: cfg.webirc,
            label_capture: RefCell::new(None),
            history: HashMap::new(),
            mline: HashMap::new(),
            event_tx,
            conn_counter,
            ext: Extensible::default(),
        }
    }

    /// Remember an identity for WHOWAS (capped ring, newest first).
    pub fn push_whowas(
        &mut self,
        nick: &str,
        ident: &str,
        host: &str,
        realname: &str,
        account: Option<String>,
    ) {
        if nick.is_empty() {
            return;
        }
        self.whowas.push_front(WhowasEntry {
            nick: nick.to_string(),
            ident: ident.to_string(),
            host: host.to_string(),
            realname: realname.to_string(),
            account,
            ts: now(),
        });
        while self.whowas.len() > 256 {
            self.whowas.pop_back();
        }
    }

    /// Record a channel message for CHATHISTORY replay (capped ring per channel).
    pub fn store_history(
        &mut self,
        key: &str,
        prefix: &str,
        verb: &'static str,
        target: &str,
        text: &str,
        msgid: &str,
    ) {
        let buf = self.history.entry(key.to_string()).or_default();
        buf.push_back(HistMsg {
            ts: now(),
            msgid: msgid.to_string(),
            prefix: prefix.to_string(),
            verb,
            target: target.to_string(),
            text: text.to_string(),
        });
        while buf.len() > HISTORY_CAP {
            buf.pop_front();
        }
    }

    /// Open an inbound draft/multiline batch for `uid` (a client assembling one
    /// long message from several tagged PRIVMSG/NOTICE lines).
    pub fn multiline_open(&mut self, uid: Uid, bref: &str, target: &str) {
        self.mline.insert(
            uid,
            MlineBatch {
                bref: bref.to_string(),
                target: target.to_string(),
                notice: false,
                parts: Vec::new(),
                bytes: 0,
            },
        );
    }

    /// Buffer one PRIVMSG/NOTICE line into `uid`'s open multiline batch when `bref`
    /// matches (bounded by the advertised byte/line limits). Returns true if it was
    /// part of the batch — i.e. it should not be delivered on its own.
    pub fn multiline_accumulate(
        &mut self,
        uid: Uid,
        bref: &str,
        notice: bool,
        text: &str,
        concat: bool,
    ) -> bool {
        match self.mline.get_mut(&uid) {
            Some(mb) if mb.bref == bref => {
                if mb.parts.len() < MLINE_MAX_LINES && mb.bytes + text.len() <= MLINE_MAX_BYTES {
                    mb.notice = notice;
                    mb.bytes += text.len();
                    mb.parts.push((text.to_string(), concat));
                }
                true
            }
            _ => false,
        }
    }

    /// Close `uid`'s multiline batch `bref` and return `(target, is_notice, lines)`
    /// with `concat` parts joined into single logical lines. `None` if no match.
    pub fn multiline_close(&mut self, uid: Uid, bref: &str) -> Option<(String, bool, Vec<String>)> {
        match self.mline.get(&uid) {
            Some(mb) if mb.bref == bref => {}
            _ => return None,
        }
        let mb = self.mline.remove(&uid)?;
        let mut lines: Vec<String> = Vec::new();
        for (text, concat) in mb.parts {
            if concat && !lines.is_empty() {
                lines.last_mut().unwrap().push_str(&text);
            } else {
                lines.push(text);
            }
        }
        Some((mb.target, mb.notice, lines))
    }

    // --- connection lifecycle ------------------------------------------------

    pub fn add_conn(
        &mut self,
        uid: Uid,
        addr: SocketAddr,
        out: OutSink,
        sock: Option<TcpStream>,
        secure: bool,
        certfp: Option<String>,
    ) {
        let uuid = self.next_uuid();
        self.uuid_local.insert(uuid.clone(), uid);
        let ip = addr.ip();
        self.users.insert(
            uid,
            User {
                uid,
                uuid,
                nick: String::new(),
                ident: String::new(),
                realname: String::new(),
                host: addr.ip().to_string(),
                cloak: String::new(),
                vhost: None,
                secure,
                certfp,
                account: None,
                signon: now(),
                addr,
                registered: false,
                dns_pending: false,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::new(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: now(),
                ping_sent: false,
                ext: Extensible::default(),
                out,
                sock,
            },
        );

        // Pre-registration connection notices, InspIRCd / solanum style. Ident-113
        // is archaic and firewalled, so those two are cosmetic; the hostname lookup
        // is real (see `resolver`) — its result arrives later as an Event.
        self.notice_star(uid, "Checking Ident");
        self.notice_star(uid, "No Ident response");
        let do_rdns = self.resolve_hosts;
        let zones = self.dnsbl_zones.clone(); // DNSBL runs if any zones are configured
        if do_rdns {
            self.notice_star(uid, "Looking up your hostname...");
        }
        if (do_rdns || !zones.is_empty()) && resolver::try_acquire() {
            if let Some(u) = self.users.get_mut(&uid) {
                u.dns_pending = true; // hold registration until the lookups return
            }
            let tx = self.event_tx.clone();
            thread::spawn(move || {
                // rDNS and DNSBL are independent (DNSBL only needs the IP), so run
                // them concurrently — the client waits on max(rdns, dnsbl), not the
                // sum. Only spin up the extra thread when both are actually needed.
                let (host, dnsbl) = if do_rdns && !zones.is_empty() {
                    let job =
                        thread::spawn(move || dnsbl::check(ip, &zones, resolver::DNS_TIMEOUT));
                    let host = resolver::reverse_confirmed(ip, resolver::DNS_TIMEOUT);
                    (host, job.join().unwrap_or(dnsbl::Outcome::Skipped))
                } else if do_rdns {
                    (
                        resolver::reverse_confirmed(ip, resolver::DNS_TIMEOUT),
                        dnsbl::Outcome::Skipped,
                    )
                } else {
                    (None, dnsbl::check(ip, &zones, resolver::DNS_TIMEOUT))
                };
                resolver::release();
                let _ = tx.send(Event::ResolvedHost { uid, host, dnsbl });
            });
        } else if do_rdns {
            // wanted rDNS but couldn't start (too many in flight): keep the IP
            self.notice_star(
                uid,
                "Couldn't look up your hostname; using your IP address instead",
            );
        }
    }

    /// A pre-registration `:server NOTICE * :*** <msg>` line.
    pub(crate) fn notice_star(&self, uid: Uid, msg: &str) {
        self.send(uid, format!(":{} NOTICE * :*** {msg}", self.name));
    }

    /// While a client's connect-time DNS/DNSBL lookups are still running, hold its
    /// handshake lines instead of processing them, so the "*** ..." notices print
    /// as one contiguous block rather than interleaving with the CAP/NICK replies.
    /// Returns true if `line` was buffered. Bounded — past the cap we let lines
    /// through (degrading to interleaved output rather than dropping input).
    pub fn defer_if_resolving(&mut self, uid: Uid, line: &str) -> bool {
        const MAX_DEFERRED: usize = 32;
        match self.users.get_mut(&uid) {
            Some(u) if u.dns_pending && u.deferred.len() < MAX_DEFERRED => {
                u.deferred.push(line.to_string());
                true
            }
            _ => false,
        }
    }

    /// Take and clear the handshake lines held while `uid`'s lookups ran, to replay
    /// once the notice block has printed.
    pub fn take_deferred(&mut self, uid: Uid) -> Vec<String> {
        self.users
            .get_mut(&uid)
            .map(|u| std::mem::take(&mut u.deferred))
            .unwrap_or_default()
    }

    /// A client's reverse-DNS lookup finished. Set the resolved host (so WHOIS,
    /// bans and cloaking use the hostname, not the IP), tell the client, and clear
    /// the flag that was holding their registration.
    pub fn on_resolved(&mut self, uid: Uid, host: Option<String>, outcome: dnsbl::Outcome) {
        // hostname result (only announced if we actually attempted the lookup)
        match &host {
            Some(h) => self.notice_star(uid, &format!("Found your hostname ({h})")),
            None if self.resolve_hosts => self.notice_star(
                uid,
                "Couldn't look up your hostname; using your IP address instead",
            ),
            None => {}
        }
        let apply = self.use_resolved_host;
        if let Some(u) = self.users.get_mut(&uid) {
            // `use_resolved_host = off` keeps the IP in the hostmask even though we
            // resolved and reported the name above.
            if apply {
                if let Some(h) = host {
                    u.host = h;
                }
            }
        }
        // DNSBL notices + action (InspIRCd m_dnsbl style) — see `modules::dnsbl`.
        // May close the connection if the zone is listed and the action bans.
        dnsbl::report(self, uid, outcome);
        // release the registration hold (no-op if a DNSBL ban already removed them)
        if let Some(u) = self.users.get_mut(&uid) {
            u.dns_pending = false;
        }
    }

    /// Mark a user as quitting; the core turns this into a full quit after the
    /// current command returns (so hooks fire while the user still exists).
    pub fn mark_quit(&mut self, uid: Uid, reason: String) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.quitting = Some(reason);
        }
    }

    pub fn take_quit(&mut self, uid: Uid) -> Option<String> {
        self.users.get_mut(&uid).and_then(|u| u.quitting.take())
    }

    /// Remove a user: broadcast QUIT to everyone sharing a channel, drop them
    /// from all channels, free the nick, and close the socket.
    pub fn remove_user(&mut self, uid: Uid, reason: &str) {
        let Some(user) = self.users.remove(&uid) else {
            return;
        };
        self.uuid_local.remove(&user.uuid);
        self.mline.remove(&uid); // any half-open multiline batch
        if user.registered {
            self.push_whowas(
                &user.nick,
                &user.ident,
                user.host_display(),
                &user.realname,
                user.account.clone(),
            );
            self.propagate(&format!(":{} QUIT :{reason}", user.uuid), None); // tell links
        }
        // NB: we do *not* force-shutdown the socket here. When `user` drops at
        // the end of this function its `out` Sender drops with it, so the writer
        // thread drains any still-queued lines — e.g. a KILL / x-line ERROR —
        // and then closes the socket itself once the channel is empty.
        if !user.nick.is_empty() {
            self.nick_index.remove(&user.nick.to_ascii_lowercase());
        }
        if user.registered {
            let line = format!(":{} QUIT :{reason}", user.prefix());
            let mut seen: HashSet<Uid> = HashSet::new();
            for key in &user.channels {
                if let Some(ch) = self.channels.get_mut(key) {
                    ch.members.remove(&uid);
                    for &m in ch.members.keys() {
                        seen.insert(m);
                    }
                }
            }
            for m in seen {
                self.send(m, line.clone());
            }
            self.channels.retain(|_, c| !c.is_empty());
            self.watch_notify_offline(&user.nick); // tell WATCH/MONITOR watchers
        }
    }

    // --- output primitives ---------------------------------------------------

    /// Queue one raw line to a connection (no-op if it's gone).
    pub fn send(&self, uid: Uid, line: String) {
        if let Some(u) = self.users.get(&uid) {
            // server-time: tag sourced (`:prefix …`) lines for clients that asked
            let line = if u.caps.server_time && line.starts_with(':') {
                format!("@time={} {line}", iso_time(now()))
            } else {
                line
            };
            self.emit_to(uid, line);
        }
    }

    /// Final hop for one line to a client: diverted into the labeled-response
    /// capture buffer when one is active for `uid`, otherwise written to the wire.
    fn emit_to(&self, uid: Uid, line: String) {
        if let Ok(mut cap) = self.label_capture.try_borrow_mut() {
            if let Some((cuid, buf)) = cap.as_mut() {
                if *cuid == uid {
                    buf.push(line);
                    return;
                }
            }
        }
        if let Some(u) = self.users.get(&uid) {
            u.out.send(line);
        }
    }

    /// Send a numeric: `:server NNN <target> <rest>`. `<target>` is the client's
    /// nick, or `*` before it has one.
    pub fn numeric(&self, uid: Uid, code: u16, rest: &str) {
        let target = self
            .users
            .get(&uid)
            .map(|u| {
                if u.nick.is_empty() {
                    "*".to_string()
                } else {
                    u.nick.clone()
                }
            })
            .unwrap_or_else(|| "*".to_string());
        self.send(
            uid,
            format!(":{} {:03} {} {}", self.name, code, target, rest),
        );
    }

    /// Send a server notice to every operator who has snomask (+s) on.
    pub fn snotice(&self, msg: &str) {
        let opers: Vec<Uid> = self
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper && u.flags.snomask)
            .map(|(&u, _)| u)
            .collect();
        for o in opers {
            let nick = self
                .users
                .get(&o)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            self.send(o, format!(":{} NOTICE {nick} :*** {msg}", self.name));
        }
    }

    /// Broadcast a `*** msg` server NOTICE to *every* registered local user — for
    /// server-wide announcements everyone should see (e.g. a config reload).
    pub fn announce(&self, msg: &str) {
        for u in self.users.values() {
            if u.registered && !u.nick.is_empty() {
                u.out
                    .send(format!(":{} NOTICE {} :*** {msg}", self.name, u.nick));
            }
        }
    }

    /// IRCv3 standard reply (`FAIL`/`WARN`/`NOTE`): structured, machine-readable
    /// command feedback. Sent in the `:server FAIL <command> <code> :<desc>` form
    /// to clients that negotiated `standard-replies`; others get the description as
    /// a plain server NOTICE so the human-readable text still reaches them.
    pub fn fail(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "FAIL", command, code, desc);
    }
    pub fn warn(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "WARN", command, code, desc);
    }
    pub fn note(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "NOTE", command, code, desc);
    }
    fn standard_reply(&self, uid: Uid, kind: &str, command: &str, code: &str, desc: &str) {
        let cap = self
            .users
            .get(&uid)
            .map(|u| u.caps.standard_replies)
            .unwrap_or(false);
        if cap {
            self.send(
                uid,
                format!(":{} {kind} {command} {code} :{desc}", self.name),
            );
        } else {
            let nick = self
                .users
                .get(&uid)
                .map(|u| {
                    if u.nick.is_empty() {
                        "*".to_string()
                    } else {
                        u.nick.clone()
                    }
                })
                .unwrap_or_else(|| "*".to_string());
            self.send(uid, format!(":{} NOTICE {nick} :{desc}", self.name));
        }
    }

    /// Send a line to every member of a channel, optionally skipping one uid.
    pub fn to_channel(&self, key: &str, line: &str, except: Option<Uid>) {
        if let Some(ch) = self.channels.get(key) {
            for &uid in ch.members.keys() {
                if Some(uid) != except {
                    self.send(uid, line.to_string());
                }
            }
        }
    }

    /// Send a message body (`:prefix CMD …`) from `src` to `uid`, composing its
    /// IRCv3 tag prefix from *that recipient's* caps: `time=` (server-time),
    /// `account=` (account-tag, from the sender's login) plus the client-only tags
    /// `ctags` and `msgid` (message-tags). For PRIVMSG / NOTICE / TAGMSG delivery.
    pub fn send_tagged(&self, uid: Uid, src: Uid, ctags: &str, msgid: &str, body: &str) {
        if let Some(u) = self.users.get(&uid) {
            let mut tags: Vec<String> = Vec::new();
            if u.caps.server_time {
                tags.push(format!("time={}", iso_time(now())));
            }
            // account-tag: label a message with the sender's services account, so
            // recipients see who's authenticated without a separate WHOIS.
            if u.caps.account_tag {
                if let Some(acct) = self.users.get(&src).and_then(|su| su.account.as_deref()) {
                    tags.push(format!("account={acct}"));
                }
            }
            // msgid (IRCv3): a unique, server-assigned id per message so clients
            // can reference it (reactions, replies, redaction). Tag-only feature,
            // so it goes to message-tags clients alongside any client `+`-tags.
            if u.caps.message_tags {
                if !msgid.is_empty() {
                    tags.push(format!("msgid={msgid}"));
                }
                if !ctags.is_empty() {
                    tags.push(ctags.to_string());
                }
            }
            let line = if tags.is_empty() {
                body.to_string()
            } else {
                format!("@{} {body}", tags.join(";"))
            };
            self.emit_to(uid, line);
        }
    }

    /// Mint a unique IRCv3 `msgid` for one message. Generated once per PRIVMSG/
    /// NOTICE/TAGMSG and shared across all its recipients so they correlate.
    /// `<server-start>-<counter>` in hex: unique for this run, distinct across
    /// restarts (the start time changes).
    pub fn next_msgid(&mut self) -> String {
        self.msgid_counter = self.msgid_counter.wrapping_add(1);
        format!("{:x}-{:x}", self.created, self.msgid_counter)
    }

    /// Send `line` to every user sharing a channel with `uid` (except `uid`) whose
    /// capabilities satisfy `want`. Drives away-/account-/chghost-/setname-notify.
    pub fn notify_peers(&self, uid: Uid, line: &str, want: fn(&Caps) -> bool) {
        let chans: Vec<String> = self
            .users
            .get(&uid)
            .map(|u| u.channels.iter().cloned().collect())
            .unwrap_or_default();
        let mut seen: HashSet<Uid> = HashSet::new();
        for k in &chans {
            if let Some(ch) = self.channels.get(k) {
                for &m in ch.members.keys() {
                    seen.insert(m);
                }
            }
        }
        // extended-monitor (IRCv3): clients that MONITOR this nick and negotiated
        // `extended-monitor` are treated as able to see it — so away/account/
        // chghost/setname reach them even without a shared channel. The `want`
        // filter below still requires the matching base cap, per spec.
        if let Some(low) = self.users.get(&uid).map(|u| u.nick.to_ascii_lowercase()) {
            for (&m, u) in &self.users {
                if u.caps.extended_monitor && u.monitor.contains(&low) {
                    seen.insert(m);
                }
            }
        }
        for m in seen {
            if m != uid && self.users.get(&m).map(|u| want(&u.caps)).unwrap_or(false) {
                self.send(m, line.to_string());
            }
        }
    }

    /// Change a user's displayed host and/or ident (CHGHOST/CHGIDENT/SETHOST/
    /// SETIDENT). Announces it via the `chghost` cap to peers that speak it and
    /// to the user, and sends RPL_HOSTHIDDEN (396) when the host changed. Mirrors
    /// InspIRCd's ChangeDisplayedHost / ChangeIdent (local scope for now).
    pub fn change_host_ident(&mut self, uid: Uid, new_ident: Option<&str>, new_host: Option<&str>) {
        let Some(u) = self.users.get(&uid) else {
            return;
        };
        let old_prefix = u.prefix();
        if let Some(h) = new_host {
            if let Some(u) = self.users.get_mut(&uid) {
                u.vhost = Some(h.to_string());
            }
        }
        if let Some(i) = new_ident {
            if let Some(u) = self.users.get_mut(&uid) {
                u.ident = i.to_string();
            }
        }
        let (ident, host, aware) = {
            let u = &self.users[&uid];
            (
                u.ident.clone(),
                u.host_display().to_string(),
                u.caps.chghost,
            )
        };
        // chghost-cap peers (and, if it speaks it, the user) get a CHGHOST line
        let line = format!(":{old_prefix} CHGHOST {ident} {host}");
        self.notify_peers(uid, &line, |c| c.chghost);
        if aware {
            self.send(uid, line);
        }
        if new_host.is_some() {
            self.numeric(
                uid,
                crate::numeric::RPL_HOSTHIDDEN,
                &format!("{host} :is now your displayed host"),
            );
        }
    }

    /// Decide which connections to PING and which to drop, given `now`.
    /// Returns `(to_ping, to_quit)`. Pure over the state, so it's unit-testable.
    pub fn idle_check(&self, now: u64) -> (Vec<Uid>, Vec<Uid>) {
        let mut ping = Vec::new();
        let mut quit = Vec::new();
        for (&uid, u) in &self.users {
            let idle = now.saturating_sub(u.last_active);
            if !u.registered {
                if idle >= REG_TIMEOUT {
                    quit.push(uid); // never registered in time
                }
            } else if u.ping_sent {
                if idle >= PING_AFTER + PING_TIMEOUT {
                    quit.push(uid); // no reply to our PING
                }
            } else if idle >= PING_AFTER {
                ping.push(uid); // idle — poke it
            }
        }
        (ping, quit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::valid_chan;
    use crate::users::{valid_nick, User, UserFlags};
    use std::sync::mpsc::{self, Receiver};

    /// Insert a registered user with an output channel we can read in the test.
    fn add_user(s: &mut Server, uid: Uid, nick: &str) -> Receiver<String> {
        let (tx, rx) = mpsc::channel();
        s.users.insert(
            uid,
            User {
                uid,
                uuid: format!("TST{uid:06}"),
                nick: nick.to_string(),
                ident: "u".to_string(),
                realname: "real".to_string(),
                host: "localhost".to_string(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                account: None,
                signon: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                registered: true,
                dns_pending: false,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::new(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(tx),
                sock: None,
            },
        );
        s.nick_index.insert(nick.to_ascii_lowercase(), uid);
        rx
    }

    fn srv() -> Server {
        let (tx, _rx) = mpsc::channel();
        Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)))
    }

    #[test]
    fn resolved_host_applied_only_when_configured() {
        let mut s = srv(); // use_resolved_host = true (default)
        let _a = add_user(&mut s, 1, "ann"); // host starts "localhost"
        s.on_resolved(
            1,
            Some("host.example.net".to_string()),
            dnsbl::Outcome::Skipped,
        );
        assert_eq!(s.users[&1].host, "host.example.net");
        assert!(!s.users[&1].dns_pending);

        s.use_resolved_host = false; // resolve + report, but keep the IP in the mask
        let _b = add_user(&mut s, 2, "bob");
        s.on_resolved(
            2,
            Some("host.example.net".to_string()),
            dnsbl::Outcome::Skipped,
        );
        assert_eq!(s.users[&2].host, "localhost");
        assert!(!s.users[&2].dns_pending); // registration still un-held either way
    }

    #[test]
    fn join_broadcasts_and_tracks_membership() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        let brx = add_user(&mut s, 2, "bob");
        s.join(1, "#c", None); // ann creates -> gets @
        s.join(2, "#c", None); // bob joins

        assert!(s.channels["#c"].members[&1].op);
        assert!(!s.channels["#c"].members[&2].op);
        assert_eq!(s.channels["#c"].members.len(), 2);

        let ann: Vec<String> = arx.try_iter().collect();
        assert!(ann
            .iter()
            .any(|l| l.contains("JOIN #c") && l.contains("ann!")));
        assert!(ann
            .iter()
            .any(|l| l.contains(":bob!") && l.contains("JOIN #c")));
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(bob.iter().any(|l| l.contains("353") && l.contains("@ann")));
    }

    #[test]
    fn nick_change_reindexes_and_notifies_channel() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        add_user(&mut s, 2, "bob");
        s.join(1, "#c", None);
        s.join(2, "#c", None);
        s.set_nick(1, "annie");
        assert_eq!(s.find_nick("annie"), Some(1));
        assert_eq!(s.find_nick("ann"), None);
        let ann: Vec<String> = arx.try_iter().collect();
        assert!(ann
            .iter()
            .any(|l| l.contains("NICK :annie") && l.contains("ann!")));
    }

    #[test]
    fn quit_frees_the_nick_and_tells_neighbors() {
        let mut s = srv();
        add_user(&mut s, 1, "ann");
        let brx = add_user(&mut s, 2, "bob");
        s.join(1, "#c", None);
        s.join(2, "#c", None);
        s.remove_user(1, "bye");
        assert!(s.find_nick("ann").is_none());
        assert!(!s.channels["#c"].members.contains_key(&1));
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(bob
            .iter()
            .any(|l| l.contains(":ann!") && l.contains("QUIT :bye")));
    }

    #[test]
    fn moderated_channel_needs_voice() {
        let mut s = srv();
        add_user(&mut s, 1, "ann");
        add_user(&mut s, 2, "bob");
        s.join(1, "#c", None); // ann = op
        s.join(2, "#c", None);
        s.channels.get_mut("#c").unwrap().modes.moderated = true;
        assert!(s.is_op(1, "#c") && !s.is_op(2, "#c"));
        assert!(s.is_member(2, "#c"));
    }

    #[test]
    fn secure_only_channel_rejects_plaintext() {
        let mut s = srv();
        add_user(&mut s, 1, "tls");
        s.users.get_mut(&1).unwrap().secure = true; // on TLS
        add_user(&mut s, 2, "plain"); // add_user defaults secure=false
        s.join(1, "#z", None); // tls creates -> op
        s.channels.get_mut("#z").unwrap().modes.secure_only = true;
        s.join(2, "#z", None); // plaintext tries to join
        assert!(s.is_member(1, "#z")); // the TLS user stays
        assert!(!s.is_member(2, "#z")); // the plaintext user is refused
    }

    #[test]
    fn reg_only_channel_rejects_unregistered() {
        let mut s = srv();
        add_user(&mut s, 1, "member");
        s.users.get_mut(&1).unwrap().account = Some("acct".to_string()); // logged in
        add_user(&mut s, 2, "guest"); // account None
        s.join(1, "#r", None); // logged-in user creates -> op
        s.channels.get_mut("#r").unwrap().modes.reg_only = true;
        s.join(2, "#r", None); // guest tries to join
        assert!(s.is_member(1, "#r")); // the logged-in user stays
        assert!(!s.is_member(2, "#r")); // the guest is refused
    }

    #[test]
    fn iso_time_formats_server_time() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_000_000_000), "2001-09-09T01:46:40.000Z");
    }

    #[test]
    fn nick_and_chan_validation() {
        assert!(valid_nick("reverse"));
        assert!(valid_nick("[abc]`"));
        assert!(!valid_nick("1abc")); // can't start with a digit
        assert!(!valid_nick(""));
        assert!(valid_chan("#argentina"));
        assert!(!valid_chan("argentina"));
        assert!(!valid_chan("#a b"));
    }

    #[test]
    fn idle_check_pings_then_times_out() {
        let mut s = srv();
        add_user(&mut s, 1, "ann"); // registered, last_active = 0
        let now = 1000;
        let (ping, quit) = s.idle_check(now);
        assert_eq!(ping, vec![1]); // idle -> PING
        assert!(quit.is_empty());

        s.users.get_mut(&1).unwrap().ping_sent = true;
        let (ping, quit) = s.idle_check(now);
        assert!(ping.is_empty()); // already pinged
        assert_eq!(quit, vec![1]); // no reply -> ping timeout

        s.users.get_mut(&1).unwrap().ping_sent = false;
        s.users.get_mut(&1).unwrap().last_active = now;
        let (ping, quit) = s.idle_check(now);
        assert!(ping.is_empty() && quit.is_empty()); // active -> left alone

        s.users.get_mut(&1).unwrap().registered = false;
        s.users.get_mut(&1).unwrap().last_active = 0;
        let (_, quit) = s.idle_check(now);
        assert_eq!(quit, vec![1]); // unregistered + idle -> registration timeout
    }
}
