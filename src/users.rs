//! Users: the `User` record plus nick handling, user modes, oper status and the
//! registration/welcome burst.

use crate::map::HashSet;
use std::net::{SocketAddr, TcpStream};

use crate::extensible::Extensible;
use crate::module::Hook;
use crate::numeric::*;
use crate::server::{Server, RELEASE};
use crate::socketengine::OutSink;
use crate::Uid;

/// Snomask category letters an oper subscribes to (the standard set): a announce,
/// c connect, d dnsbl, f filter, g globops, j chancreate, k kill, l link, n nick,
/// o oper, q quit, r rehash, t stats, u acctreg, v override, w gateway, x xline.
/// Opers get all of them by default and narrow with `+s -c` etc.
pub const DEFAULT_SNOMASK: &str = "acdfgjklnoqrtuvwx";

/// User modes and session flags. Kept in one `Default` bag so adding a mode
/// doesn't ripple through every `User { .. }` constructor.
#[derive(Default)]
pub struct UserFlags {
    pub oper: bool,           // +o (granted by OPER only)
    pub invisible: bool,      // +i
    pub wallops: bool,        // +w (receives WALLOPS)
    pub cloak: bool,          // +x (host cloak shown; see modules::cloak)
    pub bot: bool,            // +B (marked as a bot; WHOIS 335)
    pub deaf: bool,           // +D (doesn't receive channel messages)
    pub hidechans: bool,      // +I (channels hidden in WHOIS)
    pub hideoper: bool,       // +H (oper status hidden in WHOIS)
    pub logged_in: bool,      // +r (logged into an account; services-managed)
    pub reg_only_pm: bool,    // +R (only accept PMs from logged-in users)
    pub ssl_pm: bool,         // +z (only accept PMs from TLS users)
    pub snomask: bool,        // +s (oper: receive server notices)
    pub snomask_cats: String, // +s snomask category letters this oper is subscribed to
    pub callerid: bool,       // +g (only accept PMs from users on the ACCEPT list)
    pub showwhois: bool,      // +W (get a notice when someone WHOISes you)
    pub helpop: bool,         // +h (helpop: available for help; shown in WHOIS)
    pub deny_uncommon: bool,  // +c (only users sharing a channel may PM you)
    pub nick_locked: bool,    // NICKLOCK: services/oper holds this nick (no self-change)
    pub servprotect: bool,    // +k (services-only: can't be KILLed/KICKed/SA-commanded)
    pub via_webirc: bool,     // connected through a WEBIRC gateway (securitygroups)
    pub via_websocket: bool,  // connected over the WebSocket transport (ws://, wss://)
    pub away: Option<String>, // AWAY message, if set
    // anti-abuse session state (not IRC modes): kept here so it defaults in every
    // constructor. See modules::targetlimit and the AWAY throttle.
    pub recent_targets: Vec<u64>, // MRU hashes of recent PRIVMSG/NOTICE targets
    pub target_credit: u64,       // token-bucket "not-before" secs for a new target
    pub last_away: u64,           // secs of the last AWAY change (away throttle)
}

impl UserFlags {
    pub fn umodes(&self) -> String {
        let mut s = String::from("+");
        if self.invisible {
            s.push('i');
        }
        if self.wallops {
            s.push('w');
        }
        if self.oper {
            s.push('o');
        }
        if self.cloak {
            s.push('x');
        }
        if self.bot {
            s.push('B');
        }
        if self.servprotect {
            s.push('k');
        }
        if self.deaf {
            s.push('D');
        }
        if self.hidechans {
            s.push('I');
        }
        if self.hideoper {
            s.push('H');
        }
        if self.logged_in {
            s.push('r');
        }
        if self.reg_only_pm {
            s.push('R');
        }
        if self.ssl_pm {
            s.push('z');
        }
        if self.snomask {
            s.push('s');
        }
        if self.callerid {
            s.push('g');
        }
        if self.showwhois {
            s.push('W');
        }
        if self.helpop {
            s.push('h');
        }
        if self.deny_uncommon {
            s.push('c');
        }
        s
    }
}

/// Declare every advertised capability exactly once — the CAP LS token and the
/// `Caps` bool field it toggles — and derive `SUPPORTED_CAPS`, the `Caps` struct,
/// and `has`/`set` from that single list. This makes "advertised but not wired up"
/// (or a field with no token) a compile error rather than a silent bug.
macro_rules! define_caps {
    ($($tok:literal => $field:ident),+ $(,)?) => {
        /// The IRCv3 capabilities advertised, in CAP LS order.
        pub const SUPPORTED_CAPS: &[&str] = &[$($tok),+];

        /// Per-connection IRCv3 capability state, one bool per advertised cap;
        /// toggled by `CAP REQ`, consulted wherever a line is formatted per-client.
        #[derive(Default)]
        pub struct Caps {
            $(pub $field: bool,)+
        }

        impl Caps {
            /// Whether `name` is currently enabled on this connection.
            pub fn has(&self, name: &str) -> bool {
                match name {
                    $($tok => self.$field,)+
                    _ => false,
                }
            }
            /// Enable/disable a cap by name; returns whether the name was recognised.
            pub fn set(&mut self, name: &str, on: bool) -> bool {
                match name {
                    $($tok => { self.$field = on; true })+
                    _ => false,
                }
            }
        }
    };
}

define_caps! {
    "sasl" => sasl,
    "server-time" => server_time,
    "message-tags" => message_tags,
    "multi-prefix" => multi_prefix,
    "away-notify" => away_notify,
    "account-notify" => account_notify,
    "extended-join" => extended_join,
    "chghost" => chghost,
    "userhost-in-names" => userhost_in_names,
    "echo-message" => echo_message,
    "invite-notify" => invite_notify,
    "setname" => setname,
    "extended-monitor" => extended_monitor,
    "account-tag" => account_tag,
    "standard-replies" => standard_replies,
    "labeled-response" => labeled_response,
    "batch" => batch,
    "draft/chathistory" => chathistory,
    "draft/event-playback" => event_playback,
    "draft/message-redaction" => message_redaction,
    "draft/pre-away" => pre_away,
    "draft/metadata-2" => metadata,
    "draft/multiline" => multiline,
    "draft/account-registration" => acct_registration,
    "draft/json-log" => json_log,
    "draft/metrics" => metrics,
    "echoircd/e2e" => e2e,
    "draft/extended-isupport" => ext_isupport,
    "reverse.im/filehost" => filehost,
    "draft/relaymsg" => relaymsg,
    "draft/channel-rename" => channel_rename,
    "draft/read-marker" => read_marker,
    "draft/webpush" => webpush,
    "no-implicit-names" => no_implicit_names,
    "cap-notify" => cap_notify,
}

impl Caps {
    pub fn is_known(name: &str) -> bool {
        SUPPORTED_CAPS.contains(&name)
    }

    /// The `CAP LS` token list; `sasl` carries its mechanisms for 302 clients.
    /// EXTERNAL is only offered on TLS connections (it needs a client cert).
    /// `mline_bytes`/`mline_lines` are the (config-driven) draft/multiline limits.
    pub fn ls_line(
        cap302: bool,
        secure: bool,
        acctreg: &str,
        mline_bytes: usize,
        mline_lines: usize,
    ) -> String {
        SUPPORTED_CAPS
            .iter()
            .map(|c| {
                if *c == "sasl" && cap302 {
                    if secure {
                        "sasl=PLAIN,EXTERNAL,SCRAM-SHA-256,ECDSA-NIST256P-CHALLENGE".to_string()
                    } else {
                        "sasl=PLAIN,SCRAM-SHA-256,ECDSA-NIST256P-CHALLENGE".to_string()
                    }
                } else if *c == "draft/multiline" && cap302 {
                    format!("draft/multiline=max-bytes={mline_bytes},max-lines={mline_lines}")
                } else if *c == "draft/account-registration" && cap302 && !acctreg.is_empty() {
                    format!("draft/account-registration={acctreg}")
                } else {
                    (*c).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Space-separated list of the currently-enabled caps (for `CAP LIST`).
    pub fn enabled(&self) -> String {
        SUPPORTED_CAPS
            .iter()
            .filter(|c| self.has(c))
            .copied()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct User {
    pub uid: Uid,
    pub uuid: String,  // network-wide id (SID + 6) for S2S
    pub nick: String,  // "" until NICK
    pub ident: String, // "" until USER
    pub realname: String,
    pub host: String,  // displayed host: reverse-DNS name if resolved, else IP
    pub cloak: String, // masked host shown under +x ("" until computed)
    pub vhost: Option<String>, // displayed-host override (CHGHOST/SETHOST vhost)
    pub secure: bool,  // connected over TLS (drives WHOIS 671 / sslinfo)
    pub certfp: Option<String>, // TLS client-cert fingerprint (SASL EXTERNAL / CertFP)
    pub tls_info: Option<String>, // negotiated TLS version/group/cipher (WHOIS 671)
    pub sni: Option<String>, // TLS SNI hostname the client requested (connect notice)
    pub brand_server: Option<String>, // per-SNI display server name (None = global)
    pub brand_network: Option<String>, // per-SNI display network name (None = global)
    pub account: Option<String>, // logged-in account name (set by services)
    pub signon: u64,   // unix secs at registration (WHOIS 317)
    pub nick_ts: u64,  // unix secs the current nick was taken (nick-collision arbitration)
    pub addr: SocketAddr,
    pub port: u16, // listener port the client connected to (connectclass port=, ident)
    pub registered: bool,
    pub dns_pending: bool,   // holding registration for a reverse-DNS lookup
    pub ident_pending: bool, // holding registration for an ident (RFC1413) lookup
    pub auth_pending: bool,  // holding registration for an off-core connect-class password verify
    pub waitpong: Option<String>, // conn_waitpong: cookie the client must PONG before registering
    pub class: Option<String>, // connectclass: assigned connection class name
    pub pass: Option<String>, // password sent via PASS (for connectclass passwords)
    pub deferred: Vec<String>, // handshake lines held while dns_pending (replayed after)
    pub cap: bool,           // CAP negotiation in progress (holds registration)
    pub cap_302: bool,       // client sent CAP LS 302 (cap-notify aware)
    pub caps: Caps,          // enabled IRCv3 capabilities
    pub sasl_mech: Option<String>, // SASL mechanism chosen, mid-handshake
    pub channels: HashSet<String>, // lowercased channel keys
    pub invited: HashSet<String>, // channels this user has a pending +i invite to (reverse index)
    pub watch: Vec<String>,  // WATCH list — lowercased nicks
    pub monitor: Vec<String>, // MONITOR list — lowercased nicks
    pub silence: Vec<String>, // SILENCE masks — nick!user@host globs
    pub signore: Vec<String>, // SIGNORE masks — mutual server-side ignore (both ways)
    pub accept: Vec<String>, // ACCEPT list — lowercased nicks (callerid +g)
    pub quitting: Option<String>, // set by QUIT; drained by the core
    pub flags: UserFlags,
    pub last_active: u64, // unix secs of the last line received (liveness / ping sweep)
    pub last_msg: u64,    // unix secs of the last PRIVMSG/NOTICE sent (WHOIS 317 idle clock)
    pub ping_sent: bool,  // a server PING is outstanding
    pub ext: Extensible,  // typed, module-owned per-user metadata
    pub out: OutSink,
    pub sock: Option<TcpStream>, // core-side fd handle; dropped on quit so the
                                 // writer thread flushes then closes (None in tests)
}

impl User {
    /// Displayed host: explicit vhost (CHGHOST/SETHOST), else cloak (when +x and
    /// one was computed), else real host. Used everywhere a prefix is broadcast so
    /// the shown host stays consistent.
    pub fn host_display(&self) -> &str {
        if let Some(v) = &self.vhost {
            v
        } else if self.flags.cloak && !self.cloak.is_empty() {
            &self.cloak
        } else {
            &self.host
        }
    }

    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.ident, self.host_display())
    }
}

impl Server {
    pub fn find_nick(&self, nick: &str) -> Option<Uid> {
        self.nick_index.get(&nick.to_ascii_lowercase()).copied()
    }

    pub fn is_oper(&self, uid: Uid) -> bool {
        self.users.get(&uid).map(|u| u.flags.oper).unwrap_or(false)
    }

    /// Emit the full LUSERS block (251–255, 265, 266). Called on registration and by LUSERS.
    pub fn send_lusers(&mut self, uid: Uid) {
        let global = self.users.values().filter(|u| u.registered).count();
        let invisible = self
            .users
            .values()
            .filter(|u| u.registered && u.flags.invisible)
            .count();
        let opers = self
            .users
            .values()
            .filter(|u| u.registered && u.flags.oper)
            .count();
        let unknown = self.users.values().filter(|u| !u.registered).count();
        let local = self
            .users
            .values()
            .filter(|u| u.registered && u.uuid.starts_with(self.sid.as_str()))
            .count();
        let channels = self.channels.len();
        let servers = self.servers.len();
        self.max_local = self.max_local.max(local);
        self.max_global = self.max_global.max(global);

        let (g, inv, ns) = (
            global.to_string(),
            invisible.to_string(),
            (servers + 1).to_string(),
        );
        let m = self.trf(
            "There are {0} users and {1} invisible on {2} servers",
            &[g.as_str(), inv.as_str(), ns.as_str()],
        );
        self.numeric(uid, RPL_LUSERCLIENT, &format!(":{m}"));

        let o = opers.to_string();
        let m = self.trf("{0} :operator(s) online", &[o.as_str()]);
        self.numeric(uid, RPL_LUSEROP, &m);

        let uk = unknown.to_string();
        let m = self.trf("{0} :unknown connection(s)", &[uk.as_str()]);
        self.numeric(uid, RPL_LUSERUNKNOWN, &m);

        let ch = channels.to_string();
        let m = self.trf("{0} :channels formed", &[ch.as_str()]);
        self.numeric(uid, RPL_LUSERCHANNELS, &m);

        let (lc, sv) = (local.to_string(), servers.to_string());
        let m = self.trf("I have {0} clients and {1} servers", &[lc.as_str(), sv.as_str()]);
        self.numeric(uid, RPL_LUSERME, &format!(":{m}"));

        let (l, ml) = (local.to_string(), self.max_local.to_string());
        let m = self.trf("Current local users {0}, max {1}", &[l.as_str(), ml.as_str()]);
        self.numeric(uid, RPL_LOCALUSERS, &format!("{l} {ml} :{m}"));

        let (gg, mg) = (global.to_string(), self.max_global.to_string());
        let m = self.trf("Current global users {0}, max {1}", &[gg.as_str(), mg.as_str()]);
        self.numeric(uid, RPL_GLOBALUSERS, &format!("{gg} {mg} :{m}"));
    }

    /// Whether the user `uid` is servprotected (+k) — a service that must not be
    /// KILLed / KICKed / SA-commanded.
    pub fn uid_servprotected(&self, uid: Uid) -> bool {
        self.users
            .get(&uid)
            .map(|u| u.flags.servprotect)
            .unwrap_or(false)
    }

    /// Whether the nick `n` (local user or a remote services pseudo-client) is
    /// servprotected (+k). Remote users carry their modes as a letter string.
    pub fn nick_servprotected(&self, n: &str) -> bool {
        if let Some(uid) = self.find_nick(n) {
            return self.uid_servprotected(uid);
        }
        self.find_remote(n)
            .and_then(|(uuid, _)| self.remote_users.get(&uuid))
            .map(|ru| ru.modes.contains('k'))
            .unwrap_or(false)
    }

    /// Grant IRC-operator status and tell the user.
    pub fn oper_up(&mut self, uid: Uid) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.flags.oper = true;
            u.flags.snomask = true; // opers get server notices by default
            u.flags.snomask_cats = DEFAULT_SNOMASK.to_string(); // all categories
        }
        let nick = self
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        self.numeric(uid, RPL_YOUREOPER, ":You are now an IRC operator");
        self.send(uid, format!(":{} MODE {nick} :+os", self.name));
        let m = self.trf("{0} is now an IRC operator", &[nick.as_str()]);
        self.snotice_c('o', &m);
        if crate::redis::active(self) {
            let mask = self
                .users
                .get(&uid)
                .map(|u| format!("{}@{}", u.ident, u.host_display()))
                .unwrap_or_default();
            crate::redis::publish_event(self, &["oper", nick.as_str(), mask.as_str()]);
        }
        // operprefix: give this oper the ! prefix in every channel they're already in
        crate::modules::operprefix::grant_all(self, uid);
        // opermodes: extra umodes on oper-up
        let om = self.conf("opermodes").or_else(|| self.conf("oper_umodes"));
        if let Some(modes) = om.map(str::to_string) {
            crate::coremods::core_mode::svs_set_user_modes(self, uid, &modes);
        }
        // operjoin: auto-join configured oper channels
        let chans: Vec<String> = self
            .conf_all("operjoin")
            .iter()
            .flat_map(|v| v.split([',', ' ']).map(str::to_string))
            .filter(|c| !c.is_empty())
            .collect();
        for chan in chans {
            self.join(uid, &chan, None);
        }
        // tell services / linked servers this user is now an operator, so services
        // (OperServ etc.) can track and act on network operators.
        if !self.links.is_empty() {
            if let Some(uuid) = self.users.get(&uid).map(|u| u.uuid.clone()) {
                self.propagate(&format!(":{uuid} OPERTYPE :IRC_Operator"), None);
            }
        }
    }

    /// Send a WALLOPS to every oper and every +w user.
    pub fn wallops(&self, from: &str, text: &str) {
        let line = format!(":{from} WALLOPS :{text}");
        let targets: Vec<Uid> = self
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper || u.flags.wallops)
            .map(|(&uid, _)| uid)
            .collect();
        for uid in targets {
            self.send(uid, line.clone());
        }
    }

    /// Set or change a user's nick, keeping the index in sync and broadcasting
    /// the change to the user + everyone in their channels once registered.
    pub fn set_nick(&mut self, uid: Uid, newnick: &str) {
        let (old, registered, prefix, ident, host, realname, account) = match self.users.get(&uid) {
            Some(u) => (
                u.nick.clone(),
                u.registered,
                u.prefix(),
                u.ident.clone(),
                u.host_display().to_string(),
                u.realname.clone(),
                u.account.clone(),
            ),
            None => return,
        };
        if registered {
            self.push_whowas(&old, &ident, &host, &realname, account);
        }
        if !old.is_empty() {
            self.nick_index.remove(&old.to_ascii_lowercase());
        }
        self.nick_index.insert(newnick.to_ascii_lowercase(), uid);
        if let Some(u) = self.users.get_mut(&uid) {
            u.nick = newnick.to_string();
            u.nick_ts = crate::server::now();
        }
        // Keep +g callerid ACCEPT lists in step: move the entry from the old nick to
        // the new one, so the freed old nick can't be grabbed to bypass someone's gate.
        let (oldlow, newlow) = (old.to_ascii_lowercase(), newnick.to_ascii_lowercase());
        if !old.is_empty() && oldlow != newlow {
            for u in self.users.values_mut() {
                for n in u.accept.iter_mut() {
                    if *n == oldlow {
                        *n = newlow.clone();
                    }
                }
            }
            // carry the accepted-nick reverse count across the rename (the number of
            // acceptors doesn't change when the accepted user renames), so the
            // count-gated quit scrub stays correct — otherwise a reused old nick could
            // inherit acceptance and bypass +g, and the old-nick count would leak.
            if let Some(c) = self.accepted_nicks.remove(&oldlow) {
                *self.accepted_nicks.entry(newlow.clone()).or_insert(0) += c;
            }
        }
        if registered {
            let line = format!(":{prefix} NICK :{newnick}");
            let mut targets: HashSet<Uid> = HashSet::default();
            targets.insert(uid);
            let chans: Vec<String> = self.users[&uid].channels.iter().cloned().collect();
            for key in &chans {
                crate::modules::chathistory::record_event(self, key, &line);
                if let Some(ch) = self.channels.get(key) {
                    // +D delayjoin: a still-hidden member's NICK isn't shown here
                    if ch.members.get(&uid).map(|m| m.hidden).unwrap_or(false) {
                        continue;
                    }
                    for &m in ch.members.keys() {
                        targets.insert(m);
                    }
                }
            }
            for t in targets {
                self.send(t, line.clone());
            }
            if self.conf_bool("seenicks", false) {
                let m = self.trf("{0} is now known as {1}", &[old.as_str(), newnick]);
                self.snotice_c('n', &m);
            }
            // WATCH/MONITOR: the old nick is now gone, the new one is here
            self.watch_notify_offline(&old);
            self.watch_notify_online(newnick);
            if crate::redis::active(self) {
                crate::redis::publish_event(self, &["nick", old.as_str(), newnick]);
            }
        }
        self.propagate_nick(uid, newnick); // tell linked servers
    }

    /// Finish registration: send the welcome burst + MOTD and queue the connect
    /// hook. The core calls this once NICK, USER and CAP are all satisfied.
    pub fn welcome(&mut self, uid: Uid) {
        let was_unreg = self.users.get(&uid).map(|u| !u.registered).unwrap_or(false);
        if let Some(u) = self.users.get_mut(&uid) {
            u.registered = true;
        }
        if was_unreg {
            crate::connguard::note_registered(self); // left the unregistered pool
        }
        self.metrics
            .connects
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nick = self
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let net = self.disp_network(uid).to_string();
        let welcome = self.trf(
            "Welcome to the {0} IRC Network, {1}",
            &[net.as_str(), nick.as_str()],
        );
        self.numeric(uid, RPL_WELCOME, &format!(":{welcome}"));
        let host = self.disp_name(uid).to_string();
        let yourhost = self.trf(
            "Your host is {0}, running echoircd-{1}",
            &[host.as_str(), RELEASE],
        );
        self.numeric(uid, RPL_YOURHOST, &format!(":{yourhost}"));
        let created = self.created.to_string();
        let created_msg = self.trf("This server was created at unix {0}", &[created.as_str()]);
        self.numeric(uid, RPL_CREATED, &format!(":{created_msg}"));
        self.numeric(
            uid,
            RPL_MYINFO,
            &format!(
                "{} echoircd-{RELEASE} iowxsgBkDIHrRzWhc qaohvbeIklimnpstzCTcSNORMfjFLgGuBQAPJUdKXwDE",
                self.disp_name(uid)
            ),
        );
        // ISUPPORT (005): the fixed set + config-driven module tokens (ICON/FILEHOST).
        // draft/extended-isupport + batch clients get it wrapped in a draft/isupport batch.
        let batched = self
            .users
            .get(&uid)
            .map(|u| u.caps.ext_isupport && u.caps.batch)
            .unwrap_or(false);
        self.send_isupport(uid, batched);
        self.send_lusers(uid);
        self.send_motd(uid);
        // connbanner: NOTICE lines to every connecting client
        for line in self.conf_all("connbanner").to_vec() {
            self.send(uid, format!(":{} NOTICE {nick} :{line}", self.name));
        }
        // conn_umodes: auto-set user modes on connect
        let auto_umodes = self.conf("conn_umodes").or_else(|| self.conf("autoumodes"));
        if let Some(modes) = auto_umodes.map(str::to_string) {
            crate::coremods::core_mode::svs_set_user_modes(self, uid, &modes);
        }
        self.watch_notify_online(&nick); // tell WATCH/MONITOR watchers
        self.events.push_back(Hook::Connect(uid));
        // redis event bus: announce the new client (no-op when redis is off)
        if crate::redis::active(self) {
            let who = self
                .users
                .get(&uid)
                .map(|u| (u.ident.clone(), u.host_display().to_string(), u.addr.ip().to_string()));
            if let Some((id, host, ip)) = who {
                let mask = format!("{id}@{host}");
                crate::redis::publish_event(self, &["connect", nick.as_str(), mask.as_str(), ip.as_str()]);
            }
        }
        // conn_join: auto-join configured channels (comma/space separated, repeatable)
        let chans: Vec<String> = self
            .conf_all("autojoin")
            .iter()
            .chain(self.conf_all("conn_join"))
            .flat_map(|v| v.split([',', ' ']).map(str::to_string))
            .filter(|c| !c.is_empty())
            .collect();
        for chan in chans {
            self.join(uid, &chan, None);
        }
    }

    pub fn send_motd(&self, uid: Uid) {
        if self.motd.is_empty() {
            self.numeric(uid, ERR_NOMOTD, ":MOTD File is missing");
            return;
        }
        self.numeric(
            uid,
            RPL_MOTDSTART,
            &format!(":- {} Message of the day -", self.name),
        );
        for line in &self.motd {
            self.numeric(uid, RPL_MOTD, &format!(":- {line}"));
        }
        self.numeric(uid, RPL_ENDOFMOTD, ":End of /MOTD command.");
    }
}

/// A nick is 1–30 chars: first is a letter or `[]\`_^{}|`, rest add digits/`-`.
/// A syntactically valid hostname for CHGHOST/SETHOST: letters, digits, `.` `-`
/// `_` `/` (the last two allowed for cloak-style vhosts), 1..=64 chars.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 64
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/'))
}

/// A syntactically valid ident/username for CHGIDENT/SETIDENT.
pub fn valid_ident(i: &str) -> bool {
    !i.is_empty()
        && i.len() <= 20
        && i.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub fn valid_nick(n: &str, maxlen: usize) -> bool {
    let special = |c: char| "[]\\`_^{}|".contains(c);
    let mut chars = n.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || special(c) => {}
        _ => return false,
    }
    n.len() <= maxlen
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || special(c) || c == '-')
}

/// Turn a USER-supplied username into a safe ident (≤ 10 chars, no funny bytes).
pub fn ident_of(user: &str) -> String {
    let s: String = user
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(10)
        .collect();
    if s.is_empty() {
        "user".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_set_has_enabled_and_ls() {
        let mut c = Caps::default();
        assert!(c.set("server-time", true));
        assert!(c.set("multi-prefix", true));
        assert!(!c.set("bogus-cap", true)); // unknown cap rejected
        assert!(c.has("server-time") && c.has("multi-prefix") && !c.has("sasl"));
        assert_eq!(c.enabled(), "server-time multi-prefix"); // SUPPORTED order
        assert!(Caps::ls_line(true, false, "", 4096, 24).contains("sasl=PLAIN")); // 302 shows mechs
        assert!(!Caps::ls_line(true, false, "", 4096, 24).contains("EXTERNAL")); // plaintext: no EXTERNAL
        assert!(Caps::ls_line(true, true, "", 4096, 24).contains("sasl=PLAIN,EXTERNAL")); // TLS offers it
                                                                                          // SCRAM-SHA-256 is offered on both transports (challenge-response, no wire password)
        assert!(Caps::ls_line(true, false, "", 4096, 24).contains("SCRAM-SHA-256"));
        assert!(Caps::ls_line(true, true, "", 4096, 24).contains("SCRAM-SHA-256"));
        assert!(
            Caps::ls_line(false, false, "", 4096, 24).contains("sasl")
                && !Caps::ls_line(false, false, "", 4096, 24).contains("sasl=")
        );
        c.set("server-time", false);
        assert!(!c.has("server-time"));
    }

    #[test]
    fn host_ident_validators() {
        assert!(valid_host("cloaked-a1b2.users.echo"));
        assert!(valid_host("some/vhost"));
        assert!(!valid_host("bad host")); // space
        assert!(!valid_host("")); // empty
        assert!(!valid_host(&"x".repeat(65))); // too long
        assert!(valid_ident("reverse"));
        assert!(!valid_ident("re verse")); // space
        assert!(!valid_ident("")); // empty
    }
}
