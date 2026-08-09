//! Users: the `User` record plus nick handling, user modes, oper status and the
//! registration/welcome burst — the same job InspIRCd splits across users/
//! usermanager, written from scratch in Rust (InspIRCd is a behaviour reference).

use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream};

use crate::extensible::Extensible;
use crate::module::Hook;
use crate::modules::multiline::{MAX_BYTES as MLINE_MAX_BYTES, MAX_LINES as MLINE_MAX_LINES};
use crate::numeric::*;
use crate::server::{Server, VERSION};
use crate::socketengine::OutSink;
use crate::Uid;

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
    pub callerid: bool,       // +g (only accept PMs from users on the ACCEPT list)
    pub showwhois: bool,      // +W (get a notice when someone WHOISes you)
    pub deny_uncommon: bool,  // +c (only users sharing a channel may PM you)
    pub away: Option<String>, // AWAY message, if set
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
        if self.deny_uncommon {
            s.push('c');
        }
        s
    }
}

/// The IRCv3 capabilities echoIRCd advertises. Order = the CAP LS order.
pub const SUPPORTED_CAPS: &[&str] = &[
    "sasl",
    "server-time",
    "message-tags",
    "multi-prefix",
    "away-notify",
    "account-notify",
    "extended-join",
    "chghost",
    "userhost-in-names",
    "echo-message",
    "invite-notify",
    "setname",
    "extended-monitor",
    "account-tag",
    "standard-replies",
    "labeled-response",
    "batch",
    "draft/chathistory",
    "draft/message-redaction",
    "draft/pre-away",
    "draft/metadata-2",
    "draft/multiline",
    "cap-notify",
];

/// Per-connection IRCv3 capability state — echoIRCd's answer to InspIRCd's `m_cap`
/// plus the individual `m_ircv3_*` modules, as one flat set (not a plugin per cap).
/// Toggled by `CAP REQ`; consulted wherever a line is formatted per-client.
#[derive(Default)]
pub struct Caps {
    pub sasl: bool,
    pub server_time: bool,
    pub message_tags: bool,
    pub multi_prefix: bool,
    pub away_notify: bool,
    pub account_notify: bool,
    pub extended_join: bool,
    pub chghost: bool,
    pub userhost_in_names: bool,
    pub echo_message: bool,
    pub invite_notify: bool,
    pub setname: bool,
    pub extended_monitor: bool, // route away/account/chghost/setname for MONITOR targets
    pub account_tag: bool,      // prepend account=<name> tag on messages from logged-in users
    pub standard_replies: bool, // understands FAIL/WARN/NOTE structured replies
    pub labeled_response: bool, // tag responses to a labeled command with its label
    pub batch: bool,            // understands BATCH framing
    pub chathistory: bool,      // draft/chathistory — can request message history
    pub message_redaction: bool, // draft/message-redaction — understands REDACT
    pub pre_away: bool,         // draft/pre-away — may set AWAY before registration
    pub metadata: bool,         // draft/metadata-2 — wants metadata + change notices
    pub multiline: bool,        // draft/multiline — may send multiline message batches
    pub cap_notify: bool,
}

impl Caps {
    pub fn is_known(name: &str) -> bool {
        SUPPORTED_CAPS.contains(&name)
    }

    /// The `CAP LS` token list; `sasl` carries its mechanisms for 302 clients.
    /// EXTERNAL is only offered on TLS connections (it needs a client cert).
    pub fn ls_line(cap302: bool, secure: bool) -> String {
        SUPPORTED_CAPS
            .iter()
            .map(|c| {
                if *c == "sasl" && cap302 {
                    if secure {
                        "sasl=PLAIN,EXTERNAL".to_string()
                    } else {
                        "sasl=PLAIN".to_string()
                    }
                } else if *c == "draft/multiline" && cap302 {
                    format!(
                        "draft/multiline=max-bytes={MLINE_MAX_BYTES},max-lines={MLINE_MAX_LINES}"
                    )
                } else {
                    (*c).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn has(&self, name: &str) -> bool {
        match name {
            "sasl" => self.sasl,
            "server-time" => self.server_time,
            "message-tags" => self.message_tags,
            "multi-prefix" => self.multi_prefix,
            "away-notify" => self.away_notify,
            "account-notify" => self.account_notify,
            "extended-join" => self.extended_join,
            "chghost" => self.chghost,
            "userhost-in-names" => self.userhost_in_names,
            "echo-message" => self.echo_message,
            "invite-notify" => self.invite_notify,
            "setname" => self.setname,
            "extended-monitor" => self.extended_monitor,
            "account-tag" => self.account_tag,
            "standard-replies" => self.standard_replies,
            "labeled-response" => self.labeled_response,
            "batch" => self.batch,
            "draft/chathistory" => self.chathistory,
            "draft/message-redaction" => self.message_redaction,
            "draft/pre-away" => self.pre_away,
            "draft/metadata-2" => self.metadata,
            "draft/multiline" => self.multiline,
            "cap-notify" => self.cap_notify,
            _ => false,
        }
    }

    /// Enable/disable a cap by name; returns whether the name was recognised.
    pub fn set(&mut self, name: &str, on: bool) -> bool {
        let field = match name {
            "sasl" => &mut self.sasl,
            "server-time" => &mut self.server_time,
            "message-tags" => &mut self.message_tags,
            "multi-prefix" => &mut self.multi_prefix,
            "away-notify" => &mut self.away_notify,
            "account-notify" => &mut self.account_notify,
            "extended-join" => &mut self.extended_join,
            "chghost" => &mut self.chghost,
            "userhost-in-names" => &mut self.userhost_in_names,
            "echo-message" => &mut self.echo_message,
            "invite-notify" => &mut self.invite_notify,
            "setname" => &mut self.setname,
            "extended-monitor" => &mut self.extended_monitor,
            "account-tag" => &mut self.account_tag,
            "standard-replies" => &mut self.standard_replies,
            "labeled-response" => &mut self.labeled_response,
            "batch" => &mut self.batch,
            "draft/chathistory" => &mut self.chathistory,
            "draft/message-redaction" => &mut self.message_redaction,
            "draft/pre-away" => &mut self.pre_away,
            "draft/metadata-2" => &mut self.metadata,
            "draft/multiline" => &mut self.multiline,
            "cap-notify" => &mut self.cap_notify,
            _ => return false,
        };
        *field = on;
        true
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
    pub account: Option<String>, // logged-in account name (set by services)
    pub signon: u64,   // unix secs at registration (WHOIS 317)
    pub addr: SocketAddr,
    pub registered: bool,
    pub dns_pending: bool,     // holding registration for a reverse-DNS lookup
    pub deferred: Vec<String>, // handshake lines held while dns_pending (replayed after)
    pub cap: bool,             // CAP negotiation in progress (holds registration)
    pub cap_302: bool,         // client sent CAP LS 302 (cap-notify aware)
    pub caps: Caps,            // enabled IRCv3 capabilities
    pub sasl_mech: Option<String>, // SASL mechanism chosen, mid-handshake
    pub channels: HashSet<String>, // lowercased channel keys
    pub watch: Vec<String>,    // WATCH list — lowercased nicks
    pub monitor: Vec<String>,  // MONITOR list — lowercased nicks
    pub silence: Vec<String>,  // SILENCE masks — nick!user@host globs
    pub accept: Vec<String>,   // ACCEPT list — lowercased nicks (callerid +g)
    pub quitting: Option<String>, // set by QUIT; drained by the core
    pub flags: UserFlags,
    pub last_active: u64, // unix secs of the last line we received
    pub ping_sent: bool,  // a server PING is outstanding
    pub ext: Extensible,  // typed, module-owned per-user metadata
    pub out: OutSink,
    pub sock: Option<TcpStream>, // core-side fd handle; dropped on quit so the
                                 // writer thread flushes then closes (None in tests)
}

impl User {
    /// The host others see: an explicit vhost (CHGHOST/SETHOST) wins, then the
    /// cloak when +x is set (and one was computed), otherwise the real host.
    /// Everything that broadcasts a prefix — JOIN, QUIT, NICK, PRIVMSG source, ban
    /// matching — goes through here, so the displayed host is consistent for free.
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

    /// Grant IRC-operator status and tell the user.
    pub fn oper_up(&mut self, uid: Uid) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.flags.oper = true;
            u.flags.snomask = true; // opers get server notices by default
        }
        let nick = self
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        self.numeric(uid, RPL_YOUREOPER, ":You are now an IRC operator");
        self.send(uid, format!(":{} MODE {nick} :+os", self.name));
        self.snotice(&format!("{nick} is now an IRC operator"));
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
        }
        if registered {
            let line = format!(":{prefix} NICK :{newnick}");
            let mut targets: HashSet<Uid> = HashSet::new();
            targets.insert(uid);
            let chans: Vec<String> = self.users[&uid].channels.iter().cloned().collect();
            for key in &chans {
                if let Some(ch) = self.channels.get(key) {
                    for &m in ch.members.keys() {
                        targets.insert(m);
                    }
                }
            }
            for t in targets {
                self.send(t, line.clone());
            }
            // WATCH/MONITOR: the old nick is now gone, the new one is here
            self.watch_notify_offline(&old);
            self.watch_notify_online(newnick);
        }
        self.propagate_nick(uid, newnick); // tell linked servers
    }

    /// Finish registration: send the welcome burst + MOTD and queue the connect
    /// hook. The core calls this once NICK, USER and CAP are all satisfied.
    pub fn welcome(&mut self, uid: Uid) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.registered = true;
        }
        let nick = self
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        self.numeric(
            uid,
            RPL_WELCOME,
            &format!(":Welcome to the {} IRC Network, {nick}", self.network),
        );
        self.numeric(
            uid,
            RPL_YOURHOST,
            &format!(":Your host is {}, running echoircd-{VERSION}", self.name),
        );
        self.numeric(
            uid,
            RPL_CREATED,
            &format!(":This server was created at unix {}", self.created),
        );
        self.numeric(
            uid,
            RPL_MYINFO,
            &format!(
                "{} echoircd-{VERSION} iowxsgBDIHrRzWc qaohvbeIklimnpstzCTcSNORMfjFLgGuBQAPJ",
                self.name
            ),
        );
        self.numeric(
            uid,
            RPL_ISUPPORT,
            &format!(
                "CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beIg,k,lfjFLHBJ,ACGMNOPQRSTcimnpstuz EXTBAN=,cmn WATCH=128 MONITOR=128 SILENCE=32 CALLERID=g WHOX CHATHISTORY=256 MSGREFTYPES=timestamp,msgid UTF8ONLY CASEMAPPING=ascii NICKLEN=30 CHANNELLEN=50 NETWORK={} :are supported by this server",
                self.network
            ),
        );
        self.numeric(
            uid,
            RPL_LUSERCLIENT,
            &format!(":There are {} users on 1 server", self.users.len()),
        );
        self.send_motd(uid);
        self.watch_notify_online(&nick); // tell WATCH/MONITOR watchers
        self.events.push_back(Hook::Connect(uid));
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

pub fn valid_nick(n: &str) -> bool {
    let special = |c: char| "[]\\`_^{}|".contains(c);
    let mut chars = n.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || special(c) => {}
        _ => return false,
    }
    n.len() <= 30
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
        assert!(Caps::ls_line(true, false).contains("sasl=PLAIN")); // 302 shows mechs
        assert!(!Caps::ls_line(true, false).contains("EXTERNAL")); // plaintext: no EXTERNAL
        assert!(Caps::ls_line(true, true).contains("sasl=PLAIN,EXTERNAL")); // TLS offers it
        assert!(
            Caps::ls_line(false, false).contains("sasl")
                && !Caps::ls_line(false, false).contains("sasl=")
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
