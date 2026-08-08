//! core_user — the client registration & session commands: CAP, NICK, USER,
//! PING, PONG, QUIT.

use std::net::{IpAddr, SocketAddr};

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::Server;
use crate::users::{ident_of, valid_nick, Caps};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Cap),
        Box::new(Authenticate),
        Box::new(Nick),
        Box::new(UserCmd),
        Box::new(Ping),
        Box::new(Pong),
        Box::new(Quit),
        Box::new(Away),
        Box::new(SetName),
        Box::new(WebIrc),
    ]
}

/// WEBIRC — a trusted web gateway declares the real client's host + IP, so users
/// behind it don't all share the gateway's address. `WEBIRC <password> <gateway>
/// <hostname> <ip> [:flags]`; must precede registration and the password must
/// match a `webirc` config block. (Password-only trust for now — restricting it
/// to the gateway's own source IP is a TODO.)
struct WebIrc;
impl Command for WebIrc {
    fn name(&self) -> &'static str {
        "WEBIRC"
    }
    fn min_params(&self) -> usize {
        4
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if s.users.get(&uid).map(|u| u.registered).unwrap_or(false) {
            return CmdResult::Fail; // can't re-spoof a registered session
        }
        let (pass, host, ip) = (&params[0], &params[2], &params[3]);
        // the gateway's own connecting IP (before we spoof it below)
        let from = s
            .users
            .get(&uid)
            .map(|u| u.addr.ip().to_string())
            .unwrap_or_default();
        let Some(gw) = s
            .webirc
            .iter()
            .find(|(p, _, mask)| p == pass && (mask.is_empty() || glob_match(mask, &from)))
            .map(|(_, g, _)| g.clone())
        else {
            s.notice_star(uid, "WEBIRC: invalid credentials");
            return CmdResult::Fail;
        };
        let newip = ip.parse::<IpAddr>().ok();
        if let Some(u) = s.users.get_mut(&uid) {
            u.host = host.clone();
            if let Some(a) = newip {
                u.addr = SocketAddr::new(a, u.addr.port());
            }
        }
        s.notice_star(uid, &format!("WEBIRC identity accepted via {gw}"));
        CmdResult::Ok
    }
}

struct Away;
impl Command for Away {
    fn name(&self) -> &'static str {
        "AWAY"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let msg = params.first().cloned().filter(|m| !m.is_empty());
        let now_away = msg.is_some();
        let prefix = match s.users.get_mut(&uid) {
            Some(u) => {
                u.flags.away = msg.clone();
                u.prefix()
            }
            None => return CmdResult::Fail,
        };
        // away-notify: tell capable peers we went away / came back
        let line = match &msg {
            Some(m) => format!(":{prefix} AWAY :{m}"),
            None => format!(":{prefix} AWAY"),
        };
        s.notify_peers(uid, &line, |c| c.away_notify);
        if now_away {
            s.numeric(uid, RPL_NOWAWAY, ":You have been marked as being away");
        } else {
            s.numeric(uid, RPL_UNAWAY, ":You are no longer marked as being away");
        }
        CmdResult::Ok
    }
}

struct Cap;
impl Command for Cap {
    fn name(&self) -> &'static str {
        "CAP"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let who = cap_target(s, uid);
        match params[0].to_ascii_uppercase().as_str() {
            "LS" => {
                let cap302 = params.get(1).map(|v| v == "302").unwrap_or(false);
                let secure = s.users.get(&uid).map(|u| u.secure).unwrap_or(false);
                if let Some(u) = s.users.get_mut(&uid) {
                    u.cap = true; // hold registration until CAP END
                    u.cap_302 |= cap302;
                }
                let mut caps = Caps::ls_line(cap302, secure);
                if let Some(sts) = s.sts_token(secure) {
                    caps.push(' ');
                    caps.push_str(&sts); // IRCv3 STS — advertised, not REQ-able
                }
                s.send(uid, format!(":{} CAP {who} LS :{caps}", s.name));
            }
            "REQ" => {
                if let Some(u) = s.users.get_mut(&uid) {
                    u.cap = true;
                }
                let req = params.get(1).cloned().unwrap_or_default();
                let wanted: Vec<(&str, bool)> = req
                    .split_whitespace()
                    .map(|t| match t.strip_prefix('-') {
                        Some(rest) => (rest, false),
                        None => (t, true),
                    })
                    .collect();
                // CAP REQ is atomic: ACK the whole set or NAK the whole set
                if !wanted.is_empty() && wanted.iter().all(|(n, _)| Caps::is_known(n)) {
                    for (name, on) in &wanted {
                        if let Some(u) = s.users.get_mut(&uid) {
                            u.caps.set(name, *on);
                        }
                    }
                    s.send(uid, format!(":{} CAP {who} ACK :{req}", s.name));
                } else {
                    s.send(uid, format!(":{} CAP {who} NAK :{req}", s.name));
                }
            }
            "LIST" => {
                let list = s
                    .users
                    .get(&uid)
                    .map(|u| u.caps.enabled())
                    .unwrap_or_default();
                s.send(uid, format!(":{} CAP {who} LIST :{list}", s.name));
            }
            "END" => {
                if let Some(u) = s.users.get_mut(&uid) {
                    u.cap = false;
                }
            }
            _ => {}
        }
        CmdResult::Ok
    }
}

/// CAP reply target: the nick, or `*` before one is set.
fn cap_target(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .map(|u| {
            if u.nick.is_empty() {
                "*".to_string()
            } else {
                u.nick.clone()
            }
        })
        .unwrap_or_else(|| "*".to_string())
}

/// AUTHENTICATE — the SASL handshake. echoIRCd verifies nothing itself (it has no
/// accounts); once a services server is linked over S2S the payload is relayed to
/// it and `set_login` applied on success. Until then — exactly like InspIRCd with
/// no services — SASL fails cleanly.
struct Authenticate;
impl Command for Authenticate {
    fn name(&self) -> &'static str {
        "AUTHENTICATE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.users.get(&uid).map(|u| u.caps.sasl).unwrap_or(false) {
            s.numeric(
                uid,
                ERR_SASLFAIL,
                ":You must request the sasl capability first",
            );
            return CmdResult::Fail;
        }
        let arg = &params[0];
        let mech = s.users.get(&uid).and_then(|u| u.sasl_mech.clone());
        // SASL is relayed to a linked services server (see `Server::sasl_relay`);
        // with none configured/linked it fails cleanly, exactly like InspIRCd.
        let have_services = s.sasl_link().is_some();
        match mech {
            // step 1 — the client picks a mechanism
            None => {
                if arg == "*" {
                    s.numeric(uid, ERR_SASLABORTED, ":SASL authentication aborted");
                    CmdResult::Ok
                } else if arg.eq_ignore_ascii_case("PLAIN") {
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.sasl_mech = Some("PLAIN".to_string());
                    }
                    if have_services {
                        s.sasl_relay(uid, "S PLAIN"); // start the exchange at services
                    }
                    s.send(uid, "AUTHENTICATE +".to_string());
                    CmdResult::Ok
                } else if arg.eq_ignore_ascii_case("EXTERNAL") {
                    // CertFP: only works on TLS with a client cert; the fingerprint
                    // goes to services, which map it to an account.
                    let certfp = s.users.get(&uid).and_then(|u| u.certfp.clone());
                    match certfp {
                        Some(fp) if have_services => {
                            if let Some(u) = s.users.get_mut(&uid) {
                                u.sasl_mech = Some("EXTERNAL".to_string());
                            }
                            s.sasl_relay(uid, &format!("S EXTERNAL {fp}"));
                            s.send(uid, "AUTHENTICATE +".to_string());
                            CmdResult::Ok
                        }
                        _ => {
                            s.numeric(
                                uid,
                                ERR_SASLFAIL,
                                ":SASL EXTERNAL requires a client certificate",
                            );
                            CmdResult::Fail
                        }
                    }
                } else {
                    s.numeric(uid, RPL_SASLMECHS, "PLAIN :are available SASL mechanisms");
                    s.numeric(uid, ERR_SASLFAIL, ":Unsupported SASL mechanism");
                    CmdResult::Fail
                }
            }
            // step 2 — the client sends the base64 payload (or aborts with `*`)
            Some(_) => {
                if arg == "*" {
                    if have_services {
                        s.sasl_relay(uid, "D A");
                    }
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.sasl_mech = None;
                    }
                    s.numeric(uid, ERR_SASLABORTED, ":SASL authentication aborted");
                    return CmdResult::Ok;
                }
                if arg.len() > 400 {
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.sasl_mech = None;
                    }
                    s.numeric(uid, ERR_SASLTOOLONG, ":SASL message too long");
                    return CmdResult::Fail;
                }
                if have_services {
                    // relay the response; the verdict (900/903 or 904) comes back
                    // over S2S in `Server::link_sasl`, which clears `sasl_mech`.
                    s.sasl_relay(uid, &format!("C {arg}"));
                    CmdResult::Ok
                } else {
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.sasl_mech = None;
                    }
                    s.numeric(
                        uid,
                        ERR_SASLFAIL,
                        ":SASL authentication failed (services are not available)",
                    );
                    CmdResult::Fail
                }
            }
        }
    }
}

/// SETNAME — change your realname (IRCv3). Broadcast to `setname`-capable peers.
struct SetName;
impl Command for SetName {
    fn name(&self) -> &'static str {
        "SETNAME"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let realname = params[0].clone();
        let prefix = match s.users.get_mut(&uid) {
            Some(u) => {
                u.realname = realname.clone();
                u.prefix()
            }
            None => return CmdResult::Fail,
        };
        let line = format!(":{prefix} SETNAME :{realname}");
        if s.users.get(&uid).map(|u| u.caps.setname).unwrap_or(false) {
            s.send(uid, line.clone());
        }
        s.notify_peers(uid, &line, |c| c.setname);
        CmdResult::Ok
    }
}

struct Nick;
impl Command for Nick {
    fn name(&self) -> &'static str {
        "NICK"
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let Some(newnick) = params.first() else {
            s.numeric(uid, ERR_NONICKNAMEGIVEN, ":No nickname given");
            return CmdResult::Fail;
        };
        if !valid_nick(newnick) {
            s.numeric(
                uid,
                ERR_ERRONEUSNICKNAME,
                &format!("{newnick} :Erroneous nickname"),
            );
            return CmdResult::Fail;
        }
        // Q-line: a reserved nick is refused (opers and services bypass)
        if !s.is_oper(uid) {
            if let Some(reason) = s.matched_qline(newnick) {
                s.numeric(
                    uid,
                    ERR_ERRONEUSNICKNAME,
                    &format!("{newnick} :Nickname is reserved: {reason}"),
                );
                return CmdResult::Fail;
            }
        }
        if let Some(other) = s.find_nick(newnick) {
            if other != uid {
                s.numeric(
                    uid,
                    ERR_NICKNAMEINUSE,
                    &format!("{newnick} :Nickname is already in use"),
                );
                return CmdResult::Fail;
            }
            return CmdResult::Ok; // same nick, no-op
        }
        // a nick already held by a user on a linked server is taken too
        if s.remote_nick.contains_key(&newnick.to_ascii_lowercase()) {
            s.numeric(
                uid,
                ERR_NICKNAMEINUSE,
                &format!("{newnick} :Nickname is already in use"),
            );
            return CmdResult::Fail;
        }
        // +N — can't change nick while on a no-nick-change channel (opers bypass)
        if !s.is_oper(uid) {
            let blocked = s
                .users
                .get(&uid)
                .map(|u| u.channels.clone())
                .unwrap_or_default()
                .iter()
                .find_map(|k| {
                    s.channels
                        .get(k)
                        .filter(|c| c.modes.no_nick)
                        .map(|c| c.name.clone())
                });
            if let Some(cn) = blocked {
                s.numeric(
                    uid,
                    ERR_CANTCHANGENICK,
                    &format!("{cn} :Cannot change nick while on this channel (+N is set)"),
                );
                return CmdResult::Fail;
            }
            // extban `n:` — a matched user can't change nick on that channel
            let chans = s
                .users
                .get(&uid)
                .map(|u| u.channels.clone())
                .unwrap_or_default();
            if let Some(k) = chans.into_iter().find(|k| s.extban_active(uid, k, 'n')) {
                let cn = s.channels.get(&k).map(|c| c.name.clone()).unwrap_or(k);
                s.numeric(
                    uid,
                    ERR_CANTCHANGENICK,
                    &format!("{cn} :Cannot change nick here (+b n:)"),
                );
                return CmdResult::Fail;
            }
            // +F nick-change flood — locks nick changes on the channel for 60s
            if let Some(cn) = s.nickflood_blocked(uid) {
                s.numeric(
                    uid,
                    ERR_CANTCHANGENICK,
                    &format!("{cn} :Too many nick changes, try later (+F is set)"),
                );
                return CmdResult::Fail;
            }
        }
        s.set_nick(uid, newnick);
        CmdResult::Ok
    }
}

struct UserCmd;
impl Command for UserCmd {
    fn name(&self) -> &'static str {
        "USER"
    }
    fn min_params(&self) -> usize {
        4
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if s.users.get(&uid).map(|u| u.registered).unwrap_or(false) {
            s.numeric(uid, ERR_ALREADYREGISTERED, ":You may not reregister");
            return CmdResult::Fail;
        }
        let ident = ident_of(&params[0]);
        let realname = params[3].clone();
        if let Some(u) = s.users.get_mut(&uid) {
            u.ident = format!("~{ident}");
            u.realname = realname;
        }
        CmdResult::Ok
    }
}

struct Ping;
impl Command for Ping {
    fn name(&self) -> &'static str {
        "PING"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        s.send(uid, format!(":{} PONG {} :{}", s.name, s.name, params[0]));
        CmdResult::Ok
    }
}

struct Pong;
impl Command for Pong {
    fn name(&self) -> &'static str {
        "PONG"
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, _s: &mut Server, _uid: Uid, _params: &[String]) -> CmdResult {
        CmdResult::Ok // keepalive; nothing to do yet
    }
}

struct Quit;
impl Command for Quit {
    fn name(&self) -> &'static str {
        "QUIT"
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let reason = params
            .first()
            .cloned()
            .unwrap_or_else(|| "Client quit".to_string());
        s.mark_quit(uid, format!("Quit: {reason}"));
        CmdResult::Ok
    }
}
