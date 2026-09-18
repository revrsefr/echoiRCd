//! `JUMPSERVER <host> <port> [:reason]` — redirect new client connections to another
//! server via RPL_REDIR (010), e.g. while draining a node for maintenance.
//! `JUMPSERVER` alone (or `-`) clears it. Loopback is exempt. State in `Server.ext`.

use std::net::IpAddr;

use crate::command::{CmdResult, Command};
use crate::numeric::{ERR_NOPRIVILEGES, RPL_REDIR};
use crate::server::{is_local_ip, Server};
use crate::Uid;

struct Jump {
    host: String,
    port: u16,
    reason: String,
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(JumpServer)]
}

/// If a jump target is set, redirect a new (non-loopback) connection and return true
/// so the caller drops it. Called from `add_conn`.
pub fn redirect(s: &mut Server, uid: Uid, ip: IpAddr) -> bool {
    if is_local_ip(ip) {
        return false;
    }
    let Some((host, port, reason)) = s
        .ext
        .get::<Jump>()
        .map(|j| (j.host.clone(), j.port, j.reason.clone()))
    else {
        return false;
    };
    let name = s.name.clone();
    s.send(uid, format!(":{name} {RPL_REDIR:03} * {host} {port} :{reason}"));
    s.send(
        uid,
        format!("ERROR :Closing link: (Redirected to {host}:{port})"),
    );
    s.remove_user(uid, "Redirected (jumpserver)");
    true
}

fn require_oper(s: &mut Server, uid: Uid) -> bool {
    if s.is_oper(uid) {
        return true;
    }
    s.numeric(
        uid,
        ERR_NOPRIVILEGES,
        ":Permission Denied- You're not an IRC operator",
    );
    false
}

struct JumpServer;
impl Command for JumpServer {
    fn name(&self) -> &'static str {
        "JUMPSERVER"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let name = s.name.clone();
        if params.is_empty() || params[0] == "-" {
            s.ext.take::<Jump>();
            let m = s.trf("JUMPSERVER: {0} cleared the redirect", &[nick.as_str()]);
            s.snotice_c('o', &m);
            s.send(
                uid,
                format!(":{name} NOTICE {nick} :Jumpserver redirect cleared"),
            );
            return CmdResult::Ok;
        }
        if params.len() < 2 {
            s.send(
                uid,
                format!(":{name} NOTICE {nick} :Usage: JUMPSERVER <host> <port> [:reason]"),
            );
            return CmdResult::Fail;
        }
        let Ok(port) = params[1].parse::<u16>() else {
            s.send(uid, format!(":{name} NOTICE {nick} :Invalid port"));
            return CmdResult::Fail;
        };
        let reason = params
            .get(2)
            .cloned()
            .unwrap_or_else(|| "This server is redirecting new connections".to_string());
        let host = params[0].clone();
        s.ext.set(Jump {
            host: host.clone(),
            port,
            reason,
        });
        let m = s.trf(
            "JUMPSERVER: {0} now redirecting new connections to {1}:{2}",
            &[nick.as_str(), host.as_str(), params[1].as_str()],
        );
        s.snotice_c('o', &m);
        s.send(
            uid,
            format!(":{name} NOTICE {nick} :New connections now redirected to {host}:{port}"),
        );
        CmdResult::Ok
    }
}
