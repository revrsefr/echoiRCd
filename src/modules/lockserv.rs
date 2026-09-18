//! `LOCKSERV` / `UNLOCKSERV` — oper commands that stop (and resume) new local client
//! connections, e.g. during maintenance. Loopback (services / web / local admin) is
//! always exempt so the box stays reachable. State lives in `Server.ext`.

use std::net::IpAddr;

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::{is_local_ip, Server};
use crate::Uid;

/// Presence of this marker in `Server.ext` = the server is locked.
struct Locked;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(LockServ), Box::new(UnlockServ)]
}

/// Whether a new (non-loopback) connection should be refused. Called from `add_conn`.
pub fn blocked(s: &Server, ip: IpAddr) -> bool {
    s.ext.get::<Locked>().is_some() && !is_local_ip(ip)
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

struct LockServ;
impl Command for LockServ {
    fn name(&self) -> &'static str {
        "LOCKSERV"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _p: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        s.ext.set(Locked);
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let m = s.trf(
            "LOCKSERV: {0} locked the server to new connections",
            &[nick.as_str()],
        );
        s.snotice_c('o', &m);
        let name = s.name.clone();
        s.send(
            uid,
            format!(":{name} NOTICE {nick} :Server is now locked to new connections"),
        );
        CmdResult::Ok
    }
}

struct UnlockServ;
impl Command for UnlockServ {
    fn name(&self) -> &'static str {
        "UNLOCKSERV"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _p: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        s.ext.take::<Locked>();
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let m = s.trf("LOCKSERV: {0} unlocked the server", &[nick.as_str()]);
        s.snotice_c('o', &m);
        let name = s.name.clone();
        s.send(
            uid,
            format!(":{name} NOTICE {nick} :Server is now unlocked to new connections"),
        );
        CmdResult::Ok
    }
}
