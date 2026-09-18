//! `CLONES [min]` — oper command listing local IP addresses with at least `min`
//! (default 2) connections, to spot clone floods at a glance.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ClonesCmd)]
}

struct ClonesCmd;
impl Command for ClonesCmd {
    fn name(&self) -> &'static str {
        "CLONES"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let min = params
            .first()
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(2)
            .max(2);
        let mut by_ip: HashMap<IpAddr, usize> = HashMap::new();
        for u in s.users.values() {
            *by_ip.entry(u.addr.ip()).or_insert(0) += 1;
        }
        let mut rows: Vec<(IpAddr, usize)> =
            by_ip.into_iter().filter(|(_, n)| *n >= min).collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1));
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let name = s.name.clone();
        if rows.is_empty() {
            s.send(
                uid,
                format!(":{name} NOTICE {nick} :No IP has {min} or more connections"),
            );
        } else {
            for (ip, n) in &rows {
                s.send(
                    uid,
                    format!(":{name} NOTICE {nick} :{n} connections from {ip}"),
                );
            }
            s.send(
                uid,
                format!(":{name} NOTICE {nick} :End of CLONES ({} address(es))", rows.len()),
            );
        }
        CmdResult::Ok
    }
}
