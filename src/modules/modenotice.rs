//! `MODENOTICE <umodes> <message>` — oper command sending a NOTICE to every local
//! user who has all of the given user modes set (e.g. `+o` reaches all opers).

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ModeNoticeCmd)]
}

struct ModeNoticeCmd;
impl Command for ModeNoticeCmd {
    fn name(&self) -> &'static str {
        "MODENOTICE"
    }
    fn min_params(&self) -> usize {
        2
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
        let want: Vec<char> = params[0].chars().filter(|c| *c != '+' && *c != '-').collect();
        if want.is_empty() {
            return CmdResult::Fail;
        }
        let body = params[1..].join(" ");
        let from = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let name = s.name.clone();
        let targets: Vec<Uid> = s
            .users
            .iter()
            .filter(|(_, u)| {
                u.registered && {
                    let m = u.flags.umodes();
                    want.iter().all(|c| m.contains(*c))
                }
            })
            .map(|(id, _)| *id)
            .collect();
        for t in targets {
            let tn = s.users.get(&t).map(|u| u.nick.clone()).unwrap_or_default();
            s.send(
                t,
                format!(":{name} NOTICE {tn} :*** From {from}: {body}"),
            );
        }
        CmdResult::Ok
    }
}
