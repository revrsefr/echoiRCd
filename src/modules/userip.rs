//! `USERIP <nick> [nick ...]` — oper command returning each user's ident and real
//! IP as RPL_USERIP (340), the IP-showing sibling of USERHOST. Oper-only since it
//! exposes real addresses.

use crate::command::{CmdResult, Command};
use crate::numeric::{ERR_NOPRIVILEGES, RPL_USERIP};
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(UserIpCmd)]
}

struct UserIpCmd;
impl Command for UserIpCmd {
    fn name(&self) -> &'static str {
        "USERIP"
    }
    fn min_params(&self) -> usize {
        1
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
        let mut parts: Vec<String> = Vec::new();
        for want in params.iter().take(5) {
            for name in want.split_whitespace() {
                if let Some(tu) = s.find_nick(name).and_then(|t| s.users.get(&t)) {
                    let star = if tu.flags.oper { "*" } else { "" };
                    let here = if tu.flags.away.is_some() { "-" } else { "+" };
                    parts.push(format!(
                        "{}{star}={here}{}@{}",
                        tu.nick,
                        tu.ident,
                        tu.addr.ip()
                    ));
                }
            }
        }
        s.numeric(uid, RPL_USERIP, &format!(":{}", parts.join(" ")));
        CmdResult::Ok
    }
}
