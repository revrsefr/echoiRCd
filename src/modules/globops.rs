//! `GLOBOPS <message>`: lets an oper send a message to all opers via the
//! server-notice stream.

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(GlobopsCmd)]
}

struct GlobopsCmd;
impl Command for GlobopsCmd {
    fn name(&self) -> &'static str {
        "GLOBOPS"
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
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        s.snotice(&format!("GLOBOPS from {nick}: {}", params.join(" ")));
        CmdResult::Ok
    }
}
