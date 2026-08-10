//! `draft/extended-isupport` capability: lets a client re-request the current
//! ISUPPORT (005) tokens at any time via the `ISUPPORT` command. With the `batch`
//! cap the reply is wrapped in a `draft/isupport` BATCH so the set arrives atomically.
//! Emission lives in `Server::send_isupport`, shared with the welcome burst.

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_UNKNOWNCOMMAND;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ISupportCmd)]
}

/// ISUPPORT — re-send the server's ISUPPORT tokens. Requires the
/// `draft/extended-isupport` cap; usable before registration completes.
struct ISupportCmd;
impl Command for ISupportCmd {
    fn name(&self) -> &'static str {
        "ISUPPORT"
    }
    fn min_params(&self) -> usize {
        0
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        let (has_cap, has_batch) = s
            .users
            .get(&uid)
            .map(|u| (u.caps.ext_isupport, u.caps.batch))
            .unwrap_or((false, false));
        if !has_cap {
            s.numeric(
                uid,
                ERR_UNKNOWNCOMMAND,
                "ISUPPORT :You must request the draft/extended-isupport capability to use this command",
            );
            return CmdResult::Fail;
        }
        s.send_isupport(uid, has_batch);
        CmdResult::Ok
    }
}
