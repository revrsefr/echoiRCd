//! extended_isupport — the `draft/extended-isupport` capability. reverse's own
//! module. Normally ISUPPORT (005) is a one-shot at registration; with this cap a
//! client can send the `ISUPPORT` command any time to re-request the current tokens
//! (handy after a rehash changes them). If the client also has `batch`, the reply
//! is wrapped in a `draft/isupport` BATCH so the multi-line set arrives atomically —
//! the emission itself lives in `Server::send_isupport`, shared with the welcome burst.
//!
//! Behaviour reference: reverse's InspIRCd `m_ircv3_extended_isupport`. Original native Rust.

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
