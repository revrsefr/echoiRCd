//! disable — refuse a configured set of commands to ordinary users (opers bypass).
//! `disabled_commands = LIST WHO KNOCK` (space-separated; repeatable). A disabled
//! command replies with `421` as if it didn't exist. Off unless configured.
//!
//! Behaviour reference: InspIRCd's `m_disable`. Original native Rust.

use crate::module::{ModResult, Module};
use crate::numeric::ERR_UNKNOWNCOMMAND;
use crate::server::Server;
use crate::Uid;

pub struct Disable;

impl Module for Disable {
    fn name(&self) -> &'static str {
        "disable"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // opers are never restricted
        if srv.is_oper(uid) {
            return ModResult::Passthru;
        }
        let disabled = srv
            .conf_all("disabled_commands")
            .iter()
            .flat_map(|line| line.split_whitespace())
            .any(|c| c.eq_ignore_ascii_case(cmd));
        if disabled {
            srv.numeric(
                uid,
                ERR_UNKNOWNCOMMAND,
                &format!("{cmd} :This command has been disabled by the administrator."),
            );
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
