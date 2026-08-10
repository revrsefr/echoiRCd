//! autodrop — silently drop a not-yet-registered client that sends one of the
//! configured commands. HTTP scanners and other junk open a connection and blurt
//! `GET` / `POST` / `CONNECT` before ever sending NICK/USER; a real IRC client
//! never does. Config, space-separated (repeatable):
//!
//! ```text
//! autodrop_commands = GET POST HEAD CONNECT PUT DELETE OPTIONS TRACE PATCH
//! ```

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

pub struct AutoDrop;

impl Module for AutoDrop {
    fn name(&self) -> &'static str {
        "autodrop"
    }

    fn on_pre_command(
        &mut self,
        s: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // only before registration — a registered client's commands are its own
        if s.users.get(&uid).map(|u| u.registered).unwrap_or(true) {
            return ModResult::Passthru;
        }
        let hit = s
            .conf_all("autodrop_commands")
            .iter()
            .any(|line| line.split_whitespace().any(|w| w.eq_ignore_ascii_case(cmd)));
        if hit {
            s.send(uid, "ERROR :Closing link (dropped)".to_string());
            s.remove_user(uid, "Autodropped");
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
