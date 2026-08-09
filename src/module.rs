//! The module API — echoIRCd's answer to InspIRCd's `Module` class.
//!
//! Modules hook lifecycle events. "Pre" hooks return a [`ModResult`] and can
//! **deny** an action; "notify" hooks are informational. The core fires pre-hooks
//! inline (so a `Deny` actually blocks) and notify-hooks from a queue after the
//! triggering command finishes — so a handler can emit an event without ever
//! touching the module list. All hooks get `&mut Server`, so a module can act
//! (send lines, force a join, …), exactly like an InspIRCd module gets the
//! `ServerInstance`.

use crate::server::Server;
use crate::Uid;

/// A pre-hook's verdict. `Passthru` = no opinion; `Allow` = force-allow (skip
/// remaining checks); `Deny` = block the action.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ModResult {
    Passthru,
    Allow,
    Deny,
}

/// A queued notify-event, drained by the core after each command.
pub enum Hook {
    Connect(Uid),
    Join(Uid, String),
    Part(Uid, String, String),
    Quit(Uid, String),
}

#[allow(unused_variables)]
pub trait Module: Send {
    fn name(&self) -> &'static str;

    // --- pre-hooks (can Deny) ------------------------------------------------

    /// Last gate before a client finishes registration. `Deny` refuses the link.
    fn on_user_register(&mut self, srv: &mut Server, uid: Uid) -> ModResult {
        ModResult::Passthru
    }
    /// Before any command runs. `Deny` swallows the command silently.
    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        params: &[String],
    ) -> ModResult {
        ModResult::Passthru
    }
    /// Before a PRIVMSG/NOTICE is delivered. `Deny` drops it.
    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        target: &str,
        text: &str,
    ) -> ModResult {
        ModResult::Passthru
    }

    // --- notify-hooks --------------------------------------------------------

    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {}
    fn on_post_command(&mut self, srv: &mut Server, uid: Uid, cmd: &str) {}
    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {}
    fn on_part(&mut self, srv: &mut Server, uid: Uid, chan: &str, reason: &str) {}
    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {}
    /// Fired on the background timer (every `TICK_SECS`).
    fn on_tick(&mut self, srv: &mut Server) {}
}
