//! The command API — echoIRCd's answer to InspIRCd's `Command` class.
//!
//! A command is a stateless handler registered by name. The core validates
//! `min_params` and the registration gate (`before_reg`) before calling
//! [`Command::handle`], which gets `&mut Server` and does the work.

use crate::server::Server;
use crate::Uid;

/// Outcome of a command (mirrors InspIRCd's `CmdResult`, minus server-only bits).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CmdResult {
    Ok,
    Fail,
}

pub trait Command: Send {
    /// The command name, upper-case (also its registry key).
    fn name(&self) -> &'static str;
    /// Minimum parameters; fewer ⇒ the core replies `461` and skips the handler.
    fn min_params(&self) -> usize {
        0
    }
    /// May this run before the client has registered (NICK/USER/CAP/PING/QUIT)?
    fn before_reg(&self) -> bool {
        false
    }
    fn handle(&self, srv: &mut Server, uid: Uid, params: &[String]) -> CmdResult;
}
