//! `ALINE` / `GALINE` — require any connection matching a `user@host` (or IP) mask to
//! be logged into a services account before it may finish registering; an
//! unauthenticated match is refused. ALINE is local, GALINE is propagated like the
//! other x-lines. Enforced from `welcome` at registration.

use crate::command::{CmdResult, Command};
use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ALine), Box::new(GALine)]
}

/// At registration: if the user isn't an oper or logged in and matches an A/GA-line,
/// return the refusal reason. Opers and authenticated users always pass.
pub fn check(s: &Server, uid: Uid) -> Option<String> {
    let u = s.users.get(&uid)?;
    if u.flags.oper || u.account.is_some() {
        return None;
    }
    let ident = u.ident.clone();
    let host = u.host_display().to_string();
    let ip = u.addr.ip().to_string();
    s.matched_require_auth(&ident, &host, &ip)
}

struct ALine;
impl Command for ALine {
    fn name(&self) -> &'static str {
        "ALINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        crate::coremods::core_oper::do_xline(s, uid, params, XKind::Aline)
    }
}

struct GALine;
impl Command for GALine {
    fn name(&self) -> &'static str {
        "GALINE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        crate::coremods::core_oper::do_xline(s, uid, params, XKind::Galine)
    }
}
