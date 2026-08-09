//! tline — `TLINE <mask>`, an oper command that reports how many currently-connected
//! local users a would-be K/G/Z-line mask matches, so you can gauge the blast radius
//! before actually setting the ban.
//!
//! Behaviour reference: InspIRCd's `m_tline`. Original native Rust.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(TLine)]
}

struct TLine;
impl Command for TLine {
    fn name(&self) -> &'static str {
        "TLINE"
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
        let mask = &params[0];
        let total = s.users.len();
        let matched = s
            .users
            .values()
            .filter(|u| {
                let forms = [
                    format!("{}!{}@{}", u.nick, u.ident, u.host_display()),
                    format!("{}@{}", u.ident, u.host),
                    format!("{}@{}", u.ident, u.addr.ip()),
                ];
                forms.iter().any(|f| glob_match(mask, f))
            })
            .count();
        let pct = (matched * 100).checked_div(total).unwrap_or(0);
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :*** TLINE: {mask} matches {matched} of {total} local users ({pct}%)",
                s.name
            ),
        );
        CmdResult::Ok
    }
}
