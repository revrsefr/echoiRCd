//! `TLINE <mask>` — oper command reporting how many currently-connected local users
//! a would-be K/G/Z-line mask matches, to gauge the blast radius before setting the ban.

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
        let matcheds = matched.to_string();
        let totals = total.to_string();
        let pcts = pct.to_string();
        let m = s.trf(
            "TLINE: {0} matches {1} of {2} local users ({3}%)",
            &[
                mask.as_str(),
                matcheds.as_str(),
                totals.as_str(),
                pcts.as_str(),
            ],
        );
        s.send(uid, format!(":{} NOTICE {nick} :*** {m}", s.name));
        CmdResult::Ok
    }
}
