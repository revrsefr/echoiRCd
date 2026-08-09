//! customtitle — `TITLE <name> <password>` lets a user claim a configured vanity
//! title (shown in their WHOIS) and, optionally, a matching vhost — a lightweight
//! "mini-oper" identity without operator privileges. Config, one block per title:
//!
//! ```text
//! customtitle = <name> <password> <vhost|*> <title text…>
//! ```
//!
//! The password is checked via [`crate::modules::password_hash`] so it may be
//! plaintext or a hash. The claimed title lives in the user's `ext`.
//!
//! Behaviour reference: InspIRCd's `m_customtitle`. Original native Rust.

use crate::command::{CmdResult, Command};
use crate::modules::password_hash;
use crate::server::Server;
use crate::Uid;

/// The title a user has claimed, stored in `User.ext`.
struct Title(String);

/// The WHOIS special line for `tuid`, if they've claimed a title. Called from core_info.
pub fn line(s: &Server, tuid: Uid) -> Option<String> {
    s.users
        .get(&tuid)
        .and_then(|u| u.ext.get::<Title>())
        .map(|t| format!("is {}", t.0))
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(TitleCmd)]
}

struct TitleCmd;
impl Command for TitleCmd {
    fn name(&self) -> &'static str {
        "TITLE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (name, pass) = (params[0].clone(), params[1].clone());
        // find a matching <name> <password> <vhost> <title…> block
        let found = s.conf_all("customtitle").iter().find_map(|line| {
            let mut it = line.split_whitespace();
            let cname = it.next()?;
            let cpass = it.next()?;
            let cvhost = it.next()?;
            let title = it.collect::<Vec<_>>().join(" ");
            if cname == name && !title.is_empty() && password_hash::verify(cpass, &pass) {
                Some((title, cvhost.to_string()))
            } else {
                None
            }
        });
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let Some((title, vhost)) = found else {
            s.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :*** TITLE: invalid title name or password.",
                    s.name
                ),
            );
            return CmdResult::Fail;
        };
        if let Some(u) = s.users.get_mut(&uid) {
            u.ext.set(Title(title.clone()));
        }
        if vhost != "*" && !vhost.is_empty() {
            s.change_host_ident(uid, None, Some(&vhost));
        }
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :*** TITLE: you are now known as \"{title}\".",
                s.name
            ),
        );
        CmdResult::Ok
    }
}
