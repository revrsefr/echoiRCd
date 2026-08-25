//! customtitle: `TITLE <name> <password>` lets a user claim a configured title
//! (shown in their WHOIS) and, optionally, a matching vhost. Config, one block per
//! title:
//!
//! ```text
//! customtitle = <name> <password> <vhost|*> <title text…>
//! ```
//!
//! The password is checked via [`crate::modules::password_hash`], so it may be
//! plaintext or a hash. The claimed title lives in the user's `ext`.

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

fn nick(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default()
}

/// Apply a verified title: store it, apply the vhost (unless `*`), and confirm.
pub fn grant(s: &mut Server, uid: Uid, title: &str, vhost: &str) {
    if let Some(u) = s.users.get_mut(&uid) {
        u.ext.set(Title(title.to_string()));
    }
    if vhost != "*" && !vhost.is_empty() {
        s.change_host_ident(uid, None, Some(vhost));
    }
    let nick = nick(s, uid);
    let m = s.trf("TITLE: you are now known as \"{0}\".", &[title]);
    s.send(
        uid,
        format!(":{} NOTICE {nick} :*** {m}", s.name),
    );
}

/// Reject a TITLE attempt (bad name or password).
pub fn deny(s: &Server, uid: Uid) {
    let nick = nick(s, uid);
    s.send(
        uid,
        format!(":{} NOTICE {nick} :*** TITLE: invalid title name or password.", s.name),
    );
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
        // find the <name> <password> <vhost> <title…> block by name (first wins)
        let block = s.conf_all("customtitle").iter().find_map(|line| {
            let mut it = line.split_whitespace();
            let cname = it.next()?;
            let cpass = it.next()?;
            let cvhost = it.next()?;
            let title = it.collect::<Vec<_>>().join(" ");
            (cname == name && !title.is_empty())
                .then(|| (cpass.to_string(), cvhost.to_string(), title))
        });
        let Some((cpass, cvhost, title)) = block else {
            deny(s, uid);
            return CmdResult::Fail;
        };
        // a KDF title password is slow — verify it off the core thread (result comes
        // back as TitleAuth) so /TITLE spam can't freeze the server.
        if password_hash::is_slow(&cpass) {
            let started = s.spawn_crypto(move || {
                let ok = password_hash::verify(&cpass, &pass);
                crate::ircd::Event::TitleAuth {
                    uid,
                    ok,
                    title,
                    vhost: cvhost,
                }
            });
            if !started {
                deny(s, uid);
                return CmdResult::Fail; // crypto pool full — consistent with the sync path
            }
            return CmdResult::Ok;
        }
        if password_hash::verify(&cpass, &pass) {
            grant(s, uid, &title, &cvhost);
            CmdResult::Ok
        } else {
            deny(s, uid);
            CmdResult::Fail
        }
    }
}
