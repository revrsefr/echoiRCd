//! Serve a text file as its own command. Config, one line per file:
//!
//! ```text
//! showfile = <COMMAND> <path>      # e.g.  showfile = RULES /etc/echoircd/rules.txt
//! ```
//!
//! makes `/RULES` stream the file to the client. Dispatched from the same place as
//! command aliases (an unknown, config-named command), so no static registration is
//! needed. The file is read fresh on each use, so edits show without a REHASH.

use crate::server::Server;
use crate::Uid;

/// If `cmd` names a configured `showfile`, stream that file to `uid` (one NOTICE
/// per line) and return `true`. Returns `false` if no showfile matches `cmd`, so
/// the caller can fall through to the normal unknown-command handling.
pub fn maybe_show(s: &mut Server, uid: Uid, cmd: &str) -> bool {
    let path = s.conf_all("showfile").iter().find_map(|line| {
        let (name, path) = line.split_once(char::is_whitespace)?;
        name.eq_ignore_ascii_case(cmd)
            .then(|| path.trim().to_string())
    });
    let Some(path) = path else {
        return false;
    };
    let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
    match std::fs::read_to_string(&path) {
        Ok(body) => {
            for line in body.lines() {
                s.send(uid, format!(":{} NOTICE {nick} :{line}", s.name));
            }
        }
        Err(_) => s.send(
            uid,
            format!(":{} NOTICE {nick} :*** {cmd}: file not available.", s.name),
        ),
    }
    true
}
