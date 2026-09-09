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
    let nick = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    // cap the blocking read so a huge (mis)configured file can't stall the core loop
    let body = std::fs::File::open(&path).ok().and_then(|f| {
        use std::io::Read;
        let mut buf = String::new();
        f.take(256 * 1024)
            .read_to_string(&mut buf)
            .ok()
            .map(|_| buf)
    });
    match body {
        Some(body) => {
            for line in body.lines() {
                s.send(uid, format!(":{} NOTICE {nick} :{line}", s.name));
            }
        }
        None => {
            let m = s.trf("{0}: file not available.", &[cmd]);
            s.send(uid, format!(":{} NOTICE {nick} :*** {m}", s.name));
        }
    }
    true
}
