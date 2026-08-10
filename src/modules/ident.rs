//! ident — optional RFC 1413 (Ident) lookups. When a connection class (or the
//! global `useident = yes`) asks for one, we ask the client's host (port 113) who
//! owns the connection; a confirmed reply becomes the visible username without the
//! `~` that marks an unverified ident. `requireident` refuses clients whose ident
//! can't be confirmed. The lookup runs on a short-lived worker thread (like the
//! resolver) and reports back as `Event::Ident`, so the core never blocks.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::ircd::Event;
use crate::modules::connclass;
use crate::server::Server;
use crate::users::ident_of;
use crate::Uid;

/// Default per-lookup timeout; overridable with `ident_timeout` (seconds).
const IDENT_TIMEOUT: u64 = 5;
/// Cap on concurrent lookups so a connection flood can't spawn unbounded threads.
const MAX_ACTIVE: usize = 256;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Per-user lookup result stored on `User.ext`: `Some(name)` confirmed, `None` not.
struct IdentResult(Option<String>);

/// `(useident, requireident)` combining the client's class with the global default.
fn policy(s: &Server, uid: Uid) -> (bool, bool) {
    let (cu, cr) = connclass::ident_policy(s, uid);
    (
        cu || s.conf_bool("useident", false),
        cr || s.conf_bool("requireident", false),
    )
}

/// Start an ident lookup for a freshly-connected client if its class (or the global
/// config) wants one. Sets `ident_pending` to hold registration until the reply
/// arrives. Returns whether a lookup was started.
pub fn dispatch(s: &mut Server, uid: Uid) -> bool {
    let (useident, requireident) = policy(s, uid);
    if !useident && !requireident {
        return false;
    }
    let (ip, their_port, our_port) = match s.users.get(&uid) {
        Some(u) => (u.addr.ip(), u.addr.port(), u.port),
        None => return false,
    };
    if ACTIVE.fetch_add(1, Ordering::Relaxed) >= MAX_ACTIVE {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        return false; // too many in flight: skip (treated as no ident)
    }
    let timeout = Duration::from_secs(s.conf_num("ident_timeout", IDENT_TIMEOUT));
    if let Some(u) = s.users.get_mut(&uid) {
        u.ident_pending = true;
    }
    s.notice_star(uid, "Checking Ident");
    let tx = s.event_tx.clone();
    std::thread::spawn(move || {
        let ident = lookup(ip, their_port, our_port, timeout);
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        let _ = tx.send(Event::Ident { uid, ident });
    });
    true
}

/// The blocking RFC 1413 exchange: connect to `<ip>:113`, ask about the connection
/// pair, and return the confirmed username (unsanitised) or `None`.
fn lookup(ip: IpAddr, their_port: u16, our_port: u16, timeout: Duration) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(ip, 113), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    // the query is "<port on their side>, <port on our side>"
    let query = format!("{their_port}, {our_port}\r\n");
    stream.write_all(query.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 512 || buf.contains(&b'\n') {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    parse_reply(&String::from_utf8_lossy(&buf))
}

/// Parse an ident reply: `<port>,<port> : USERID : <opsys> : <username>`.
fn parse_reply(reply: &str) -> Option<String> {
    let fields: Vec<&str> = reply.split(':').collect();
    if fields.len() < 4 || !fields[1].trim().eq_ignore_ascii_case("USERID") {
        return None;
    }
    let name = fields[3].trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// A lookup finished: stash the result and clear the registration hold. The result
/// is applied to the visible ident at registration (so a late USER can't clobber it).
pub fn on_result(s: &mut Server, uid: Uid, ident: Option<String>) {
    match &ident {
        Some(name) => s.notice_star(uid, &format!("Received Ident response: {name}")),
        None => s.notice_star(uid, "No Ident response"),
    }
    if let Some(u) = s.users.get_mut(&uid) {
        *u.ext.get_or_insert_with(|| IdentResult(None)) = IdentResult(ident);
        u.ident_pending = false;
    }
}

/// At registration, apply a confirmed ident (dropping the leading `~`) and enforce
/// `requireident`. Returns `Some(reason)` to reject.
pub fn finalize(s: &mut Server, uid: Uid) -> Option<String> {
    let confirmed = s
        .users
        .get(&uid)
        .and_then(|u| u.ext.get::<IdentResult>().map(|r| r.0.clone()));
    if let Some(Some(name)) = confirmed {
        let clean = ident_of(&name); // sanitised, no `~`
        if let Some(u) = s.users.get_mut(&uid) {
            u.ident = clean;
        }
    }
    let (_, requireident) = policy(s, uid);
    if requireident {
        let unverified = s
            .users
            .get(&uid)
            .map(|u| u.ident.is_empty() || u.ident.starts_with('~'))
            .unwrap_or(true);
        if unverified {
            return Some("Your connection class requires a valid ident response".to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_userid_and_error() {
        assert_eq!(
            parse_reply("6193, 6667 : USERID : UNIX : reverse\r\n").as_deref(),
            Some("reverse")
        );
        assert_eq!(parse_reply("6193, 6667 : ERROR : NO-USER"), None);
        assert_eq!(parse_reply("garbage"), None);
        // case-insensitive reply type, trailing charset field tolerated
        assert_eq!(
            parse_reply("1,2 : userid : UNIX,US-ASCII : bob").as_deref(),
            Some("bob")
        );
    }
}
