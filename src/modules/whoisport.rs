//! Shows an IRC operator, in WHOIS, the listener port the target connected to —
//! read straight from the user's own connection (set at accept time), so it's
//! correct even when the server has several `bind` / `bind_tls` listeners.

use crate::server::Server;
use crate::Uid;

/// The `is using port N` WHOIS line for opers, or `None` if the port is unknown.
pub fn line(s: &Server, target: Uid) -> Option<String> {
    s.users
        .get(&target)
        .map(|u| u.port)
        .filter(|&p| p != 0)
        .map(|p| format!("is using port {p}"))
}
