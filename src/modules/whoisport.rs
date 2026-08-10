//! Shows an IRC operator, in WHOIS, the listener port the target connected to.
//! Derives the port from the `bind` / `bind_tls` listeners.

use crate::server::Server;
use crate::Uid;

fn port_of(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(0)
}

/// The `is using port N` WHOIS line for opers, or `None` if the port is unknown.
pub fn line(s: &Server, target: Uid) -> Option<String> {
    let secure = s.users.get(&target).map(|u| u.secure).unwrap_or(false);
    let bind = if secure { "bind_tls" } else { "bind" };
    let port = s.conf(bind).map(port_of).unwrap_or(0);
    (port != 0).then(|| format!("is using port {port}"))
}
