//! network_icon — advertise a network icon via the `ICON` ISUPPORT token from
//! `network_icon = <url>`.

use crate::server::Server;

/// The `ICON=<url>` ISUPPORT token, or `None` when unconfigured.
pub fn isupport(s: &Server) -> Option<String> {
    match s.conf("network_icon") {
        Some(url) if !url.is_empty() => Some(format!("ICON={url}")),
        _ => None,
    }
}
