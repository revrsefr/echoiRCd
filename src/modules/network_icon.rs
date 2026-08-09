//! ircv3_network_icon — InspIRCd `m_ircv3_network_icon`. Advertises a network icon
//! via the `draft/ICON` ISUPPORT token from `network_icon = <url>`. Config-driven;
//! nothing lives on `Server`.

use crate::server::Server;

/// The `ICON=<url>` ISUPPORT token, or `None` when unconfigured.
pub fn isupport(s: &Server) -> Option<String> {
    match s.conf("network_icon") {
        Some(url) if !url.is_empty() => Some(format!("ICON={url}")),
        _ => None,
    }
}
