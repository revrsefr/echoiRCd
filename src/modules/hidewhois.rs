//! hidewhois — InspIRCd `m_hidewhois`. Hides sensitive WHOIS lines (server, idle,
//! secure, …) from ordinary users. Opers and the user themselves are exempt when
//! the matching config toggle is on. All config-driven; nothing lives on `Server`.

use crate::server::Server;
use crate::Uid;

/// Whether sensitive WHOIS lines should be hidden for this (viewer, target) pair.
pub fn hide(s: &Server, viewer: Uid, target: Uid, viewer_oper: bool) -> bool {
    if !s.conf_bool("hidewhois", false) {
        return false;
    }
    let selfview = s.conf_bool("hidewhois_selfview", true);
    let opers = s.conf_bool("hidewhois_opers", true);
    !(viewer == target && selfview) && !(viewer_oper && opers)
}

pub fn hide_server(s: &Server) -> bool {
    s.conf_bool("hidewhois_hide_server", true)
}
pub fn hide_idle(s: &Server) -> bool {
    s.conf_bool("hidewhois_hide_idle", true)
}
pub fn hide_secure(s: &Server) -> bool {
    s.conf_bool("hidewhois_hide_secure", true)
}
