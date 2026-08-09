//! profileLink — InspIRCd `m_profileLink`. Adds a profile URL to WHOIS for
//! logged-in users from `profilelink_baseurl = <url>`. Config-driven; nothing
//! lives on `Server`.

use crate::server::Server;

/// The WHOIS profile line for `account`, or `None` when unconfigured.
pub fn line(s: &Server, account: &Option<String>) -> Option<String> {
    let base = s.conf("profilelink_baseurl")?;
    if base.is_empty() {
        return None;
    }
    Some(match account {
        Some(acct) => format!("Profil: {base}{acct}"),
        None => "Profile: The user is not logged in or the account is not registered.".to_string(),
    })
}
