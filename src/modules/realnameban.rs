//! realnameban — the `r:` matching extban: match a user by their real name
//! (GECOS) instead of their host. `+b r:*some spammer*` bans everyone whose
//! realname matches the glob. Dispatched from the channel ban matcher; the logic
//! lives here in its own file.
//!
//! Behaviour reference: InspIRCd's `m_realnameban`. Original native Rust.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// Does `uid`'s realname match the glob `mask` (the part after `r:`)?
pub fn matches(s: &Server, uid: Uid, mask: &str) -> bool {
    s.users
        .get(&uid)
        .map(|u| glob_match(mask, &u.realname))
        .unwrap_or(false)
}
