//! channames — restrict which characters may appear in *new* channel names, beyond
//! the protocol minimum. `channames_deny = <chars>` lists forbidden characters (e.g.
//! control codes or fancy Unicode an admin doesn't want in channel names). Existing
//! channels are unaffected. Off unless `channames_deny` is set. Dispatched from
//! `Server::join`.
//!
//! Behaviour reference: InspIRCd's `m_channames`. Original native Rust.

use crate::numeric::ERR_BADCHANNEL;
use crate::server::Server;
use crate::Uid;

/// Called from `Server::join`. Returns true when `name` uses a forbidden character
/// (the caller returns without joining). Only creation of new channels is checked.
pub fn intercept(s: &mut Server, uid: Uid, name: &str) -> bool {
    let Some(deny) = s.conf("channames_deny").filter(|d| !d.is_empty()) else {
        return false;
    };
    let deny: Vec<char> = deny.chars().collect();
    // joining an existing channel is always allowed
    if s.channels.contains_key(&name.to_ascii_lowercase()) {
        return false;
    }
    if name.chars().any(|c| deny.contains(&c)) {
        s.numeric(
            uid,
            ERR_BADCHANNEL,
            &format!("{name} :Channel name contains characters not permitted here"),
        );
        return true;
    }
    false
}
