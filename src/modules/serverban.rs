//! serverban — the `s:` matching extban: match a user by the name of the server
//! they are connected to. `+b s:irc.example.net` bans everyone on that server.
//! Ban matching only ever runs against local users (join happens locally), so a
//! matched user is on this server — we glob the mask against our own name.
//! Dispatched from the channel ban matcher; the logic lives here.
//!
//! Behaviour reference: InspIRCd's `m_serverban`. Original native Rust.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// Does `uid`'s server name match the glob `mask` (the part after `s:`)?
pub fn matches(s: &Server, uid: Uid, mask: &str) -> bool {
    // local users are on this server; guard on the user still existing
    if !s.users.contains_key(&uid) {
        return false;
    }
    glob_match(mask, &s.name)
}
