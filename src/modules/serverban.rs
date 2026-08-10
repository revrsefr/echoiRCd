//! The `s:` matching extban: match a user by the name of the server they are
//! connected to. `+b s:irc.example.net` bans everyone on that server. Ban matching
//! only ever runs against local users, so a matched user is on this server and the
//! mask is globbed against the local server name. Dispatched from the channel ban
//! matcher.

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
