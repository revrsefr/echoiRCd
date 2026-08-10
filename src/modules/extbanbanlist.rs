//! extbanbanlist: matching extban `b:<#channel>` catches a user if they are on
//! `#channel`'s ban list, letting one channel borrow another's bans (e.g.
//! `+b b:#staff` bans everyone banned in #staff).
//!
//! The match is deliberately non-recursive: it tests only the referenced channel's
//! plain host-mask bans (and its plain excepts), never that channel's own extbans,
//! so two channels referencing each other can't loop.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// A plain host-mask ban entry (not itself an extban).
fn is_plain(mask: &str) -> bool {
    mask.as_bytes().get(1) != Some(&b':')
}

/// True if `uid` is on `chan`'s (plain) ban list with no matching plain exception.
pub fn matches(s: &Server, uid: Uid, chan: &str) -> bool {
    let Some(who) = s.users.get(&uid).map(|u| u.prefix()) else {
        return false;
    };
    let Some(ch) = s.channels.get(&chan.to_ascii_lowercase()) else {
        return false;
    };
    if ch
        .excepts
        .iter()
        .any(|e| is_plain(&e.mask) && glob_match(&e.mask, &who))
    {
        return false;
    }
    ch.bans
        .iter()
        .any(|b| is_plain(&b.mask) && glob_match(&b.mask, &who))
}
