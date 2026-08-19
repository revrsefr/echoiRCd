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

/// A plain host-mask ban entry (not itself an extban). An extban is `<letter>:…`,
/// matching `normalize_ban_mask`'s rule — anything else is a plain host-mask.
fn is_plain(mask: &str) -> bool {
    let b = mask.as_bytes();
    !(b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
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
