//! channelban — the `j:` matching extban: match a user by another channel they
//! are in. `+b j:#lobby` bans everyone who is also in `#lobby`; an optional status
//! prefix narrows it to members at/above that rank, e.g. `+b j:@#staff` matches
//! only ops-or-higher in `#staff`. The channel part is a glob. Dispatched from the
//! channel ban matcher; the logic lives here in its own file.
//!
//! Behaviour reference: InspIRCd's `m_channelban`. Original native Rust.

use crate::channels::{glob_match, RANK_ADMIN, RANK_HALFOP, RANK_OP, RANK_OWNER, RANK_VOICE};
use crate::server::Server;
use crate::Uid;

/// Map a leading status prefix to the minimum rank it requires; `None` if the
/// first char isn't a prefix (so the whole string is the channel glob).
fn split_prefix(mask: &str) -> (u8, &str) {
    match mask.chars().next() {
        Some('~') => (RANK_OWNER, &mask[1..]),
        Some('&') => (RANK_ADMIN, &mask[1..]),
        Some('@') => (RANK_OP, &mask[1..]),
        Some('%') => (RANK_HALFOP, &mask[1..]),
        Some('+') => (RANK_VOICE, &mask[1..]),
        _ => (0, mask),
    }
}

/// Is `uid` a member (at/above the required rank) of a channel matching the glob
/// in `mask` (the part after `j:`)?
pub fn matches(s: &Server, uid: Uid, mask: &str) -> bool {
    let (min_rank, changlob) = split_prefix(mask);
    let changlob = changlob.to_ascii_lowercase();
    let Some(u) = s.users.get(&uid) else {
        return false;
    };
    u.channels.iter().any(|key| {
        if !glob_match(&changlob, key) {
            return false;
        }
        if min_rank == 0 {
            return true;
        }
        s.channels
            .get(key)
            .and_then(|ch| ch.members.get(&uid))
            .map(|m| m.rank() >= min_rank)
            .unwrap_or(false)
    })
}
