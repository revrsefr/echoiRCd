//! Hides a channel list mode's entries (e.g. the +b ban list) from members below a
//! configured rank. Config, repeatable: `hidelist = <modechar> <rank>` where rank is
//! one of owner|admin|op|halfop|voice. Opers always see.

use crate::channels::{RANK_ADMIN, RANK_HALFOP, RANK_OP, RANK_OWNER, RANK_VOICE};
use crate::server::Server;
use crate::Uid;

fn rank_value(name: &str) -> u8 {
    match name.to_ascii_lowercase().as_str() {
        "owner" | "founder" | "q" => RANK_OWNER,
        "admin" | "protect" | "a" => RANK_ADMIN,
        "op" | "o" => RANK_OP,
        "halfop" | "h" => RANK_HALFOP,
        "voice" | "v" => RANK_VOICE,
        _ => RANK_OP, // unknown ⇒ require op, the safe default
    }
}

/// True if `uid` may NOT view the `modechar` list in channel `key`: the config sets
/// a per-mode minimum rank via `hidelist = <modechar> <rank>`. Opers always see.
pub fn denied(s: &Server, uid: Uid, key: &str, modechar: char) -> bool {
    if s.is_oper(uid) {
        return false;
    }
    // last matching line wins, mirroring conf()'s last-value-overrides semantics
    let mut req: Option<u8> = None;
    for line in s.conf_all("hidelist") {
        let mut it = line.split_whitespace();
        if let (Some(mc), Some(rank)) = (it.next(), it.next()) {
            if mc.chars().next() == Some(modechar) {
                req = Some(rank_value(rank));
            }
        }
    }
    match req {
        Some(r) => s.rank(uid, key) < r,
        None => false,
    }
}
