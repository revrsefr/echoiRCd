//! banredirect — a ban of the form `+b <mask>$<#channel>` bounces a matching,
//! banned user into `#channel` instead of refusing them outright. The redirect
//! fires at most once, guarded by `Server.in_redirect` (shared with the `+L`
//! full-channel redirect), so it can never loop.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// The mask part of a ban, without any `$#chan` redirect suffix — used both for
/// matching (a redirect ban must still *block*) and for reading the target.
pub fn mask_part(mask: &str) -> &str {
    mask.split('$').next().unwrap_or(mask)
}

/// If `uid` is caught by a redirect ban (`mask$#chan`) in `key` with no matching
/// exception, return the target channel. The caller has already established the
/// user is banned; this extracts the `$#chan` destination.
pub fn redirect_target(s: &Server, uid: Uid, key: &str) -> Option<String> {
    let ch = s.channels.get(key)?;
    let who = s.users.get(&uid)?.prefix();
    // a matching +e exception cancels the ban, hence the redirect
    if ch.excepts.iter().any(|e| glob_match(mask_part(&e.mask), &who)) {
        return None;
    }
    ch.bans.iter().find_map(|b| {
        let (mask, redir) = b.mask.split_once('$')?;
        (redir.starts_with('#') && glob_match(mask, &who)).then(|| redir.to_string())
    })
}
