//! Only opers may *create* new channels; everyone can still join existing ones.
//! A `restrictchan = <glob>` whitelist lets ordinary users create channels whose
//! name matches (e.g. `restrictchan = #public-*`). Off unless `restrictchans = yes`.
//! Dispatched from `Server::join`.

use crate::channels::glob_match;
use crate::numeric::ERR_BADCHANNEL;
use crate::server::Server;
use crate::Uid;

/// Called from `Server::join`. Returns true when creating `name` should be blocked
/// (the caller returns without joining). Holders of `channels/restricted-create` and
/// joins to *existing* channels pass.
pub fn intercept(s: &mut Server, uid: Uid, name: &str, may_create: bool) -> bool {
    if may_create || !s.conf_bool("restrictchans", false) {
        return false;
    }
    // joining a channel that already exists is always fine
    if s.channels.contains_key(&name.to_ascii_lowercase()) {
        return false;
    }
    // creating a new one: allowed only if it matches a whitelist glob
    if s.conf_all("restrictchan")
        .iter()
        .any(|g| glob_match(g, name))
    {
        return false;
    }
    s.numeric(
        uid,
        ERR_BADCHANNEL,
        &format!("{name} :Only IRC operators may create new channels here"),
    );
    true
}
