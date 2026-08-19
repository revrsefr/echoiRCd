//! chanlog — mirror server notices (the `snotice` stream opers see with +s) into a
//! channel, so staff can watch the log in a normal channel window. Off unless
//! `chanlog = #channel` is configured.

use crate::server::Server;

/// Tee `msg` to the configured chanlog channel (if set and it exists). Called at
/// the tail of `Server::snotice`. Read-only over server state, so it can't loop.
pub fn tee(s: &Server, msg: &str) {
    let Some(chan) = s.conf("chanlog") else {
        return;
    };
    let key = chan.to_ascii_lowercase();
    if !s.channels.contains_key(&key) {
        return; // channel not created yet — nothing to log into
    }
    // to_channel builds the line once and shares it by Arc across members (and adds
    // the server-time tag per recipient) instead of cloning a String per member.
    let line = format!(":{} NOTICE {chan} :{msg}", s.name);
    s.to_channel(&key, &line, None);
}
