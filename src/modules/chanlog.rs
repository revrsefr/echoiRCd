//! chanlog — mirror server notices (the `snotice` stream opers see with +s) into a
//! channel, so staff can watch the log in a normal channel window. Off unless
//! `chanlog = #channel` is configured. Reference: InspIRCd's `m_chanlog`.
//! Original native Rust.

use crate::server::Server;
use crate::Uid;

/// Tee `msg` to the configured chanlog channel (if set and it exists). Called at
/// the tail of `Server::snotice`. Read-only over server state, so it can't loop.
pub fn tee(s: &Server, msg: &str) {
    let Some(chan) = s.conf("chanlog") else {
        return;
    };
    let Some(ch) = s.channels.get(&chan.to_ascii_lowercase()) else {
        return; // channel not created yet — nothing to log into
    };
    let line = format!(":{} NOTICE {chan} :{msg}", s.name);
    let members: Vec<Uid> = ch.members.keys().copied().collect();
    for u in members {
        s.send(u, line.clone());
    }
}
