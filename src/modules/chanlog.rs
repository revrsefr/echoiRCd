//! chanlog — mirror server notices (the `snotice` stream opers see with +s) into a
//! channel, so staff can watch the log in a normal channel window. Off unless at
//! least one `chanlog = #channel [snomask-letters]` is configured.
//!
//! Each entry may carry a snomask filter — the category letters (the same letters
//! as the `+s` snomask set: `x` x-lines, `d` dnsbl, `c` connects, `o` oper, …) to
//! send there. With no letters, every category goes to that channel (the original
//! behaviour). The key is repeatable, so different snomasks can be routed to
//! different channels: `chanlog = #xlog x` / `chanlog = #conns cq`.

use crate::server::Server;

/// Tee a snomask-`cat` server notice `msg` to every configured chanlog channel
/// whose filter admits `cat`. Called at the tail of `Server::snotice_c`. Read-only
/// over server state, so it can't loop.
pub fn tee(s: &Server, cat: char, msg: &str) {
    for spec in s.conf_all("chanlog") {
        let mut parts = spec.split_whitespace();
        let Some(chan) = parts.next() else {
            continue;
        };
        // Optional snomask filter: only these category letters go here; absent means
        // every category (so a bare `chanlog = #channel` logs everything, as before).
        if let Some(masks) = parts.next() {
            if !masks.contains(cat) {
                continue;
            }
        }
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            continue; // channel not created yet — nothing to log into
        }
        // to_channel builds the line once and shares it by Arc across members (and
        // adds the server-time tag per recipient) instead of cloning per member.
        let line = format!(":{} NOTICE {chan} :{msg}", s.name);
        s.to_channel(&key, &line, None);
    }
}
