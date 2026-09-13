//! Block a single channel message that highlights (mentions as a whole word) more than
//! `masshighlight` distinct *other* channel members — the "nick1 nick2 nick3 … <spam>"
//! mass-ping. Off unless `masshighlight` is set to a positive limit. IRC operators and
//! channel operators (op or above) are exempt, since they can legitimately address the
//! room. Counting is O(words-in-message), not O(members), so it stays cheap on a large
//! channel: each distinct word is resolved through the nick index rather than scanning
//! the member list.

use crate::channels::RANK_OP;
use crate::map::HashSet;
use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

/// A word boundary for highlight detection (mirrors the web-push highlighter, plus `@`
/// so `@nick` pings count too).
fn is_boundary(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            ',' | ':' | ';' | '.' | '!' | '?' | '<' | '>' | '(' | ')' | '"' | '@'
        )
}

/// Whether `text` mentions, as whole words, more than `limit` distinct nicks (other than
/// `sender`) for which `is_member` is true. Stops early once the limit is exceeded.
fn over_highlight_limit(
    text: &str,
    sender: &str,
    limit: usize,
    is_member: impl Fn(&str) -> bool,
) -> bool {
    let mut seen: HashSet<String> = HashSet::default();
    let mut count = 0usize;
    for word in text.split(is_boundary) {
        if word.is_empty() {
            continue;
        }
        let w = word.to_ascii_lowercase();
        if w == sender || !seen.insert(w.clone()) {
            continue;
        }
        if is_member(&w) {
            count += 1;
            if count > limit {
                return true;
            }
        }
    }
    false
}

pub struct MassHighlight;

impl Module for MassHighlight {
    fn name(&self) -> &'static str {
        "masshighlight"
    }
    fn on_pre_message(&mut self, s: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
        let limit = s.conf_num("masshighlight", 0usize);
        if limit == 0 || !target.starts_with('#') {
            return ModResult::Passthru;
        }
        let key = target.to_ascii_lowercase();
        // network staff and channel operators may address the whole room
        if s.is_oper(uid) || s.rank(uid, &key) >= RANK_OP {
            return ModResult::Passthru;
        }
        let sender = match s.users.get(&uid) {
            Some(u) => u.nick.to_ascii_lowercase(),
            None => return ModResult::Passthru,
        };
        // Count distinct members mentioned. `ch` and the nick-index lookups are all
        // shared borrows of `s`; the closure returns before any `&mut s` action below.
        let over = {
            let Some(ch) = s.channels.get(&key) else {
                return ModResult::Passthru;
            };
            over_highlight_limit(text, &sender, limit, |w| {
                if let Some(t) = s.find_nick(w) {
                    ch.members.contains_key(&t)
                } else if let Some((uuid, _)) = s.find_remote(w) {
                    ch.rmembers.contains_key(&uuid)
                } else {
                    false
                }
            })
        };
        if !over {
            return ModResult::Passthru;
        }
        let mask = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
        s.snotice_c(
            'f',
            &format!("MASSHIGHLIGHT: {mask} blocked in {target} (over {limit} highlights)"),
        );
        s.notice_star(
            uid,
            &format!("Your message to {target} was blocked: too many highlights (limit {limit})"),
        );
        ModResult::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_distinct_member_highlights() {
        let members: std::collections::HashSet<&str> =
            ["alice", "bob", "carol", "dave"].into_iter().collect();
        let m = |w: &str| members.contains(w);
        // 3 distinct members, limit 2 → over (block when count exceeds the limit)
        assert!(over_highlight_limit(
            "hey alice, bob and carol!",
            "spammer",
            2,
            m
        ));
        // exactly the limit (2 distinct) → not over
        assert!(!over_highlight_limit("alice and bob", "spammer", 2, m));
        // duplicates of one member count once
        assert!(!over_highlight_limit("alice alice alice", "spammer", 2, m));
        // non-members and the sender's own nick don't count
        assert!(!over_highlight_limit(
            "x y z alice sender",
            "sender",
            2,
            m
        ));
        // @nick pings are counted
        assert!(over_highlight_limit(
            "@alice @bob @carol @dave",
            "spammer",
            2,
            m
        ));
    }
}
