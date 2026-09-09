//! Hides specific mode changes from channel members below a rank (e.g. bans being
//! set/removed). Config, repeatable: `hidemode = <modechar> <rank>` (rank:
//! owner|admin|op|halfop|voice). The setter, opers and linked servers always see
//! the full change.

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
        _ => RANK_OP,
    }
}

/// The minimum rank needed to *see* changes to `modechar`, if it's configured
/// hidden. `None` ⇒ the mode is visible to everyone (the common case).
pub fn hidden_rank(s: &Server, modechar: char) -> Option<u8> {
    for line in s.conf_all("hidemode") {
        let mut it = line.split_whitespace();
        if let (Some(mc), Some(rank)) = (it.next(), it.next()) {
            if mc.starts_with(modechar) {
                return Some(rank_value(rank));
            }
        }
    }
    None
}

/// Render a subset of changes back into a `<modes> <params…>` pair.
fn render(changes: &[&(char, char, Option<String>)]) -> (String, Vec<String>) {
    let mut modes = String::new();
    let mut last = ' ';
    let mut params = Vec::new();
    for (sign, letter, param) in changes {
        if *sign != last {
            modes.push(*sign);
            last = *sign;
        }
        modes.push(*letter);
        if let Some(p) = param {
            params.push(p.clone());
        }
    }
    (modes, params)
}

/// Deliver a MODE change per-recipient, dropping any hidden mode from the line sent
/// to members below its required rank. Called from `apply_mode` only when at least
/// one changed mode is hidden.
pub fn broadcast(
    s: &Server,
    key: &str,
    target: &str,
    setter: Uid,
    prefix: &str,
    changes: &[(char, char, Option<String>)],
) {
    let members: Vec<Uid> = s
        .channels
        .get(key)
        .map(|c| c.members.keys().copied().collect())
        .unwrap_or_default();
    // resolve each changed mode's hidden-rank once (a config scan) rather than
    // re-scanning `hidemode` for every (member × change) pair.
    let hidden: Vec<Option<u8>> = changes.iter().map(|(_, c, _)| hidden_rank(s, *c)).collect();
    for m in members {
        let privileged = m == setter || s.is_oper(m);
        // compute this member's rank once, not once per changed mode
        let mrank = if privileged { u8::MAX } else { s.rank(m, key) };
        let visible: Vec<&(char, char, Option<String>)> = changes
            .iter()
            .enumerate()
            .filter(|(i, _)| match hidden[*i] {
                None => true,
                Some(req) => mrank >= req,
            })
            .map(|(_, ch)| ch)
            .collect();
        if visible.is_empty() {
            continue;
        }
        let (modes, params) = render(&visible);
        let pstr = if params.is_empty() {
            String::new()
        } else {
            format!(" {}", params.join(" "))
        };
        s.send(m, format!(":{prefix} MODE {target} {modes}{pstr}"));
    }
}
