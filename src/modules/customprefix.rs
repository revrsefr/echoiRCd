//! customprefix — override the *symbol* (sigil) of the channel prefix tiers from
//! config, e.g. show `!` for op instead of `@`. One line per tier:
//!
//! ```text
//! customprefix = op *          # ops show as *nick, PREFIX advertises it too
//! customprefix = voice -
//! ```
//!
//! Tiers: `oper founder admin op halfop voice`. Only the displayed symbol changes —
//! the mode letters (`yqaohv`) and ranks stay fixed, so NAMES/WHO, ISUPPORT PREFIX
//! and the S2S FJOIN burst stay consistent (a linked network must share this config,
//! as with InspIRCd). Loaded once at boot; unset tiers keep their default sigil.

use std::sync::OnceLock;

use crate::server::Server;

const TIER_NAMES: [&str; 6] = ["oper", "founder", "admin", "op", "halfop", "voice"];
const LETTERS: [char; 6] = ['y', 'q', 'a', 'o', 'h', 'v'];
const DEFAULT_SIGILS: [&str; 6] = ["!", "~", "&", "@", "%", "+"];

/// The configured sigils, indexed by tier. Being a `static` its `String`s live for
/// the program, so `sigil()` can hand out `&'static str` without leaking.
static SIGILS: OnceLock<[String; 6]> = OnceLock::new();

/// Load the `customprefix` overrides once, at boot.
pub fn init(s: &Server) {
    let mut a: [String; 6] = DEFAULT_SIGILS.map(String::from);
    for line in s.conf_all("customprefix") {
        let mut it = line.split_whitespace();
        if let (Some(name), Some(sym)) = (it.next(), it.next()) {
            if let Some(i) = TIER_NAMES.iter().position(|t| t.eq_ignore_ascii_case(name)) {
                if let Some(c) = sym.chars().next() {
                    a[i] = c.to_string();
                }
            }
        }
    }
    let _ = SIGILS.set(a);
}

/// The sigil for tier `i` (0 = oper … 5 = voice).
pub fn sigil(i: usize) -> &'static str {
    SIGILS
        .get()
        .map(|a| a[i].as_str())
        .unwrap_or(DEFAULT_SIGILS[i])
}

/// The prefix mode letter for a sigil char (used by the FJOIN decode); `' '` if the
/// char isn't a prefix sigil.
pub fn letter_for_sigil(c: char) -> char {
    let cs = c.to_string();
    (0..6)
        .find(|&i| sigil(i) == cs)
        .map(|i| LETTERS[i])
        .unwrap_or(' ')
}

/// The ISUPPORT `PREFIX=(modes)symbols` token; `include_oper` adds the `y` tier
/// (operprefix/ojoin).
pub fn isupport(include_oper: bool) -> String {
    let start = if include_oper { 0 } else { 1 };
    let letters: String = LETTERS[start..].iter().collect();
    let sigils: String = (start..6).map(sigil).collect();
    format!("({letters}){sigils}")
}
