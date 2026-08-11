//! customprefix — reconfigure the channel prefix tiers from config, like InspIRCd's
//! m_customprefix does for existing prefixes (`change="yes"`). One line per tier:
//!
//! ```text
//! customprefix = op * ranktoset=admin ranktounset=admin depriv=no
//! customprefix = voice -
//! ```
//!
//! Tiers: `oper founder admin op halfop voice`. Knobs:
//!   * a bare token = the displayed sigil (e.g. `*`)
//!   * `ranktoset=<rank>`   min rank to grant this prefix (default: the prefix's rank)
//!   * `ranktounset=<rank>` min rank to revoke it (default: ranktoset)
//!   * `depriv=no`          members may not remove this prefix from themselves
//!
//! A `<rank>` is a number (1–6) or a tier name (`op`, `admin`, …). Only the display
//! and set/unset policy change — the mode letters (`yqaohv`) and ranks stay fixed, so
//! NAMES/WHO, ISUPPORT PREFIX and the S2S FJOIN burst stay consistent (a linked
//! network must share this config). Adding brand-new tiers with new letters/ranks
//! would need a data-driven prefix engine and isn't supported. Loaded once at boot.

use std::sync::OnceLock;

use crate::server::Server;

const TIER_NAMES: [&str; 6] = ["oper", "founder", "admin", "op", "halfop", "voice"];
const LETTERS: [char; 6] = ['y', 'q', 'a', 'o', 'h', 'v'];
const DEFAULT_SIGILS: [&str; 6] = ["!", "~", "&", "@", "%", "+"];
const RANKS: [u8; 6] = [6, 5, 4, 3, 2, 1]; // oper..voice

struct PrefixCfg {
    sigils: [String; 6],
    ranktoset: [Option<u8>; 6],
    ranktounset: [Option<u8>; 6],
    depriv: [bool; 6],
}

static CFG: OnceLock<PrefixCfg> = OnceLock::new();

/// Parse a rank: a number (1–6) or a tier name.
fn parse_rank(v: &str) -> Option<u8> {
    if let Ok(n) = v.parse::<u8>() {
        return Some(n.min(6));
    }
    TIER_NAMES
        .iter()
        .position(|t| t.eq_ignore_ascii_case(v))
        .map(|i| RANKS[i])
}

/// Load the `customprefix` overrides once, at boot.
pub fn init(s: &Server) {
    let mut cfg = PrefixCfg {
        sigils: DEFAULT_SIGILS.map(String::from),
        ranktoset: [None; 6],
        ranktounset: [None; 6],
        depriv: [true; 6],
    };
    for line in s.conf_all("customprefix") {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        let Some(i) = TIER_NAMES.iter().position(|t| t.eq_ignore_ascii_case(name)) else {
            continue;
        };
        for tok in it {
            match tok.split_once('=') {
                Some(("ranktoset", v)) => cfg.ranktoset[i] = parse_rank(v),
                Some(("ranktounset", v)) => cfg.ranktounset[i] = parse_rank(v),
                Some(("depriv", v)) => cfg.depriv[i] = crate::config::yesish(v),
                Some(_) => {}
                None => {
                    // a bare token is the sigil
                    if let Some(c) = tok.chars().next() {
                        cfg.sigils[i] = c.to_string();
                    }
                }
            }
        }
    }
    let _ = CFG.set(cfg);
}

/// The sigil for tier `i` (0 = oper … 5 = voice).
pub fn sigil(i: usize) -> &'static str {
    CFG.get()
        .map(|c| c.sigils[i].as_str())
        .unwrap_or(DEFAULT_SIGILS[i])
}

/// The prefix mode letter for a sigil char (FJOIN decode); `' '` if none.
pub fn letter_for_sigil(c: char) -> char {
    let cs = c.to_string();
    (0..6)
        .find(|&i| sigil(i) == cs)
        .map(|i| LETTERS[i])
        .unwrap_or(' ')
}

fn index_for_letter(letter: char) -> Option<usize> {
    LETTERS.iter().position(|&l| l == letter)
}

/// Configured minimum rank to grant the prefix with mode letter `letter` (None ⇒
/// use the prefix's own rank).
pub fn rank_to_set(letter: char) -> Option<u8> {
    let i = index_for_letter(letter)?;
    CFG.get()?.ranktoset[i]
}

/// Configured minimum rank to revoke the prefix (None ⇒ use the prefix's own rank).
pub fn rank_to_unset(letter: char) -> Option<u8> {
    let i = index_for_letter(letter)?;
    CFG.get()?.ranktounset[i]
}

/// Whether a member may remove this prefix from themselves (default yes).
pub fn can_depriv(letter: char) -> bool {
    index_for_letter(letter)
        .and_then(|i| CFG.get().map(|c| c.depriv[i]))
        .unwrap_or(true)
}

/// The ISUPPORT `PREFIX=(modes)symbols` token; `include_oper` adds the `y` tier.
pub fn isupport(include_oper: bool) -> String {
    let start = if include_oper { 0 } else { 1 };
    let letters: String = LETTERS[start..].iter().collect();
    let sigils: String = (start..6).map(sigil).collect();
    format!("({letters}){sigils}")
}
