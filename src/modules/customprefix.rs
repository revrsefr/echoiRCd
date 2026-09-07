//! customprefix — reconfigure the channel prefix tiers *and* define brand-new ones.
//! Two forms, one line each:
//!
//! ```text
//! # reconfigure a built-in tier (oper founder admin op halfop voice):
//! customprefix = op * ranktoset=admin ranktounset=admin depriv=no
//!
//! # define a NEW prefix mode (name is anything that isn't a built-in tier):
//! customprefix = helper letter=V prefix=? rank=25 ranktoset=op ranktounset=op depriv=yes
//! ```
//!
//! For a built-in tier: a bare token is the sigil; `ranktoset`/`ranktounset` set the
//! min rank to grant/revoke it; `depriv=no` forbids self-removal. For a new prefix:
//! `letter` (mode char) and `prefix` (sigil) are required; `rank` is its rank
//! (default 1); `ranktoset`/`ranktounset` default to `rank`; `depriv` defaults yes.
//! A `<rank>` is a number or a built-in tier name. New prefixes flow through the
//! normal mode machinery (a dynamic handler is registered in [`crate::mode`]) and
//! are held on `Member.custom_prefixes`. A linked network must share this config.

use std::sync::OnceLock;

use crate::config::yesish;
use crate::server::Server;

const TIER_NAMES: [&str; 6] = ["oper", "founder", "admin", "op", "halfop", "voice"];
pub const LETTERS: [char; 6] = ['y', 'q', 'a', 'o', 'h', 'v'];
const DEFAULT_SIGILS: [&str; 6] = ["!", "~", "&", "@", "%", "+"];
/// Built-in tier ranks (×10 spacing leaves room to slot custom tiers between them).
pub const RANKS: [u8; 6] = [60, 50, 40, 30, 20, 10];

/// A config-defined channel prefix mode.
pub struct PrefixDef {
    pub letter: char,
    pub sigil: String,
    pub rank: u8,
    pub ranktoset: u8,
    pub ranktounset: u8,
    pub depriv: bool,
}

struct PrefixCfg {
    sigils: [String; 6],
    ranktoset: [Option<u8>; 6],
    ranktounset: [Option<u8>; 6],
    depriv: [bool; 6],
    custom: Vec<PrefixDef>,
}

static CFG: OnceLock<PrefixCfg> = OnceLock::new();

fn is_builtin_letter(c: char) -> bool {
    LETTERS.contains(&c)
}

/// Parse a rank: a number or a tier name.
fn parse_rank(v: &str) -> Option<u8> {
    if let Ok(n) = v.parse::<u8>() {
        return Some(n);
    }
    TIER_NAMES
        .iter()
        .position(|t| t.eq_ignore_ascii_case(v))
        .map(|i| RANKS[i])
}

/// Load the `customprefix` config once, at boot.
pub fn init(s: &Server) {
    let mut cfg = PrefixCfg {
        sigils: DEFAULT_SIGILS.map(String::from),
        ranktoset: [None; 6],
        ranktounset: [None; 6],
        depriv: [true; 6],
        custom: Vec::new(),
    };
    for line in s.conf_all("customprefix") {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        if let Some(i) = TIER_NAMES.iter().position(|t| t.eq_ignore_ascii_case(name)) {
            // reconfigure a built-in tier
            for tok in it {
                match tok.split_once('=') {
                    Some(("ranktoset", v)) => cfg.ranktoset[i] = parse_rank(v),
                    Some(("ranktounset", v)) => cfg.ranktounset[i] = parse_rank(v),
                    Some(("depriv", v)) => cfg.depriv[i] = yesish(v),
                    Some(_) => {}
                    None => {
                        if let Some(c) = tok.chars().next() {
                            cfg.sigils[i] = c.to_string();
                        }
                    }
                }
            }
        } else {
            // define a new prefix mode
            let (mut letter, mut sigil, mut rank, mut rts, mut rtu, mut depriv) =
                (None, None, 1u8, None, None, true);
            for tok in it {
                match tok.split_once('=') {
                    Some(("letter", v)) => letter = v.chars().next(),
                    Some(("prefix", v)) => sigil = v.chars().next(),
                    Some(("rank", v)) => rank = parse_rank(v).unwrap_or(1),
                    Some(("ranktoset", v)) => rts = parse_rank(v),
                    Some(("ranktounset", v)) => rtu = parse_rank(v),
                    Some(("depriv", v)) => depriv = yesish(v),
                    _ => {}
                }
            }
            if let (Some(l), Some(sy)) = (letter, sigil) {
                // don't shadow a built-in mode letter or a duplicate custom one
                let taken = is_builtin_letter(l)
                    || crate::mode::chan_mode(l).is_some()
                    || cfg.custom.iter().any(|d| d.letter == l);
                if !taken {
                    let ranktoset = rts.unwrap_or(rank);
                    cfg.custom.push(PrefixDef {
                        letter: l,
                        sigil: sy.to_string(),
                        rank,
                        ranktoset,
                        ranktounset: rtu.unwrap_or(ranktoset),
                        depriv,
                    });
                }
            }
        }
    }
    let _ = CFG.set(cfg);
}

/// The sigil for built-in tier `i` (0 = oper … 5 = voice).
pub fn sigil(i: usize) -> &'static str {
    CFG.get()
        .map(|c| c.sigils[i].as_str())
        .unwrap_or(DEFAULT_SIGILS[i])
}

/// Every config-defined (non-built-in) prefix.
pub fn custom_defs() -> &'static [PrefixDef] {
    CFG.get().map(|c| c.custom.as_slice()).unwrap_or(&[])
}

/// A custom prefix by its mode letter.
pub fn def_for_letter(c: char) -> Option<&'static PrefixDef> {
    custom_defs().iter().find(|d| d.letter == c)
}

fn builtin_index(letter: char) -> Option<usize> {
    LETTERS.iter().position(|&l| l == letter)
}

/// Min rank to grant a prefix (None ⇒ use the prefix's own rank).
pub fn rank_to_set(letter: char) -> Option<u8> {
    if let Some(i) = builtin_index(letter) {
        return CFG.get().and_then(|c| c.ranktoset[i]);
    }
    def_for_letter(letter).map(|d| d.ranktoset)
}

/// Min rank to revoke a prefix (None ⇒ use the prefix's own rank).
pub fn rank_to_unset(letter: char) -> Option<u8> {
    if let Some(i) = builtin_index(letter) {
        return CFG.get().and_then(|c| c.ranktounset[i]);
    }
    def_for_letter(letter).map(|d| d.ranktounset)
}

/// Whether a member may remove this prefix from themselves (default yes).
pub fn can_depriv(letter: char) -> bool {
    if let Some(i) = builtin_index(letter) {
        return CFG.get().map(|c| c.depriv[i]).unwrap_or(true);
    }
    def_for_letter(letter).map(|d| d.depriv).unwrap_or(true)
}

/// The ISUPPORT `PREFIX=(modes)symbols` token — built-in tiers plus custom prefixes,
/// ordered high→low by rank. `include_oper` adds the `y` (operprefix) tier.
pub fn isupport(include_oper: bool) -> String {
    let mut all: Vec<(u8, char, &'static str)> = Vec::new();
    let start = if include_oper { 0 } else { 1 };
    for i in start..6 {
        all.push((RANKS[i], LETTERS[i], sigil(i)));
    }
    for d in custom_defs() {
        all.push((d.rank, d.letter, d.sigil.as_str()));
    }
    all.sort_by(|a, b| b.0.cmp(&a.0));
    let letters: String = all.iter().map(|(_, l, _)| *l).collect();
    let sigils: String = all.iter().map(|(_, _, s)| *s).collect();
    format!("({letters}){sigils}")
}
