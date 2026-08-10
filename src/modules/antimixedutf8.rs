//! antimixedutf8 — blocks spam that mixes Unicode scripts within words (Latin
//! letters swapped for Cyrillic/Greek look-alikes: "ＦᏒｅe Ⅴ1аgrа"). The scoring
//! rules and the confusable / fancy-Latin / zero-width tables define what counts as
//! spam.
//!
//! Per word: letters from more than one script score; so do words that are ASCII
//! mixed with Latin-confusable letters, words built almost entirely of confusables,
//! and "fancy" styled-Latin words. Zero-width chars score too. At/above the
//! configured threshold the action fires (block | kill | gline | kline | zline).

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Other = 0, // digits, punctuation, symbols — ignored for mixing
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Hebrew,
    Arabic,
    Cjk,
}

/// Map a codepoint to a script; `Other` for anything that isn't a letter we track.
fn classify_script(cp: u32) -> Script {
    match cp {
        0x41..=0x5A | 0x61..=0x7A => Script::Latin, // ASCII A-Z a-z
        0x00C0..=0x024F => Script::Latin,           // Latin-1 suppl + extended
        0x0370..=0x03FF => Script::Greek,
        0x0400..=0x04FF => Script::Cyrillic,
        0x0530..=0x058F => Script::Armenian,
        0x0590..=0x05FF => Script::Hebrew,
        0x0600..=0x06FF => Script::Arabic,
        0x4E00..=0x9FFF => Script::Cjk, // CJK unified
        0x3040..=0x30FF => Script::Cjk, // hiragana / katakana
        _ => Script::Other,
    }
}

/// A non-Latin letter that looks like an ASCII Latin letter (a homoglyph). Catches
/// pure-homoglyph words that script-mixing misses, without tripping on genuine
/// monolingual text.
fn is_latin_confusable(cp: u32) -> bool {
    matches!(
        cp,
        // Cyrillic look-alikes
        0x0430 | 0x0410 | 0x0435 | 0x0415 | 0x043E | 0x041E | 0x0440 | 0x0420 |
        0x0441 | 0x0421 | 0x0443 | 0x0423 | 0x0445 | 0x0425 | 0x0456 | 0x0406 |
        0x0455 | 0x0405 | 0x0458 | 0x0408 | 0x043A | 0x041A | 0x043C | 0x041C |
        0x043D | 0x041D | 0x0432 | 0x0412 | 0x0442 | 0x0422 |
        // Greek look-alikes
        0x03BF | 0x039F | 0x03B1 | 0x0391 | 0x03B5 | 0x0395 | 0x03C1 | 0x03A1 |
        0x03C5 | 0x03A5 | 0x03BD | 0x03BA | 0x039A | 0x03B9 | 0x0399 | 0x03BC |
        0x0392 | 0x039D | 0x03A4 | 0x0397 | 0x03A7 | 0x0396
    )
}

/// "Fancy" Latin: fullwidth, mathematical alphanumerics, enclosed/circled letters.
/// These render as styled ASCII ("𝐅𝐫𝐞𝐞", "Ｆｒｅｅ", "🅵🆁🅴🅴") — pure obfuscation.
fn is_fancy_latin(cp: u32) -> bool {
    matches!(
        cp,
        0xFF21..=0xFF5A     // fullwidth A-Z a-z
        | 0x1D400..=0x1D7FF // mathematical alphanumeric symbols
        | 0x1F130..=0x1F189 // squared/enclosed latin
        | 0x24B6..=0x24E9   // circled latin
        | 0x2460..=0x24FF   // enclosed alphanumerics (loose)
    )
}

/// Invisible / zero-width characters used to split words and evade filters.
fn is_invisible(cp: u32) -> bool {
    matches!(
        cp,
        0x00AD | 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF | 0x180E
    )
}

/// Per-message tally, folded word by word.
#[derive(Default)]
struct Scorer {
    mixedwords: u32,     // words mixing >1 real script
    homoglyphwords: u32, // ASCII + confusable letters in one word
    purehomowords: u32,  // word made (almost) entirely of confusables
    fancywords: u32,     // words containing fancy/styled latin
    invisibles: u32,     // zero-width chars anywhere
    totalletters: u32,
    latinletters: u32,
    wordhas: [bool; 8],
    word_has_ascii: bool,
    word_has_confusable: bool,
    word_has_fancy: bool,
    word_letters: u32,
    word_confusables: u32,
}

impl Scorer {
    fn word_scripts(&self) -> u32 {
        (1..8).filter(|&s| self.wordhas[s]).count() as u32
    }

    fn reset_word(&mut self) {
        self.wordhas = [false; 8];
        self.word_has_ascii = false;
        self.word_has_confusable = false;
        self.word_has_fancy = false;
        self.word_letters = 0;
        self.word_confusables = 0;
    }

    fn end_word(&mut self) {
        // Confusable mixed with real ASCII in one word: count once here so a single
        // stray homoglyph doesn't also score as script-mixing.
        if self.word_has_confusable && self.word_has_ascii {
            self.homoglyphwords += 1;
        } else if self.word_scripts() >= 2 {
            self.mixedwords += 1;
        } else if !self.word_has_ascii
            && self.word_scripts() == 1
            && self.word_letters >= 4
            && self.word_confusables * 100 / self.word_letters >= 80
        {
            // single-script word with no ASCII, ≥80% confusables = Latin in disguise
            self.purehomowords += 1;
        }
        if self.word_has_fancy {
            self.fancywords += 1;
        }
        self.reset_word();
    }
}

/// Score a message for look-alike / obfuscated-text spam. Higher = worse; genuine
/// monolingual text (any script) stays at 0.
fn score_message(text: &str) -> u32 {
    let mut sc = Scorer::default();
    for cp in text.chars().map(|c| c as u32) {
        if is_invisible(cp) {
            sc.invisibles += 1;
            continue; // not a word boundary
        }
        let fancy = is_fancy_latin(cp);
        let confusable = is_latin_confusable(cp);
        let script = classify_script(cp);
        let isletter = script != Script::Other || fancy;
        let isboundary = matches!(cp, 0x20 | 0x09 | 0x2C | 0x2E | 0x21 | 0x3F | 0xFFFD);

        if isletter {
            if script != Script::Other {
                sc.wordhas[script as usize] = true;
            }
            sc.totalletters += 1;
            sc.word_letters += 1;
            if script == Script::Latin {
                sc.latinletters += 1;
                sc.word_has_ascii = true;
            }
            if confusable {
                sc.word_has_confusable = true;
                sc.word_confusables += 1;
            }
            if fancy {
                sc.word_has_fancy = true;
            }
        }
        if isboundary {
            sc.end_word();
        }
    }
    sc.end_word(); // final word

    // One disguised word is usually an accident (a pasted Cyrillic letter); real
    // attacks disguise MANY. Grant a 1-word grace.
    let disguised = sc.homoglyphwords + sc.mixedwords + sc.purehomowords + sc.fancywords;
    let effective = disguised.saturating_sub(1);

    let mut score = 0u32;
    score += effective * 5; // each disguised word past the first
    score += sc.fancywords; // styled unicode is rarely innocent
    score += sc.invisibles * 3; // zero-width evasion is always suspicious

    // Ratio bonus: only with real disguise (≥2 words) and non-Latin dominance.
    if sc.totalletters >= 8 && disguised >= 2 {
        let nonlatin = sc.totalletters - sc.latinletters;
        if nonlatin > 0 && sc.latinletters > 0 && nonlatin * 100 / sc.totalletters >= 40 {
            score += 3;
        }
    }
    score
}

/// If `text` is a CTCP, return the ACTION body to check, else `None` to skip
/// (non-ACTION CTCPs aren't scanned). Plain messages return the text unchanged.
fn checkable(text: &str) -> Option<&str> {
    let Some(inner) = text.strip_prefix('\u{01}') else {
        return Some(text);
    };
    let inner = inner.strip_suffix('\u{01}').unwrap_or(inner);
    let (name, body) = inner.split_once(' ').unwrap_or((inner, ""));
    if name.eq_ignore_ascii_case("ACTION") {
        Some(body)
    } else {
        None
    }
}

/// A single-line, length-capped snippet of a blocked message for the oper
/// snotice. Keeps the look-alike glyphs visible (that's the point) but neutralises
/// every control byte (CR/LF, mIRC formatting) so it can't inject into or break
/// the protocol line the snotice is embedded in.
fn snippet(text: &str) -> String {
    const MAX: usize = 120;
    let mut out = String::new();
    for (i, ch) in text.chars().enumerate() {
        if i >= MAX {
            out.push('…');
            break;
        }
        if (ch as u32) < 0x20 || ch == '\u{7f}' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

pub struct AntiMixedUtf8;

impl Module for AntiMixedUtf8 {
    fn name(&self) -> &'static str {
        "antimixedutf8"
    }

    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        target: &str,
        text: &str,
    ) -> ModResult {
        if !srv.amu.enable {
            return ModResult::Passthru;
        }
        // exempt opers and users logged into an account
        if srv.is_oper(uid) || srv.is_logged_in(uid) {
            return ModResult::Passthru;
        }
        let is_channel = target.starts_with('#');
        if (is_channel && !srv.amu.check_channel) || (!is_channel && !srv.amu.check_private) {
            return ModResult::Passthru;
        }
        let Some(body) = checkable(text) else {
            return ModResult::Passthru;
        };
        if body.chars().count() < srv.amu.minlen {
            return ModResult::Passthru;
        }
        let score = score_message(body);
        if score < srv.amu.threshold {
            return ModResult::Passthru;
        }

        let (nick, mask, host, ip) = {
            let Some(u) = srv.users.get(&uid) else {
                return ModResult::Passthru;
            };
            (
                u.nick.clone(),
                u.prefix(),
                u.host.clone(),
                u.addr.ip().to_string(),
            )
        };
        // Snotice a sanitized snippet so opers can judge the catch / spot false positives.
        srv.snotice(&format!(
            "ANTIMIXEDUTF8: blocked spam from {mask} to {target} (score {score} >= {}): {}",
            srv.amu.threshold,
            snippet(body)
        ));

        // Notify the sender even for punitive actions: the writer flushes queued
        // lines before a disconnect.
        srv.send(
            uid,
            format!(
                ":{} NOTICE {nick} :*** {} (Flagged by the spam filter; network operators have been notified.)",
                srv.name, srv.amu.block_msg
            ),
        );

        let action = srv.amu.action.to_ascii_lowercase();
        let (dur, reason, setter) = (
            srv.amu.duration,
            srv.amu.reason.clone(),
            format!("antimixedutf8@{}", srv.name),
        );
        match action.as_str() {
            "gline" => srv.add_xline(XKind::Gline, &format!("*@{host}"), dur, &setter, &reason),
            "kline" => srv.add_xline(XKind::Kline, &format!("*@{host}"), dur, &setter, &reason),
            "zline" => srv.add_xline(XKind::Zline, &ip, dur, &setter, &reason),
            "kill" => srv.remove_user(uid, &reason),
            // "block": also emit the standard channel-failure numeric so clients
            // render the drop inline; the explanatory NOTICE above covers the rest.
            _ if is_channel => srv.numeric(
                uid,
                crate::numeric::ERR_CANNOTSENDTOCHAN,
                &format!("{target} :Message blocked by the spam filter"),
            ),
            _ => {}
        }
        ModResult::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genuine_monolingual_text_scores_zero() {
        assert_eq!(score_message("hello everyone how are you today"), 0); // Latin
        assert_eq!(score_message("привет всем как у вас дела сегодня"), 0); // Russian
        assert_eq!(score_message("γεια σας πως ειστε ολοι σημερα εδω"), 0); // Greek
    }

    #[test]
    fn mixed_script_spam_scores_high() {
        // Cyrillic look-alikes swapped into Latin words (multi-word disguise)
        assert!(score_message("Ѕесurіtу аlеrt сlісk hеrе nоw рlеаѕе") >= 8);
        // fancy/fullwidth styled word run
        assert!(score_message("Ｆｒｅｅ Ｖ１ａｇｒａ ｎｏｗ ｃｌｉｃｋ ｈｅｒｅ") >= 8);
    }

    #[test]
    fn one_stray_homoglyph_is_tolerated() {
        // a single disguised word gets the 1-word grace → stays under threshold
        assert!(score_message("hello wоrld this is a normal message") < 8);
    }

    #[test]
    fn zero_width_evasion_scores() {
        // three zero-width joiners = 3*3 = 9
        assert!(score_message("buy\u{200b}now\u{200b}cheap\u{200b}deal") >= 8);
    }

    #[test]
    fn snippet_is_one_clean_line_and_capped() {
        // CR/LF and mIRC control bytes are neutralised (no protocol injection)
        assert_eq!(snippet("hi\r\nthere"), "hi  there");
        assert!(!snippet("x\u{03}04red").contains('\u{03}'));
        // look-alike glyphs survive so opers can see what was caught
        assert!(snippet("Ѕесurіtу").contains('Ѕ'));
        // long input is capped with an ellipsis
        let s = snippet(&"a".repeat(200));
        assert!(s.ends_with('…') && s.chars().count() == 121);
    }
}
