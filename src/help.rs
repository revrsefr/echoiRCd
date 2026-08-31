//! Config-driven, localisable HELP topics. Each `help/<code>.conf` holds `[TOPIC]`
//! sections whose following lines are the body, in order; `[INDEX]` is shown for a
//! bare /HELP. English (`help/en.conf`) is embedded as the built-in fallback and
//! may be overridden on disk; the active `locale` file then overlays its topics on
//! top, so a partial translation still falls back to English per topic. Loaded at
//! startup and reloaded on REHASH — editing help never needs a rebuild or restart.

use std::collections::HashMap;

const EMBEDDED_EN: &str = include_str!("../help/en.conf");

#[derive(Default)]
pub struct HelpBook {
    topics: HashMap<String, Vec<String>>,
}

impl HelpBook {
    /// Body lines for a topic (case-insensitive), or `None` if unknown.
    pub fn get(&self, topic: &str) -> Option<&[String]> {
        self.topics.get(&topic.to_ascii_uppercase()).map(Vec::as_slice)
    }

    /// Embedded English → disk `<dir>/en.conf` → disk `<dir>/<locale>.conf`, each
    /// overlaying the previous by topic. Warnings are collected, never fatal.
    pub fn load(dir: &str, locale: &str) -> (HelpBook, Vec<String>) {
        let mut warnings = Vec::new();
        let mut topics = parse(EMBEDDED_EN);
        overlay(&mut topics, dir, "en", false, &mut warnings);
        if !locale.is_empty() && !locale.eq_ignore_ascii_case("en") {
            overlay(&mut topics, dir, locale, true, &mut warnings);
        }
        (HelpBook { topics }, warnings)
    }
}

/// Read `<dir>/<code>.conf` and replace each non-empty topic it defines.
fn overlay(
    topics: &mut HashMap<String, Vec<String>>,
    dir: &str,
    code: &str,
    warn_missing: bool,
    warnings: &mut Vec<String>,
) {
    let path = format!("{dir}/{code}.conf");
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            for (name, lines) in parse(&text) {
                if !lines.is_empty() {
                    topics.insert(name, lines);
                }
            }
        }
        Err(e) if warn_missing => {
            warnings.push(format!("help {code}: cannot read {path}: {e} (using English)"));
        }
        Err(_) => {}
    }
}

/// `[TOPIC]` headers open a section; following non-comment, non-blank lines are its
/// body (trailing whitespace trimmed, leading kept for alignment).
fn parse(text: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    let mut cur: Option<String> = None;
    for raw in text.lines() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(name) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let name = name.trim().to_ascii_uppercase();
            map.entry(name.clone()).or_default();
            cur = Some(name);
            continue;
        }
        if let Some(c) = &cur {
            if let Some(v) = map.get_mut(c) {
                v.push(raw.trim_end().to_string());
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_en_has_core_topics() {
        let (book, warn) = HelpBook::load("help", "en");
        assert!(warn.is_empty(), "unexpected warnings: {warn:?}");
        for t in ["INDEX", "CHANNELS", "CHMODES", "SERVICES", "OPER"] {
            assert!(book.get(t).is_some_and(|l| !l.is_empty()), "missing topic {t}");
        }
        // case-insensitive lookup
        assert_eq!(book.get("chmodes").is_some(), true);
    }

    #[test]
    fn parse_keeps_order_and_leading_space() {
        let m = parse("[A]\nfirst\n   indented\n# c\n\nlast\n");
        assert_eq!(m["A"], vec!["first", "   indented", "last"]);
    }

    #[test]
    fn missing_locale_warns_and_falls_back() {
        let (book, warn) = HelpBook::load("help", "zz");
        assert!(warn.iter().any(|w| w.contains("zz")));
        assert!(book.get("INDEX").is_some()); // English still present
    }
}
