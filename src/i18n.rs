//! Server-wide message localization.
//!
//! The English strings in the source are the msgids (the source of truth); a per-locale
//! catalog file `lang/<code>.conf` maps each to its translation. The catalog is parsed
//! ONCE at startup/rehash into an in-memory map — there is no per-message disk access and
//! no per-message parsing. `locale = en` (or a missing file) yields an empty catalog that
//! passes English through untouched, so the default path is byte-for-byte what it was.
//!
//! Only prose sent to a LOCAL client is localized (numeric trailing text, notices). The
//! hot channel-broadcast fan-out is protocol (`PRIVMSG`/`JOIN`/`MODE`) and is never
//! touched, so the fast path is unchanged. Protocol tokens, params, nicks, channels and
//! the S2S wire stay canonical English always.
//!
//! File format, one entry per line (blank lines and `#` comments ignored):
//! ```text
//! "No such nick/channel" = "Aucun pseudo/salon de ce nom"
//! "Welcome to the {0} IRC Network, {1}" = "Bienvenue sur le réseau IRC {0}, {1}"
//! ```
//! `{0}`,`{1}`,… are positional placeholders filled after translation, so word order
//! may differ per language. A translation whose placeholder set differs from its msgid
//! is rejected at load time (kept as English) so a bad file can never panic or drop args.

use crate::map::HashMap;
use std::borrow::Cow;

/// A loaded locale: English msgid -> translated string. Empty = English passthrough.
#[derive(Default)]
pub struct Catalog {
    map: HashMap<Box<str>, Box<str>>,
    pub locale: String,
}

impl Catalog {
    /// English passthrough (locale `en` or a missing/unreadable file).
    pub fn passthrough() -> Catalog {
        Catalog {
            map: HashMap::default(),
            locale: "en".to_string(),
        }
    }

    #[inline]
    pub fn is_passthrough(&self) -> bool {
        self.map.is_empty()
    }

    pub fn entries(&self) -> usize {
        self.map.len()
    }

    /// Load `<dir>/<locale>.conf`. `en`/empty/unreadable -> passthrough. The second
    /// return value is a list of human-readable warnings (bad lines, placeholder
    /// mismatches, missing file) for the caller to log — loading never fails hard.
    pub fn load(dir: &str, locale: &str) -> (Catalog, Vec<String>) {
        let mut warnings = Vec::new();
        if locale.is_empty() || locale.eq_ignore_ascii_case("en") {
            return (Catalog::passthrough(), warnings);
        }
        let path = format!("{dir}/{locale}.conf");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                warnings.push(format!("locale {locale}: cannot read {path}: {e} (using English)"));
                return (Catalog::passthrough(), warnings);
            }
        };
        let mut map: HashMap<Box<str>, Box<str>> = HashMap::default();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_entry(line) {
                Some((key, val)) => {
                    if placeholders(&key) != placeholders(&val) {
                        warnings.push(format!(
                            "locale {locale}:{}: placeholder set differs from msgid, skipped: {key:?}",
                            i + 1
                        ));
                        continue;
                    }
                    if !val.is_empty() {
                        map.insert(key.into_boxed_str(), val.into_boxed_str());
                    }
                }
                None => warnings.push(format!("locale {locale}:{}: malformed entry, skipped", i + 1)),
            }
        }
        (
            Catalog {
                map,
                locale: locale.to_string(),
            },
            warnings,
        )
    }

    /// Translate a whole English string; returns the input unchanged if not present.
    #[inline]
    pub fn tr<'a>(&'a self, english: &'a str) -> &'a str {
        match self.map.get(english) {
            Some(t) => t,
            None => english,
        }
    }

    /// Translate only the *trailing prose* of a numeric body `[params ]:trailing`,
    /// leaving params (nicks/channels/numbers) intact. Passthrough locales and bodies
    /// with no catalogued trailing return the input borrowed (no allocation).
    pub fn tr_numeric<'a>(&'a self, rest: &'a str) -> Cow<'a, str> {
        if self.is_passthrough() {
            return Cow::Borrowed(rest);
        }
        let (head, trail) = if let Some(idx) = rest.find(" :") {
            (&rest[..idx + 2], &rest[idx + 2..])
        } else if rest.starts_with(':') {
            (&rest[..1], &rest[1..])
        } else {
            return Cow::Borrowed(rest);
        };
        let translated = self.tr(trail);
        if std::ptr::eq(translated.as_ptr(), trail.as_ptr()) {
            Cow::Borrowed(rest)
        } else {
            Cow::Owned(format!("{head}{translated}"))
        }
    }
}

/// Fill `{0}`,`{1}`,… placeholders in a (already-translated) template. `{{`/`}}` are
/// literal braces; an out-of-range or malformed index is emitted verbatim so a bad
/// template degrades to visible text rather than losing data.
pub fn render(template: &str, args: &[&str]) -> String {
    if !template.contains('{') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len() + 16);
    let b = template.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' if i + 1 < b.len() && b[i + 1] == b'{' => {
                out.push('{');
                i += 2;
            }
            b'}' if i + 1 < b.len() && b[i + 1] == b'}' => {
                out.push('}');
                i += 2;
            }
            b'{' => {
                if let Some(end) = template[i + 1..].find('}') {
                    let inner = &template[i + 1..i + 1 + end];
                    if let Ok(idx) = inner.parse::<usize>() {
                        if let Some(a) = args.get(idx) {
                            out.push_str(a);
                        }
                        i += end + 2;
                        continue;
                    }
                }
                out.push('{');
                i += 1;
            }
            _ => {
                // copy one UTF-8 char
                let ch_len = utf8_len(b[i]);
                out.push_str(&template[i..i + ch_len]);
                i += ch_len;
            }
        }
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// The set of placeholder indices `{N}` used in `s` (ignoring `{{`/`}}`).
fn placeholders(s: &str) -> std::collections::BTreeSet<usize> {
    let mut set = std::collections::BTreeSet::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if i + 1 < b.len() && b[i + 1] == b'{' {
                i += 2;
                continue;
            }
            if let Some(end) = s[i + 1..].find('}') {
                if let Ok(idx) = s[i + 1..i + 1 + end].parse::<usize>() {
                    set.insert(idx);
                }
                i += end + 2;
                continue;
            }
        }
        i += 1;
    }
    set
}

/// Parse one `"msgid" = "msgstr"` line, honoring `\"`, `\\` and `\n` escapes.
fn parse_entry(line: &str) -> Option<(String, String)> {
    let (key, rest) = read_quoted(line)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let (val, tail) = read_quoted(rest)?;
    if !tail.trim().is_empty() {
        return None;
    }
    Some((key, val))
}

/// Read a `"..."` string at the start of `s`; return (unescaped, remainder).
fn read_quoted(s: &str) -> Option<(String, &str)> {
    let mut chars = s.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    while let Some((idx, c)) = chars.next() {
        match c {
            '\\' => match chars.next()?.1 {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                // \xNN — a raw byte, so IRC formatting controls (e.g. \x02 bold) in a
                // msgid match the literal byte the source `"\x02"` compiles to.
                'x' => {
                    let (h1, h2) = (chars.next()?.1, chars.next()?.1);
                    match u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                        Ok(b) => out.push(b as char),
                        Err(_) => {
                            out.push('\\');
                            out.push('x');
                            out.push(h1);
                            out.push(h2);
                        }
                    }
                }
                other => {
                    out.push('\\');
                    out.push(other);
                }
            },
            '"' => return Some((out, &s[idx + 1..])),
            _ => out.push(c),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fills_positional_and_reorders() {
        assert_eq!(render("Hi {0} and {1}", &["a", "b"]), "Hi a and b");
        // translations may reorder
        assert_eq!(render("{1} puis {0}", &["a", "b"]), "b puis a");
        assert_eq!(render("no args here", &[]), "no args here");
        assert_eq!(render("brace {{ ok }}", &[]), "brace { ok }");
    }

    #[test]
    fn parse_and_translate() {
        let text = "\"No such nick/channel\" = \"Aucun pseudo/salon de ce nom\"\n# c\n\"x {0}\" = \"y {0}\"\n";
        std::fs::create_dir_all("/tmp/echo-i18n-test").unwrap();
        std::fs::write("/tmp/echo-i18n-test/fr.conf", text).unwrap();
        let (cat, warns) = Catalog::load("/tmp/echo-i18n-test", "fr");
        assert!(warns.is_empty(), "{warns:?}");
        assert_eq!(cat.tr("No such nick/channel"), "Aucun pseudo/salon de ce nom");
        assert_eq!(cat.tr("unknown"), "unknown"); // fallback
    }

    #[test]
    fn numeric_translates_only_trailing() {
        let text = "\"You're not on that channel\" = \"Vous n'êtes pas sur ce salon\"\n";
        std::fs::create_dir_all("/tmp/echo-i18n-test2").unwrap();
        std::fs::write("/tmp/echo-i18n-test2/fr.conf", text).unwrap();
        let (cat, _) = Catalog::load("/tmp/echo-i18n-test2", "fr");
        // params (#chan) preserved, trailing prose translated
        assert_eq!(
            cat.tr_numeric("#chan :You're not on that channel"),
            "#chan :Vous n'êtes pas sur ce salon"
        );
        // data trailing not in catalog -> unchanged, no allocation
        assert!(matches!(cat.tr_numeric("bob user host * :Real Name"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn placeholder_mismatch_is_rejected() {
        let text = "\"a {0} {1}\" = \"b {0}\"\n"; // drops {1}
        std::fs::create_dir_all("/tmp/echo-i18n-test3").unwrap();
        std::fs::write("/tmp/echo-i18n-test3/fr.conf", text).unwrap();
        let (cat, warns) = Catalog::load("/tmp/echo-i18n-test3", "fr");
        assert_eq!(warns.len(), 1);
        assert_eq!(cat.tr("a {0} {1}"), "a {0} {1}"); // stayed English
    }
}
