//! Pluggable pattern engines: match text against a pattern using either simple
//! wildcard globs or full regular expressions, selected by name from config.
//!
//! Modules that test user input against admin-set patterns (e.g. the spam
//! `filter`) compile a pattern once via [`compile`] — rejecting a bad one at set
//! time — then call [`Matcher::is_match`] on the hot path, so the engine choice
//! costs a single virtual call and no per-message compilation. New engines slot in
//! by adding an arm to [`compile`] and a name to [`ENGINES`].

use crate::channels::glob_match;
use crate::regex::Regex;

/// A compiled pattern that can test text for a match. `Send` so it can live in
/// `Server.ext` alongside the rest of a module's state.
pub trait Matcher: Send {
    fn is_match(&self, text: &str) -> bool;
}

/// Wildcard glob (`*` / `?`), the default — case-insensitive like the rest of the
/// ircd's mask matching.
struct GlobMatcher(String);
impl Matcher for GlobMatcher {
    fn is_match(&self, text: &str) -> bool {
        glob_match(&self.0, text)
    }
}

/// Full regular expression (the same engine RLINE uses).
struct RegexMatcher(Regex);
impl Matcher for RegexMatcher {
    fn is_match(&self, text: &str) -> bool {
        self.0.is_match(text)
    }
}

/// The engine names selectable in config (for help text / error messages).
pub const ENGINES: &[&str] = &["glob", "regex"];

/// Compile `pattern` for the named `engine`: `glob` (default, wildcards) or
/// `regex` (a full regular expression). Errors on an unknown engine or an invalid
/// regex, so a bad rule is refused when it's set rather than silently never matching.
pub fn compile(engine: &str, pattern: &str) -> Result<Box<dyn Matcher>, String> {
    match engine {
        "glob" | "" => Ok(Box::new(GlobMatcher(pattern.to_string()))),
        "regex" => Ok(Box::new(RegexMatcher(Regex::new(pattern)?))),
        other => Err(format!(
            "unknown pattern engine '{other}' (use one of: {})",
            ENGINES.join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_and_regex_engines_match() {
        let g = compile("glob", "*spam*").unwrap();
        assert!(g.is_match("this is SPAM here")); // wildcards, case-insensitive
        assert!(!g.is_match("clean text"));

        let r = compile("regex", "spam.*bot").unwrap();
        assert!(r.is_match("a spam sending bot")); // full regex (case-sensitive, substring)
        assert!(!r.is_match("nothing to see"));

        // default (empty) engine is glob
        assert!(compile("", "*x*").unwrap().is_match("axb"));
    }

    #[test]
    fn bad_engine_or_regex_is_rejected() {
        assert!(compile("pcre", ".*").is_err()); // unknown engine
        assert!(compile("regex", "(unclosed").is_err()); // invalid regex
    }
}
