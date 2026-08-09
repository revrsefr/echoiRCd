//! Minimal JSON for the RPC subsystem — no serde (openssl+mio-only crate policy).
//! Two jobs: pull a named field out of a flat-ish request object (`get_*`), and
//! escape strings when *building* result JSON with `format!`. The scanners respect
//! nesting and string escapes, so `get_raw` only ever matches a **top-level** key
//! (a `"nick"` buried inside a nested value or another string won't false-match).

/// Given `b[i] == b'"'`, return the index just past the closing quote.
fn scan_string(b: &[u8], mut i: usize) -> Option<usize> {
    debug_assert!(b[i] == b'"');
    i += 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2, // skip the escaped char
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Given `i` at the first byte of a JSON value, return the index just past it.
fn scan_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => scan_string(b, i),
        b'{' | b'[' => {
            let (open, close) = if b[i] == b'{' {
                (b'{', b'}')
            } else {
                (b'[', b']')
            };
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => j = scan_string(b, j)?,
                    c if c == open => {
                        depth += 1;
                        j += 1;
                    }
                    c if c == close => {
                        depth -= 1;
                        j += 1;
                        if depth == 0 {
                            return Some(j);
                        }
                    }
                    _ => j += 1,
                }
            }
            None
        }
        // scalar: number / true / false / null — up to the next delimiter
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The raw text of top-level object key `key` in `obj` (value verbatim, incl. any
/// quotes/braces), or `None` if the key isn't a top-level member.
pub fn get_raw(obj: &str, key: &str) -> Option<String> {
    let b = obj.as_bytes();
    let mut i = obj.find('{')? + 1;
    loop {
        // skip whitespace / commas to the next key string
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
            i += 1;
        }
        if i >= b.len() || b[i] == b'}' {
            return None;
        }
        if b[i] != b'"' {
            return None; // malformed
        }
        let key_end = scan_string(b, i)?;
        let this_key = &obj[i + 1..key_end - 1];
        // skip ws + ':'
        let mut c = key_end;
        while c < b.len() && matches!(b[c], b' ' | b'\t' | b'\n' | b'\r') {
            c += 1;
        }
        if b.get(c) != Some(&b':') {
            return None;
        }
        c += 1;
        while c < b.len() && matches!(b[c], b' ' | b'\t' | b'\n' | b'\r') {
            c += 1;
        }
        let val_end = scan_value(b, c)?;
        if this_key == key {
            return Some(obj[c..val_end].to_string());
        }
        i = val_end;
    }
}

/// A string field, JSON-unescaped. `None` if absent or not a string.
pub fn get_str(obj: &str, key: &str) -> Option<String> {
    let raw = get_raw(obj, key)?;
    let inner = raw.strip_prefix('"')?.strip_suffix('"')?;
    Some(unescape(inner))
}

/// A numeric field parsed as `T`. Accepts a bare number or a quoted number.
pub fn get_num<T: std::str::FromStr>(obj: &str, key: &str) -> Option<T> {
    let raw = get_raw(obj, key)?;
    raw.trim_matches('"').parse().ok()
}

/// A boolean field (`true`/`false`, or the strings `"true"`/`"false"`).
pub fn get_bool(obj: &str, key: &str) -> Option<bool> {
    match get_raw(obj, key)?.trim_matches('"') {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Unescape a JSON string body (the bytes between the quotes).
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('b') => out.push('\u{08}'),
            Some('f') => out.push('\u{0C}'),
            Some('u') => {
                let hex: String = it.by_ref().take(4).collect();
                if let Some(ch) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

/// Escape a string for embedding in JSON output (between quotes).
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A JSON object literal from `(key, raw-json-value)` pairs. Values are inserted
/// verbatim (already valid JSON) — use [`esc`] + quotes for strings.
pub fn obj(fields: &[(&str, String)]) -> String {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{{}}}", body.join(","))
}

/// A quoted, escaped JSON string value from a Rust string.
pub fn qstr(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_keys_only() {
        let o = r#"{"nick":"bob","nested":{"nick":"decoy"},"n":42,"ok":true}"#;
        assert_eq!(get_str(o, "nick").as_deref(), Some("bob"));
        assert_eq!(get_num::<i64>(o, "n"), Some(42));
        assert_eq!(get_bool(o, "ok"), Some(true));
        assert_eq!(get_raw(o, "nested").as_deref(), Some(r#"{"nick":"decoy"}"#));
        assert_eq!(get_str(o, "missing"), None);
    }

    #[test]
    fn escapes_roundtrip() {
        let o = r#"{"reason":"a \"quoted\" line\nnext"}"#;
        assert_eq!(
            get_str(o, "reason").as_deref(),
            Some("a \"quoted\" line\nnext")
        );
        assert_eq!(esc("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn quoted_number_accepted() {
        assert_eq!(get_num::<u64>(r#"{"d":"3600"}"#, "d"), Some(3600));
    }
}
