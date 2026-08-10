//! jsonlog — the `draft/json-log` capability. When an oper negotiates
//! `CAP REQ draft/json-log`, every server notice they receive carries a structured
//! JSON object (timestamp, level, subsystem, msg, …) as an IRCv3 message tag; the
//! human-readable text stays in the NOTICE. Dispatched from `Server::snotice`; the
//! tag build lives here.

use crate::modules::rpc::json::{obj, qstr};
use crate::server::{iso_time, now, Server};

/// Strip mIRC/IRC formatting control codes so the `msg` field is clean plaintext:
/// bold/reset/mono/reverse/italic/strike/underline, colour (`\x03 fg[,bg]`) and hex
/// colour (`\x04 rrggbb[,rrggbb]`). The raw NOTICE keeps its formatting.
fn strip_formatting(input: &str) -> String {
    let b: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            '\u{02}' | '\u{0F}' | '\u{11}' | '\u{16}' | '\u{1D}' | '\u{1E}' | '\u{1F}' => {}
            '\u{03}' => i = skip_run(&b, i, 2, |c| c.is_ascii_digit()),
            '\u{04}' => i = skip_run(&b, i, 6, |c| c.is_ascii_hexdigit()),
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// From a colour/hex-colour introducer at `i`, skip up to `max` matching digits and
/// an optional `,` + up to `max` more. Returns the index of the last consumed char.
fn skip_run(b: &[char], mut i: usize, max: usize, ok: impl Fn(char) -> bool) -> usize {
    let mut n = 0;
    while i + 1 < b.len() && ok(b[i + 1]) && n < max {
        i += 1;
        n += 1;
    }
    if n > 0 && i + 2 < b.len() && b[i + 1] == ',' && ok(b[i + 2]) {
        i += 1; // the comma
        n = 0;
        while i + 1 < b.len() && ok(b[i + 1]) && n < max {
            i += 1;
            n += 1;
        }
    }
    i
}

/// IRCv3 message-tag value escape (space→`\s`, `;`→`\:`, `\`→`\\`, CR/LF). Required
/// because the JSON is full of spaces and would otherwise split the wire line apart.
fn escape_tag(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// The escaped `draft/json-log` tag *value* for a server notice `msg`. Place after
/// `draft/json-log=` in the tag block. echoIRCd snotices are untyped, so `subsystem`
/// / `event_id` are derived from the leading word and `snomask` is the generic `s`.
pub fn tag_value(s: &Server, msg: &str) -> String {
    let head = msg
        .split_whitespace()
        .next()
        .unwrap_or("general")
        .trim_end_matches(':');
    let subsystem = head.to_ascii_lowercase();
    let event_id = head.to_ascii_uppercase();
    let json = obj(&[
        ("timestamp", qstr(&iso_time(now()))),
        ("level", qstr("info")),
        ("subsystem", qstr(&subsystem)),
        ("event_id", qstr(&event_id)),
        ("log_source", qstr(&s.name)),
        ("msg", qstr(&strip_formatting(msg))),
        ("snomask", qstr("s")),
    ]);
    escape_tag(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_codes() {
        assert_eq!(strip_formatting("\u{02}bold\u{0F} x"), "bold x");
        assert_eq!(strip_formatting("\u{03}04red\u{03} y"), "red y");
        assert_eq!(strip_formatting("\u{03}04,08two z"), "two z");
    }

    #[test]
    fn escapes_tag_value() {
        assert_eq!(escape_tag("a b;c\\d"), "a\\sb\\:c\\\\d");
    }
}
