//! IRC line parsing (RFC 1459 + IRCv3 message tags). One line in → an optional
//! [`Message`] out. Client-only tags (the `+`-prefixed ones) are captured so
//! TAGMSG / PRIVMSG can relay them onward; server tags from clients are dropped.

#[derive(Debug, PartialEq)]
pub struct Message {
    /// The `:source` prefix, if any (clients rarely send one).
    pub source: Option<String>,
    /// Command, upper-cased (`PRIVMSG`, `JOIN`, …) or a 3-digit numeric.
    pub command: String,
    /// Parameters, with the trailing `:param` unwrapped into the last element.
    pub params: Vec<String>,
    /// Client-only IRCv3 tags (`+key=val;…`) re-serialised for relay; `""` if none.
    pub ctags: String,
    /// The IRCv3 `label` tag value, if the client tagged this command (for
    /// labeled-response); `None` otherwise.
    pub label: Option<String>,
    /// The `batch` tag value (which client batch this line belongs to), for
    /// inbound draft/multiline.
    pub batch: Option<String>,
    /// Whether the line carried the `draft/multiline-concat` tag (join to the
    /// previous multiline part with no newline).
    pub concat: bool,
}

impl Message {
    /// Re-serialise to a wire line, for forwarding across links. The last param is
    /// emitted as a trailing `:param` when it's empty, has a space, or starts `:`.
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        if let Some(src) = &self.source {
            out.push(':');
            out.push_str(src);
            out.push(' ');
        }
        out.push_str(&self.command);
        let n = self.params.len();
        for (i, p) in self.params.iter().enumerate() {
            out.push(' ');
            if i + 1 == n && (p.is_empty() || p.contains(' ') || p.starts_with(':')) {
                out.push(':');
            }
            out.push_str(p);
        }
        out
    }
}

/// Parse one wire line. Returns `None` for an empty/garbage line.
pub fn parse(line: &str) -> Option<Message> {
    let mut rest = line.trim_start_matches(' ');

    // IRCv3 message tags — keep the client-only (`+`) tags for relay, drop the rest.
    let mut ctags = String::new();
    let mut label = None;
    let mut batch = None;
    let mut concat = false;
    if let Some(after_at) = rest.strip_prefix('@') {
        let (tags, r) = after_at.split_once(' ')?;
        ctags = tags
            .split(';')
            .filter(|t| t.starts_with('+'))
            .collect::<Vec<_>>()
            .join(";");
        label = tags
            .split(';')
            .find_map(|t| t.strip_prefix("label="))
            .map(|v| v.to_string());
        batch = tags
            .split(';')
            .find_map(|t| t.strip_prefix("batch="))
            .map(|v| v.to_string());
        concat = tags.split(';').any(|t| t == "draft/multiline-concat");
        rest = r.trim_start_matches(' ');
    }

    let mut source = None;
    if let Some(after_colon) = rest.strip_prefix(':') {
        let (src, r) = after_colon.split_once(' ')?;
        source = Some(src.to_string());
        rest = r.trim_start_matches(' ');
    }

    let (cmd, mut rest) = match rest.split_once(' ') {
        Some((c, r)) => (c, r.trim_start_matches(' ')),
        None => (rest, ""),
    };
    if cmd.is_empty() {
        return None;
    }

    let mut params = Vec::new();
    while !rest.is_empty() {
        if let Some(trailing) = rest.strip_prefix(':') {
            params.push(trailing.to_string());
            break;
        }
        match rest.split_once(' ') {
            Some((p, r)) => {
                params.push(p.to_string());
                rest = r.trim_start_matches(' ');
            }
            None => {
                params.push(rest.to_string());
                break;
            }
        }
    }

    Some(Message {
        source,
        command: cmd.to_ascii_uppercase(),
        params,
        ctags,
        label,
        batch,
        concat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Fuzz: no arbitrary line may panic the parser.
        #[test]
        fn parse_never_panics(line in ".*") {
            let _ = parse(&line);
        }

        // Round-trip: a parsed line, re-serialised and re-parsed, yields the same
        // source/command/params (to_wire drops tags by design, so we don't compare those).
        #[test]
        fn parse_roundtrips_core_fields(line in ".*") {
            if let Some(m) = parse(&line) {
                let again = parse(&m.to_wire());
                prop_assert_eq!(again.as_ref().map(|x| x.source.clone()), Some(m.source.clone()));
                prop_assert_eq!(again.as_ref().map(|x| x.command.clone()), Some(m.command.clone()));
                prop_assert_eq!(again.as_ref().map(|x| x.params.clone()), Some(m.params.clone()));
            }
        }
    }

    #[test]
    fn simple_command() {
        let m = parse("NICK reverse").unwrap();
        assert_eq!(m.command, "NICK");
        assert_eq!(m.params, vec!["reverse"]);
        assert!(m.source.is_none());
    }

    #[test]
    fn trailing_keeps_spaces() {
        let m = parse("PRIVMSG #argentina :hola que tal").unwrap();
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["#argentina", "hola que tal"]);
    }

    #[test]
    fn source_and_lowercase_command_upcased() {
        let m = parse(":nick!u@h privmsg x :y").unwrap();
        assert_eq!(m.source.as_deref(), Some("nick!u@h"));
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["x", "y"]);
    }

    #[test]
    fn tags_are_skipped() {
        let m = parse("@id=1;time=x PING :token").unwrap();
        assert_eq!(m.command, "PING");
        assert_eq!(m.params, vec!["token"]);
        assert_eq!(m.ctags, ""); // no client-only tags here
    }

    #[test]
    fn client_only_tags_kept_for_relay() {
        let m = parse("@time=x;+typing=done;account=z TAGMSG #devs").unwrap();
        assert_eq!(m.command, "TAGMSG");
        assert_eq!(m.params, vec!["#devs"]);
        assert_eq!(m.ctags, "+typing=done"); // server tags dropped, `+` kept
    }

    #[test]
    fn empty_and_junk() {
        assert!(parse("").is_none());
        assert!(parse("   ").is_none());
        // a lone colon prefix with nothing after is not a message
        assert!(parse(":only").is_none());
    }
}
