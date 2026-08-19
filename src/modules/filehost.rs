//! `reverse.im/filehost` (draft) IRCv3 extension: advertises an external
//! file-hosting service and hands a logged-in user a short-lived, server-signed JWT
//! upload link so the web uploader trusts them without a second login.
//!
//! Surfaces:
//!   * ISUPPORT `reverse.im/FILEHOST=<website>` + the `reverse.im/filehost` cap.
//!   * `FILEHOST [info]` — login-gated; replies with `<website>/upload?token=<jwt>`
//!     and usage info.
//!   * a `reverse.im/filehost` message tag carrying JSON metadata (url/filename/
//!     type) attached to any message containing a `<website>/files/…` link, so
//!     clients render the file inline. Scoped to the message's recipients.
//!   * `filehost_requiressl`: refuse to relay a filehost link from a plaintext user.
//!
//! Config: `filehost_website` (enables it) `filehost_jwt_secret` `filehost_jwt_issuer`
//! (default FILEHOST) `filehost_token_expiry` (secs, default 3600) `filehost_requiressl`
//! (default yes) `filehost_auth_message`.

use crate::command::{CmdResult, Command};
use crate::module::{ModResult, Module};
use crate::modules::jwt;
use crate::server::{now, Server};
use crate::Uid;

/// The configured website, trailing slash trimmed; `None` when unconfigured.
fn website(s: &Server) -> Option<String> {
    s.conf("filehost_website")
        .map(|w| w.trim_end_matches('/').to_string())
        .filter(|w| !w.is_empty())
}

/// ISUPPORT token advertising the file host (called from the welcome burst).
pub fn isupport(s: &Server) -> Option<String> {
    website(s).map(|w| format!("reverse.im/FILEHOST={w}"))
}

/// File category from a filename extension.
fn file_type(filename: &str) -> &'static str {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e)
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "svg" => "image",
        "txt" | "md" | "html" | "htm" | "css" | "js" => "text",
        "pdf" | "doc" | "docx" => "document",
        "zip" | "tar" | "gz" | "rar" => "archive",
        "" => "unknown",
        _ => "binary",
    }
}

/// Escape a string for embedding in a JSON string literal (the tag carries JSON,
/// so a `"`/`\` in the url or filename would otherwise break it).
fn json_esc(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// IRCv3 message-tag value escape (JSON is full of spaces, which would split the line).
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

pub struct FileHost;

impl Module for FileHost {
    fn name(&self) -> &'static str {
        "filehost"
    }

    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        _target: &str,
        text: &str,
    ) -> ModResult {
        let Some(web) = website(srv) else {
            return ModResult::Passthru;
        };
        let files_prefix = format!("{web}/files/");

        // require_ssl: don't let a plaintext user spread filehost links
        if srv.conf_bool("filehost_requiressl", true)
            && text.contains(&web)
            && !srv.users.get(&uid).map(|u| u.secure).unwrap_or(false)
        {
            let nick = srv
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            srv.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :You cannot share FILEHOST links over a non-TLS connection.",
                    srv.name
                ),
            );
            return ModResult::Deny;
        }

        // detect a "<website>/files/<name>" link and attach file metadata as a tag,
        // so the recipients' clients can render it inline
        if let Some(pos) = text.find(&files_prefix) {
            let rest = &text[pos..];
            let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches([',', '.', ';', ':', '!', '?', ')', ']', '}']);
            let filename = &url[files_prefix.len().min(url.len())..];
            let meta = format!(
                "{{\"url\":\"{}\",\"filename\":\"{}\",\"type\":\"{}\"}}",
                json_esc(url),
                json_esc(filename),
                file_type(filename)
            );
            // fold the metadata onto this message's relayed tag block (message-tags
            // recipients get it; clients that don't know the tag ignore it)
            let tag = format!("reverse.im/filehost={}", escape_tag(&meta));
            if srv.line_ctags.is_empty() {
                srv.line_ctags = tag;
            } else {
                srv.line_ctags.push(';');
                srv.line_ctags.push_str(&tag);
            }
        }
        ModResult::Passthru
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(FileHostCmd)]
}

/// FILEHOST `[info]` — a logged-in user gets a signed upload link.
struct FileHostCmd;
impl Command for FileHostCmd {
    fn name(&self) -> &'static str {
        "FILEHOST"
    }
    fn min_params(&self) -> usize {
        0
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let Some(web) = website(s) else {
            note(s, uid, "FILEHOST is not configured on this server.");
            return CmdResult::Fail;
        };
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();

        if params
            .first()
            .map(|p| p.eq_ignore_ascii_case("info"))
            .unwrap_or(false)
        {
            note(s, uid, &format!("FILEHOST: service provided by {web}"));
            note(s, uid, "FILEHOST: allowed types: txt, md, pdf, png, jpg, jpeg, gif, html, htm, css, js, svg, zip");
            return CmdResult::Ok;
        }

        // must be logged into an account
        let account = match s.users.get(&uid).and_then(|u| u.account.clone()) {
            Some(a) if !a.is_empty() => a,
            _ => {
                let msg = s
                    .conf("filehost_auth_message")
                    .unwrap_or("Log in to your account to use file hosting.")
                    .to_string();
                note(
                    s,
                    uid,
                    &format!("You must be logged in to use file hosting. {msg}"),
                );
                return CmdResult::Fail;
            }
        };

        // Fail closed: signing upload tokens with a missing/placeholder secret
        // would let anyone forge a server-trusted upload authorization.
        let secret = match s.conf("filehost_jwt_secret") {
            Some(sec) if !sec.is_empty() && sec != "changeme" => sec.to_string(),
            _ => {
                note(
                    s,
                    uid,
                    "FILEHOST: file hosting is misconfigured (no upload secret set). \
                     Please tell an operator.",
                );
                return CmdResult::Fail;
            }
        };
        let issuer = s
            .conf("filehost_jwt_issuer")
            .unwrap_or("FILEHOST")
            .to_string();
        let expiry = s
            .conf_num("filehost_token_expiry", 3600u64)
            .clamp(60, 86400);
        let n = now();
        let claims = format!(
            r#"{{"iss":"{issuer}","sub":"{nick}","iat":{n},"exp":{}}}"#,
            n + expiry
        );
        let Some(token) = jwt::sign_hs256(&claims, &secret) else {
            note(s, uid, "FILEHOST: could not create an upload token.");
            return CmdResult::Fail;
        };
        note(
            s,
            uid,
            &format!("FILEHOST: upload files at {web}/upload?token={token}"),
        );
        note(
            s,
            uid,
            &format!("FILEHOST: share them via {web}/files/<filename>"),
        );
        note(
            s,
            uid,
            &format!(
                "FILEHOST: authenticated as {account}; link valid {} minutes",
                expiry / 60
            ),
        );
        CmdResult::Ok
    }
}

fn note(s: &Server, uid: Uid, msg: &str) {
    let nick = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    s.send(uid, format!(":{} NOTICE {nick} :*** {msg}", s.name));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_type_by_extension() {
        assert_eq!(file_type("cat.png"), "image");
        assert_eq!(file_type("notes.txt"), "text");
        assert_eq!(file_type("paper.pdf"), "document");
        assert_eq!(file_type("blob.bin"), "binary");
        assert_eq!(file_type("noext"), "unknown");
    }

    #[test]
    fn tag_escape() {
        assert_eq!(escape_tag(r#"{"a":"b c"}"#), "{\"a\":\"b\\sc\"}");
    }
}
