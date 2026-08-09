//! irccloudtags — support for IRCCloud's client-only message tags
//! (`+draft/unreact`, `+draft/edit`, `+draft/edit-text`, `+draft/attachments`,
//! `+draft/attachment-fallback`). echoIRCd already relays *all* `+` client tags to
//! `message-tags` clients, so these flow for free; what this module adds is the
//! spec validation InspIRCd's `m_ircv3_irccloudtags` does — each of these tags MUST
//! carry a value, and an empty one is rejected with `FAIL … MESSAGE_TAG_TOO_SHORT`.
//!
//! Behaviour reference: InspIRCd's `m_ircv3_irccloudtags`. Original native Rust.

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

/// The IRCCloud client tags that require a value.
const TAGS: &[&str] = &[
    "+draft/unreact",
    "+draft/edit",
    "+draft/edit-text",
    "+draft/attachments",
    "+draft/attachment-fallback",
];

pub struct IrcCloudTags;

impl Module for IrcCloudTags {
    fn name(&self) -> &'static str {
        "irccloudtags"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // only messages carry client tags
        if !(cmd.eq_ignore_ascii_case("PRIVMSG")
            || cmd.eq_ignore_ascii_case("NOTICE")
            || cmd.eq_ignore_ascii_case("TAGMSG"))
        {
            return ModResult::Passthru;
        }
        // the line's client-only tags are stashed on the server before dispatch
        for raw in srv.line_ctags.split(';').filter(|t| !t.is_empty()) {
            let (name, val) = raw.split_once('=').unwrap_or((raw, ""));
            if TAGS.contains(&name) && val.is_empty() {
                srv.fail(
                    uid,
                    name,
                    "MESSAGE_TAG_TOO_SHORT",
                    "That message tag must contain a value.",
                );
                return ModResult::Deny;
            }
        }
        ModResult::Passthru
    }
}
