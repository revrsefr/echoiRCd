//! relaymsg — `RELAYMSG <channel> <nick> <text>` (IRCv3 `draft/relaymsg`): a member
//! whose client negotiated the capability sends a channel message under a spoofed
//! "relay" nick (e.g. `discord/alice`), for stateless bridges. The message is
//! tagged `@draft/relaymsg=<sender>` so clients can attribute it. The spoofed nick
//! must contain a configured separator and must not collide with a real nick.
//!
//! Config: `relaymsg_separators` (default `/`), `relaymsg_ident` (default `relay`),
//! `relaymsg_host` (default = server name). Local delivery only; cross-server ENCAP
//! relay is not propagated.

use crate::command::{CmdResult, Command};
use crate::numeric::{ERR_BADRELAYNICK, ERR_CANNOTSENDTOCHAN, ERR_NOPRIVILEGES, ERR_NOSUCHCHANNEL};
use crate::server::Server;
use crate::Uid;

/// Characters never allowed in a spoofed relay nick (core IRC syntax).
const FORBIDDEN: &str = "!+%@&#$:'\"?*,.";

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(RelayMsg)]
}

struct RelayMsg;
impl Command for RelayMsg {
    fn name(&self) -> &'static str {
        "RELAYMSG"
    }
    fn min_params(&self) -> usize {
        3
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let (chan, nick, text) = (&params[0], &params[1], &params[2]);
        let bad = |s: &mut Server, msg: &str| {
            s.numeric(uid, ERR_BADRELAYNICK, &format!("{nick} :{msg}"));
            CmdResult::Fail
        };

        if !s.users.get(&uid).map(|u| u.caps.relaymsg).unwrap_or(false) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":You must enable the draft/relaymsg capability to use RELAYMSG",
            );
            return CmdResult::Fail;
        }
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        if !s.is_member(uid, &key) {
            s.numeric(
                uid,
                ERR_CANNOTSENDTOCHAN,
                &format!("{chan} :You must be in the channel to use RELAYMSG"),
            );
            return CmdResult::Fail;
        }
        if s.find_nick(nick).is_some() || s.remote_nick.contains_key(&nick.to_ascii_lowercase()) {
            return bad(s, "RELAYMSG spoofed nick is already in use");
        }
        if nick.chars().any(|c| FORBIDDEN.contains(c)) {
            return bad(s, "Invalid characters in spoofed nick");
        }
        let seps = s
            .conf("relaymsg_separators")
            .filter(|v| !v.is_empty())
            .unwrap_or("/")
            .to_string();
        if !nick.chars().any(|c| seps.contains(c)) {
            return bad(
                s,
                &format!("Spoofed nick must include one of these separators: {seps}"),
            );
        }

        // build the fake source and relay it to every member (sender included, so
        // their own client sees the @draft/relaymsg echo)
        let ident = s.conf("relaymsg_ident").filter(|v| !v.is_empty()).unwrap_or("relay").to_string();
        let host = s
            .conf("relaymsg_host")
            .filter(|v| !v.is_empty())
            .unwrap_or(s.name.as_str())
            .to_string();
        let sender = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let body = format!(":{nick}!{ident}@{host} PRIVMSG {chan} :{text}");
        let ctags = format!("draft/relaymsg={sender}");
        let msgid = s.next_msgid();
        let members: Vec<Uid> = s
            .channels
            .get(&key)
            .map(|c| c.members.keys().copied().collect())
            .unwrap_or_default();
        for m in members {
            s.send_tagged(m, uid, &ctags, &msgid, &body);
        }
        CmdResult::Ok
    }
}
