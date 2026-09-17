//! dccallow: block DCC SEND matching configured filename globs (and, with
//! `dccallow_blockchat`, DCC CHAT) unless the recipient has allowed the sender
//! with `/DCCALLOW +<nick>`. Config (all optional, all runtime-read):
//!
//! ```text
//! dccallow_blockfile = *.exe        # repeatable: filename globs to block on DCC SEND
//! dccallow_blockfile = *.scr
//! dccallow_blockchat = yes          # also block DCC CHAT (default: no)
//! dccallow_maxentries = 20          # per-user allow-list cap (default 20)
//! ```
//!
//! A user's allow-list lives on their `User.ext`, so it vanishes when they quit.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

/// Nicks (lowercased) a user permits to DCC them. Stored on the recipient's ext.
#[derive(Default)]
struct Allowed(Vec<String>);

/// A parsed DCC CTCP request.
enum Dcc {
    Send(String), // SEND <filename> ...
    Chat,         // CHAT chat ...
    Other,        // RESUME/ACCEPT/etc. — not gated
}

/// Parse a `\x01DCC …\x01` CTCP body; `None` if the text isn't a DCC request.
/// Handles a quoted filename that contains spaces (`"my file.exe"`).
fn parse_dcc(text: &str) -> Option<Dcc> {
    let inner = text.strip_prefix('\u{1}')?;
    let inner = inner.strip_suffix('\u{1}').unwrap_or(inner);
    let mut it = inner.split_whitespace();
    if !it.next()?.eq_ignore_ascii_case("DCC") {
        return None;
    }
    let sub = it.next()?;
    if sub.eq_ignore_ascii_case("SEND") {
        let first = it.next()?;
        let fname = if let Some(stripped) = first.strip_prefix('"') {
            match stripped.strip_suffix('"') {
                Some(one) => one.to_string(), // "name" — single token
                None => {
                    let mut acc = stripped.to_string();
                    for tok in it.by_ref() {
                        acc.push(' ');
                        if let Some(end) = tok.strip_suffix('"') {
                            acc.push_str(end);
                            break;
                        }
                        acc.push_str(tok);
                    }
                    acc
                }
            }
        } else {
            first.to_string()
        };
        Some(Dcc::Send(fname))
    } else if sub.eq_ignore_ascii_case("CHAT") {
        Some(Dcc::Chat)
    } else {
        Some(Dcc::Other)
    }
}

pub struct DccAllow;

impl Module for DccAllow {
    fn name(&self) -> &'static str {
        "dccallow"
    }
    fn description(&self) -> &'static str {
        "Blocks DCC SEND/CHAT by filename glob unless allowed via /DCCALLOW"
    }

    fn on_pre_message(&mut self, s: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
        let Some(dcc) = parse_dcc(text) else {
            return ModResult::Passthru; // not a DCC request
        };
        let Some(tuid) = s.find_nick(target) else {
            return ModResult::Passthru; // DCC only makes sense user-to-user
        };
        if tuid == uid {
            return ModResult::Passthru;
        }
        let sender = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let low = sender.to_ascii_lowercase();
        // recipient already whitelisted this sender?
        let allowed = s
            .users
            .get(&tuid)
            .and_then(|u| u.ext.get::<Allowed>())
            .map(|a| a.0.contains(&low))
            .unwrap_or(false);
        if allowed {
            return ModResult::Passthru;
        }
        let (block, what) = match &dcc {
            Dcc::Send(fname) => {
                let hit = s
                    .conf_all("dccallow_blockfile")
                    .iter()
                    .any(|p| glob_match(p, fname));
                (hit, format!("the file \"{fname}\""))
            }
            Dcc::Chat => (
                s.conf_bool("dccallow_blockchat", false),
                "a DCC CHAT".to_string(),
            ),
            Dcc::Other => (false, String::new()),
        };
        if !block {
            return ModResult::Passthru;
        }
        let tnick = s
            .users
            .get(&tuid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let m1 = s.trf(
            "Your DCC to {0} was blocked; they must /DCCALLOW +{1} first.",
            &[tnick.as_str(), sender.as_str()],
        );
        s.send(uid, format!(":{} NOTICE {sender} :*** {m1}", s.name));
        let m2 = s.trf(
            "{0} tried to send you {1} — blocked. /DCCALLOW +{2} to allow it, then ask them to resend.",
            &[sender.as_str(), what.as_str(), sender.as_str()],
        );
        s.send(tuid, format!(":{} NOTICE {tnick} :*** {m2}", s.name));
        ModResult::Deny
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(DccAllowCmd)]
}

/// DCCALLOW `+nick` / `-nick` / `LIST` / `HELP` — manage the nicks you let DCC you.
struct DccAllowCmd;
impl Command for DccAllowCmd {
    fn name(&self) -> &'static str {
        "DCCALLOW"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let note =
            |s: &Server, msg: String| s.send(uid, format!(":{} NOTICE {nick} :{msg}", s.name));
        let arg = &params[0];

        if arg.eq_ignore_ascii_case("LIST") {
            let list = s
                .users
                .get(&uid)
                .and_then(|u| u.ext.get::<Allowed>())
                .map(|a| a.0.join(", "))
                .unwrap_or_default();
            note(
                s,
                if list.is_empty() {
                    "*** Your DCCALLOW list is empty.".to_string()
                } else {
                    format!("*** DCCALLOW list: {list}")
                },
            );
            return CmdResult::Ok;
        }

        let (add, name) = match arg.strip_prefix('+') {
            Some(n) => (true, n),
            None => match arg.strip_prefix('-') {
                Some(n) => (false, n),
                None => {
                    note(
                        s,
                        "*** Usage: DCCALLOW +<nick> | -<nick> | LIST".to_string(),
                    );
                    return CmdResult::Ok;
                }
            },
        };
        if name.is_empty() {
            note(s, "*** DCCALLOW: no nick given.".to_string());
            return CmdResult::Fail;
        }
        let low = name.to_ascii_lowercase();
        let max = s.conf_num("dccallow_maxentries", 20usize);
        // mutate under the borrow, then drop it before sending the notice
        let msg = {
            let Some(u) = s.users.get_mut(&uid) else {
                return CmdResult::Fail;
            };
            let a = u.ext.get_or_insert_with(Allowed::default);
            if add {
                if a.0.contains(&low) {
                    format!("*** {name} is already on your DCCALLOW list.")
                } else if a.0.len() >= max {
                    format!("*** Your DCCALLOW list is full ({max}).")
                } else {
                    a.0.push(low);
                    format!("*** Added {name} to your DCCALLOW list.")
                }
            } else if let Some(pos) = a.0.iter().position(|n| n == &low) {
                a.0.remove(pos);
                format!("*** Removed {name} from your DCCALLOW list.")
            } else {
                format!("*** {name} was not on your DCCALLOW list.")
            }
        };
        note(s, msg);
        CmdResult::Ok
    }
}
