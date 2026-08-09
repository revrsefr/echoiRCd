//! restrictcommands — hold back chosen commands from brand-new / unregistered
//! users (UnrealIRCd's `set::restrict-commands`), with exemptions. reverse's own
//! module. Each restriction is one config line:
//!
//! ```text
//! restrictcommand = LIST connectdelay=60 exemptidentified=yes exemptwebirc=yes \
//!                        exempttls=no exemptscore=24 reason="Please wait a bit."
//! ```
//!
//! A user may run the command if they are an oper, if ANY exemption matches, or
//! once they have been connected at least `connectdelay` seconds. Everything is
//! read from the config via `Server::conf*` — nothing lives on `Server`.

use crate::module::{ModResult, Module};
use crate::server::{now, Server};
use crate::Uid;

/// One parsed `restrictcommand` line.
struct Restriction {
    command: String, // uppercased
    connectdelay: u64,
    exempt_identified: bool,
    exempt_webirc: bool,
    exempt_tls: bool,
    exempt_score: Option<u32>,
    reason: String,
}

/// Split a config line into whitespace tokens, but keep `"quoted values"`
/// (spaces and all) as a single token — so `reason="a b c"` survives intact.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut has = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                in_q = !in_q;
                has = true;
            }
            c if c.is_whitespace() && !in_q => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

/// Parse all `restrictcommand` config lines into restrictions.
fn parse(s: &Server) -> Vec<Restriction> {
    let mut out = Vec::new();
    for line in s.conf_all("restrictcommand") {
        let toks = tokenize(line);
        let Some((name, attrs)) = toks.split_first() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let mut r = Restriction {
            command: name.to_ascii_uppercase(),
            connectdelay: 60,
            exempt_identified: true,
            exempt_webirc: false,
            exempt_tls: false,
            exempt_score: None,
            reason: "You cannot use this command yet. Please wait or log in.".to_string(),
        };
        for tok in attrs {
            let Some((k, v)) = tok.split_once('=') else {
                continue;
            };
            match k {
                "connectdelay" => r.connectdelay = crate::xline::parse_duration(v).unwrap_or(60),
                "exemptidentified" => r.exempt_identified = crate::config::yesish(v),
                "exemptwebirc" => r.exempt_webirc = crate::config::yesish(v),
                "exempttls" => r.exempt_tls = crate::config::yesish(v),
                "exemptscore" => r.exempt_score = v.parse().ok(),
                "reason" => r.reason = v.to_string(),
                _ => {}
            }
        }
        out.push(r);
    }
    out
}

pub struct RestrictCommands;

impl Module for RestrictCommands {
    fn name(&self) -> &'static str {
        "restrictcommands"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // fast path: nothing configured
        if srv.conf_all("restrictcommand").is_empty() {
            return ModResult::Passthru;
        }
        let restrictions = parse(srv);
        let Some(r) = restrictions
            .iter()
            .find(|r| r.command.eq_ignore_ascii_case(cmd))
        else {
            return ModResult::Passthru;
        };

        // opers are never restricted
        if srv.is_oper(uid) {
            return ModResult::Passthru;
        }
        let (secure, webirc, signon) = {
            let Some(u) = srv.users.get(&uid) else {
                return ModResult::Passthru;
            };
            (u.secure, u.flags.via_webirc, u.signon)
        };

        // exemptions: any match lets the command through
        if r.exempt_identified && srv.is_logged_in(uid) {
            return ModResult::Passthru;
        }
        if r.exempt_webirc && webirc {
            return ModResult::Passthru;
        }
        if r.exempt_tls && secure {
            return ModResult::Passthru;
        }
        if let Some(min) = r.exempt_score {
            if crate::modules::reputation::score_of(srv, uid) >= min {
                return ModResult::Passthru;
            }
        }
        // connect-delay: allowed once connected long enough
        if r.connectdelay > 0 && now().saturating_sub(signon) >= r.connectdelay {
            return ModResult::Passthru;
        }

        let (nick, reason) = (
            srv.users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default(),
            r.reason.clone(),
        );
        srv.send(uid, format!(":{} NOTICE {nick} :*** {reason}", srv.name));
        ModResult::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_keeps_quoted_reason() {
        let t = tokenize(r#"LIST connectdelay=60 reason="please wait a bit""#);
        assert_eq!(
            t,
            vec!["LIST", "connectdelay=60", "reason=please wait a bit"]
        );
    }

    #[test]
    fn tokenize_plain() {
        assert_eq!(tokenize("A  b   c"), vec!["A", "b", "c"]);
    }
}
