//! `EXTJWT` command: issues a short-lived, server-signed HS256 JWT a client can
//! present to an external service to prove its IRC identity, modes and channel
//! membership. Uses the [`crate::modules::jwt`] signer.
//!
//! `EXTJWT *|<channel> [<service>]` → one or more
//! `:<server> EXTJWT <target> <service> [*] <chunk>` lines (a `*` param before the
//! chunk means more chunks follow). Claims: `exp, iss, sub`(nick)`, account,
//! umodes[]`, and for a channel target `channel, cmodes[]`.
//!
//! Config: `extjwt_secret` (+ `extjwt_duration`, default 30s); optional named
//! services via `extjwt_service = <name> <secret> [duration]`. Off with no secret.

use crate::command::{CmdResult, Command};
use crate::modules::jwt;
use crate::numeric::ERR_NOSUCHCHANNEL;
use crate::server::{now, Server};
use crate::Uid;

/// Longest token chunk per EXTJWT line (keeps the whole line well under 512).
const CHUNK: usize = 200; // default token chunk size if `extjwt_chunk` unset

/// Resolve `(secret, duration)` for a service name (`*` = the default service).
fn service(s: &Server, name: &str) -> Option<(String, u64)> {
    if name == "*" {
        let secret = s.conf("extjwt_secret").filter(|v| !v.is_empty())?;
        return Some((secret.to_string(), s.conf_num("extjwt_duration", 30u64)));
    }
    for line in s.conf_all("extjwt_service") {
        let mut it = line.split_whitespace();
        if it.next().is_some_and(|n| n.eq_ignore_ascii_case(name)) {
            let secret = it.next()?.to_string();
            let dur = it.next().and_then(|d| d.parse().ok()).unwrap_or(30);
            return Some((secret, dur));
        }
    }
    None
}

/// JSON array literal of single-char strings, e.g. `["i","o"]`.
fn json_arr(chars: impl IntoIterator<Item = char>) -> String {
    let items: Vec<String> = chars.into_iter().map(|c| format!("\"{c}\"")).collect();
    format!("[{}]", items.join(","))
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ExtJwt)]
}

struct ExtJwt;
impl Command for ExtJwt {
    fn name(&self) -> &'static str {
        "EXTJWT"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = params[0].clone();
        let svc_name = params.get(1).cloned().unwrap_or_else(|| "*".to_string());
        let Some((secret, duration)) = service(s, &svc_name) else {
            s.fail(
                uid,
                "EXTJWT",
                "NO_SUCH_SERVICE",
                &format!("No such JWT service: {svc_name}"),
            );
            return CmdResult::Fail;
        };
        let Some(u) = s.users.get(&uid) else {
            return CmdResult::Fail;
        };
        let (nick, account) = (u.nick.clone(), u.account.clone().unwrap_or_default());
        let umodes = json_arr(u.flags.umodes().chars().filter(|c| c.is_ascii_alphabetic()));

        // channel target: verify membership and collect the user's status modes
        let mut chan_claims = String::new();
        if target != "*" {
            let key = target.to_ascii_lowercase();
            let Some(ch) = s.channels.get(&key) else {
                s.numeric(
                    uid,
                    ERR_NOSUCHCHANNEL,
                    &format!("{target} :No such channel"),
                );
                return CmdResult::Fail;
            };
            let member = ch.members.get(&uid);
            let cmodes = member
                .map(|m| {
                    let mut v = Vec::new();
                    if m.owner {
                        v.push('q');
                    }
                    if m.admin {
                        v.push('a');
                    }
                    if m.op {
                        v.push('o');
                    }
                    if m.halfop {
                        v.push('h');
                    }
                    if m.voice {
                        v.push('v');
                    }
                    v
                })
                .unwrap_or_default();
            chan_claims = format!(",\"channel\":\"{target}\",\"cmodes\":{}", json_arr(cmodes));
        }

        let claims = format!(
            "{{\"exp\":{},\"iss\":\"{}\",\"sub\":\"{}\",\"account\":\"{}\",\"umodes\":{}{}}}",
            now() + duration,
            s.name,
            nick,
            account,
            umodes,
            chan_claims
        );
        let Some(token) = jwt::sign_hs256(&claims, &secret) else {
            s.fail(
                uid,
                "EXTJWT",
                "UNSPECIFIED_ERROR",
                "Failed to create token.",
            );
            return CmdResult::Fail;
        };

        // send the token, chunked, with a `*` continuation marker on all but the last
        let chunk_sz = s.conf_num("extjwt_chunk", CHUNK).max(1);
        let bytes = token.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let end = (i + chunk_sz).min(bytes.len());
            let chunk = &token[i..end];
            let more = end < bytes.len();
            let line = if more {
                format!(":{} EXTJWT {target} {svc_name} * {chunk}", s.name)
            } else {
                format!(":{} EXTJWT {target} {svc_name} {chunk}", s.name)
            };
            s.send(uid, line);
            i = end;
        }
        CmdResult::Ok
    }
}
