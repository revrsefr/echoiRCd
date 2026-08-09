//! denychans — forbid joining channels whose name matches a `badchan` glob, with
//! an optional redirect to a safe channel and an `allowopers` bypass. A `goodchan`
//! glob whitelists names back out of a broad `badchan` pattern. Config:
//!
//! ```text
//! badchan  = #evil* reason="That channel is off-limits." redirect=#lobby allowopers=yes
//! goodchan = #evilgenius
//! ```
//!
//! Dispatched straight from `Server::join` (like the CBAN check), so it works
//! per-channel even when several are joined at once. All config-driven; nothing
//! lives on `Server`.
//!
//! Behaviour reference: InspIRCd's `m_denychans`. Original native Rust.

use crate::channels::glob_match;
use crate::numeric::{ERR_BADCHANNEL, ERR_LINKCHANNEL};
use crate::server::Server;
use crate::Uid;

/// One parsed `badchan` line.
struct BadChan {
    glob: String,
    reason: String,
    redirect: Option<String>,
    allowopers: bool,
}

/// Reuse the quoted-attribute tokenizer shape: split on whitespace but keep
/// `key="quoted value"` together.
fn tokenize(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_q, mut has) = (false, false);
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

fn parse(s: &Server) -> Vec<BadChan> {
    let mut out = Vec::new();
    for line in s.conf_all("badchan") {
        let toks = tokenize(line);
        let Some((glob, attrs)) = toks.split_first() else {
            continue;
        };
        if glob.is_empty() {
            continue;
        }
        let mut bc = BadChan {
            glob: glob.clone(),
            reason: "Channel is forbidden.".to_string(),
            redirect: None,
            allowopers: false,
        };
        for tok in attrs {
            let Some((k, v)) = tok.split_once('=') else {
                continue;
            };
            match k {
                "reason" => bc.reason = v.to_string(),
                "redirect" => {
                    if !v.is_empty() {
                        bc.redirect = Some(v.to_string())
                    }
                }
                "allowopers" => bc.allowopers = crate::config::yesish(v),
                _ => {}
            }
        }
        out.push(bc);
    }
    out
}

/// Whether `name` is whitelisted by any `goodchan` glob.
fn is_good(s: &Server, name: &str) -> bool {
    s.conf_all("goodchan").iter().any(|g| glob_match(g, name))
}

/// Called from `Server::join`. Returns `true` when the join to `name` should be
/// blocked (the caller returns without joining); emits the numeric and performs a
/// redirect join if configured. `is_oper` lets an `allowopers` badchan through.
pub fn intercept(s: &mut Server, uid: Uid, name: &str, is_oper: bool) -> bool {
    if s.conf_all("badchan").is_empty() {
        return false;
    }
    if is_good(s, name) {
        return false;
    }
    let bad = parse(s);
    let Some(bc) = bad.iter().find(|b| glob_match(&b.glob, name)) else {
        return false;
    };
    if is_oper && bc.allowopers {
        return false;
    }

    s.numeric(uid, ERR_BADCHANNEL, &format!("{name} :{}", bc.reason));
    if let Some(redir) = &bc.redirect {
        if !redir.eq_ignore_ascii_case(name) {
            let redir = redir.clone();
            s.numeric(
                uid,
                ERR_LINKCHANNEL,
                &format!("{name} {redir} :You have been redirected."),
            );
            s.join(uid, &redir, None);
        }
    }
    true
}
