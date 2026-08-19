//! denychans: forbid joining channels whose name matches a `badchan` glob, with an
//! optional redirect to a safe channel and an `allowopers` bypass. A `goodchan`
//! glob whitelists names back out of a broad `badchan` pattern. Config:
//!
//! ```text
//! badchan  = #evil* reason="That channel is off-limits." redirect=#lobby allowopers=yes
//! goodchan = #evilgenius
//! ```
//!
//! Dispatched from `Server::join`, so it applies per-channel even when several are
//! joined at once.

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

/// Re-entrancy depth for redirect joins. `intercept` redirects by re-entering
/// `Server::join`, which runs `intercept` again — so a redirect chain (`#a→#b→#a`)
/// or a redirect into a broad `badchan` glob would recurse until the stack blows.
/// A real redirect is a single hop to a safe channel; cap the chain well short of
/// anything that could overflow.
#[derive(Default)]
struct RedirDepth(u32);
const MAX_REDIR: u32 = 8;

/// Split on whitespace but keep `key="quoted value"` together.
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
/// blocked; emits the numeric and performs a redirect join if configured.
/// `is_oper` lets an `allowopers` badchan through.
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
        // Bounded redirect: re-entering join runs intercept again, so stop chaining
        // once we've hopped MAX_REDIR times (a loop or badchan→badchan redirect).
        let depth = s.ext.get::<RedirDepth>().map(|d| d.0).unwrap_or(0);
        if !redir.eq_ignore_ascii_case(name) && depth < MAX_REDIR {
            let redir = redir.clone();
            s.ext.get_or_insert_with(RedirDepth::default).0 = depth + 1;
            s.numeric(
                uid,
                ERR_LINKCHANNEL,
                &format!("{name} {redir} :You have been redirected."),
            );
            s.join(uid, &redir, None);
            if let Some(d) = s.ext.get_mut::<RedirDepth>() {
                d.0 = d.0.saturating_sub(1);
            }
        }
    }
    true
}
