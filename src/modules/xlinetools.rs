//! `XSEARCH` / `XCOUNT` / `XREMOVE` / `XCOPY` — oper tooling over the x-line store
//! (K/G/Z/E/SHUN/Q/CBAN/R/JUPE/ALINE/GALINE): search by kind + mask glob, count,
//! remove, or copy a line to another kind (e.g. promote a K-line to a G-line).

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::{now, Server};
use crate::xline::XKind;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(XSearch),
        Box::new(XCount),
        Box::new(XRemove),
        Box::new(XCopy),
    ]
}

fn require_oper(s: &mut Server, uid: Uid) -> bool {
    if s.is_oper(uid) {
        return true;
    }
    s.numeric(
        uid,
        ERR_NOPRIVILEGES,
        ":Permission Denied- You're not an IRC operator",
    );
    false
}

fn notice(s: &mut Server, uid: Uid, msg: &str) {
    let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
    let name = s.name.clone();
    s.send(uid, format!(":{name} NOTICE {nick} :{msg}"));
}

/// Resolve the optional leading kind filter: returns (kind, mask). `XSEARCH K *host*`
/// filters by kind; `XSEARCH *host*` searches every kind.
fn parse_filter(params: &[String]) -> (Option<XKind>, String) {
    if params.len() >= 2 {
        if let Some(k) = XKind::from_tag(&params[0].to_ascii_uppercase()) {
            return (Some(k), params[1].clone());
        }
    }
    (None, params.first().cloned().unwrap_or_else(|| "*".to_string()))
}

struct XSearch;
impl Command for XSearch {
    fn name(&self) -> &'static str {
        "XSEARCH"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let (kind, mask) = parse_filter(params);
        let n = now();
        let mut lines: Vec<String> = Vec::new();
        for x in &s.xlines {
            if kind.map(|k| k == x.kind).unwrap_or(true) && glob_match(&mask, &x.mask) {
                let left = if x.expires == 0 {
                    "permanent".to_string()
                } else {
                    format!("{}s left", x.expires.saturating_sub(n))
                };
                lines.push(format!(
                    "{}-line {} ({}) by {}: {}",
                    x.kind.tag(),
                    x.mask,
                    left,
                    x.setter,
                    x.reason
                ));
            }
        }
        if lines.is_empty() {
            notice(s, uid, "XSEARCH: no matching x-lines");
        } else {
            for l in &lines {
                notice(s, uid, l);
            }
            let m = format!("End of XSEARCH ({} match(es))", lines.len());
            notice(s, uid, &m);
        }
        CmdResult::Ok
    }
}

struct XCount;
impl Command for XCount {
    fn name(&self) -> &'static str {
        "XCOUNT"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let (kind, mask) = if params.is_empty() {
            (None, "*".to_string())
        } else {
            parse_filter(params)
        };
        let count = s
            .xlines
            .iter()
            .filter(|x| kind.map(|k| k == x.kind).unwrap_or(true) && glob_match(&mask, &x.mask))
            .count();
        let m = format!("XCOUNT: {count} matching x-line(s)");
        notice(s, uid, &m);
        CmdResult::Ok
    }
}

struct XRemove;
impl Command for XRemove {
    fn name(&self) -> &'static str {
        "XREMOVE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let Some(kind) = XKind::from_tag(&params[0].to_ascii_uppercase()) else {
            notice(s, uid, "XREMOVE: unknown x-line type");
            return CmdResult::Fail;
        };
        let mask = params[1].clone();
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        if s.remove_xline(kind, &mask, &nick) {
            s.propagate_delline(kind.tag(), &mask);
        } else {
            let m = format!("XREMOVE: no {}-line on {mask}", kind.tag());
            notice(s, uid, &m);
        }
        CmdResult::Ok
    }
}

struct XCopy;
impl Command for XCopy {
    fn name(&self) -> &'static str {
        "XCOPY"
    }
    fn min_params(&self) -> usize {
        3
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !require_oper(s, uid) {
            return CmdResult::Fail;
        }
        let (Some(from), Some(to)) = (
            XKind::from_tag(&params[0].to_ascii_uppercase()),
            XKind::from_tag(&params[1].to_ascii_uppercase()),
        ) else {
            notice(s, uid, "XCOPY: unknown x-line type");
            return CmdResult::Fail;
        };
        let mask = params[2].clone();
        let n = now();
        let src = s
            .xlines
            .iter()
            .find(|x| x.kind == from && x.mask == mask)
            .map(|x| (x.expires, x.reason.clone()));
        let Some((expires, reason)) = src else {
            let m = format!("XCOPY: no {}-line on {mask}", from.tag());
            notice(s, uid, &m);
            return CmdResult::Fail;
        };
        let dur = if expires == 0 {
            0
        } else {
            expires.saturating_sub(n)
        };
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        s.add_xline(to, &mask, dur, &nick, &reason);
        s.propagate_addline(to.tag(), &mask, &nick, dur, &reason);
        CmdResult::Ok
    }
}
