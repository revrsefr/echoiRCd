//! Oper-configured spam/word filters: a glob is matched against PRIVMSG/NOTICE text
//! and, on a hit, an action is taken. The rule set lives in `Server.ext`, the
//! `FILTER` command manages it, and the `on_pre_message` hook enforces it.

use crate::command::{CmdResult, Command};
use crate::module::{ModResult, Module};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::xline::{parse_duration, XKind};
use crate::Uid;

/// One filter rule.
pub struct SpamFilter {
    pub pattern: String, // matched against message text via `engine`
    pub engine: String,  // pattern engine: "glob" (default) or "regex"
    pub action: String,  // block | silent | kill | kline | gline | zline
    pub duration: u64,   // ban length for the *line actions (seconds; 0 = permanent)
    pub reason: String,
    matcher: Box<dyn crate::modules::pattern::Matcher>, // compiled `pattern` for `engine`
}

impl SpamFilter {
    /// Build a rule, compiling `pattern` with `engine` (`glob` or `regex`). Errors
    /// (as a message string) if the engine is unknown or a regex is invalid, so a
    /// bad rule is refused when set rather than silently never matching.
    pub fn new(
        pattern: String,
        engine: String,
        action: String,
        duration: u64,
        reason: String,
    ) -> Result<SpamFilter, String> {
        let matcher = crate::modules::pattern::compile(&engine, &pattern)?;
        Ok(SpamFilter { pattern, engine, action, duration, reason, matcher })
    }
}

/// The rule set, stored in `Server.ext`.
#[derive(Default)]
pub struct Filters(pub Vec<SpamFilter>);

impl Filters {
    /// The (action, reason, duration) of the first rule whose pattern matches `text`.
    fn hit(&self, text: &str) -> Option<(String, String, u64)> {
        self.0
            .iter()
            .find(|f| f.matcher.is_match(text))
            .map(|f| (f.action.clone(), f.reason.clone(), f.duration))
    }
}

/// The enforcement hook.
pub struct Filter;
impl Module for Filter {
    fn name(&self) -> &'static str {
        "filter"
    }
    fn on_pre_message(&mut self, s: &mut Server, uid: Uid, _target: &str, text: &str) -> ModResult {
        let Some((action, reason, duration)) = s.ext.get::<Filters>().and_then(|f| f.hit(text))
        else {
            return ModResult::Passthru;
        };
        let (mask, ip) = match s.users.get(&uid) {
            Some(u) => (u.prefix(), u.addr.ip().to_string()),
            None => return ModResult::Deny,
        };
        s.snotice_c('f', &format!(
            "FILTER: {mask} matched a filter (action={action}): {reason}"
        ));
        match action.as_str() {
            "block" => s.notice_star(uid, &format!("Your message was blocked: {reason}")),
            "silent" => {}
            "kill" => {
                let m = s.trf("Closing link: ({0})", &[reason.as_str()]);
                s.send(uid, format!("ERROR :{m}"));
                s.remove_user(uid, &reason);
            }
            "kline" => {
                s.add_xline(
                    XKind::Kline,
                    &format!("*@{ip}"),
                    duration,
                    "filter",
                    &reason,
                );
                s.remove_user(uid, &reason);
            }
            "gline" => {
                s.add_xline(
                    XKind::Gline,
                    &format!("*@{ip}"),
                    duration,
                    "filter",
                    &reason,
                );
                s.remove_user(uid, &reason);
            }
            "zline" => {
                s.add_xline(XKind::Zline, &ip, duration, "filter", &reason);
                s.remove_user(uid, &reason);
            }
            _ => {}
        }
        ModResult::Deny // the message never reaches the channel/user
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(FilterCmd)]
}

/// FILTER — manage spam filters (oper). No args = list; `<pattern>` = remove;
/// `<pattern> <action> [duration] :<reason>` = add/replace.
struct FilterCmd;
impl Command for FilterCmd {
    fn name(&self) -> &'static str {
        "FILTER"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        match params.first() {
            None => {
                let list: Vec<String> = s
                    .ext
                    .get::<Filters>()
                    .map(|f| {
                        f.0.iter()
                            .map(|r| {
                                format!("{} [{}] {} {} :{}", r.pattern, r.engine, r.action, r.duration, r.reason)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for r in list {
                    s.send(uid, format!(":{} NOTICE {nick} :FILTER {r}", s.name));
                }
                s.send(
                    uid,
                    format!(":{} NOTICE {nick} :End of FILTER list", s.name),
                );
            }
            Some(pattern) => {
                let pattern = pattern.clone();
                if params.len() < 2 {
                    let removed = s
                        .ext
                        .get_mut::<Filters>()
                        .map(|f| {
                            let before = f.0.len();
                            f.0.retain(|r| r.pattern != pattern);
                            before != f.0.len()
                        })
                        .unwrap_or(false);
                    let word = if removed { "removed" } else { "not found" };
                    s.send(
                        uid,
                        format!(":{} NOTICE {nick} :FILTER {word}: {pattern}", s.name),
                    );
                } else {
                    let action = params[1].clone();
                    let (duration, reason) = match params.get(2).and_then(|p| parse_duration(p)) {
                        Some(d) if params.len() > 3 => (d, params[3].clone()),
                        _ => (
                            0,
                            params
                                .get(2)
                                .cloned()
                                .unwrap_or_else(|| "Filtered".to_string()),
                        ),
                    };
                    // Compile with the configured engine (glob default), rejecting a
                    // bad rule now rather than having it silently never match.
                    let engine = s.conf("filter_engine").unwrap_or("glob").to_string();
                    let filter = match SpamFilter::new(pattern.clone(), engine.clone(), action.clone(), duration, reason) {
                        Ok(f) => f,
                        Err(e) => {
                            let e_s = e.to_string();
                            let m = s.trf("FILTER rejected ({0})", &[e_s.as_str()]);
                            s.send(uid, format!(":{} NOTICE {nick} :{m}", s.name));
                            return CmdResult::Fail;
                        }
                    };
                    let f = s.ext.get_or_insert_with::<Filters>(Filters::default);
                    f.0.retain(|r| r.pattern != pattern);
                    f.0.push(filter);
                    let m = s.trf(
                        "{0} added FILTER {1} (engine={2} action={3})",
                        &[nick.as_str(), pattern.as_str(), engine.as_str(), action.as_str()],
                    );
                    s.snotice_c('f', &m);
                }
            }
        }
        CmdResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_by_engine() {
        let mut filters = Filters::default();
        filters.0.push(SpamFilter::new("*buy now*".into(), "glob".into(), "block".into(), 0, "spam".into()).unwrap());
        filters.0.push(SpamFilter::new("free.*money".into(), "regex".into(), "kill".into(), 0, "scam".into()).unwrap());
        // glob is case-insensitive wildcard matching
        assert!(filters.hit("hey BUY NOW cheap").is_some(), "glob rule matches");
        // regex is a full expression (unanchored substring search)
        assert_eq!(filters.hit("get free money here").map(|(a, _, _)| a), Some("kill".into()), "regex rule matches");
        assert!(filters.hit("an ordinary message").is_none(), "no rule matches clean text");
        // an invalid regex is refused when the rule is built
        assert!(SpamFilter::new("(oops".into(), "regex".into(), "block".into(), 0, "x".into()).is_err());
    }
}
