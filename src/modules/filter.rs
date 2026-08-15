//! Oper-configured spam/word filters: a glob is matched against PRIVMSG/NOTICE text
//! and, on a hit, an action is taken. The rule set lives in `Server.ext`, the
//! `FILTER` command manages it, and the `on_pre_message` hook enforces it.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::module::{ModResult, Module};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::xline::{parse_duration, XKind};
use crate::Uid;

/// One filter rule.
#[derive(Clone)]
pub struct SpamFilter {
    pub pattern: String, // glob matched against message text
    pub action: String,  // block | silent | kill | kline | gline | zline
    pub duration: u64,   // ban length for the *line actions (seconds; 0 = permanent)
    pub reason: String,
}

/// The rule set, stored in `Server.ext`.
#[derive(Default)]
pub struct Filters(pub Vec<SpamFilter>);

impl Filters {
    /// The (action, reason, duration) of the first rule whose glob matches `text`.
    fn hit(&self, text: &str) -> Option<(String, String, u64)> {
        self.0
            .iter()
            .find(|f| glob_match(&f.pattern, text))
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
                s.send(uid, format!("ERROR :Closing link: ({reason})"));
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
                                format!("{} {} {} :{}", r.pattern, r.action, r.duration, r.reason)
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
                    let f = s.ext.get_or_insert_with::<Filters>(Filters::default);
                    f.0.retain(|r| r.pattern != pattern);
                    f.0.push(SpamFilter {
                        pattern: pattern.clone(),
                        action: action.clone(),
                        duration,
                        reason,
                    });
                    s.snotice_c('f', &format!("{nick} added FILTER {pattern} (action={action})"));
                }
            }
        }
        CmdResult::Ok
    }
}
