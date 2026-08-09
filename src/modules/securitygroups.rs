//! securitygroups — UnrealIRCd-style security groups (InspIRCd `m_securitygroups`).
//! A `securitygroup` config line defines a named set of users by AND-ed criteria
//! (host masks, TLS, account, oper, bot, webirc, reputation score range). Groups
//! drive the `g:` matching extban, the `SECURITYGROUPS` command, and a WHOIS line.
//! Self-contained: the group defs live in `Server.sec_groups`; evaluation is here.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::config::{SecGroup, Tri};
use crate::numeric::ERR_NOSUCHNICK;
use crate::server::Server;
use crate::Uid;

/// Does `uid`'s identity match `mask` (glob against nick!user@{display,real,ip})?
fn mask_matches(s: &Server, uid: Uid, mask: &str) -> bool {
    let Some(u) = s.users.get(&uid) else {
        return false;
    };
    let forms = [
        format!("{}!{}@{}", u.nick, u.ident, u.host_display()),
        format!("{}!{}@{}", u.nick, u.ident, u.host),
        format!("{}!{}@{}", u.nick, u.ident, u.addr.ip()),
    ];
    forms.iter().any(|f| glob_match(mask, f))
}

/// True when a tri-state criterion is satisfied by `fact`.
fn tri_ok(want: Tri, fact: bool) -> bool {
    match want {
        Tri::Yes => fact,
        Tri::No => !fact,
        Tri::Ignore => true,
    }
}

/// Does `uid` match every criterion of `g`?
fn matches(s: &Server, uid: Uid, g: &SecGroup) -> bool {
    let Some(u) = s.users.get(&uid) else {
        return false;
    };
    // masks: an exclude match vetoes; positive masks (if any) require one to match
    if g.exclude_masks.iter().any(|m| mask_matches(s, uid, m)) {
        return false;
    }
    if !g.masks.is_empty() && !g.masks.iter().any(|m| mask_matches(s, uid, m)) {
        return false;
    }
    if !tri_ok(g.tls, u.secure)
        || !tri_ok(g.account, u.account.is_some())
        || !tri_ok(g.oper, u.flags.oper)
        || !tri_ok(g.bot, u.flags.bot)
        || !tri_ok(g.webirc, u.flags.via_webirc)
    {
        return false;
    }
    if g.score_min.is_some() || g.score_max.is_some() {
        let score = crate::modules::reputation::score_of(s, uid);
        if g.score_min.is_some_and(|m| score < m) || g.score_max.is_some_and(|m| score > m) {
            return false;
        }
    }
    true
}

/// Whether `uid` is a member of the named security group (case-insensitive).
pub fn in_group(s: &Server, uid: Uid, name: &str) -> bool {
    s.sec_groups
        .iter()
        .any(|g| g.name.eq_ignore_ascii_case(name) && matches(s, uid, g))
}

/// The names of the groups `uid` is in (only public ones unless `include_private`).
pub fn user_groups(s: &Server, uid: Uid, include_private: bool) -> Vec<String> {
    s.sec_groups
        .iter()
        .filter(|g| (include_private || g.public) && matches(s, uid, g))
        .map(|g| g.name.clone())
        .collect()
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(SecGroupsCmd)]
}

/// SECURITYGROUPS — `SECURITYGROUPS [nick]`. List the security groups a user is in.
/// You always see your own; opers see everyone's; otherwise only public groups show.
struct SecGroupsCmd;
impl Command for SecGroupsCmd {
    fn name(&self) -> &'static str {
        "SECURITYGROUPS"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let tuid = match params.first() {
            Some(n) => match s.find_nick(n) {
                Some(t) => t,
                None => {
                    s.numeric(uid, ERR_NOSUCHNICK, &format!("{n} :No such nick/channel"));
                    return CmdResult::Fail;
                }
            },
            None => uid,
        };
        let include_private = tuid == uid || s.is_oper(uid);
        let groups = user_groups(s, tuid, include_private);
        let list = if groups.is_empty() {
            "none".to_string()
        } else {
            groups.join(", ")
        };
        let (tnick, anick) = (
            s.users
                .get(&tuid)
                .map(|u| u.nick.clone())
                .unwrap_or_default(),
            s.users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default(),
        );
        s.send(
            uid,
            format!(
                ":{} NOTICE {anick} :{tnick} is in security groups: {list}",
                s.name
            ),
        );
        CmdResult::Ok
    }
}
