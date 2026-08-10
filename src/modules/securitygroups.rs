//! Named security groups. A `securitygroup` config line defines a named set of users
//! by AND-ed criteria (host masks, TLS, account, oper, bot, webirc, reputation score
//! range). Groups drive the `g:` matching extban, the `SECURITYGROUPS` command, and a
//! WHOIS line.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOSUCHNICK;
use crate::server::Server;
use crate::Uid;

/// Tri-state for a criterion: don't-care / must-be / must-not-be.
#[derive(Clone, Copy, PartialEq, Default)]
enum Tri {
    #[default]
    Ignore,
    Yes,
    No,
}

/// A security group — all criteria AND-ed.
#[derive(Clone, Default)]
struct SecGroup {
    name: String,
    public: bool,
    masks: Vec<String>,
    exclude_masks: Vec<String>,
    tls: Tri,
    account: Tri,
    oper: Tri,
    bot: Tri,
    webirc: Tri,
    score_min: Option<u32>,
    score_max: Option<u32>,
}

/// Parse the `securitygroup = <name> [criteria…]` config lines into groups.
fn parse_groups(s: &Server) -> Vec<SecGroup> {
    let mut out = Vec::new();
    for line in s
        .conf_all("securitygroup")
        .iter()
        .chain(s.conf_all("secgroup"))
    {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        let mut g = SecGroup {
            name: name.to_string(),
            ..Default::default()
        };
        for tok in it {
            let (k, val) = match tok.split_once('=') {
                Some((a, b)) => (a, Some(b)),
                None => (tok, None),
            };
            match (k, val) {
                ("public", _) => g.public = true,
                ("mask", Some(m)) => g.masks.push(m.to_string()),
                ("exclude", Some(m)) | ("exclude-mask", Some(m)) => {
                    g.exclude_masks.push(m.to_string())
                }
                ("tls", _) | ("tls-users", _) => g.tls = Tri::Yes,
                ("insecure", _) | ("exclude-tls", _) => g.tls = Tri::No,
                ("account", _) | ("registered", _) => g.account = Tri::Yes,
                ("unregistered", _) | ("exclude-account", _) => g.account = Tri::No,
                ("oper", _) => g.oper = Tri::Yes,
                ("exclude-oper", _) => g.oper = Tri::No,
                ("bot", _) | ("bmode", _) => g.bot = Tri::Yes,
                ("exclude-bot", _) | ("exclude-bmode", _) => g.bot = Tri::No,
                ("webirc", _) => g.webirc = Tri::Yes,
                ("exclude-webirc", _) => g.webirc = Tri::No,
                ("scoremin", Some(n)) => g.score_min = n.parse().ok(),
                ("scoremax", Some(n)) => g.score_max = n.parse().ok(),
                _ => {}
            }
        }
        out.push(g);
    }
    out
}

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
    parse_groups(s)
        .iter()
        .any(|g| g.name.eq_ignore_ascii_case(name) && matches(s, uid, g))
}

/// The names of the groups `uid` is in (only public ones unless `include_private`).
pub fn user_groups(s: &Server, uid: Uid, include_private: bool) -> Vec<String> {
    parse_groups(s)
        .into_iter()
        .filter(|g| (include_private || g.public) && matches(s, uid, g))
        .map(|g| g.name)
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
