//! Named security groups. A `securitygroup` config line defines a named set of users
//! by AND-ed criteria: host masks, TLS, account (any, or specific names), oper, bot,
//! webirc, real name, connect class, listener port, TLS cert fingerprint, origin ASN,
//! GeoIP country, and reputation score range. Groups drive the `g:` matching extban,
//! the `SECURITYGROUPS` command, and a WHOIS line.

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
    asn: Vec<u32>,
    realnames: Vec<String>,
    exclude_realnames: Vec<String>,
    classes: Vec<String>,
    ports: Vec<u16>,
    certfps: Vec<String>,
    accounts: Vec<String>,
    countries: String, // comma-joined ISO country codes, matched via geoip
}

/// Parse the `securitygroup = <name> [criteria…]` config lines into groups.
/// A "require X" flag: bare or `=yes` requires it; an explicit falsy value excludes it.
fn flag_tri(v: Option<&str>) -> Tri {
    match v {
        Some(x)
            if matches!(
                x.to_ascii_lowercase().as_str(),
                "no" | "false" | "0" | "off"
            ) =>
        {
            Tri::No
        }
        _ => Tri::Yes,
    }
}

thread_local! {
    /// (config_gen, parsed groups) — re-parsed only when the config changes. The
    /// core is single-threaded, so a thread_local cache is safe and lets the
    /// `&Server` callers (the `g:` extban match, WHOIS) skip re-parsing per call.
    static GROUPS: std::cell::RefCell<(u64, Vec<SecGroup>)> =
        const { std::cell::RefCell::new((u64::MAX, Vec::new())) };
}

/// Run `f` over the security groups, (re)parsing them only when the config changed.
fn with_groups<R>(s: &Server, f: impl FnOnce(&[SecGroup]) -> R) -> R {
    GROUPS.with(|cell| {
        if cell.borrow().0 != s.config_gen {
            let fresh = parse_groups(s);
            *cell.borrow_mut() = (s.config_gen, fresh);
        }
        let guard = cell.borrow();
        f(&guard.1)
    })
}

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
                // A bare flag (or `=yes`) requires it; an explicit `=no`/`false`/`0`/`off`
                // excludes it — so `tls=no` means "not TLS", not "require TLS".
                ("tls", v) | ("tls-users", v) => g.tls = flag_tri(v),
                ("insecure", _) | ("exclude-tls", _) => g.tls = Tri::No,
                ("account", v) | ("registered", v) => g.account = flag_tri(v),
                ("unregistered", _) | ("exclude-account", _) => g.account = Tri::No,
                ("oper", v) => g.oper = flag_tri(v),
                ("exclude-oper", _) => g.oper = Tri::No,
                ("bot", v) | ("bmode", v) => g.bot = flag_tri(v),
                ("exclude-bot", _) | ("exclude-bmode", _) => g.bot = Tri::No,
                ("webirc", v) => g.webirc = flag_tri(v),
                ("exclude-webirc", _) => g.webirc = Tri::No,
                ("scoremin", Some(n)) => g.score_min = n.parse().ok(),
                ("scoremax", Some(n)) => g.score_max = n.parse().ok(),
                ("asn", Some(a)) => g.asn.extend(crate::modules::asn::parse_list(a)),
                // real name (GECOS) globs; wildcards stand in for spaces
                ("realname", Some(m)) | ("gecos", Some(m)) => g.realnames.push(m.to_string()),
                ("exclude-realname", Some(m)) | ("exclude-gecos", Some(m)) => {
                    g.exclude_realnames.push(m.to_string())
                }
                // connect class name(s)
                ("class", Some(c)) | ("connectclass", Some(c)) => g
                    .classes
                    .extend(c.split(',').filter(|x| !x.is_empty()).map(str::to_string)),
                // listener port(s) the client connected to
                ("port", Some(p)) => g
                    .ports
                    .extend(p.split(',').filter_map(|x| x.parse::<u16>().ok())),
                // TLS client-cert fingerprint(s)
                ("certfp", Some(f)) | ("fingerprint", Some(f)) => g.certfps.extend(
                    f.split(',')
                        .filter(|x| !x.is_empty())
                        .map(|x| x.to_ascii_lowercase()),
                ),
                // specific account name(s) — globs; `account`/`registered` stays the boolean
                ("accountname", Some(a)) | ("acct", Some(a)) => g
                    .accounts
                    .extend(a.split(',').filter(|x| !x.is_empty()).map(str::to_string)),
                // GeoIP country code(s)
                ("country", Some(c)) | ("cc", Some(c)) | ("geo", Some(c)) => {
                    if !g.countries.is_empty() {
                        g.countries.push(',');
                    }
                    g.countries.push_str(&c.to_ascii_uppercase());
                }
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
    if !g.asn.is_empty() && !crate::modules::asn::user_in(s, uid, &g.asn) {
        return false;
    }
    // real name globs: an exclude match vetoes; positive globs require one to match
    if g.exclude_realnames.iter().any(|m| glob_match(m, &u.realname)) {
        return false;
    }
    if !g.realnames.is_empty() && !g.realnames.iter().any(|m| glob_match(m, &u.realname)) {
        return false;
    }
    // connect class name
    if !g.classes.is_empty()
        && !u
            .class
            .as_deref()
            .is_some_and(|c| g.classes.iter().any(|x| x.eq_ignore_ascii_case(c)))
    {
        return false;
    }
    // listener port the client connected to
    if !g.ports.is_empty() && !g.ports.contains(&u.port) {
        return false;
    }
    // TLS client-cert fingerprint
    if !g.certfps.is_empty()
        && !u
            .certfp
            .as_deref()
            .is_some_and(|fp| g.certfps.iter().any(|x| x.eq_ignore_ascii_case(fp)))
    {
        return false;
    }
    // specific account name(s), glob (case-insensitive)
    if !g.accounts.is_empty()
        && !u
            .account
            .as_deref()
            .is_some_and(|a| g.accounts.iter().any(|m| glob_match(m, a)))
    {
        return false;
    }
    // GeoIP country
    if !g.countries.is_empty() && !crate::modules::geoip::geoban_match(s, uid, &g.countries) {
        return false;
    }
    true
}

/// Whether `uid` is a member of the named security group (case-insensitive).
pub fn in_group(s: &Server, uid: Uid, name: &str) -> bool {
    with_groups(s, |groups| {
        groups
            .iter()
            .any(|g| g.name.eq_ignore_ascii_case(name) && matches(s, uid, g))
    })
}

/// The names of the groups `uid` is in (only public ones unless `include_private`).
pub fn user_groups(s: &Server, uid: Uid, include_private: bool) -> Vec<String> {
    with_groups(s, |groups| {
        groups
            .iter()
            .filter(|g| (include_private || g.public) && matches(s, uid, g))
            .map(|g| g.name.clone())
            .collect()
    })
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
        let m = s.trf(
            "{0} is in security groups: {1}",
            &[tnick.as_str(), list.as_str()],
        );
        s.send(uid, format!(":{} NOTICE {anick} :{m}", s.name));
        CmdResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::extensible::Extensible;
    use crate::map::HashSet;
    use crate::socketengine::OutSink;
    use crate::users::{Caps, User, UserFlags};
    use std::sync::atomic::AtomicU64;
    use std::sync::{mpsc, Arc};

    fn srv_with_user() -> Server {
        let (tx, _rx) = mpsc::sync_channel(1024);
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        let (utx, _urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "Cool Bot Client".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: true,
                certfp: Some("ABCDEF0123".into()),
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: Some("alice".into()),
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6697,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: Some("trusted".into()),
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                last_msg: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s
    }

    #[test]
    fn new_criteria_match_and_veto() {
        let s = srv_with_user();
        let base = SecGroup {
            name: "t".into(),
            realnames: vec!["*bot*".into()],
            classes: vec!["trusted".into()],
            ports: vec![6697],
            certfps: vec!["abcdef0123".into()], // case-insensitive vs the user's mixed-case fp
            accounts: vec!["ali*".into()],      // glob
            ..Default::default()
        };
        assert!(matches(&s, 7, &base), "all new criteria satisfied");

        let wrong_port = SecGroup {
            ports: vec![6667],
            ..base.clone()
        };
        assert!(!matches(&s, 7, &wrong_port), "wrong port fails");

        let wrong_class = SecGroup {
            classes: vec!["main".into()],
            ..base.clone()
        };
        assert!(!matches(&s, 7, &wrong_class), "wrong connect class fails");

        let wrong_acct = SecGroup {
            accounts: vec!["bob".into()],
            ..base.clone()
        };
        assert!(!matches(&s, 7, &wrong_acct), "wrong account fails");

        let vetoed = SecGroup {
            exclude_realnames: vec!["*bot*".into()],
            ..base.clone()
        };
        assert!(!matches(&s, 7, &vetoed), "exclude-realname vetoes");
    }
}
