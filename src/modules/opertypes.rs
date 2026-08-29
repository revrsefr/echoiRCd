//! opertypes — oper classes + types. A `class` is a reusable
//! capability bundle (commands / privs / snomasks); an `opertype` is a named role
//! (the WHOIS title) built from classes plus auto usermodes / snomasks / vhost. An
//! `oper` block selects one with `type=<id>`. Enforced through `on_pre_command`; an
//! oper with no type keeps full access (legacy). Five types ship built-in.
//!
//! Config (repeatable):
//!   class    = <id> commands=A,B privs=x,y snomasks=abc
//!   opertype = <id> classes=c1,c2 [commands=..] [privs=..] modes=+iw snomasks=+cg \
//!              [vhost=host.name] [title=Nice_Title] [level=N]
//!   oper     = <name> <pass> type=<id> [fp=..]

use std::cell::RefCell;
use std::collections::HashSet;

use crate::map::HashMap;
use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::users::DEFAULT_SNOMASK;
use crate::Uid;

/// Canonical operator privilege names, grouped by domain. Every gate calls
/// [`has_priv`]/[`user_has_priv`] with one of these constants, so the strings live
/// in one place instead of drifting as scattered literals. Config `class privs="…"`
/// uses the same strings (space/comma separated; `*` grants all).
pub mod privs {
    /// see a user's real host+IP and geo, and +i users you share no channel with
    pub const USERS_AUSPEX: &str = "users/auspex";
    /// see secret/private (+s/+p) channels in LIST / WHO / WHOIS
    pub const CHANNELS_AUSPEX: &str = "channels/auspex";
    /// see U-lined/services servers otherwise hidden by `hideservices`
    pub const SERVERS_AUSPEX: &str = "servers/auspex";
    /// exempt from message-flood and join-flood limits
    pub const USERS_FLOOD: &str = "users/flood";
    /// message a +c user without sharing a common channel
    pub const USERS_IGNORE_COMMONCHANS: &str = "users/ignore-commonchans";
    /// join through +k/+b/+i/+l/+z/+R/+J, CBAN and the max-channels cap
    pub const CHANNELS_OVERRIDE: &str = "channels/override";
    /// create a new channel while `restrictchans` is on
    pub const CHANNELS_RESTRICTED_CREATE: &str = "channels/restricted-create";
    /// change nick while on a +N (no-nick-change) channel
    pub const CHANNELS_IGNORE_NONICKS: &str = "channels/ignore-nonicks";
    /// message a +g (caller-id) user without being on their ACCEPT list
    pub const USERS_IGNORE_CALLERID: &str = "users/ignore-callerid";
    /// reach a +D (deaf) user with your channel messages despite their deafness
    pub const USERS_IGNORE_PRIVDEAF: &str = "users/ignore-privdeaf";
    /// `/WHOIS` a +W (showwhois) user without notifying them
    pub const USERS_SECRET_WHOIS: &str = "users/secret-whois";
    /// private-message anyone while `restrictmsg` is on
    pub const USERS_IGNORE_RESTRICTMSG: &str = "users/ignore-restrictmsg";
    /// use a command turned off by `disabled_commands`
    pub const SERVERS_USE_DISABLED_COMMANDS: &str = "servers/use-disabled-commands";
    /// bypass the `securelist` LIST hold for fresh connections
    pub const SERVERS_IGNORE_SECURELIST: &str = "servers/ignore-securelist";
    /// send `/AMSG`-style multi-channel messages the `blockamsg` module blocks
    pub const SERVERS_IGNORE_BLOCKAMSG: &str = "servers/ignore-blockamsg";
}

/// Per-user resolved grant, stored on `User.ext` at oper-up. Present ⇒ a typed
/// oper; absent ⇒ a legacy oper with full access. Read by WHOIS for the title.
pub struct OperType {
    pub title: String,
    pub color: Option<u8>, // mIRC colour for the WHOIS title line (None = plain)
    pub all_commands: bool,
    pub commands: HashSet<String>,
    pub all_privs: bool,
    pub privs: HashSet<String>,
    pub deny_commands: HashSet<String>, // `-CMD` removals even when all_commands
    pub deny_privs: HashSet<String>,    // `-priv` removals even when all_privs
    pub usermodes: ModeAllow, // oper-only user modes this type may set
    pub chanmodes: ModeAllow, // oper-only channel modes this type may set
}

/// Commands an oper type gates. Anything outside this set (OPERMOTD, MKPASSWD,
/// ALLTIME, WHOIS, …) is open to every oper.
const GATED: &[&str] = &[
    "KILL", "KLINE", "GLINE", "ZLINE", "QLINE", "ELINE", "RLINE", "SHUN", "CBAN",
    "CHECK", "NICKLOCK", "NICKUNLOCK", "SAJOIN", "SAPART", "SANICK", "SAKICK",
    "SAMODE", "SATOPIC", "SAQUIT", "CLEARCHAN", "SVSNICK", "SVSJOIN", "SVSPART",
    "SVSMODE", "SVSLOGIN", "SVSLOGOUT", "CHGHOST", "CHGIDENT", "CHGNAME", "SETHOST",
    "SETIDENT", "SETIDLE", "SWHOIS", "WALLOPS", "GLOBOPS", "CONNECT", "SQUIT",
    "DIE", "RESTART",
];

fn gated(cmd: &str) -> bool {
    GATED.contains(&cmd.to_ascii_uppercase().as_str())
}

pub struct OperTypes;

impl Module for OperTypes {
    fn name(&self) -> &'static str {
        "opertypes"
    }
    fn on_pre_command(&mut self, srv: &mut Server, uid: Uid, cmd: &str, _params: &[String]) -> ModResult {
        if !srv.is_oper(uid) || !gated(cmd) {
            return ModResult::Passthru;
        }
        let up = cmd.to_ascii_uppercase();
        let (allowed, title) = match srv.users.get(&uid).and_then(|u| u.ext.get::<OperType>()) {
            None => (true, String::new()), // legacy full-access oper (no type)
            Some(t) => (
                (t.all_commands || t.commands.contains(&up)) && !t.deny_commands.contains(&up),
                t.title.clone(),
            ),
        };
        if allowed {
            return ModResult::Passthru;
        }
        srv.numeric(
            uid,
            crate::numeric::ERR_NOPRIVILEGES,
            &format!(":Permission denied — your \x02{title}\x02 oper type may not use {up}"),
        );
        ModResult::Deny
    }
}

/// The WHOIS title of a typed oper, if any (used in the denial message).
pub fn title_of(s: &Server, uid: Uid) -> Option<String> {
    s.users.get(&uid).and_then(|u| u.ext.get::<OperType>()).map(|t| t.title.clone())
}

/// The formatted WHOIS special line for a typed oper, if any — "is a/an <title>",
/// bold + the type's colour (mIRC code, e.g. 4 = red) so it stands out. core_info
/// emits it on its own 320 line.
pub fn whois_line(s: &Server, uid: Uid) -> Option<String> {
    let t = s.users.get(&uid).and_then(|u| u.ext.get::<OperType>())?;
    let article = if t.title.chars().next().is_some_and(|c| "aeiouAEIOU".contains(c)) {
        "an"
    } else {
        "a"
    };
    let body = format!("is {article} {}", t.title);
    Some(match t.color {
        Some(c) => format!("\x02\x03{c:02}{body}\x0f"), // bold + colour, reset after
        None => body,
    })
}

/// Whether operator `uid` holds privilege `name` (e.g. `users/auspex`).
/// A typed oper holds it if its type has `privs=*` or lists the privilege; an untyped
/// legacy oper (an `oper` block with no `type=`) holds every privilege; a non-oper holds
/// none. This is the check every privilege gate calls.
pub fn has_priv(s: &Server, uid: Uid, name: &str) -> bool {
    s.users.get(&uid).is_some_and(|u| user_has_priv(u, name))
}

/// [`has_priv`] against an already-borrowed `&User`, for use inside a user iteration.
pub fn user_has_priv(u: &crate::users::User, name: &str) -> bool {
    if !u.flags.oper {
        return false;
    }
    match u.ext.get::<OperType>() {
        None => true, // legacy oper (no type) — unrestricted
        Some(t) => (t.all_privs || t.privs.contains(name)) && !t.deny_privs.contains(name),
    }
}

/// Which oper-only modes a type may set: `All` (`usermodes="*"`, or a type that never
/// restricts) or `Only(set)` for an explicit letter list. An unspecified allowlist
/// resolves to `All`, so a type restricts modes only when it opts in.
#[derive(Clone, Default)]
pub enum ModeAllow {
    #[default]
    All,
    Only(HashSet<char>),
}

impl ModeAllow {
    fn allows(&self, c: char) -> bool {
        match self {
            ModeAllow::All => true,
            ModeAllow::Only(set) => set.contains(&c),
        }
    }
}

/// Whether oper `uid`'s type may set the oper-only mode `letter` (`chan` picks the
/// channel-mode vs user-mode allowlist). Legacy untyped opers may set anything; the
/// caller has already confirmed oper-ness, so this only applies the per-type allowlist.
pub fn can_use_mode(s: &Server, uid: Uid, letter: char, chan: bool) -> bool {
    match s.users.get(&uid).and_then(|u| u.ext.get::<OperType>()) {
        None => true,
        Some(t) => {
            if chan {
                t.chanmodes.allows(letter)
            } else {
                t.usermodes.allows(letter)
            }
        }
    }
}

/// Parse a `usermodes=`/`chanmodes=` value into an allowlist (`*` = all).
fn parse_modeallow(v: &str) -> ModeAllow {
    if v.contains('*') {
        ModeAllow::All
    } else {
        ModeAllow::Only(v.chars().filter(|c| c.is_ascii_alphabetic()).collect())
    }
}

/// Fold `add` into `acc`, favouring the more permissive result (All wins, else union).
fn merge_modeallow(acc: &mut Option<ModeAllow>, add: &Option<ModeAllow>) {
    match add {
        None => {}
        Some(ModeAllow::All) => *acc = Some(ModeAllow::All),
        Some(ModeAllow::Only(s)) => match acc {
            Some(ModeAllow::All) => {}
            Some(ModeAllow::Only(existing)) => existing.extend(s.iter().copied()),
            None => *acc = Some(ModeAllow::Only(s.clone())),
        },
    }
}

/// Apply the oper's type at oper-up: auto usermodes / snomasks / vhost / level, then
/// store the grant + title. A missing type (or an unknown id) leaves the oper with
/// full access, so `oper` blocks without `type=` keep working.
pub fn apply(s: &mut Server, uid: Uid, type_id: Option<&str>) {
    let Some(id) = type_id.map(|t| t.to_ascii_lowercase()) else {
        return;
    };
    let Some(r) = with_resolved(s, |m| m.get(&id).cloned()) else {
        let m = s.trf("oper type '{0}' is not defined — granting full access", &[id.as_str()]);
        s.snotice_c('o', &m);
        return;
    };
    if !r.modes.is_empty() {
        crate::coremods::core_mode::svs_set_user_modes(s, uid, &r.modes);
    }
    if r.all_snomasks {
        set_snomask(s, uid, DEFAULT_SNOMASK);
    } else if let Some(letters) = &r.snomasks {
        set_snomask(s, uid, letters);
    }
    if let Some(h) = &r.vhost {
        s.change_host_ident(uid, None, Some(h));
    }
    if let Some(lvl) = r.level {
        crate::modules::operlevels::set(s, uid, lvl);
    }
    if let Some(u) = s.users.get_mut(&uid) {
        u.ext.set(OperType {
            title: r.title.clone(),
            color: r.color,
            all_commands: r.all_commands,
            commands: r.commands.clone(),
            all_privs: r.all_privs,
            privs: r.privs.clone(),
            deny_commands: r.deny_commands.clone(),
            deny_privs: r.deny_privs.clone(),
            usermodes: r.usermodes.clone(),
            chanmodes: r.chanmodes.clone(),
        });
    }
}

fn set_snomask(s: &mut Server, uid: Uid, letters: &str) {
    let cats: String = letters.chars().filter(|c| DEFAULT_SNOMASK.contains(*c)).collect();
    if let Some(u) = s.users.get_mut(&uid) {
        u.flags.snomask = !cats.is_empty();
        u.flags.snomask_cats = cats;
    }
}

// --- resolved types (built-in + config), rebuilt on rehash -------------------

#[derive(Clone)]
struct Resolved {
    title: String,
    color: Option<u8>,
    all_commands: bool,
    commands: HashSet<String>,
    all_privs: bool,
    privs: HashSet<String>,
    deny_commands: HashSet<String>,
    deny_privs: HashSet<String>,
    modes: String,
    snomasks: Option<String>, // Some(letters) auto-set; None = keep the oper-up default
    all_snomasks: bool,
    vhost: Option<String>,
    level: Option<u32>,
    usermodes: ModeAllow,
    chanmodes: ModeAllow,
}

thread_local! {
    static TYPES: RefCell<(u64, HashMap<String, Resolved>)> =
        RefCell::new((u64::MAX, HashMap::default()));
}

fn with_resolved<R>(s: &Server, f: impl FnOnce(&HashMap<String, Resolved>) -> R) -> R {
    TYPES.with(|cell| {
        if cell.borrow().0 != s.config_gen {
            let fresh = build_types(s);
            *cell.borrow_mut() = (s.config_gen, fresh);
        }
        f(&cell.borrow().1)
    })
}

#[derive(Default, Clone)]
struct ClassDef {
    all_commands: bool,
    commands: Vec<String>,
    all_privs: bool,
    privs: Vec<String>,
    deny_commands: Vec<String>,
    deny_privs: Vec<String>,
    all_snomasks: bool,
    snomasks: String,
    usermodes: Option<ModeAllow>,
    chanmodes: Option<ModeAllow>,
}

#[derive(Default, Clone)]
struct TypeDef {
    title: String,
    all_classes: bool,
    classes: Vec<String>,
    all_commands: bool,
    commands: Vec<String>,
    all_privs: bool,
    privs: Vec<String>,
    deny_commands: Vec<String>,
    deny_privs: Vec<String>,
    modes: String,
    all_snomasks: bool,
    snomasks: String,
    vhost: Option<String>,
    level: Option<u32>,
    color: Option<u8>,
    usermodes: Option<ModeAllow>,
    chanmodes: Option<ModeAllow>,
}

fn cdef(commands: &[&str], privs: &[&str], sno: &str) -> ClassDef {
    ClassDef {
        commands: commands.iter().map(|c| c.to_string()).collect(),
        privs: privs.iter().map(|p| p.to_string()).collect(),
        snomasks: sno.to_string(),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn tdef(title: &str, classes: &[&str], all_classes: bool, modes: &str, sno: &str, all_sno: bool, level: u32, color: Option<u8>) -> TypeDef {
    TypeDef {
        title: title.to_string(),
        all_classes,
        classes: classes.iter().map(|s| s.to_string()).collect(),
        modes: modes.to_string(),
        snomasks: sno.to_string(),
        all_snomasks: all_sno,
        level: Some(level),
        color,
        ..Default::default()
    }
}

/// The five ships-with-echoIRCd classes + types.
fn builtin() -> (HashMap<String, ClassDef>, HashMap<String, TypeDef>) {
    let mut classes: HashMap<String, ClassDef> = HashMap::default();
    classes.insert("announce".into(), cdef(&["WALLOPS", "GLOBOPS"], &[], "ag"));
    classes.insert("ban".into(), cdef(&["KILL", "KLINE", "GLINE", "ZLINE", "QLINE", "ELINE", "RLINE", "SHUN", "CBAN", "CHECK", "NICKLOCK", "NICKUNLOCK"], &[], "kx"));
    classes.insert("override".into(), cdef(&["SAJOIN", "SAPART", "SANICK", "SAKICK", "SAMODE", "SATOPIC", "SAQUIT", "CLEARCHAN"], &["channels/override", "users/flood", "channels/restricted-create", "channels/ignore-nonicks", "users/ignore-restrictmsg", "servers/ignore-securelist", "servers/ignore-blockamsg"], "v"));
    classes.insert("host".into(), cdef(&["CHGHOST", "CHGIDENT", "CHGNAME", "SETHOST", "SETIDENT", "SETIDLE", "SWHOIS"], &[], ""));
    classes.insert("services".into(), cdef(&["SVSNICK", "SVSJOIN", "SVSPART", "SVSMODE", "SVSLOGIN", "SVSLOGOUT"], &[], ""));
    classes.insert("server".into(), cdef(&["CONNECT", "SQUIT", "DIE", "RESTART"], &["servers/use-disabled-commands"], "lr"));
    // auspex: see through user/channel privacy (real host+IP, geo, secret channels)
    classes.insert("auspex".into(), cdef(&[], &["users/auspex", "channels/auspex", "servers/auspex", "users/secret-whois", "users/ignore-callerid", "users/ignore-privdeaf"], ""));

    let mut types: HashMap<String, TypeDef> = HashMap::default();
    // The WHOIS title line is bold + colour 4 (red) by default; override per type
    // with `color=<name|0-15|none>`.
    let red = Some(4);
    //                     title                       classes                                           all    modes   sno      all*   level color
    types.insert("helpop".into(), tdef("Help Operator", &[], false, "+ih", "o", false, 10, red));
    types.insert("globop".into(), tdef("GlobOp", &["announce"], false, "+iw", "acgoq", false, 20, red));
    types.insert("admin".into(), tdef("Administrator", &["announce", "ban", "override", "host"], false, "+iw", "", true, 50, red));
    types.insert("servadmin".into(), tdef("Services Administrator", &["announce", "ban", "override", "host", "services"], false, "+iw", "", true, 70, red));
    types.insert("netadmin".into(), tdef("Network Administrator", &[], true, "+iw", "", true, 100, red));
    (classes, types)
}

fn build_types(s: &Server) -> HashMap<String, Resolved> {
    let (mut classes, mut types) = builtin();
    for line in s.conf_all("class") {
        let mut it = line.split_whitespace();
        let Some(id) = it.next() else { continue };
        let mut cd = classes.get(id).cloned().unwrap_or_default();
        for tok in it {
            if let Some((k, v)) = tok.split_once('=') {
                apply_class_kv(&mut cd, k, v);
            }
        }
        classes.insert(id.to_string(), cd);
    }
    for line in s.conf_all("opertype") {
        let mut it = line.split_whitespace();
        let Some(id) = it.next() else { continue };
        let mut td = types.get(id).cloned().unwrap_or_default();
        for tok in it {
            if let Some((k, v)) = tok.split_once('=') {
                apply_type_kv(&mut td, k, v);
            }
        }
        if td.title.is_empty() {
            td.title = id.to_string();
        }
        types.insert(id.to_string(), td);
    }
    types.iter().map(|(id, td)| (id.clone(), resolve(td, &classes))).collect()
}

/// Fold a comma list of command/priv tokens: `*` sets `all`, `-X` denies X, a bare
/// token allows X. `norm` normalises case per axis (upper for commands, lower for privs).
fn fold_tokens(
    v: &str,
    all: &mut bool,
    allow: &mut Vec<String>,
    deny: &mut Vec<String>,
    norm: fn(&str) -> String,
) {
    for tok in v.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if tok == "*" {
            *all = true;
        } else if let Some(rest) = tok.strip_prefix('-').filter(|r| !r.is_empty()) {
            deny.push(norm(rest));
        } else {
            allow.push(norm(tok));
        }
    }
}

fn apply_class_kv(cd: &mut ClassDef, k: &str, v: &str) {
    match k {
        "commands" | "cmds" => {
            fold_tokens(v, &mut cd.all_commands, &mut cd.commands, &mut cd.deny_commands, str::to_ascii_uppercase)
        }
        "privs" => {
            fold_tokens(v, &mut cd.all_privs, &mut cd.privs, &mut cd.deny_privs, str::to_ascii_lowercase)
        }
        "snomasks" | "snomask" => {
            if v.contains('*') {
                cd.all_snomasks = true;
            } else {
                cd.snomasks.push_str(v);
            }
        }
        "usermodes" => cd.usermodes = Some(parse_modeallow(v)),
        "chanmodes" => cd.chanmodes = Some(parse_modeallow(v)),
        _ => {}
    }
}

fn apply_type_kv(td: &mut TypeDef, k: &str, v: &str) {
    match k {
        "classes" => {
            if v == "*" {
                td.all_classes = true;
            } else {
                td.classes.extend(v.split(',').filter(|x| !x.is_empty()).map(|x| x.to_string()));
            }
        }
        "commands" | "cmds" => {
            fold_tokens(v, &mut td.all_commands, &mut td.commands, &mut td.deny_commands, str::to_ascii_uppercase)
        }
        "privs" => {
            fold_tokens(v, &mut td.all_privs, &mut td.privs, &mut td.deny_privs, str::to_ascii_lowercase)
        }
        "modes" => td.modes = v.to_string(),
        "usermodes" => td.usermodes = Some(parse_modeallow(v)),
        "chanmodes" => td.chanmodes = Some(parse_modeallow(v)),
        "snomasks" | "snomask" => {
            if v.contains('*') {
                td.all_snomasks = true;
            } else {
                td.snomasks.push_str(v);
            }
        }
        "vhost" | "host" => td.vhost = Some(v.to_string()),
        "title" => td.title = v.replace('_', " "),
        "level" => {
            if let Ok(l) = v.parse() {
                td.level = Some(l);
            }
        }
        "color" | "colour" => {
            td.color = match v.to_ascii_lowercase().as_str() {
                "none" | "off" | "no" | "plain" => None,
                "white" => Some(0),
                "black" => Some(1),
                "blue" => Some(2),
                "green" => Some(3),
                "red" => Some(4),
                "brown" => Some(5),
                "magenta" | "purple" => Some(6),
                "orange" => Some(7),
                "yellow" => Some(8),
                "cyan" | "teal" => Some(10),
                "pink" => Some(13),
                "grey" | "gray" => Some(14),
                n => n.parse::<u8>().ok().filter(|c| *c <= 15).or(td.color),
            };
        }
        _ => {} // maxchans etc.: accepted, not yet enforced
    }
}

fn resolve(td: &TypeDef, classes: &HashMap<String, ClassDef>) -> Resolved {
    let mut all_commands = td.all_commands || td.all_classes;
    let mut commands: HashSet<String> = td.commands.iter().cloned().collect();
    let mut all_privs = td.all_privs || td.all_classes;
    let mut privs: HashSet<String> = td.privs.iter().cloned().collect();
    let mut deny_commands: HashSet<String> = td.deny_commands.iter().cloned().collect();
    let mut deny_privs: HashSet<String> = td.deny_privs.iter().cloned().collect();
    let mut all_sno = td.all_snomasks;
    let mut sno = td.snomasks.clone();
    // mode allowlists: an all-classes type may set every oper mode; otherwise merge the
    // classes' + type's lists, and an unspecified allowlist stays permissive (`All`).
    let mut usermodes: Option<ModeAllow> = td.usermodes.clone();
    let mut chanmodes: Option<ModeAllow> = td.chanmodes.clone();
    if td.all_classes {
        usermodes = Some(ModeAllow::All);
        chanmodes = Some(ModeAllow::All);
    }

    let names: Vec<String> = if td.all_classes {
        classes.keys().cloned().collect()
    } else {
        td.classes.clone()
    };
    for name in names {
        if let Some(cd) = classes.get(&name) {
            all_commands |= cd.all_commands;
            commands.extend(cd.commands.iter().cloned());
            all_privs |= cd.all_privs;
            privs.extend(cd.privs.iter().cloned());
            deny_commands.extend(cd.deny_commands.iter().cloned());
            deny_privs.extend(cd.deny_privs.iter().cloned());
            all_sno |= cd.all_snomasks;
            sno.push_str(&cd.snomasks);
            merge_modeallow(&mut usermodes, &cd.usermodes);
            merge_modeallow(&mut chanmodes, &cd.chanmodes);
        }
    }

    let snomasks = if all_sno {
        None
    } else {
        let mut seen = String::new();
        for ch in sno.chars() {
            if DEFAULT_SNOMASK.contains(ch) && !seen.contains(ch) {
                seen.push(ch);
            }
        }
        (!seen.is_empty()).then_some(seen)
    };

    Resolved {
        title: td.title.clone(),
        color: td.color,
        all_commands,
        commands,
        all_privs,
        privs,
        deny_commands,
        deny_privs,
        modes: td.modes.clone(),
        snomasks,
        all_snomasks: all_sno,
        vhost: td.vhost.clone(),
        level: td.level,
        usermodes: usermodes.unwrap_or_default(),
        chanmodes: chanmodes.unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(id: &str) -> Resolved {
        let (classes, types) = builtin();
        resolve(types.get(id).expect("builtin type"), &classes)
    }

    #[test]
    fn builtin_types_grant_the_right_capabilities() {
        let helpop = resolved("helpop");
        assert_eq!(helpop.title, "Help Operator");
        assert!(!helpop.all_commands);
        assert!(helpop.commands.is_empty(), "helpop gets no gated commands");
        assert_eq!(helpop.modes, "+ih");

        let globop = resolved("globop");
        assert!(globop.commands.contains("GLOBOPS") && globop.commands.contains("WALLOPS"));
        assert!(!globop.commands.contains("KILL"), "globop can't KILL");

        let admin = resolved("admin");
        assert!(admin.commands.contains("KILL") && admin.commands.contains("SAJOIN") && admin.commands.contains("CHGHOST"));
        assert!(admin.privs.contains("channels/override") && admin.privs.contains("users/flood"));
        assert!(!admin.commands.contains("DIE"), "admin can't DIE");
        assert!(!admin.commands.contains("SVSNICK"), "admin isn't a services admin");
        assert!(admin.all_snomasks);

        let servadmin = resolved("servadmin");
        assert!(servadmin.commands.contains("SVSNICK") && servadmin.commands.contains("KILL"));
        assert!(!servadmin.commands.contains("DIE"), "servadmin can't DIE");

        let netadmin = resolved("netadmin");
        assert_eq!(netadmin.title, "Network Administrator");
        assert!(netadmin.all_commands, "netadmin gets everything");
    }

    #[test]
    fn only_all_privs_types_hold_auspex_by_default() {
        // the resolved priv set is what user_has_priv checks: all_privs || privs.contains.
        let has = |r: &Resolved, p: &str| r.all_privs || r.privs.contains(p);

        // netadmin holds every class ⇒ every privilege, incl. the auspex pair
        let netadmin = resolved("netadmin");
        assert!(netadmin.all_privs, "netadmin holds every privilege");
        assert!(has(&netadmin, "users/auspex") && has(&netadmin, "channels/auspex"));

        // no lower built-in type sees through privacy until granted the auspex class
        for id in ["helpop", "globop", "admin", "servadmin"] {
            let r = resolved(id);
            assert!(!has(&r, "users/auspex"), "{id} must not hold users/auspex by default");
            assert!(!has(&r, "channels/auspex"), "{id} must not hold channels/auspex by default");
        }

        // the auspex class exists so an admin can opt a type in
        let (classes, _) = builtin();
        let aux = classes.get("auspex").expect("auspex class");
        assert!(
            aux.privs.contains(&"users/auspex".to_string())
                && aux.privs.contains(&"channels/auspex".to_string())
        );
    }

    #[test]
    fn mode_allowlist_defaults_permissive_and_restricts_when_set() {
        let no_classes: HashMap<String, ClassDef> = HashMap::default();
        // built-ins never restrict modes → every oper-only letter is allowed
        for id in ["helpop", "globop", "admin", "servadmin", "netadmin"] {
            let r = resolved(id);
            assert!(r.usermodes.allows('H') && r.chanmodes.allows('O'), "{id} unrestricted");
        }
        // an explicit list restricts to those letters; the unset axis stays permissive
        let mut td = TypeDef::default();
        apply_type_kv(&mut td, "usermodes", "iw");
        let r = resolve(&td, &no_classes);
        assert!(r.usermodes.allows('i') && r.usermodes.allows('w'));
        assert!(!r.usermodes.allows('H'), "H is not in the usermodes allowlist");
        assert!(r.chanmodes.allows('O'), "unspecified chanmodes stay permissive");
        // "*" grants all
        let mut td2 = TypeDef::default();
        apply_type_kv(&mut td2, "usermodes", "*");
        assert!(resolve(&td2, &no_classes).usermodes.allows('H'));
    }

    #[test]
    fn token_deny_removes_even_when_all() {
        let no_classes: HashMap<String, ClassDef> = HashMap::default();
        // `*,-X` = all except X, on both the command and priv axes
        let mut td = TypeDef::default();
        apply_type_kv(&mut td, "commands", "*,-DIE");
        apply_type_kv(&mut td, "privs", "*,-users/auspex");
        let r = resolve(&td, &no_classes);
        assert!(r.all_commands && r.deny_commands.contains("DIE"));
        assert!(r.all_privs && r.deny_privs.contains("users/auspex"));
        // a bare list may still carry a removal
        let mut td2 = TypeDef::default();
        apply_type_kv(&mut td2, "commands", "KILL,-GLINE");
        let r2 = resolve(&td2, &no_classes);
        assert!(!r2.all_commands && r2.commands.contains("KILL") && r2.deny_commands.contains("GLINE"));
    }

    #[test]
    fn builtin_classes_grant_the_new_privileges() {
        let (classes, _) = builtin();
        let has = |c: &str, p: &str| classes.get(c).unwrap().privs.contains(&p.to_string());
        assert!(has("override", "channels/restricted-create") && has("override", "channels/ignore-nonicks"));
        assert!(has("override", "users/ignore-restrictmsg"));
        assert!(has("override", "servers/ignore-securelist") && has("override", "servers/ignore-blockamsg"));
        assert!(has("auspex", "users/secret-whois") && has("auspex", "users/ignore-callerid"));
        assert!(has("auspex", "users/ignore-privdeaf"));
        assert!(has("server", "servers/use-disabled-commands"));
        // netadmin holds every class ⇒ every one of the new privileges resolves in
        assert!(resolved("netadmin").all_privs);
    }

    #[test]
    fn gated_covers_the_dangerous_commands_only() {
        assert!(gated("kill") && gated("DIE") && gated("svsnick") && gated("CONNECT"));
        assert!(!gated("whois") && !gated("opermotd") && !gated("mkpasswd"));
    }

    // A config `opertype`/`class` extends or overrides the built-ins by id.
    #[test]
    fn config_class_and_type_parse() {
        let mut cd = ClassDef::default();
        apply_class_kv(&mut cd, "commands", "kill,gline");
        apply_class_kv(&mut cd, "snomasks", "kx");
        assert!(cd.commands.contains(&"KILL".to_string()) && cd.commands.contains(&"GLINE".to_string()));
        assert_eq!(cd.snomasks, "kx");

        let mut td = TypeDef::default();
        apply_type_kv(&mut td, "classes", "*");
        apply_type_kv(&mut td, "title", "Big_Boss");
        apply_type_kv(&mut td, "level", "99");
        assert!(td.all_classes);
        assert_eq!(td.title, "Big Boss");
        assert_eq!(td.level, Some(99));
    }
}
