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

/// Per-user resolved grant, stored on `User.ext` at oper-up. Present ⇒ a typed
/// oper; absent ⇒ a legacy oper with full access. Read by WHOIS for the title.
pub struct OperType {
    pub title: String,
    pub color: Option<u8>, // mIRC colour for the WHOIS title line (None = plain)
    pub all_commands: bool,
    pub commands: HashSet<String>,
    pub all_privs: bool,
    pub privs: HashSet<String>,
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
            Some(t) => (t.all_commands || t.commands.contains(&up), t.title.clone()),
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

/// Apply the oper's type at oper-up: auto usermodes / snomasks / vhost / level, then
/// store the grant + title. A missing type (or an unknown id) leaves the oper with
/// full access, so `oper` blocks without `type=` keep working.
pub fn apply(s: &mut Server, uid: Uid, type_id: Option<&str>) {
    let Some(id) = type_id.map(|t| t.to_ascii_lowercase()) else {
        return;
    };
    let Some(r) = with_resolved(s, |m| m.get(&id).cloned()) else {
        s.snotice_c('o', &format!("oper type '{id}' is not defined — granting full access"));
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
    modes: String,
    snomasks: Option<String>, // Some(letters) auto-set; None = keep the oper-up default
    all_snomasks: bool,
    vhost: Option<String>,
    level: Option<u32>,
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
    all_snomasks: bool,
    snomasks: String,
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
    modes: String,
    all_snomasks: bool,
    snomasks: String,
    vhost: Option<String>,
    level: Option<u32>,
    color: Option<u8>,
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
    classes.insert("override".into(), cdef(&["SAJOIN", "SAPART", "SANICK", "SAKICK", "SAMODE", "SATOPIC", "SAQUIT", "CLEARCHAN"], &["override"], "v"));
    classes.insert("host".into(), cdef(&["CHGHOST", "CHGIDENT", "CHGNAME", "SETHOST", "SETIDENT", "SETIDLE", "SWHOIS"], &[], ""));
    classes.insert("services".into(), cdef(&["SVSNICK", "SVSJOIN", "SVSPART", "SVSMODE", "SVSLOGIN", "SVSLOGOUT"], &[], ""));
    classes.insert("server".into(), cdef(&["CONNECT", "SQUIT", "DIE", "RESTART"], &[], "lr"));

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

fn apply_class_kv(cd: &mut ClassDef, k: &str, v: &str) {
    match k {
        "commands" | "cmds" => {
            if v == "*" {
                cd.all_commands = true;
            } else {
                cd.commands.extend(v.split(',').filter(|x| !x.is_empty()).map(|x| x.to_ascii_uppercase()));
            }
        }
        "privs" => {
            if v == "*" {
                cd.all_privs = true;
            } else {
                cd.privs.extend(v.split(',').filter(|x| !x.is_empty()).map(|x| x.to_ascii_lowercase()));
            }
        }
        "snomasks" | "snomask" => {
            if v.contains('*') {
                cd.all_snomasks = true;
            } else {
                cd.snomasks.push_str(v);
            }
        }
        _ => {} // usermodes/chanmodes allowlist: accepted but not yet enforced
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
            if v == "*" {
                td.all_commands = true;
            } else {
                td.commands.extend(v.split(',').filter(|x| !x.is_empty()).map(|x| x.to_ascii_uppercase()));
            }
        }
        "privs" => {
            if v == "*" {
                td.all_privs = true;
            } else {
                td.privs.extend(v.split(',').filter(|x| !x.is_empty()).map(|x| x.to_ascii_lowercase()));
            }
        }
        "modes" | "usermodes" => td.modes = v.to_string(),
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
    let mut all_sno = td.all_snomasks;
    let mut sno = td.snomasks.clone();

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
            all_sno |= cd.all_snomasks;
            sno.push_str(&cd.snomasks);
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
        modes: td.modes.clone(),
        snomasks,
        all_snomasks: all_sno,
        vhost: td.vhost.clone(),
        level: td.level,
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
        assert!(admin.privs.contains("override"));
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
