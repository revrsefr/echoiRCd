//! connclass — connection classes. Each `connectclass` config line matches
//! connecting clients by IP glob (and optionally TLS), then applies per-class
//! policy: reject (deny), a per-IP connection cap, a password, usermodes on
//! connect, and overrides for max channels / ping frequency / registration
//! timeout. Config, one line per class (first token = name, rest key=value):
//!
//! ```text
//! connectclass = <name> allow=<ip glob> [deny=yes] [ssl=yes] [password=<pw>]
//!   [localmax=<n>] [maxchans=<n>] [pingfreq=<secs>] [timeout=<secs>] [modes=<+modes>]
//! ```
//!
//! The first class whose `allow` glob (and `ssl` if given) matches a client is
//! assigned at connect. With no class, the global limits apply. Matching is against
//! the IP (the host isn't resolved yet at connect).

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

#[derive(Default)]
pub struct ConnClass {
    pub name: String,
    pub allow: String,
    pub deny: bool,
    pub ssl: bool,
    pub password: Option<String>,
    pub localmax: Option<usize>,
    pub maxchans: Option<usize>,
    pub pingfreq: Option<u64>,
    pub timeout: Option<u64>,
    pub modes: Option<String>,
}

fn parse(line: &str) -> Option<ConnClass> {
    let mut it = line.split_whitespace();
    let mut c = ConnClass {
        name: it.next()?.to_string(),
        allow: "*".to_string(),
        ..Default::default()
    };
    for tok in it {
        let Some((k, v)) = tok.split_once('=') else {
            continue;
        };
        match k {
            "allow" => c.allow = v.to_string(),
            "deny" => c.deny = v.eq_ignore_ascii_case("yes"),
            "ssl" | "requiressl" => c.ssl = v.eq_ignore_ascii_case("yes"),
            "password" | "pass" => c.password = Some(v.to_string()),
            "localmax" => c.localmax = v.parse().ok(),
            "maxchans" => c.maxchans = v.parse().ok(),
            "pingfreq" => c.pingfreq = v.parse().ok(),
            "timeout" => c.timeout = v.parse().ok(),
            "modes" => c.modes = Some(v.to_string()),
            _ => {}
        }
    }
    Some(c)
}

pub fn all(s: &Server) -> Vec<ConnClass> {
    s.conf_all("connectclass")
        .iter()
        .filter_map(|l| parse(l))
        .collect()
}

pub fn named(s: &Server, name: &str) -> Option<ConnClass> {
    all(s).into_iter().find(|c| c.name == name)
}

/// Assign the connecting client to the first matching class. Returns `Some(reason)`
/// if the connection must be rejected (a deny class or a per-IP cap); otherwise sets
/// the class name on the user and returns `None`. Called from `add_conn`.
pub fn assign(s: &mut Server, uid: Uid) -> Option<String> {
    let (ip, secure) = {
        let u = s.users.get(&uid)?;
        (u.addr.ip().to_string(), u.secure)
    };
    let class = all(s)
        .into_iter()
        .find(|c| glob_match(&c.allow, &ip) && (!c.ssl || secure))?;
    if class.deny {
        return Some(format!("Connection class {} denies your address", class.name));
    }
    if let Some(max) = class.localmax {
        let n = s
            .users
            .values()
            .filter(|u| {
                u.addr.ip().to_string() == ip && u.class.as_deref() == Some(class.name.as_str())
            })
            .count();
        if n >= max {
            return Some("Too many connections from your address".to_string());
        }
    }
    if let Some(u) = s.users.get_mut(&uid) {
        u.class = Some(class.name);
    }
    None
}

/// At registration: verify the class password (if any) and apply the class's
/// on-connect usermodes. Returns `Some(reason)` to reject.
pub fn on_register(s: &mut Server, uid: Uid) -> Option<String> {
    let name = s.users.get(&uid)?.class.clone()?;
    let class = named(s, &name)?;
    if let Some(pw) = &class.password {
        let ok = s.users.get(&uid).and_then(|u| u.pass.clone());
        if ok.as_deref() != Some(pw.as_str()) {
            return Some("Password mismatch for your connection class".to_string());
        }
    }
    if let Some(m) = class.modes {
        crate::coremods::core_mode::svs_set_user_modes(s, uid, &m);
    }
    None
}

fn class_of(s: &Server, uid: Uid) -> Option<ConnClass> {
    let name = s.users.get(&uid).and_then(|u| u.class.clone())?;
    named(s, &name)
}

pub fn ping_freq(s: &Server, uid: Uid) -> Option<u64> {
    class_of(s, uid)?.pingfreq
}
pub fn reg_timeout(s: &Server, uid: Uid) -> Option<u64> {
    class_of(s, uid)?.timeout
}
pub fn max_chans(s: &Server, uid: Uid) -> Option<usize> {
    class_of(s, uid)?.maxchans
}
