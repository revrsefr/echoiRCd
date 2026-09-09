//! connclass — connection classes. Each `connectclass` config line matches
//! connecting clients by IP/host mask (CIDR or glob) and optional TLS/port, then
//! applies per-class policy: reject (deny), per-IP and per-class connection caps, a
//! password, on-connect usermodes, queue/flood limits, and overrides for max
//! channels / ping frequency / registration timeout. One line per class — the first
//! token is the name, the rest are `key=value`:
//!
//! ```text
//! connectclass = <name> allow=<mask[,mask]> [parent=<name>] [deny=yes]
//!   [requiressl=yes|trusted] [password=<pw>] [hash=<algo>] [port=<p[,p]>] [asn=<n[,n]>]
//!   [localmax=<n>] [globalmax=<n>] [limit=<n>] [maxchans=<n>] [pingfreq=<secs>]
//!   [timeout=<secs>] [modes=<+modes>] [recvq=<bytes>] [hardsendq=<bytes>]
//!   [softsendq=<bytes>] [fakelag=yes|no] [penaltythreshold=<n>] [commandrate=<secs>]
//!   [useident=yes] [requireident=yes] [resolvehostnames=no] [maxconnwarn=yes]
//! ```
//!
//! The first class whose masks (and TLS/port conditions) match a client is assigned.
//! Masks are tested against the IP at connect and re-tested against the resolved
//! host at registration, so host masks work once rDNS returns. With no class the
//! global limits apply; set `connectclass_required = yes` to refuse clients that
//! match no allow class.

use std::net::IpAddr;

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

#[derive(Default, Clone)]
pub struct ConnClass {
    pub name: String,
    pub allow: Vec<String>, // IP/host masks (glob or CIDR); any match = match
    pub deny: bool,         // deny class: matching clients are refused
    pub ssl: bool,          // require TLS
    pub ssl_trusted: bool,  // require a TLS client certificate (requiressl=trusted)
    pub password: Option<String>, // PASS credential (plain or hashed; verify auto-detects)
    pub ports: Vec<u16>,    // restrict to these listener ports (empty = any)
    pub asn: Vec<u32>,      // restrict to these origin AS numbers (empty = any)
    pub localmax: Option<usize>, // max local connections per IP in this class
    pub globalmax: Option<usize>, // max network-wide connections per IP
    pub limit: Option<usize>, // max total local users in this class
    pub maxchans: Option<usize>,
    pub pingfreq: Option<u64>,
    pub timeout: Option<u64>,            // registration timeout
    pub modes: Option<String>,           // usermodes set on connect
    pub recvq: Option<usize>,            // per-conn receive-queue byte cap
    pub hardsendq: Option<usize>,        // send-queue byte cap → disconnect
    pub softsendq: Option<usize>,        // send-queue byte cap → pause reading (backpressure)
    pub penaltythreshold: Option<usize>, // flood message cap override (see modules::flood)
    pub commandrate: Option<u64>,        // flood window override, seconds
    pub fakelag: bool,                   // apply flood limiting (default); false = kill on flood
    pub useident: bool,                  // do an ident (RFC1413) lookup for this class
    pub requireident: bool,              // refuse if the ident lookup fails
    pub resolvehostnames: bool,          // resolve rDNS for this class (default yes)
    pub maxconnwarn: bool,               // snotice opers when a limit refuses a client
    pub waitpongexempt: bool,            // skip the conn_waitpong cookie for this class
}

/// Split a `key=value` value on commas into non-empty pieces.
fn list(v: &str) -> impl Iterator<Item = &str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// Apply one `key=value` token to `c`.
fn apply(c: &mut ConnClass, k: &str, v: &str) {
    match k {
        "allow" => c.allow.extend(list(v).map(str::to_string)),
        "deny" => c.deny = v.eq_ignore_ascii_case("yes"),
        "ssl" | "requiressl" => {
            c.ssl = !v.eq_ignore_ascii_case("no") && !v.is_empty();
            c.ssl_trusted = v.eq_ignore_ascii_case("trusted");
        }
        "password" | "pass" => c.password = Some(v.to_string()),
        // `hash=` names the algorithm of a hashed password; it's folded into the
        // stored credential in build() *after* the whole token pass, so it works
        // regardless of whether it appears before or after `password=`.
        "hash" => {}
        "port" => c
            .ports
            .extend(list(v).filter_map(|p| p.parse::<u16>().ok())),
        "asn" => c.asn.extend(crate::modules::asn::parse_list(v)),
        "localmax" => c.localmax = v.parse().ok(),
        "globalmax" => c.globalmax = v.parse().ok(),
        "limit" => c.limit = v.parse().ok(),
        "maxchans" => c.maxchans = v.parse().ok(),
        "pingfreq" => c.pingfreq = v.parse().ok(),
        "timeout" => c.timeout = v.parse().ok(),
        "modes" => c.modes = Some(v.to_string()),
        "recvq" => c.recvq = v.parse().ok(),
        "hardsendq" => c.hardsendq = v.parse().ok(),
        "softsendq" => c.softsendq = v.parse().ok(),
        "penaltythreshold" => c.penaltythreshold = v.parse().ok(),
        "commandrate" => c.commandrate = v.parse().ok(),
        "fakelag" => c.fakelag = !v.eq_ignore_ascii_case("no"),
        "useident" => c.useident = v.eq_ignore_ascii_case("yes"),
        "requireident" => c.requireident = v.eq_ignore_ascii_case("yes"),
        "resolvehostnames" => c.resolvehostnames = !v.eq_ignore_ascii_case("no"),
        "maxconnwarn" => c.maxconnwarn = v.eq_ignore_ascii_case("yes"),
        "waitpongexempt" => c.waitpongexempt = v.eq_ignore_ascii_case("yes"),
        _ => {}
    }
}

/// The raw `connectclass` line whose first token is `name`.
fn raw_line(s: &Server, name: &str) -> Option<String> {
    s.conf_all("connectclass")
        .iter()
        .find(|l| l.split_whitespace().next() == Some(name))
        .map(|l| l.to_string())
}

/// The effective token list for `name` with `parent=` inheritance applied: a
/// parent's tokens come first (so the child overrides), minus the block-defining
/// `allow`/`deny`/`parent` keys, which stay class-local. Bounded against cycles.
fn tokens_for(s: &Server, name: &str, depth: u8) -> Option<Vec<String>> {
    let line = raw_line(s, name)?;
    let own: Vec<String> = line
        .split_whitespace()
        .skip(1)
        .map(str::to_string)
        .collect();
    let parent = own
        .iter()
        .find_map(|t| t.strip_prefix("parent="))
        .map(str::to_string);
    let mut merged = Vec::new();
    if let Some(p) = parent {
        if depth < 8 {
            if let Some(pt) = tokens_for(s, &p, depth + 1) {
                merged.extend(pt.into_iter().filter(|t| {
                    !t.starts_with("allow=") && !t.starts_with("deny=") && !t.starts_with("parent=")
                }));
            }
        }
    }
    merged.extend(own);
    Some(merged)
}

/// Build a resolved class (parent inheritance applied) from its config line.
fn build(s: &Server, name: &str) -> Option<ConnClass> {
    let toks = tokens_for(s, name, 0)?;
    let mut c = ConnClass {
        name: name.to_string(),
        fakelag: true,
        resolvehostnames: true,
        ..Default::default()
    };
    // resolve the hash algorithm independently of token order, taking the LAST `hash=`
    // (a child's overrides a parent's) to match `password=`'s last-wins semantics
    let hash_algo = toks
        .iter()
        .filter_map(|t| t.strip_prefix("hash="))
        .next_back()
        .map(str::to_string);
    for tok in &toks {
        if let Some((k, v)) = tok.split_once('=') {
            apply(&mut c, k, v);
        }
    }
    // fold `<algo>:<digest>` into the credential verify() auto-detects, unless the
    // password already carries its own prefix.
    if let (Some(algo), Some(pw)) = (hash_algo, c.password.take()) {
        c.password = Some(if pw.contains(':') {
            pw
        } else {
            format!("{algo}:{pw}")
        });
    }
    if c.allow.is_empty() {
        c.allow.push("*".to_string()); // an unqualified class matches everyone
    }
    Some(c)
}

thread_local! {
    /// (config_gen, resolved classes) — rebuilt only when the config changes. The
    /// core is single-threaded, so this thread_local cache lets the `&Server`
    /// entry points (pick/assign/named and the per-ping/per-message getters) avoid
    /// re-parsing + re-resolving parent inheritance on every call.
    static CLASSES: std::cell::RefCell<(u64, Vec<ConnClass>)> =
        const { std::cell::RefCell::new((u64::MAX, Vec::new())) };
}

/// Run `f` over the resolved connect classes, (re)building them only on config change.
fn with_classes<R>(s: &Server, f: impl FnOnce(&[ConnClass]) -> R) -> R {
    CLASSES.with(|cell| {
        if cell.borrow().0 != s.config_gen {
            let fresh: Vec<ConnClass> = s
                .conf_all("connectclass")
                .iter()
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|name| build(s, name))
                .collect();
            *cell.borrow_mut() = (s.config_gen, fresh);
        }
        let g = cell.borrow();
        f(&g.1)
    })
}

/// Every configured class, resolved.
pub fn all(s: &Server) -> Vec<ConnClass> {
    with_classes(s, <[ConnClass]>::to_vec)
}

/// A single resolved class by name.
pub fn named(s: &Server, name: &str) -> Option<ConnClass> {
    with_classes(s, |c| c.iter().find(|x| x.name == name).cloned())
}

// --- mask matching -----------------------------------------------------------

/// Whether the first `bits` bits of `a` and `b` are equal.
fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Whether `target` falls inside the CIDR `base`/`bits` (same family required).
fn cidr_contains(base: IpAddr, bits: u8, target: IpAddr) -> bool {
    match (base, target) {
        (IpAddr::V4(b), IpAddr::V4(t)) => prefix_eq(&b.octets(), &t.octets(), bits.min(32)),
        (IpAddr::V6(b), IpAddr::V6(t)) => prefix_eq(&b.octets(), &t.octets(), bits.min(128)),
        _ => false,
    }
}

/// Whether `ip` matches `mask`, where `mask` is a CIDR range or an IP glob. Shared
/// with the WebSocket `proxyranges` and PROXY-protocol trust checks so they accept
/// the same glob-or-CIDR syntax.
pub fn ip_matches(mask: &str, ip: &str) -> bool {
    mask_match(mask, ip, "")
}

/// Match one mask against a client's IP and (once known) resolved host. A mask with
/// a `/` is a CIDR range tested against the IP; otherwise it's a glob tested against
/// both the IP text and the host.
fn mask_match(mask: &str, ip: &str, host: &str) -> bool {
    if let Some((net, bits)) = mask.split_once('/') {
        if let (Ok(base), Ok(bits), Ok(target)) = (
            net.parse::<IpAddr>(),
            bits.parse::<u8>(),
            ip.parse::<IpAddr>(),
        ) {
            return cidr_contains(base, bits, target);
        }
        return false;
    }
    glob_match(mask, ip) || (!host.is_empty() && glob_match(mask, host))
}

// --- class selection ---------------------------------------------------------

enum Pick {
    Class(ConnClass),
    Deny(String),
    None,
}

/// Choose the first suitable class for a client. Suitability = a matching mask plus
/// any TLS/port/limit conditions; an unsuitable class is skipped, a matching deny
/// class rejects. `host` is empty at connect (pre-rDNS) and the resolved name later.
fn pick(
    s: &Server,
    uid: Uid,
    ip: &str,
    host: &str,
    secure: bool,
    has_cert: bool,
    port: u16,
    asn: Option<u32>,
) -> Pick {
    for c in all(s) {
        if !c.allow.iter().any(|m| mask_match(m, ip, host)) {
            continue;
        }
        if c.ssl && !secure {
            continue;
        }
        if c.ssl_trusted && !has_cert {
            continue;
        }
        if !c.ports.is_empty() && !c.ports.contains(&port) {
            continue;
        }
        if !c.asn.is_empty() && !asn.is_some_and(|a| c.asn.contains(&a)) {
            continue;
        }
        if c.deny {
            return Pick::Deny(c.name);
        }
        if let Some(max) = c.limit {
            if class_count(s, &c.name, uid) >= max {
                if c.maxconnwarn {
                    let max_s = max.to_string();
                    let m = s.trf(
                        "connect class {0} is full ({1})",
                        &[c.name.as_str(), max_s.as_str()],
                    );
                    s.snotice_c('c', &m);
                }
                continue; // full — try the next class
            }
        }
        return Pick::Class(c);
    }
    Pick::None
}

/// Local users currently in class `name` (excluding `uid`).
fn class_count(s: &Server, name: &str, uid: Uid) -> usize {
    s.users
        .iter()
        .filter(|(&k, u)| k != uid && u.class.as_deref() == Some(name))
        .count()
}

/// Local connections from `ip` in class `name` (excluding `uid`).
fn local_clones(s: &Server, ip: &str, name: &str, uid: Uid) -> usize {
    s.users
        .iter()
        .filter(|(&k, u)| {
            k != uid && u.addr.ip().to_string() == ip && u.class.as_deref() == Some(name)
        })
        .count()
}

/// Connections from `ip` across the whole network (local + remote), excluding `uid`.
fn global_clones(s: &Server, ip: &str, uid: Uid) -> usize {
    let local = s
        .users
        .iter()
        .filter(|(&k, u)| k != uid && u.addr.ip().to_string() == ip)
        .count();
    let remote = s.remote_users.values().filter(|ru| ru.ip == ip).count();
    local + remote
}

/// Assign the connecting client to the first matching class. Returns `Some(reason)`
/// if the connection must be rejected (a deny class or a per-IP/per-class cap);
/// otherwise sets the class on the user and returns `None`. Called from `add_conn`.
pub fn assign(s: &mut Server, uid: Uid) -> Option<String> {
    let (ip, secure, has_cert, port) = {
        let u = s.users.get(&uid)?;
        (
            u.addr.ip().to_string(),
            u.secure,
            u.certfp.is_some(),
            u.port,
        )
    };
    let asn = crate::modules::asn::of(s, uid);
    let class = match pick(s, uid, &ip, "", secure, has_cert, port, asn) {
        Pick::Deny(name) => {
            return Some(format!("Connection class {name} denies your address"));
        }
        Pick::None => {
            if !all(s).iter().any(|c| !c.deny) || !s.conf_bool("connectclass_required", false) {
                return None; // no allow classes, or strict mode off: allow, no class
            }
            return Some("You are not allowed to connect to this server".to_string());
        }
        Pick::Class(c) => c,
    };
    let warn = |s: &Server, why: &str| {
        if class.maxconnwarn {
            let m = s.trf(
                "connect class {0} refused {1}: {2}",
                &[class.name.as_str(), ip.as_str(), why],
            );
            s.snotice_c('c', &m);
        }
    };
    if let Some(max) = class.localmax {
        if local_clones(s, &ip, &class.name, uid) >= max {
            warn(s, "local clone limit");
            return Some("Too many connections from your address".to_string());
        }
    }
    if let Some(max) = class.globalmax {
        if global_clones(s, &ip, uid) >= max {
            warn(s, "global clone limit");
            return Some("Too many global connections from your address".to_string());
        }
    }
    if let Some(u) = s.users.get_mut(&uid) {
        u.class = Some(class.name);
    }
    None
}

/// Outcome of the connect-class check run at registration.
pub enum AuthOutcome {
    /// All checks passed and on-connect modes applied; the caller should welcome.
    Proceed,
    /// Refuse the connection with this reason.
    Reject(String),
    /// A slow (KDF) class password is being verified off the core thread; hold
    /// registration until the resulting `Event::ConnclassAuth` lands.
    Pending,
}

/// At registration: re-pick the class now the host is resolved (host masks), enforce a
/// required client cert, verify the class password, and apply on-connect modes. A KDF
/// password is verified off the core thread ([`AuthOutcome::Pending`]).
pub fn on_register(s: &mut Server, uid: Uid) -> AuthOutcome {
    let Some((ip, host, secure, has_cert, port, sent)) = s.users.get(&uid).map(|u| {
        (
            u.addr.ip().to_string(),
            u.host.clone(),
            u.secure,
            u.certfp.is_some(),
            u.port,
            u.pass.clone(),
        )
    }) else {
        return AuthOutcome::Proceed;
    };
    let asn = crate::modules::asn::of(s, uid);
    match pick(s, uid, &ip, &host, secure, has_cert, port, asn) {
        Pick::Deny(name) => {
            return AuthOutcome::Reject(format!("Connection class {name} denies your address"));
        }
        Pick::Class(c) => {
            if let Some(u) = s.users.get_mut(&uid) {
                u.class = Some(c.name);
            }
        }
        Pick::None => {} // keep whatever was assigned at connect
    }
    let Some(class) = s
        .users
        .get(&uid)
        .and_then(|u| u.class.clone())
        .and_then(|n| named(s, &n))
    else {
        return AuthOutcome::Proceed;
    };
    // enforce per-IP clone caps here too: a class matched only by a host mask isn't
    // picked at connect, so `assign` never got to check them
    if let Some(max) = class.localmax {
        if local_clones(s, &ip, &class.name, uid) >= max {
            return AuthOutcome::Reject("Too many connections from your address".into());
        }
    }
    if let Some(max) = class.globalmax {
        if global_clones(s, &ip, uid) >= max {
            return AuthOutcome::Reject("Too many connections from your address".into());
        }
    }
    // cheap cert check before the (possibly slow) password verify
    if class.ssl_trusted && !has_cert {
        return AuthOutcome::Reject("Your connection class requires a client certificate".into());
    }
    if let Some(pw) = class.password.clone() {
        // a KDF class password is slow — verify it off the core thread and hold
        // registration, so connect floods to a password-protected class can't freeze us.
        if crate::modules::password_hash::is_slow(&pw) {
            let started = s.spawn_crypto(move || {
                let ok = sent
                    .as_deref()
                    .map(|p| crate::modules::password_hash::verify(&pw, p))
                    .unwrap_or(false);
                crate::ircd::Event::ConnclassAuth { uid, ok }
            });
            if !started {
                return AuthOutcome::Reject("Server busy, try again".into());
            }
            if let Some(u) = s.users.get_mut(&uid) {
                u.auth_pending = true;
            }
            return AuthOutcome::Pending;
        }
        let ok = sent
            .as_deref()
            .map(|p| crate::modules::password_hash::verify(&pw, p))
            .unwrap_or(false);
        if !ok {
            return AuthOutcome::Reject("Password mismatch for your connection class".into());
        }
    }
    finish_register(s, uid);
    AuthOutcome::Proceed
}

/// Apply the assigned class's on-connect user modes. Runs after the password check
/// (inline, or from the `ConnclassAuth` handler once an off-core verify succeeds).
pub fn finish_register(s: &mut Server, uid: Uid) {
    let modes = s
        .users
        .get(&uid)
        .and_then(|u| u.class.clone())
        .and_then(|n| named(s, &n))
        .and_then(|c| c.modes);
    if let Some(m) = modes {
        crate::coremods::core_mode::svs_set_user_modes(s, uid, &m);
    }
}

// --- per-class getters consulted by the core / other modules -----------------

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
pub fn recvq(s: &Server, uid: Uid) -> Option<usize> {
    class_of(s, uid)?.recvq
}
pub fn hardsendq(s: &Server, uid: Uid) -> Option<usize> {
    class_of(s, uid)?.hardsendq
}
pub fn softsendq(s: &Server, uid: Uid) -> Option<usize> {
    class_of(s, uid)?.softsendq
}
/// Per-class flood override: `(message cap, window secs, fakelag)`. `fakelag=false`
/// means flooders are killed rather than rate-limited.
pub fn flood_over(s: &Server, uid: Uid) -> Option<(Option<usize>, Option<u64>, bool)> {
    let c = class_of(s, uid)?;
    Some((c.penaltythreshold, c.commandrate, c.fakelag))
}
/// Whether reverse-DNS should be resolved for this client's class (default yes).
pub fn resolve_hostnames(s: &Server, uid: Uid) -> bool {
    class_of(s, uid).map(|c| c.resolvehostnames).unwrap_or(true)
}
/// Whether this client's class opts out of the conn_waitpong cookie.
pub fn waitpong_exempt(s: &Server, uid: Uid) -> bool {
    class_of(s, uid).map(|c| c.waitpongexempt).unwrap_or(false)
}
/// `(useident, requireident)` for this client's class.
pub fn ident_policy(s: &Server, uid: Uid) -> (bool, bool) {
    class_of(s, uid)
        .map(|c| (c.useident, c.requireident))
        .unwrap_or((false, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn cidr_v4_ranges() {
        let base = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        assert!(cidr_contains(base, 8, "10.9.9.9".parse().unwrap()));
        assert!(!cidr_contains(base, 8, "11.0.0.1".parse().unwrap()));
        let net = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0));
        assert!(cidr_contains(net, 24, "192.168.1.200".parse().unwrap()));
        assert!(!cidr_contains(net, 24, "192.168.2.1".parse().unwrap()));
        // a /32 is an exact host
        let host = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert!(cidr_contains(host, 32, "203.0.113.5".parse().unwrap()));
        assert!(!cidr_contains(host, 32, "203.0.113.6".parse().unwrap()));
    }

    #[test]
    fn mask_glob_and_cidr() {
        assert!(mask_match("10.0.0.0/8", "10.1.2.3", ""));
        assert!(!mask_match("10.0.0.0/8", "192.0.2.1", ""));
        assert!(mask_match("*.example.com", "192.0.2.1", "host.example.com"));
        assert!(mask_match("192.0.2.*", "192.0.2.7", ""));
        assert!(!mask_match("nomatch/33", "1.2.3.4", "")); // unparseable → no match
    }

    #[test]
    fn asn_param_parses() {
        let mut c = ConnClass::default();
        apply(&mut c, "asn", "3215,15169");
        apply(&mut c, "asn", "AS16276");
        assert_eq!(c.asn, vec![3215, 15169, 16276]);
    }
}
