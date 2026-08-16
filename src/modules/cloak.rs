//! cloak: keyed host masking under user mode +x, auto-set on connect (only opers
//! may drop it). Config key `cloak_key`; with no key set, cloaking is off and +x
//! is a no-op.
//!
//! A cloak hides the real IP while preserving subnet structure, so a channel ban
//! on a /24 or /16 still matches. IPv4 `a.b.c.d` becomes one keyed segment per
//! octet-prefix tier, most-specific first, with a literal `.IP` suffix marking a
//! cloaked address (a cloaked hostname keeps its domain instead):
//!
//! ```text
//!   HASH(a.b.c.d) . HASH(a.b.c) . HASH(a.b) . HASH(a) . IP
//!      (/32)          (/24)        (/16)       (/8)
//! ```
//!
//! Two IPs in the same /24 share the `…/24./16./8.IP` tail; the exact address
//! never appears. The hash is SHA-256 (via the openssl already linked for TLS).

use openssl::sha::sha256;

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

/// The suffix marking a cloaked IP address.
const IP_SUFFIX: &str = ".IP";

pub struct Cloak;

impl Module for Cloak {
    fn name(&self) -> &'static str {
        "cloak"
    }

    /// Compute the cloak once, at connect, and cloak the user by default (+x).
    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        let Some(cloak) = compute_cloak(srv, uid) else {
            return; // cloaking disabled / no method produced a result
        };
        if let Some(u) = srv.users.get_mut(&uid) {
            u.cloak = cloak;
            u.flags.cloak = true; // cloaked by default; -x is oper-only
        }
    }
}

/// Compute a user's cloak from the ordered `cloak_method` config (first that
/// applies wins); with none configured, the keyed host cloak. Methods:
///   account       `<cloak_account_prefix>/<account>` for logged-in users
///   fingerprint   `<cloak_cert_prefix>/<hash>` for TLS clients with a cert
///   static        the fixed `cloak_static_host`
///   hmac-sha256   the keyed, subnet-preserving host cloak (the default)
/// A method that doesn't apply (e.g. `account` for a user who isn't logged in)
/// falls through to the next; the keyed host cloak is the final fallback.
pub fn compute_cloak(srv: &Server, uid: Uid) -> Option<String> {
    let u = srv.users.get(&uid)?;
    let configured = srv.conf_all("cloak_method");
    let methods: Vec<&str> = if configured.is_empty() {
        vec!["hmac-sha256"]
    } else {
        configured.iter().map(|s| s.as_str()).collect()
    };
    for m in methods {
        match m {
            "account" => {
                if let Some(acct) = &u.account {
                    let prefix = srv.conf("cloak_account_prefix").unwrap_or("account");
                    return Some(format!("{prefix}/{}", sanitize_label(acct)));
                }
            }
            "fingerprint" | "certfp" => {
                if let (Some(key), Some(fp)) = (srv.cloak_key.as_deref(), u.certfp.as_deref()) {
                    let prefix = srv.conf("cloak_cert_prefix").unwrap_or("cert");
                    return Some(format!("{prefix}/{}", label(key, fp, 10)));
                }
            }
            "static" => {
                if let Some(h) = srv.conf("cloak_static_host").filter(|h| !h.is_empty()) {
                    return Some(h.to_string());
                }
            }
            _ => {
                let key = srv.cloak_key.as_deref()?;
                return Some(cloak_host(key, &u.host));
            }
        }
    }
    // configured methods all fell through (e.g. account-only, not logged in)
    let key = srv.cloak_key.as_deref()?;
    Some(cloak_host(key, &u.host))
}

/// Turn a value into a host-safe label: letters/digits/`-`/`.` kept, else `-`.
fn sanitize_label(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect();
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// One cloak label: the first `n` hex chars of `SHA-256(key ‖ NUL ‖ data)`.
fn label(key: &str, data: &str, n: usize) -> String {
    let digest = sha256(format!("{key}\u{0}{data}").as_bytes());
    let mut s = String::with_capacity(n + 1);
    for b in &digest {
        s.push_str(&format!("{b:02x}"));
        if s.len() >= n {
            break;
        }
    }
    s.truncate(n);
    s
}

/// Parse `"a.b.c.d"` into four octets, or `None` if it isn't a dotted IPv4.
fn parse_v4(host: &str) -> Option<(u8, u8, u8, u8)> {
    let mut it = host.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((a, b, c, d))
}

/// Compute a user's cloak from their real host.
///
/// - IPv4 `a.b.c.d` → `H(a.b.c.d).H(a.b.c).H(a.b).H(a).IP` — one keyed segment per
///   octet-prefix tier (/32 · /24 · /16 · /8), so subnet bans keep working while
///   the exact address never appears.
/// - IPv6 → `ALPHA.BETA.GAMMA.IP`, coarsened by hextet groups.
/// - hostname → keep the last two labels (the domain), mask everything to the left
///   (no `.IP` — a resolved name isn't a raw address).
pub fn cloak_host(key: &str, host: &str) -> String {
    if let Some((a, b, c, d)) = parse_v4(host) {
        let h32 = label(key, &format!("{a}.{b}.{c}.{d}"), 6);
        let h24 = label(key, &format!("{a}.{b}.{c}"), 5);
        let h16 = label(key, &format!("{a}.{b}"), 4);
        let h8 = label(key, &format!("{a}"), 4);
        format!("{h32}.{h24}.{h16}.{h8}{IP_SUFFIX}")
    } else if host.contains(':') {
        let groups: Vec<&str> = host.split(':').filter(|g| !g.is_empty()).collect();
        let mid = groups.iter().take(4).copied().collect::<Vec<_>>().join(":");
        let wide = groups.iter().take(2).copied().collect::<Vec<_>>().join(":");
        let alpha = label(key, host, 6);
        let beta = label(key, &mid, 5);
        let gamma = label(key, &wide, 4);
        format!("{alpha}.{beta}.{gamma}{IP_SUFFIX}")
    } else {
        let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
        // reveal the registered domain suffix only for a real hostname (its TLD has a
        // letter); a numeric dotted string that slipped past the IP parsers is fully
        // cloaked so no octets leak in cleartext
        let real_host = parts
            .last()
            .is_some_and(|t| t.bytes().any(|b| b.is_ascii_alphabetic()));
        if parts.len() >= 3 && real_host {
            let suffix = parts[parts.len() - 2..].join(".");
            format!("{}.{suffix}", label(key, host, 8))
        } else {
            format!("{}.cloak", label(key, host, 8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_label_is_host_safe() {
        assert_eq!(sanitize_label("Reverse"), "Reverse");
        assert_eq!(sanitize_label("a b!c@d"), "a-b-c-d");
        assert_eq!(sanitize_label("na.me-1"), "na.me-1");
        assert_eq!(sanitize_label(""), "unknown");
    }

    #[test]
    fn v4_cloak_is_deterministic_and_hides_the_ip() {
        let c = cloak_host("secret", "203.0.113.7");
        assert_eq!(c, cloak_host("secret", "203.0.113.7")); // stable
        assert!(!c.contains("203.0.113")); // the dotted IP never appears
        assert!(c.ends_with(".IP")); // IP suffix
        assert_eq!(c.split('.').count(), 5); // H32.H24.H16.H8.IP
    }

    #[test]
    fn same_subnet_shares_a_suffix_but_host_differs() {
        let a = cloak_host("secret", "203.0.113.7");
        let b = cloak_host("secret", "203.0.113.9"); // same /24
        let e = cloak_host("secret", "8.8.8.8"); // different net
        let tail = |s: &str| s.split_once('.').unwrap().1.to_string();
        assert_eq!(tail(&a), tail(&b)); // /24 ban still matches both
        assert_ne!(a, b); // but the exact host label differs
        assert_ne!(tail(&a), tail(&e)); // unrelated net -> unrelated tail
    }

    #[test]
    fn wider_ban_matches_the_whole_16() {
        // two different /24s inside the same /16 share only the /16./8.IP tail
        let a = cloak_host("secret", "203.0.113.7");
        let b = cloak_host("secret", "203.0.200.4");
        let net16_tail = |s: &str| s.splitn(3, '.').nth(2).unwrap().to_string();
        assert_eq!(net16_tail(&a), net16_tail(&b)); // H16.H8.IP shared
        assert_ne!(a.split_once('.').unwrap().1, b.split_once('.').unwrap().1); // /24 differs
    }

    #[test]
    fn the_key_changes_the_cloak() {
        assert_ne!(
            cloak_host("key-one", "203.0.113.7"),
            cloak_host("key-two", "203.0.113.7"),
        );
    }

    #[test]
    fn hostname_keeps_its_domain_and_has_no_ip_suffix() {
        let c = cloak_host("secret", "host.dyn.example.com");
        assert!(c.ends_with(".example.com"));
        assert!(!c.ends_with(".IP"));
        assert!(!c.starts_with("host"));
    }
}
