//! DNSBL: DNS blocklist checks on connect. The resolver thread reverses the
//! client's IP under each configured blocklist zone and A-looks it up (see
//! [`crate::resolver`]); a listing triggers the configured action. Works for IPv4
//! (reversed octets) and IPv6 (reversed nibbles); a v4-only blocklist NXDOMAINs a
//! v6 query, which reads as "not listed".
//!
//! Actions (`dnsbl_action`): `mark` shows the notice and lets them in (default),
//! `kill` disconnects, `kline`/`gline`/`zline` add a 1-day ban and disconnect.
//! Driven from the connection lifecycle (`Server::add_conn` → `on_resolved`)
//! rather than as a hook `Module`.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::resolver;
use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

/// One configured DNS blocklist. The resolver worker only needs `domain` (the zone
/// it reverses the client IP under); the rest shape what happens on a hit and are
/// looked up on the core thread. Unset per-zone fields fall back to the global
/// `dnsbl_action` / `dnsbl_reason` / `dnsbl_duration`.
#[derive(Clone, Debug)]
pub struct DnsblZone {
    pub domain: String,         // DNS zone queried (e.g. torexit.dan.me.uk)
    pub name: String,           // friendly label shown in the hit notice
    pub action: Option<String>, // per-zone action override (mark/kill/kline/gline/zline)
    pub duration: Option<u64>,  // per-zone ban duration override (seconds)
    pub reason: Option<String>, // per-zone ban reason (supports %ip%)
}

/// Parse one `dnsbl = …` config value. Two forms:
///   * bare zone — `dnsbl = torexit.dan.me.uk` (uses the global action/reason)
///   * attributes — `dnsbl = domain=torexit.dan.me.uk name="Tor exit node"
///     action=zline duration=1w reason="… %ip% …"` (values may be "quoted")
pub fn parse_zone(value: &str) -> Option<DnsblZone> {
    let value = value.trim();
    let first = value.split_whitespace().next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    if !first.contains('=') {
        let domain = first.trim_end_matches('.').to_string();
        return Some(DnsblZone { name: domain.clone(), domain, action: None, duration: None, reason: None });
    }
    let attrs = parse_kv(value);
    let get = |k: &str| attrs.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    let domain = get("domain")?.trim_end_matches('.').to_string();
    if domain.is_empty() {
        return None;
    }
    Some(DnsblZone {
        action: get("action").map(|a| a.to_ascii_lowercase()),
        duration: get("duration").and_then(|d| crate::xline::parse_duration(&d)),
        reason: get("reason"),
        name: get("name").unwrap_or_else(|| domain.clone()),
        domain,
    })
}

/// Tokenise `key=value` attributes, honouring `"double quotes"` so a value may
/// contain spaces (a reason string, a URL).
fn parse_kv(s: &str) -> Vec<(String, String)> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_whitespace() {
            i += 1;
        }
        let ks = i;
        while i < b.len() && b[i] != '=' && !b[i].is_whitespace() {
            i += 1;
        }
        let key: String = b[ks..i].iter().collect();
        if i < b.len() && b[i] == '=' {
            i += 1;
            let val = if i < b.len() && b[i] == '"' {
                i += 1;
                let vs = i;
                while i < b.len() && b[i] != '"' {
                    i += 1;
                }
                let v: String = b[vs..i].iter().collect();
                i += 1; // skip the closing quote (or the end)
                v
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_whitespace() {
                    i += 1;
                }
                b[vs..i].iter().collect()
            };
            if !key.is_empty() {
                out.push((key.to_ascii_lowercase(), val));
            }
        }
    }
    out
}

/// Ban length applied by the `*line` actions on a hit.
const DNSBL_BAN: u64 = 86_400; // default ban length (1 day) if `dnsbl_duration` unset

/// Outcome of a DNSBL check for one connecting client.
pub enum Outcome {
    /// No blocklists configured — the check didn't run.
    Skipped,
    /// Checked against every zone; the address is not listed.
    Clean,
    /// Listed: `zone` returned `reply` (`127.0.0.x`, last octet = reason code).
    Hit { zone: String, reply: Ipv4Addr },
}

/// Most blocklist zones consulted per connecting client (latency bound).
const MAX_ZONES: usize = 16;

/// Check `ip` against every blocklist `zone`; the first listing wins. Runs off the
/// core thread (called from the resolver worker), so it may block on DNS.
pub fn check(ip: IpAddr, zones: &[String], timeout: Duration) -> Outcome {
    if zones.is_empty() {
        return Outcome::Skipped;
    }
    // Each zone is a serial blocking lookup, so total latency is bounded by the
    // number checked × timeout; cap it so a long (mis)configured zone list can't
    // stall a client's registration for a very long time.
    for zone in zones.iter().take(MAX_ZONES) {
        let z = zone.trim().trim_end_matches('.');
        let qname = format!("{}.{z}", resolver::reverse_labels(ip));
        if let Some(reply) = resolver::a_lookup(&qname, timeout) {
            return Outcome::Hit {
                zone: zone.clone(),
                reply,
            };
        }
    }
    Outcome::Clean
}

/// Emit the DNSBL notices for `outcome` and, on a hit, take the configured action.
/// Called from `Server::on_resolved` on the core thread.
pub fn report(s: &mut Server, uid: Uid, outcome: Outcome) {
    match outcome {
        Outcome::Skipped => {}
        Outcome::Clean => {
            s.notice_star(uid, "Checking for DNSBL");
            s.notice_star(uid, "Checking for DNSBL done, no hit.");
        }
        Outcome::Hit { zone, reply: _ } => {
            s.notice_star(uid, "Checking for DNSBL");
            s.notice_star(uid, "Checking for DNSBL done.");
            act(s, uid, &zone);
        }
    }
}

/// Act on a hit against blocklist `domain` per its (or the global) action: `mark`
/// just informs; the `*line` actions add a ban and close; `kill` closes without a
/// persistent ban. Emits the XLINE notice (via `add_xline`) then the DNSBL one.
fn act(s: &mut Server, uid: Uid, domain: &str) {
    let (mask, ip) = match s.users.get(&uid) {
        Some(u) => (u.prefix(), u.addr.ip()),
        None => return,
    };
    let ipstr = ip.to_string();
    // Resolve this hit's per-zone settings, each falling back to the global default.
    let zone = s
        .dnsbl_zones
        .iter()
        .find(|z| z.domain.eq_ignore_ascii_case(domain))
        .cloned();
    let name = zone.as_ref().map(|z| z.name.clone()).unwrap_or_else(|| domain.to_string());
    let action = zone
        .as_ref()
        .and_then(|z| z.action.clone())
        .unwrap_or_else(|| s.dnsbl_action.clone());
    let dur = zone
        .as_ref()
        .and_then(|z| z.duration)
        .unwrap_or_else(|| s.conf_num("dnsbl_duration", DNSBL_BAN));
    let reason_tmpl = zone
        .as_ref()
        .and_then(|z| z.reason.clone())
        .unwrap_or_else(|| s.dnsbl_reason.clone());
    // Reason templating: %ip% → the client IP, %dnsbl% → the zone domain.
    let reason = reason_tmpl.replace("%ip%", &ipstr).replace("%dnsbl%", domain);
    let setter = format!("dnsbl@{}", s.name);
    // Apply the action first so the XLINE notice precedes the DNSBL one, matching
    // how an operator watching both snomasks sees a blocklist ban land.
    let closes = match action.as_str() {
        "kline" => {
            s.add_xline(XKind::Kline, &format!("*@{ipstr}"), dur, &setter, &reason);
            true
        }
        "gline" => {
            s.add_xline(XKind::Gline, &format!("*@{ipstr}"), dur, &setter, &reason);
            true
        }
        "zline" => {
            s.add_xline(XKind::Zline, &ipstr, dur, &setter, &reason);
            true
        }
        "kill" | "reject" => true,
        _ => false, // "mark" or unknown: notify only, let them in
    };
    s.snotice_c('d', &format!(
        "DNSBL: Connecting user {mask} ({ipstr}) detected as being on the '{domain}' DNSBL: {name}"
    ));
    if closes {
        // pre-registration users aren't caught by add_xline's enforce sweep, so close
        // this connection explicitly (the ERROR flushes before the socket).
        let m = s.trf("Closing link: ({0})", &[reason.as_str()]);
        s.send(uid, format!("ERROR :{m}"));
        s.remove_user(uid, &reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zone_bare_domain() {
        let z = parse_zone("torexit.dan.me.uk.").unwrap();
        assert_eq!(z.domain, "torexit.dan.me.uk"); // trailing dot trimmed
        assert_eq!(z.name, "torexit.dan.me.uk"); // name defaults to the domain
        assert!(z.action.is_none() && z.duration.is_none() && z.reason.is_none());
        assert!(parse_zone("   ").is_none());
    }

    #[test]
    fn parse_zone_with_quoted_attrs() {
        let z = parse_zone(
            "domain=torexit.dan.me.uk name=\"Tor exit node\" action=ZLINE duration=1w \
             reason=\"Not allowed. See https://x/%ip% here\"",
        )
        .unwrap();
        assert_eq!(z.domain, "torexit.dan.me.uk");
        assert_eq!(z.name, "Tor exit node");
        assert_eq!(z.action.as_deref(), Some("zline")); // lower-cased
        assert_eq!(z.duration, Some(604800)); // 1w
        assert_eq!(z.reason.as_deref(), Some("Not allowed. See https://x/%ip% here"));
        // attrs missing a domain are rejected
        assert!(parse_zone("name=\"no domain\" action=zline").is_none());
    }
}
