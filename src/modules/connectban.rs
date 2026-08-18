//! connectban: z-line an IP range that opens too many connections. Each connection
//! bumps a per-range counter; at `connectban_threshold` the range is z-lined for
//! `connectban_duration` and the counter cleared. The tally is periodically wiped
//! (`connectban_gcinterval`) so long-lived counts don't accumulate. A
//! `connectban_bootwait` grace after start avoids banning the restart reconnect
//! storm. Off unless `connectban = yes`; all state in `Server.ext`.
//!
//! z-lines match by glob, not CIDR, so the banned range is emitted as a wildcard
//! mask (`1.2.3.*` for an IPv4 /24, the exact IP for a /32).

use crate::map::HashMap;
use std::net::IpAddr;

use crate::module::Module;
use crate::server::{now, Server};
use crate::xline::XKind;

/// Per-range connection tally plus the boot-grace / GC bookkeeping.
#[derive(Default)]
struct State {
    counts: HashMap<String, u32>,
    ignore_until: u64, // ignore connections until this unix time (boot grace)
    last_gc: u64,      // unix time of the last full clear
    booted: bool,      // whether ignore_until has been initialised
}

/// From an IP and the configured prefix length, return `(group_key, ban_glob)`.
/// The group key buckets connections; the glob is what gets z-lined. Non-8-bit
/// (v4) / non-16-bit (v6) prefixes are rounded down for the glob.
fn range_of(ip: IpAddr, v4cidr: u8, v6cidr: u8) -> (String, String) {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            // byte-granular: keep at least one octet, so a sub-/8 config can never
            // collapse the ban mask to "*" and z-line the entire network.
            let keep = (v4cidr / 8).clamp(1, 4) as usize;
            match keep {
                0 => ("v4:*".to_string(), "*".to_string()),
                4 => (format!("v4:{}", a), a.to_string()),
                k => {
                    let head = o[..k]
                        .iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(".");
                    (format!("v4:{head}"), format!("{head}.*"))
                }
            }
        }
        IpAddr::V6(a) => {
            let segs = a.segments();
            let keep = (v6cidr / 16).min(8) as usize;
            if keep >= 8 {
                (format!("v6:{}", a), a.to_string())
            } else {
                let head = segs[..keep]
                    .iter()
                    .map(|s| format!("{s:x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                let glob = if head.is_empty() {
                    "*".to_string()
                } else {
                    format!("{head}:*")
                };
                (format!("v6:{head}"), glob)
            }
        }
    }
}

/// Whether `ip` matches a configured `connectban_exempt` glob/CIDR (repeatable).
fn connectban_exempt(s: &Server, ip: IpAddr) -> bool {
    let ipstr = ip.to_string();
    s.conf_all("connectban_exempt")
        .iter()
        .any(|m| crate::modules::connclass::ip_matches(m, &ipstr))
}

/// Record a new connection from `ip`, z-lining its range if it crosses the limit.
/// No-op when connectban is disabled or still inside the boot-grace window.
pub fn on_connect(s: &mut Server, ip: IpAddr) {
    if !s.conf_bool("connectban", false) {
        return;
    }
    // never connect-ban loopback (local services, bridges, admin tooling all dial in
    // over 127.0.0.1 / ::1) or an admin-configured exempt range
    if ip.is_loopback() || connectban_exempt(s, ip) {
        return;
    }
    let threshold = s.conf_num("connectban_threshold", 10u32).max(2);
    let v4 = s.conf_num("connectban_ipv4cidr", 32u8).clamp(1, 32);
    let v6 = s.conf_num("connectban_ipv6cidr", 128u8).clamp(1, 128);
    let bootwait = s.conf_num("connectban_bootwait", 120u64);
    let n = now();

    let st = s.ext.get_or_insert_with::<State>(State::default);
    if !st.booted {
        st.ignore_until = n + bootwait;
        st.last_gc = n;
        st.booted = true;
    }
    if n < st.ignore_until {
        return;
    }

    let (key, glob) = range_of(ip, v4, v6);
    let c = st.counts.entry(key.clone()).or_insert(0);
    *c += 1;
    if *c < threshold {
        return;
    }
    st.counts.remove(&key);

    let dur = s.conf_num("connectban_duration", 6 * 60 * 60u64).max(1);
    let setter = format!("connectban@{}", s.name);
    let reason = s
        .conf("connectban_banmessage")
        .unwrap_or(
            "Your IP range has been attempting to connect too many times in too short a \
             duration. Wait a while, and you will be able to connect.",
        )
        .to_string();
    s.add_xline(XKind::Zline, &glob, dur, &setter, &reason);
    s.snotice_c('x', &format!(
        "Connect flooding from IP range {glob} (threshold {threshold})"
    ));
}

/// Periodically clears the whole tally.
pub struct ConnectBan;
impl Module for ConnectBan {
    fn name(&self) -> &'static str {
        "connectban"
    }
    fn on_tick(&mut self, s: &mut Server) {
        if !s.conf_bool("connectban", false) {
            return;
        }
        let gc = s.conf_num("connectban_gcinterval", 3600u64).max(1);
        let n = now();
        if let Some(st) = s.ext.get_mut::<State>() {
            if n.saturating_sub(st.last_gc) >= gc {
                st.counts.clear();
                st.last_gc = n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_ranges() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(range_of(ip, 32, 128).1, "1.2.3.4");
        assert_eq!(range_of(ip, 24, 128).1, "1.2.3.*");
        assert_eq!(range_of(ip, 16, 128).1, "1.2.*");
        assert_eq!(range_of(ip, 8, 128).1, "1.*");
        // same /24 buckets to one key
        let ip2: IpAddr = "1.2.3.9".parse().unwrap();
        assert_eq!(range_of(ip, 24, 128).0, range_of(ip2, 24, 128).0);
    }

    #[test]
    fn v6_ranges() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(range_of(ip, 32, 128).1, "2001:db8::1");
        assert_eq!(range_of(ip, 32, 32).1, "2001:db8:*");
    }
}
