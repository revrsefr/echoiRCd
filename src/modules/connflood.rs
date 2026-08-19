//! connflood: refuse connections from an IP opening too many too fast. Config:
//! `connflood = <max> <secs>`. Per-IP recent-connect times live in `Server.ext`,
//! pruned on the tick.

use crate::map::HashMap;
use std::net::IpAddr;

use crate::module::Module;
use crate::server::{now, Server};

/// per-IP recent connection timestamps. Stored in `Server.ext`.
#[derive(Default)]
pub struct ConnHistory(pub HashMap<IpAddr, Vec<u64>>);

/// `(max, secs)` from `connflood = <max> <secs>`, or `None` when disabled.
fn cfg(s: &Server) -> Option<(u32, u64)> {
    let v = s.conf("connflood")?;
    let mut it = v.split_whitespace();
    let mx: u32 = it.next()?.parse().ok()?;
    let sc: u64 = it.next()?.parse().ok()?;
    (mx > 0 && sc > 0).then_some((mx, sc))
}

/// Record a connection from `ip`; returns true when it exceeds the limit (the
/// caller should refuse it). No-op → false when connflood is unconfigured.
pub fn over_limit(s: &mut Server, ip: IpAddr) -> bool {
    // loopback (local services / bridges / admin) is never connection-throttled
    if ip.is_loopback() {
        return false;
    }
    let Some((max, secs)) = cfg(s) else {
        return false;
    };
    let n = now();
    let store = s.ext.get_or_insert_with::<ConnHistory>(ConnHistory::default);
    // Bound memory: a wide source-IP spread (e.g. an IPv6 /64) could otherwise grow
    // this map unbounded between tick GCs — once it's large, drop stale buckets now.
    if store.0.len() > MAX_TRACKED_IPS {
        store.0.retain(|_, times| {
            times.retain(|&t| n.saturating_sub(t) < secs);
            !times.is_empty()
        });
    }
    let hist = store.0.entry(ip).or_default();
    hist.retain(|&t| n.saturating_sub(t) < secs);
    hist.push(n);
    hist.len() as u32 > max
}

/// Ceiling on distinct source IPs tracked between GC ticks (memory bound).
const MAX_TRACKED_IPS: usize = 65_536;

/// Prunes stale per-IP bookkeeping on the tick.
pub struct ConnFlood;
impl Module for ConnFlood {
    fn name(&self) -> &'static str {
        "connflood"
    }
    fn on_tick(&mut self, s: &mut Server) {
        let Some((_, secs)) = cfg(s) else {
            return;
        };
        let n = now();
        if let Some(h) = s.ext.get_mut::<ConnHistory>() {
            h.0.retain(|_, times| {
                times.retain(|&t| n.saturating_sub(t) < secs);
                !times.is_empty()
            });
        }
    }
}
