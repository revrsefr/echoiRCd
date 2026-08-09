//! DNSBL — DNS blocklist checks on connect, InspIRCd `m_dnsbl` style. On connect
//! the resolver thread reverses the client's IP under each configured blocklist
//! zone and A-looks it up (see [`crate::resolver`]); a listing triggers the
//! configured action. Works for IPv4 **and** IPv6 (v4 reversed octets or v6
//! reversed nibbles under the zone) — a v4-only blocklist simply NXDOMAINs a v6
//! query, which reads as "not listed".
//!
//! Actions (`dnsbl_action`): `mark` just shows the notice and lets them in
//! (default, safe), `kill` disconnects, `kline`/`gline`/`zline` add a 1-day ban
//! and disconnect. This isn't a hook `Module` — it's driven from the connection
//! lifecycle (`Server::add_conn` → `on_resolved`) — but it lives here as its own
//! self-contained unit.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::resolver;
use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

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

/// Check `ip` against every blocklist `zone`; the first listing wins. Runs off the
/// core thread (called from the resolver worker), so it may block on DNS.
pub fn check(ip: IpAddr, zones: &[String], timeout: Duration) -> Outcome {
    if zones.is_empty() {
        return Outcome::Skipped;
    }
    for zone in zones {
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
        Outcome::Hit { zone, reply } => {
            s.notice_star(uid, "Checking for DNSBL");
            s.notice_star(
                uid,
                &format!("Checking for DNSBL done — LISTED on {zone} ({reply})."),
            );
            act(s, uid, &zone, reply);
        }
    }
}

/// Act on a hit per `dnsbl_action`: `mark` just informs; the `*line` actions add a
/// temporary ban and close; `kill` closes without a persistent ban.
fn act(s: &mut Server, uid: Uid, zone: &str, reply: Ipv4Addr) {
    let (mask, ip) = match s.users.get(&uid) {
        Some(u) => (u.prefix(), u.addr.ip()),
        None => return,
    };
    let action = s.dnsbl_action.clone();
    s.snotice(&format!(
        "DNSBL: {mask} is listed on {zone} ({reply}); action={action}"
    ));
    let reason = format!("{} (listed on {zone})", s.dnsbl_reason);
    let ipstr = ip.to_string();
    let dur = s.conf_num("dnsbl_duration", DNSBL_BAN);
    match action.as_str() {
        "kline" => s.add_xline(XKind::Kline, &format!("*@{ipstr}"), dur, "dnsbl", &reason),
        "gline" => s.add_xline(XKind::Gline, &format!("*@{ipstr}"), dur, "dnsbl", &reason),
        "zline" => s.add_xline(XKind::Zline, &ipstr, dur, "dnsbl", &reason),
        "kill" | "reject" => {}
        _ => return, // "mark" or unknown: notify only, don't disconnect
    }
    // pre-registration users aren't caught by add_xline's enforce sweep, so close
    // this connection explicitly (the ERROR flushes before the socket).
    s.send(uid, format!("ERROR :Closing link: ({reason})"));
    s.remove_user(uid, &reason);
}
