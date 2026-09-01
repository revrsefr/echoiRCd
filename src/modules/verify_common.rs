//! Shared state for the human-verification gates ([`super::recaptcha`],
//! [`super::cloudflare_challenge`]). When the verification web page confirms a
//! Turnstile solve it pushes the token to the daemon over RPC (`verify.pass`); that
//! records the token's IP here so held connections from that IP complete on their
//! own — the user never sends `CAPTCHA`/`VERIFYCHALLENGE` by hand.

use crate::map::HashMap;
use crate::server::{now, Server};
use crate::Uid;

/// client IP -> unix-secs expiry. An IP present and unexpired counts as verified.
#[derive(Default)]
pub struct VerifiedIps(pub HashMap<String, u64>);

/// UIDs to re-attempt registration on the next tick (their IP was just cleared
/// out-of-band). Drained by the core in `on_tick`; empty in the common case.
#[derive(Default)]
pub struct PendingComplete(pub Vec<Uid>);

/// Record `ip` verified until `exp`, and queue any held (unregistered) connections
/// from that IP to complete on the next tick.
pub fn mark_ip(s: &mut Server, ip: &str, exp: u64) {
    s.ext
        .get_or_insert_with::<VerifiedIps>(VerifiedIps::default)
        .0
        .insert(ip.to_string(), exp);
    let held: Vec<Uid> = s
        .users
        .iter()
        .filter(|(_, u)| !u.registered && u.addr.ip().to_string() == ip)
        .map(|(&uid, _)| uid)
        .collect();
    if !held.is_empty() {
        s.ext
            .get_or_insert_with::<PendingComplete>(PendingComplete::default)
            .0
            .extend(held);
    }
}

/// Whether `ip` has an unexpired verification record.
pub fn ip_verified(s: &Server, ip: &str) -> bool {
    s.ext
        .get::<VerifiedIps>()
        .and_then(|v| v.0.get(ip))
        .is_some_and(|&exp| exp > now())
}

/// Drop expired IP records (bounds the map; called from `on_tick`).
pub fn purge(s: &mut Server) {
    if let Some(v) = s.ext.get_mut::<VerifiedIps>() {
        let n = now();
        v.0.retain(|_, exp| *exp > n);
    }
}
