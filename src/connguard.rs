//! Guard against a flood of held / not-yet-registered connections.
//!
//! The human-verification gates ([`crate::modules::recaptcha`],
//! [`crate::modules::cloudflare_challenge`]) PAUSE registration until a client
//! proves it is human. Under a bot flood the not-yet-registered pool can grow
//! until it fills the connection class `limit` and locks real users out — the
//! event loop is epoll so this is a slot-exhaustion lockout, not a CPU meltdown.
//!
//! This is a cheap O(1) running count of local unregistered connections plus two
//! entirely config-driven policies:
//!
//!   * `max_unregistered` — a hard cap: connections past it are refused at connect
//!     (before a challenge is even issued), except from loopback. 0 = off.
//!   * `unreg_floodwater` / `unreg_flood_timeout` — when the pool crosses the
//!     high-water mark, the handshake timeout for unregistered connections is cut
//!     to `unreg_flood_timeout` so squatted slots recycle fast, and opers are
//!     snoted once per transition. 0 = off.
//!
//! The count is maintained incrementally (connect / register / remove) and
//! reconciled against the live user map every tick, so it is self-healing.

use crate::server::Server;

/// Running state for the unregistered-connection guard. Lives in `Server.ext`.
#[derive(Default)]
pub struct UnregGuard {
    /// concurrent local unregistered connections
    pub count: usize,
    /// whether high-water flood mode is currently active (for edge-triggered snotes)
    pub flood: bool,
}

fn state(s: &mut Server) -> &mut UnregGuard {
    s.ext.get_or_insert_with::<UnregGuard>(UnregGuard::default)
}

/// The current unregistered-connection count (0 if never touched).
pub fn count(s: &Server) -> usize {
    s.ext.get::<UnregGuard>().map(|g| g.count).unwrap_or(0)
}

/// A new local connection was accepted (it always starts unregistered).
pub fn note_connect(s: &mut Server) {
    state(s).count += 1;
}

/// A connection finished registration (unregistered -> registered).
pub fn note_registered(s: &mut Server) {
    let g = state(s);
    g.count = g.count.saturating_sub(1);
}

/// An unregistered connection was removed before it ever registered.
pub fn note_removed_unreg(s: &mut Server) {
    let g = state(s);
    g.count = g.count.saturating_sub(1);
}

/// Whether the unregistered pool is over the hard cap (`max_unregistered`).
/// Always false when the cap is unset (0) — the feature is opt-in.
pub fn over_cap(s: &Server) -> bool {
    let cap = s.conf_num("max_unregistered", 0i64);
    cap > 0 && count(s) as i64 > cap
}

/// Whether flood mode is active: the pool is over `unreg_floodwater` (>0).
pub fn flood_active(s: &Server) -> bool {
    let water = s.conf_num("unreg_floodwater", 0i64);
    water > 0 && count(s) as i64 > water
}

/// The handshake timeout to apply to unregistered connections right now: the
/// shortened `unreg_flood_timeout` while flood mode is active, else `None`.
pub fn flood_timeout(s: &Server) -> Option<u64> {
    flood_active(s).then(|| s.conf_num("unreg_flood_timeout", 30u64))
}

/// Recount from the live user map (authoritative, O(N)) and edge-detect flood
/// mode, snoting opers on each transition. Called once per tick — keeps the
/// incremental count self-healing.
pub fn tick(s: &mut Server) {
    let live = s.users.values().filter(|u| !u.registered).count();
    let water = s.conf_num("unreg_floodwater", 0i64);
    let now_flood = water > 0 && live as i64 > water;
    let was_flood = s.ext.get::<UnregGuard>().map(|g| g.flood).unwrap_or(false);
    {
        let g = state(s);
        g.count = live;
        g.flood = now_flood;
    }
    if now_flood && !was_flood {
        let to = s.conf_num("unreg_flood_timeout", 30u64);
        s.snotice_c(
            'x',
            &format!(
                "Unregistered-connection flood: {live} pending (> {water}) — handshake timeout cut to {to}s"
            ),
        );
    } else if !now_flood && was_flood {
        s.snotice_c(
            'x',
            &format!("Unregistered-connection flood cleared: {live} pending"),
        );
    }
}
