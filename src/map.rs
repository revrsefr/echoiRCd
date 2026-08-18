//! Project-wide `HashMap` / `HashSet` backed by [aHash] instead of the standard
//! library's SipHash.
//!
//! The router touches maps on every single message — `users` by uid, `nick_index`
//! and `remote_nick` by nick, `channels` by name, per-channel `members`. SipHash is
//! deliberately slow (it trades speed for DoS resistance); aHash keeps the
//! DoS resistance (its state is seeded from process-random data, so an attacker
//! can't predict bucket placement to force collisions) while hashing these short
//! keys 2-3x faster. Same std `HashMap<K, V, S>` underneath — every method, the
//! `entry` API and `Index` all behave exactly as before; only the hasher changes,
//! so construction moves from `::new()` (SipHash-only) to `::default()`.
//!
//! [aHash]: https://docs.rs/ahash

pub type HashMap<K, V> = std::collections::HashMap<K, V, ahash::RandomState>;
pub type HashSet<T> = std::collections::HashSet<T, ahash::RandomState>;
