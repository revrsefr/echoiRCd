//! Native, non-blocking SQL database subsystem.
//!
//! A worker-thread pool holds the database connections and runs every query
//! off-core, so a slow query or a stalled database can never freeze the event
//! loop (the same discipline as the DNS resolver and the disk writer). Modules
//! submit a query with a callback; the result is delivered back to the core as an
//! [`crate::ircd::Event`] and the callback runs there with `&mut Server`.
//!
//! `pgsql` is the first backend: a from-scratch PostgreSQL v3 wire-protocol client
//! (no `unsafe`, no libpq, no async runtime) built on the openssl the daemon
//! already links for TLS and SCRAM-SHA-256 auth.

pub mod scram;
