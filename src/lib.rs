//! echoIRCd — a small, dependency-light IRC daemon.
//!
//! - **engine** — `server` (the core + state), `users`, `channels`, `message`,
//!   `numeric`, `config`.
//! - **`coremods`** — the built-in commands (core_user, core_channel,
//!   core_message, core_mode, core_info).
//! - **`modules`** — optional, pluggable behaviour via lifecycle hooks.
//! - **`socketengine`** — the I/O edge (accept + per-connection threads).
//! - **`ircd`** — the single-threaded core loop that ties it together.
#![forbid(unsafe_code)]

/// A local connection id. (Server linking will later need real UUIDs.)
pub type Uid = u64;

pub mod accounts;
pub mod bcrypt;
pub mod channels;
pub mod command;
pub mod config;
pub mod connguard;
pub mod coremods;
pub mod database;
pub mod extensible;
pub mod help;
pub mod http;
pub mod i18n;
pub mod ircd;
pub mod link;
pub mod map;
pub mod message;
pub mod mode;
pub mod module;
pub mod modules;
pub mod numeric;
pub mod proxy;
pub mod regex;
pub mod resolver;
pub mod reuseport;
#[cfg(test)]
mod s2s_sim;
pub mod server;
pub mod socketengine;
pub mod tls;
pub mod tls_rustls;
pub mod upgrade;
pub mod users;
pub mod watch;
pub mod websocket;
pub mod xline;
