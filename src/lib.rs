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
pub mod channels;
pub mod command;
pub mod config;
pub mod coremods;
pub mod extensible;
pub mod http;
pub mod ircd;
pub mod link;
pub mod message;
pub mod mode;
pub mod module;
pub mod modules;
pub mod numeric;
pub mod resolver;
pub mod server;
pub mod socketengine;
pub mod tls;
pub mod users;
pub mod watch;
pub mod websocket;
pub mod xline;
