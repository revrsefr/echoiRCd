//! rpc — a JSON-RPC 2.0 control interface over a small native HTTP server, the
//! echoIRCd analogue of InspIRCd's `m_httpd` + `m_jsonrpc` + `m_rpc_*`. Admin tools
//! call it to introspect and drive the ircd (list/kill users, manage bans, rehash…).
//!
//! Layering (each provider is its own file, per [[echoircd-module-per-file]]):
//!   * [`httpd`] — the listener thread: accept, parse HTTP, authenticate, and hand
//!     the JSON-RPC body to the core as `Event::RpcRequest`.
//!   * [`json`] — native JSON scan/build (no serde).
//!   * `core` / `user` / `channel` / `server` / `stats` / `ban` / `message` /
//!     `whowas` / `spamfilter` / `log` — the method providers, called on the core
//!     thread with `&mut Server`.
//!
//! Security: **off** unless `rpc = yes` AND `rpc_token` is set; binds `rpc_bind`
//! (default `127.0.0.1:8080`); every request must carry the token (HTTP Basic or
//! Bearer), checked constant-time on the listener thread before anything dispatches.

pub mod ban;
pub mod channel;
pub mod core;
pub mod httpd;
pub mod json;
pub mod message;
pub mod server;
pub mod spamfilter;
pub mod stats;
pub mod user;
pub mod whowas;

use std::sync::mpsc::Sender;

use crate::config::Config;
use crate::ircd::Event;
use crate::server::Server;

/// A JSON-RPC error (standard codes plus app-specific negatives).
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn method_not_found(m: &str) -> RpcError {
        RpcError {
            code: -32601,
            message: format!("Method not found: {m}"),
        }
    }
    pub fn invalid_params(msg: &str) -> RpcError {
        RpcError {
            code: -32602,
            message: msg.to_string(),
        }
    }
    pub fn not_found(msg: &str) -> RpcError {
        RpcError {
            code: -1000,
            message: msg.to_string(),
        }
    }
    pub fn internal(msg: &str) -> RpcError {
        RpcError {
            code: -32603,
            message: msg.to_string(),
        }
    }
}

/// Every method name the interface exposes (drives `rpc.methods`). Keep in sync
/// with the `dispatch` routes as providers are added.
pub const ALL_METHODS: &[&str] = &[
    "rpc.methods",
    "rpc.info",
    "server.info",
    "stats.get",
    "user.list",
    "user.get",
    "user.kill",
    "user.set_mode",
    "user.set_vhost",
    "user.set_nick",
    "user.set_oper",
    "channel.list",
    "channel.get",
    "channel.kick",
    "channel.set_topic",
    "server.list",
    "server.rehash",
    "server.disconnect",
    "module.list",
    "oper.list",
    "security_group.list",
    "xline.list",
    "xline.add",
    "xline.del",
    "message.send_notice",
    "whowas.get",
    "spamfilter.list",
    "spamfilter.add",
    "spamfilter.del",
];

/// Run a parsed JSON-RPC request on the core thread. `params` is the raw JSON of
/// the `params` member (`{}` if none); `id` is the raw JSON of the request id
/// (echoed verbatim). Returns the full JSON-RPC response envelope.
pub fn dispatch(s: &mut Server, method: &str, params: &str, id: &str) -> String {
    let result: Result<String, RpcError> = match method {
        "rpc.methods" | "rpc.info" => core::rpc_info(s, method),
        "server.info" | "stats.get" => core::server_info(s),
        "module.list" | "oper.list" | "security_group.list" => stats::handle(s, method, params),
        _ => match method.split_once('.') {
            Some(("user", action)) => user::handle(s, action, params),
            Some(("channel", action)) => channel::handle(s, action, params),
            Some(("server", action)) => server::handle(s, action, params),
            Some(("xline", action)) => ban::handle(s, action, params),
            Some(("message", action)) => message::handle(s, action, params),
            Some(("whowas", action)) => whowas::handle(s, action, params),
            Some(("spamfilter", action)) => spamfilter::handle(s, action, params),
            _ => Err(RpcError::method_not_found(method)),
        },
    };
    envelope(method, id, result)
}

/// Wrap a provider result (or error) in the JSON-RPC 2.0 response envelope, echoing
/// the method and id (InspIRCd includes the method in its responses too).
pub fn envelope(method: &str, id: &str, result: Result<String, RpcError>) -> String {
    let id = if id.trim().is_empty() { "null" } else { id };
    match result {
        Ok(res) => format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":{},\"result\":{res},\"id\":{id}}}",
            json::qstr(method)
        ),
        Err(e) => format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":{},\"error\":{{\"code\":{},\"message\":{}}},\"id\":{id}}}",
            json::qstr(method),
            e.code,
            json::qstr(&e.message)
        ),
    }
}

/// Start the RPC HTTP listener if configured. Called from `main` with a clone of
/// the core's event sender. No-op (with a stderr note) when disabled or misconfigured.
pub fn maybe_start(cfg: &Config, tx: Sender<Event>) {
    let get = |k: &str| cfg.raw.get(k).and_then(|v| v.last()).map(|s| s.as_str());
    let on = get("rpc").map(crate::config::yesish).unwrap_or(false);
    if !on {
        return;
    }
    let token = match get("rpc_token") {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            eprintln!("echoircd: rpc enabled but no rpc_token set — RPC stays OFF");
            return;
        }
    };
    let bind = get("rpc_bind").unwrap_or("127.0.0.1:8080").to_string();
    let user = get("rpc_user").unwrap_or("admin").to_string();
    match std::net::TcpListener::bind(&bind) {
        Ok(listener) => {
            eprintln!("echoircd JSON-RPC on {bind} (token auth)");
            std::thread::spawn(move || httpd::serve(listener, tx, user, token));
        }
        Err(e) => eprintln!("echoircd: cannot bind rpc {bind}: {e}"),
    }
}
