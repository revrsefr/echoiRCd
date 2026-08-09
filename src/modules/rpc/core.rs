//! rpc core provider — introspection: `rpc.methods` (list the interface),
//! `rpc.info` (identity + methods), and `server.info` / `stats.get` (identity +
//! network counts). InspIRCd's `m_rpc_core` + the legacy `stats.get`.

use super::json::{obj, qstr};
use super::{RpcError, ALL_METHODS};
use crate::server::{now, Server, VERSION};

/// `{"methods":[...]}` — every method name the interface exposes.
fn methods_json() -> String {
    let list: Vec<String> = ALL_METHODS.iter().map(|m| qstr(m)).collect();
    format!("[{}]", list.join(","))
}

/// `rpc.methods` and `rpc.info`.
pub fn rpc_info(s: &Server, method: &str) -> Result<String, RpcError> {
    if method == "rpc.methods" {
        return Ok(obj(&[("methods", methods_json())]));
    }
    // rpc.info: identity + the method list
    let mut fields = identity_fields(s);
    fields.push(("methods", methods_json()));
    Ok(obj(&fields))
}

/// `server.info` / `stats.get` — identity plus live network counts.
pub fn server_info(s: &Server) -> Result<String, RpcError> {
    Ok(obj(&identity_fields(s)))
}

/// The shared identity + counts fields.
fn identity_fields(s: &Server) -> Vec<(&'static str, String)> {
    let opers = s.users.values().filter(|u| u.flags.oper).count();
    let users_local = s.users.len();
    let users_total = users_local + s.remote_users.len();
    let counts = obj(&[
        ("users", users_total.to_string()),
        ("users_local", users_local.to_string()),
        ("opers", opers.to_string()),
        ("channels", s.channels.len().to_string()),
    ]);
    vec![
        ("name", qstr(&s.name)),
        ("id", qstr(&s.sid)),
        ("description", qstr(&s.server_desc)),
        ("version", qstr(&format!("echoircd-{VERSION}"))),
        ("boot_time", s.created.to_string()),
        ("current_time", now().to_string()),
        ("counts", counts),
    ]
}
