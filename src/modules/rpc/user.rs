//! User RPC provider: `user.list`, `user.get`, and the mutators `user.kill`,
//! `user.set_mode`, `user.set_vhost`, `user.set_nick`, `user.set_oper`. Mutators
//! route through the same `Server` primitives the commands use, so behaviour and
//! side-effects (QUIT/CHGHOST/MODE broadcasts) stay identical.

use super::json::{self, obj, qstr};
use super::RpcError;
use crate::coremods::core_mode::svs_set_user_modes;
use crate::server::Server;
use crate::Uid;

/// Resolve the target uid from a `nick` or `uuid` param.
fn resolve(s: &Server, params: &str) -> Option<Uid> {
    if let Some(nick) = json::get_str(params, "nick") {
        if let Some(uid) = s.find_nick(&nick) {
            return Some(uid);
        }
    }
    if let Some(uuid) = json::get_str(params, "uuid") {
        return s
            .users
            .iter()
            .find(|(_, u)| u.uuid == uuid)
            .map(|(&id, _)| id);
    }
    None
}

/// User modes as a bare letter string (no leading `+`).
fn modes_str(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .map(|u| u.flags.umodes().trim_start_matches('+').to_string())
        .unwrap_or_default()
}

/// A compact user object (used in `user.list`).
fn brief(s: &Server, uid: Uid) -> String {
    let u = &s.users[&uid];
    obj(&[
        ("nick", qstr(&u.nick)),
        ("uuid", qstr(&u.uuid)),
        ("ident", qstr(&u.ident)),
        ("host", qstr(u.host_display())),
    ])
}

/// The full user object (used in `user.get`).
fn full(s: &Server, uid: Uid) -> String {
    let u = &s.users[&uid];
    let channels: Vec<String> = u.channels.iter().map(|c| qstr(c)).collect();
    let mut fields = vec![
        ("nick", qstr(&u.nick)),
        ("uuid", qstr(&u.uuid)),
        ("ident", qstr(&u.ident)),
        ("realname", qstr(&u.realname)),
        ("host", qstr(&u.host)),
        ("displayhost", qstr(u.host_display())),
        ("ip", qstr(&u.addr.ip().to_string())),
        ("mask", qstr(&u.prefix())),
        ("server", qstr(&s.name)),
        ("signon", u.signon.to_string()),
        ("modes", qstr(&modes_str(s, uid))),
        ("channels", format!("[{}]", channels.join(","))),
        ("oper", u.flags.oper.to_string()),
        ("secure", u.secure.to_string()),
        ("websocket", u.flags.via_websocket.to_string()),
    ];
    if let Some(acct) = &u.account {
        fields.push(("account", qstr(acct)));
    }
    if let Some(away) = &u.flags.away {
        fields.push(("away", qstr(away)));
    }
    if let Some(fp) = &u.certfp {
        fields.push(("fingerprint", qstr(fp)));
    }
    obj(&fields)
}

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "list" => {
            let users: Vec<Uid> = s.users.keys().copied().collect();
            let arr: Vec<String> = users.iter().map(|&id| brief(s, id)).collect();
            Ok(obj(&[("users", format!("[{}]", arr.join(",")))]))
        }
        "get" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            Ok(full(s, uid))
        }
        "kill" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            let reason = json::get_str(params, "reason").unwrap_or_else(|| "Killed via RPC".into());
            s.remove_user(uid, &reason);
            Ok(obj(&[("result", "true".into())]))
        }
        "set_mode" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            let modes = json::get_str(params, "modes")
                .ok_or_else(|| RpcError::invalid_params("missing 'modes'"))?;
            svs_set_user_modes(s, uid, &modes);
            Ok(obj(&[("result", "true".into())]))
        }
        "set_vhost" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            let host = json::get_str(params, "vhost")
                .or_else(|| json::get_str(params, "host"))
                .ok_or_else(|| RpcError::invalid_params("missing 'vhost'"))?;
            s.change_host_ident(uid, None, Some(&host));
            Ok(obj(&[("result", "true".into())]))
        }
        "set_nick" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            let newnick = json::get_str(params, "newnick")
                .ok_or_else(|| RpcError::invalid_params("missing 'newnick'"))?;
            s.set_nick(uid, &newnick);
            Ok(obj(&[("result", "true".into())]))
        }
        "set_oper" => {
            let uid = resolve(s, params).ok_or_else(|| RpcError::not_found("no such user"))?;
            let oper = json::get_str(params, "oper").or_else(|| json::get_str(params, "type"));
            match oper {
                Some(name) if !name.is_empty() => s.oper_up(uid),
                _ => svs_set_user_modes(s, uid, "-o"), // de-oper
            }
            Ok(obj(&[("result", "true".into())]))
        }
        other => Err(RpcError::method_not_found(&format!("user.{other}"))),
    }
}
