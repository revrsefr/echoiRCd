//! Message RPC provider: `message.send_notice`. Sends a server NOTICE to a
//! channel (`#…`), a single user (nick), or every local user (`*` / `$*`).

use super::json::{self, obj};
use super::RpcError;
use crate::server::Server;

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "send_notice" => {
            let target = json::get_str(params, "target")
                .ok_or_else(|| RpcError::invalid_params("missing 'target'"))?;
            let text = json::get_str(params, "message")
                .ok_or_else(|| RpcError::invalid_params("missing 'message'"))?;
            // strip CR/LF so a crafted message/target can't inject extra IRC lines
            let strip =
                |v: String| -> String { v.chars().filter(|c| *c != '\r' && *c != '\n').collect() };
            let (target, text) = (strip(target), strip(text));
            let src = s.name.clone();
            if target == "*" || target == "$*" {
                let uids: Vec<crate::Uid> = s.users.keys().copied().collect();
                for uid in uids {
                    let nick = s
                        .users
                        .get(&uid)
                        .map(|u| u.nick.clone())
                        .unwrap_or_default();
                    s.send(uid, format!(":{src} NOTICE {nick} :{text}"));
                }
            } else if target.starts_with('#') {
                let key = target.to_ascii_lowercase();
                if !s.channels.contains_key(&key) {
                    return Err(RpcError::not_found("no such channel"));
                }
                s.to_channel(&key, &format!(":{src} NOTICE {target} :{text}"), None);
            } else {
                let uid = s
                    .find_nick(&target)
                    .ok_or_else(|| RpcError::not_found("no such nick"))?;
                let nick = s
                    .users
                    .get(&uid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                s.send(uid, format!(":{src} NOTICE {nick} :{text}"));
            }
            Ok(obj(&[("result", "true".into())]))
        }
        other => Err(RpcError::method_not_found(&format!("message.{other}"))),
    }
}
