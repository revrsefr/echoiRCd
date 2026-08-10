//! Whowas RPC provider: `whowas.get`. Returns the recent-nick-history entries
//! the ircd keeps for `WHOWAS`.

use super::json::{self, obj, qstr};
use super::RpcError;
use crate::server::Server;

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "get" => {
            let nick = json::get_str(params, "nick")
                .ok_or_else(|| RpcError::invalid_params("missing 'nick'"))?;
            let entries: Vec<String> = s
                .whowas
                .iter()
                .filter(|e| e.nick.eq_ignore_ascii_case(&nick))
                .map(|e| {
                    let mut fields = vec![
                        ("nick", qstr(&e.nick)),
                        ("ident", qstr(&e.ident)),
                        ("host", qstr(&e.host)),
                        ("realname", qstr(&e.realname)),
                        ("signon", e.ts.to_string()),
                    ];
                    if let Some(acct) = &e.account {
                        fields.push(("account", qstr(acct)));
                    }
                    obj(&fields)
                })
                .collect();
            Ok(obj(&[("entries", format!("[{}]", entries.join(",")))]))
        }
        other => Err(RpcError::method_not_found(&format!("whowas.{other}"))),
    }
}
