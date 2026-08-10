//! Server RPC provider: `server.list`, `server.rehash`, `server.connect`,
//! `server.disconnect`.

use super::json::{obj, qstr};
use super::RpcError;
use crate::config::Config;
use crate::server::Server;

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "list" => {
            let mut servers = vec![obj(&[
                ("name", qstr(&s.name)),
                ("description", qstr(&s.server_desc)),
                ("uplink", qstr("")),
                ("usercount", s.users.len().to_string()),
            ])];
            for rs in s.servers.values() {
                let uplink = s
                    .servers
                    .values()
                    .find(|o| o.sid == rs.sid)
                    .map(|_| s.name.clone())
                    .unwrap_or_default();
                servers.push(obj(&[
                    ("name", qstr(&rs.name)),
                    ("description", qstr(&rs.desc)),
                    ("uplink", qstr(&uplink)),
                    ("usercount", "0".to_string()),
                ]));
            }
            Ok(obj(&[("servers", format!("[{}]", servers.join(",")))]))
        }
        "rehash" => match Config::try_load(&s.conf_path) {
            Some(fresh) => {
                s.apply_config(fresh);
                s.announce("Server configuration reloaded via RPC.");
                Ok(obj(&[("result", "true".into())]))
            }
            None => Err(RpcError::internal("config file could not be read")),
        },
        "connect" => {
            let name = json_name(params)?;
            let Some(b) = s
                .link_blocks
                .iter()
                .find(|b| b.name.eq_ignore_ascii_case(&name))
                .cloned()
            else {
                return Err(RpcError::not_found(&format!("no link block named {name}")));
            };
            if s.servers
                .values()
                .any(|sv| sv.name.eq_ignore_ascii_case(&b.name))
            {
                return Err(RpcError::invalid_params("server is already linked"));
            }
            let addr = format!("{}:{}", b.ip, b.port);
            let (tx, counter) = (s.event_tx.clone(), s.conn_counter.clone());
            std::thread::spawn(move || crate::socketengine::connect_link(&addr, tx, counter));
            s.snotice(&format!("RPC initiated a link to {}", b.name));
            Ok(obj(&[("result", "true".into())]))
        }
        "disconnect" => {
            let name = json_name(params)?;
            let via = s
                .servers
                .values()
                .find(|rs| rs.name.eq_ignore_ascii_case(&name))
                .map(|rs| rs.via)
                .ok_or_else(|| RpcError::not_found("no such linked server"))?;
            s.close_link(via, "Disconnected via RPC");
            Ok(obj(&[("result", "true".into())]))
        }
        other => Err(RpcError::method_not_found(&format!("server.{other}"))),
    }
}

fn json_name(params: &str) -> Result<String, RpcError> {
    super::json::get_str(params, "name")
        .or_else(|| super::json::get_str(params, "server"))
        .ok_or_else(|| RpcError::invalid_params("missing 'name'"))
}
