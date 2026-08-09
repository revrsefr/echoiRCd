//! rpc log provider — `log.tail` and `log.events`. InspIRCd's `m_rpc_log` /
//! `m_jsonrpclog`. echoIRCd has no log *file* (it logs to journald), so both read
//! the in-memory server-log ring that `Server::snotice` feeds (`Server.log`).

use super::json::{self, obj, qstr};
use super::RpcError;
use crate::server::Server;

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    let log = s.log.borrow();
    match action {
        "tail" => {
            let n = json::get_num::<usize>(params, "lines")
                .unwrap_or(200)
                .clamp(1, 1000);
            let start = log.ring.len().saturating_sub(n);
            let lines: Vec<String> = log.ring.iter().skip(start).map(|e| qstr(&e.msg)).collect();
            Ok(obj(&[("lines", format!("[{}]", lines.join(",")))]))
        }
        "events" => {
            let since = json::get_num::<u64>(params, "since").unwrap_or(0);
            let limit = json::get_num::<usize>(params, "limit")
                .unwrap_or(200)
                .clamp(1, 1000);
            let events: Vec<String> = log
                .ring
                .iter()
                .filter(|e| e.id > since)
                .take(limit)
                .map(|e| {
                    obj(&[
                        ("id", e.id.to_string()),
                        ("timestamp", e.ts.to_string()),
                        ("msg", qstr(&e.msg)),
                    ])
                })
                .collect();
            let last_id = log.ring.back().map(|e| e.id).unwrap_or(since);
            Ok(obj(&[
                ("events", format!("[{}]", events.join(","))),
                ("last_id", last_id.to_string()),
            ]))
        }
        other => Err(RpcError::method_not_found(&format!("log.{other}"))),
    }
}
