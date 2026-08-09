//! rpc spamfilter provider — `spamfilter.list`, `spamfilter.add`, `spamfilter.del`.
//! InspIRCd's `m_rpc_spamfilter`. Operates on the same [`crate::modules::filter`]
//! rule set (stored in `Server.ext`) that the `FILTER` command and the enforcement
//! hook use, so a rule added here takes effect immediately.

use super::json::{self, obj, qstr};
use super::RpcError;
use crate::modules::filter::{Filters, SpamFilter};
use crate::server::Server;

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "list" => {
            let items: Vec<String> = s
                .ext
                .get::<Filters>()
                .map(|f| {
                    f.0.iter()
                        .map(|r| {
                            obj(&[
                                ("pattern", qstr(&r.pattern)),
                                ("reason", qstr(&r.reason)),
                                ("action", qstr(&r.action)),
                                ("duration", r.duration.to_string()),
                            ])
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(obj(&[("filters", format!("[{}]", items.join(",")))]))
        }
        "add" => {
            let pattern = json::get_str(params, "pattern")
                .or_else(|| json::get_str(params, "name"))
                .ok_or_else(|| RpcError::invalid_params("missing 'pattern'"))?;
            let action = json::get_str(params, "action").unwrap_or_else(|| "block".into());
            let reason = json::get_str(params, "reason").unwrap_or_else(|| "Set via RPC".into());
            let duration = json::get_num::<u64>(params, "duration").unwrap_or(0);
            let set = s.ext.get_or_insert_with::<Filters>(Filters::default);
            if set.0.iter().any(|f| f.pattern == pattern) {
                return Err(RpcError::not_found("filter already exists"));
            }
            set.0.push(SpamFilter {
                pattern,
                action,
                duration,
                reason,
            });
            Ok(obj(&[("result", "true".into())]))
        }
        "del" => {
            let pattern = json::get_str(params, "pattern")
                .or_else(|| json::get_str(params, "name"))
                .ok_or_else(|| RpcError::invalid_params("missing 'pattern'"))?;
            let set = s.ext.get_or_insert_with::<Filters>(Filters::default);
            let before = set.0.len();
            set.0.retain(|f| f.pattern != pattern);
            if set.0.len() < before {
                Ok(obj(&[("result", "true".into())]))
            } else {
                Err(RpcError::not_found("no matching filter"))
            }
        }
        other => Err(RpcError::method_not_found(&format!("spamfilter.{other}"))),
    }
}
