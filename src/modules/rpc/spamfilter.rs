//! Spamfilter RPC provider: `spamfilter.list`, `spamfilter.add`, `spamfilter.del`.
//! Operates on the same [`crate::modules::filter`] rule set (in `Server.ext`) that
//! the `FILTER` command and the enforcement hook use, so a rule added here takes
//! effect immediately.

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
                    f.rules()
                        .iter()
                        .map(|r| {
                            obj(&[
                                ("pattern", qstr(&r.pattern)),
                                ("engine", qstr(&r.engine)),
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
            // engine: an explicit param, else the configured default, else glob.
            let engine = json::get_str(params, "engine")
                .or_else(|| s.conf("filter_engine").map(str::to_string))
                .unwrap_or_else(|| "glob".to_string());
            let filter = SpamFilter::new(pattern, engine, action, duration, reason)
                .map_err(|e| RpcError::invalid_params(&e))?;
            let set = s.ext.get_or_insert_with::<Filters>(Filters::default);
            if set.rules().iter().any(|f| f.pattern == filter.pattern) {
                return Err(RpcError::not_found("filter already exists"));
            }
            set.upsert(filter);
            Ok(obj(&[("result", "true".into())]))
        }
        "del" => {
            let pattern = json::get_str(params, "pattern")
                .or_else(|| json::get_str(params, "name"))
                .ok_or_else(|| RpcError::invalid_params("missing 'pattern'"))?;
            let set = s.ext.get_or_insert_with::<Filters>(Filters::default);
            if set.remove(&pattern) {
                Ok(obj(&[("result", "true".into())]))
            } else {
                Err(RpcError::not_found("no matching filter"))
            }
        }
        other => Err(RpcError::method_not_found(&format!("spamfilter.{other}"))),
    }
}
