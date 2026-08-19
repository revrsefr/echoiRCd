//! X-line RPC provider: `xline.list`, `xline.add`, `xline.del`. Covers every
//! x-line kind (K/G/Z/E/SHUN/Q/CBAN) via the same `add_xline`/`remove_xline`
//! primitives the oper commands use.

use super::json::{self, obj, qstr};
use super::RpcError;
use crate::server::Server;
use crate::xline::{parse_duration, XKind};

/// Map a request `type` (letter tag or full name like `KLINE`) to an `XKind`.
fn kind_of(t: &str) -> Option<XKind> {
    let up = t.to_ascii_uppercase();
    XKind::from_tag(&up).or_else(|| {
        Some(match up.as_str() {
            "KLINE" => XKind::Kline,
            "GLINE" => XKind::Gline,
            "ZLINE" => XKind::Zline,
            "ELINE" => XKind::Eline,
            "QLINE" => XKind::Qline,
            _ => return None,
        })
    })
}

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "list" => {
            let want = json::get_str(params, "type").and_then(|t| kind_of(&t));
            let items: Vec<String> = s
                .xlines
                .iter()
                .filter(|x| want.is_none_or(|k| x.kind == k))
                .map(|x| {
                    let expires_at = if x.expires == 0 {
                        "null".to_string()
                    } else {
                        x.expires.to_string()
                    };
                    obj(&[
                        ("type", qstr(x.kind.tag())),
                        ("mask", qstr(&x.mask)),
                        ("reason", qstr(&x.reason)),
                        ("setter", qstr(&x.setter)),
                        ("expires_at", expires_at),
                    ])
                })
                .collect();
            Ok(obj(&[("xlines", format!("[{}]", items.join(",")))]))
        }
        "add" => {
            let kind = json::get_str(params, "type")
                .and_then(|t| kind_of(&t))
                .ok_or_else(|| RpcError::invalid_params("missing/unknown 'type'"))?;
            let mask = json::get_str(params, "mask")
                .or_else(|| json::get_str(params, "name"))
                .ok_or_else(|| RpcError::invalid_params("missing 'mask'"))?;
            // Refuse an all-wildcard ban (`*`, `*@*`, `*!*@*`, empty): it must carry a
            // literal host/ip/nick component, or it bans the whole network.
            if !mask.chars().any(|c| c.is_ascii_alphanumeric()) {
                return Err(RpcError::invalid_params(
                    "mask must contain a literal host/ip/nick component (refusing an all-wildcard ban)",
                ));
            }
            let duration = json::get_num::<u64>(params, "duration")
                .or_else(|| {
                    json::get_str(params, "duration_string").and_then(|d| parse_duration(&d))
                })
                .unwrap_or(0);
            let reason = json::get_str(params, "reason").unwrap_or_else(|| "Set via RPC".into());
            let setter = json::get_str(params, "setter").unwrap_or_else(|| "RPC".into());
            s.add_xline(kind, &mask, duration, &setter, &reason);
            Ok(obj(&[("result", "true".into())]))
        }
        "del" => {
            let kind = json::get_str(params, "type")
                .and_then(|t| kind_of(&t))
                .ok_or_else(|| RpcError::invalid_params("missing/unknown 'type'"))?;
            let mask = json::get_str(params, "mask")
                .or_else(|| json::get_str(params, "name"))
                .ok_or_else(|| RpcError::invalid_params("missing 'mask'"))?;
            let removed = s.remove_xline(kind, &mask);
            if removed {
                Ok(obj(&[("result", "true".into())]))
            } else {
                Err(RpcError::not_found("no matching x-line"))
            }
        }
        other => Err(RpcError::method_not_found(&format!("xline.{other}"))),
    }
}
