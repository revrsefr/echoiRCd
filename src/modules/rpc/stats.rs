//! rpc stats provider — read-only introspection: `module.list`, `oper.list`,
//! `security_group.list`. InspIRCd's `m_rpc_stats`.

use super::json::{obj, qstr};
use super::RpcError;
use crate::server::Server;

pub fn handle(s: &mut Server, method: &str, _params: &str) -> Result<String, RpcError> {
    match method {
        "module.list" => {
            let mods: Vec<String> = crate::modules::module_names()
                .iter()
                .map(|n| {
                    obj(&[
                        ("name", qstr(n)),
                        ("description", qstr("")),
                        ("version", qstr("")),
                    ])
                })
                .collect();
            Ok(obj(&[("modules", format!("[{}]", mods.join(",")))]))
        }
        "oper.list" => {
            // configured oper blocks — names only, never the passwords
            let opers: Vec<String> = s
                .opers
                .iter()
                .map(|(name, _pass)| {
                    obj(&[
                        ("name", qstr(name)),
                        ("type", qstr("")),
                        ("online", "0".into()),
                    ])
                })
                .collect();
            Ok(obj(&[("opers", format!("[{}]", opers.join(",")))]))
        }
        "security_group.list" => {
            let groups: Vec<String> = s
                .conf_all("securitygroup")
                .iter()
                .filter_map(|line| {
                    let mut it = line.split_whitespace();
                    let name = it.next()?;
                    let criteria = it.collect::<Vec<_>>().join(" ");
                    let public = criteria.split_whitespace().any(|t| t == "public");
                    Some(obj(&[
                        ("name", qstr(name)),
                        ("criteria", qstr(&criteria)),
                        ("public", public.to_string()),
                    ]))
                })
                .collect();
            Ok(obj(&[(
                "security_groups",
                format!("[{}]", groups.join(",")),
            )]))
        }
        other => Err(RpcError::method_not_found(other)),
    }
}
