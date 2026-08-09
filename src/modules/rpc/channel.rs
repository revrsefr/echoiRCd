//! rpc channel provider — `channel.list`, `channel.get`, and the mutators
//! `channel.kick`, `channel.set_topic`. InspIRCd's `m_rpc_channel`. (`channel.set_mode`
//! lands with the shared server-side mode applier in a later pass.)

use super::json::{obj, qstr};
use super::RpcError;
use crate::channels::Topic;
use crate::server::{now, Server};

/// All prefix chars a member holds, highest first (e.g. `"@+"`).
fn prefixes(m: &crate::channels::Member) -> String {
    let mut p = String::new();
    for (has, ch) in [
        (m.owner, '~'),
        (m.admin, '&'),
        (m.op, '@'),
        (m.halfop, '%'),
        (m.voice, '+'),
    ] {
        if has {
            p.push(ch);
        }
    }
    p
}

/// Compact channel object for `channel.list`.
fn brief(s: &Server, key: &str) -> String {
    let ch = &s.channels[key];
    obj(&[
        ("name", qstr(&ch.name)),
        ("usercount", ch.members.len().to_string()),
        ("modes", qstr(&ch.modes.render(true))),
    ])
}

/// Full channel object for `channel.get`.
fn full(s: &Server, key: &str) -> String {
    let ch = &s.channels[key];
    let members: Vec<String> = ch
        .members
        .iter()
        .map(|(&uid, m)| {
            let (nick, uuid) = s
                .users
                .get(&uid)
                .map(|u| (u.nick.clone(), u.uuid.clone()))
                .unwrap_or_default();
            obj(&[
                ("nick", qstr(&nick)),
                ("uuid", qstr(&uuid)),
                ("prefixes", qstr(&prefixes(m))),
            ])
        })
        .collect();
    let bans: Vec<String> = ch
        .bans
        .iter()
        .map(|b| {
            obj(&[
                ("mask", qstr(&b.mask)),
                ("setter", qstr(&b.setter)),
                ("time", b.ts.to_string()),
            ])
        })
        .collect();
    let mut fields = vec![
        ("name", qstr(&ch.name)),
        ("created", ch.created.to_string()),
        ("usercount", ch.members.len().to_string()),
        ("modes", qstr(&ch.modes.render(true))),
        ("members", format!("[{}]", members.join(","))),
        ("bans", format!("[{}]", bans.join(","))),
    ];
    if let Some(t) = &ch.topic {
        let topic = obj(&[
            ("text", qstr(&t.text)),
            ("setter", qstr(&t.setter)),
            ("time", t.ts.to_string()),
        ]);
        fields.push(("topic", topic));
    }
    obj(&fields)
}

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "list" => {
            let keys: Vec<String> = s.channels.keys().cloned().collect();
            let arr: Vec<String> = keys.iter().map(|k| brief(s, k)).collect();
            Ok(obj(&[("channels", format!("[{}]", arr.join(",")))]))
        }
        "get" => {
            let name = json_channel(params)?;
            let key = name.to_ascii_lowercase();
            if !s.channels.contains_key(&key) {
                return Err(RpcError::not_found("no such channel"));
            }
            Ok(full(s, &key))
        }
        "kick" => {
            let name = json_channel(params)?;
            let key = name.to_ascii_lowercase();
            let victim = super::json::get_str(params, "nick")
                .ok_or_else(|| RpcError::invalid_params("missing 'nick'"))?;
            let reason =
                super::json::get_str(params, "reason").unwrap_or_else(|| "Kicked via RPC".into());
            if !s.channels.contains_key(&key) {
                return Err(RpcError::not_found("no such channel"));
            }
            let tuid = s
                .find_nick(&victim)
                .filter(|t| s.channels[&key].members.contains_key(t))
                .ok_or_else(|| RpcError::not_found("user not on channel"))?;
            s.to_channel(
                &key,
                &format!(
                    ":{} KICK {} {victim} :{reason}",
                    s.name, s.channels[&key].name
                ),
                None,
            );
            if let Some(ch) = s.channels.get_mut(&key) {
                ch.members.remove(&tuid);
            }
            if let Some(u) = s.users.get_mut(&tuid) {
                u.channels.remove(&key);
            }
            s.channels.retain(|_, c| c.keep_alive());
            Ok(obj(&[("result", "true".into())]))
        }
        "set_topic" => {
            let name = json_channel(params)?;
            let key = name.to_ascii_lowercase();
            let text = super::json::get_str(params, "topic")
                .ok_or_else(|| RpcError::invalid_params("missing 'topic'"))?;
            if !s.channels.contains_key(&key) {
                return Err(RpcError::not_found("no such channel"));
            }
            let display = s.channels[&key].name.clone();
            if let Some(ch) = s.channels.get_mut(&key) {
                ch.topic = Some(Topic {
                    text: text.clone(),
                    setter: s.name.clone(),
                    ts: now(),
                });
            }
            s.to_channel(&key, &format!(":{} TOPIC {display} :{text}", s.name), None);
            Ok(obj(&[("result", "true".into())]))
        }
        "set_mode" => {
            let name = json_channel(params)?;
            let key = name.to_ascii_lowercase();
            let modes = super::json::get_str(params, "modes")
                .ok_or_else(|| RpcError::invalid_params("missing 'modes'"))?;
            if !s.channels.contains_key(&key) {
                return Err(RpcError::not_found("no such channel"));
            }
            // `parameters` (array) or `param` (single) — the mode arguments
            let mut args = super::json::get_str_array(params, "parameters");
            if args.is_empty() {
                if let Some(p) = super::json::get_str(params, "param") {
                    args.push(p);
                }
            }
            let changed = crate::coremods::core_mode::svs_set_chan_modes(s, &name, &modes, &args);
            Ok(obj(&[("result", changed.to_string())]))
        }
        other => Err(RpcError::method_not_found(&format!("channel.{other}"))),
    }
}

/// The required `channel` param.
fn json_channel(params: &str) -> Result<String, RpcError> {
    super::json::get_str(params, "channel")
        .ok_or_else(|| RpcError::invalid_params("missing 'channel'"))
}
