//! MODE: parse the modestring and dispatch each letter to its handler in
//! [`crate::mode`] (channel and user modes alike).

use crate::channels::RANK_HALFOP;
use crate::command::{CmdResult, Command};
use crate::mode::{chan_mode, user_mode, Applied};
use crate::numeric::*;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Mode)]
}

/// Append one mode change to the echo string, emitting the +/- only when it flips.
fn emit(applied: &mut String, last: &mut char, sign: char, c: char) {
    if *last != sign {
        applied.push(sign);
        *last = sign;
    }
    applied.push(c);
}

/// Apply user modes to `tuid` with services authority (SVSMODE): no "only your
/// own modes" restriction — that's the whole point. Reuses the per-mode handlers
/// and broadcasts the result to the target as `:nick MODE nick :<changes>`.
pub fn svs_set_user_modes(s: &mut Server, tuid: Uid, modestring: &str) {
    let mut sign = '+';
    let mut applied = String::new();
    let mut last = ' ';
    s.mode_sudo = true; // services authority — allows server-only modes like +k
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
        let adding = sign == '+';
        if let Some(handler) = user_mode(c) {
            if handler.apply(s, tuid, adding) {
                emit(&mut applied, &mut last, sign, c);
            }
        }
    }
    s.mode_sudo = false;
    if !applied.is_empty() {
        let nick = s
            .users
            .get(&tuid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        s.send(tuid, format!(":{nick} MODE {nick} :{applied}"));
    }
}

struct Mode;
impl Command for Mode {
    fn name(&self) -> &'static str {
        "MODE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        apply_mode(s, uid, params)
    }
}

/// The MODE body, shared with SAMODE (which wraps it in `Server::mode_sudo` so
/// the rank gates below all pass — see `core_oper::SaMode`).
pub fn apply_mode(s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
    let target = &params[0];
    if !target.starts_with('#') {
        return apply_user_modes(s, uid, target, params);
    }
    let key = target.to_ascii_lowercase();
    if !s.channels.contains_key(&key) {
        s.numeric(
            uid,
            ERR_NOSUCHCHANNEL,
            &format!("{target} :No such channel"),
        );
        return CmdResult::Fail;
    }
    // query: `MODE #c`
    if params.len() < 2 {
        let modestr = s.channels[&key].modes.render(s.is_member(uid, &key));
        s.numeric(uid, RPL_CHANNELMODEIS, &format!("{target} {modestr}"));
        let created = s.channels[&key].created;
        s.numeric(uid, RPL_CREATIONTIME, &format!("{target} {created}"));
        return CmdResult::Ok;
    }
    // dispatch each mode letter to its handler
    let modestring = params[1].clone();
    let args = &params[2..];
    // a *pure list query* (only list-mode letters, no arguments, e.g. `MODE #c +b`)
    // is just viewing — allow it for anyone (the hidelist module may still restrict
    // it). Anything that changes a mode needs at least half-op; each handler then
    // enforces its own finer rule (prefixes need enough rank, +z needs all-secure…).
    let pure_list_query = args.is_empty()
        && modestring
            .chars()
            .filter(|c| *c != '+' && *c != '-')
            .all(|c| chan_mode(c).is_some_and(|h| h.is_list()));
    // Viewing autoop (+w), exemptchanops (+X) or filter (+g) exposes trusted
    // host/pattern lists, so require half-op to read them (public ban lists stay open).
    let sensitive_view = pure_list_query && modestring.chars().any(|c| matches!(c, 'w' | 'X' | 'g'));
    if (!pure_list_query || sensitive_view) && s.rank(uid, &key) < RANK_HALFOP {
        s.numeric(
            uid,
            ERR_CHANOPRIVSNEEDED,
            &format!("{target} :You're not a channel operator"),
        );
        return CmdResult::Fail;
    }
    let mut argi = 0usize;
    let mut sign = '+';
    let mut applied = String::new();
    let mut last = ' ';
    let mut echoed: Vec<String> = Vec::new();
    // (sign, letter, displayed-param) per applied change — for hidemode filtering
    let mut changes: Vec<(char, char, Option<String>)> = Vec::new();
    // Cap mode changes per command (advertised as MODES=, default 20):
    // otherwise `MODE #c +bbbb…` in one line dispatches hundreds of handlers, each
    // fanning out to the whole channel and every link — a cheap amplification flood.
    let max_modes = s.conf_num("modes", 20usize).max(1);
    let mut processed = 0usize;
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
        if processed >= max_modes {
            break;
        }
        processed += 1;
        let adding = sign == '+';
        let Some(handler) = chan_mode(c) else {
            s.numeric(
                uid,
                ERR_UNKNOWNMODE,
                &format!("{c} :is unknown mode char to me"),
            );
            continue;
        };
        let param = if handler.wants_param(adding) {
            let p = args.get(argi).cloned();
            if p.is_some() {
                argi += 1;
            }
            p
        } else {
            None
        };
        if let Applied::Yes(echo) = handler.apply(s, target, &key, uid, adding, param.as_deref()) {
            emit(&mut applied, &mut last, sign, c);
            changes.push((sign, c, echo.clone()));
            if let Some(p) = echo {
                echoed.push(p);
            }
        }
    }
    if !applied.is_empty() {
        let prefix = s.users[&uid].prefix();
        let pstr = if echoed.is_empty() {
            String::new()
        } else {
            format!(" {}", echoed.join(" "))
        };
        // hidemode: if any changed mode is configured hidden, deliver per-recipient
        // so members below the required rank don't see it; the setter, opers and
        // linked servers always get the full line.
        if changes
            .iter()
            .any(|(_, c, _)| crate::modules::hidemode::hidden_rank(s, *c).is_some())
        {
            crate::modules::hidemode::broadcast(s, &key, target, uid, &prefix, &changes);
        } else {
            s.to_channel(
                &key,
                &format!(":{prefix} MODE {target} {applied}{pstr}"),
                None,
            );
        }
        // links: a timestamped FMODE sourced from the acting user's uuid
        let src_uuid = s.users[&uid].uuid.clone();
        s.propagate_chan_mode(&src_uuid, target, &applied, &echoed);
    }
    // A mode change may have removed the channel's last reason to exist while it has
    // no members (e.g. -P / -r on an empty channel): destroy it now, as an empty
    // channel is normally culled the moment its final member leaves.
    let cull = s.channels.get(&key).is_some_and(|c| !c.keep_alive());
    if cull {
        s.channels.remove(&key);
    }
    CmdResult::Ok
}

/// Apply channel modes with **server** authority (no acting user) — for the RPC
/// `channel.set_mode`. Same per-letter dispatch as [`apply_mode`] under `mode_sudo`
/// (so every rank gate passes), but the resulting `MODE` line is sourced from the
/// server, not a user. The handlers only ever touch the actor uid through
/// `s.rank()` (maxed by sudo) or `s.users.get()` (safe on the `0` sentinel), so no
/// live actor is needed. Returns whether anything actually changed.
pub fn svs_set_chan_modes(s: &mut Server, target: &str, modestring: &str, args: &[String]) -> bool {
    let key = target.to_ascii_lowercase();
    if !s.channels.contains_key(&key) {
        return false;
    }
    s.mode_sudo = true;
    let mut argi = 0usize;
    let mut sign = '+';
    let mut applied = String::new();
    let mut last = ' ';
    let mut echoed: Vec<String> = Vec::new();
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
        let adding = sign == '+';
        let Some(handler) = chan_mode(c) else {
            continue;
        };
        let param = if handler.wants_param(adding) {
            let p = args.get(argi).cloned();
            if p.is_some() {
                argi += 1;
            }
            p
        } else {
            None
        };
        if let Applied::Yes(echo) = handler.apply(s, target, &key, 0, adding, param.as_deref()) {
            emit(&mut applied, &mut last, sign, c);
            if let Some(p) = echo {
                echoed.push(p);
            }
        }
    }
    s.mode_sudo = false;
    if applied.is_empty() {
        return false;
    }
    let pstr = if echoed.is_empty() {
        String::new()
    } else {
        format!(" {}", echoed.join(" "))
    };
    s.to_channel(
        &key,
        &format!(":{} MODE {target} {applied}{pstr}", s.name),
        None,
    );
    // links: a timestamped FMODE sourced from this server's sid
    let sid = s.sid.clone();
    s.propagate_chan_mode(&sid, target, &applied, &echoed);
    true
}

/// Apply a client `+s`/`-s` snomask change. Oper-only. `+s` with a mask edits the
/// subscribed categories (`+cq` adds, `-c` removes, `*` all); `+s` with no mask
/// subscribes to everything; `-s` clears it. Emits `RPL_SNOMASKIS` (008) and returns
/// whether the `s` mode char should appear in the MODE echo.
fn apply_snomask(s: &mut Server, uid: Uid, adding: bool, param: Option<&str>) -> bool {
    if !s.is_oper(uid) {
        s.numeric(
            uid,
            crate::numeric::ERR_NOPRIVILEGES,
            ":Permission denied - only operators may set a server notice mask",
        );
        return false;
    }
    let mut cats: std::collections::BTreeSet<char> = s
        .users
        .get(&uid)
        .map(|u| u.flags.snomask_cats.chars().collect())
        .unwrap_or_default();
    let all = || crate::users::DEFAULT_SNOMASK.chars().collect::<std::collections::BTreeSet<char>>();
    if !adding {
        cats.clear();
    } else {
        match param {
            None => cats = all(),
            Some(p) => {
                let mut sign = '+';
                for c in p.chars() {
                    match c {
                        '+' => sign = '+',
                        '-' => sign = '-',
                        '*' => cats = if sign == '+' { all() } else { Default::default() },
                        c if crate::users::DEFAULT_SNOMASK.contains(c) => {
                            if sign == '+' {
                                cats.insert(c);
                            } else {
                                cats.remove(&c);
                            }
                        }
                        _ => {} // ignore unknown snomask letters
                    }
                }
            }
        }
    }
    let mask: String = cats.iter().collect();
    let on = !mask.is_empty();
    if let Some(u) = s.users.get_mut(&uid) {
        u.flags.snomask = on;
        u.flags.snomask_cats = mask.clone();
    }
    s.numeric(
        uid,
        crate::numeric::RPL_SNOMASKIS,
        &format!("+{mask} :Server notice mask"),
    );
    if adding {
        on
    } else {
        true
    }
}

/// User modes: dispatched to the [`crate::mode`] `UserMode` handler objects.
fn apply_user_modes(s: &mut Server, uid: Uid, target: &str, params: &[String]) -> CmdResult {
    let me = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    if !target.eq_ignore_ascii_case(&me) {
        s.numeric(
            uid,
            ERR_USERSDONTMATCH,
            ":Can't change mode for other users",
        );
        return CmdResult::Ok;
    }
    if params.len() < 2 {
        let um = s
            .users
            .get(&uid)
            .map(|u| u.flags.umodes())
            .unwrap_or_else(|| "+".to_string());
        s.numeric(uid, RPL_UMODEIS, &um);
        return CmdResult::Ok;
    }
    let modestring = params[1].clone();
    let mut sign = '+';
    let mut applied = String::new();
    let mut last = ' ';
    let mut argi = 2usize; // params[2..] are mode arguments (the +s snomask mask)
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
        let adding = sign == '+';
        // +s is a parametric snomask mode: it consumes the following mask argument
        if c == 's' {
            let param = if adding {
                let p = params.get(argi).cloned();
                if p.is_some() {
                    argi += 1;
                }
                p
            } else {
                None
            };
            if apply_snomask(s, uid, adding, param.as_deref()) {
                emit(&mut applied, &mut last, sign, c);
            }
            continue;
        }
        let Some(handler) = user_mode(c) else {
            s.numeric(
                uid,
                ERR_UMODEUNKNOWNFLAG,
                &format!(":Unknown MODE flag {c}"),
            );
            continue;
        };
        if handler.apply(s, uid, adding) {
            emit(&mut applied, &mut last, sign, c);
        }
    }
    if !applied.is_empty() {
        s.send(uid, format!(":{me} MODE {me} :{applied}"));
    }
    CmdResult::Ok
}
