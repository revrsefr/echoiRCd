//! core_mode — the MODE command. Both channel and user modes are dispatched to
//! the handler objects in [`crate::mode`] (InspIRCd-style `ModeHandler`s); this
//! file just parses the modestring and orchestrates.

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
    if !pure_list_query && s.rank(uid, &key) < RANK_HALFOP {
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
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
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
        s.to_channel(
            &key,
            &format!(":{prefix} MODE {target} {applied}{pstr}"),
            None,
        );
        s.propagate_from_user(uid, &format!("MODE {target} {applied}{pstr}"));
        // links
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
    s.propagate(&format!(":{} MODE {target} {applied}{pstr}", s.sid), None); // links
    true
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
    for c in modestring.chars() {
        if c == '+' || c == '-' {
            sign = c;
            continue;
        }
        let adding = sign == '+';
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
