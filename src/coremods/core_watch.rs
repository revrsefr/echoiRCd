//! core_watch — WATCH, MONITOR (IRCv3) and SILENCE. The per-user lists live on
//! the `User`; the online/offline notifications are driven from the lifecycle
//! code via [`crate::server::Server::watch_notify_online`] / `_offline`. Mirrors
//! InspIRCd's `m_watch` / `m_monitor` / `m_silence`.

use crate::channels::normalize_mask;
use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::Server;
use crate::watch::{MONITOR_MAX, SILENCE_MAX, WATCH_MAX};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Watch), Box::new(Monitor), Box::new(Silence)]
}

// --- WATCH ------------------------------------------------------------------

/// Report a nick's current presence as RPL_NOWON (604) or RPL_NOWOFF (605).
fn watch_status(s: &Server, uid: Uid, nick: &str) {
    if let Some(u) = s.find_nick(nick).and_then(|tu| s.users.get(&tu)) {
        s.numeric(
            uid,
            RPL_NOWON,
            &format!(
                "{} {} {} {} :is online",
                u.nick,
                u.ident,
                u.host_display(),
                u.signon
            ),
        );
    } else {
        s.numeric(uid, RPL_NOWOFF, &format!("{nick} * * 0 :is offline"));
    }
}

fn watch_add(s: &mut Server, uid: Uid, nick: &str) {
    if nick.is_empty() {
        return;
    }
    let low = nick.to_ascii_lowercase();
    let full = s
        .users
        .get(&uid)
        .map(|u| u.watch.len() >= WATCH_MAX && !u.watch.contains(&low))
        .unwrap_or(true);
    if full {
        s.numeric(
            uid,
            ERR_TOOMANYWATCH,
            &format!("{nick} :Maximum size for WATCH-list exceeded"),
        );
        return;
    }
    if let Some(u) = s.users.get_mut(&uid) {
        if !u.watch.contains(&low) {
            u.watch.push(low);
        }
    }
    watch_status(s, uid, nick);
}

fn watch_list(s: &Server, uid: Uid, online_only: bool) {
    let nicks = s
        .users
        .get(&uid)
        .map(|u| u.watch.clone())
        .unwrap_or_default();
    for n in nicks {
        // `l` (online-only) skips offline entries; `L` shows all
        if !online_only || s.find_nick(&n).is_some() {
            watch_status(s, uid, &n);
        }
    }
    s.numeric(uid, RPL_ENDOFWATCHLIST, ":End of WATCH list");
}

struct Watch;
impl Command for Watch {
    fn name(&self) -> &'static str {
        "WATCH"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if params.is_empty() {
            watch_list(s, uid, true); // bare WATCH lists your online entries
            return CmdResult::Ok;
        }
        for tok in params.iter().flat_map(|p| p.split_whitespace()) {
            match tok {
                "C" | "c" => {
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.watch.clear();
                    }
                    s.numeric(uid, RPL_ENDOFWATCHLIST, ":End of WATCH list");
                }
                "S" | "s" => {
                    let (mine, watched) = s
                        .users
                        .get(&uid)
                        .map(|u| (u.watch.len(), u.watch.clone()))
                        .unwrap_or((0, Vec::new()));
                    let me = s
                        .users
                        .get(&uid)
                        .map(|u| u.nick.clone())
                        .unwrap_or_default();
                    let on_me = s.watchers_of(&me);
                    s.numeric(
                        uid,
                        RPL_WATCHSTAT,
                        &format!(":You have {mine} and are on {on_me} WATCH entries"),
                    );
                    if !watched.is_empty() {
                        s.numeric(uid, RPL_WATCHLIST, &format!(":{}", watched.join(" ")));
                    }
                    s.numeric(uid, RPL_ENDOFWATCHLIST, ":End of WATCH S");
                }
                "L" => watch_list(s, uid, false),
                "l" => watch_list(s, uid, true),
                _ if tok.starts_with('+') => watch_add(s, uid, &tok[1..]),
                _ if tok.starts_with('-') => {
                    let low = tok[1..].to_ascii_lowercase();
                    if let Some(u) = s.users.get_mut(&uid) {
                        u.watch.retain(|n| n != &low);
                    }
                    s.numeric(
                        uid,
                        RPL_WATCHOFF,
                        &format!("{} * * 0 :stopped watching", &tok[1..]),
                    );
                }
                _ => {}
            }
        }
        CmdResult::Ok
    }
}

// --- MONITOR (IRCv3) --------------------------------------------------------

/// Report the online/offline split of `nicks` to `uid` (730 / 731).
fn monitor_report(s: &Server, uid: Uid, nicks: &[String]) {
    let mut online = Vec::new();
    let mut offline = Vec::new();
    for n in nicks {
        match s.find_nick(n).and_then(|tu| s.users.get(&tu)) {
            Some(u) => online.push(format!("{}!{}@{}", u.nick, u.ident, u.host_display())),
            None => offline.push(n.clone()),
        }
    }
    if !online.is_empty() {
        s.numeric(uid, RPL_MONONLINE, &format!(":{}", online.join(",")));
    }
    if !offline.is_empty() {
        s.numeric(uid, RPL_MONOFFLINE, &format!(":{}", offline.join(",")));
    }
}

struct Monitor;
impl Command for Monitor {
    fn name(&self) -> &'static str {
        "MONITOR"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        match params[0].to_ascii_uppercase().as_str() {
            "+" => {
                let targets: Vec<String> = params
                    .get(1)
                    .map(|t| {
                        t.split(',')
                            .filter(|x| !x.is_empty())
                            .map(String::from)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut added = Vec::new();
                for t in targets {
                    let low = t.to_ascii_lowercase();
                    let full = s
                        .users
                        .get(&uid)
                        .map(|u| u.monitor.len() >= MONITOR_MAX && !u.monitor.contains(&low))
                        .unwrap_or(true);
                    if full {
                        s.numeric(
                            uid,
                            ERR_MONLISTFULL,
                            &format!("{MONITOR_MAX} {t} :Monitor list is full"),
                        );
                        continue;
                    }
                    if let Some(u) = s.users.get_mut(&uid) {
                        if !u.monitor.contains(&low) {
                            u.monitor.push(low);
                        }
                    }
                    added.push(t);
                }
                monitor_report(s, uid, &added);
            }
            "-" => {
                let targets: Vec<String> = params
                    .get(1)
                    .map(|t| {
                        t.split(',')
                            .filter(|x| !x.is_empty())
                            .map(|x| x.to_ascii_lowercase())
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(u) = s.users.get_mut(&uid) {
                    u.monitor.retain(|n| !targets.contains(n));
                }
            }
            "C" => {
                if let Some(u) = s.users.get_mut(&uid) {
                    u.monitor.clear();
                }
            }
            "L" => {
                let list = s
                    .users
                    .get(&uid)
                    .map(|u| u.monitor.clone())
                    .unwrap_or_default();
                if !list.is_empty() {
                    s.numeric(uid, RPL_MONLIST, &format!(":{}", list.join(",")));
                }
                s.numeric(uid, RPL_ENDOFMONLIST, ":End of MONITOR list");
            }
            "S" => {
                let list = s
                    .users
                    .get(&uid)
                    .map(|u| u.monitor.clone())
                    .unwrap_or_default();
                monitor_report(s, uid, &list);
            }
            _ => {}
        }
        CmdResult::Ok
    }
}

// --- SILENCE ----------------------------------------------------------------

fn silence_list(s: &Server, uid: Uid) {
    let list = s
        .users
        .get(&uid)
        .map(|u| u.silence.clone())
        .unwrap_or_default();
    for m in list {
        s.numeric(uid, RPL_SILELIST, &m);
    }
    s.numeric(uid, RPL_ENDOFSILENCE, ":End of SILENCE list");
}

struct Silence;
impl Command for Silence {
    fn name(&self) -> &'static str {
        "SILENCE"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let Some(arg) = params.first() else {
            silence_list(s, uid);
            return CmdResult::Ok;
        };
        let prefix = s.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
        if let Some(m) = arg.strip_prefix('+') {
            let mask = normalize_mask(m);
            let full = s
                .users
                .get(&uid)
                .map(|u| u.silence.len() >= SILENCE_MAX && !u.silence.contains(&mask))
                .unwrap_or(true);
            if full {
                s.numeric(
                    uid,
                    ERR_SILELISTFULL,
                    &format!("{mask} :Your SILENCE list is full"),
                );
                return CmdResult::Fail;
            }
            if let Some(u) = s.users.get_mut(&uid) {
                if !u.silence.contains(&mask) {
                    u.silence.push(mask.clone());
                }
            }
            s.send(uid, format!(":{prefix} SILENCE +{mask}"));
        } else if let Some(m) = arg.strip_prefix('-') {
            let mask = normalize_mask(m);
            if let Some(u) = s.users.get_mut(&uid) {
                u.silence.retain(|x| x != &mask);
            }
            s.send(uid, format!(":{prefix} SILENCE -{mask}"));
        } else {
            silence_list(s, uid);
        }
        CmdResult::Ok
    }
}
