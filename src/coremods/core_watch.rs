//! WATCH, MONITOR (IRCv3), SILENCE and ACCEPT. The per-user lists live on the
//! `User`; online/offline notifications are driven from the lifecycle code via
//! [`crate::server::Server::watch_notify_online`] / `_offline`.

use crate::channels::normalize_mask;
use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::Server;
use crate::watch::{ACCEPT_MAX, MONITOR_MAX, SILENCE_MAX, WATCH_MAX};
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(Watch),
        Box::new(Monitor),
        Box::new(Silence),
        Box::new(Signore),
        Box::new(Accept),
    ]
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
    let maxwatch = s.conf_num("maxwatch", WATCH_MAX);
    let full = s
        .users
        .get(&uid)
        .map(|u| u.watch.len() >= maxwatch && !u.watch.contains(&low))
        .unwrap_or(true);
    if full {
        s.numeric(
            uid,
            ERR_TOOMANYWATCH,
            &format!("{nick} :Maximum size for WATCH-list exceeded"),
        );
        return;
    }
    s.watch_index_add(uid, low);
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
                    s.watch_index_clear(uid);
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
                    s.watch_index_remove(uid, &low);
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
                    let maxmon = s.conf_num("maxmonitor", MONITOR_MAX);
                    let full = s
                        .users
                        .get(&uid)
                        .map(|u| u.monitor.len() >= maxmon && !u.monitor.contains(&low))
                        .unwrap_or(true);
                    if full {
                        s.numeric(
                            uid,
                            ERR_MONLISTFULL,
                            &format!("{maxmon} {t} :Monitor list is full"),
                        );
                        continue;
                    }
                    s.monitor_index_add(uid, low);
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
                for t in &targets {
                    s.monitor_index_remove(uid, t);
                }
            }
            "C" => {
                s.monitor_index_clear(uid);
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
            let maxsil = s.conf_num("maxsilence", SILENCE_MAX);
            let full = s
                .users
                .get(&uid)
                .map(|u| u.silence.len() >= maxsil && !u.silence.contains(&mask))
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

// --- SIGNORE (personal mutual server-side ignore) ---------------------------

fn signore_list(s: &Server, uid: Uid) {
    let (nick, list) = s
        .users
        .get(&uid)
        .map(|u| (u.nick.clone(), u.signore.clone()))
        .unwrap_or_default();
    let sn = &s.name;
    if list.is_empty() {
        s.send(uid, format!(":{sn} NOTICE {nick} :Your SIGNORE list is empty."));
    } else {
        for m in &list {
            s.send(uid, format!(":{sn} NOTICE {nick} :SIGNORE {m}"));
        }
    }
    s.send(uid, format!(":{sn} NOTICE {nick} :End of SIGNORE list."));
}

/// SIGNORE — a personal, mutual server-side ignore. `SIGNORE <mask>` (or `+mask`)
/// blocks a user both ways: neither of you sees the other's channel or private
/// messages. `SIGNORE -<mask>` lifts it; a bare `SIGNORE` lists your masks. A bare
/// nick becomes `nick!*@*`.
struct Signore;
impl Command for Signore {
    fn name(&self) -> &'static str {
        "SIGNORE"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let Some(arg) = params.first() else {
            signore_list(s, uid);
            return CmdResult::Ok;
        };
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let sn = s.name.clone();
        let (add, raw) = match arg.strip_prefix('-') {
            Some(m) => (false, m),
            None => (true, arg.strip_prefix('+').unwrap_or(arg)),
        };
        if raw.is_empty() {
            signore_list(s, uid);
            return CmdResult::Ok;
        }
        let mask = normalize_mask(raw);
        if add {
            let max = s.conf_num("maxsignore", 64usize);
            let full = s
                .users
                .get(&uid)
                .map(|u| u.signore.len() >= max && !u.signore.contains(&mask))
                .unwrap_or(true);
            if full {
                s.send(uid, format!(":{sn} NOTICE {nick} :Your SIGNORE list is full ({max} max)."));
                return CmdResult::Fail;
            }
            if let Some(u) = s.users.get_mut(&uid) {
                if !u.signore.contains(&mask) {
                    u.signore.push(mask.clone());
                }
            }
            s.send(uid, format!(":{sn} NOTICE {nick} :SIGNORE \x02{mask}\x02 added — you and they can no longer see each other's messages."));
        } else {
            if let Some(u) = s.users.get_mut(&uid) {
                u.signore.retain(|x| x != &mask);
            }
            s.send(uid, format!(":{sn} NOTICE {nick} :SIGNORE \x02{mask}\x02 removed."));
        }
        // Persist the change to the user's services account (no-op if not logged in).
        s.push_signore_to_services(uid);
        CmdResult::Ok
    }
}

// --- ACCEPT (callerid +g allow-list) ----------------------------------------

fn accept_list(s: &Server, uid: Uid) {
    let list = s
        .users
        .get(&uid)
        .map(|u| u.accept.clone())
        .unwrap_or_default();
    for n in list {
        s.numeric(uid, RPL_ACCEPTLIST, &n);
    }
    s.numeric(uid, RPL_ENDOFACCEPT, ":End of ACCEPT list");
}

struct Accept;
impl Command for Accept {
    fn name(&self) -> &'static str {
        "ACCEPT"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let first = params.first().map(|a| a.as_str()).unwrap_or("");
        if first.is_empty() || first == "*" {
            accept_list(s, uid);
            return CmdResult::Ok;
        }
        for tok in params
            .iter()
            .flat_map(|p| p.split([',', ' ']))
            .filter(|t| !t.is_empty())
        {
            if tok == "*" {
                accept_list(s, uid);
                continue;
            }
            let (adding, name) = match tok.strip_prefix('-') {
                Some(n) => (false, n),
                None => (true, tok.strip_prefix('+').unwrap_or(tok)),
            };
            if name.is_empty() {
                continue;
            }
            let low = name.to_ascii_lowercase();
            if adding {
                let maxacc = s.conf_num("maxaccept", ACCEPT_MAX);
                let (full, exists) = s
                    .users
                    .get(&uid)
                    .map(|u| (u.accept.len() >= maxacc, u.accept.contains(&low)))
                    .unwrap_or((true, false));
                if exists {
                    s.numeric(
                        uid,
                        ERR_ACCEPTEXIST,
                        &format!("{name} :is already on your accept list"),
                    );
                } else if full {
                    s.numeric(
                        uid,
                        ERR_ACCEPTFULL,
                        &format!("{name} :Your accept list is full"),
                    );
                } else {
                    s.accept_add(uid, low);
                }
            } else {
                let existed = s
                    .users
                    .get(&uid)
                    .map(|u| u.accept.contains(&low))
                    .unwrap_or(false);
                if !existed {
                    s.numeric(
                        uid,
                        ERR_ACCEPTNOT,
                        &format!("{name} :is not on your accept list"),
                    );
                } else {
                    s.accept_remove(uid, &low);
                }
            }
        }
        CmdResult::Ok
    }
}
