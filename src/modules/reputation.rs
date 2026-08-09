//! reputation — InspIRCd `m_reputation`. Tracks a per-IP reputation score that
//! accrues while users from that IP stay connected (roughly, time-online), so
//! opers can tell established users apart from fresh/throwaway connections.
//! Self-contained: the scores live in `Server.ext`, accrue on the tick, and
//! persist to `<conf>.reputation`. `REPUTATION` reads/sets a user's score.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::command::{CmdResult, Command};
use crate::module::Module;
use crate::numeric::{ERR_NOPRIVILEGES, ERR_NOSUCHNICK};
use crate::server::Server;
use crate::Uid;

/// per-IP reputation score. Stored in `Server.ext`.
#[derive(Default)]
pub struct Reputation(pub HashMap<IpAddr, u32>);

/// Whether `uid` is in at least one channel with `min` or more members (the
/// reputation `minchanmembers` gate — stops idle bots farming score alone).
fn in_active_channel(s: &Server, uid: Uid, min: usize) -> bool {
    if min <= 1 {
        return true;
    }
    s.users
        .get(&uid)
        .map(|u| {
            u.channels.iter().any(|k| {
                s.channels
                    .get(k)
                    .map(|c| c.members.len() >= min)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// The tick-driven accrual + periodic save. Bumps every `rep_bump_secs` (default
/// 5 min): +1 per connected user's IP, +1 more if they're logged into an account.
#[derive(Default)]
pub struct ReputationMod {
    secs: u64, // seconds since the last bump
    since_save: u64,
}
impl Module for ReputationMod {
    fn name(&self) -> &'static str {
        "reputation"
    }
    fn on_tick(&mut self, s: &mut Server) {
        self.secs += crate::server::TICK_SECS;
        self.since_save += crate::server::TICK_SECS;
        if self.secs < s.rep_bump_secs {
            return;
        }
        self.secs = 0;
        let cap = s.rep_scorecap;
        let min = s.rep_minchanmembers;
        // (ip, bump amount): +1 base, +1 if the user is logged into services
        let bumps: Vec<(IpAddr, u32)> = s
            .users
            .values()
            .filter(|u| u.registered)
            .filter(|u| in_active_channel(s, u.uid, min))
            .map(|u| (u.addr.ip(), if u.account.is_some() { 2 } else { 1 }))
            .collect();
        let store = s.ext.get_or_insert_with::<Reputation>(Reputation::default);
        for (ip, amt) in bumps {
            let e = store.0.entry(ip).or_insert(0);
            *e = (*e + amt).min(cap);
        }
        if self.since_save >= 600 {
            self.since_save = 0;
            save(s);
        }
    }
}

/// The reputation score of the IP `uid` is connecting from.
pub fn score_of(s: &Server, uid: Uid) -> u32 {
    let Some(ip) = s.users.get(&uid).map(|u| u.addr.ip()) else {
        return 0;
    };
    s.ext
        .get::<Reputation>()
        .and_then(|r| r.0.get(&ip))
        .copied()
        .unwrap_or(0)
}

/// The `y:` score extban: `y:<N` matches a score below N, `y:>N` above N.
pub fn score_ban_match(s: &Server, uid: Uid, spec: &str) -> bool {
    let (gt, num) = match spec.strip_prefix('>') {
        Some(n) => (true, n),
        None => (false, spec.strip_prefix('<').unwrap_or(spec)),
    };
    let Ok(threshold) = num.trim().parse::<u32>() else {
        return false;
    };
    let score = score_of(s, uid);
    if gt {
        score > threshold
    } else {
        score < threshold
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ReputationCmd)]
}

/// REPUTATION — `REPUTATION <nick> [<value>]` (oper). Show, or set, the reputation
/// of the IP `<nick>` is connecting from.
struct ReputationCmd;
impl Command for ReputationCmd {
    fn name(&self) -> &'static str {
        "REPUTATION"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let Some(tuid) = s.find_nick(&params[0]) else {
            s.numeric(
                uid,
                ERR_NOSUCHNICK,
                &format!("{} :No such nick/channel", params[0]),
            );
            return CmdResult::Fail;
        };
        let Some(ip) = s.users.get(&tuid).map(|u| u.addr.ip()) else {
            return CmdResult::Fail;
        };
        let nick = params[0].clone();
        let anick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        if let Some(val) = params.get(1).and_then(|v| v.parse::<u32>().ok()) {
            let cap = s.rep_scorecap;
            s.ext
                .get_or_insert_with::<Reputation>(Reputation::default)
                .0
                .insert(ip, val.min(cap));
            save(s);
            s.send(
                uid,
                format!(
                    ":{} NOTICE {anick} :REPUTATION {nick} ({ip}) set to {val}",
                    s.name
                ),
            );
        } else {
            let score = s
                .ext
                .get::<Reputation>()
                .and_then(|r| r.0.get(&ip))
                .copied()
                .unwrap_or(0);
            s.send(
                uid,
                format!(
                    ":{} NOTICE {anick} :REPUTATION {nick} ({ip}) = {score}",
                    s.name
                ),
            );
        }
        CmdResult::Ok
    }
}

fn db_path(s: &Server) -> String {
    format!("{}.reputation", s.conf_path)
}

/// Persist per-IP reputation so it survives a restart.
pub fn save(s: &Server) {
    let mut out = String::new();
    if let Some(r) = s.ext.get::<Reputation>() {
        for (ip, score) in &r.0 {
            out.push_str(&format!("{ip} {score}\n"));
        }
    }
    let _ = std::fs::write(db_path(s), out);
}

/// Reload persisted reputation at startup.
pub fn load(s: &mut Server) {
    let Ok(text) = std::fs::read_to_string(db_path(s)) else {
        return;
    };
    let store = s.ext.get_or_insert_with::<Reputation>(Reputation::default);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        if let (Some(ip), Some(sc)) = (it.next(), it.next()) {
            if let (Ok(ip), Ok(sc)) = (ip.parse::<IpAddr>(), sc.parse::<u32>()) {
                store.0.insert(ip, sc);
            }
        }
    }
}
