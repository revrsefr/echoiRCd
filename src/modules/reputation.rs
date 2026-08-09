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

const REP_CAP: u32 = 100_000;
const SAVE_EVERY: u32 = 20; // ticks between disk saves (~5 min at TICK_SECS=15)

/// per-IP reputation score. Stored in `Server.ext`.
#[derive(Default)]
pub struct Reputation(pub HashMap<IpAddr, u32>);

/// The tick-driven accrual + periodic save. Holds a tick counter of its own.
#[derive(Default)]
pub struct ReputationMod {
    ticks: u32,
}
impl Module for ReputationMod {
    fn name(&self) -> &'static str {
        "reputation"
    }
    fn on_tick(&mut self, s: &mut Server) {
        let ips: Vec<IpAddr> = s
            .users
            .values()
            .filter(|u| u.registered)
            .map(|u| u.addr.ip())
            .collect();
        let store = s.ext.get_or_insert_with::<Reputation>(Reputation::default);
        for ip in ips {
            let e = store.0.entry(ip).or_insert(0);
            *e = (*e + 1).min(REP_CAP);
        }
        self.ticks += 1;
        if self.ticks % SAVE_EVERY == 0 {
            save(s);
        }
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
            s.ext
                .get_or_insert_with::<Reputation>(Reputation::default)
                .0
                .insert(ip, val.min(REP_CAP));
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
