//! Per-network-address reputation scoring. Every `bumpinterval` (default 5m) each
//! connected user's masked address gains +1 (+2 if logged into services), provided
//! they're in a channel with at least `minchanmembers` members. Scores decay per the
//! `reputationexpire` rules and persist to disk. Exposes the `y:` score extban, WHOIS
//! visibility, and the `REPUTATION` oper command. Config-driven (see `[reputation_*]`).

use crate::map::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::command::{CmdResult, Command};
use crate::module::Module;
use crate::numeric::{ERR_NOPRIVILEGES, ERR_NOSUCHNICK};
use crate::server::{now, Server};
use crate::Uid;

/// One address's score plus when it was last active (for the decay rules).
#[derive(Clone, Default)]
pub struct Entry {
    pub score: u32,
    pub last_seen: u64,
}

/// masked-address -> entry. Stored in `Server.ext`.
#[derive(Default)]
pub struct Reputation(pub HashMap<IpAddr, Entry>);

/// Mask an address to the configured CIDR prefix so a whole subnet shares a score.
fn mask_ip(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let keep = match v4 {
                0 => 0,
                p if p >= 32 => u32::MAX,
                p => u32::MAX << (32 - p),
            };
            IpAddr::V4(Ipv4Addr::from(bits & keep))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let keep = match v6 {
                0 => 0,
                p if p >= 128 => u128::MAX,
                p => u128::MAX << (128 - p),
            };
            IpAddr::V6(Ipv6Addr::from(bits & keep))
        }
    }
}

// --- config accessors ----------------------------------------------------------
fn v4prefix(s: &Server) -> u8 {
    s.conf_num::<u8>("reputation_ipv4prefix", 32).clamp(1, 32)
}
fn v6prefix(s: &Server) -> u8 {
    s.conf_num::<u8>("reputation_ipv6prefix", 64).clamp(1, 128)
}
fn scorecap(s: &Server) -> u32 {
    s.conf_num("reputation_scorecap", 10000)
}
fn minchan(s: &Server) -> usize {
    s.conf_num("reputation_minchanmembers", 3)
}
fn dur(s: &Server, key: &str, def: u64) -> u64 {
    s.conf(key)
        .and_then(crate::xline::parse_duration)
        .filter(|&d| d > 0)
        .unwrap_or(def)
}
fn expire_rules(s: &Server) -> Vec<(i32, u64)> {
    let rules: Vec<(i32, u64)> = s
        .conf_all("reputationexpire")
        .iter()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let sc = it.next()?;
            let age = it.next()?;
            let score = if sc == "*" { -1 } else { sc.parse().ok()? };
            let age = crate::xline::parse_duration(age).filter(|&a| a > 0)?;
            Some((score, age))
        })
        .collect();
    if rules.is_empty() {
        // defaults: score<=2 after 1h, <=6 after 7d, <=12 after 30d, any after 90d
        vec![(2, 3600), (6, 604800), (12, 2592000), (-1, 7776000)]
    } else {
        rules
    }
}
fn db_path(s: &Server) -> String {
    match s.conf("reputation_database") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => format!("{}.reputation", s.conf_path),
    }
}

/// The masked key for `uid`'s address.
fn key_of(s: &Server, uid: Uid) -> Option<IpAddr> {
    let ip = s.users.get(&uid).map(|u| u.addr.ip())?;
    Some(mask_ip(ip, v4prefix(s), v6prefix(s)))
}

/// Whether `uid` is in at least one channel with `min` or more members (the
/// `minchanmembers` gate — stops idle bots farming score alone). Counts every
/// member, local AND remote (services bots, users on other servers), matching
/// the network-wide channel population — otherwise a user sharing a channel with
/// only remote/services members never bumps and their score freezes.
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
                    .map(|c| c.members.len() + c.rmembers.len() >= min)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// The tick-driven bump / expire / save. Tracks seconds since each last ran.
#[derive(Default)]
pub struct ReputationMod {
    since_bump: u64,
    since_expire: u64,
    since_save: u64,
}
impl Module for ReputationMod {
    fn name(&self) -> &'static str {
        "reputation"
    }
    fn on_tick(&mut self, s: &mut Server) {
        let t = crate::server::TICK_SECS;
        self.since_bump += t;
        self.since_expire += t;
        self.since_save += t;
        // Scores only ever change in bump_scores / expire_old, so persist right
        // after each: the on-disk table then always reflects the live one, and a
        // restart (however frequent) reloads the current scores instead of
        // reverting to whatever the coarse periodic timer last happened to write.
        if self.since_bump >= dur(s, "reputation_bumpinterval", 300) {
            self.since_bump = 0;
            bump_scores(s);
            save(s);
        }
        if self.since_expire >= dur(s, "reputation_expireinterval", 605) {
            self.since_expire = 0;
            expire_old(s);
            save(s);
        }
        // Backstop flush: guards any future mutation path that forgets to persist.
        if self.since_save >= dur(s, "reputation_saveinterval", 902) {
            self.since_save = 0;
            save(s);
        }
    }
}

/// +1 per connected user's masked address (+1 more if logged in), capped, and
/// refresh their last_seen so active addresses don't decay.
fn bump_scores(s: &mut Server) {
    let n = now();
    let cap = scorecap(s);
    let min = minchan(s);
    let (v4, v6) = (v4prefix(s), v6prefix(s));
    let bumps: Vec<(IpAddr, u32)> = s
        .users
        .values()
        .filter(|u| u.registered)
        .filter(|u| in_active_channel(s, u.uid, min))
        .map(|u| {
            (
                mask_ip(u.addr.ip(), v4, v6),
                if u.account.is_some() { 2 } else { 1 },
            )
        })
        .collect();
    let store = s.ext.get_or_insert_with::<Reputation>(Reputation::default);
    for (ip, amt) in bumps {
        let e = store.0.entry(ip).or_default();
        e.score = (e.score + amt).min(cap);
        e.last_seen = n;
    }
}

/// Drop entries that have aged out under any matching `reputationexpire` rule.
fn expire_old(s: &mut Server) {
    let n = now();
    let rules = expire_rules(s);
    if let Some(store) = s.ext.get_mut::<Reputation>() {
        store.0.retain(|_, e| {
            let expired = rules.iter().any(|&(score, age)| {
                age > 0
                    && n.saturating_sub(e.last_seen) > age
                    && (score == -1 || e.score <= score as u32)
            });
            !expired
        });
    }
}

/// The reputation score of the (masked) address `uid` is connecting from.
pub fn score_of(s: &Server, uid: Uid) -> u32 {
    let Some(k) = key_of(s, uid) else {
        return 0;
    };
    s.ext
        .get::<Reputation>()
        .and_then(|r| r.0.get(&k))
        .map(|e| e.score)
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

/// Whether the WHOIS `source` may see `target`'s reputation, per the `whois` mode.
pub fn whois_visible(s: &Server, source: Uid, target: Uid) -> bool {
    match s.conf("reputation_whois").unwrap_or("all") {
        "none" => false,
        "self" => source == target,
        "opers" => source == target || s.is_oper(source),
        _ => true, // "all"
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ReputationCmd)]
}

/// REPUTATION — `REPUTATION <nick> [<value>]` (oper). Show, or set, the reputation
/// of the masked address `<nick>` is connecting from.
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
        let Some(k) = key_of(s, tuid) else {
            return CmdResult::Fail;
        };
        let nick = params[0].clone();
        let anick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        if let Some(val) = params.get(1).and_then(|v| v.parse::<u32>().ok()) {
            let (cap, n) = (scorecap(s), now());
            let store = s.ext.get_or_insert_with::<Reputation>(Reputation::default);
            let e = store.0.entry(k).or_default();
            e.score = val.min(cap);
            e.last_seen = n;
            save(s);
            s.send(
                uid,
                format!(
                    ":{} NOTICE {anick} :REPUTATION {nick} ({k}) set to {val}",
                    s.name
                ),
            );
        } else {
            let score = score_of(s, tuid);
            s.send(
                uid,
                format!(
                    ":{} NOTICE {anick} :REPUTATION {nick} ({k}) = {score}",
                    s.name
                ),
            );
        }
        CmdResult::Ok
    }
}

/// Persist reputation (masked-ip score last_seen per line) so it survives a restart.
pub fn save(s: &Server) {
    let mut out = String::new();
    if let Some(r) = s.ext.get::<Reputation>() {
        for (ip, e) in &r.0 {
            out.push_str(&format!("{ip} {} {}\n", e.score, e.last_seen));
        }
    }
    s.disk_write(db_path(s), out); // off-core: a slow disk mustn't stall the event loop
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
            if let (Ok(ip), Ok(score)) = (ip.parse::<IpAddr>(), sc.parse::<u32>()) {
                let last_seen = it.next().and_then(|s| s.parse().ok()).unwrap_or_else(now);
                store.0.insert(ip, Entry { score, last_seen });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::{Channel, Member};
    use crate::config::Config;
    use crate::extensible::Extensible;
    use crate::socketengine::OutSink;
    use crate::users::{Caps, User, UserFlags};
    use crate::map::HashSet;
    use std::sync::atomic::AtomicU64;
    use std::sync::{mpsc, Arc};

    // The minchanmembers bump gate must count ALL members — local plus remote
    // (services bots, users on other servers) — like InspIRCd's GetUsers().size().
    // Regression: counting only local members froze the score of anyone sharing a
    // channel with remote/services members (e.g. reverse + a bot in #echoircd).
    #[test]
    fn active_channel_counts_remote_members() {
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        let (utx, _urx) = mpsc::channel();
        let mut chans = HashSet::default();
        chans.insert("#echoircd".to_string());
        s.users.insert(
            1,
            User {
                uid: 1,
                uuid: "0AAAAAAAB".into(),
                nick: "reverse".into(),
                ident: "r".into(),
                realname: "r".into(),
                host: "h".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                account: Some("reverse".into()),
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: chans,
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        // #echoircd: 1 local (reverse) + 2 remote (a user + a services bot) = 3 total
        let mut c = Channel::new("#echoircd");
        c.members.insert(1, Member::default());
        c.rmembers.insert("42SBOT0001".into(), Member::default());
        c.rmembers.insert("10HUSER002".into(), Member::default());
        s.channels.insert("#echoircd".into(), c);

        assert!(
            in_active_channel(&s, 1, 3),
            "3 total members (1 local + 2 remote) must satisfy minchanmembers=3"
        );

        // drop one remote member -> 2 total -> below the gate
        s.channels
            .get_mut("#echoircd")
            .unwrap()
            .rmembers
            .remove("10HUSER002");
        assert!(
            !in_active_channel(&s, 1, 3),
            "2 total members must not satisfy minchanmembers=3"
        );
    }
}
