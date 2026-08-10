//! core_extra — the standard informational / utility commands a full ircd is
//! expected to answer: LIST, WHOWAS, USERHOST, ISON, TIME, ADMIN, INFO, STATS, MAP.

use crate::command::{CmdResult, Command};
use crate::numeric::*;
use crate::server::{iso_time, now, Server, VERSION};
use crate::xline::XKind;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![
        Box::new(List),
        Box::new(Whowas),
        Box::new(UserHost),
        Box::new(IsOn),
        Box::new(Time),
        Box::new(Admin),
        Box::new(Info),
        Box::new(Stats),
        Box::new(Map),
    ]
}

struct List;
impl Command for List {
    fn name(&self) -> &'static str {
        "LIST"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(uid, RPL_LISTSTART, "Channel :Users Name");
        let keys: Vec<String> = s.channels.keys().cloned().collect();
        for key in keys {
            let ch = &s.channels[&key];
            // hide secret / private channels from non-members
            if (ch.modes.secret || ch.modes.private) && !ch.members.contains_key(&uid) {
                continue;
            }
            let count = ch.members.len() + ch.rmembers.len();
            let topic = ch
                .topic
                .as_ref()
                .map(|t| t.text.clone())
                .unwrap_or_default();
            let name = ch.name.clone();
            s.numeric(uid, RPL_LIST, &format!("{name} {count} :{topic}"));
        }
        s.numeric(uid, RPL_LISTEND, ":End of /LIST");
        CmdResult::Ok
    }
}

struct Whowas;
impl Command for Whowas {
    fn name(&self) -> &'static str {
        "WHOWAS"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = &params[0];
        let want = target.to_ascii_lowercase();
        let limit = params
            .get(1)
            .and_then(|c| c.parse::<usize>().ok())
            .unwrap_or(8);
        let hits: Vec<(String, String, String, String, u64)> = s
            .whowas
            .iter()
            .filter(|e| e.nick.to_ascii_lowercase() == want)
            .take(limit)
            .map(|e| {
                (
                    e.nick.clone(),
                    e.ident.clone(),
                    e.host.clone(),
                    e.realname.clone(),
                    e.ts,
                )
            })
            .collect();
        if hits.is_empty() {
            s.numeric(
                uid,
                ERR_WASNOSUCHNICK,
                &format!("{target} :There was no such nickname"),
            );
        }
        for (nick, ident, host, realname, ts) in hits {
            s.numeric(
                uid,
                RPL_WHOWASUSER,
                &format!("{nick} {ident} {host} * :{realname}"),
            );
            s.numeric(
                uid,
                RPL_WHOISSERVER,
                &format!("{nick} {} :{}", s.name, iso_time(ts)),
            );
        }
        s.numeric(uid, RPL_ENDOFWHOWAS, &format!("{target} :End of WHOWAS"));
        CmdResult::Ok
    }
}

struct UserHost;
impl Command for UserHost {
    fn name(&self) -> &'static str {
        "USERHOST"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let mut parts: Vec<String> = Vec::new();
        for nick in params.iter().take(5) {
            if let Some(tuid) = s.find_nick(nick) {
                if let Some(u) = s.users.get(&tuid) {
                    let star = if u.flags.oper { "*" } else { "" };
                    let here = if u.flags.away.is_some() { "-" } else { "+" };
                    parts.push(format!(
                        "{}{star}={here}{}@{}",
                        u.nick,
                        u.ident,
                        u.host_display()
                    ));
                }
            }
        }
        s.numeric(uid, RPL_USERHOST, &format!(":{}", parts.join(" ")));
        CmdResult::Ok
    }
}

struct IsOn;
impl Command for IsOn {
    fn name(&self) -> &'static str {
        "ISON"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let on: Vec<String> = params
            .iter()
            .flat_map(|p| p.split_whitespace())
            .filter(|n| s.find_nick(n).is_some() || s.find_remote(n).is_some())
            .map(|n| n.to_string())
            .collect();
        s.numeric(uid, RPL_ISON, &format!(":{}", on.join(" ")));
        CmdResult::Ok
    }
}

struct Time;
impl Command for Time {
    fn name(&self) -> &'static str {
        "TIME"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(uid, RPL_TIME, &format!("{} :{}", s.name, iso_time(now())));
        CmdResult::Ok
    }
}

struct Admin;
impl Command for Admin {
    fn name(&self) -> &'static str {
        "ADMIN"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(
            uid,
            RPL_ADMINME,
            &format!("{} :Administrative info", s.name),
        );
        s.numeric(uid, RPL_ADMINLOC1, &format!(":{} IRC network", s.network));
        s.numeric(
            uid,
            RPL_ADMINLOC2,
            ":echoIRCd — a from-scratch ircd in Rust",
        );
        s.numeric(uid, RPL_ADMINEMAIL, &format!(":admin@{}", s.name));
        CmdResult::Ok
    }
}

struct Info;
impl Command for Info {
    fn name(&self) -> &'static str {
        "INFO"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        for line in [
            format!("echoircd-{VERSION} — a from-scratch IRC daemon in Rust"),
            "Memory-safe by construction; no unsafe code".to_string(),
            format!("Running the {} network", s.network),
        ] {
            s.numeric(uid, RPL_INFO, &format!(":{line}"));
        }
        s.numeric(uid, RPL_ENDOFINFO, ":End of /INFO list");
        CmdResult::Ok
    }
}

struct Stats;
impl Command for Stats {
    fn name(&self) -> &'static str {
        "STATS"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let letter = params[0].chars().next().unwrap_or(' ');
        // everything but uptime exposes server internals — opers only
        if letter != 'u' && !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            s.numeric(
                uid,
                RPL_ENDOFSTATS,
                &format!("{letter} :End of /STATS report"),
            );
            return CmdResult::Fail;
        }
        match letter {
            'u' => {
                let up = now().saturating_sub(s.created);
                let (d, h, m, sec) = (up / 86400, (up % 86400) / 3600, (up % 3600) / 60, up % 60);
                s.numeric(
                    uid,
                    RPL_STATSUPTIME,
                    &format!(":Server Up {d} days {h:02}:{m:02}:{sec:02}"),
                );
            }
            'o' => {
                let opers: Vec<String> = s.opers.iter().map(|(n, _)| n.clone()).collect();
                for n in opers {
                    s.numeric(uid, RPL_STATSOLINE, &format!("O * * {n} :oper"));
                }
            }
            'k' | 'g' | 'z' | 'e' | 'q' | 's' | 'S' => {
                let kind = match letter {
                    'k' => XKind::Kline,
                    'g' => XKind::Gline,
                    'z' => XKind::Zline,
                    'e' => XKind::Eline,
                    'q' => XKind::Qline,
                    'S' => XKind::Svshold,
                    _ => XKind::Shun,
                };
                let rows: Vec<String> = s
                    .xlines
                    .iter()
                    .filter(|x| x.kind == kind)
                    .map(|x| {
                        format!(
                            "{} {} {} {} :{}",
                            x.kind.tag(),
                            x.mask,
                            x.expires,
                            x.setter,
                            x.reason
                        )
                    })
                    .collect();
                for r in rows {
                    s.numeric(uid, RPL_STATSXLINE, &r);
                }
            }
            'l' => {
                for sv in s.servers.values() {
                    s.numeric(
                        uid,
                        RPL_STATSLINKINFO,
                        &format!("{} 0 0 0 0 :{}", sv.name, sv.desc),
                    );
                }
            }
            _ => {}
        }
        s.numeric(
            uid,
            RPL_ENDOFSTATS,
            &format!("{letter} :End of /STATS report"),
        );
        CmdResult::Ok
    }
}

struct Map;
impl Command for Map {
    fn name(&self) -> &'static str {
        "MAP"
    }
    fn handle(&self, s: &mut Server, uid: Uid, _params: &[String]) -> CmdResult {
        s.numeric(
            uid,
            RPL_MAP,
            &format!("{} ({} users)", s.name, s.users.len()),
        );
        let mut peers: Vec<String> = s.servers.values().map(|sv| sv.name.clone()).collect();
        peers.sort();
        for name in peers {
            s.numeric(uid, RPL_MAP, &format!("`- {name}"));
        }
        s.numeric(uid, RPL_MAPEND, ":End of /MAP");
        CmdResult::Ok
    }
}
