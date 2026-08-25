//! `RMODE <channel> <listmode> [pattern]` — bulk-remove entries from a channel list
//! mode (`b` bans, `e` ban exceptions, `I` invite exceptions). With a `pattern` glob
//! only matching entries are cleared; without one, all are. Needs half-op+ (opers
//! bypass). Removals go through the normal mode engine (chunked to keep each `MODE`
//! line legal), so they broadcast and propagate like any other.

use crate::channels::{glob_match, RANK_HALFOP};
use crate::command::{CmdResult, Command};
use crate::coremods::core_mode::apply_mode;
use crate::numeric::{ERR_CHANOPRIVSNEEDED, ERR_NOSUCHCHANNEL};
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(RMode)]
}

struct RMode;
impl Command for RMode {
    fn name(&self) -> &'static str {
        "RMODE"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let chan = params[0].clone();
        let key = chan.to_ascii_lowercase();
        let Some(mode) = params[1].chars().find(|c| c.is_ascii_alphabetic()) else {
            let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
            s.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :RMODE usage: RMODE <channel> <b|e|I> [pattern]",
                    s.name
                ),
            );
            return CmdResult::Fail;
        };
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        let is_oper = s.is_oper(uid);
        if !is_oper && s.rank(uid, &key) < RANK_HALFOP {
            s.numeric(
                uid,
                ERR_CHANOPRIVSNEEDED,
                &format!("{chan} :You're not a channel operator"),
            );
            return CmdResult::Fail;
        }
        // collect the matching masks from the requested list mode
        let pattern = params.get(2).map(|p| p.as_str()).unwrap_or("*");
        let masks: Vec<String> = {
            let ch = &s.channels[&key];
            let list = match mode {
                'b' => &ch.bans,
                'e' => &ch.excepts,
                'I' => &ch.invex,
                _ => {
                    let nick = s
                        .users
                        .get(&uid)
                        .map(|u| u.nick.clone())
                        .unwrap_or_default();
                    s.send(
                        uid,
                        format!(
                            ":{} NOTICE {nick} :RMODE only supports list modes b, e, I",
                            s.name
                        ),
                    );
                    return CmdResult::Fail;
                }
            };
            list.iter()
                .filter(|b| glob_match(pattern, &b.mask))
                .map(|b| b.mask.clone())
                .collect()
        };
        let removed = masks.len();
        // apply in chunks so each MODE line stays within limits
        for chunk in masks.chunks(6) {
            let mut p = vec![
                chan.clone(),
                format!("-{}", mode.to_string().repeat(chunk.len())),
            ];
            p.extend(chunk.iter().cloned());
            if is_oper {
                s.mode_sudo = true;
            }
            apply_mode(s, uid, &p);
            s.mode_sudo = false;
        }
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let plural = if removed == 1 { "y" } else { "ies" };
        let removeds = removed.to_string();
        let modes = mode.to_string();
        let m = s.trf(
            "RMODE: removed {0} +{1} entr{2} from {3}",
            &[removeds.as_str(), modes.as_str(), plural, chan.as_str()],
        );
        s.send(uid, format!(":{} NOTICE {nick} :{m}", s.name));
        CmdResult::Ok
    }
}
