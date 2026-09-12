//! `CLEARMODE <channel>` — oper reset: strip every channel-wide mode and clear the
//! ban (+b), exception (+e) and invite (+I) lists in one command. Member prefixes are
//! left intact (this resets channel settings, it is not a mass-deop). Removals go
//! through the normal mode engine (chunked, oper-sudo), so they broadcast to members
//! and propagate to links like any other MODE.

use crate::command::{CmdResult, Command};
use crate::coremods::core_mode::apply_mode;
use crate::numeric::{ERR_NOPRIVILEGES, ERR_NOSUCHCHANNEL};
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(ClearMode)]
}

struct ClearMode;
impl Command for ClearMode {
    fn name(&self) -> &'static str {
        "CLEARMODE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- CLEARMODE is for IRC operators",
            );
            return CmdResult::Fail;
        }
        let chan = params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !s.channels.contains_key(&key) {
            s.numeric(uid, ERR_NOSUCHCHANNEL, &format!("{chan} :No such channel"));
            return CmdResult::Fail;
        }
        // snapshot what's set: flag/param mode letters (render omits the `+` and lists),
        // the current key (needed as the `-k` argument), and the three list modes.
        let letters: Vec<char> = s.channels[&key]
            .modes
            .render(false)
            .chars()
            .filter(|c| *c != '+')
            .collect();
        let key_val = s.channels[&key].modes.key.clone();
        let lists: [(char, Vec<String>); 3] = {
            let ch = &s.channels[&key];
            [
                ('b', ch.bans.iter().map(|b| b.mask.clone()).collect()),
                ('e', ch.excepts.iter().map(|b| b.mask.clone()).collect()),
                ('I', ch.invex.iter().map(|b| b.mask.clone()).collect()),
            ]
        };

        s.mode_sudo = true;
        // 1) clear the list modes first (chunked so each MODE line stays legal)
        for (letter, masks) in &lists {
            for chunk in masks.chunks(6) {
                let mut p = vec![
                    chan.clone(),
                    format!("-{}", letter.to_string().repeat(chunk.len())),
                ];
                p.extend(chunk.iter().cloned());
                apply_mode(s, uid, &p);
            }
        }
        // 2) +k needs its key echoed back on removal
        if let Some(k) = key_val {
            apply_mode(s, uid, &[chan.clone(), "-k".into(), k]);
        }
        // 3) the remaining no-argument flag/param modes, last — removing +P/+r may cull
        //    a now-empty channel, so nothing else must run after this.
        let noparam: Vec<char> = letters.into_iter().filter(|&c| c != 'k').collect();
        for chunk in noparam.chunks(12) {
            let modestr: String = std::iter::once('-').chain(chunk.iter().copied()).collect();
            apply_mode(s, uid, &[chan.clone(), modestr]);
        }
        s.mode_sudo = false;

        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :CLEARMODE: reset all modes on {chan}",
                s.name
            ),
        );
        CmdResult::Ok
    }
}
