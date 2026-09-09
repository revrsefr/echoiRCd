//! namedmodes — the `PROP` command sets or queries channel modes by long name
//! instead of by letter, e.g. `PROP #chan +op nick +moderated -limit`. Names map to
//! echoIRCd's channel-mode letters and go through the normal MODE machinery
//! (`core_mode::apply_mode`), so all the usual permission checks apply. `PROP #chan`
//! with no changes lists the modes currently set, by name.

use crate::command::{CmdResult, Command};
use crate::coremods::core_mode::apply_mode;
use crate::mode::chan_mode;
use crate::numeric::ERR_NOSUCHCHANNEL;
use crate::server::Server;
use crate::Uid;

/// Mode long-name → echoIRCd channel-mode letter.
static NAMES: &[(&str, char)] = &[
    ("founder", 'q'),
    ("admin", 'a'),
    ("op", 'o'),
    ("halfop", 'h'),
    ("voice", 'v'),
    ("ban", 'b'),
    ("banexception", 'e'),
    ("invex", 'I'),
    ("key", 'k'),
    ("limit", 'l'),
    ("moderated", 'm'),
    ("noextmsg", 'n'),
    ("topiclock", 't'),
    ("inviteonly", 'i'),
    ("secret", 's'),
    ("private", 'p'),
    ("sslonly", 'z'),
    ("operonly", 'O'),
    ("nonick", 'N'),
    ("noctcp", 'C'),
    ("nonotice", 'T'),
    ("blockcolor", 'c'),
    ("stripcolor", 'S'),
    ("censor", 'G'),
    ("auditorium", 'u'),
    ("regonly", 'R'),
    ("regmoderated", 'M'),
    ("nokicks", 'Q'),
    ("allowinvite", 'A'),
    ("permanent", 'P'),
    ("opmoderated", 'U'),
    ("delayjoin", 'D'),
    ("filter", 'g'),
    ("exemptchanops", 'X'),
    ("autoop", 'w'),
    ("flood", 'f'),
    ("joinflood", 'j'),
    ("nickflood", 'F'),
    ("redirect", 'L'),
    ("blockcaps", 'B'),
    ("kicknorejoin", 'J'),
    ("history", 'H'),
    ("delaymsg", 'd'),
    ("repeat", 'K'),
];

fn name_to_letter(name: &str) -> Option<char> {
    let n = name.to_ascii_lowercase();
    NAMES.iter().find(|(nm, _)| *nm == n).map(|(_, c)| *c)
}

fn letter_to_name(letter: char) -> Option<&'static str> {
    NAMES.iter().find(|(_, c)| *c == letter).map(|(nm, _)| *nm)
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Prop)]
}

struct Prop;
impl Command for Prop {
    fn name(&self) -> &'static str {
        "PROP"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let target = params[0].clone();
        let key = target.to_ascii_lowercase();
        if !target.starts_with('#') || !s.channels.contains_key(&key) {
            s.numeric(
                uid,
                ERR_NOSUCHCHANNEL,
                &format!("{target} :No such channel"),
            );
            return CmdResult::Fail;
        }
        // no changes → list the modes currently set, by name
        if params.len() < 2 {
            let rendered = s.channels[&key].modes.render(s.is_member(uid, &key));
            let letters = rendered
                .trim_start_matches(['+', '-'])
                .split(' ')
                .next()
                .unwrap_or("");
            let names: Vec<&str> = letters.chars().filter_map(letter_to_name).collect();
            let nick = s
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            s.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :{target} modes: {} ({rendered})",
                    s.name,
                    names.join(" ")
                ),
            );
            return CmdResult::Ok;
        }
        // translate `+name [value] -name …` into a MODE string + ordered args, then
        // reuse apply_mode (same wants_param arg-consumption, so they stay aligned)
        let mut modestr = String::new();
        let mut modeargs: Vec<String> = Vec::new();
        let mut i = 1;
        while i < params.len() {
            let tok = &params[i];
            let (sign, nm) = match tok.chars().next() {
                Some('+') => ('+', &tok[1..]),
                Some('-') => ('-', &tok[1..]),
                _ => {
                    i += 1;
                    continue;
                }
            };
            if let Some(letter) = name_to_letter(nm) {
                modestr.push(sign);
                modestr.push(letter);
                if chan_mode(letter).is_some_and(|m| m.wants_param(sign == '+')) {
                    i += 1;
                    if i < params.len() {
                        modeargs.push(params[i].clone());
                    }
                }
            }
            i += 1;
        }
        if modestr.is_empty() {
            return CmdResult::Ok;
        }
        let mut p = vec![target, modestr];
        p.extend(modeargs);
        apply_mode(s, uid, &p)
    }
}
