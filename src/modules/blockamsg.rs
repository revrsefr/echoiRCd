//! blockamsg — block the mass "/amsg" and "/ame" commands (one message fanned out
//! to every channel the sender is on), a classic advertise/flood vector. A
//! PRIVMSG/NOTICE whose target list is two-or-more channels is blocked when either:
//! the same text was just sent to a *different* target list within `blockamsg_delay`
//! seconds, or the number of channel targets equals the number of channels the
//! sender is on (>1). Off unless `blockamsg = yes`. Per-user last-message state
//! lives in `Server.ext`.

use crate::map::HashMap;

use crate::module::{ModResult, Module};
use crate::server::{now, Server};
use crate::xline::XKind;
use crate::Uid;

/// Per-user record of the last PRIVMSG/NOTICE: (text, target-list, unix secs).
#[derive(Default)]
struct LastMsg(HashMap<Uid, (String, String, u64)>);

/// Count how many comma-separated targets in `list` are channels (`#…`).
fn channel_targets(list: &str) -> usize {
    list.split(',').filter(|t| t.starts_with('#')).count()
}

pub struct BlockAmsg;

impl Module for BlockAmsg {
    fn name(&self) -> &'static str {
        "blockamsg"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(m) = s.ext.get_mut::<LastMsg>() {
            m.0.remove(&uid);
        }
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        params: &[String],
    ) -> ModResult {
        if !srv.conf_bool("blockamsg", false) {
            return ModResult::Passthru;
        }
        if !(cmd.eq_ignore_ascii_case("PRIVMSG") || cmd.eq_ignore_ascii_case("NOTICE")) {
            return ModResult::Passthru;
        }
        if params.len() < 2 {
            return ModResult::Passthru;
        }
        // opers bypass the check entirely
        if srv.is_oper(uid) {
            return ModResult::Passthru;
        }

        let (list, text) = (&params[0], &params[1]);
        let targets = channel_targets(list);
        if targets == 0 {
            return ModResult::Passthru; // a PM — never blocked
        }

        let delay = srv.conf_num("blockamsg_delay", 3u64);
        let chan_count = srv.users.get(&uid).map(|u| u.channels.len()).unwrap_or(0);
        let n = now();

        let store = srv.ext.get_or_insert_with::<LastMsg>(LastMsg::default);
        let prev = store.0.get(&uid).cloned();
        // record this message for next time (always update)
        store.0.insert(uid, (text.clone(), list.clone(), n));

        let repeat_hit = prev
            .as_ref()
            .map(|(pmsg, ptgt, psent)| {
                pmsg == text && ptgt != list && delay > 0 && *psent >= n.saturating_sub(delay)
            })
            .unwrap_or(false);
        let allchans_hit = targets > 1 && targets == chan_count;

        if !(repeat_hit || allchans_hit) {
            return ModResult::Passthru;
        }

        // ── block it ──
        let action = srv
            .conf("blockamsg_action")
            .unwrap_or("killopers")
            .to_ascii_lowercase();
        let notify_opers = matches!(action.as_str(), "killopers" | "noticeopers" | "zlineopers");
        if notify_opers {
            let mask = srv.users.get(&uid).map(|u| u.prefix()).unwrap_or_default();
            let m = srv.trf("User {0} had an /amsg or /ame blocked", &[mask.as_str()]);
            srv.snotice(&m);
        }
        let reason = "Attempted to global message (/amsg or /ame)";
        match action.as_str() {
            "kill" | "killopers" => srv.remove_user(uid, reason),
            "notice" | "noticeopers" => {
                let nick = srv
                    .users
                    .get(&uid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                srv.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :Global message (/amsg or /ame) blocked",
                        srv.name
                    ),
                );
            }
            "zline" | "zlineopers" => {
                let (ip, dur) = (
                    srv.users
                        .get(&uid)
                        .map(|u| u.addr.ip().to_string())
                        .unwrap_or_default(),
                    srv.conf_num("blockamsg_duration", 900u64),
                );
                let setter = format!("blockamsg@{}", srv.name);
                srv.add_xline(XKind::Zline, &ip, dur, &setter, reason);
            }
            _ => {} // "silent": drop with no output
        }
        ModResult::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_channel_targets() {
        assert_eq!(channel_targets("#a,#b,#c"), 3);
        assert_eq!(channel_targets("nick"), 0);
        assert_eq!(channel_targets("#a,nick"), 1);
    }
}
