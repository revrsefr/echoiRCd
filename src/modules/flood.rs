//! Per-user message-rate limit (`flood_messages` within `flood_seconds`); opers
//! exempt. A connection class can override the limit (`penaltythreshold` /
//! `commandrate`) and, with `fakelag=no`, have flooders disconnected instead of
//! rate-limited. Recent message times live in the user's typed
//! [`crate::extensible::Extensible`] slot, so the state is freed when the user quits.

use crate::modules::connclass;
use crate::module::{ModResult, Module};
use crate::server::{now, Server};
use crate::Uid;

// Defaults if unset in the config (`flood_messages` / `flood_seconds`): this many
// messages allowed within this many seconds.
const FLOOD_MAX: usize = 8;
const FLOOD_WINDOW: u64 = 4;

#[derive(Default)]
struct FloodState {
    times: Vec<u64>,
    warned: bool,
}

pub struct Flood;

impl Module for Flood {
    fn name(&self) -> &'static str {
        "flood"
    }

    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        _target: &str,
        _text: &str,
    ) -> ModResult {
        let now = now();
        // a connection class may raise the limit and/or opt out of fake lag
        let (cls_max, cls_window, fakelag) =
            connclass::flood_over(srv, uid).unwrap_or((None, None, true));
        let max = cls_max.unwrap_or_else(|| srv.conf_num("flood_messages", FLOOD_MAX));
        let window = cls_window.unwrap_or_else(|| srv.conf_num("flood_seconds", FLOOD_WINDOW));
        let (over, warn) = {
            let Some(u) = srv.users.get_mut(&uid) else {
                return ModResult::Passthru;
            };
            if u.flags.oper {
                return ModResult::Passthru; // opers bypass flood limits
            }
            let st = u.ext.get_or_insert_with(FloodState::default);
            st.times.retain(|&t| now.saturating_sub(t) < window);
            st.times.push(now);
            let over = st.times.len() > max;
            let warn = over && !st.warned; // notice once per burst
            st.warned = over;
            (over, warn)
        };
        if over {
            if !fakelag {
                // fakelag disabled: disconnect the flooder instead of throttling
                let m = srv.trf("Closing link: (Excess flood)", &[]);
                srv.send(uid, format!("ERROR :{m}"));
                srv.mark_quit(uid, "Excess flood".to_string());
                return ModResult::Deny;
            }
            if warn {
                let nick = srv
                    .users
                    .get(&uid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                srv.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :*** Flood detected — slow down",
                        srv.name
                    ),
                );
            }
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
