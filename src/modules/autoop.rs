//! autoop — the channel list mode `+w <prefix>:<hostmask>` grants a status prefix
//! to matching users the moment they join, e.g. `+w o:*!*@trusted.host` auto-ops
//! them, `+w v:*!*@*.friend` auto-voices. The list lives on the channel (like +b,
//! stored verbatim) and is applied on join via the server-authority mode path.

use crate::channels::glob_match;
use crate::module::Module;
use crate::server::Server;
use crate::Uid;

pub struct AutoOp;

impl Module for AutoOp {
    fn name(&self) -> &'static str {
        "autoop"
    }

    fn on_join(&mut self, s: &mut Server, uid: Uid, chan: &str) {
        let key = chan.to_ascii_lowercase();
        let Some(who) = s.users.get(&uid).map(|u| u.prefix()) else {
            return;
        };
        let Some(nick) = s.users.get(&uid).map(|u| u.nick.clone()) else {
            return;
        };
        // gather the prefix modes this user's mask earns (deduped)
        let mut modes = String::new();
        if let Some(c) = s.channels.get(&key) {
            for e in &c.autoop {
                let Some((pfx, mask)) = e.mask.split_once(':') else {
                    continue;
                };
                let Some(m) = pfx.chars().next() else { continue };
                if "qaohv".contains(m) && !modes.contains(m) && glob_match(mask, &who) {
                    modes.push(m);
                }
            }
        }
        if modes.is_empty() {
            return;
        }
        // grant them under server authority (the joiner can't op themselves)
        let args: Vec<String> = modes.chars().map(|_| nick.clone()).collect();
        crate::coremods::core_mode::svs_set_chan_modes(s, chan, &format!("+{modes}"), &args);
    }
}
