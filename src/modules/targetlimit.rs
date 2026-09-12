//! targetlimit — anti-spam target-change throttle. A local, non-oper user may address
//! up to `target_max` distinct recent PRIVMSG/NOTICE targets in a burst; beyond that a
//! new (not-recently-messaged) target is allowed only once per `target_delay` seconds,
//! via a token bucket. Re-messaging a recent target is always free, so ordinary chatting
//! never trips it — only fanning out across many fresh targets (spam) does. With
//! `no_multi_targets` a comma-separated target list is refused outright. Per-user state
//! lives in `UserFlags`, so it frees on disconnect.

use crate::module::{ModResult, Module};
use crate::numeric::{ERR_TARGETTOOFAST, ERR_TOOMANYTARGETS};
use crate::server::Server;
use crate::Uid;

pub struct TargetLimit;

impl Module for TargetLimit {
    fn name(&self) -> &'static str {
        "targetlimit"
    }

    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        target: &str,
        _text: &str,
    ) -> ModResult {
        // opers (and any sender we can't see) are exempt; remote/service messages don't
        // pass through this hook at all.
        if srv.users.get(&uid).map(|u| u.flags.oper).unwrap_or(true) {
            return ModResult::Passthru;
        }
        if target.contains(',') && srv.conf_bool("no_multi_targets", false) {
            srv.numeric(
                uid,
                ERR_TOOMANYTARGETS,
                &format!("{target} :Too many targets — one recipient per message"),
            );
            return ModResult::Deny;
        }
        let delay: u64 = srv.conf_num("target_delay", 10u64);
        if delay == 0 {
            return ModResult::Passthru; // throttle disabled
        }
        let maxt: u64 = srv.conf_num("target_max", 20u64).max(1);
        let hash = target_hash(target);
        let now = crate::server::now();

        enum Act {
            Pass,
            TooFast(u64),
        }
        let act = {
            let Some(u) = srv.users.get_mut(&uid) else {
                return ModResult::Passthru;
            };
            if let Some(pos) = u.flags.recent_targets.iter().position(|&h| h == hash) {
                // already talking to this target — free, keep it most-recent
                let h = u.flags.recent_targets.remove(pos);
                u.flags.recent_targets.insert(0, h);
                Act::Pass
            } else {
                // a new target: token bucket, floored so a burst of `maxt` is allowed
                let floor = now.saturating_sub(delay.saturating_mul(maxt - 1));
                let credit = u.flags.target_credit.max(floor);
                if credit > now {
                    Act::TooFast(credit - now)
                } else {
                    u.flags.target_credit = credit + delay;
                    u.flags.recent_targets.insert(0, hash);
                    u.flags.recent_targets.truncate(maxt as usize);
                    Act::Pass
                }
            }
        };
        match act {
            Act::Pass => ModResult::Passthru,
            Act::TooFast(wait) => {
                srv.numeric(
                    uid,
                    ERR_TARGETTOOFAST,
                    &format!("{target} :Targets changing too fast, please wait {wait}s"),
                );
                ModResult::Deny
            }
        }
    }
}

/// Case-insensitive djb2 hash of a target name — keeps the recent-target ring compact.
fn target_hash(t: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in t.as_bytes() {
        h = h.wrapping_mul(33) ^ b.to_ascii_lowercase() as u64;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_case_insensitive() {
        assert_eq!(target_hash("#Chan"), target_hash("#chan"));
        assert_ne!(target_hash("#a"), target_hash("#b"));
    }
}
