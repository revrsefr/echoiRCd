//! WATCH / MONITOR notification plumbing + SILENCE matching.
//!
//! The lists themselves live on the [`crate::users::User`] (`watch` / `monitor` /
//! `silence`); the commands are in [`crate::coremods::core_watch`]. Whenever a
//! nick's online-state flips — registration, quit, or a nick change — the
//! lifecycle code calls [`Server::watch_notify_online`] / [`Server::watch_notify_offline`],
//! which scan for anyone WATCHing/MONITORing that nick and send the right numeric.
//!
//! An O(users) scan, not a reverse index: correct-by-construction (nothing to keep
//! in sync) and fine on a small server — a reverse index can slot in later if it
//! ever needs to scale, exactly the kind of change the borrow checker makes safe.

use crate::channels::glob_match;
use crate::numeric::*;
use crate::server::{now, Server};
use crate::Uid;

pub const WATCH_MAX: usize = 128;
pub const MONITOR_MAX: usize = 128;
pub const SILENCE_MAX: usize = 32;
pub const ACCEPT_MAX: usize = 64;

impl Server {
    /// A nick just came online (registered, or someone renamed to it): tell its
    /// WATCHers (600 RPL_LOGON) and MONITORers (730 RPL_MONONLINE).
    pub fn watch_notify_online(&self, nick: &str) {
        let low = nick.to_ascii_lowercase();
        let Some((dnick, ident, host, ts)) = self.find_nick(nick).and_then(|tu| {
            self.users.get(&tu).map(|x| {
                (
                    x.nick.clone(),
                    x.ident.clone(),
                    x.host_display().to_string(),
                    x.signon,
                )
            })
        }) else {
            return;
        };
        if let Some(set) = self.watch_by.get(&low) {
            for &uid in set {
                self.numeric(
                    uid,
                    RPL_LOGON,
                    &format!("{dnick} {ident} {host} {ts} :is now online"),
                );
            }
        }
        if let Some(set) = self.monitor_by.get(&low) {
            for &uid in set {
                self.numeric(uid, RPL_MONONLINE, &format!(":{dnick}!{ident}@{host}"));
            }
        }
    }

    /// A nick just went offline (quit, or renamed away): tell its WATCHers
    /// (601 RPL_LOGOFF) and MONITORers (731 RPL_MONOFFLINE).
    pub fn watch_notify_offline(&self, nick: &str) {
        let low = nick.to_ascii_lowercase();
        let ts = now();
        if let Some(set) = self.watch_by.get(&low) {
            for &uid in set {
                self.numeric(uid, RPL_LOGOFF, &format!("{nick} * * {ts} :is now offline"));
            }
        }
        if let Some(set) = self.monitor_by.get(&low) {
            for &uid in set {
                self.numeric(uid, RPL_MONOFFLINE, &format!(":{nick}"));
            }
        }
    }

    /// How many users currently WATCH `nick` (for `WATCH S` stats).
    pub fn watchers_of(&self, nick: &str) -> usize {
        let low = nick.to_ascii_lowercase();
        self.watch_by.get(&low).map(|s| s.len()).unwrap_or(0)
    }

    // ── WATCH/MONITOR list mutators — keep the reverse index in sync ──────────

    /// Add `nick_low` to `uid`'s WATCH list (if absent) and index it.
    pub fn watch_index_add(&mut self, uid: Uid, nick_low: String) {
        let added = self
            .users
            .get_mut(&uid)
            .map(|u| {
                if u.watch.contains(&nick_low) {
                    false
                } else {
                    u.watch.push(nick_low.clone());
                    true
                }
            })
            .unwrap_or(false);
        if added {
            self.watch_by.entry(nick_low).or_default().insert(uid);
        }
    }

    /// Remove `nick_low` from `uid`'s WATCH list and de-index it.
    pub fn watch_index_remove(&mut self, uid: Uid, nick_low: &str) {
        let removed = self
            .users
            .get_mut(&uid)
            .map(|u| {
                let before = u.watch.len();
                u.watch.retain(|n| n != nick_low);
                before != u.watch.len()
            })
            .unwrap_or(false);
        if removed {
            if let Some(set) = self.watch_by.get_mut(nick_low) {
                set.remove(&uid);
                if set.is_empty() {
                    self.watch_by.remove(nick_low);
                }
            }
        }
    }

    /// Clear `uid`'s whole WATCH list (WATCH C) and de-index every entry.
    pub fn watch_index_clear(&mut self, uid: Uid) {
        let nicks = self
            .users
            .get_mut(&uid)
            .map(|u| std::mem::take(&mut u.watch))
            .unwrap_or_default();
        for n in nicks {
            if let Some(set) = self.watch_by.get_mut(&n) {
                set.remove(&uid);
                if set.is_empty() {
                    self.watch_by.remove(&n);
                }
            }
        }
    }

    /// Add `nick_low` to `uid`'s MONITOR list (if absent) and index it.
    pub fn monitor_index_add(&mut self, uid: Uid, nick_low: String) {
        let added = self
            .users
            .get_mut(&uid)
            .map(|u| {
                if u.monitor.contains(&nick_low) {
                    false
                } else {
                    u.monitor.push(nick_low.clone());
                    true
                }
            })
            .unwrap_or(false);
        if added {
            self.monitor_by.entry(nick_low).or_default().insert(uid);
        }
    }

    /// Remove `nick_low` from `uid`'s MONITOR list and de-index it.
    pub fn monitor_index_remove(&mut self, uid: Uid, nick_low: &str) {
        let removed = self
            .users
            .get_mut(&uid)
            .map(|u| {
                let before = u.monitor.len();
                u.monitor.retain(|n| n != nick_low);
                before != u.monitor.len()
            })
            .unwrap_or(false);
        if removed {
            if let Some(set) = self.monitor_by.get_mut(nick_low) {
                set.remove(&uid);
                if set.is_empty() {
                    self.monitor_by.remove(nick_low);
                }
            }
        }
    }

    /// Clear `uid`'s whole MONITOR list (MONITOR C) and de-index every entry.
    pub fn monitor_index_clear(&mut self, uid: Uid) {
        let nicks = self
            .users
            .get_mut(&uid)
            .map(|u| std::mem::take(&mut u.monitor))
            .unwrap_or_default();
        for n in nicks {
            if let Some(set) = self.monitor_by.get_mut(&n) {
                set.remove(&uid);
                if set.is_empty() {
                    self.monitor_by.remove(&n);
                }
            }
        }
    }

    /// True if `sender_nick` is on `target`'s ACCEPT list (callerid +g).
    pub fn is_accepted(&self, target: Uid, sender_nick: &str) -> bool {
        let low = sender_nick.to_ascii_lowercase();
        self.users
            .get(&target)
            .map(|u| u.accept.contains(&low))
            .unwrap_or(false)
    }

    /// True if user `by` has silenced someone whose prefix is `sender_mask`.
    pub fn is_silenced(&self, by: Uid, sender_mask: &str) -> bool {
        self.users
            .get(&by)
            .map(|u| u.silence.iter().any(|m| glob_match(m, sender_mask)))
            .unwrap_or(false)
    }

    /// True if `a` and `b` mutually SIGNORE each other (either one has the other on
    /// their SIGNORE list): a bidirectional block — neither sees the other's channel
    /// or PM messages, triggered by whichever one ran SIGNORE.
    pub fn signore_blocks(&self, a: Uid, b: Uid) -> bool {
        self.signore_one_way(a, b) || self.signore_one_way(b, a)
    }

    /// Does `by`'s SIGNORE list match `who`'s current mask?
    fn signore_one_way(&self, by: Uid, who: Uid) -> bool {
        let Some(byu) = self.users.get(&by) else {
            return false;
        };
        if byu.signore.is_empty() {
            return false;
        }
        let mask = self.users.get(&who).map(|u| u.prefix()).unwrap_or_default();
        byu.signore.iter().any(|m| glob_match(m, &mask))
    }
}
