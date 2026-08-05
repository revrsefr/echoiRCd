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
        for (&uid, u) in &self.users {
            if u.watch.contains(&low) {
                self.numeric(
                    uid,
                    RPL_LOGON,
                    &format!("{dnick} {ident} {host} {ts} :is now online"),
                );
            }
            if u.monitor.contains(&low) {
                self.numeric(uid, RPL_MONONLINE, &format!(":{dnick}!{ident}@{host}"));
            }
        }
    }

    /// A nick just went offline (quit, or renamed away): tell its WATCHers
    /// (601 RPL_LOGOFF) and MONITORers (731 RPL_MONOFFLINE).
    pub fn watch_notify_offline(&self, nick: &str) {
        let low = nick.to_ascii_lowercase();
        let ts = now();
        for (&uid, u) in &self.users {
            if u.watch.contains(&low) {
                self.numeric(uid, RPL_LOGOFF, &format!("{nick} * * {ts} :is now offline"));
            }
            if u.monitor.contains(&low) {
                self.numeric(uid, RPL_MONOFFLINE, &format!(":{nick}"));
            }
        }
    }

    /// How many users currently WATCH `nick` (for `WATCH S` stats).
    pub fn watchers_of(&self, nick: &str) -> usize {
        let low = nick.to_ascii_lowercase();
        self.users
            .values()
            .filter(|u| u.watch.contains(&low))
            .count()
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
}
