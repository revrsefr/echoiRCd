//! core_rehash — the REHASH command. Re-reads the config file and applies every
//! setting that can change at runtime, the way InspIRCd's rehash does:
//!
//!   * opers only; replies with RPL_REHASHING (382) and a server-notice to +s opers;
//!   * takes an optional `<servermask>` (we only rehash if it matches this server —
//!     there's no remote-rehash over S2S yet);
//!   * **keeps the running config if the file can't be read** (via `Config::try_load`),
//!     so a REHASH of a deleted/renamed config never resets opers/cloak-key to defaults.
//!
//! Reloadable live: MOTD, oper blocks, cloak key, +G censor words, antimixedutf8,
//! and the reverse-DNS options. Listener/bind/SID changes still need a restart.

use crate::channels::glob_match;
use crate::command::{CmdResult, Command};
use crate::config::Config;
use crate::numeric::*;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Rehash)]
}

struct Rehash;
impl Command for Rehash {
    fn name(&self) -> &'static str {
        "REHASH"
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        // `REHASH <mask>` only rehashes servers matching the mask; we're one server.
        if let Some(mask) = params.first() {
            if !glob_match(mask, &s.name) {
                s.numeric(uid, RPL_REHASHING, &format!("{mask} :No matching servers"));
                return CmdResult::Ok;
            }
        }
        let who = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let path = s.conf_path.clone();
        match Config::try_load(&path) {
            Some(fresh) => {
                s.motd = fresh.motd;
                s.opers = fresh.opers;
                s.cloak_key = fresh.cloak_key;
                s.censor = fresh.censor;
                s.amu = fresh.amu;
                s.resolve_hosts = fresh.resolve_hosts;
                s.use_resolved_host = fresh.use_resolved_host;
                s.numeric(uid, RPL_REHASHING, &format!("{path} :Rehashing"));
                s.snotice(&format!("{who} is rehashing config: {path}"));
            }
            None => {
                // Unreadable config — keep what's running (do NOT reset to defaults).
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {who} :*** Cannot read {path}; keeping the running config",
                        s.name
                    ),
                );
                s.snotice(&format!(
                    "{who} tried to REHASH but {path} could not be read; config unchanged"
                ));
            }
        }
        CmdResult::Ok
    }
}
