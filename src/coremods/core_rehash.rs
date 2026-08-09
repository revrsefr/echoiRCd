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
                // echoIRCd's own announcement (not InspIRCd's) — broadcast to
                // everyone connected, not just opers.
                s.announce(&format!(
                    "admin {who} has changed the configuration of the server."
                ));
                s.announce(&format!("{who} is rehashing the server config file."));
                s.apply_config(fresh);
                s.announce("Server configuration reloaded.");
                s.numeric(uid, RPL_REHASHING, &format!("{path} :Rehashing"));
            }
            None => {
                // Unreadable config — keep what's running (do NOT reset to defaults).
                s.announce(&format!(
                    "{who} tried to reload the server configuration, but the config file \
                     could not be read — no changes were made."
                ));
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {who} :*** Could not read {path} — the running configuration was kept.",
                        s.name
                    ),
                );
            }
        }
        CmdResult::Ok
    }
}
