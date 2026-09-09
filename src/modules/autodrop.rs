//! autodrop — silently drop a not-yet-registered client that sends one of the
//! configured commands. HTTP scanners and other junk open a connection and blurt
//! `GET` / `POST` / `CONNECT` before ever sending NICK/USER; a real IRC client
//! never does. Config, space-separated (repeatable):
//!
//! ```text
//! autodrop_commands = GET POST HEAD CONNECT PUT DELETE OPTIONS TRACE PATCH
//! ```

use crate::map::HashSet;
use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

/// The autodrop-command set, parsed once and re-parsed only on rehash.
#[derive(Default)]
struct DropCache {
    gen: u64,
    cmds: HashSet<String>, // uppercased
}

pub struct AutoDrop;

impl Module for AutoDrop {
    fn name(&self) -> &'static str {
        "autodrop"
    }

    fn on_pre_command(
        &mut self,
        s: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // only before registration — a registered client's commands are its own
        if s.users.get(&uid).map(|u| u.registered).unwrap_or(true) {
            return ModResult::Passthru;
        }
        // cache the set (config_gen-tagged): this hook runs hottest under the exact
        // scanner flood it defends against, so don't re-split the config per packet.
        let gen = s.config_gen;
        let stale = s
            .ext
            .get::<DropCache>()
            .map(|c| c.gen != gen)
            .unwrap_or(true);
        if stale {
            let cmds: HashSet<String> = s
                .conf_all("autodrop_commands")
                .iter()
                .flat_map(|line| line.split_whitespace())
                .map(|w| w.to_ascii_uppercase())
                .collect();
            s.ext.set(DropCache { gen, cmds });
        }
        let hit = s
            .ext
            .get::<DropCache>()
            .is_some_and(|c| c.cmds.contains(&cmd.to_ascii_uppercase()));
        if hit {
            let m = s.trf("Closing link (dropped)", &[]);
            s.send(uid, format!("ERROR :{m}"));
            s.remove_user(uid, "Autodropped");
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
