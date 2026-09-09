//! disable: refuse a configured set of commands to ordinary users (opers bypass).
//! `disabled_commands = LIST WHO KNOCK` (space-separated; repeatable). A disabled
//! command replies with `421` as if it didn't exist. Off unless configured.

use crate::map::HashSet;
use crate::module::{ModResult, Module};
use crate::numeric::ERR_UNKNOWNCOMMAND;
use crate::server::Server;
use crate::Uid;

/// The disabled-command set, parsed once and re-parsed only when the config changes.
#[derive(Default)]
struct DisabledCache {
    gen: u64,
    cmds: HashSet<String>, // uppercased command names
}

pub struct Disable;

impl Module for Disable {
    fn name(&self) -> &'static str {
        "disable"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        // servers/use-disabled-commands opers bypass the disabled list
        if crate::modules::opertypes::has_priv(
            srv,
            uid,
            crate::modules::opertypes::privs::SERVERS_USE_DISABLED_COMMANDS,
        ) {
            return ModResult::Passthru;
        }
        // (re)build the set only when the config generation changes, not per command
        let gen = srv.config_gen;
        let stale = srv
            .ext
            .get::<DisabledCache>()
            .map(|c| c.gen != gen)
            .unwrap_or(true);
        if stale {
            let cmds: HashSet<String> = srv
                .conf_all("disabled_commands")
                .iter()
                .flat_map(|line| line.split_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect();
            srv.ext.set(DisabledCache { gen, cmds });
        }
        let disabled = srv
            .ext
            .get::<DisabledCache>()
            .is_some_and(|c| c.cmds.contains(&cmd.to_ascii_uppercase()));
        if disabled {
            srv.numeric(
                uid,
                ERR_UNKNOWNCOMMAND,
                &format!("{cmd} :This command has been disabled by the administrator."),
            );
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
