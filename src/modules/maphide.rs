//! maphide — hide the server map (`LINKS` / `MAP`) from non-opers, so network
//! topology isn't exposed. Off unless `maphide = yes`.

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

pub struct MapHide;

impl Module for MapHide {
    fn name(&self) -> &'static str {
        "maphide"
    }
    fn description(&self) -> &'static str {
        "Hides LINKS/MAP from non-opers (network-topology privacy)"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        if !srv.conf_bool("maphide", false) || srv.is_oper(uid) {
            return ModResult::Passthru;
        }
        if cmd.eq_ignore_ascii_case("LINKS") || cmd.eq_ignore_ascii_case("MAP") {
            let nick = srv
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            srv.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :The server map is hidden; ask an operator.",
                    srv.name
                ),
            );
            return ModResult::Deny;
        }
        ModResult::Passthru
    }
}
