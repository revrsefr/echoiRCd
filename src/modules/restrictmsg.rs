//! Stop ordinary users from private-messaging each other. A PM between two users is
//! allowed only when the sender is an oper, the target is an oper, or the target is a
//! service/bot (so users can still reach NickServ etc.). Channel messages are never
//! affected. Off unless `restrictmsg = yes`.

use crate::module::{ModResult, Module};
use crate::numeric::ERR_CANTSENDTOUSER;
use crate::server::Server;
use crate::Uid;

pub struct RestrictMsg;

impl Module for RestrictMsg {
    fn name(&self) -> &'static str {
        "restrictmsg"
    }

    fn on_pre_message(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        target: &str,
        _text: &str,
    ) -> ModResult {
        if !srv.conf_bool("restrictmsg", false) {
            return ModResult::Passthru;
        }
        // channels are unaffected
        if target.starts_with('#') {
            return ModResult::Passthru;
        }
        // users/ignore-restrictmsg senders may message anyone
        if crate::modules::opertypes::has_priv(srv, uid, crate::modules::opertypes::privs::USERS_IGNORE_RESTRICTMSG) {
            return ModResult::Passthru;
        }
        let Some(tuid) = srv.find_nick(target) else {
            return ModResult::Passthru; // let the core answer "no such nick"
        };
        // allow messaging opers and services/bots
        let target_privileged = srv
            .users
            .get(&tuid)
            .map(|u| u.flags.oper || u.flags.bot)
            .unwrap_or(false);
        if target_privileged {
            return ModResult::Passthru;
        }

        srv.numeric(
            uid,
            ERR_CANTSENDTOUSER,
            &format!("{target} :You cannot send messages to this user."),
        );
        ModResult::Deny
    }
}
