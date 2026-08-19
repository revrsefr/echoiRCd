//! A tiny example module: log connects, joins and quits to stderr. It exercises
//! the hook wiring end-to-end and is the template for real modules.

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

pub struct Snoop;

impl Module for Snoop {
    fn name(&self) -> &'static str {
        "snoop"
    }
    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        let info = srv
            .users
            .get(&uid)
            .map(|u| (u.nick.clone(), u.ident.clone(), u.host.clone()));
        if let Some((nick, ident, host)) = info {
            if srv.conf_bool("snoop_stderr", false) {
                eprintln!("[snoop] connect {nick} ({ident}@{host})");
            }
            srv.snotice_c('c', &format!("Client connecting: {nick} ({ident}@{host})"));
        }
    }
    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {
        if srv.conf_bool("snoop_stderr", false) {
            if let Some(u) = srv.users.get(&uid) {
                eprintln!("[snoop] {} joined {chan}", u.nick);
            }
        }
    }
    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {
        // Only announce clients that actually registered. A health/liveness probe — or
        // any client that drops mid-handshake — never fired a connect notice, so it must
        // not fire an exit notice either, else it spams the +q snomask on every probe.
        // (on_user_quit itself still fires for unregistered users so modules reclaim
        // their per-uid state; only this operator-facing notice is gated.)
        let Some(nick) = srv
            .users
            .get(&uid)
            .filter(|u| u.registered)
            .map(|u| u.nick.clone())
        else {
            return;
        };
        if srv.conf_bool("snoop_stderr", false) {
            eprintln!("[snoop] quit uid={uid} ({reason})");
        }
        srv.snotice_c('q', &format!("Client exiting: {nick} ({reason})"));
    }
}
