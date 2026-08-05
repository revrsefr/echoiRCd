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
            eprintln!("[snoop] connect {nick} ({ident}@{host})");
            srv.snotice(&format!("Client connecting: {nick} ({ident}@{host})"));
        }
    }
    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {
        if let Some(u) = srv.users.get(&uid) {
            eprintln!("[snoop] {} joined {chan}", u.nick);
        }
    }
    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {
        let nick = srv.users.get(&uid).map(|u| u.nick.clone());
        eprintln!("[snoop] quit uid={uid} ({reason})");
        if let Some(nick) = nick {
            srv.snotice(&format!("Client exiting: {nick} ({reason})"));
        }
    }
}
