//! ojoin — `OJOIN <channel>`: an oper joins a channel as network staff, taking the
//! oper prefix (`!`, mode `y`, above owner) and — unless `ojoin_op = no` — channel
//! op. The prefix's rank protects them from being kicked/deopped. Off unless
//! `ojoin = yes`.

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(OjoinCmd)]
}

struct OjoinCmd;
impl Command for OjoinCmd {
    fn name(&self) -> &'static str {
        "OJOIN"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        if !s.conf_bool("ojoin", false) {
            s.send(
                uid,
                format!(":{} NOTICE {nick} :*** OJOIN is not enabled on this server.", s.name),
            );
            return CmdResult::Fail;
        }
        let chan = params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !s.is_member(uid, &key) {
            s.join(uid, &chan, None);
        }
        if !s.is_member(uid, &key) {
            return CmdResult::Fail; // join was refused (bad name, etc.)
        }
        crate::modules::operprefix::grant(s, uid, &key);
        if s.conf_bool("ojoin_op", true) {
            crate::coremods::core_mode::svs_set_chan_modes(s, &chan, "+o", &[nick.clone()]);
        }
        s.snotice_c('v', &format!("{nick} used OJOIN to enter {chan}"));
        CmdResult::Ok
    }
}
