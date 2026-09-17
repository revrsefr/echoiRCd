//! Greet each connecting user with a random line from the configured quote set.
//! Off unless one or more `randquote = <line>` are configured.

use openssl::rand::rand_bytes;

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

/// A random index in `0..n` from the CSPRNG (0 if `n == 0` or on error).
fn rand_below(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mut b = [0u8; 8];
    if rand_bytes(&mut b).is_err() {
        return 0;
    }
    (u64::from_le_bytes(b) % n as u64) as usize
}

pub struct RandQuote;

impl Module for RandQuote {
    fn name(&self) -> &'static str {
        "randquote"
    }
    fn description(&self) -> &'static str {
        "Greets each connecting user with a random configured quote"
    }

    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        let quotes = srv.conf_all("randquote");
        if quotes.is_empty() {
            return;
        }
        let quote = quotes[rand_below(quotes.len())].clone();
        let nick = srv
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        srv.send(uid, format!(":{} NOTICE {nick} :{quote}", srv.name));
    }
}
