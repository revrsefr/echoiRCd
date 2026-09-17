//! Hold back the `/LIST` command until a user has been connected for a while, which
//! defeats spambots that connect, `LIST`, spam every channel and leave. Non-exempt
//! users who `LIST` too early get an optional notice and a throwaway *fake* channel
//! list (so a bot waiting on the reply is satisfied), then the real `LIST` is denied.
//! Exempt: opers, logged-in accounts (when `securelist_exemptregistered`), and hosts
//! matching a `securelist_exception` glob. Off unless `securelist = yes`.

use openssl::rand::rand_bytes;

use crate::channels::glob_match;
use crate::module::{ModResult, Module};
use crate::numeric::{RPL_LIST, RPL_LISTEND, RPL_LISTSTART};
use crate::server::{now, Server};
use crate::Uid;

/// A small unsigned int from the CSPRNG in `0..bound` (bound>0), else 0.
fn rand_below(bound: u32) -> u32 {
    if bound == 0 {
        return 0;
    }
    let mut b = [0u8; 4];
    if rand_bytes(&mut b).is_err() {
        return 0;
    }
    u32::from_le_bytes(b) % bound
}

/// A random lowercase-alnum string of `len` chars (for a fake channel suffix).
fn rand_name(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    if rand_bytes(&mut buf).is_err() {
        return "channel".to_string();
    }
    buf.iter()
        .map(|&b| ALPHABET[b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Is `uid` exempt from the LIST hold?
fn is_exempt(s: &Server, uid: Uid) -> bool {
    if crate::modules::opertypes::has_priv(
        s,
        uid,
        crate::modules::opertypes::privs::SERVERS_IGNORE_SECURELIST,
    ) {
        return true;
    }
    if s.conf_bool("securelist_exemptregistered", true) && s.is_logged_in(uid) {
        return true;
    }
    let exceptions = s.conf_all("securelist_exception");
    if exceptions.is_empty() {
        return false;
    }
    let Some(u) = s.users.get(&uid) else {
        return false;
    };
    let forms = [
        format!("{}@{}", u.ident, u.host),
        format!("{}@{}", u.ident, u.addr.ip()),
    ];
    exceptions
        .iter()
        .any(|mask| forms.iter().any(|f| glob_match(mask, f)))
}

pub struct SecureList;

impl Module for SecureList {
    fn name(&self) -> &'static str {
        "securelist"
    }
    fn description(&self) -> &'static str {
        "Delays /LIST for freshly-connected users (defeats LIST-spam bots)"
    }

    fn on_pre_command(
        &mut self,
        srv: &mut Server,
        uid: Uid,
        cmd: &str,
        _params: &[String],
    ) -> ModResult {
        if !srv.conf_bool("securelist", false) || !cmd.eq_ignore_ascii_case("LIST") {
            return ModResult::Passthru;
        }
        if is_exempt(srv, uid) {
            return ModResult::Passthru;
        }
        let waittime = srv.conf_num("securelist_waittime", 60u64);
        let signon = srv.users.get(&uid).map(|u| u.signon).unwrap_or(0);
        let elapsed = now().saturating_sub(signon);
        if waittime > 0 && elapsed >= waittime {
            return ModResult::Passthru;
        }

        // tell them to wait
        if srv.conf_bool("securelist_showmsg", true) {
            let remain = waittime.saturating_sub(elapsed);
            let nick = srv
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            srv.send(
                uid,
                format!(
                    ":{} NOTICE {nick} :*** You cannot view the channel list yet. \
                     Please try again in {remain} seconds (or log in to an account).",
                    srv.name
                ),
            );
        }

        // throwaway fake list so a bot waiting on the reply is satisfied
        let fakechans = srv.conf_num("securelist_fakechans", 5u32);
        let prefix = srv
            .conf("securelist_fakechanprefix")
            .unwrap_or("#")
            .to_string();
        let topic = srv
            .conf("securelist_fakechantopic")
            .unwrap_or("Fake channel for confusing spambots")
            .to_string();
        let usercount = srv.users.len().max(1) as u32;

        srv.numeric(uid, RPL_LISTSTART, "Channel :Users Name");
        for _ in 0..fakechans {
            let suffix = rand_name((rand_below(8) + 3) as usize);
            let count = rand_below(usercount) + 1;
            srv.numeric(uid, RPL_LIST, &format!("{prefix}{suffix} {count} :{topic}"));
        }
        srv.numeric(uid, RPL_LISTEND, ":End of channel list.");
        ModResult::Deny
    }
}
