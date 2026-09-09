//! A lightweight anti-spam gate: before an un-vouched user's *private* messages are
//! delivered, they must answer one small arithmetic question. Opers and users logged
//! into an account are exempt. Off unless `solvemsg = yes`.
//!
//! Flow: the first PM is held and a question is posed; the user replies with the
//! number (that reply is consumed), and once correct every later message passes.

use crate::module::{ModResult, Module};
use crate::server::Server;
use crate::Uid;

/// Per-user challenge state, on `User.ext`.
#[derive(Default)]
struct SolveState {
    solved: bool,
    answer: Option<i64>,
}

/// A uniform-ish random byte in `0..max` via the OpenSSL CSPRNG.
fn rnd(max: u8) -> u8 {
    let mut b = [0u8; 1];
    let _ = openssl::rand::rand_bytes(&mut b);
    b[0] % max
}

pub struct SolveMsg;

impl Module for SolveMsg {
    fn name(&self) -> &'static str {
        "solvemsg"
    }

    fn on_pre_message(&mut self, s: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
        if !s.conf_bool("solvemsg", false) {
            return ModResult::Passthru;
        }
        // trusted: opers and logged-in accounts never see a challenge
        let exempt = s
            .users
            .get(&uid)
            .map(|u| u.flags.oper || u.account.is_some())
            .unwrap_or(true);
        if exempt {
            return ModResult::Passthru;
        }
        // only gate PMs to another user (channels have their own controls)
        let Some(tuid) = s.find_nick(target) else {
            return ModResult::Passthru;
        };
        if tuid == uid {
            return ModResult::Passthru;
        }
        let st = s.users.get(&uid).and_then(|u| u.ext.get::<SolveState>());
        if st.map(|st| st.solved).unwrap_or(false) {
            return ModResult::Passthru; // already solved
        }
        let pending = st.and_then(|st| st.answer);
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();

        // is this message the answer to an outstanding challenge?
        if let Some(ans) = pending {
            if text.trim().parse::<i64>().ok() == Some(ans) {
                if let Some(u) = s.users.get_mut(&uid) {
                    u.ext.set(SolveState {
                        solved: true,
                        answer: None,
                    });
                }
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :*** Correct — you may now message freely; please resend your message.",
                        s.name
                    ),
                );
                return ModResult::Deny; // consume the answer itself
            }
        }

        // pose a fresh question
        let a = (rnd(9) + 1) as i64;
        let b = (rnd(9) + 1) as i64;
        let (sym, ans) = match rnd(3) {
            0 => ("+", a + b),
            1 => ("-", a - b),
            _ => ("*", a * b),
        };
        if let Some(u) = s.users.get_mut(&uid) {
            u.ext.set(SolveState {
                solved: false,
                answer: Some(ans),
            });
        }
        let as_ = a.to_string();
        let bs = b.to_string();
        let m = s.trf(
            "To cut spam, answer this to send your message — what is {0} {1} {2} ?",
            &[as_.as_str(), sym, bs.as_str()],
        );
        s.send(uid, format!(":{} NOTICE {nick} :*** {m}", s.name));
        ModResult::Deny
    }
}
