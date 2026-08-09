//! conn_waitpong — optionally hold registration until the client answers a server
//! PING with the exact cookie we sent, filtering bots that never PONG. Config:
//!
//! ```text
//! conn_waitpong = yes                  # require the pong before registering (default off)
//! conn_waitpong_killonbadreply = yes   # disconnect on a wrong pong (default: keep waiting)
//! ```
//!
//! The gate itself is the core `User.waitpong` field (checked in `try_register`,
//! like `dns_pending`); this module just arms it at connect and clears it on the
//! matching PONG. Behaviour reference: InspIRCd's `m_conn_waitpong`. Native Rust.

use crate::server::Server;
use crate::Uid;

/// A short random cookie the client must echo back in its PONG.
fn cookie() -> String {
    let mut b = [0u8; 8];
    let _ = openssl::rand::rand_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// At connect: if enabled, stash a cookie on the user and PING it. `try_register`
/// will not complete while `User.waitpong` is set.
pub fn arm(s: &mut Server, uid: Uid) {
    if !s.conf_bool("conn_waitpong", false) {
        return;
    }
    let c = cookie();
    if let Some(u) = s.users.get_mut(&uid) {
        u.waitpong = Some(c.clone());
    }
    s.send(uid, format!(":{} PING :{c}", s.name));
}

/// On PONG: clear the gate if the cookie matches. On a wrong reply, optionally drop
/// the client (else keep waiting — a real client will retry on the next PING).
pub fn on_pong(s: &mut Server, uid: Uid, params: &[String]) {
    let Some(want) = s.users.get(&uid).and_then(|u| u.waitpong.clone()) else {
        return; // not waiting (already satisfied, or feature off)
    };
    let got = params.last().map(String::as_str).unwrap_or("");
    if got == want {
        if let Some(u) = s.users.get_mut(&uid) {
            u.waitpong = None;
        }
    } else if s.conf_bool("conn_waitpong_killonbadreply", false) {
        s.send(
            uid,
            "ERROR :Closing link (incorrect ping reply)".to_string(),
        );
        s.remove_user(uid, "Incorrect ping reply");
    }
}
