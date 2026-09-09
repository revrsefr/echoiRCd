//! operprefix — network staff (IRC opers) get a distinct `!` prefix (prefix mode
//! `y`, ranked above channel owner) in every channel, so users can see who's staff
//! and ops can't kick/deop them. Enabled with `operprefix = yes`. Also provides the
//! shared grant/clear primitive used by [`crate::modules::ojoin`].

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

pub fn enabled(s: &Server) -> bool {
    s.conf_bool("operprefix", false)
}

/// Set/clear the oper prefix for `uid` in one channel and broadcast `MODE ±y`.
fn set(s: &mut Server, uid: Uid, key: &str, on: bool) {
    let Some(nick) = s.users.get(&uid).map(|u| u.nick.clone()) else {
        return;
    };
    let changed = match s
        .channels
        .get_mut(key)
        .and_then(|c| c.members.get_mut(&uid))
    {
        Some(m) if m.oprefix() != on => {
            m.set_oprefix(on);
            true
        }
        _ => false,
    };
    if !changed {
        return;
    }
    let sign = if on { '+' } else { '-' };
    let name = s
        .channels
        .get(key)
        .map(|c| c.name.clone())
        .unwrap_or_default();
    s.to_channel(
        key,
        &format!(":{} MODE {name} {sign}y {nick}", s.name),
        None,
    );
    // links: a timestamped FMODE (not a plain channel MODE), member named by uuid
    let sid = s.sid.clone();
    s.propagate_chan_mode(
        &sid,
        &name,
        &format!("{sign}y"),
        std::slice::from_ref(&nick),
    );
}

/// Grant the oper prefix in `key` (used by ojoin and on-join auto-grant).
pub fn grant(s: &mut Server, uid: Uid, key: &str) {
    set(s, uid, key, true);
}

fn all_channels(s: &Server, uid: Uid) -> Vec<String> {
    s.users
        .get(&uid)
        .map(|u| u.channels.iter().cloned().collect())
        .unwrap_or_default()
}

/// Auto-grant to opers on join when the feature is enabled.
fn join_grant(s: &mut Server, uid: Uid, key: &str) {
    if enabled(s) && s.is_oper(uid) {
        grant(s, uid, key);
    }
}

/// Grant across all of `uid`'s channels — on oper-up.
pub fn grant_all(s: &mut Server, uid: Uid) {
    if !enabled(s) {
        return;
    }
    for key in all_channels(s, uid) {
        grant(s, uid, &key);
    }
}

/// Clear across all of `uid`'s channels — on de-oper (safe no-op if never granted).
pub fn clear_all(s: &mut Server, uid: Uid) {
    for key in all_channels(s, uid) {
        set(s, uid, &key, false);
    }
}

pub struct OperPrefix;
impl Module for OperPrefix {
    fn name(&self) -> &'static str {
        "operprefix"
    }
    fn on_join(&mut self, s: &mut Server, uid: Uid, chan: &str) {
        join_grant(s, uid, &chan.to_ascii_lowercase());
    }
}
