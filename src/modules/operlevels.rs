//! operlevels — each `oper` block may carry a numeric level (`oper = <name> <pass>
//! <level>`, default 0). A lower-level oper cannot KILL a higher-level oper. The
//! level is stored on the user at OPER; with all levels at the default it's inert,
//! so no config flag is needed.

use crate::server::Server;
use crate::Uid;

/// The oper level stored on a user's `ext`.
struct OperLevel(u32);

/// Record `uid`'s oper level (called from the OPER handler after oper-up).
pub fn set(s: &mut Server, uid: Uid, level: u32) {
    if let Some(u) = s.users.get_mut(&uid) {
        u.ext.set(OperLevel(level));
    }
}

/// A user's oper level (0 if unset / not an oper).
pub fn level(s: &Server, uid: Uid) -> u32 {
    s.users
        .get(&uid)
        .and_then(|u| u.ext.get::<OperLevel>())
        .map(|l| l.0)
        .unwrap_or(0)
}

/// The reason `actor` may not KILL `target` under operlevels, if any: only when the
/// target is an oper of a strictly higher level than the actor.
pub fn deny_kill(s: &Server, actor: Uid, target: Uid) -> Option<String> {
    if !s.is_oper(target) {
        return None; // non-opers aren't protected
    }
    if level(s, actor) < level(s, target) {
        let tnick = s
            .users
            .get(&target)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        Some(format!(
            "Permission Denied- {tnick} outranks you (higher oper level)"
        ))
    } else {
        None
    }
}
