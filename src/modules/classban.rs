//! classban — the `C:` matching extban: match a local user by the name of the connect
//! class they were assigned. `+b C:guests` bans everyone whose class name (spaces
//! turned into `_`) matches the glob; local users only (remote users have no local
//! class here). Uses the letter `C` (Class) — a matching extban like `G:`/`A:` —
//! because `n:` is already the no-nick-change acting extban. Setting a `C:` ban can
//! be restricted to opers with `classban_operonly`.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// Does `uid`'s assigned connect class match the `C:` glob `spec`?
pub fn matches(s: &Server, uid: Uid, spec: &str) -> bool {
    let Some(class) = s.users.get(&uid).and_then(|u| u.class.clone()) else {
        return false; // no local class (unregistered or remote) — never matches
    };
    glob_match(spec, &class.replace(' ', "_"))
}
