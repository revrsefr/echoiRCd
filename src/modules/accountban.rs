//! The `a:` matching extban (IRCv3 account-extban): match a user by the services
//! account they are logged into. `+b a:spammer` bans the account `spammer` (glob),
//! `+e a:trusted` exempts one. A user with no account never matches. Dispatched
//! from the channel ban matcher; advertised via `ACCOUNTEXTBAN=a`.

use crate::channels::glob_match;
use crate::server::Server;
use crate::Uid;

/// Does `uid`'s logged-in account match the glob `mask` (the part after `a:`)?
pub fn matches(s: &Server, uid: Uid, mask: &str) -> bool {
    match s.users.get(&uid).and_then(|u| u.account.as_deref()) {
        Some(acct) => glob_match(mask, acct),
        None => false, // not logged in — an account ban can't match
    }
}
