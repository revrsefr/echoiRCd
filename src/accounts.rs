//! Account layer — the ircd's *services-ready* account support, modelled on
//! InspIRCd's `m_services_account`. **This is NOT a services daemon.**
//!
//! echoIRCd stores no passwords and runs no NickServ — registering nicks/channels
//! is a **services package**'s job (Anope/Atheme), linked in over S2S. What the
//! ircd owns is only the plumbing a service plugs into:
//!   * a per-user **account name** (`User.account`) — the extension a service sets
//!     or clears (InspIRCd's `accountname` metadata), which flips user mode `+r`;
//!   * the account-gated **modes** (chan `+R`/`+M`, user `+r`/`+R`) that key off it
//!     and live in [`crate::mode`];
//!   * the **interface** a service drives it through: [`Server::set_login`] /
//!     [`Server::logout`], reached today via the oper/`SVSLOGIN` command and, once
//!     S2S + SASL land, by a linked services pseudoserver.
//!
//! So a real network runs Anope *beside* echoIRCd; the ircd just has to be ready.

use crate::server::Server;
use crate::Uid;

impl Server {
    pub fn is_logged_in(&self, uid: Uid) -> bool {
        self.users
            .get(&uid)
            .map(|u| u.account.is_some())
            .unwrap_or(false)
    }

    /// Log `uid` into `account` (services-driven): sets the account name, flips
    /// `+r`, and reflects the mode back to the user.
    pub fn set_login(&mut self, uid: Uid, account: &str) {
        let (nick, prefix) = match self.users.get_mut(&uid) {
            Some(u) => {
                u.account = Some(account.to_string());
                u.flags.logged_in = true;
                (u.nick.clone(), u.prefix())
            }
            None => return,
        };
        self.send(uid, format!(":{} MODE {nick} :+r", self.name));
        // account-notify
        self.notify_peers(uid, &format!(":{prefix} ACCOUNT {account}"), |c| {
            c.account_notify
        });
    }

    /// Log `uid` out of any account (services-driven): clears `+r`.
    pub fn logout(&mut self, uid: Uid) {
        let (nick, prefix) = match self.users.get_mut(&uid) {
            Some(u) if u.account.is_some() => {
                u.account = None;
                u.flags.logged_in = false;
                (u.nick.clone(), u.prefix())
            }
            _ => return,
        };
        self.send(uid, format!(":{} MODE {nick} :-r", self.name));
        self.notify_peers(uid, &format!(":{prefix} ACCOUNT *"), |c| c.account_notify);
    }
}
