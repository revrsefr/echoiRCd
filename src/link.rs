//! Server-to-server linking — echoIRCd's answer to InspIRCd's `m_spanningtree`.
//!
//! A link connection is a first-class peer, *not* a client `User`: it lives in
//! `Server.links` and is driven by [`Server::on_link`] instead of the client
//! command table. What's here:
//!   * **handshake** — `SERVER <name> <pass> <sid> :<desc>` (shared per-block key),
//!     then `BURST`/`ENDBURST`; a registry of linked servers (`Server.servers`).
//!   * **users** — local users get network **UIDs**; on link-up they're burst as
//!     `UID`, and NICK/QUIT propagate; remote users live in `remote_users`.
//!   * **channels** — JOIN/PART/TOPIC/KICK/MODE (incl. ban/except/invex lists)
//!     propagate; every server tracks a channel's full membership (`Channel.rmembers`,
//!     with prefix modes), modes and bans; channel messages fan out **one copy per
//!     link** (not per remote member), forwarded on but the origin; `FJOIN` bursts
//!     channels (members + bans) on link-up.
//!   * **collisions** — a nick already on the network is refused; an incoming `UID`
//!     that clashes with a local user kills the local (both sides ⇒ both vanish).
//!   * **netsplit** — dropping a link QUITs every user behind it.
//!
//! Toward full InspIRCd interop still: TS6 tie-breaking and the exact
//! CAPAB/FJOIN/metadata wire format. Also: SASL relays here once a services links in.

use std::net::{SocketAddr, TcpStream};

use std::collections::HashSet;

use crate::channels::{Ban, Channel, Member, Topic};
use crate::message::Message;
use crate::server::{now, Server};
use crate::socketengine::OutSink;
use crate::users::{valid_nick, User};
use crate::Uid;

/// A local server-link connection (one hop away). Distinct from a client `User`.
pub struct Link {
    pub uid: Uid,
    pub out: OutSink,
    pub outbound: bool,    // we dialed them (so we introduce ourselves first)
    pub registered: bool,  // handshake complete
    pub sent_server: bool, // we've sent our own SERVER line
    pub sid: Option<String>,
    pub name: Option<String>,
    pub bursting: bool, // between the peer's BURST and ENDBURST
}

/// A server known on the network, for LINKS / MAP / routing.
pub struct RemoteServer {
    pub sid: String,
    pub name: String,
    pub desc: String,
    pub via: Uid, // the local link uid it is reachable through
}

/// A user living on another server, reached via a link — not a local `User`.
pub struct RemoteUser {
    pub uuid: String,
    pub nick: String,
    pub ident: String,
    pub host: String,
    pub realname: String,
    pub account: Option<String>,
    pub sid: String, // origin server id
    pub via: Uid,    // local link uid it is reached through
}

impl RemoteUser {
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.ident, self.host)
    }
}

/// A valid 3-char SID: digit, then two upper-case alphanumerics (InspIRCd's rule).
pub fn valid_sid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && b[0].is_ascii_digit()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

impl Server {
    /// Mint the next network-wide UID for a local user: our SID + 6 base-26 chars
    /// (InspIRCd-style, e.g. `0AAAAAAAB`).
    pub fn next_uuid(&mut self) -> String {
        let mut x = self.uuid_counter;
        self.uuid_counter += 1;
        let mut suffix = [b'A'; 6];
        for c in suffix.iter_mut().rev() {
            *c = b'A' + (x % 26) as u8;
            x /= 26;
        }
        format!(
            "{}{}",
            self.sid,
            std::str::from_utf8(&suffix).unwrap_or("AAAAAA")
        )
    }

    /// Register a new server-link connection. An **outbound** link introduces
    /// itself right away with our `SERVER` line (using the dialled block's key).
    pub fn add_link(
        &mut self,
        uid: Uid,
        addr: SocketAddr,
        out: OutSink,
        _sock: Option<TcpStream>, // held by the reader/writer threads; closed gracefully
        outbound: bool,
    ) {
        let mut sent_server = false;
        if outbound {
            let pass = self
                .link_blocks
                .iter()
                .find(|b| b.ip == addr.ip().to_string())
                .map(|b| b.password.clone());
            if let Some(pass) = pass {
                out.send(format!(
                    "SERVER {} {} {} :{}",
                    self.name, pass, self.sid, self.server_desc
                ));
                sent_server = true;
            }
        }
        self.links.insert(
            uid,
            Link {
                uid,
                out,
                outbound,
                registered: false,
                sent_server,
                sid: None,
                name: None,
                bursting: false,
            },
        );
    }

    fn link_out(&self, uid: Uid, line: String) {
        if let Some(l) = self.links.get(&uid) {
            l.out.send(line);
        }
    }

    /// Dispatch one parsed S2S line from link `uid`.
    pub fn on_link(&mut self, uid: Uid, msg: &Message) {
        let registered = self.links.get(&uid).map(|l| l.registered).unwrap_or(false);
        match msg.command.as_str() {
            "SERVER" if !registered => self.link_server(uid, msg),
            "PING" if registered => {
                let token = msg.params.first().cloned().unwrap_or_default();
                self.link_out(uid, format!("PONG :{token}"));
            }
            "UID" if registered => self.link_uid_recv(uid, msg),
            "NICK" if registered => self.link_nick_recv(uid, msg),
            "QUIT" if registered => self.link_quit_recv(uid, msg),
            "PRIVMSG" if registered => self.link_message_recv(uid, msg, false),
            "NOTICE" if registered => self.link_message_recv(uid, msg, true),
            "JOIN" if registered => self.link_join_recv(uid, msg),
            "PART" if registered => self.link_part_recv(uid, msg),
            "TOPIC" if registered => self.link_topic_recv(uid, msg),
            "KICK" if registered => self.link_kick_recv(uid, msg),
            "MODE" | "FMODE" if registered => self.link_mode_recv(uid, msg),
            "FJOIN" if registered => self.link_fjoin_recv(uid, msg),
            // services (SVS*) enforcement + account login, driven by a linked
            // services pseudoserver
            "SVSNICK" if registered => self.link_svsnick(msg),
            "SVSJOIN" if registered => self.link_svsjoin(msg),
            "SVSPART" if registered => self.link_svspart(msg),
            "SVSMODE" if registered => self.link_svsmode(msg),
            "SVSLOGIN" if registered => self.link_svslogin(msg),
            "SVSLOGOUT" if registered => self.link_svslogout(msg),
            "BURST" => {
                if let Some(l) = self.links.get_mut(&uid) {
                    l.bursting = true;
                }
            }
            "ENDBURST" => {
                if let Some(l) = self.links.get_mut(&uid) {
                    l.bursting = false;
                }
            }
            "SQUIT" => self.close_link(uid, "SQUIT"),
            "ERROR" => {
                eprintln!("[link] {uid} ERROR: {}", msg.params.join(" "));
                self.close_link(uid, "peer error");
            }
            _ => {}
        }
    }

    /// Handle the `SERVER <name> <password> <sid> :<desc>` handshake line.
    fn link_server(&mut self, uid: Uid, msg: &Message) {
        if msg.params.len() < 4 {
            self.reject_link(uid, "Not enough SERVER parameters");
            return;
        }
        let (name, pass, sid, desc) = (
            msg.params[0].clone(),
            msg.params[1].clone(),
            msg.params[2].clone(),
            msg.params[3].clone(),
        );
        let Some(block) = self.link_blocks.iter().find(|b| b.name == name).cloned() else {
            self.reject_link(uid, "No link block for that server name");
            return;
        };
        if block.password != pass {
            self.reject_link(uid, "Invalid link password");
            return;
        }
        if !valid_sid(&sid) || sid == self.sid || self.servers.contains_key(&sid) {
            self.reject_link(uid, "Bad or already-present SID");
            return;
        }

        let already_sent = self.links.get(&uid).map(|l| l.sent_server).unwrap_or(false);
        if let Some(l) = self.links.get_mut(&uid) {
            l.registered = true;
            l.sid = Some(sid.clone());
            l.name = Some(name.clone());
        }
        self.servers.insert(
            sid.clone(),
            RemoteServer {
                sid: sid.clone(),
                name: name.clone(),
                desc: desc.clone(),
                via: uid,
            },
        );
        // if we accepted (inbound) we still owe them our SERVER line
        if !already_sent {
            self.link_out(
                uid,
                format!(
                    "SERVER {} {} {} :{}",
                    self.name, block.password, self.sid, self.server_desc
                ),
            );
            if let Some(l) = self.links.get_mut(&uid) {
                l.sent_server = true;
            }
        }
        // netburst: introduce our local users (channels/FJOIN are phase 2b)
        self.link_out(uid, format!("BURST {}", now()));
        self.burst_users(uid);
        self.burst_channels(uid);
        self.link_out(uid, "ENDBURST".to_string());
        eprintln!("[link] linked {name} ({sid}) — {desc}");
    }

    fn reject_link(&mut self, uid: Uid, why: &str) {
        self.link_out(uid, format!("ERROR :Link denied: {why}"));
        eprintln!("[link] rejected {uid}: {why}");
        self.close_link(uid, why);
    }

    /// Drop a link and every server reachable through it (a netsplit). We don't
    /// force the socket shut: dropping the `Link` drops its `out` sender, so the
    /// writer thread first flushes any queued line (e.g. an `ERROR`) and *then*
    /// closes the socket — otherwise a rejection races its own disconnect.
    pub fn close_link(&mut self, uid: Uid, reason: &str) {
        let mut peer = String::new();
        if let Some(l) = self.links.remove(&uid) {
            peer = l.name.clone().unwrap_or_default();
            if let Some(sid) = l.sid {
                eprintln!("[link] netsplit {peer} ({sid}): {reason}");
            }
        }
        self.servers.retain(|_, s| s.via != uid);
        // every remote user reached through this link is now gone (netsplit) —
        // drop them from channels and QUIT them to any local channel-mates.
        let netreason = format!("{} {peer}", self.name);
        let gone: Vec<String> = self
            .remote_users
            .iter()
            .filter(|(_, ru)| ru.via == uid)
            .map(|(k, _)| k.clone())
            .collect();
        for uuid in &gone {
            self.drop_remote_user(uuid, &netreason);
        }
    }

    /// Periodic keepalive: PING every registered link.
    pub fn ping_links(&self) {
        let token = self.sid.clone();
        let uids: Vec<Uid> = self
            .links
            .iter()
            .filter(|(_, l)| l.registered)
            .map(|(&u, _)| u)
            .collect();
        for u in uids {
            self.link_out(u, format!("PING :{token}"));
        }
    }

    /// Relay `line` to every registered link except `except` (the origin).
    pub fn propagate(&self, line: &str, except: Option<Uid>) {
        let targets: Vec<Uid> = self
            .links
            .iter()
            .filter(|(u, l)| l.registered && Some(**u) != except)
            .map(|(&u, _)| u)
            .collect();
        for u in targets {
            self.link_out(u, line.to_string());
        }
    }

    /// The `UID` introduction line for a local user.
    fn uid_line(&self, u: &User) -> String {
        let acct = u.account.clone().unwrap_or_else(|| "*".to_string());
        format!(
            ":{} UID {} {} {} {} {} :{}",
            self.sid,
            u.uuid,
            u.nick,
            u.ident,
            u.host_display(),
            acct,
            u.realname
        )
    }

    /// Burst all local registered users to a freshly-linked peer.
    fn burst_users(&self, link_uid: Uid) {
        let lines: Vec<String> = self
            .users
            .values()
            .filter(|u| u.registered)
            .map(|u| self.uid_line(u))
            .collect();
        for l in lines {
            self.link_out(link_uid, l);
        }
    }

    /// Announce a newly-registered local user to every link.
    pub fn introduce_to_links(&self, uid: Uid) {
        if self.links.is_empty() {
            return;
        }
        if let Some(u) = self.users.get(&uid) {
            let line = self.uid_line(u);
            self.propagate(&line, None);
        }
    }

    /// Propagate a local user's nick change.
    pub fn propagate_nick(&self, uid: Uid, newnick: &str) {
        if let Some(u) = self.users.get(&uid) {
            if u.registered && !self.links.is_empty() {
                self.propagate(&format!(":{} NICK {newnick}", u.uuid), None);
            }
        }
    }

    /// Find a remote user by nick: returns `(uuid, via-link)`.
    pub fn find_remote(&self, nick: &str) -> Option<(String, Uid)> {
        let uuid = self.remote_nick.get(&nick.to_ascii_lowercase())?;
        let ru = self.remote_users.get(uuid)?;
        Some((uuid.clone(), ru.via))
    }

    /// Resolve any network uuid (remote or local) to a `nick!user@host` prefix.
    pub fn uuid_prefix(&self, uuid: &str) -> Option<String> {
        if let Some(ru) = self.remote_users.get(uuid) {
            return Some(ru.prefix());
        }
        self.uuid_local
            .get(uuid)
            .and_then(|&uid| self.users.get(&uid))
            .map(|u| u.prefix())
    }

    /// Route a message from a local sender to a remote user across its link.
    pub fn send_to_remote(&self, sender: Uid, target_uuid: &str, via: Uid, cmd: &str, text: &str) {
        if let Some(u) = self.users.get(&sender) {
            self.link_out(via, format!(":{} {cmd} {target_uuid} :{text}", u.uuid));
        }
    }

    // --- services (SVS*) over S2S ---------------------------------------------
    // A linked services pseudoserver enforces nick/join/part/mode and account
    // login on our users with these. Authority is the link itself — only
    // registered peers reach `on_link`. Targets are network UUIDs or nicks; we
    // act only on locally-present targets (multi-hop forwarding is still TODO,
    // like the SVSLOGIN/SASL note in the module header). Each reuses the same
    // primitive as the local SVS* command, so behaviour and propagation match.

    /// Resolve an S2S target token (network UUID or nickname) to a local user.
    fn link_local_target(&self, target: &str) -> Option<Uid> {
        self.uuid_local
            .get(target)
            .copied()
            .or_else(|| self.find_nick(target))
    }

    /// `:src SVSNICK <target> <newnick> [ts]` — force a nick change.
    fn link_svsnick(&mut self, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        let (target, newnick) = (&msg.params[0], &msg.params[1]);
        let Some(tuid) = self.link_local_target(target) else {
            return;
        };
        if !valid_nick(newnick)
            || self.find_nick(newnick).is_some()
            || self.remote_nick.contains_key(&newnick.to_ascii_lowercase())
        {
            return; // collision / invalid — services should pick a free nick
        }
        self.set_nick(tuid, newnick);
    }

    /// `:src SVSJOIN <target> <channel>` — force a join.
    fn link_svsjoin(&mut self, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        if let Some(tuid) = self.link_local_target(&msg.params[0]) {
            self.join(tuid, &msg.params[1], None);
        }
    }

    /// `:src SVSPART <target> <channel> [reason]` — force a part.
    fn link_svspart(&mut self, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        if let Some(tuid) = self.link_local_target(&msg.params[0]) {
            let reason = msg
                .params
                .get(2)
                .cloned()
                .unwrap_or_else(|| "Services forced part".to_string());
            self.force_part(tuid, &msg.params[1], &reason);
        }
    }

    /// `:src SVSMODE <target> <modes>` — set a user's modes (e.g. `+r`). Channel
    /// modes travel as (F)MODE, so a `#` target is ignored here.
    fn link_svsmode(&mut self, msg: &Message) {
        if msg.params.len() < 2 || msg.params[0].starts_with('#') {
            return;
        }
        if let Some(tuid) = self.link_local_target(&msg.params[0]) {
            crate::coremods::core_mode::svs_set_user_modes(self, tuid, &msg.params[1]);
        }
    }

    /// `:src SVSLOGIN <target> <account>` — log a user into (or, with `*`/`0`, out
    /// of) a services account.
    fn link_svslogin(&mut self, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        if let Some(tuid) = self.link_local_target(&msg.params[0]) {
            let account = &msg.params[1];
            if account == "*" || account == "0" {
                self.logout(tuid);
            } else {
                self.set_login(tuid, account);
            }
        }
    }

    /// `:src SVSLOGOUT <target>` — log a user out of their account.
    fn link_svslogout(&mut self, msg: &Message) {
        if let Some(t) = msg.params.first() {
            if let Some(tuid) = self.link_local_target(t) {
                self.logout(tuid);
            }
        }
    }

    // --- inbound S2S records --------------------------------------------------

    fn link_uid_recv(&mut self, via: Uid, msg: &Message) {
        // :<sid> UID <uuid> <nick> <ident> <host> <account> :<realname>
        if msg.params.len() < 6 {
            return;
        }
        let sid = msg.source.clone().unwrap_or_default();
        let uuid = msg.params[0].clone();
        let nick = msg.params[1].clone();
        // nick collision: a local holder is killed (both sides do this, so both
        // vanish deterministically); an existing remote holder simply wins.
        if let Some(luid) = self.find_nick(&nick) {
            self.send(luid, "ERROR :Closing link: Nick collision".to_string());
            self.remove_user(luid, "Nick collision");
            return;
        }
        if self.remote_nick.contains_key(&nick.to_ascii_lowercase()) {
            return;
        }
        let account = if msg.params[4] == "*" {
            None
        } else {
            Some(msg.params[4].clone())
        };
        self.remote_nick
            .insert(nick.to_ascii_lowercase(), uuid.clone());
        self.remote_users.insert(
            uuid.clone(),
            RemoteUser {
                uuid,
                nick,
                ident: msg.params[2].clone(),
                host: msg.params[3].clone(),
                realname: msg.params[5].clone(),
                account,
                sid: sid.clone(),
                via,
            },
        );
        let line = format!(
            ":{sid} UID {} {} {} {} {} :{}",
            msg.params[0],
            msg.params[1],
            msg.params[2],
            msg.params[3],
            msg.params[4],
            msg.params[5]
        );
        self.propagate(&line, Some(via));
    }

    fn link_nick_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> NICK <newnick>
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let Some(newnick) = msg.params.first().cloned() else {
            return;
        };
        let old = match self.remote_users.get_mut(&uuid) {
            Some(ru) => {
                let old = ru.nick.clone();
                ru.nick = newnick.clone();
                old
            }
            None => return,
        };
        self.remote_nick.remove(&old.to_ascii_lowercase());
        self.remote_nick
            .insert(newnick.to_ascii_lowercase(), uuid.clone());
        self.propagate(&format!(":{uuid} NICK {newnick}"), Some(via));
    }

    fn link_quit_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> QUIT :<reason>
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let reason = msg.params.first().cloned().unwrap_or_default();
        self.drop_remote_user(&uuid, &reason);
        self.propagate(&format!(":{uuid} QUIT :{reason}"), Some(via));
    }

    fn link_message_recv(&mut self, via: Uid, msg: &Message, notice: bool) {
        // :<srcuuid> PRIVMSG <#chan|dstuuid> :<text>
        let cmd = if notice { "NOTICE" } else { "PRIVMSG" };
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 2 {
            return;
        }
        let (target, text) = (msg.params[0].clone(), msg.params[1].clone());
        let Some(prefix) = self.uuid_prefix(&src) else {
            return;
        };
        if target.starts_with('#') {
            let key = target.to_ascii_lowercase();
            if !self.channels.contains_key(&key) {
                return;
            }
            let line = format!(":{prefix} {cmd} {target} :{text}");
            let members: Vec<Uid> = self.channels[&key].members.keys().copied().collect();
            for m in members {
                if self.users.get(&m).map(|u| u.flags.deaf).unwrap_or(false) {
                    continue;
                }
                self.send(m, line.clone());
            }
            // forward to the other links that have members in this channel
            for l in self.channel_link_targets(&key, Some(via)) {
                self.link_out(l, format!(":{src} {cmd} {target} :{text}"));
            }
        } else if let Some(&dst) = self.uuid_local.get(&target) {
            let nick = self
                .users
                .get(&dst)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            self.send(dst, format!(":{prefix} {cmd} {nick} :{text}"));
        }
    }

    /// Tell linked servers a local user joined a channel.
    pub fn propagate_join(&self, uid: Uid, chan: &str) {
        if self.links.is_empty() {
            return;
        }
        if let Some(u) = self.users.get(&uid) {
            if u.registered {
                self.propagate(&format!(":{} JOIN {chan}", u.uuid), None);
            }
        }
    }

    /// Tell linked servers a local user parted a channel.
    pub fn propagate_part(&self, uid: Uid, chan: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        if let Some(u) = self.users.get(&uid) {
            if u.registered {
                let line = if reason.is_empty() {
                    format!(":{} PART {chan}", u.uuid)
                } else {
                    format!(":{} PART {chan} :{reason}", u.uuid)
                };
                self.propagate(&line, None);
            }
        }
    }

    /// The distinct links a channel's remote members sit behind (minus `except`).
    fn channel_link_targets(&self, key: &str, except: Option<Uid>) -> Vec<Uid> {
        let mut set: HashSet<Uid> = HashSet::new();
        if let Some(ch) = self.channels.get(key) {
            for uuid in ch.rmembers.keys() {
                if let Some(ru) = self.remote_users.get(uuid) {
                    if Some(ru.via) != except {
                        set.insert(ru.via);
                    }
                }
            }
        }
        set.into_iter().collect()
    }

    /// Relay a local user's channel message to every link with members there.
    pub fn send_channel_to_links(
        &self,
        sender: Uid,
        key: &str,
        target: &str,
        cmd: &str,
        text: &str,
    ) {
        let Some(uuid) = self.users.get(&sender).map(|u| u.uuid.clone()) else {
            return;
        };
        let line = format!(":{uuid} {cmd} {target} :{text}");
        for l in self.channel_link_targets(key, None) {
            self.link_out(l, line.clone());
        }
    }

    fn link_join_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> JOIN #chan
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let Some(chan) = msg.params.first().cloned() else {
            return;
        };
        if !self.remote_users.contains_key(&uuid) {
            return;
        }
        let key = chan.to_ascii_lowercase();
        self.channels
            .entry(key.clone())
            .or_insert_with(|| Channel::new(&chan))
            .rmembers
            .insert(uuid.clone(), Member::default());
        let prefix = self
            .remote_users
            .get(&uuid)
            .map(|r| r.prefix())
            .unwrap_or_default();
        self.to_channel(&key, &format!(":{prefix} JOIN {chan}"), None);
        self.propagate(&format!(":{uuid} JOIN {chan}"), Some(via));
    }

    fn link_part_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> PART #chan [:reason]
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let Some(chan) = msg.params.first().cloned() else {
            return;
        };
        let reason = msg.params.get(1).cloned().unwrap_or_default();
        let key = chan.to_ascii_lowercase();
        let removed = self
            .channels
            .get_mut(&key)
            .map(|c| c.rmembers.remove(&uuid).is_some())
            .unwrap_or(false);
        if !removed {
            return;
        }
        let prefix = self
            .remote_users
            .get(&uuid)
            .map(|r| r.prefix())
            .unwrap_or_default();
        let line = if reason.is_empty() {
            format!(":{prefix} PART {chan}")
        } else {
            format!(":{prefix} PART {chan} :{reason}")
        };
        self.to_channel(&key, &line, None);
        self.channels.retain(|_, c| !c.is_empty());
        let fwd = if reason.is_empty() {
            format!(":{uuid} PART {chan}")
        } else {
            format!(":{uuid} PART {chan} :{reason}")
        };
        self.propagate(&fwd, Some(via));
    }

    /// Remove a remote user everywhere (channels + registries) and QUIT them to
    /// any local users who shared a channel.
    fn drop_remote_user(&mut self, uuid: &str, reason: &str) {
        let prefix = match self.remote_users.get(uuid) {
            Some(ru) => ru.prefix(),
            None => return,
        };
        let mut notify: HashSet<Uid> = HashSet::new();
        let chans: Vec<String> = self
            .channels
            .iter()
            .filter(|(_, c)| c.rmembers.contains_key(uuid))
            .map(|(k, _)| k.clone())
            .collect();
        for key in &chans {
            if let Some(c) = self.channels.get_mut(key) {
                c.rmembers.remove(uuid);
                for &m in c.members.keys() {
                    notify.insert(m);
                }
            }
        }
        let line = format!(":{prefix} QUIT :{reason}");
        for m in notify {
            self.send(m, line.clone());
        }
        self.channels.retain(|_, c| !c.is_empty());
        if let Some(ru) = self.remote_users.remove(uuid) {
            self.remote_nick.remove(&ru.nick.to_ascii_lowercase());
        }
    }

    /// Relay `:<sender-uuid> <rest>` to every link (MODE/TOPIC/KICK propagation).
    pub fn propagate_from_user(&self, uid: Uid, rest: &str) {
        if self.links.is_empty() {
            return;
        }
        if let Some(u) = self.users.get(&uid) {
            if u.registered {
                self.propagate(&format!(":{} {rest}", u.uuid), None);
            }
        }
    }

    /// Set a prefix mode on `nick` in `key`, be they a local or remote member.
    fn set_member_prefix(&mut self, key: &str, nick: &str, letter: char, adding: bool) {
        if let Some(uid) = self.find_nick(nick) {
            if let Some(m) = self
                .channels
                .get_mut(key)
                .and_then(|c| c.members.get_mut(&uid))
            {
                m.set_prefix(letter, adding);
            }
        } else if let Some((uuid, _)) = self.find_remote(nick) {
            if let Some(m) = self
                .channels
                .get_mut(key)
                .and_then(|c| c.rmembers.get_mut(&uuid))
            {
                m.set_prefix(letter, adding);
            }
        }
    }

    fn link_topic_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> TOPIC #chan :<text>
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 2 {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        let text = msg.params[1].clone();
        if !self.channels.contains_key(&key) {
            return;
        }
        let setter = self
            .remote_users
            .get(&src)
            .map(|r| r.nick.clone())
            .unwrap_or_default();
        if let Some(c) = self.channels.get_mut(&key) {
            c.topic = Some(Topic {
                text: text.clone(),
                setter,
                ts: now(),
            });
        }
        let prefix = self.uuid_prefix(&src).unwrap_or_default();
        self.to_channel(&key, &format!(":{prefix} TOPIC {chan} :{text}"), None);
        self.propagate(&format!(":{src} TOPIC {chan} :{text}"), Some(via));
    }

    fn link_kick_recv(&mut self, via: Uid, msg: &Message) {
        // :<kicker-uuid> KICK #chan <victim-nick> :<reason>
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 2 {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        let victim = msg.params[1].clone();
        let reason = msg.params.get(2).cloned().unwrap_or_else(|| victim.clone());
        let prefix = self.uuid_prefix(&src).unwrap_or_default();
        let mut removed = false;
        if let Some(vuid) = self.find_nick(&victim) {
            if let Some(c) = self.channels.get_mut(&key) {
                removed = c.members.remove(&vuid).is_some();
            }
            if removed {
                if let Some(u) = self.users.get_mut(&vuid) {
                    u.channels.remove(&key);
                }
            }
        } else if let Some((vuuid, _)) = self.find_remote(&victim) {
            if let Some(c) = self.channels.get_mut(&key) {
                removed = c.rmembers.remove(&vuuid).is_some();
            }
        }
        if !removed {
            return;
        }
        self.to_channel(
            &key,
            &format!(":{prefix} KICK {chan} {victim} :{reason}"),
            None,
        );
        self.channels.retain(|_, c| !c.is_empty());
        self.propagate(&format!(":{src} KICK {chan} {victim} :{reason}"), Some(via));
    }

    fn link_mode_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> MODE #chan <modestring> [params...]  (applied without re-checking)
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 2 || !msg.params[0].starts_with('#') {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !self.channels.contains_key(&key) {
            return;
        }
        let modestring = msg.params[1].clone();
        let args: Vec<String> = msg.params[2..].to_vec();
        let mut argi = 0usize;
        let mut sign = '+';
        for c in modestring.chars() {
            if c == '+' || c == '-' {
                sign = c;
                continue;
            }
            let adding = sign == '+';
            match c {
                'q' | 'a' | 'o' | 'h' | 'v' => {
                    if let Some(n) = args.get(argi).cloned() {
                        argi += 1;
                        self.set_member_prefix(&key, &n, c, adding);
                    }
                }
                'k' => {
                    let p = args.get(argi).cloned();
                    if p.is_some() {
                        argi += 1;
                    }
                    if let Some(ch) = self.channels.get_mut(&key) {
                        ch.modes.key = if adding { p } else { None };
                    }
                }
                'l' => {
                    if adding {
                        if let Some(n) = args.get(argi).and_then(|s| s.parse::<u32>().ok()) {
                            argi += 1;
                            if let Some(ch) = self.channels.get_mut(&key) {
                                ch.modes.limit = Some(n);
                            }
                        }
                    } else if let Some(ch) = self.channels.get_mut(&key) {
                        ch.modes.limit = None;
                    }
                }
                'b' | 'e' | 'I' => {
                    if let Some(mask) = args.get(argi).cloned() {
                        argi += 1;
                        let setter = self
                            .remote_users
                            .get(&src)
                            .map(|r| r.nick.clone())
                            .unwrap_or_else(|| src.clone());
                        if let Some(ch) = self.channels.get_mut(&key) {
                            let list = match c {
                                'b' => &mut ch.bans,
                                'e' => &mut ch.excepts,
                                _ => &mut ch.invex,
                            };
                            if adding {
                                if !list.iter().any(|b| b.mask == mask) {
                                    list.push(Ban {
                                        mask,
                                        setter,
                                        ts: now(),
                                    });
                                }
                            } else {
                                list.retain(|b| b.mask != mask);
                            }
                        }
                    }
                }
                _ => {
                    if let Some(ch) = self.channels.get_mut(&key) {
                        ch.modes.set_by_letter(c, adding);
                    }
                }
            }
        }
        // source is a user (uuid) or, for a burst, a server (sid)
        let prefix = self
            .uuid_prefix(&src)
            .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
            .unwrap_or_else(|| self.name.clone());
        let paramstr = if args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.join(" "))
        };
        self.to_channel(
            &key,
            &format!(":{prefix} MODE {chan} {modestring}{paramstr}"),
            None,
        );
        self.propagate(
            &format!(":{src} MODE {chan} {modestring}{paramstr}"),
            Some(via),
        );
    }

    /// Burst every channel (name, ts, modes, prefixed members) to a new peer.
    fn burst_channels(&self, link_uid: Uid) {
        let mut lines = Vec::new();
        for ch in self.channels.values() {
            let mut mem: Vec<String> = Vec::new();
            for (uid, m) in &ch.members {
                if let Some(u) = self.users.get(uid) {
                    mem.push(format!("{}{}", m.all_prefixes(), u.uuid));
                }
            }
            for (uuid, m) in &ch.rmembers {
                mem.push(format!("{}{}", m.all_prefixes(), uuid));
            }
            if mem.is_empty() {
                continue;
            }
            lines.push(format!(
                ":{} FJOIN {} {} {} :{}",
                self.sid,
                ch.name,
                ch.created,
                ch.modes.render(false),
                mem.join(" ")
            ));
            // burst the ban / except / invite-exception lists too
            for (letter, list) in [('b', &ch.bans), ('e', &ch.excepts), ('I', &ch.invex)] {
                for b in list {
                    lines.push(format!(
                        ":{} MODE {} +{letter} {}",
                        self.sid, ch.name, b.mask
                    ));
                }
            }
        }
        for l in lines {
            self.link_out(link_uid, l);
        }
    }

    fn link_fjoin_recv(&mut self, via: Uid, msg: &Message) {
        // :<sid> FJOIN #chan <ts> <modes> :<pfx>uuid <pfx>uuid ...
        if msg.params.len() < 4 {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        let ts: u64 = msg.params[1].parse().unwrap_or_else(|_| now());
        let modes = msg.params[2].clone();
        let memberlist = msg.params[3].clone();
        let is_new = !self.channels.contains_key(&key);
        {
            let ch = self
                .channels
                .entry(key.clone())
                .or_insert_with(|| Channel::new(&chan));
            if is_new {
                ch.created = ts;
                let mut sign = '+';
                for c in modes.chars() {
                    match c {
                        '+' => sign = '+',
                        '-' => sign = '-',
                        _ => ch.modes.set_by_letter(c, sign == '+'),
                    }
                }
            }
        }
        let mut adds: Vec<(String, Member)> = Vec::new();
        for tok in memberlist.split_whitespace() {
            let (pfx, uuid) = split_member(tok);
            if self.uuid_local.contains_key(&uuid) || !self.remote_users.contains_key(&uuid) {
                continue; // our own user, or one we don't know yet
            }
            let mut m = Member::default();
            for pc in pfx.chars() {
                m.set_prefix(prefix_letter(pc), true);
            }
            adds.push((uuid, m));
        }
        if let Some(ch) = self.channels.get_mut(&key) {
            for (uuid, m) in adds {
                ch.rmembers.insert(uuid, m);
            }
        }
        let raw = format!(
            ":{} FJOIN {chan} {ts} {modes} :{memberlist}",
            msg.source.clone().unwrap_or_default()
        );
        self.propagate(&raw, Some(via));
    }
}

/// Split a bursted member token `@+0AAAAAAAB` into its prefix chars and uuid.
fn split_member(tok: &str) -> (String, String) {
    let idx = tok
        .find(|c: char| !"~&@%+".contains(c))
        .unwrap_or(tok.len());
    (tok[..idx].to_string(), tok[idx..].to_string())
}

/// Map a prefix char to its mode letter (`@` → `o`, …).
fn prefix_letter(c: char) -> char {
    match c {
        '~' => 'q',
        '&' => 'a',
        '@' => 'o',
        '%' => 'h',
        '+' => 'v',
        _ => ' ',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_validation() {
        assert!(valid_sid("0AA"));
        assert!(valid_sid("1Z9"));
        assert!(valid_sid("9ZZ"));
        assert!(!valid_sid("AAA")); // must start with a digit
        assert!(!valid_sid("0a1")); // no lowercase
        assert!(!valid_sid("0A")); // too short
        assert!(!valid_sid("0ABC")); // too long
    }
}
