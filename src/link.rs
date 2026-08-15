//! Server-to-server linking (spanning tree).
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

use std::net::{SocketAddr, TcpStream};

use std::collections::HashSet;

use crate::channels::{glob_match, Ban, Channel, Member, Topic};
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
    pub ip: String,  // client IP (for network-wide clone limits); "" if a peer omitted it
    pub sid: String, // origin server id
    pub via: Uid,    // local link uid it is reached through
}

impl RemoteUser {
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.ident, self.host)
    }
}

/// A valid 3-char SID: digit, then two upper-case alphanumerics.
pub fn valid_sid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3
        && b[0].is_ascii_digit()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

impl Server {
    /// Mint the next network-wide UID for a local user: our SID + 6 base-26 chars
    /// (e.g. `0AAAAAAAB`).
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
            "FTOPIC" if registered => self.link_ftopic_recv(uid, msg),
            "KICK" if registered => self.link_kick_recv(uid, msg),
            "MODE" | "FMODE" if registered => self.link_mode_recv(uid, msg),
            "FJOIN" if registered => self.link_fjoin_recv(uid, msg),
            "IJOIN" if registered => self.link_ijoin_recv(uid, msg),
            // services (SVS*) enforcement + account login, driven by a linked
            // services pseudoserver (forwarded on if the target is on another server)
            "SVSNICK" if registered => self.link_svsnick(uid, msg),
            "SVSJOIN" if registered => self.link_svsjoin(uid, msg),
            "SVSPART" if registered => self.link_svspart(uid, msg),
            "SVSMODE" if registered => self.link_svsmode(uid, msg),
            "SVSLOGIN" if registered => self.link_svslogin(uid, msg),
            "SVSLOGOUT" if registered => self.link_svslogout(uid, msg),
            "SVSHOLD" if registered => self.link_svshold(uid, msg),
            "SVSTOPIC" if registered => self.link_svstopic(uid, msg),
            "SVSOPER" if registered => self.link_svsoper(uid, msg),
            "SVSCMODE" if registered => self.link_svscmode(uid, msg),
            "ENCAP" if registered => self.link_encap(uid, msg),
            "METADATA" if registered => self.link_metadata(uid, msg),
            "SASL" if registered => self.link_sasl(uid, msg),
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

    /// The `UID` introduction line for a local user. Field order is uuid, nick
    /// timestamp, nick, real host, displayed host, real ident, displayed ident,
    /// ip, signon timestamp, user modes, then the real name as the trailing param.
    fn uid_line(&self, u: &User) -> String {
        format!(
            ":{} UID {} {} {} {} {} {} {} {} {} {} :{}",
            self.sid,
            u.uuid,
            u.signon,
            u.nick,
            u.host,
            u.host_display(),
            u.ident,
            u.ident,
            u.addr.ip(),
            u.signon,
            u.flags.umodes(),
            u.realname
        )
    }

    /// The lines that introduce a local user across a link: the `UID`, and — when
    /// they're logged into an account — a `METADATA accountname` so services and
    /// remote servers see the login (the account isn't carried in `UID`).
    fn user_intro_lines(&self, u: &User) -> Vec<String> {
        let mut v = vec![self.uid_line(u)];
        if let Some(acct) = &u.account {
            v.push(format!(":{} METADATA {} accountname :{acct}", self.sid, u.uuid));
        }
        v
    }

    /// Burst all local registered users to a freshly-linked peer.
    fn burst_users(&self, link_uid: Uid) {
        let lines: Vec<String> = self
            .users
            .values()
            .filter(|u| u.registered)
            .flat_map(|u| self.user_intro_lines(u))
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
            for line in self.user_intro_lines(u) {
                self.propagate(&line, None);
            }
        }
    }

    /// Propagate a local user's nick change.
    pub fn propagate_nick(&self, uid: Uid, newnick: &str) {
        if let Some(u) = self.users.get(&uid) {
            if u.registered && !self.links.is_empty() {
                self.propagate(&format!(":{} NICK {newnick} {}", u.uuid, now()), None);
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
    // login with these. Authority is the link itself — only registered peers
    // reach `on_link`. Targets are network UUIDs or nicks: a locally-present
    // target is acted on directly (reusing the same primitive as the local SVS*
    // command); a target on another server is forwarded one hop toward it.

    /// Resolve an S2S target token (network UUID or nickname) to a local user.
    fn link_local_target(&self, target: &str) -> Option<Uid> {
        self.uuid_local
            .get(target)
            .copied()
            .or_else(|| self.find_nick(target))
    }

    /// The local link toward the server that owns `target` (a UUID or nick), if the
    /// user is remote and reachable. `None` when the target is local or unknown.
    fn link_toward(&self, target: &str) -> Option<Uid> {
        let uuid = if self.remote_users.contains_key(target) {
            target.to_string()
        } else {
            self.remote_nick.get(&target.to_ascii_lowercase())?.clone()
        };
        self.remote_users.get(&uuid).map(|ru| ru.via)
    }

    /// Route a services command aimed at a non-local `target` one hop onward.
    /// Returns true if it was forwarded (never back down the link it came from).
    fn forward_to_target(&self, target: &str, msg: &Message, from: Uid) -> bool {
        match self.link_toward(target) {
            Some(v) if v != from => {
                self.link_out(v, msg.to_wire());
                true
            }
            _ => false,
        }
    }

    /// `:src SVSNICK <target> <newnick> [ts]` — force a nick change.
    fn link_svsnick(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        let (target, newnick) = (&msg.params[0], &msg.params[1]);
        let Some(tuid) = self.link_local_target(target) else {
            self.forward_to_target(target, msg, from);
            return;
        };
        if !valid_nick(newnick, self.conf_num("maxnick", 30usize))
            || self.find_nick(newnick).is_some()
            || self.remote_nick.contains_key(&newnick.to_ascii_lowercase())
        {
            return; // collision / invalid — services should pick a free nick
        }
        self.set_nick(tuid, newnick);
    }

    /// `:src SVSJOIN <target> <channel>` — force a join.
    fn link_svsjoin(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        match self.link_local_target(&msg.params[0]) {
            Some(tuid) => self.join(tuid, &msg.params[1], None),
            None => {
                self.forward_to_target(&msg.params[0], msg, from);
            }
        }
    }

    /// `:src SVSPART <target> <channel> [reason]` — force a part.
    fn link_svspart(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        match self.link_local_target(&msg.params[0]) {
            Some(tuid) => {
                let reason = msg
                    .params
                    .get(2)
                    .cloned()
                    .unwrap_or_else(|| "Services forced part".to_string());
                self.force_part(tuid, &msg.params[1], &reason);
            }
            None => {
                self.forward_to_target(&msg.params[0], msg, from);
            }
        }
    }

    /// `:src SVSMODE <target> <modes>` — set a user's modes (e.g. `+r`). Channel
    /// modes travel as (F)MODE, so a `#` target is ignored here.
    fn link_svsmode(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 || msg.params[0].starts_with('#') {
            return;
        }
        match self.link_local_target(&msg.params[0]) {
            Some(tuid) => {
                crate::coremods::core_mode::svs_set_user_modes(self, tuid, &msg.params[1])
            }
            None => {
                self.forward_to_target(&msg.params[0], msg, from);
            }
        }
    }

    /// `:src SVSLOGIN <target> <account>` — log a user into (or, with `*`/`0`, out
    /// of) a services account.
    fn link_svslogin(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        match self.link_local_target(&msg.params[0]) {
            Some(tuid) => {
                let account = &msg.params[1];
                if account == "*" || account == "0" {
                    self.logout(tuid);
                } else {
                    self.set_login(tuid, account);
                }
            }
            None => {
                self.forward_to_target(&msg.params[0], msg, from);
            }
        }
    }

    /// `:src SVSLOGOUT <target>` — log a user out of their account.
    fn link_svslogout(&mut self, from: Uid, msg: &Message) {
        if let Some(t) = msg.params.first() {
            match self.link_local_target(t) {
                Some(tuid) => self.logout(tuid),
                None => {
                    self.forward_to_target(t, msg, from);
                }
            }
        }
    }

    /// A display name for whoever sourced a services command: the source uuid's
    /// nick if we know it, else the raw source, else "services".
    fn link_setter(&self, msg: &Message) -> String {
        let Some(src) = &msg.source else {
            return "services".to_string();
        };
        if let Some(ru) = self.remote_users.get(src) {
            return ru.nick.clone();
        }
        if let Some(&uid) = self.uuid_local.get(src) {
            if let Some(u) = self.users.get(&uid) {
                return u.nick.clone();
            }
        }
        src.clone()
    }

    /// `:src SVSHOLD <nick> [<duration> :<reason>]` — services reserve a nick (added
    /// as an SVSHOLD x-line, so NICK to it is refused) or, with just the nick,
    /// release it. Broadcast across the network.
    fn link_svshold(&mut self, from: Uid, msg: &Message) {
        let Some(nick) = msg.params.first().cloned() else {
            return;
        };
        if msg.params.len() == 1 {
            self.remove_xline(crate::xline::XKind::Svshold, &nick);
        } else if msg.params.len() >= 3 {
            let Some(dur) = crate::xline::parse_duration(&msg.params[1]) else {
                return;
            };
            let setter = self.link_setter(msg);
            self.add_xline(
                crate::xline::XKind::Svshold,
                &nick,
                dur,
                &setter,
                &msg.params[2],
            );
        } else {
            return;
        }
        self.propagate(&msg.to_wire(), Some(from)); // spanning-tree broadcast
    }

    /// `:src SVSTOPIC <chan> [<topicts> <setter> :<topic>]` — services set (4-param)
    /// or clear (1-param) a channel's topic, overriding +t and op checks.
    fn link_svstopic(&mut self, from: Uid, msg: &Message) {
        let Some(chan) = msg.params.first().cloned() else {
            return;
        };
        let key = chan.to_ascii_lowercase();
        if !self.channels.contains_key(&key) {
            return;
        }
        let (text, setter, ts) = if msg.params.len() >= 4 {
            let ts = msg.params[1].parse::<u64>().unwrap_or_else(|_| now());
            (msg.params[3].clone(), msg.params[2].clone(), ts)
        } else {
            (String::new(), String::new(), 0) // clear
        };
        if let Some(ch) = self.channels.get_mut(&key) {
            ch.topic = if text.is_empty() {
                None
            } else {
                Some(Topic {
                    text: text.clone(),
                    setter,
                    ts,
                })
            };
        }
        let src = self.link_setter(msg);
        self.to_channel(&key, &format!(":{src} TOPIC {chan} :{text}"), None);
        self.propagate(&msg.to_wire(), Some(from));
    }

    /// `:src SVSOPER <target> <opertype>` — services grant IRC-operator status to a
    /// local user (echo's opers are flat, so the type is accepted but not stored).
    fn link_svsoper(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        match self.link_local_target(&msg.params[0]) {
            Some(tuid) => {
                if !self.is_oper(tuid) {
                    self.oper_up(tuid);
                }
            }
            None => {
                self.forward_to_target(&msg.params[0], msg, from);
            }
        }
    }

    /// `:src SVSCMODE <target> <chan> <listmodes>` — services clear the target user's
    /// matching entries from the named channel list modes (e.g. `b` to unban them,
    /// `be` bans + exceptions).
    fn link_svscmode(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 3 {
            return;
        }
        let Some(tuid) = self.link_local_target(&msg.params[0]) else {
            self.forward_to_target(&msg.params[0], msg, from);
            return;
        };
        let key = msg.params[1].to_ascii_lowercase();
        let mut removals: Vec<(char, String)> = Vec::new();
        if let Some(ch) = self.channels.get(&key) {
            for mc in msg.params[2].chars() {
                let list = match mc {
                    'b' => &ch.bans,
                    'e' => &ch.excepts,
                    'I' => &ch.invex,
                    _ => continue,
                };
                for ban in list {
                    if self.ban_list_hit(tuid, std::slice::from_ref(ban)) {
                        removals.push((mc, ban.mask.clone()));
                    }
                }
            }
        } else {
            return;
        }
        for (mc, mask) in removals {
            crate::coremods::core_mode::svs_set_chan_modes(
                self,
                &msg.params[1],
                &format!("-{mc}"),
                std::slice::from_ref(&mask),
            );
        }
    }

    /// `:src ENCAP <servermask> <subcommand> [params...]` — a command encapsulated
    /// for specific server(s); services wrap SVS*/SASL this way. If the mask
    /// matches us we unwrap and dispatch the subcommand; a `*` mask is also flooded
    /// onward (minus the origin), and a specific other-server mask is routed to it.
    fn link_encap(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        let mask = msg.params[0].as_str();
        if mask == "*" {
            self.encap_unwrap(from, msg);
            self.propagate(&msg.to_wire(), Some(from)); // spanning-tree flood
        } else if mask == self.sid || glob_match(mask, &self.name) {
            self.encap_unwrap(from, msg);
        } else if let Some(v) = self.server_link(mask) {
            if v != from {
                self.link_out(v, msg.to_wire());
            }
        }
    }

    /// Unwrap an ENCAP whose mask targets us and dispatch the inner subcommand as
    /// if it had arrived directly on the link.
    fn encap_unwrap(&mut self, from: Uid, msg: &Message) {
        let sub = Message {
            source: msg.source.clone(),
            command: msg.params[1].to_ascii_uppercase(),
            params: msg.params[2..].to_vec(),
            ctags: String::new(),
            label: None,
            batch: None,
            concat: false,
        };
        self.on_link(from, &sub);
    }

    /// The local link toward a server named/ided by `mask` (exact SID or name).
    fn server_link(&self, mask: &str) -> Option<Uid> {
        self.servers
            .values()
            .find(|sv| sv.sid == mask || sv.name.eq_ignore_ascii_case(mask))
            .map(|sv| sv.via)
    }

    /// `:src METADATA <target> <key> :<value>` — services sync metadata onto a
    /// user. We apply `accountname` (login/logout); other keys are accepted and
    /// ignored for now. Forwarded on if the target is remote.
    fn link_metadata(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 3 {
            return;
        }
        let (target, key, value) = (&msg.params[0], &msg.params[1], &msg.params[2]);
        let Some(tuid) = self.link_local_target(target) else {
            self.forward_to_target(target, msg, from);
            return;
        };
        if key == "accountname" {
            if value.is_empty() || value == "*" {
                self.logout(tuid);
            } else {
                self.set_login(tuid, value);
            }
        }
    }

    // --- SASL relay (client AUTHENTICATE ⇄ services) --------------------------

    /// The local link toward the configured SASL services server, if connected.
    pub fn sasl_link(&self) -> Option<Uid> {
        if self.sasl_server.is_empty() {
            return None;
        }
        self.servers
            .values()
            .find(|sv| sv.name == self.sasl_server)
            .map(|sv| sv.via)
    }

    /// Relay one SASL step for local client `uid` to the services server, wrapped
    /// as `:<our-sid> ENCAP <svc> SASL <client-uuid> * <mode> [data...]`. `rest` is
    /// the mode letter and its data (e.g. `S PLAIN`, `C <b64>`). The agent field is
    /// `*` — services accept it, so we needn't track their agent id. No-op with no
    /// SASL services linked.
    pub fn sasl_relay(&self, uid: Uid, rest: &str) {
        let (Some(via), Some(uuid)) = (
            self.sasl_link(),
            self.users.get(&uid).map(|u| u.uuid.clone()),
        ) else {
            return;
        };
        let mask = self
            .servers
            .values()
            .find(|s| s.via == via)
            .map(|s| s.sid.clone())
            .unwrap_or_else(|| "*".to_string());
        self.link_out(via, format!(":{} ENCAP {mask} SASL {uuid} * {rest}", self.sid));
    }

    /// A SASL step from services, unwrapped from its ENCAP: params are
    /// `<agent> <client-uuid> <mode> [data...]`.
    ///   `C <data>` → relay a server challenge to the client as `AUTHENTICATE`;
    ///   `D S` → success (the account was set by a preceding `METADATA accountname`,
    ///   so we emit 900/903 for it); `D <other>` → fail (904).
    fn link_sasl(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 3 {
            return;
        }
        let client = msg.params[1].clone();
        let Some(&uid) = self.uuid_local.get(&client) else {
            // not our client — route toward the server that owns them
            self.forward_to_target(&client, msg, from);
            return;
        };
        match msg.params[2].as_str() {
            "C" => {
                if let Some(data) = msg.params.get(3) {
                    self.send(uid, format!("AUTHENTICATE {data}"));
                }
            }
            "D" => {
                let ok = msg.params.get(3).map(|t| t == "S").unwrap_or(false);
                let account = self
                    .users
                    .get(&uid)
                    .and_then(|u| u.account.clone())
                    .unwrap_or_default();
                self.sasl_done(uid, ok, &account);
                if let Some(u) = self.users.get_mut(&uid) {
                    u.sasl_mech = None;
                }
            }
            _ => {}
        }
    }

    /// Emit the SASL outcome to the client: 900 + 903 on success, 904 on failure.
    fn sasl_done(&self, uid: Uid, success: bool, account: &str) {
        if success {
            let mask = self
                .users
                .get(&uid)
                .map(|u| u.prefix())
                .unwrap_or_else(|| "*".to_string());
            self.numeric(
                uid,
                crate::numeric::RPL_LOGGEDIN,
                &format!("{mask} {account} :You are now logged in as {account}"),
            );
            self.numeric(
                uid,
                crate::numeric::RPL_SASLSUCCESS,
                ":SASL authentication successful",
            );
        } else {
            self.numeric(
                uid,
                crate::numeric::ERR_SASLFAIL,
                ":SASL authentication failed",
            );
        }
    }

    // --- inbound S2S records --------------------------------------------------

    fn link_uid_recv(&mut self, via: Uid, msg: &Message) {
        // :<sid> UID <uuid> <nickts> <nick> <realhost> <disphost> <realident>
        //             <dispident> <ip> <signonts> +<modes> [modeparams] :<realname>
        // We keep the displayed host/ident (what other users see) and the real
        // name; the account arrives separately via METADATA accountname.
        if msg.params.len() < 11 {
            return;
        }
        let sid = msg.source.clone().unwrap_or_default();
        let uuid = msg.params[0].clone();
        let nick = msg.params[2].clone();
        let host = msg.params[4].clone(); // displayed host
        let ident = msg.params[6].clone(); // displayed ident
        let ip = msg.params[7].clone();
        let realname = msg.params.last().cloned().unwrap_or_default();
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
        self.remote_nick
            .insert(nick.to_ascii_lowercase(), uuid.clone());
        self.remote_users.insert(
            uuid.clone(),
            RemoteUser {
                uuid,
                nick,
                ident,
                host,
                realname,
                account: None,
                ip,
                sid,
                via,
            },
        );
        // re-propagate verbatim to our other peers (keeps every field intact)
        self.propagate(&msg.to_wire(), Some(via));
    }

    fn link_nick_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> NICK <newnick> [<ts>]
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
        let ts = msg.params.get(1).cloned().unwrap_or_else(|| now().to_string());
        self.propagate(&format!(":{uuid} NICK {newnick} {ts}"), Some(via));
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
        let key = chan.to_ascii_lowercase();
        let (Some(u), Some(ch)) = (self.users.get(&uid), self.channels.get(&key)) else {
            return;
        };
        if !u.registered {
            return;
        }
        // introduce the join as a single-member channel burst, carrying whatever
        // status the user holds (creator gets ops) and the channel's modes/TS so a
        // peer that doesn't yet know the channel creates it consistently.
        let letters = ch
            .members
            .get(&uid)
            .map(|m| m.mode_letters())
            .unwrap_or_default();
        self.propagate(
            &format!(
                ":{} FJOIN {} {} {} :{},{}",
                self.sid,
                ch.name,
                ch.created,
                ch.modes.render(false),
                letters,
                u.uuid
            ),
            None,
        );
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

    /// `:<uuid> IJOIN <channel> [<membid>] [<ts>] [<modes>]` — a single remote
    /// member joining an existing channel (services pseudo-clients use this to
    /// enter their control channel). The optional trailing token is the status
    /// modes the user joins holding.
    fn link_ijoin_recv(&mut self, via: Uid, msg: &Message) {
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let Some(chan) = msg.params.first().cloned() else {
            return;
        };
        if !chan.starts_with('#') || !self.remote_users.contains_key(&uuid) {
            return;
        }
        let key = chan.to_ascii_lowercase();
        let mut m = Member::default();
        // membid and ts are numeric; a trailing all-letter token is the modes
        if let Some(modes) = msg.params.get(3) {
            if modes.chars().all(|c| c.is_ascii_alphabetic()) {
                for c in modes.chars() {
                    m.set_prefix(c, true);
                }
            }
        }
        self.channels
            .entry(key.clone())
            .or_insert_with(|| Channel::new(&chan))
            .rmembers
            .insert(uuid.clone(), m);
        let prefix = self
            .remote_users
            .get(&uuid)
            .map(|r| r.prefix())
            .unwrap_or_default();
        self.to_channel(&key, &format!(":{prefix} JOIN {chan}"), None);
        self.propagate(&msg.to_wire(), Some(via));
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
        self.channels.retain(|_, c| c.keep_alive());
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
        self.channels.retain(|_, c| c.keep_alive());
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

    /// Resolve a nickname to its network uuid (local or remote); pass anything
    /// that isn't a known nick (a ban mask, a key) through unchanged.
    fn nick_to_uuid(&self, tok: &str) -> String {
        if let Some(u) = self.find_nick(tok).and_then(|l| self.users.get(&l)) {
            return u.uuid.clone();
        }
        if let Some((uuid, _)) = self.find_remote(tok) {
            return uuid;
        }
        tok.to_string()
    }

    /// Propagate a local channel mode change to links as a timestamped `FMODE`,
    /// rewriting member (prefix) params from nicks to uuids as the protocol wants.
    /// `params` are the displayed params in mode order (member nicks, masks, key…).
    pub fn propagate_chan_mode(&self, src: &str, chan: &str, modestring: &str, params: &[String]) {
        if self.links.is_empty() {
            return;
        }
        let key = chan.to_ascii_lowercase();
        let ts = self.channels.get(&key).map(|c| c.created).unwrap_or_else(now);
        let mut out: Vec<String> = Vec::new();
        let mut pi = 0usize;
        let mut sign = '+';
        for c in modestring.chars() {
            match c {
                '+' | '-' => sign = c,
                'q' | 'a' | 'o' | 'h' | 'v' => {
                    if let Some(p) = params.get(pi) {
                        out.push(self.nick_to_uuid(p));
                        pi += 1;
                    }
                }
                'b' | 'e' | 'I' | 'k' => {
                    if let Some(p) = params.get(pi) {
                        out.push(p.clone());
                        pi += 1;
                    }
                }
                'l' => {
                    if sign == '+' {
                        if let Some(p) = params.get(pi) {
                            out.push(p.clone());
                            pi += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        while pi < params.len() {
            out.push(params[pi].clone());
            pi += 1;
        }
        let pstr = if out.is_empty() {
            String::new()
        } else {
            format!(" {}", out.join(" "))
        };
        self.propagate(&format!(":{src} FMODE {chan} {ts} {modestring}{pstr}"), None);
    }

    /// Propagate a local user's topic change to links as `FTOPIC`, carrying the
    /// channel and topic timestamps and the setter mask the protocol expects.
    pub fn propagate_topic(&self, uid: Uid, chan: &str, text: &str) {
        if self.links.is_empty() {
            return;
        }
        let key = chan.to_ascii_lowercase();
        let (Some(u), Some(c)) = (self.users.get(&uid), self.channels.get(&key)) else {
            return;
        };
        if !u.registered {
            return;
        }
        let ts = c.topic.as_ref().map(|t| t.ts).unwrap_or_else(now);
        self.propagate(
            &format!(
                ":{} FTOPIC {} {} {} {} :{text}",
                u.uuid,
                c.name,
                c.created,
                ts,
                u.prefix()
            ),
            None,
        );
    }

    /// Propagate a local KICK to links, naming the victim by network uuid.
    pub fn propagate_kick(&self, uid: Uid, chan: &str, victim: &str, reason: &str) {
        if self.links.is_empty() {
            return;
        }
        let Some(u) = self.users.get(&uid) else {
            return;
        };
        if !u.registered {
            return;
        }
        let vuuid = self.nick_to_uuid(victim);
        self.propagate(
            &format!(":{} KICK {chan} {vuuid} :{reason}", u.uuid),
            None,
        );
    }

    /// Set a status prefix on a channel member named by network uuid or nickname
    /// (the S2S form uses uuids; a local MODE may pass a nick).
    fn set_member_prefix(&mut self, key: &str, who: &str, letter: char, adding: bool) {
        // a local user, by uuid then by nick
        let luid = self
            .uuid_local
            .get(who)
            .copied()
            .or_else(|| self.find_nick(who));
        if let Some(uid) = luid {
            if let Some(m) = self
                .channels
                .get_mut(key)
                .and_then(|c| c.members.get_mut(&uid))
            {
                m.set_prefix(letter, adding);
            }
            return;
        }
        // a remote user, by uuid then by nick
        let ruuid = if self.remote_users.contains_key(who) {
            Some(who.to_string())
        } else {
            self.find_remote(who).map(|(u, _)| u)
        };
        if let Some(uuid) = ruuid {
            if let Some(m) = self
                .channels
                .get_mut(key)
                .and_then(|c| c.rmembers.get_mut(&uuid))
            {
                m.set_prefix(letter, adding);
            }
        }
    }

    /// Resolve a network uuid to a nick for client-facing display; pass anything
    /// else (already a nick, a mask) through unchanged.
    fn uuid_to_nick(&self, tok: &str) -> String {
        if let Some(ru) = self.remote_users.get(tok) {
            return ru.nick.clone();
        }
        if let Some(u) = self.uuid_local.get(tok).and_then(|&l| self.users.get(&l)) {
            return u.nick.clone();
        }
        tok.to_string()
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
        // :<kicker> KICK #chan <victim-uuid|nick> :<reason>  (the S2S form uses a uuid)
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
        let vnick;
        let vlocal = self
            .uuid_local
            .get(&victim)
            .copied()
            .or_else(|| self.find_nick(&victim));
        if let Some(vuid) = vlocal {
            vnick = self
                .users
                .get(&vuid)
                .map(|u| u.nick.clone())
                .unwrap_or_else(|| victim.clone());
            if let Some(c) = self.channels.get_mut(&key) {
                removed = c.members.remove(&vuid).is_some();
            }
            if removed {
                if let Some(u) = self.users.get_mut(&vuid) {
                    u.channels.remove(&key);
                }
                // the kicked local user must see it too (they've left the member set)
                self.send(vuid, format!(":{prefix} KICK {chan} {vnick} :{reason}"));
            }
        } else {
            let vuuid = if self.remote_users.contains_key(&victim) {
                Some(victim.clone())
            } else {
                self.find_remote(&victim).map(|(u, _)| u)
            };
            match vuuid {
                Some(vuuid) => {
                    vnick = self
                        .remote_users
                        .get(&vuuid)
                        .map(|r| r.nick.clone())
                        .unwrap_or_else(|| victim.clone());
                    if let Some(c) = self.channels.get_mut(&key) {
                        removed = c.rmembers.remove(&vuuid).is_some();
                    }
                }
                None => return,
            }
        }
        if !removed {
            return;
        }
        self.to_channel(
            &key,
            &format!(":{prefix} KICK {chan} {vnick} :{reason}"),
            None,
        );
        self.channels.retain(|_, c| c.keep_alive());
        self.propagate(&msg.to_wire(), Some(via));
    }

    fn link_ftopic_recv(&mut self, via: Uid, msg: &Message) {
        // :<src> FTOPIC <#chan> <chants> <topicts> [<setter>] :<topic>
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 4 {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !self.channels.contains_key(&key) {
            return;
        }
        let topic = msg.params.last().cloned().unwrap_or_default();
        let ts = msg.params[2].parse().unwrap_or_else(|_| now());
        // an explicit setter mask sits at param[3] when present (>=5 params); else
        // fall back to the source's display name
        let setter = if msg.params.len() >= 5 {
            msg.params[3].clone()
        } else {
            self.remote_users
                .get(&src)
                .map(|r| r.nick.clone())
                .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
                .unwrap_or_else(|| src.clone())
        };
        if let Some(c) = self.channels.get_mut(&key) {
            c.topic = Some(Topic {
                text: topic.clone(),
                setter: setter.clone(),
                ts,
            });
        }
        let prefix = self
            .uuid_prefix(&src)
            .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
            .unwrap_or(setter);
        self.to_channel(&key, &format!(":{prefix} TOPIC {chan} :{topic}"), None);
        self.propagate(&msg.to_wire(), Some(via));
    }

    fn link_mode_recv(&mut self, via: Uid, msg: &Message) {
        // Channel modes arrive as `:<src> FMODE <#chan> <ts> <modes> [params]`
        // (timestamped) or `:<src> MODE <#chan> <modes> [params]`; user modes as
        // `:<src> MODE <uuid> <modes>`. Applied without re-checking privilege — the
        // originating server already authorised the change.
        let Some(src) = msg.source.clone() else {
            return;
        };
        if msg.params.len() < 2 {
            return;
        }
        // FMODE inserts a channel timestamp before the mode string
        let mode_idx = if msg.command == "FMODE" { 2 } else { 1 };

        // a user-mode change: relay onward, and drop it if aimed at a local (we
        // don't re-toggle umodes here — services force user modes via SVSMODE)
        if !msg.params[0].starts_with('#') {
            self.propagate(&msg.to_wire(), Some(via));
            return;
        }

        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !self.channels.contains_key(&key) {
            return;
        }
        let Some(modestring) = msg.params.get(mode_idx).cloned() else {
            return;
        };
        let args: Vec<String> = msg
            .params
            .get(mode_idx + 1..)
            .map(<[String]>::to_vec)
            .unwrap_or_default();
        let mut argi = 0usize;
        let mut sign = '+';
        // client-facing param list: prefix-mode targets shown as nicks, not uuids
        let mut shown: Vec<String> = Vec::new();
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
                        shown.push(self.uuid_to_nick(&n));
                    }
                }
                'k' => {
                    let p = args.get(argi).cloned();
                    if let Some(p) = &p {
                        argi += 1;
                        shown.push(p.clone());
                    }
                    if let Some(ch) = self.channels.get_mut(&key) {
                        ch.modes.key = if adding { p } else { None };
                    }
                }
                'l' => {
                    if adding {
                        if let Some(n) = args.get(argi).and_then(|s| s.parse::<u32>().ok()) {
                            shown.push(args[argi].clone());
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
                        shown.push(mask.clone());
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
                                        expires: None,
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
        // client-facing line: source is a user (uuid) or, for a burst, a server
        // (sid); params show member nicks rather than uuids
        let prefix = self
            .uuid_prefix(&src)
            .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
            .unwrap_or_else(|| self.name.clone());
        let paramstr = if shown.is_empty() {
            String::new()
        } else {
            format!(" {}", shown.join(" "))
        };
        self.to_channel(
            &key,
            &format!(":{prefix} MODE {chan} {modestring}{paramstr}"),
            None,
        );
        // relay onward exactly as received (keeps the FMODE timestamp intact)
        self.propagate(&msg.to_wire(), Some(via));
    }

    /// Burst every channel (name, ts, modes, prefixed members) to a new peer.
    fn burst_channels(&self, link_uid: Uid) {
        let mut lines = Vec::new();
        for ch in self.channels.values() {
            let mut mem: Vec<String> = Vec::new();
            for (uid, m) in &ch.members {
                if let Some(u) = self.users.get(uid) {
                    mem.push(format!("{},{}", m.mode_letters(), u.uuid));
                }
            }
            for (uuid, m) in &ch.rmembers {
                mem.push(format!("{},{}", m.mode_letters(), uuid));
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
            // burst the ban / except / invite-exception lists as timestamped mode
            // changes sourced from this server
            for (letter, list) in [('b', &ch.bans), ('e', &ch.excepts), ('I', &ch.invex)] {
                for b in list {
                    lines.push(format!(
                        ":{} FMODE {} {} +{letter} {}",
                        self.sid, ch.name, ch.created, b.mask
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
            let (letters, uuid) = split_member(tok);
            if self.uuid_local.contains_key(&uuid) || !self.remote_users.contains_key(&uuid) {
                continue; // our own user, or one we don't know yet
            }
            let mut m = Member::default();
            for pc in letters.chars() {
                m.set_prefix(pc, true);
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

/// Split a bursted member token `ov,0AAAAAAAB` (with an optional `:membid`
/// suffix) into its status mode letters and the bare uuid.
fn split_member(tok: &str) -> (String, String) {
    let (letters, rest) = tok.split_once(',').unwrap_or(("", tok));
    let uuid = rest.split(':').next().unwrap_or(rest);
    (letters.to_string(), uuid.to_string())
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
