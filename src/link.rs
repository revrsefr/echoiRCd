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

use crate::map::HashSet;

use crate::channels::{glob_match, Ban, ChanModes, Channel, Member, Topic};
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
    /// A services (U-lined) server: its name matches a `uline` config entry or the
    /// configured `sasl_server`. Derived locally from OUR config at link/rehash time,
    /// matched by server name; nothing on the wire declares
    /// it. Every user on it is a network service.
    pub is_service: bool,
    /// `uline ... silent`: suppress this server's users' connect/quit server-notices.
    pub silent_service: bool,
}

/// A user living on another server, reached via a link — not a local `User`.
pub struct RemoteUser {
    pub uuid: String,
    pub nick: String,
    pub ident: String,
    pub host: String,
    pub realname: String,
    pub account: Option<String>,
    pub ip: String, // client IP (for network-wide clone limits); "" if a peer omitted it
    pub modes: String, // user mode letters (no leading '+'); e.g. services wear "iHB"
    pub sid: String, // origin server id
    pub via: Uid,   // local link uid it is reached through
    pub nick_ts: u64, // nick timestamp, for TS6 remote-vs-remote collision arbitration
    pub away: Option<String>, // away reason (None = present), for away-notify + WHOIS 301
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
        loop {
            let mut x = self.uuid_counter;
            self.uuid_counter += 1;
            let mut suffix = [b'A'; 6];
            for c in suffix.iter_mut().rev() {
                *c = b'A' + (x % 26) as u8;
                x /= 26;
            }
            let uuid = format!(
                "{}{}",
                self.sid,
                std::str::from_utf8(&suffix).unwrap_or("AAAAAA")
            );
            // after 26^6 mints the counter wraps and could re-issue a still-live id;
            // skip any that's in use so uuids stay unique
            if !self.uuid_local.contains_key(&uuid) && !self.remote_users.contains_key(&uuid) {
                return uuid;
            }
        }
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
                out.send(
                    format!(
                        "SERVER {} {} {} :{}",
                        self.name, pass, self.sid, self.server_desc
                    )
                    .into(),
                );
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
            l.out.send(line.into());
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
            "KILL" if registered => self.link_kill_recv(uid, msg),
            "SAVE" if registered => self.link_save_recv(uid, msg),
            "INVITE" if registered => self.link_invite_recv(uid, msg),
            "ADDLINE" if registered => self.link_addline_recv(uid, msg),
            "DELLINE" if registered => self.link_delline_recv(uid, msg),
            "PRIVMSG" if registered => self.link_message_recv(uid, msg, false),
            "NOTICE" if registered => self.link_message_recv(uid, msg, true),
            "JOIN" if registered => self.link_join_recv(uid, msg),
            "PART" if registered => self.link_part_recv(uid, msg),
            "TOPIC" if registered => self.link_topic_recv(uid, msg),
            "FTOPIC" if registered => self.link_ftopic_recv(uid, msg),
            "KICK" if registered => self.link_kick_recv(uid, msg),
            "RENAME" if registered => self.link_rename_recv(uid, msg),
            "MODE" | "FMODE" if registered => self.link_mode_recv(uid, msg),
            "FJOIN" if registered => self.link_fjoin_recv(uid, msg),
            "IJOIN" if registered => self.link_ijoin_recv(uid, msg),
            // services (SVS*) enforcement + account login, driven by a linked
            // services pseudoserver (forwarded on if the target is on another server).
            // They are honoured ONLY from a source on a
            // U-lined services server — an ordinary peer's SVS* is ignored.
            "SVSNICK" if registered && self.source_is_service(msg) => self.link_svsnick(uid, msg),
            "SVSJOIN" if registered && self.source_is_service(msg) => self.link_svsjoin(uid, msg),
            "SVSPART" if registered && self.source_is_service(msg) => self.link_svspart(uid, msg),
            "SVSMODE" if registered && self.source_is_service(msg) => self.link_svsmode(uid, msg),
            "SVSLOGIN" if registered && self.source_is_service(msg) => self.link_svslogin(uid, msg),
            "SVSLOGOUT" if registered && self.source_is_service(msg) => {
                self.link_svslogout(uid, msg)
            }
            "SVSHOLD" if registered && self.source_is_service(msg) => self.link_svshold(uid, msg),
            "SVSTOPIC" if registered && self.source_is_service(msg) => self.link_svstopic(uid, msg),
            "SVSOPER" if registered && self.source_is_service(msg) => self.link_svsoper(uid, msg),
            "SVSCMODE" if registered && self.source_is_service(msg) => self.link_svscmode(uid, msg),
            "ENCAP" if registered => self.link_encap(uid, msg),
            "METADATA" if registered => self.link_metadata(uid, msg),
            "CHGHOST" if registered => self.link_chghost_recv(uid, msg),
            "CHGIDENT" if registered => self.link_chgident_recv(uid, msg),
            "AWAY" if registered => self.link_away_recv(uid, msg),
            "SWSTDRPL" if registered => self.link_stdreply_recv(uid, msg),
            "OPERTYPE" if registered => self.link_opertype_recv(uid, msg),
            "REDACT" if registered => self.link_redact_recv(uid, msg),
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
    /// Whether a server NAME is a services (U-lined) server, and whether it is
    /// "silent". A name matches if it is the configured `sasl_server` (a SASL
    /// provider is a service) or appears as a `uline = <name> [silent]` entry.
    /// Case-insensitive, matched by server name.
    pub fn uline_match(&self, name: &str) -> (bool, bool) {
        if !self.sasl_server.is_empty() && name.eq_ignore_ascii_case(&self.sasl_server) {
            return (true, false);
        }
        for line in self.conf_all("uline") {
            let mut it = line.split_whitespace();
            if it.next().is_some_and(|n| n.eq_ignore_ascii_case(name)) {
                return (true, it.any(|t| t.eq_ignore_ascii_case("silent")));
            }
        }
        (false, false)
    }

    /// Whether the server with this SID is a services (U-lined) server.
    pub fn server_is_service(&self, sid: &str) -> bool {
        self.servers.get(sid).is_some_and(|s| s.is_service)
    }

    /// Whether a message's source (a SID or a UUID whose first 3 chars are the SID)
    /// originates on a services server — the authority gate for SVS* commands.
    pub fn source_is_service(&self, msg: &Message) -> bool {
        let Some(src) = msg.source.as_deref() else {
            return false;
        };
        self.server_is_service(src.get(..3).unwrap_or(src))
    }

    /// Whether the remote user with this UUID lives on a services server. Local
    /// users are never services (they are on us, and a server is not its own uline).
    pub fn uuid_is_service(&self, uuid: &str) -> bool {
        self.remote_users
            .get(uuid)
            .is_some_and(|ru| self.server_is_service(&ru.sid))
    }

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
        if let Some(reason) = self.matched_jupe(&name) {
            self.reject_link(uid, &format!("Server name is juped: {reason}"));
            return;
        }
        let Some(block) = self.link_blocks.iter().find(|b| b.name == name).cloned() else {
            self.reject_link(uid, "No link block for that server name");
            return;
        };
        // constant-time compare — the link secret is attacker-guessable over the S2S
        // port (which has no source-IP check), so a byte-by-byte `!=` leaks it via timing
        if !crate::modules::password_hash::ct_eq(block.password.as_bytes(), pass.as_bytes()) {
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
        let (is_service, silent_service) = self.uline_match(&name);
        self.servers.insert(
            sid.clone(),
            RemoteServer {
                sid: sid.clone(),
                name: name.clone(),
                desc: desc.clone(),
                via: uid,
                is_service,
                silent_service,
            },
        );
        if is_service {
            eprintln!("[link] {name} ({sid}) is a services (U-lined) server");
        }
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
        self.burst_xlines(uid);
        self.burst_filters(uid);
        self.link_out(uid, "ENDBURST".to_string());
        eprintln!("[link] linked {name} ({sid}) — {desc}");
    }

    fn reject_link(&mut self, uid: Uid, why: &str) {
        let m = self.trf("Link denied: {0}", &[why]);
        self.link_out(uid, format!("ERROR :{m}"));
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
            v.push(format!(
                ":{} METADATA {} accountname :{acct}",
                self.sid, u.uuid
            ));
        }
        // ssl_cert so services learn the client's TLS fingerprint (cert auto-login,
        // fingerprint extbans). Flags `vsT` = valid/secure/trusted; no `E` (error).
        if let Some(fp) = &u.certfp {
            v.push(format!(
                ":{} METADATA {} ssl_cert :vsT {fp}",
                self.sid, u.uuid
            ));
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
            let setter = self.link_setter(msg);
            self.remove_xline(crate::xline::XKind::Svshold, &nick, &setter);
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

    /// `:<src> CHGHOST <target> <newhost>` — a services vhost / oper host change
    /// (arrives ENCAP'd to the target's server). Apply to a local target (which
    /// propagates + hostcycles via `change_host_ident`), or forward toward a remote one.
    /// An `ident@host` vhost arrives as ONE CHGHOST (host param `ident@host`) and is
    /// applied as a single CHGHOST line — not a CHGIDENT + CHGHOST pair, which would
    /// show the client two "changed host" notices.
    /// `:<uuid> AWAY [:<reason>]` — a remote user's away state changed. Update our copy
    /// (for WHOIS 301), tell local away-notify members who share a channel, relay onward.
    fn link_away_recv(&mut self, via: Uid, msg: &Message) {
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        if !self.sourced_via(&uuid, via) {
            return;
        }
        let reason = msg.params.first().cloned().filter(|r| !r.is_empty());
        let line = match self.remote_users.get_mut(&uuid) {
            Some(ru) => {
                ru.away = reason.clone();
                let prefix = ru.prefix();
                match &reason {
                    Some(r) => format!(":{prefix} AWAY :{r}"),
                    None => format!(":{prefix} AWAY"),
                }
            }
            None => return,
        };
        self.notify_common_local_if(&uuid, &line, |c| c.away_notify);
        let fwd = match &reason {
            Some(r) => format!(":{uuid} AWAY :{r}"),
            None => format!(":{uuid} AWAY"),
        };
        self.propagate(&fwd, Some(via));
    }

    fn link_chghost_recv(&mut self, from: Uid, msg: &Message) {
        let (Some(target), Some(host)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        match self.link_local_target(&target) {
            Some(tuid) => match host.split_once('@') {
                Some((ident, h)) if !ident.is_empty() && !h.is_empty() => {
                    self.change_host_ident_quiet(tuid, Some(ident), Some(h))
                }
                _ => self.change_host_ident_quiet(tuid, None, Some(&host)),
            },
            None => {
                // remote target: update our copy + tell local cap members, then relay
                match host.split_once('@') {
                    Some((i, h)) if !i.is_empty() && !h.is_empty() => {
                        self.apply_remote_host_ident(&target, Some(i), Some(h))
                    }
                    _ => self.apply_remote_host_ident(&target, None, Some(&host)),
                }
                self.forward_to_target(&target, msg, from);
            }
        }
    }

    /// `:<src> CHGIDENT <target> <newident>` — a standalone services/oper ident
    /// change (a full `ident@host` vhost instead comes as one CHGHOST, see above).
    fn link_chgident_recv(&mut self, from: Uid, msg: &Message) {
        let (Some(target), Some(ident)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        match self.link_local_target(&target) {
            Some(tuid) => self.change_host_ident_quiet(tuid, Some(&ident), None),
            None => {
                self.apply_remote_host_ident(&target, Some(&ident), None);
                self.forward_to_target(&target, msg, from);
            }
        }
    }

    /// `:src METADATA <target> <key> :<value>` — services sync metadata onto a
    /// user. We apply `accountname` (login/logout); other keys are accepted and
    /// ignored for now. Forwarded on if the target is remote.
    /// `ENCAP * SWSTDRPL <client-uuid> <src|*> <FAIL|WARN|NOTE> <command|*> <code> :<text>`
    /// — a services IRCv3 standard reply, re-emitted locally to the target client (or
    /// forwarded on). Without this a `standard-replies` client sees no feedback when a
    /// services command fails (e.g. a bad NickServ IDENTIFY).
    fn link_stdreply_recv(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 5 {
            return;
        }
        let to = msg.params[0].clone();
        let Some(&dst) = self.uuid_local.get(&to) else {
            self.forward_to_target(&to, msg, from);
            return;
        };
        let (command, code) = (msg.params[3].clone(), msg.params[4].clone());
        let text = msg.params.get(5).cloned().unwrap_or_default();
        match msg.params[2].as_str() {
            "WARN" => self.warn(dst, &command, &code, &text),
            "NOTE" => self.note(dst, &command, &code, &text),
            _ => self.fail(dst, &command, &code, &text),
        }
    }

    /// `:<uuid> OPERTYPE :<type>` — a remote user opered up; reflect it on their modes
    /// so the network's view of who is an operator stays consistent.
    fn link_opertype_recv(&mut self, via: Uid, msg: &Message) {
        if let Some(src) = msg.source.as_deref() {
            if !self.sourced_via(src, via) {
                return; // a peer can't flag a user behind another link as oper
            }
            if let Some(ru) = self.remote_users.get_mut(src) {
                if !ru.modes.contains('o') {
                    ru.modes.push('o');
                }
            }
        }
    }

    /// `:<uuid> REDACT <#chan> <msgid> [:reason]` — a services/remote message deletion:
    /// relay it to local channel members who understand draft/message-redaction, drop it
    /// from CHATHISTORY, and forward to other links with members there.
    fn link_redact_recv(&mut self, via: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return; // reject a forged message-deletion from behind another link
        }
        let (target, msgid) = (msg.params[0].clone(), msg.params[1].clone());
        if !target.starts_with('#') {
            return;
        }
        let key = target.to_ascii_lowercase();
        let Some(prefix) = self
            .uuid_prefix(&src)
            .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
        else {
            return;
        };
        if self.channels.contains_key(&key) {
            let line = match msg.params.get(2) {
                Some(r) => format!(":{prefix} REDACT {target} {msgid} :{r}"),
                None => format!(":{prefix} REDACT {target} {msgid}"),
            };
            let members: Vec<Uid> = self.channels[&key].members.keys().copied().collect();
            for m in members {
                if self
                    .users
                    .get(&m)
                    .map(|u| u.caps.message_redaction)
                    .unwrap_or(false)
                {
                    self.send(m, line.clone());
                }
            }
            for l in self.channel_link_targets(&key, Some(via)) {
                self.link_out(l, msg.to_wire());
            }
        }
        crate::modules::chathistory::forget(self, &key, &msgid);
    }

    fn link_metadata(&mut self, from: Uid, msg: &Message) {
        if msg.params.len() < 3 {
            return;
        }
        let (target, key, value) = (
            msg.params[0].clone(),
            msg.params[1].clone(),
            msg.params[2].clone(),
        );
        // Server-level (target "*") metadata: the spam-filter ruleset syncs this way,
        // both on netburst and on live changes from a linked server.
        if target == "*" {
            if key == "filter" {
                crate::modules::filter::apply_metadata(self, &value);
            }
            return;
        }
        let Some(tuid) = self.link_local_target(&target) else {
            self.forward_to_target(&target, msg, from);
            return;
        };
        // Metadata pushed onto a local user (login state, profile fields) is a
        // services authority: ignore it from an ordinary peer. Each hop re-checks,
        // so forwarding an unauthorised one stays harmless.
        if !self.source_is_service(msg) {
            return;
        }
        match key.as_str() {
            "accountname" => {
                if value.is_empty() || value == "*" {
                    self.logout(tuid);
                } else {
                    self.set_login(tuid, &value);
                }
            }
            // profile fields NickServ SET populates — surface them over metadata-2
            "avatar" | "bio" | "pronouns" | "timezone" | "url" => {
                let nick = self
                    .users
                    .get(&tuid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                let setter = msg
                    .source
                    .as_deref()
                    .and_then(|src| self.servers.get(src).map(|sv| sv.name.clone()))
                    .unwrap_or_else(|| self.name.clone());
                let v = (!value.is_empty()).then_some(value.as_str());
                crate::modules::metadata::apply_user(self, tuid, &nick, &key, v, &setter);
            }
            // OperServ SWHOIS: an extra WHOIS line services set on the account and
            // re-push on each login (empty value clears it).
            "swhois" => {
                if let Some(u) = self.users.get_mut(&tuid) {
                    if value.is_empty() {
                        u.ext.take::<crate::coremods::core_oper::Swhois>();
                    } else {
                        u.ext.set(crate::coremods::core_oper::Swhois(value.clone()));
                    }
                }
            }
            // Persistent SIGNORE list: services store it per-account and replay it on
            // each login (space-separated masks; empty value clears it).
            "signore" => {
                if let Some(u) = self.users.get_mut(&tuid) {
                    u.signore = value
                        .split(' ')
                        .filter(|m| !m.is_empty())
                        .map(str::to_string)
                        .collect();
                }
            }
            _ => {}
        }
    }

    /// Push a user's current SIGNORE list up to the services server so it's saved on
    /// their account and replayed on the next login. No-op when the user isn't logged
    /// in (no account to store it on) or services aren't linked — the list then stays
    /// session-only, exactly as it worked before persistence.
    pub fn push_signore_to_services(&self, uid: Uid) {
        let Some(via) = self.sasl_link() else {
            return;
        };
        let Some(u) = self.users.get(&uid) else {
            return;
        };
        if u.account.is_none() {
            return;
        }
        let masks = u.signore.join(" ");
        self.link_out(
            via,
            format!(":{} METADATA {} signore :{masks}", self.sid, u.uuid),
        );
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
        self.link_out(
            via,
            format!(":{} ENCAP {mask} SASL {uuid} * {rest}", self.sid),
        );
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
        // the announcing server must actually sit behind the link this UID arrived on,
        // else a peer could introduce phantom users under another server's SID
        if !self.source_behind(&sid, via) {
            return;
        }
        let uuid = msg.params[0].clone();
        // reject a malformed or duplicate UID instead of corrupting the routing
        // tables: the uuid is 9 chars carrying the announcing server's 3-char SID,
        // and must not already be present.
        if sid.len() != 3
            || uuid.len() != 9
            || !uuid.starts_with(&sid)
            || self.remote_users.contains_key(&uuid)
        {
            return;
        }
        let mut nick = msg.params[2].clone();
        let host = msg.params[4].clone(); // displayed host
        let ident = msg.params[6].clone(); // displayed ident
        let ip = msg.params[7].clone();
        let modes = msg
            .params
            .get(9)
            .map(|m| m.trim_start_matches('+').to_string())
            .unwrap_or_default();
        let realname = msg.params.last().cloned().unwrap_or_default();
        let nickts: u64 = msg.params[1].parse().unwrap_or_else(|_| now());
        // nick collision with a local user: resolve by timestamp, force-renaming the
        // loser to its UUID rather than killing anyone.
        if let Some(luid) = self.find_nick(&nick) {
            let rsvc = self.server_is_service(&sid);
            if self.resolve_collision(via, luid, nickts, &ident, &ip, &uuid, rsvc) {
                nick = uuid.clone(); // the incoming user lost: introduce it under its UUID
            }
        }
        // Collision with an existing REMOTE user: full TS6 arbitration (DoCollision).
        // If the incoming user loses it takes its UUID here; if the existing one loses
        // it is renamed to its UUID + SAVEd network-wide (so no routing ghost either way).
        if let Some(existing) = self.remote_nick.get(&nick.to_ascii_lowercase()).cloned() {
            if existing != uuid
                && self.resolve_remote_collision(via, &existing, nickts, &ident, &ip, &uuid, &sid)
            {
                nick = uuid.clone();
            }
        }
        let renamed = nick != msg.params[2];
        self.remote_nick
            .insert(nick.to_ascii_lowercase(), uuid.clone());
        self.remote_users.insert(
            uuid.clone(),
            RemoteUser {
                uuid,
                nick: nick.clone(),
                ident,
                host,
                realname,
                account: None,
                ip,
                modes,
                sid,
                via,
                nick_ts: nickts,
                away: None,
            },
        );
        // Re-propagate to our other peers. If a collision renamed the loser, rewrite
        // the nick in the forwarded UID so downstream learns the corrected nick and
        // doesn't re-collide; otherwise forward verbatim.
        if renamed {
            let mut p = msg.params.clone();
            p[2] = nick;
            let fwd = Message {
                source: msg.source.clone(),
                command: msg.command.clone(),
                params: p,
                ctags: String::new(),
                label: None,
                batch: None,
                concat: false,
            };
            self.propagate(&fwd.to_wire(), Some(via));
        } else {
            self.propagate(&msg.to_wire(), Some(via));
        }
    }

    /// Whether a remote source uuid is genuinely reached through link `via` — guards
    /// against a peer spoofing a user that lives behind a different link.
    fn sourced_via(&self, uuid: &str, via: Uid) -> bool {
        self.remote_users.get(uuid).map(|ru| ru.via) == Some(via)
    }

    /// Whether a message source `src` — a remote user uuid **or** a server sid —
    /// genuinely sits behind the link `via` it arrived on. In a spanning tree a
    /// line from `src` must always reach us via the next hop toward `src`; a peer
    /// naming a source that lives behind a *different* link is forging it. Used to
    /// gate the channel-state handlers (JOIN/KICK/TOPIC/MODE/message) the same way
    /// `sourced_via` already gates NICK/QUIT/PART — except this also accepts a
    /// server source, since services burst FMODE/FTOPIC/NOTICE from their SID.
    fn source_behind(&self, src: &str, via: Uid) -> bool {
        if let Some(ru) = self.remote_users.get(src) {
            return ru.via == via;
        }
        if let Some(sv) = self.servers.get(src) {
            return sv.via == via;
        }
        false
    }

    /// Resolve a nick collision between local user `luid` and an incoming remote
    /// user by timestamp: same user@ip → the OLDER changes; else the NEWER changes;
    /// equal TS → both. The loser is force-renamed to its UUID — locally right here
    /// (with the normal NICK propagation), remotely via a SAVE back to the source.
    /// Returns true if the REMOTE user must take its UUID.
    fn resolve_collision(
        &mut self,
        via: Uid,
        luid: Uid,
        remote_ts: u64,
        remote_user: &str,
        remote_ip: &str,
        remote_uuid: &str,
        remote_is_service: bool,
    ) -> bool {
        let (local_ts, local_user, local_ip, local_uuid) = match self.users.get(&luid) {
            Some(u) => (
                u.nick_ts,
                u.ident.clone(),
                u.addr.ip().to_string(),
                u.uuid.clone(),
            ),
            None => return true,
        };
        let same = local_user == remote_user && local_ip == remote_ip;
        // a network service always keeps its nick; the local user is the one to yield
        let (change_local, change_remote) = if remote_is_service {
            (true, false)
        } else {
            collision_decision(local_ts, remote_ts, same)
        };
        if change_local {
            self.set_nick(luid, &local_uuid);
        }
        if change_remote {
            self.link_out(
                via,
                format!(":{} SAVE {} {}", self.sid, remote_uuid, remote_ts),
            );
        }
        change_remote
    }

    /// Remote-vs-remote nick collision (TS6, mirrors InspIRCd `DoCollision`). An
    /// existing remote user (`existing_uuid`) already holds the nick the incoming
    /// remote user (`remote_uuid`, on server `remote_sid`) wants. Force-rename the
    /// loser to its UUID: the existing one right here + a network-wide SAVE broadcast;
    /// the incoming one via a SAVE back to its source (its caller renames it locally).
    /// Returns whether the INCOMING user must change to its UUID.
    #[allow(clippy::too_many_arguments)]
    fn resolve_remote_collision(
        &mut self,
        via: Uid,
        existing_uuid: &str,
        remote_ts: u64,
        remote_user: &str,
        remote_ip: &str,
        remote_uuid: &str,
        remote_sid: &str,
    ) -> bool {
        let (existing_ts, existing_user, existing_ip) = match self.remote_users.get(existing_uuid) {
            Some(r) => (r.nick_ts, r.ident.clone(), r.ip.clone()),
            None => return false, // it vanished: no collision, incoming keeps its nick
        };
        let same = existing_user == remote_user && existing_ip == remote_ip;
        // a services pseudo-client always keeps its nick; the other side yields.
        let (change_existing, change_incoming) = if self.server_is_service(remote_sid) {
            (true, false)
        } else if self.uuid_is_service(existing_uuid) {
            (false, true)
        } else {
            collision_decision(existing_ts, remote_ts, same)
        };
        if change_existing {
            self.save_remote_user(existing_uuid);
        }
        if change_incoming {
            self.link_out(
                via,
                format!(":{} SAVE {} {}", self.sid, remote_uuid, remote_ts),
            );
        }
        change_incoming
    }

    /// A remote user lost a nick collision: rename our copy of it to its UUID and
    /// broadcast a SAVE so the whole network converges (its owner renames it; the echo
    /// back is a harmless no-op). Mirrors the local side of `DoCollision`.
    fn save_remote_user(&mut self, uuid: &str) {
        let (old, ts, ident, host) = match self.remote_users.get_mut(uuid) {
            Some(r) => {
                let old = r.nick.clone();
                let (ident, host) = (r.ident.clone(), r.host.clone());
                r.nick = uuid.to_string();
                (old, r.nick_ts, ident, host)
            }
            None => return,
        };
        if old.eq_ignore_ascii_case(uuid) {
            return; // already at its UUID
        }
        self.remote_nick.remove(&old.to_ascii_lowercase());
        self.remote_nick
            .insert(uuid.to_ascii_lowercase(), uuid.to_string());
        self.notify_common_local(uuid, &format!(":{old}!{ident}@{host} NICK {uuid}"));
        self.propagate(&format!(":{} SAVE {} {}", self.sid, uuid, ts), None);
    }

    /// `:<src> SAVE <uuid> <ts>` — force our local user to its UUID if the ts still
    /// matches (it lost a collision elsewhere), or forward toward a remote target.
    fn link_save_recv(&mut self, via: Uid, msg: &Message) {
        let (Some(target), Some(ts)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        let ts: u64 = ts.parse().unwrap_or(0);
        if let Some(&luid) = self.uuid_local.get(&target) {
            if self.users.get(&luid).map(|u| u.nick_ts) == Some(ts) {
                let uuid = self.users[&luid].uuid.clone();
                self.set_nick(luid, &uuid);
            }
        } else {
            self.forward_to_target(&target, msg, via);
        }
    }

    fn link_nick_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> NICK <newnick> [<ts>]
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        let Some(newnick) = msg.params.first().cloned() else {
            return;
        };
        if !self.sourced_via(&uuid, via) {
            return;
        }
        // collision with a local user: resolve by timestamp (force-rename the loser
        // to its UUID) rather than killing.
        if let Some(luid) = self.find_nick(&newnick) {
            let remote_ts = msg
                .params
                .get(1)
                .and_then(|t| t.parse().ok())
                .unwrap_or_else(now);
            let (ruser, rip) = self
                .remote_users
                .get(&uuid)
                .map(|r| (r.ident.clone(), r.ip.clone()))
                .unwrap_or_default();
            let rsvc = self.uuid_is_service(&uuid);
            if self.resolve_collision(via, luid, remote_ts, &ruser, &rip, &uuid, rsvc) {
                return; // remote lost: it keeps its old nick; a SAVE will move it to UUID
            }
        }
        // collision with ANOTHER remote user: TS6 arbitration (DoCollision).
        if let Some(existing) = self.remote_nick.get(&newnick.to_ascii_lowercase()).cloned() {
            if existing != uuid {
                let remote_ts = msg
                    .params
                    .get(1)
                    .and_then(|t| t.parse().ok())
                    .unwrap_or_else(now);
                let (ruser, rip, rsid) = self
                    .remote_users
                    .get(&uuid)
                    .map(|r| (r.ident.clone(), r.ip.clone(), r.sid.clone()))
                    .unwrap_or_default();
                if self.resolve_remote_collision(via, &existing, remote_ts, &ruser, &rip, &uuid, &rsid)
                {
                    return; // the changer lost; a SAVE will move it to its UUID
                }
            }
        }
        let new_ts: u64 = msg
            .params
            .get(1)
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(now);
        let (old, ident, host) = match self.remote_users.get_mut(&uuid) {
            Some(ru) => {
                let old = ru.nick.clone();
                let (ident, host) = (ru.ident.clone(), ru.host.clone());
                ru.nick = newnick.clone();
                ru.nick_ts = new_ts;
                (old, ident, host)
            }
            None => return,
        };
        self.remote_nick.remove(&old.to_ascii_lowercase());
        self.remote_nick
            .insert(newnick.to_ascii_lowercase(), uuid.clone());
        // local members sharing a channel must see the rename (their list shows `old`)
        self.notify_common_local(&uuid, &format!(":{old}!{ident}@{host} NICK {newnick}"));
        self.propagate(&format!(":{uuid} NICK {newnick} {new_ts}"), Some(via));
    }

    fn link_quit_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> QUIT :<reason>
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        if !self.sourced_via(&uuid, via) {
            return;
        }
        let reason = msg.params.first().cloned().unwrap_or_default();
        self.drop_remote_user(&uuid, &reason);
        self.propagate(&format!(":{uuid} QUIT :{reason}"), Some(via));
    }

    /// `:<src> KILL <target> :<reason>` — a services/oper kill from a peer. A local
    /// target is notified and removed (its QUIT tells the rest of the tree); a
    /// remote target is routed one hop onward.
    fn link_kill_recv(&mut self, via: Uid, msg: &Message) {
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return; // reject a KILL whose source doesn't live behind this link
        }
        let (Some(target), Some(reason)) =
            (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        match self.link_local_target(&target) {
            Some(tuid) => {
                let from = self
                    .uuid_prefix(&src)
                    .or_else(|| self.servers.get(&src).map(|sv| sv.name.clone()))
                    .unwrap_or_else(|| src.clone());
                let nick = self
                    .users
                    .get(&tuid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                self.send(tuid, format!(":{from} KILL {nick} :{reason}"));
                self.remove_user(tuid, &format!("Killed ({reason})"));
            }
            None => {
                self.forward_to_target(&target, msg, via);
            }
        }
    }

    /// Route a KILL toward the server that owns a remote `target` uuid.
    pub fn route_kill(&self, killer: &str, target: &str, reason: &str) {
        if let Some(v) = self.link_toward(target) {
            self.link_out(v, format!(":{killer} KILL {target} :{reason}"));
        }
    }

    /// Route an INVITE toward the server that owns a remote `target` uuid.
    pub fn route_invite(&self, inviter: &str, target: &str, chan: &str) {
        if let Some(v) = self.link_toward(target) {
            self.link_out(v, format!(":{inviter} INVITE {target} {chan}"));
        }
    }

    /// `:<src> INVITE <target> <chan>` — deliver an invite to a local target (record
    /// it so they bypass +i, and notify them), or forward toward a remote one.
    fn link_invite_recv(&mut self, via: Uid, msg: &Message) {
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return; // reject an invite-bypass forged from behind another link
        }
        let (Some(target), Some(chan)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        if let Some(&luid) = self.uuid_local.get(&target) {
            let key = chan.to_ascii_lowercase();
            if let Some(ch) = self.channels.get_mut(&key) {
                ch.invites.insert(luid);
            }
            if let Some(u) = self.users.get_mut(&luid) {
                u.invited.insert(key.clone()); // reverse index for O(1) quit scrub
            }
            let prefix = self.uuid_prefix(&src).unwrap_or_else(|| src.clone());
            let nick = self
                .users
                .get(&luid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            self.send(luid, format!(":{prefix} INVITE {nick} :{chan}"));
        } else {
            self.forward_to_target(&target, msg, via);
        }
    }

    /// `:<src> ADDLINE <type> <mask> <setter> <settime> <duration> :<reason>` — a
    /// network ban set on a peer (e.g. a services akill). Apply and relay onward.
    fn link_addline_recv(&mut self, via: Uid, msg: &Message) {
        if msg.params.len() < 6 {
            return;
        }
        let Some(src) = msg.source.as_deref() else {
            return;
        };
        if !self.source_behind(src, via) {
            return; // reject a network x-line forged from behind another link
        }
        let Some(kind) = crate::xline::XKind::from_tag(&msg.params[0]) else {
            return;
        };
        // A malformed duration must not be silently coerced to 0 (= permanent);
        // a legitimate peer always sends a decimal integer (0 explicitly means
        // permanent). Reject garbage rather than installing an accidental perma-ban.
        let Ok(duration) = msg.params[4].parse::<u64>() else {
            return;
        };
        // params[3] is the origin's set-time — keep it so the ban's age/expiry and
        // the eventual "expired" notice reflect when it was really set, not now.
        let set_at = msg.params[3].parse::<u64>().unwrap_or_else(|_| now());
        self.add_xline_at(
            kind,
            &msg.params[1],
            duration,
            &msg.params[2],
            &msg.params[5],
            set_at,
        );
        self.propagate(&msg.to_wire(), Some(via));
    }

    /// `:<src> DELLINE <type> <mask>` — remove a network ban set on a peer.
    fn link_delline_recv(&mut self, via: Uid, msg: &Message) {
        if msg.params.len() < 2 {
            return;
        }
        let Some(src) = msg.source.as_deref() else {
            return;
        };
        if !self.source_behind(src, via) {
            return; // reject an x-line removal forged from behind another link
        }
        let Some(kind) = crate::xline::XKind::from_tag(&msg.params[0]) else {
            return;
        };
        let remover = self.link_setter(msg);
        if self.remove_xline(kind, &msg.params[1], &remover) {
            self.propagate(&msg.to_wire(), Some(via));
        }
    }

    /// Announce a locally-set network ban to peers as ADDLINE.
    pub fn propagate_addline(
        &self,
        kind: &str,
        mask: &str,
        setter: &str,
        duration: u64,
        reason: &str,
    ) {
        self.propagate(
            &format!(
                ":{} ADDLINE {kind} {mask} {setter} {} {duration} :{reason}",
                self.sid,
                now()
            ),
            None,
        );
    }

    /// Announce removal of a locally-set network ban to peers as DELLINE.
    pub fn propagate_delline(&self, kind: &str, mask: &str) {
        self.propagate(&format!(":{} DELLINE {kind} {mask}", self.sid), None);
    }

    /// Burst our current x-lines to a freshly-linked peer (SVSHOLD keeps its own path).
    fn burst_xlines(&self, link_uid: Uid) {
        for x in &self.xlines {
            if matches!(x.kind, crate::xline::XKind::Svshold) {
                continue;
            }
            let dur = if x.expires == 0 {
                0
            } else {
                x.expires.saturating_sub(now())
            };
            self.link_out(
                link_uid,
                format!(
                    ":{} ADDLINE {} {} {} {} {} :{}",
                    self.sid,
                    x.kind.tag(),
                    x.mask,
                    x.setter,
                    now(),
                    dur,
                    x.reason
                ),
            );
        }
    }

    /// Burst our spam-filter ruleset to a freshly-linked peer as `filter` metadata,
    /// so the network converges on the same rules (matches the peer's netburst).
    fn burst_filters(&self, link_uid: Uid) {
        if let Some(f) = self.ext.get::<crate::modules::filter::Filters>() {
            for r in &f.0 {
                self.link_out(
                    link_uid,
                    format!(
                        ":{} METADATA * filter :{}",
                        self.sid,
                        crate::modules::filter::encode_filter(r)
                    ),
                );
            }
        }
    }

    fn link_message_recv(&mut self, via: Uid, msg: &Message, notice: bool) {
        // :<srcuuid> PRIVMSG <#chan|dstuuid> :<text>
        let cmd = if notice { "NOTICE" } else { "PRIVMSG" };
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return; // don't relay a message forged from behind another link
        }
        if msg.params.len() < 2 {
            return;
        }
        let (target, text) = (msg.params[0].clone(), msg.params[1].clone());
        // Usually a remote user, but services can source a NOTICE from the server
        // itself — SET SNOTICE re-sources NickServ notices from the SID — so fall
        // back to the server name instead of dropping the message.
        let Some(prefix) = self
            .uuid_prefix(&src)
            .or_else(|| self.servers.get(&src).map(|s| s.name.clone()))
        else {
            return;
        };
        // A services user OR the services server itself counts as a service source.
        let src_is_service = self.uuid_is_service(&src) || self.server_is_service(&src);
        if target.starts_with('#') {
            let key = target.to_ascii_lowercase();
            if !self.channels.contains_key(&key) {
                return;
            }
            // echo/services badges a service source for message-tags clients; the
            // line is built once and shared by Arc across all members (not cloned
            // per recipient).
            let base = format!(":{prefix} {cmd} {target} :{text}");
            self.relay_channel_message(&key, &base, src_is_service);
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
            let want_tag = src_is_service
                && self
                    .users
                    .get(&dst)
                    .map(|u| u.caps.message_tags)
                    .unwrap_or(false);
            let tag = if want_tag { "@echo/services " } else { "" };
            self.send(dst, format!("{tag}:{prefix} {cmd} {nick} :{text}"));
        } else {
            // a remote target reached via another link (multi-hop) — forward onward
            self.forward_to_target(&target, msg, via);
        }
    }

    /// Tell linked servers a local user joined a channel.
    pub fn propagate_join(&self, uid: Uid, chan: &str, is_new: bool) {
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
        let letters = ch
            .members
            .get(&uid)
            .map(|m| m.mode_letters())
            .unwrap_or_default();
        if is_new {
            // a brand-new channel: burst it (its modes + the creating member) so a
            // peer that doesn't yet know the channel creates it consistently.
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
        } else {
            // joining an existing channel: an incremental single-member add that must
            // NOT carry the channel's modes. Re-asserting them on every join fights a
            // linked services mode-lock (it would re-apply +r etc. each time someone
            // enters). `IJOIN` carries only membership + status, per the standard
            // incremental-join primitive.
            let flags = if letters.is_empty() {
                String::new()
            } else {
                format!(" {letters}")
            };
            self.propagate(
                &format!(":{} IJOIN {} 1 {}{}", u.uuid, ch.name, ch.created, flags),
                None,
            );
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

    /// Tell linked servers a channel was renamed. `source` is the initiator's
    /// uuid (a client or a services pseudoclient) or a server SID; each receiver
    /// moves the channel and notifies its own members. `except` skips the link a
    /// forwarded rename arrived on.
    pub fn propagate_rename(
        &self,
        source: &str,
        oldname: &str,
        newname: &str,
        reason: &str,
        except: Option<Uid>,
    ) {
        if self.links.is_empty() {
            return;
        }
        self.propagate(
            &format!(":{source} RENAME {oldname} {newname} :{reason}"),
            except,
        );
    }

    /// The distinct links a channel's remote members sit behind (minus `except`).
    fn channel_link_targets(&self, key: &str, except: Option<Uid>) -> Vec<Uid> {
        let mut set: HashSet<Uid> = HashSet::default();
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
        // the joiner must actually live behind the link this JOIN arrived on
        if !self.sourced_via(&uuid, via) {
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
        if !chan.starts_with('#') || !self.sourced_via(&uuid, via) {
            return;
        }
        let key = chan.to_ascii_lowercase();
        let mut m = Member::default();
        // membid and ts are numeric; a trailing all-letter token is the status modes
        // the member arrives with (a services bot joins "ao", core services "o").
        let status = msg
            .params
            .get(3)
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphabetic()));
        if let Some(modes) = status {
            for c in modes.chars() {
                m.set_prefix(c, true);
            }
        }
        // If the channel is unknown (a desync/race), create it with the TS the IJOIN
        // carries — not now() — so our fabricated instance doesn't later win a bogus
        // TS war and propagate the wrong age.
        let ijoin_ts: Option<u64> = msg.params.get(2).and_then(|t| t.parse().ok());
        self.channels
            .entry(key.clone())
            .or_insert_with(|| {
                let mut c = Channel::new(&chan);
                if let Some(ts) = ijoin_ts {
                    c.created = ts;
                }
                c
            })
            .rmembers
            .insert(uuid.clone(), m);
        let prefix = self
            .remote_users
            .get(&uuid)
            .map(|r| r.prefix())
            .unwrap_or_default();
        self.to_channel(&key, &format!(":{prefix} JOIN {chan}"), None);
        // The JOIN conveys membership but not the status the member arrived with, so a
        // client already in the channel would show a services bot oppless after it
        // rejoins (e.g. across a services restart). Announce the status as a MODE too,
        // attributed to the member's server as a netburst status change is.
        if let Some(modes) = status {
            let nick = self
                .remote_users
                .get(&uuid)
                .map(|r| r.nick.clone())
                .unwrap_or_else(|| uuid.clone());
            let src = uuid
                .get(..3)
                .and_then(|sid| self.servers.get(sid))
                .map(|s| s.name.clone())
                .unwrap_or_else(|| self.name.clone());
            let targets = vec![nick.as_str(); modes.len()].join(" ");
            self.to_channel(
                &key,
                &format!(":{src} MODE {chan} +{modes} {targets}"),
                None,
            );
        }
        self.propagate(&msg.to_wire(), Some(via));
    }

    fn link_part_recv(&mut self, via: Uid, msg: &Message) {
        // :<uuid> PART #chan [:reason]
        let Some(uuid) = msg.source.clone() else {
            return;
        };
        if !self.sourced_via(&uuid, via) {
            return;
        }
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

    fn link_rename_recv(&mut self, via: Uid, msg: &Message) {
        // :<source> RENAME <old> <new> [:reason] — a channel renamed elsewhere
        // (by a client on another server, or by ChanServ). Apply it locally,
        // notify our members, then forward to the rest of the mesh. A
        // services-sourced rename is honoured unconditionally: services owns the
        // registered name and validated the op/founder before sending this.
        let Some(source) = msg.source.clone() else {
            return;
        };
        let (Some(old), Some(new)) = (msg.params.first().cloned(), msg.params.get(1).cloned())
        else {
            return;
        };
        let reason = msg.params.get(2).cloned().unwrap_or_default();
        if !self.source_behind(&source, via) {
            return; // reject a channel rename forged from behind another link
        }
        let oldkey = old.to_ascii_lowercase();
        if !self.channels.contains_key(&oldkey) {
            return;
        }
        // The nick!user@host (or server name) shown to local members as the source.
        let prefix = self
            .remote_users
            .get(&source)
            .map(|r| r.prefix())
            .or_else(|| self.servers.get(&source).map(|s| s.name.clone()))
            .or_else(|| {
                self.servers
                    .get(source.get(..3).unwrap_or(source.as_str()))
                    .map(|s| s.name.clone())
            });
        let Some(prefix) = prefix else {
            return; // unknown source — don't act on a rename we can't attribute
        };
        if self
            .rename_channel(&oldkey, &new, &prefix, &reason)
            .is_some()
        {
            self.propagate_rename(&source, &old, &new, &reason, Some(via));
        }
    }

    /// Remove a remote user everywhere (channels + registries) and QUIT them to
    /// any local users who shared a channel.
    fn drop_remote_user(&mut self, uuid: &str, reason: &str) {
        let prefix = match self.remote_users.get(uuid) {
            Some(ru) => ru.prefix(),
            None => return,
        };
        let mut notify: HashSet<Uid> = HashSet::default();
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

    /// Send `line` once to every LOCAL user who shares a channel with remote user
    /// `uuid` (deduped). Surfaces a remote user's nick change to local clients, whose
    /// member lists would otherwise keep showing the stale nick.
    fn notify_common_local(&self, uuid: &str, line: &str) {
        self.notify_common_local_if(uuid, line, |_| true);
    }

    /// Like [`Self::notify_common_local`] but only to members whose caps satisfy
    /// `want` (e.g. `|c| c.chghost` so a remote CHGHOST reaches only cap-aware clients).
    fn notify_common_local_if(
        &self,
        uuid: &str,
        line: &str,
        want: impl Fn(&crate::users::Caps) -> bool,
    ) {
        let mut notify: HashSet<Uid> = HashSet::default();
        for c in self.channels.values() {
            if c.rmembers.contains_key(uuid) {
                for &m in c.members.keys() {
                    notify.insert(m);
                }
            }
        }
        for m in notify {
            if self.users.get(&m).is_some_and(|u| want(&u.caps)) {
                self.send(m, line.to_string());
            }
        }
    }

    /// A remote user's host/ident changed (a CHGHOST/CHGIDENT whose target lives
    /// behind another server): update our copy so messages/WHOIS/NAMES show the new
    /// mask, and give local chghost-cap members a live CHGHOST. (Non-cap members see
    /// the new mask on their next NAMES; a full host-cycle for them is a TODO.)
    fn apply_remote_host_ident(
        &mut self,
        target: &str,
        new_ident: Option<&str>,
        new_host: Option<&str>,
    ) {
        let uuid = if self.remote_users.contains_key(target) {
            target.to_string()
        } else if let Some(u) = self.remote_nick.get(&target.to_ascii_lowercase()) {
            u.clone()
        } else {
            return;
        };
        let old_prefix = match self.remote_users.get(&uuid) {
            Some(r) => r.prefix(),
            None => return,
        };
        let (ident, host) = match self.remote_users.get_mut(&uuid) {
            Some(r) => {
                if let Some(i) = new_ident {
                    r.ident = i.to_string();
                }
                if let Some(h) = new_host {
                    r.host = h.to_string();
                }
                (r.ident.clone(), r.host.clone())
            }
            None => return,
        };
        let line = format!(":{old_prefix} CHGHOST {ident} {host}");
        self.notify_common_local_if(&uuid, &line, |c| c.chghost);
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
        let ts = self
            .channels
            .get(&key)
            .map(|c| c.created)
            .unwrap_or_else(now);
        let mut out: Vec<String> = Vec::new();
        let mut pi = 0usize;
        let mut sign = '+';
        for c in modestring.chars() {
            match c {
                '+' | '-' => sign = c,
                'y' | 'q' | 'a' | 'o' | 'h' | 'v' => {
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
        self.propagate(
            &format!(":{src} FMODE {chan} {ts} {modestring}{pstr}"),
            None,
        );
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
        self.propagate(&format!(":{} KICK {chan} {vuuid} :{reason}", u.uuid), None);
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
        if !self.source_behind(&src, via) {
            return; // a peer can't set a topic sourced from behind another link
        }
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
        // relay onward as a timestamped FTOPIC (services/peers ignore a plain TOPIC)
        let chants = self
            .channels
            .get(&key)
            .map(|c| c.created)
            .unwrap_or_else(now);
        self.propagate(
            &format!(":{src} FTOPIC {chan} {chants} {} :{text}", now()),
            Some(via),
        );
    }

    fn link_kick_recv(&mut self, via: Uid, msg: &Message) {
        // :<kicker> KICK #chan <victim-uuid|nick> :<reason>  (the S2S form uses a uuid)
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return; // reject a KICK whose kicker doesn't live behind this link
        }
        if msg.params.len() < 2 {
            return;
        }
        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        let victim = msg.params[1].clone();
        let reason = msg.params.get(2).cloned().unwrap_or_default();
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
        if !self.source_behind(&src, via) {
            return; // a peer can't set a topic sourced from behind another link
        }
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
        // channel-TS guard: if our channel won the TS war (older/lower created TS),
        // ignore a topic coming from an instance that lost it.
        let chants: u64 = msg.params[1].parse().unwrap_or(0);
        if self
            .channels
            .get(&key)
            .map(|c| c.created)
            .is_some_and(|ours| ours < chants)
        {
            self.propagate(&msg.to_wire(), Some(via));
            return;
        }
        // keep whichever topic was set later: drop an FTOPIC older than the one we hold.
        if let Some(cur_ts) = self
            .channels
            .get(&key)
            .and_then(|c| c.topic.as_ref())
            .map(|t| t.ts)
        {
            if ts < cur_ts {
                self.propagate(&msg.to_wire(), Some(via));
                return;
            }
        }
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
        // originating server already authorised the change, *provided* the source
        // genuinely sits behind this link (else a peer could forge ops/bans).
        let Some(src) = msg.source.clone() else {
            return;
        };
        if !self.source_behind(&src, via) {
            return;
        }
        if msg.params.len() < 2 {
            return;
        }
        // FMODE inserts a channel timestamp before the mode string
        let mode_idx = if msg.command == "FMODE" { 2 } else { 1 };

        // a user-mode change: reflect it on our record of the remote user (WHOIS
        // 335/379 read `RemoteUser.modes`) and relay onward. We don't re-toggle a LOCAL
        // user's umodes here — services force those via SVSMODE.
        if !msg.params[0].starts_with('#') {
            if let (Some(target), Some(changes)) = (msg.params.first(), msg.params.get(1)) {
                if let Some(ru) = self.remote_users.get_mut(target) {
                    apply_umode_string(&mut ru.modes, changes);
                }
            }
            self.propagate(&msg.to_wire(), Some(via));
            return;
        }

        let chan = msg.params[0].clone();
        let key = chan.to_ascii_lowercase();
        if !self.channels.contains_key(&key) {
            return;
        }
        // FMODE timestamp arbitration: a change stamped NEWER than our channel TS lost
        // the timestamp war and is dropped (services stamp ts 1, so theirs always win).
        if msg.command == "FMODE" {
            if let Some(ts) = msg.params.get(1).and_then(|t| t.parse::<u64>().ok()) {
                let ours = self.channels.get(&key).map(|c| c.created).unwrap_or(0);
                if ts > ours {
                    self.propagate(&msg.to_wire(), Some(via));
                    return;
                }
            }
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
                'y' | 'q' | 'a' | 'o' | 'h' | 'v' => {
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
                    // Any other channel mode. Consult the registry for its arity so
                    // we consume exactly the right number of params — mis-consuming
                    // here shifts every later mode's argument — then apply it through
                    // the same handler the local MODE path uses, so parameter modes
                    // (+f/+j/+F/+L/+H/+B/+J/+d/+K) and list modes (+g/+X/+w) are
                    // stored, not silently dropped.
                    let handler = crate::mode::chan_mode(c);
                    let param = if handler.map(|h| h.wants_param(adding)).unwrap_or(false) {
                        let p = args.get(argi).cloned();
                        if p.is_some() {
                            argi += 1;
                        }
                        p
                    } else {
                        None
                    };
                    if let Some(p) = &param {
                        shown.push(p.clone());
                    }
                    match handler {
                        Some(h) => {
                            self.mode_sudo = true;
                            h.apply(self, &chan, &key, 0, adding, param.as_deref());
                            self.mode_sudo = false;
                        }
                        // no registry handler (e.g. the services-only +r): a plain flag
                        None => {
                            if let Some(ch) = self.channels.get_mut(&key) {
                                ch.modes.set_by_letter(c, adding);
                            }
                        }
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
            // render(false) puts parametric mode letters in the FJOIN without their
            // values; burst the access-controlling ones (key, limit) as timestamped
            // FMODEs so they survive netburst (the receiver's FMODE path is param-aware)
            if let Some(k) = &ch.modes.key {
                lines.push(format!(
                    ":{} FMODE {} {} +k {}",
                    self.sid, ch.name, ch.created, k
                ));
            }
            if let Some(l) = ch.modes.limit {
                lines.push(format!(
                    ":{} FMODE {} {} +l {}",
                    self.sid, ch.name, ch.created, l
                ));
            }
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
        // TS arbitration (lower wins). Fresh channel or equal TS: adopt the remote
        // modes, members keep their status. Incoming TS OLDER than ours → we lost:
        // adopt it, drop our modes and de-status every member. Incoming TS NEWER →
        // we won: its members join stripped of status.
        let our_ts = self.channels.get(&key).map(|c| c.created);
        let remote_wins = our_ts.is_some_and(|ours| ts < ours);
        let we_win = our_ts.is_some_and(|ours| ts > ours);
        let keep_status = !we_win;
        {
            let ch = self
                .channels
                .entry(key.clone())
                .or_insert_with(|| Channel::new(&chan));
            if !we_win {
                // Fresh channel, we lost the TS war, or an equal-TS merge: adopt the
                // remote channel modes. On a loss, first wipe OUR state — the boolean
                // modes AND (previously missed) the list modes + topic — else a ban
                // the winning side never had lingers here forever (split-brain).
                if remote_wins {
                    ch.modes = ChanModes::default();
                    ch.bans.clear();
                    ch.excepts.clear();
                    ch.invex.clear();
                    ch.filters.clear();
                    ch.exemptchanops.clear();
                    ch.autoop.clear();
                    ch.topic = None;
                    for m in ch.members.values_mut() {
                        m.clear_status();
                    }
                    for m in ch.rmembers.values_mut() {
                        m.clear_status();
                    }
                }
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
            if keep_status {
                for pc in letters.chars() {
                    m.set_prefix(pc, true);
                }
            }
            adds.push((uuid, m));
        }
        for (uuid, m) in adds {
            let already = self
                .channels
                .get(&key)
                .map(|c| c.rmembers.contains_key(&uuid))
                .unwrap_or(false);
            if let Some(ch) = self.channels.get_mut(&key) {
                ch.rmembers.insert(uuid.clone(), m);
            }
            // announce the join to local members (a no-op for a brand-new channel)
            if !already {
                if let Some(prefix) = self.remote_users.get(&uuid).map(|r| r.prefix()) {
                    self.to_channel(&key, &format!(":{prefix} JOIN {chan}"), None);
                }
            }
        }
        let raw = format!(
            ":{} FJOIN {chan} {ts} {modes} :{memberlist}",
            msg.source.clone().unwrap_or_default()
        );
        self.propagate(&raw, Some(via));
    }
}

/// Nick-collision outcome `(change_local, change_remote)` by timestamp: same
/// user@ip → the older nick changes; different → the newer changes; equal → both.
fn collision_decision(local_ts: u64, remote_ts: u64, same_person: bool) -> (bool, bool) {
    if remote_ts == local_ts {
        (true, true)
    } else if (same_person && remote_ts < local_ts) || (!same_person && remote_ts > local_ts) {
        (false, true)
    } else {
        (true, false)
    }
}

/// Apply a `+ab-c`-style user-mode delta to a stored mode-letter string, so a remote
/// user's `modes` stay current for WHOIS when their umodes change over the link.
fn apply_umode_string(modes: &mut String, changes: &str) {
    let mut adding = true;
    for c in changes.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            _ if adding => {
                if !modes.contains(c) {
                    modes.push(c);
                }
            }
            _ => modes.retain(|m| m != c),
        }
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
    fn nick_collision_timestamp_rules() {
        // equal TS → both change
        assert_eq!(collision_decision(100, 100, true), (true, true));
        assert_eq!(collision_decision(100, 100, false), (true, true));
        // same user@ip (reconnect): the OLDER nick changes
        assert_eq!(collision_decision(200, 100, true), (false, true)); // remote older → remote
        assert_eq!(collision_decision(100, 200, true), (true, false)); // local older → local
                                                                       // different user@ip: the NEWER nick changes
        assert_eq!(collision_decision(100, 200, false), (false, true)); // remote newer → remote
        assert_eq!(collision_decision(200, 100, false), (true, false)); // local newer → local
    }

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

    // A services `ident@host` vhost arrives as ONE `CHGHOST <uid> ident@host` and
    // must apply the ident AND host in a single CHGHOST — not a CHGIDENT + CHGHOST
    // pair, which showed the client two "changed host" notices. Regression.
    #[test]
    fn chghost_ident_at_host_applies_as_one_change() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "mik".into(),
                ident: "da55e982f672".into(),
                realname: "m".into(),
                host: "cloak.ip".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps {
                    chghost: true,
                    ..Caps::default()
                },
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);

        let msg = crate::message::parse(":42S CHGHOST 0AAAAAAAB mike@echoircd.org").unwrap();
        s.link_chghost_recv(1, &msg);

        // both ident and host applied from the single command
        assert_eq!(s.users[&7].ident, "mike");
        assert_eq!(s.users[&7].vhost.as_deref(), Some("echoircd.org"));
        // and the client saw exactly ONE CHGHOST line, carrying the final ident@host
        let chghosts: Vec<String> = urx.try_iter().filter(|l| l.contains("CHGHOST")).collect();
        assert_eq!(
            chghosts.len(),
            1,
            "exactly one CHGHOST expected, got: {chghosts:?}"
        );
        assert!(
            chghosts[0].contains("CHGHOST mike echoircd.org"),
            "got: {}",
            chghosts[0]
        );
    }

    // Remote-vs-remote nick collision: TS6 arbitration must rename the LOSER to its
    // UUID (older nick-TS wins for different people), not always the incoming one.
    #[test]
    fn remote_vs_remote_collision_ts6_arbitration() {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));

        fn add_remote(s: &mut Server, uuid: &str, nick: &str, sid: &str, ip: &str, ts: u64) {
            s.remote_users.insert(
                uuid.to_string(),
                RemoteUser {
                    uuid: uuid.to_string(),
                    nick: nick.to_string(),
                    ident: "u".into(),
                    host: "h".into(),
                    realname: "r".into(),
                    account: None,
                    ip: ip.into(),
                    modes: String::new(),
                    sid: sid.to_string(),
                    via: 1,
                    nick_ts: ts,
                    away: None,
                },
            );
        }

        // different people (differing IPs), incoming NEWER → incoming yields.
        add_remote(&mut s, "1AAAAAAAA", "foo", "1AA", "1.1.1.1", 100);
        assert!(
            s.resolve_remote_collision(1, "1AAAAAAAA", 200, "u", "9.9.9.9", "2BBAAAAAA", "2BB"),
            "newer incoming must change to its UUID"
        );
        assert_eq!(s.remote_users["1AAAAAAAA"].nick, "foo", "older existing keeps the nick");

        // different people, incoming OLDER → incoming wins, existing renamed to its UUID.
        add_remote(&mut s, "1AABBBBBB", "bar", "1AA", "1.1.1.1", 300);
        assert!(
            !s.resolve_remote_collision(1, "1AABBBBBB", 50, "u", "9.9.9.9", "2BBBBBBBB", "2BB"),
            "older incoming wins and keeps its nick"
        );
        assert_eq!(
            s.remote_users["1AABBBBBB"].nick, "1AABBBBBB",
            "the losing existing remote is renamed to its UUID"
        );
    }

    // A remote user's nick change must reach LOCAL members who share a channel — their
    // member list would otherwise keep the stale nick. Regression: link_nick_recv
    // updated S2S state + propagated to peers but never told local clients.
    #[test]
    fn remote_nick_change_reaches_local_members() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.remote_users.insert(
            "42SB00000".to_string(),
            RemoteUser {
                uuid: "42SB00000".to_string(),
                nick: "bob".into(),
                ident: "b".into(),
                host: "h".into(),
                realname: "r".into(),
                account: None,
                ip: String::new(),
                modes: String::new(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 100,
                away: None,
            },
        );
        // a local member with a captured sink, sharing #c with the remote user
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);
        let mut ch = Channel::new("#c");
        ch.members.insert(7, Member::default());
        ch.rmembers.insert("42SB00000".into(), Member::default());
        s.channels.insert("#c".into(), ch);

        let msg = crate::message::parse(":42SB00000 NICK bobby 200").unwrap();
        s.link_nick_recv(1, &msg);

        let lines: Vec<String> = std::iter::from_fn(|| urx.try_recv().ok()).collect();
        assert!(
            lines.iter().any(|l| l == ":bob!b@h NICK bobby"),
            "local member must see the remote nick change, got {lines:?}"
        );
    }

    // A remote user's CHGHOST must update our copy (so messages/WHOIS show the new
    // mask) and reach local chghost-cap members. Regression: remote-target CHGHOST
    // only forwarded, leaving our copy stale and local clients uninformed.
    #[test]
    fn remote_chghost_updates_copy_and_notifies_cap_members() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.remote_users.insert(
            "42SB00000".to_string(),
            RemoteUser {
                uuid: "42SB00000".to_string(),
                nick: "bob".into(),
                ident: "b".into(),
                host: "old.host".into(),
                realname: "r".into(),
                account: None,
                ip: String::new(),
                modes: String::new(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: {
                    let mut c = Caps::default();
                    c.chghost = true;
                    c
                },
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);
        let mut ch = Channel::new("#c");
        ch.members.insert(7, Member::default());
        ch.rmembers.insert("42SB00000".into(), Member::default());
        s.channels.insert("#c".into(), ch);

        let msg = crate::message::parse(":42S CHGHOST 42SB00000 newident@new.host").unwrap();
        s.link_chghost_recv(1, &msg);

        assert_eq!(s.remote_users["42SB00000"].host, "new.host", "our copy's host updated");
        assert_eq!(s.remote_users["42SB00000"].ident, "newident", "our copy's ident updated");
        let lines: Vec<String> = std::iter::from_fn(|| urx.try_recv().ok()).collect();
        assert!(
            lines.iter().any(|l| l == ":bob!b@old.host CHGHOST newident new.host"),
            "chghost-cap member must get the CHGHOST, got {lines:?}"
        );
    }

    // A remote user's AWAY must update our copy (for WHOIS 301) and reach local
    // away-notify members. Regression: AWAY didn't cross S2S at all.
    #[test]
    fn remote_away_updates_copy_and_notifies_cap_members() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.remote_users.insert(
            "42SB00000".to_string(),
            RemoteUser {
                uuid: "42SB00000".to_string(),
                nick: "bob".into(),
                ident: "b".into(),
                host: "h".into(),
                realname: "r".into(),
                account: None,
                ip: String::new(),
                modes: String::new(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: {
                    let mut c = Caps::default();
                    c.away_notify = true;
                    c
                },
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);
        let mut ch = Channel::new("#c");
        ch.members.insert(7, Member::default());
        ch.rmembers.insert("42SB00000".into(), Member::default());
        s.channels.insert("#c".into(), ch);

        let msg = crate::message::parse(":42SB00000 AWAY :lunch").unwrap();
        s.link_away_recv(1, &msg);
        assert_eq!(
            s.remote_users["42SB00000"].away.as_deref(),
            Some("lunch"),
            "our copy records the away reason"
        );
        let lines: Vec<String> = std::iter::from_fn(|| urx.try_recv().ok()).collect();
        assert!(
            lines.iter().any(|l| l == ":bob!b@h AWAY :lunch"),
            "away-notify member must see AWAY, got {lines:?}"
        );

        let back = crate::message::parse(":42SB00000 AWAY").unwrap();
        s.link_away_recv(1, &back);
        assert_eq!(s.remote_users["42SB00000"].away, None, "away cleared on return");
    }

    #[test]
    fn apply_umode_string_toggles_letters() {
        let mut m = "iH".to_string();
        apply_umode_string(&mut m, "+B");
        assert!(m.contains('B'), "added B");
        apply_umode_string(&mut m, "-H+x");
        assert!(!m.contains('H') && m.contains('x'), "removed H, added x");
        apply_umode_string(&mut m, "+i"); // already set
        assert_eq!(m.matches('i').count(), 1, "no duplicate letter");
    }

    // A services bot IJOINing an existing channel with a status token (e.g. "ao")
    // must join holding those prefix modes. Regression: an early S2S build accepted
    // the IJOIN but ignored the token, so BotServ bots joined bare and had to be
    // opped by hand.
    #[test]
    fn ijoin_applies_status_modes() {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        // a services bot the network already knows about
        s.remote_users.insert(
            "42SB00000".to_string(),
            RemoteUser {
                uuid: "42SB00000".to_string(),
                nick: "echoIRCd".into(),
                ident: "echo".into(),
                host: "services".into(),
                realname: "bot".into(),
                account: None,
                ip: String::new(),
                modes: "iHkB".into(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        // echo joins it to an existing channel as protected admin + op (+ao)
        let msg = crate::message::parse(":42SB00000 IJOIN #echoircd 16 1 ao").unwrap();
        s.link_ijoin_recv(1, &msg);
        let m = &s.channels["#echoircd"].rmembers["42SB00000"];
        assert!(
            m.admin(),
            "bot should hold +a (&) from the IJOIN status token"
        );
        assert!(m.op(), "bot should hold +o (@) from the IJOIN status token");
    }

    // ...and it must announce that status to members already in the channel: the
    // bare JOIN alone left a client showing a services bot oppless after it rejoined
    // (e.g. across a services restart), even though a fresh NAMES had it opped.
    #[test]
    fn ijoin_status_is_announced_to_members() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.servers.insert(
            "42S".to_string(),
            RemoteServer {
                sid: "42S".into(),
                name: "services.example.net".into(),
                desc: String::new(),
                via: 1,
                is_service: true,
                silent_service: false,
            },
        );
        s.remote_users.insert(
            "42SB00000".to_string(),
            RemoteUser {
                uuid: "42SB00000".to_string(),
                nick: "echoIRCd".into(),
                ident: "echo".into(),
                host: "services".into(),
                realname: "bot".into(),
                account: None,
                ip: String::new(),
                modes: "iHkB".into(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        // a local member already sitting in the channel, with a captured sink
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);
        let mut ch = Channel::new("#echoircd");
        ch.members.insert(7, Member::default());
        s.channels.insert("#echoircd".into(), ch);

        let msg = crate::message::parse(":42SB00000 IJOIN #echoircd 16 1 ao").unwrap();
        s.link_ijoin_recv(1, &msg);

        let lines: Vec<String> = std::iter::from_fn(|| urx.try_recv().ok()).collect();
        assert!(
            lines.iter().any(|l| l.contains("JOIN #echoircd")),
            "member should see the bot JOIN, got {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == ":services.example.net MODE #echoircd +ao echoIRCd echoIRCd"),
            "member must be told the bot's +ao status, got {lines:?}"
        );
    }

    // A server is a service iff its NAME matches the sasl_server or a `uline` config
    // entry (case-insensitive); `silent` is honoured.
    // FJOIN timestamp arbitration: the lower channel TS wins. A member bursted with
    // a NEWER TS than ours joins stripped of status; an OLDER TS wipes our side.
    #[test]
    fn fjoin_ts_arbitration_strips_losing_status() {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.remote_users.insert(
            "42SAAAAAA".to_string(),
            RemoteUser {
                uuid: "42SAAAAAA".to_string(),
                nick: "bob".into(),
                ident: "b".into(),
                host: "h".into(),
                realname: "b".into(),
                account: None,
                ip: String::new(),
                modes: String::new(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        // we already hold #c at an OLD (winning) TS
        s.channels.insert("#c".into(), {
            let mut c = Channel::new("#c");
            c.created = 1000;
            c
        });
        // a peer bursts #c with a NEWER TS, opping bob — bob must join WITHOUT +o
        let m = crate::message::parse(":42S FJOIN #c 2000 +nt :o,42SAAAAAA").unwrap();
        s.link_fjoin_recv(1, &m);
        let opped = s.channels["#c"].rmembers["42SAAAAAA"].op();
        assert!(
            !opped,
            "a member bursted with a newer (losing) TS must be de-statused"
        );
        assert_eq!(s.channels["#c"].created, 1000, "our older TS is kept");
    }

    fn bob_server() -> Server {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.remote_users.insert(
            "42SAAAAAA".to_string(),
            RemoteUser {
                uuid: "42SAAAAAA".to_string(),
                nick: "bob".into(),
                ident: "b".into(),
                host: "h".into(),
                realname: "b".into(),
                account: None,
                ip: String::new(),
                modes: String::new(),
                sid: "42S".into(),
                via: 1,
                nick_ts: 0,
                away: None,
            },
        );
        s
    }

    // Losing the FJOIN TS war must wipe our list modes (bans) and topic too — not just
    // the boolean modes — else a ban the winning side never had lingers forever here.
    #[test]
    fn fjoin_loss_clears_lists_and_topic() {
        use crate::channels::{Ban, Topic};
        let mut s = bob_server();
        s.channels.insert("#c".into(), {
            let mut c = Channel::new("#c");
            c.created = 2000; // we hold the NEWER (losing) TS
            c.bans.push(Ban {
                mask: "*!*@evil".into(),
                setter: "me".into(),
                ts: 0,
                expires: None,
            });
            c.topic = Some(Topic {
                text: "old".into(),
                setter: "me".into(),
                ts: 0,
            });
            c
        });
        let m = crate::message::parse(":42S FJOIN #c 1000 +mnt :o,42SAAAAAA").unwrap();
        s.link_fjoin_recv(1, &m);
        let ch = &s.channels["#c"];
        assert_eq!(ch.created, 1000, "we adopt the winning TS");
        assert!(
            ch.bans.is_empty(),
            "our ban must be wiped on losing the TS war"
        );
        assert!(
            ch.topic.is_none(),
            "our topic must be wiped on losing the TS war"
        );
        assert!(ch.modes.moderated, "the winner's +m is adopted");
    }

    // Equal-TS FJOIN must MERGE the remote channel modes, not drop them.
    #[test]
    fn fjoin_equal_ts_merges_modes() {
        let mut s = bob_server();
        s.channels.insert("#c".into(), {
            let mut c = Channel::new("#c");
            c.created = 1000;
            c
        });
        let m = crate::message::parse(":42S FJOIN #c 1000 +m :o,42SAAAAAA").unwrap();
        s.link_fjoin_recv(1, &m);
        assert!(
            s.channels["#c"].modes.moderated,
            "an equal-TS FJOIN must merge the remote +m"
        );
        assert_eq!(s.channels["#c"].created, 1000);
    }

    // An FTOPIC from a channel instance that LOST the TS war (its chants > our created)
    // must be ignored, even if its topic timestamp is newer.
    #[test]
    fn ftopic_dropped_when_our_channel_won_the_ts() {
        use crate::channels::Topic;
        let mut s = bob_server();
        s.channels.insert("#c".into(), {
            let mut c = Channel::new("#c");
            c.created = 1000; // we won
            c.topic = Some(Topic {
                text: "ours".into(),
                setter: "me".into(),
                ts: 5,
            });
            c
        });
        // chants=2000 (their instance lost), topicts=9 (newer) — must still be ignored
        let m = crate::message::parse(":42SAAAAAA FTOPIC #c 2000 9 bob :theirs").unwrap();
        s.link_ftopic_recv(1, &m);
        assert_eq!(
            s.channels["#c"].topic.as_ref().unwrap().text,
            "ours",
            "a topic from a channel instance that lost the TS war must be dropped"
        );
    }

    #[test]
    fn uline_recognises_services_server() {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut cfg = Config::default();
        cfg.sasl_server = "services.example.net".to_string();
        cfg.raw
            .entry("uline".to_string())
            .or_default()
            .push("other.example.net silent".to_string());
        let s = Server::new(cfg, tx, Arc::new(AtomicU64::new(1)));
        assert_eq!(s.uline_match("services.example.net"), (true, false)); // sasl_server ⇒ implicit uline
        assert_eq!(s.uline_match("OTHER.example.net"), (true, true)); // explicit, silent, case-insensitive
        assert_eq!(s.uline_match("hub.example.net"), (false, false)); // an ordinary peer
    }

    // SVS* authority: only a source on a U-lined services server counts.
    #[test]
    fn svs_source_must_be_a_service() {
        use crate::config::Config;
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};
        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        let mk = |sid: &str, is_service: bool| RemoteServer {
            sid: sid.to_string(),
            name: format!("{sid}.example.net"),
            desc: String::new(),
            via: 1,
            is_service,
            silent_service: false,
        };
        s.servers.insert("42S".into(), mk("42S", true));
        s.servers.insert("10H".into(), mk("10H", false));
        // from a service pseudo-client (uuid → sid 42S) and from the service SID itself
        assert!(
            s.source_is_service(&crate::message::parse(":42SB00000 SVSMODE 0AAAAAAAB +r").unwrap())
        );
        assert!(s.source_is_service(&crate::message::parse(":42S SVSJOIN 0AAAAAAAB #c").unwrap()));
        // from an ordinary peer: rejected
        assert!(
            !s.source_is_service(&crate::message::parse(":10HAAAAAA SVSNICK 0AAAAAAAB g").unwrap())
        );
    }

    // A NOTICE re-sourced from the services server itself (SET SNOTICE ON re-sources
    // NickServ notices from the SID, not the pseudoclient) must still reach the target
    // user — shown as coming from the server name — instead of being dropped because
    // the source isn't a user UUID. Regression: link_message_recv only resolved user
    // sources, so server-sourced service notices were silently lost.
    #[test]
    fn server_sourced_notice_reaches_the_user() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::map::HashSet;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};

        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.servers.insert(
            "42S".into(),
            RemoteServer {
                sid: "42S".into(),
                name: "services.example.net".into(),
                desc: String::new(),
                via: 1,
                is_service: true,
                silent_service: false,
            },
        );
        let (utx, urx) = mpsc::channel();
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);

        let msg =
            crate::message::parse(":42S NOTICE 0AAAAAAAB :*** NickServ: welcome back").unwrap();
        s.link_message_recv(1, &msg, true);

        let got = urx
            .try_recv()
            .expect("a server-sourced service notice must be delivered, not dropped");
        assert_eq!(
            got,
            ":services.example.net NOTICE alice :*** NickServ: welcome back"
        );
    }

    // A services IRCv3 standard reply (ENCAP * SWSTDRPL, e.g. a failed NickServ
    // IDENTIFY) must be re-emitted as a FAIL to a standard-replies client — not
    // dropped. Regression: SWSTDRPL fell through on_link's `_ => {}`.
    #[test]
    fn services_standard_reply_reaches_the_client() {
        use crate::config::Config;
        use crate::extensible::Extensible;
        use crate::map::HashSet;
        use crate::users::{Caps, UserFlags};
        use std::sync::atomic::AtomicU64;
        use std::sync::{mpsc, Arc};

        let (tx, _rx) = mpsc::channel();
        let mut s = Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)));
        s.servers.insert(
            "42S".into(),
            RemoteServer {
                sid: "42S".into(),
                name: "services.example.net".into(),
                desc: String::new(),
                via: 1,
                is_service: true,
                silent_service: false,
            },
        );
        let (utx, urx) = mpsc::channel();
        let mut caps = Caps::default();
        caps.standard_replies = true;
        s.users.insert(
            7,
            User {
                uid: 7,
                uuid: "0AAAAAAAB".into(),
                nick: "alice".into(),
                ident: "a".into(),
                realname: "a".into(),
                host: "localhost".into(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps,
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(utx),
                sock: None,
            },
        );
        s.uuid_local.insert("0AAAAAAAB".into(), 7);

        let msg = crate::message::parse(
            ":42S SWSTDRPL 0AAAAAAAB * FAIL IDENTIFY ACCOUNT_NOT_REGISTERED :that account isn't registered",
        )
        .unwrap();
        s.link_stdreply_recv(1, &msg);

        let got = urx
            .try_recv()
            .expect("a services standard reply must reach the client, not be dropped");
        let sname = s.name.clone();
        assert_eq!(
            got,
            format!(":{sname} FAIL IDENTIFY ACCOUNT_NOT_REGISTERED :that account isn't registered")
        );
    }
}
