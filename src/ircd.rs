//! The core: owns the [`Server`] state, the command table and the module list,
//! and turns a stream of [`Event`]s into IRC. Everything here runs on one
//! thread, so no state is ever locked.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{Receiver, Sender};

use crate::command::Command;
use crate::config::Config;
use crate::coremods::command_table;
use crate::message;
use crate::module::{Hook, ModResult, Module};
use crate::numeric::{ERR_NEEDMOREPARAMS, ERR_NOTREGISTERED, ERR_UNKNOWNCOMMAND};
use crate::server::Server;
use crate::socketengine::OutSink;
use crate::Uid;

/// What the I/O threads hand to the core.
pub enum Event {
    Connect {
        uid: Uid,
        addr: SocketAddr,
        out: OutSink,
        sock: Option<TcpStream>,
        secure: bool,
        certfp: Option<String>, // TLS client-cert fingerprint (clients only)
        link: bool,             // a server-to-server connection, not a client
        outbound: bool,         // (link) we dialed them
    },
    Line {
        uid: Uid,
        line: String,
    },
    Disconnect {
        uid: Uid,
    },
    /// A client's connect-time DNS work finished: the reverse-DNS hostname
    /// (`None` = none confirmed) and the DNSBL outcome.
    ResolvedHost {
        uid: Uid,
        host: Option<String>,
        dnsbl: crate::modules::dnsbl::Outcome,
    },
    /// Background timer tick — drives ping/idle timeouts.
    Tick,
}

/// Insert an extra IRCv3 tag into a wire line's tag block, creating the `@…`
/// block if the line has none. Used to fold `label=`/`batch=` onto captured lines.
fn with_extra_tag(line: &str, tag: &str) -> String {
    if let Some(rest) = line.strip_prefix('@') {
        match rest.split_once(' ') {
            Some((tags, body)) => format!("@{tags};{tag} {body}"),
            None => format!("@{rest};{tag}"),
        }
    } else {
        format!("@{tag} {line}")
    }
}

pub struct Ircd {
    server: Server,
    commands: HashMap<&'static str, Box<dyn Command>>,
    modules: Vec<Box<dyn Module>>,
}

impl Ircd {
    pub fn new(
        cfg: Config,
        event_tx: Sender<Event>,
        conn_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Ircd {
        let mut server = Server::new(cfg, event_tx, conn_counter);
        server.load_xlines(); // restore persisted bans (m_xline_db)
        Ircd {
            server,
            commands: command_table(),
            modules: crate::modules::default_modules(),
        }
    }

    /// Run until the event channel closes (i.e. the listener is gone).
    pub fn run(mut self, rx: Receiver<Event>) {
        for ev in rx {
            match ev {
                Event::Connect {
                    uid,
                    addr,
                    out,
                    sock,
                    secure,
                    certfp,
                    link,
                    outbound,
                } => {
                    if link {
                        self.server.add_link(uid, addr, out, sock, outbound);
                    } else {
                        self.server.add_conn(uid, addr, out, sock, secure, certfp);
                    }
                }
                Event::Line { uid, line } => {
                    if self.server.links.contains_key(&uid) {
                        if let Some(msg) = message::parse(&line) {
                            self.server.on_link(uid, &msg);
                        }
                    } else {
                        self.on_line(uid, &line);
                    }
                }
                Event::Disconnect { uid } => {
                    if self.server.links.contains_key(&uid) {
                        self.server.close_link(uid, "Connection closed");
                    } else {
                        self.quit_user(uid, "Connection closed");
                    }
                }
                Event::ResolvedHost { uid, host, dnsbl } => {
                    self.server.on_resolved(uid, host, dnsbl);
                    // now that the notice block has printed, replay the handshake
                    // lines we held while resolving
                    for line in self.server.take_deferred(uid) {
                        if !self.server.users.contains_key(&uid) {
                            break; // a replayed QUIT/ban already dropped them
                        }
                        self.on_line(uid, &line);
                    }
                    self.try_register(uid); // DNS may have been the last thing we waited on
                }
                Event::Tick => self.on_tick(),
            }
            self.drain_hooks();
        }
    }

    fn on_line(&mut self, uid: Uid, line: &str) {
        let Some(msg) = message::parse(line) else {
            return;
        };
        // stash this line's client-only tags for TAGMSG / PRIVMSG relay
        self.server.line_ctags = msg.ctags.clone();
        // any valid line means the connection is alive
        if let Some(u) = self.server.users.get_mut(&uid) {
            u.last_active = crate::server::now();
            u.ping_sent = false;
        }
        let registered = self
            .server
            .users
            .get(&uid)
            .map(|u| u.registered)
            .unwrap_or(false);

        // Hold the handshake while the connect-time DNS/DNSBL lookups run, so the
        // "*** ..." notices print as one block; replayed in Event::ResolvedHost.
        if !registered && self.server.defer_if_resolving(uid, line) {
            return;
        }

        // labeled-response: if the client tagged this command with `label` and
        // negotiated the cap, capture its own replies and wrap them with the label.
        let label = msg.label.clone().filter(|_| {
            self.server
                .users
                .get(&uid)
                .map(|u| u.caps.labeled_response)
                .unwrap_or(false)
        });
        if let Some(label) = label {
            *self.server.label_capture.borrow_mut() = Some((uid, Vec::new()));
            self.dispatch(uid, &msg, registered);
            let lines = self
                .server
                .label_capture
                .borrow_mut()
                .take()
                .map(|(_, l)| l)
                .unwrap_or_default();
            self.emit_labeled(uid, &label, lines);
        } else {
            self.dispatch(uid, &msg, registered);
        }
    }

    /// Run one parsed command: module gates, handler dispatch, post-hooks, and the
    /// registration/quit follow-ups. Output goes through `Server::send`, so it's
    /// transparently captured when a labeled command wraps this call.
    fn dispatch(&mut self, uid: Uid, msg: &message::Message, registered: bool) {
        let cmd = msg.command.as_str();
        // SHUN: a shunned user stays connected but their commands are silently
        // dropped — except keepalive and quit, so they still time out cleanly.
        if registered && !matches!(cmd, "PING" | "PONG" | "QUIT") && self.server.user_shunned(uid) {
            return;
        }
        // draft/multiline: a PRIVMSG/NOTICE tagged for an open batch is buffered,
        // not delivered on its own — it's assembled and sent when the BATCH closes.
        if let Some(bref) = &msg.batch {
            if matches!(cmd, "PRIVMSG" | "NOTICE") && msg.params.len() >= 2 {
                let consumed = crate::modules::multiline::accumulate(
                    &mut self.server,
                    uid,
                    bref,
                    cmd == "NOTICE",
                    &msg.params[1],
                    msg.concat,
                );
                if consumed {
                    return;
                }
            }
        }
        // module pre-command gate
        for m in &mut self.modules {
            if m.on_pre_command(&mut self.server, uid, cmd, &msg.params) == ModResult::Deny {
                return;
            }
        }
        // message pre-hook (PRIVMSG/NOTICE)
        if matches!(cmd, "PRIVMSG" | "NOTICE") && msg.params.len() >= 2 {
            let (target, text) = (msg.params[0].clone(), msg.params[1].clone());
            for m in &mut self.modules {
                if m.on_pre_message(&mut self.server, uid, &target, &text) == ModResult::Deny {
                    return;
                }
            }
        }

        let Some(handler) = self.commands.get(cmd) else {
            if registered {
                self.server
                    .numeric(uid, ERR_UNKNOWNCOMMAND, &format!("{cmd} :Unknown command"));
            }
            return;
        };
        if !registered && !handler.before_reg() {
            self.server
                .numeric(uid, ERR_NOTREGISTERED, ":You have not registered");
            return;
        }
        if msg.params.len() < handler.min_params() {
            self.server.numeric(
                uid,
                ERR_NEEDMOREPARAMS,
                &format!("{cmd} :Not enough parameters"),
            );
            return;
        }
        let _ = handler.handle(&mut self.server, uid, &msg.params);

        for m in &mut self.modules {
            m.on_post_command(&mut self.server, uid, cmd);
        }

        // a command may have asked to quit (QUIT)
        if let Some(reason) = self.server.take_quit(uid) {
            self.quit_user(uid, &reason);
            return;
        }
        // …or completed the registration handshake
        if !registered {
            self.try_register(uid);
        }
    }

    /// Emit a labeled command's captured replies (labeled-response): `ACK` if it
    /// produced none, the single line label-tagged if one, else a `BATCH`-wrapped
    /// group. Runs after the capture is taken, so these go straight to the wire.
    fn emit_labeled(&mut self, uid: Uid, label: &str, lines: Vec<String>) {
        let server = self.server.name.clone();
        match lines.len() {
            0 => self
                .server
                .send(uid, format!("@label={label} :{server} ACK")),
            1 => {
                let l = with_extra_tag(&lines[0], &format!("label={label}"));
                self.server.send(uid, l);
            }
            _ => {
                let bref = self.server.next_msgid().replace('-', ""); // batch ref: alnum only
                self.server.send(
                    uid,
                    format!("@label={label} :{server} BATCH +{bref} labeled-response"),
                );
                for l in lines {
                    self.server
                        .send(uid, with_extra_tag(&l, &format!("batch={bref}")));
                }
                self.server.send(uid, format!(":{server} BATCH -{bref}"));
            }
        }
    }

    /// Finish registration if NICK, USER, CAP and the reverse-DNS lookup are all
    /// done. Called after each command and when a DNS result arrives.
    fn try_register(&mut self, uid: Uid) {
        let ready = self
            .server
            .users
            .get(&uid)
            .map(|u| {
                !u.registered
                    && !u.nick.is_empty()
                    && !u.ident.is_empty()
                    && !u.cap
                    && !u.dns_pending
            })
            .unwrap_or(false);
        if ready {
            self.complete_registration(uid);
        }
    }

    fn complete_registration(&mut self, uid: Uid) {
        for m in &mut self.modules {
            if m.on_user_register(&mut self.server, uid) == ModResult::Deny {
                self.server.send(
                    uid,
                    "ERROR :Closing link (registration refused)".to_string(),
                );
                self.server.remove_user(uid, "Registration refused");
                return;
            }
        }
        // x-line: refuse a banned host / ip before welcoming
        let (ident, host, ip) = {
            let u = &self.server.users[&uid];
            (u.ident.clone(), u.host.clone(), u.addr.ip().to_string())
        };
        if let Some(reason) = self.server.matched_xline(&ident, &host, &ip) {
            self.server
                .send(uid, format!("ERROR :Closing link: ({reason})"));
            self.server.remove_user(uid, &reason);
            return;
        }
        self.server.welcome(uid);
    }

    fn quit_user(&mut self, uid: Uid, reason: &str) {
        if !self.server.users.contains_key(&uid) {
            return;
        }
        let registered = self.server.users[&uid].registered;
        if registered {
            // fire the quit hook while the user still exists
            for m in &mut self.modules {
                m.on_user_quit(&mut self.server, uid, reason);
            }
        }
        self.server.remove_user(uid, reason);
    }

    /// Background timer: PING idle clients, reap the unresponsive and the
    /// never-registered.
    fn on_tick(&mut self) {
        self.server.ping_links(); // keepalive on every server link
        self.server.purge_xlines(); // drop expired server bans
        self.server.purge_tbans(); // lift expired timed channel bans (TBAN)
        let now = crate::server::now();
        let (to_ping, to_quit) = self.server.idle_check(now);
        for uid in to_ping {
            let token = self.server.name.clone();
            self.server.send(uid, format!("PING :{token}"));
            if let Some(u) = self.server.users.get_mut(&uid) {
                u.ping_sent = true;
            }
        }
        for uid in to_quit {
            let reg = self
                .server
                .users
                .get(&uid)
                .map(|u| u.registered)
                .unwrap_or(false);
            let reason = if reg {
                "Ping timeout"
            } else {
                "Registration timeout"
            };
            self.server
                .send(uid, format!("ERROR :Closing link: ({reason})"));
            self.quit_user(uid, reason);
        }
    }

    /// Fire queued notify-hooks. Draining a queue (not iterating in place) lets a
    /// hook enqueue more work (e.g. a module forcing a join) without surprises.
    fn drain_hooks(&mut self) {
        while let Some(hook) = self.server.events.pop_front() {
            match hook {
                Hook::Connect(uid) => {
                    for m in &mut self.modules {
                        m.on_user_connect(&mut self.server, uid);
                    }
                    // burst to links after modules (so the cloak is already set)
                    self.server.introduce_to_links(uid);
                }
                Hook::Join(uid, chan) => {
                    for m in &mut self.modules {
                        m.on_join(&mut self.server, uid, &chan);
                    }
                }
                Hook::Part(uid, chan, reason) => {
                    for m in &mut self.modules {
                        m.on_part(&mut self.server, uid, &chan, &reason);
                    }
                }
                Hook::Quit(uid, reason) => {
                    for m in &mut self.modules {
                        m.on_user_quit(&mut self.server, uid, &reason);
                    }
                }
            }
        }
    }
}
