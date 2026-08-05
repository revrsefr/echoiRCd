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
use crate::Uid;

/// What the I/O threads hand to the core.
pub enum Event {
    Connect {
        uid: Uid,
        addr: SocketAddr,
        out: Sender<String>,
        sock: TcpStream,
        secure: bool,
        link: bool,     // a server-to-server connection, not a client
        outbound: bool, // (link) we dialed them
    },
    Line {
        uid: Uid,
        line: String,
    },
    Disconnect {
        uid: Uid,
    },
    /// Background timer tick — drives ping/idle timeouts.
    Tick,
}

pub struct Ircd {
    server: Server,
    commands: HashMap<&'static str, Box<dyn Command>>,
    modules: Vec<Box<dyn Module>>,
}

impl Ircd {
    pub fn new(cfg: Config) -> Ircd {
        Ircd {
            server: Server::new(cfg),
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
                    link,
                    outbound,
                } => {
                    if link {
                        self.server.add_link(uid, addr, out, sock, outbound);
                    } else {
                        self.server.add_conn(uid, addr, out, sock, secure);
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
        let cmd = msg.command.as_str();
        let registered = self
            .server
            .users
            .get(&uid)
            .map(|u| u.registered)
            .unwrap_or(false);

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
            let ready = self
                .server
                .users
                .get(&uid)
                .map(|u| !u.registered && !u.nick.is_empty() && !u.ident.is_empty() && !u.cap)
                .unwrap_or(false);
            if ready {
                self.complete_registration(uid);
            }
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
