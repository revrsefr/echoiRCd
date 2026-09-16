//! The core: owns the [`Server`] state, the command table and the module list,
//! and turns a stream of [`Event`]s into IRC. Runs on one thread, so no state is
//! ever locked.

use crate::map::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::time::Instant;

use crate::command::Command;
use crate::config::Config;
use crate::coremods::command_table;
use crate::message;
use crate::module::{Hook, ModResult, Module};
use crate::numeric::{
    ERR_NEEDMOREPARAMS, ERR_NOTREGISTERED, ERR_PASSWDMISMATCH, ERR_UNKNOWNCOMMAND,
};
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
        certfp: Option<String>,   // TLS client-cert fingerprint (clients only)
        tls_info: Option<String>, // negotiated TLS version/group/cipher (WHOIS 671)
        sni: Option<String>,      // TLS SNI hostname the client used (per-SNI branding)
        local_port: u16,          // the listener port the client connected to
        link: bool,               // a server-to-server connection, not a client
        outbound: bool,           // (link) we dialed them
        websocket: bool,          // arrived over the WebSocket transport
    },
    Line {
        uid: Uid,
        line: String,
    },
    /// A client sent a line longer than we'll buffer; it was dropped at the I/O edge.
    /// The core answers ERR_INPUTTOOLONG (417) so the client knows to resend shorter.
    LineTooLong {
        uid: Uid,
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
    /// A client's ident (RFC 1413) lookup finished: the confirmed username, or
    /// `None` if the host gave no valid response (see `crate::modules::ident`).
    Ident {
        uid: Uid,
        ident: Option<String>,
    },
    /// A background OPER password verify finished. KDF hashes are deliberately slow,
    /// so they run on a worker thread (see `Server::spawn_crypto`), not on the core.
    OperAuth {
        uid: Uid,
        ok: bool,
        level: u32,
        oper_type: Option<String>,
    },
    /// A background MKPASSWD hash finished (KDFs run off the core thread).
    MkpasswdResult {
        uid: Uid,
        algo: String,
        hash: Option<String>,
    },
    /// A background `/TITLE` password verify finished (see `crate::modules::customtitle`).
    TitleAuth {
        uid: Uid,
        ok: bool,
        title: String,
        vhost: String,
    },
    /// A background connect-class password verify finished (see `crate::modules::connclass`);
    /// registration was held until now.
    ConnclassAuth {
        uid: Uid,
        ok: bool,
    },
    /// A module's async HTTP request finished. `tag` is `"<module>:<detail>"`
    /// so the core can route the reply back to the module that issued it (e.g.
    /// account registration, captcha verification). `status` is 0 on transport
    /// failure.
    HttpResult {
        uid: Uid,
        tag: String,
        status: u16,
        body: String,
    },
    /// An inbound JSON-RPC request from the HTTP control interface (see
    /// `crate::modules::rpc`). Handled inline on the core thread; the reply JSON is
    /// sent back to the waiting httpd thread over `reply`.
    RpcRequest {
        method: String,
        params: String,
        id: String,
        reply: std::sync::mpsc::Sender<String>,
    },
    /// A database query finished on a worker thread — deliver it to its callback.
    SqlResult {
        id: u64,
        result: crate::database::SqlResult,
    },
    /// A Redis command finished on a worker thread — deliver it to its callback.
    RedisResult {
        id: u64,
        result: crate::redis::RedisResult,
    },
    /// A message arrived on a persistent bridge worker (e.g. the XMPP client), to be
    /// injected into the IRC `channel` from `sender`. Keyed by channel so it survives
    /// a bridge reload (indices don't).
    BridgeIn {
        channel: String,
        sender: String,
        text: String,
    },
    /// Background timer tick — drives ping/idle timeouts.
    Tick,
    /// Re-read the config file and apply it live (from SIGHUP / the `rehash` CLI).
    Rehash,
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

/// A short human label for an event, appended to `out` (cleared by the caller). Used
/// by the slow-event snote and the [watchdog] warning so a stall names its culprit
/// (which command / connect / background result) rather than only a duration. Writes
/// in place, so it costs no allocation on the hot path once `out`'s buffer is warm.
fn write_event_label(ev: &Event, out: &mut String) {
    use std::fmt::Write;
    match ev {
        Event::Connect {
            addr,
            link,
            outbound,
            ..
        } => {
            if *link {
                let _ = write!(
                    out,
                    "server link ({})",
                    if *outbound { "outbound" } else { "inbound" }
                );
            } else {
                let _ = write!(out, "connect from {}", addr.ip());
            }
        }
        Event::Line { line, .. } => push_verb(line, out),
        Event::LineTooLong { .. } => out.push_str("line too long"),
        Event::Disconnect { .. } => out.push_str("disconnect"),
        Event::ResolvedHost { .. } => out.push_str("DNS/DNSBL result"),
        Event::Ident { .. } => out.push_str("ident result"),
        Event::OperAuth { .. } => out.push_str("OPER auth result"),
        Event::MkpasswdResult { .. } => out.push_str("MKPASSWD result"),
        Event::TitleAuth { .. } => out.push_str("TITLE auth result"),
        Event::ConnclassAuth { .. } => out.push_str("connect-class auth result"),
        Event::HttpResult { tag, .. } => {
            let _ = write!(out, "HTTP result [{tag}]");
        }
        Event::RpcRequest { method, .. } => {
            let _ = write!(out, "RPC {method}");
        }
        Event::SqlResult { .. } => out.push_str("SQL result"),
        Event::RedisResult { .. } => out.push_str("Redis result"),
        Event::BridgeIn { channel, .. } => {
            let _ = write!(out, "bridge message -> {channel}");
        }
        Event::Tick => out.push_str("tick (ping/idle sweep)"),
        Event::Rehash => out.push_str("rehash"),
    }
}

/// Append the IRC command verb of a raw client line (skipping IRCv3 `@tags` and any
/// `:prefix`), upper-cased and length-bounded so a malformed line can't bloat the label.
fn push_verb(line: &str, out: &mut String) {
    let mut s = line.trim_start();
    if let Some(rest) = s.strip_prefix('@') {
        s = rest.split_once(' ').map_or("", |(_, r)| r).trim_start();
    }
    if let Some(rest) = s.strip_prefix(':') {
        s = rest.split_once(' ').map_or("", |(_, r)| r).trim_start();
    }
    match s.split_whitespace().next() {
        Some(verb) => out.extend(verb.chars().take(24).flat_map(char::to_uppercase)),
        None => out.push_str("(empty line)"),
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
        event_tx: SyncSender<Event>,
        conn_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Ircd {
        let mut server = Server::new(cfg, event_tx, conn_counter);
        crate::database::init(&mut server); // DB pool + central store — before the loads below
        crate::redis::init(&mut server); // Redis pool (cache / counters / event bus) — inert unless redis_host set
        server.load_xlines(); // restore persisted bans
        crate::modules::metadata::load(&mut server); // restore channel metadata
        crate::modules::reputation::load(&mut server); // restore per-IP reputation
        crate::modules::permchannels::load(&mut server); // recreate +P channels (pre-link)
        crate::modules::markread::load(&mut server); // restore account-keyed read markers
        crate::modules::webpush::load(&mut server); // VAPID keypair + push subscriptions
        crate::modules::geoip::init(&mut server); // load the GeoIP database
        crate::modules::customprefix::init(&server); // load prefix config
        crate::mode::init_custom_prefixes(); // register any config-defined prefix modes
        Ircd {
            server,
            commands: command_table(),
            modules: crate::modules::default_modules(),
        }
    }

    /// Run until the event channel closes (i.e. the listener is gone). Each event is
    /// handled inside `catch_unwind`: a panic in one command's handler is logged and
    /// the loop carries on, instead of the panic taking the whole single-threaded
    /// server down with it. State touched before the panic may be left inconsistent,
    /// so this is a last-resort safety net, not a licence to panic — the untrusted
    /// parsers are still written so they can't panic in the first place.
    /// `busy` is a shared marker the watchdog thread samples: it holds the ms-since-
    /// `base` at which the current event started (0 = idle), so a stuck handler is
    /// visible from outside. Events slower than `slow_command_ms` are also snoticed.
    pub fn run(
        mut self,
        rx: Receiver<Event>,
        busy: Arc<AtomicU64>,
        base: Instant,
        label: Arc<std::sync::Mutex<String>>,
    ) {
        let slow_ms = self.server.conf_num("slow_command_ms", 200u64);
        for ev in rx {
            // record what this event is into the buffer the watchdog samples, so a
            // slow or stuck event names its culprit instead of just a duration. Writes
            // into the reused String — no per-event allocation once the buffer is warm.
            {
                let mut g = label.lock().unwrap_or_else(|e| e.into_inner());
                g.clear();
                write_event_label(&ev, &mut g);
            }
            busy.store(
                (base.elapsed().as_millis() as u64).max(1),
                Ordering::Relaxed,
            );
            let start = Instant::now();
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.handle_event(ev)))
                .is_err()
            {
                // the default panic hook already logged the details to stderr
                eprintln!("[core] recovered from a panicking event handler; continuing");
                // a panic mid-handler can leave transient per-command state set;
                // clear it so it doesn't corrupt the next command
                self.server.label_capture.borrow_mut().take();
                self.server.mode_sudo = false;
            }
            busy.store(0, Ordering::Relaxed);
            let ms = start.elapsed().as_millis() as u64;
            if slow_ms != 0 && ms >= slow_ms {
                let what = label.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let ms_s = ms.to_string();
                let m = self.server.trf(
                    "slow event: {0} took {1}ms on the core thread",
                    &[what.as_str(), ms_s.as_str()],
                );
                self.server.snotice(&m);
            }
        }
    }

    /// Dispatch one event, then drain any hooks it queued.
    fn handle_event(&mut self, ev: Event) {
        match ev {
            Event::Connect {
                uid,
                addr,
                out,
                sock,
                secure,
                certfp,
                tls_info,
                sni,
                local_port,
                link,
                outbound,
                websocket,
            } => {
                if link {
                    self.server.add_link(uid, addr, out, sock, outbound);
                } else {
                    self.server.add_conn(
                        uid, addr, out, sock, secure, certfp, tls_info, sni, local_port,
                    );
                    if websocket {
                        if let Some(u) = self.server.users.get_mut(&uid) {
                            u.flags.via_websocket = true;
                        }
                    }
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
            Event::LineTooLong { uid } => {
                // only clients get 417; links never overflow (we control their traffic)
                if !self.server.links.contains_key(&uid) {
                    self.server.numeric(
                        uid,
                        crate::numeric::ERR_INPUTTOOLONG,
                        ":Input line was too long",
                    );
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
            Event::Ident { uid, ident } => {
                crate::modules::ident::on_result(&mut self.server, uid, ident);
                self.try_register(uid); // ident may have been the last hold
            }
            Event::OperAuth {
                uid,
                ok,
                level,
                oper_type,
            } => {
                if ok {
                    self.server.oper_up(uid);
                    crate::modules::operlevels::set(&mut self.server, uid, level);
                    crate::modules::opertypes::apply(&mut self.server, uid, oper_type.as_deref());
                } else if self.server.users.contains_key(&uid) {
                    self.server
                        .numeric(uid, ERR_PASSWDMISMATCH, ":Password incorrect");
                }
            }
            Event::MkpasswdResult { uid, algo, hash } => {
                let nick = self
                    .server
                    .users
                    .get(&uid)
                    .map(|u| u.nick.clone())
                    .unwrap_or_default();
                let line = match hash {
                    Some(h) => {
                        let m = self
                            .server
                            .trf("{0} hashed password: {1}", &[algo.as_str(), h.as_str()]);
                        format!(":{} NOTICE {nick} :{m}", self.server.name)
                    }
                    None => {
                        let m = self
                            .server
                            .trf("Could not hash with '{0}'", &[algo.as_str()]);
                        format!(":{} NOTICE {nick} :{m}", self.server.name)
                    }
                };
                self.server.send(uid, line);
            }
            Event::TitleAuth {
                uid,
                ok,
                title,
                vhost,
            } => {
                if ok {
                    crate::modules::customtitle::grant(&mut self.server, uid, &title, &vhost);
                } else {
                    crate::modules::customtitle::deny(&self.server, uid);
                }
            }
            Event::ConnclassAuth { uid, ok } => {
                // registration was held pending this off-core class-password verify
                let held = self
                    .server
                    .users
                    .get_mut(&uid)
                    .map(|u| {
                        let was = u.auth_pending;
                        u.auth_pending = false;
                        was
                    })
                    .unwrap_or(false);
                if !held {
                    return; // user vanished (or wasn't actually waiting)
                }
                if ok {
                    crate::modules::connclass::finish_register(&mut self.server, uid);
                    self.server.welcome(uid);
                } else {
                    self.reject_link(uid, "Password mismatch for your connection class");
                }
            }
            Event::HttpResult {
                uid,
                tag,
                status,
                body,
            } => {
                if let Some(detail) = tag.strip_prefix("acctreg:") {
                    crate::modules::account_registration::on_http_result(
                        &mut self.server,
                        uid,
                        detail,
                        status,
                        &body,
                    );
                } else if let Some(detail) = tag.strip_prefix("bridge:") {
                    crate::modules::bridge::on_http_result(
                        &mut self.server,
                        uid,
                        detail,
                        status,
                        &body,
                    );
                }
            }
            Event::RpcRequest {
                method,
                params,
                id,
                reply,
            } => {
                let resp = crate::modules::rpc::dispatch(&mut self.server, &method, &params, &id);
                let _ = reply.send(resp);
                // a `verify.pass` push may have cleared held connections — complete
                // them now rather than waiting for the next tick.
                self.drain_verified_pending();
            }
            Event::SqlResult { id, result } => {
                crate::database::on_result(&mut self.server, id, result)
            }
            Event::RedisResult { id, result } => {
                crate::redis::on_result(&mut self.server, id, result)
            }
            Event::BridgeIn {
                channel,
                sender,
                text,
            } => crate::modules::bridge::on_bridge_in(&mut self.server, &channel, &sender, &text),
            Event::Tick => self.on_tick(),
            Event::Rehash => self.on_rehash(),
        }
        self.drain_hooks();
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
        // abbreviation: with `abbreviation = yes`, an unknown verb that is a unique
        // prefix of exactly one command resolves to it (e.g. WHOI -> WHOIS).
        let typed = msg.command.as_str();
        let cmd: &str = if self.commands.contains_key(typed)
            || !(registered && self.server.conf_bool("abbreviation", false))
        {
            typed
        } else {
            let mut it = self.commands.keys().filter(|k| k.starts_with(typed));
            match (it.next(), it.next()) {
                (Some(full), None) => full, // exactly one match
                _ => typed,                 // none or ambiguous
            }
        };
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
                // config `showfile = <CMD> <path>` streams a text file as its own
                // command (e.g. /RULES).
                if crate::modules::showfile::maybe_show(&mut self.server, uid, cmd) {
                    return;
                }
                // config `alias = <CMD> <target-nick>`: `alias = NS NickServ` makes
                // `/NS help` -> PRIVMSG NickServ :help
                if let Some(target) = self.server.conf_all("alias").iter().find_map(|line| {
                    let mut it = line.split_whitespace();
                    match (it.next(), it.next()) {
                        (Some(n), Some(t)) if n.eq_ignore_ascii_case(cmd) => Some(t.to_string()),
                        _ => None,
                    }
                }) {
                    if !msg.params.is_empty() {
                        let text = msg.params.join(" ");
                        crate::coremods::core_message::deliver(
                            &mut self.server,
                            uid,
                            &[target, text],
                            false,
                        );
                    }
                    return;
                }
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
        use std::sync::atomic::Ordering::Relaxed;
        self.server.metrics.commands.fetch_add(1, Relaxed);
        if matches!(cmd, "PRIVMSG" | "NOTICE") {
            self.server.metrics.messages.fetch_add(1, Relaxed);
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
                    && !u.ident_pending
                    && !u.auth_pending
                    && u.waitpong.is_none()
            })
            .unwrap_or(false);
        if ready {
            self.complete_registration(uid);
        }
    }

    fn complete_registration(&mut self, uid: Uid) {
        for m in &mut self.modules {
            match m.on_user_register(&mut self.server, uid) {
                ModResult::Deny => {
                    let m = self.server.trf("Closing link (registration refused)", &[]);
                    self.server.send(uid, format!("ERROR :{m}"));
                    self.server.remove_user(uid, "Registration refused");
                    return;
                }
                // a challenge is pending: keep the connection, don't welcome yet.
                // A later command (the CAPTCHA/VERIFYCHALLENGE reply) re-runs this.
                ModResult::Hold => return,
                _ => {}
            }
        }
        // x-line: refuse a banned host / ip before welcoming
        let (ident, host, ip) = {
            let u = &self.server.users[&uid];
            (u.ident.clone(), u.host.clone(), u.addr.ip().to_string())
        };
        if let Some(reason) = self.server.matched_xline(&ident, &host, &ip) {
            self.server.refuse_banned(uid, &reason);
            return;
        }
        // ident: apply a confirmed username (dropping `~`) and enforce requireident
        if let Some(reason) = crate::modules::ident::finalize(&mut self.server, uid) {
            let m = self.server.trf("Closing link: ({0})", &[reason.as_str()]);
            self.server.send(uid, format!("ERROR :{m}"));
            self.server.remove_user(uid, &reason);
            return;
        }
        // R-line: refuse a user whose nick!user@host realname matches a banned regex
        // (checked after ident is finalised so the matchtext is the real username).
        let rl = {
            let u = &self.server.users[&uid];
            self.server.matched_rline(
                &u.nick,
                &u.ident,
                &u.host,
                &u.addr.ip().to_string(),
                &u.realname,
            )
        };
        if let Some(reason) = rl {
            self.server.refuse_banned(uid, &reason);
            return;
        }
        // connectclass: verify the class password and apply its on-connect modes.
        // A KDF password verifies off-core: `Pending` holds registration until the
        // ConnclassAuth event lands, which then welcomes or rejects.
        match crate::modules::connclass::on_register(&mut self.server, uid) {
            crate::modules::connclass::AuthOutcome::Proceed => {}
            crate::modules::connclass::AuthOutcome::Pending => return,
            crate::modules::connclass::AuthOutcome::Reject(reason) => {
                self.reject_link(uid, &reason);
                return;
            }
        }
        self.server.welcome(uid);
    }

    /// Refuse a link at registration: numeric + ERROR line + drop the user.
    fn reject_link(&mut self, uid: Uid, reason: &str) {
        self.server
            .numeric(uid, ERR_PASSWDMISMATCH, &format!(":{reason}"));
        let m = self.server.trf("Closing link: ({0})", &[reason]);
        self.server.send(uid, format!("ERROR :{m}"));
        self.server.remove_user(uid, reason);
    }

    fn quit_user(&mut self, uid: Uid, reason: &str) {
        if !self.server.users.contains_key(&uid) {
            return;
        }
        // Fire the quit hook while the user still exists — for EVERY user, registered
        // or not. A client that disconnects mid-registration (e.g. a captcha bot held
        // before registration) still has per-uid module state to reclaim, and Uids are
        // never reused, so skipping this leaks one entry per such disconnect (which
        // scales with exactly the hostile traffic the captcha/challenge modules target).
        for m in &mut self.modules {
            m.on_user_quit(&mut self.server, uid, reason);
        }
        self.server.remove_user(uid, reason);
    }

    /// Background timer: PING idle clients, reap the unresponsive and the
    /// never-registered.
    /// SIGHUP / `rehash` CLI: re-read the config and apply it live, keeping the
    /// running config if the file can't be read (same policy as /REHASH).
    fn on_rehash(&mut self) {
        let path = self.server.conf_path.clone();
        eprintln!("rehashing server config file.");
        match Config::try_load(&path) {
            Some(fresh) => {
                self.server
                    .announce("The server is rehashing its configuration.");
                self.server.apply_config(fresh);
                crate::modules::connclass::rebuild(&mut self.server); // reconcile clone counters
                self.server.announce("Server configuration reloaded.");
                eprintln!("server configuration is reloaded.");
            }
            None => {
                eprintln!("rehash: could not read {path} — the running configuration was kept.");
            }
        }
    }

    /// Complete held connections whose IP was cleared out-of-band by the
    /// verification web page's `verify.pass` RPC push, and drop expired IP records.
    /// Called right after each RPC (near-instant completion) and from `on_tick`.
    fn drain_verified_pending(&mut self) {
        crate::modules::verify_common::purge(&mut self.server);
        let cleared = self
            .server
            .ext
            .get_mut::<crate::modules::verify_common::PendingComplete>()
            .map(|p| std::mem::take(&mut p.0))
            .unwrap_or_default();
        for uid in cleared {
            self.try_register(uid);
        }
    }

    fn on_tick(&mut self) {
        self.server.ping_links(); // keepalive on every server link
        for uid in self.server.dead_links(crate::server::now()) {
            self.server.close_link(uid, "Ping timeout"); // hung peer: silent past ping_freq+timeout
        }
        self.server.purge_xlines(); // drop expired server bans
        self.server.purge_tbans(); // lift expired timed channel bans (TBAN)
        self.server.purge_flood_state(); // reclaim per-member +f/+J state of departed users
        for m in &mut self.modules {
            m.on_tick(&mut self.server); // timer-driven modules (e.g. reputation)
        }
        // reconcile the unregistered-connection count + edge-detect flood mode
        crate::connguard::tick(&mut self.server);
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
            let m = self.server.trf("Closing link: ({0})", &[reason]);
            self.server.send(uid, format!("ERROR :{m}"));
            self.quit_user(uid, reason);
        }
        // backstop for the RPC-driven path below (purges expired IP records too).
        self.drain_verified_pending();
        // republish gauges (the core owns this state; the scrape thread only reads)
        use std::sync::atomic::Ordering::Relaxed;
        let m = &self.server.metrics;
        m.users.store(
            self.server.users.values().filter(|u| u.registered).count() as u64,
            Relaxed,
        );
        m.channels.store(self.server.channels.len() as u64, Relaxed);
        m.servers.store(self.server.servers.len() as u64, Relaxed);
        m.links.store(self.server.links.len() as u64, Relaxed);
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
