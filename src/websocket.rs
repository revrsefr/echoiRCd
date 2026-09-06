//! WebSocket transport (RFC 6455) — lets browser IRC clients connect straight to
//! echoIRCd, no bridge. It's a transport, not a pluggable module, so it lives
//! beside `tls.rs`/`http.rs` at the I/O edge: a thread-per-connection listener
//! that does the HTTP Upgrade handshake, then frames the IRC byte stream in and
//! out of WebSocket frames. One thread owns each socket (like the TLS path) so
//! frames never interleave. SHA-1 + base64 for the accept key come from OpenSSL.
//!
//! Config (flat keys):
//!   bind_ws              = 127.0.0.1:8097   plaintext ws:// listener
//!   bind_wss             = 0.0.0.0:7799     wss:// listener (uses tls_cert/tls_key)
//!   ws_origin            = https://x.example (repeatable) allowed Origin globs; empty = any
//!   ws_handshake_timeout = 10               seconds to finish the TLS + Upgrade handshake
//!   ws_ping_interval     = 60               seconds between server keepalive pings (0 = off)
//!   ws_timeout           = 120              seconds with no traffic before we drop it
//!   ws_defaultmode       = text             frame mode with no subprotocol: text|binary|reject
//!   ws_proxyranges       = 127.0.0.1        (repeatable) glob/CIDR of proxies to trust
//!                                           X-Real-IP / X-Forwarded-For from
//!   ws_allowmissingorigin = yes             allow clients that send no Origin header
//!   ws_nativeping        = yes              liveness via WebSocket pings (no ⇒ IRC PING)
//!   ws_trust_proxy       = no               legacy: trust proxy headers from any peer

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::channels::glob_match;
use crate::config::Config;
use crate::ircd::Event;
use crate::socketengine::OutSink;
use crate::tls::{OpensslBackend, TlsBackend, TlsConn};
use crate::Uid;

/// The RFC 6455 handshake GUID appended to the client key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest single WebSocket frame payload we'll accept (flood guard).
const MAX_FRAME: usize = 128 * 1024;
/// Largest reassembled message before we drop the connection.
const MAX_MSG: usize = 256 * 1024;
/// How long a session blocks on a read before draining writes / doing keepalive.
const POLL: Duration = Duration::from_millis(100);

// opcodes
const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BIN: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The frame mode used when a client negotiates no IRCv3 subprotocol.
#[derive(Clone, Copy, PartialEq)]
enum DefaultMode {
    Text,
    Binary,
    Reject,
}

/// Tunables read once from the config.
#[derive(Clone)]
pub struct WsConfig {
    origins: Vec<String>,
    handshake_timeout: Duration,
    ping_interval: Duration,
    idle_timeout: Duration,
    trust_proxy: bool,             // legacy: trust proxy headers from any peer
    proxyranges: Vec<String>,      // glob/CIDR of proxies whose headers we trust
    default_mode: DefaultMode,     // frame mode when no subprotocol is negotiated
    allow_missing_origin: bool,    // accept clients that send no Origin header
    native_ping: bool,             // ping via WebSocket frames (else rely on IRC PING)
}

/// A stream the WS session can drive — implemented for a plaintext `TcpStream`
/// (`ws://`) and a TLS connection (`wss://`), so one session loop serves both.
pub trait WsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn shutdown(&mut self);
}

impl WsStream for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(self, buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Write::write_all(self, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Write::flush(self)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
    fn shutdown(&mut self) {
        let _ = TcpStream::shutdown(self, Shutdown::Both);
    }
}

impl WsStream for Box<dyn TlsConn> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        (**self).write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (**self).flush()
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(dur)
    }
    fn shutdown(&mut self) {
        (**self).shutdown()
    }
}

/// `Sec-WebSocket-Accept` = base64(SHA1(key + GUID)).
pub fn accept_key(client_key: &str) -> String {
    let digest = openssl::hash::hash(
        openssl::hash::MessageDigest::sha1(),
        format!("{client_key}{GUID}").as_bytes(),
    )
    .map(|d| d.to_vec())
    .unwrap_or_default();
    openssl::base64::encode_block(&digest)
}

/// Start the ws:// and/or wss:// listeners if configured. Called from `main`.
pub fn maybe_start(
    cfg: &Config,
    core: Sender<Event>,
    counter: Arc<AtomicU64>,
    inherited: &mut Vec<(String, TcpListener)>,
    reg: &Arc<std::sync::Mutex<Vec<(&'static str, std::os::fd::RawFd)>>>,
) {
    let get = |k: &str| cfg.raw.get(k).and_then(|v| v.last()).map(|s| s.as_str());
    let dur = |k: &str, d: u64| {
        get(k)
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(d))
    };
    let default_mode = match get("ws_defaultmode").map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("binary") => DefaultMode::Binary,
        Some("reject") => DefaultMode::Reject,
        _ => DefaultMode::Text,
    };
    let wscfg = WsConfig {
        origins: cfg.raw.get("ws_origin").cloned().unwrap_or_default(),
        handshake_timeout: dur("ws_handshake_timeout", 10),
        ping_interval: dur("ws_ping_interval", 60),
        idle_timeout: dur("ws_timeout", 120),
        trust_proxy: get("ws_trust_proxy")
            .map(crate::config::yesish)
            .unwrap_or(false),
        proxyranges: cfg.raw.get("ws_proxyranges").cloned().unwrap_or_default(),
        default_mode,
        allow_missing_origin: get("ws_allowmissingorigin")
            .map(crate::config::yesish)
            .unwrap_or(true),
        native_ping: get("ws_nativeping").map(crate::config::yesish).unwrap_or(true),
    };

    if let Some(bind) = get("bind_ws") {
        let mut ws_listeners = crate::upgrade::take(inherited, "ws");
        if ws_listeners.is_empty() {
            match TcpListener::bind(bind) {
                Ok(l) => {
                    eprintln!("echoircd WebSocket (ws) on {bind}");
                    ws_listeners.push(l);
                }
                Err(e) => eprintln!("echoircd: cannot bind ws {bind}: {e}"),
            }
        } else {
            eprintln!(
                "echoircd: adopted {} ws listener(s) across the upgrade",
                ws_listeners.len()
            );
        }
        for l in ws_listeners {
            if let Ok(mut r) = reg.lock() {
                r.push(("ws", std::os::fd::AsRawFd::as_raw_fd(&l)));
            }
            let (c, n, w) = (core.clone(), counter.clone(), wscfg.clone());
            thread::spawn(move || accept_ws(l, c, n, None, w));
        }
    }

    if let Some(bind) = get("bind_wss") {
        match (get("tls_cert"), get("tls_key")) {
            (Some(cert), Some(key)) => match OpensslBackend::new(cert, key, Vec::new()) {
                Ok(backend) => {
                    let backend: Arc<dyn TlsBackend> = Arc::new(backend);
                    let mut wss_listeners = crate::upgrade::take(inherited, "wss");
                    if wss_listeners.is_empty() {
                        match TcpListener::bind(bind) {
                            Ok(l) => {
                                eprintln!("echoircd WebSocket (wss) on {bind} (openssl)");
                                wss_listeners.push(l);
                            }
                            Err(e) => eprintln!("echoircd: cannot bind wss {bind}: {e}"),
                        }
                    } else {
                        eprintln!(
                            "echoircd: adopted {} wss listener(s) across the upgrade",
                            wss_listeners.len()
                        );
                    }
                    for l in wss_listeners {
                        if let Ok(mut r) = reg.lock() {
                            r.push(("wss", std::os::fd::AsRawFd::as_raw_fd(&l)));
                        }
                        let (c, n, w) = (core.clone(), counter.clone(), wscfg.clone());
                        let backend = backend.clone();
                        thread::spawn(move || accept_ws(l, c, n, Some(backend), w));
                    }
                }
                Err(e) => eprintln!("echoircd: wss disabled (cert/key error): {e}"),
            },
            _ => eprintln!("echoircd: bind_wss set but tls_cert/tls_key missing — wss OFF"),
        }
    }
}

/// Accept forever; one thread per connection.
fn accept_ws(
    listener: TcpListener,
    core: Sender<Event>,
    counter: Arc<AtomicU64>,
    tls: Option<Arc<dyn TlsBackend>>,
    cfg: WsConfig,
) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Ok(addr) = stream.peer_addr() else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let uid = counter.fetch_add(1, Ordering::Relaxed);
        let (core, tls, cfg) = (core.clone(), tls.clone(), cfg.clone());
        thread::spawn(move || ws_conn(stream, uid, addr, core, tls, cfg));
    }
}

/// Per-connection entry: wrap in TLS for wss, keep a raw handle for force-close,
/// then run the generic session.
fn ws_conn(
    raw: TcpStream,
    uid: Uid,
    addr: SocketAddr,
    core: Sender<Event>,
    tls: Option<Arc<dyn TlsBackend>>,
    cfg: WsConfig,
) {
    let Ok(shutdown) = raw.try_clone() else {
        return;
    };
    match tls {
        Some(backend) => {
            // Bound the blocking wss TLS handshake both ways — otherwise a peer that
            // stalls it pins this thread + socket forever (no uid yet). Clear the write
            // deadline (same socket via `shutdown`) once the handshake completes; the
            // HTTP-upgrade read deadline is set in ws_session.
            let _ = raw.set_read_timeout(Some(cfg.handshake_timeout));
            let _ = raw.set_write_timeout(Some(cfg.handshake_timeout));
            match backend.accept(raw) {
                Ok(conn) => {
                    let _ = shutdown.set_write_timeout(None);
                    ws_session(conn, uid, addr, true, core, shutdown, cfg);
                }
                Err(_) => {
                    let _ = shutdown.shutdown(Shutdown::Both);
                }
            }
        }
        None => ws_session(raw, uid, addr, false, core, shutdown, cfg),
    }
}

/// The result of a successful handshake.
struct Handshake {
    real_ip: Option<IpAddr>,
    secure: bool,
    binary: bool,
}

/// Drive one WebSocket connection: handshake, then frame IRC lines both ways until
/// close/EOF/idle-timeout or the core drops us.
fn ws_session<S: WsStream>(
    mut stream: S,
    uid: Uid,
    addr: SocketAddr,
    tls_secure: bool,
    core: Sender<Event>,
    shutdown: TcpStream,
    cfg: WsConfig,
) {
    // An IPv4 client on the dual-stack [::] wss listener arrives v4-mapped
    // (::ffff:1.2.3.4); collapse it so the proxy-range trust check and the fallback
    // client IP match what the plaintext/TLS listeners already normalize to. Without
    // this a reverse proxy on 127.0.0.1 shows up as ::ffff:127.0.0.1, fails the
    // ws_proxyranges match, and every web user inherits the proxy's loopback IP.
    let addr = crate::socketengine::normalize_addr(addr);
    // --- HTTP Upgrade handshake (bounded by the handshake timeout) ---
    let _ = stream.set_read_timeout(Some(cfg.handshake_timeout));
    let hs = match do_handshake(&mut stream, &cfg, addr.ip()) {
        Ok(h) => h,
        Err(_) => {
            let _ = shutdown.shutdown(Shutdown::Both);
            return;
        }
    };
    let real_addr = hs
        .real_ip
        .map(|ip| SocketAddr::new(ip, addr.port()))
        .unwrap_or(addr);
    let secure = tls_secure || hs.secure;
    let send_opcode = if hs.binary { OP_BIN } else { OP_TEXT };
    let local_port = shutdown.local_addr().map(|a| a.port()).unwrap_or(0);

    let (out_tx, out_rx) = std::sync::mpsc::channel::<String>();
    if core
        .send(Event::Connect {
            uid,
            addr: real_addr,
            out: OutSink::Thread(out_tx),
            sock: Some(shutdown),
            secure,
            certfp: None,
            tls_info: None,
            sni: None,
            local_port,
            link: false,
            outbound: false,
            websocket: true,
        })
        .is_err()
    {
        stream.shutdown();
        return;
    }

    // --- framed I/O loop (one thread, poll-read + drain-writes, like TLS) ---
    let _ = stream.set_read_timeout(Some(POLL));
    io_loop(&mut stream, uid, &core, &out_rx, &cfg, send_opcode);

    // best-effort close handshake, then tell the core we're gone
    let _ = stream.write_all(&encode(OP_CLOSE, &[]));
    stream.shutdown();
    let _ = core.send(Event::Disconnect { uid });
}

/// The read/deframe + write/frame loop. Returns when the connection should end.
fn io_loop<S: WsStream>(
    stream: &mut S,
    uid: Uid,
    core: &Sender<Event>,
    out_rx: &Receiver<String>,
    cfg: &WsConfig,
    send_opcode: u8,
) {
    let mut acc: Vec<u8> = Vec::new(); // raw bytes awaiting a full frame
    let mut msg: Vec<u8> = Vec::new(); // reassembled data message
    let mut chunk = [0u8; 8192];
    let mut last_rx = Instant::now();
    let mut last_ping = Instant::now();

    loop {
        // 1) read
        match stream.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                last_rx = Instant::now();
                acc.extend_from_slice(&chunk[..n]);
                loop {
                    match parse_frame(&acc) {
                        Ok(Some((frame, consumed))) => {
                            acc.drain(..consumed);
                            match frame.opcode {
                                // RFC 6455 §5.5: control frames must be ≤125 bytes and
                                // never fragmented — drop the connection otherwise
                                OP_CLOSE | OP_PING | OP_PONG
                                    if !frame.fin || frame.payload.len() > 125 =>
                                {
                                    return
                                }
                                OP_CLOSE => return,
                                OP_PING => {
                                    let _ = stream.write_all(&encode(OP_PONG, &frame.payload));
                                }
                                OP_PONG => {}
                                OP_TEXT | OP_BIN => {
                                    msg = frame.payload;
                                    if frame.fin && !deliver(&mut msg, uid, core) {
                                        return;
                                    }
                                }
                                OP_CONT => {
                                    msg.extend_from_slice(&frame.payload);
                                    if msg.len() > MAX_MSG {
                                        return;
                                    }
                                    if frame.fin && !deliver(&mut msg, uid, core) {
                                        return;
                                    }
                                }
                                _ => return, // unknown opcode
                            }
                        }
                        Ok(None) => break, // need more bytes
                        Err(()) => return, // protocol violation
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }

        // 2) drain queued output → frames
        loop {
            match out_rx.try_recv() {
                Ok(line) => {
                    let mut payload = line.into_bytes();
                    payload.extend_from_slice(b"\r\n");
                    if stream.write_all(&encode(send_opcode, &payload)).is_err() {
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return, // core removed us
            }
        }
        let _ = stream.flush();

        // 3) keepalive + idle timeout — WS-native pinging. With ws_nativeping=no the
        //    IRC core's PING / ping-timeout drives liveness instead, so the WS layer
        //    neither pings nor idle-drops.
        if cfg.native_ping {
            if cfg.ping_interval > Duration::ZERO && last_ping.elapsed() >= cfg.ping_interval {
                last_ping = Instant::now();
                if stream.write_all(&encode(OP_PING, b"echo")).is_err() {
                    return;
                }
            }
            if last_rx.elapsed() >= cfg.idle_timeout {
                return; // dead connection
            }
        }
    }
}

/// Split a completed data message into IRC lines and forward them; returns false if
/// the core has gone away. Clears `msg`.
fn deliver(msg: &mut Vec<u8>, uid: Uid, core: &Sender<Event>) -> bool {
    let text = String::from_utf8_lossy(msg);
    for piece in text.split('\n') {
        let l = piece.trim_end_matches('\r');
        // a WS frame can be far larger than a legal IRC line; drop an over-long
        // line so the transport can't bypass the recvq/max-line flood guard that
        // every TCP/TLS client is held to (16 KiB is generous — tags included)
        if l.len() > 16 * 1024 {
            continue;
        }
        if !l.is_empty()
            && core
                .send(Event::Line {
                    uid,
                    line: l.to_string(),
                })
                .is_err()
        {
            msg.clear();
            return false;
        }
    }
    msg.clear();
    true
}

/// One decoded WebSocket frame (payload already unmasked).
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Parse one frame from the front of `buf`, returning it plus the bytes consumed.
/// `Ok(None)` = need more bytes; `Err(())` = protocol violation (caller closes).
/// Client frames must be masked.
fn parse_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, ()> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    let masked = b1 & 0x80 != 0;
    if !masked {
        return Err(()); // RFC 6455 §5.1: client→server frames MUST be masked
    }
    let len7 = (b1 & 0x7F) as usize;
    let mut idx = 2;
    let payload_len = match len7 {
        126 => {
            if buf.len() < idx + 2 {
                return Ok(None);
            }
            let l = u16::from_be_bytes([buf[idx], buf[idx + 1]]) as usize;
            idx += 2;
            l
        }
        127 => {
            if buf.len() < idx + 8 {
                return Ok(None);
            }
            let mut a = [0u8; 8];
            a.copy_from_slice(&buf[idx..idx + 8]);
            idx += 8;
            u64::from_be_bytes(a) as usize
        }
        n => n,
    };
    if payload_len > MAX_FRAME {
        return Err(());
    }
    if buf.len() < idx + 4 + payload_len {
        return Ok(None); // mask key (4) + payload not fully arrived
    }
    let mask = [buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]];
    idx += 4;
    let mut payload = buf[idx..idx + payload_len].to_vec();
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok(Some((
        Frame {
            fin,
            opcode,
            payload,
        },
        idx + payload_len,
    )))
}

/// Encode a server frame (FIN set, never masked).
fn encode(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode);
    let n = payload.len();
    if n < 126 {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Read and validate the HTTP Upgrade request, then write the 101 response. `peer`
/// is the socket's remote IP, matched against `proxyranges` to decide whether the
/// X-Real-IP / X-Forwarded-* headers may be trusted.
fn do_handshake<S: WsStream>(stream: &mut S, cfg: &WsConfig, peer: IpAddr) -> io::Result<Handshake> {
    // read headers (bounded)
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > 16 * 1024 {
            return Err(io::Error::other("headers too large"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::other("eof in handshake"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let first = head.lines().next().unwrap_or("");
    if !first
        .split_whitespace()
        .next()
        .is_some_and(|m| m.eq_ignore_ascii_case("GET"))
    {
        return Err(io::Error::other("not a GET"));
    }
    let hdr = |name: &str| header(&head, name);
    if !hdr("upgrade").is_some_and(|v| v.to_ascii_lowercase().contains("websocket"))
        || !hdr("connection").is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"))
    {
        return Err(io::Error::other("missing upgrade"));
    }
    let key = hdr("sec-websocket-key").ok_or_else(|| io::Error::other("no key"))?;

    // origin check (CSWSH guard): a present Origin must match a configured glob (if
    // any); a missing Origin is allowed unless ws_allowmissingorigin = no.
    match hdr("origin") {
        Some(origin) => {
            if !cfg.origins.is_empty() && !cfg.origins.iter().any(|g| glob_match(g, &origin)) {
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
                return Err(io::Error::other("origin rejected"));
            }
        }
        None => {
            if !cfg.allow_missing_origin {
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
                return Err(io::Error::other("missing origin"));
            }
        }
    }

    // subprotocol: prefer text.ircv3.net, accept binary.ircv3.net; with neither,
    // fall back to ws_defaultmode (and reject the handshake if that is "reject").
    let offered = hdr("sec-websocket-protocol")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let (chosen, binary) = if offered.split(',').any(|p| p.trim() == "text.ircv3.net") {
        (Some("text.ircv3.net"), false)
    } else if offered.split(',').any(|p| p.trim() == "binary.ircv3.net") {
        (Some("binary.ircv3.net"), true)
    } else {
        match cfg.default_mode {
            DefaultMode::Text => (None, false),
            DefaultMode::Binary => (None, true),
            DefaultMode::Reject => {
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                return Err(io::Error::other("no subprotocol (reject mode)"));
            }
        }
    };

    // real IP / scheme from a trusted reverse proxy: trust the headers only when the
    // peer matches a configured proxyrange (glob/CIDR), or the legacy trust_proxy is on
    let trusted = if cfg.proxyranges.is_empty() {
        cfg.trust_proxy
    } else {
        let ip = peer.to_string();
        cfg.proxyranges
            .iter()
            .any(|r| crate::modules::connclass::ip_matches(r, &ip))
    };
    let (mut real_ip, mut secure) = (None, false);
    if trusted {
        // X-Real-IP wins; else the first hop of X-Forwarded-For
        real_ip = hdr("x-real-ip")
            .and_then(|v| v.trim().parse().ok())
            .or_else(|| {
                hdr("x-forwarded-for")
                    .and_then(|xff| xff.split(',').next().and_then(|s| s.trim().parse().ok()))
            });
        secure = hdr("x-forwarded-proto").is_some_and(|v| v.eq_ignore_ascii_case("https"));
    }

    // 101 response
    let mut resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n",
        accept_key(key.trim())
    );
    if let Some(proto) = chosen {
        resp.push_str(&format!("Sec-WebSocket-Protocol: {proto}\r\n"));
    }
    resp.push_str("\r\n");
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(Handshake {
        real_ip,
        secure,
        binary,
    })
}

/// Case-insensitive header lookup from a raw HTTP header block.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Fuzz the WebSocket frame parser: arbitrary bytes must not panic, and a
        // decoded frame must never report consuming past the buffer.
        #[test]
        fn ws_parse_frame_never_panics_and_bounds(buf in prop::collection::vec(any::<u8>(), 0..600)) {
            if let Ok(Some((_f, n))) = parse_frame(&buf) {
                prop_assert!(n <= buf.len());
            }
        }
    }

    #[test]
    fn accept_key_matches_rfc_example() {
        // RFC 6455 §1.3 worked example
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn roundtrip_masked_text_frame() {
        // build a masked client TEXT frame carrying "NICK bob"
        let payload = b"NICK bob";
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let mut frame = vec![0x81, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        let (parsed, consumed) = parse_frame(&frame).unwrap().unwrap();
        assert!(
            parsed.fin
                && parsed.opcode == OP_TEXT
                && parsed.payload == payload
                && consumed == frame.len()
        );
    }

    #[test]
    fn unmasked_client_frame_is_rejected() {
        assert!(parse_frame(&[0x81, 0x03, b'a', b'b', b'c']).is_err());
    }

    #[test]
    fn partial_frame_needs_more() {
        assert!(parse_frame(&[0x81]).unwrap().is_none());
    }

    #[test]
    fn encode_sets_fin_and_length() {
        let f = encode(OP_TEXT, b"hi");
        assert_eq!(f, vec![0x81, 0x02, b'h', b'i']);
    }

    // A minimal WsStream that replays a canned HTTP upgrade request and swallows writes.
    struct MockStream {
        data: Vec<u8>,
        pos: usize,
    }
    impl WsStream for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
        fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) {}
    }

    #[test]
    fn proxied_ws_extracts_real_ip_from_trusted_loopback() {
        use std::net::{Ipv4Addr, SocketAddr};
        // the fix: an IPv4 client on the [::] wss listener reaches the proxy as
        // ::ffff:127.0.0.1 — it must collapse to 127.0.0.1 so ws_proxyranges matches.
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:9".parse().unwrap();
        assert_eq!(
            crate::socketengine::normalize_addr(mapped).ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "mapped loopback collapses to 127.0.0.1"
        );
        // with the normalized loopback peer, a trusted proxy's X-Real-IP wins over
        // the proxy's own address.
        let req = "GET /irc/ HTTP/1.1\r\nHost: orbit.devtronic.pro\r\nUpgrade: websocket\r\n\
                   Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\nOrigin: https://orbit.devtronic.pro\r\n\
                   Sec-WebSocket-Protocol: text.ircv3.net\r\n\
                   X-Real-IP: 203.0.113.77\r\nX-Forwarded-Proto: https\r\n\r\n";
        let mut s = MockStream { data: req.as_bytes().to_vec(), pos: 0 };
        let cfg = WsConfig {
            origins: vec!["https://orbit.devtronic.pro".into()],
            handshake_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(120),
            trust_proxy: false,
            proxyranges: vec!["127.0.0.1".into()],
            default_mode: DefaultMode::Text,
            allow_missing_origin: false,
            native_ping: true,
        };
        let hs = do_handshake(&mut s, &cfg, IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("handshake");
        assert_eq!(
            hs.real_ip,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))),
            "trusted loopback proxy -> real client IP, not the proxy's loopback"
        );
        assert!(hs.secure, "x-forwarded-proto https marks the session secure");
    }
}
