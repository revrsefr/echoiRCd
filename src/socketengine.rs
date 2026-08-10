//! The socket engine: the I/O edge. Two coexisting models feed the one core:
//!
//! - **Client plaintext** connections run on a single **mio epoll reactor**
//!   ([`run_reactor`]) — one thread drives tens of thousands of sockets, so the
//!   daemon scales to ~50k users without a thread per connection. The core stays
//!   single-threaded and there is no async runtime.
//! - **TLS** and **server links** keep a thread per connection (few of them, and
//!   a TLS session can't be split across reader+writer threads).
//!
//! Both hand the core the same [`OutSink`] output handle, so the core never
//! knows or cares which model a connection uses.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mio::net::{TcpListener as MioListener, TcpStream as MioStream};
use mio::{Events, Interest, Poll, Token, Waker};

use crate::ircd::Event;
use crate::tls::TlsBackend;
use crate::Uid;

/// Default recvq: longest single line we'll buffer before dropping it. Overridable
/// globally (`max_line`) and per connection class (`recvq`).
pub const DEFAULT_MAX_LINE: usize = 16 * 1024;
/// Default hardsendq: most bytes we'll queue to a slow client before dropping them
/// and closing. Overridable globally (`max_sendq`) and per class (`hardsendq`).
pub const DEFAULT_MAX_SENDQ: usize = 1 << 20; // 1 MiB
/// How long a TLS thread blocks on a read before draining its write queue.
const TLS_POLL: Duration = Duration::from_millis(100);

/// A queued output action the core hands the reactor: a line to write to a
/// connection, a request to flush-then-close it (sent when the core drops the
/// [`OutSink`], e.g. on quit), or a per-connection queue-limit override (from the
/// assigned connection class).
pub enum Out {
    Line(usize, String),
    Close(usize),
    Limits {
        token: usize,
        recvq: Option<usize>,
        hardsendq: Option<usize>,
        softsendq: Option<usize>,
    },
}

/// The core's handle to one connection's output. Thread-model connections (TLS,
/// server links) get a plain channel to their writer thread; reactor connections
/// (plaintext clients) get a token plus the shared reactor channel and its waker.
/// Either way the core just calls [`OutSink::send`].
pub enum OutSink {
    Thread(Sender<String>),
    Reactor {
        token: usize,
        tx: Sender<Out>,
        waker: Arc<Waker>,
    },
}

impl OutSink {
    /// Queue one line for delivery (the writer appends CRLF).
    pub fn send(&self, line: String) {
        match self {
            OutSink::Thread(s) => {
                let _ = s.send(line);
            }
            OutSink::Reactor { token, tx, waker } => {
                if tx.send(Out::Line(*token, line)).is_ok() {
                    let _ = waker.wake(); // wakes coalesce: many sends → one epoll wakeup
                }
            }
        }
    }

    /// Override this connection's queue limits (from its connection class). Only the
    /// reactor (plaintext client) model honours these; thread-model connections (TLS,
    /// links) use the global defaults.
    pub fn set_limits(
        &self,
        recvq: Option<usize>,
        hardsendq: Option<usize>,
        softsendq: Option<usize>,
    ) {
        if let OutSink::Reactor { token, tx, waker } = self {
            if tx
                .send(Out::Limits {
                    token: *token,
                    recvq,
                    hardsendq,
                    softsendq,
                })
                .is_ok()
            {
                let _ = waker.wake();
            }
        }
    }
}

impl Drop for OutSink {
    fn drop(&mut self) {
        // The core dropping this handle means "this connection is done". For the
        // thread model, dropping the Sender ends the writer loop (which flushes
        // first). For the reactor, ask it to flush any queued lines then close.
        if let OutSink::Reactor { token, tx, waker } = self {
            let _ = tx.send(Out::Close(*token));
            let _ = waker.wake();
        }
    }
}

// === mio reactor: all client plaintext connections on one thread =============

const LISTENER: Token = Token(0);
const WAKE: Token = Token(1);
const FIRST_CONN: usize = 16; // conn tokens start past the reserved ones

struct Conn {
    stream: MioStream,
    uid: Uid,
    rbuf: Vec<u8>, // bytes read, awaiting a newline
    wbuf: Vec<u8>, // bytes queued to write
    wpos: usize,   // how far into wbuf we've written
    want_read: bool,
    want_write: bool,
    closing: bool,     // flush wbuf, then close
    paused: bool,      // reads paused (softsendq backpressure); ⟺ pending > softsendq
    recvq: usize,      // max buffered unterminated-line bytes before dropping
    hardsendq: usize,  // max queued output bytes before dropping + closing
    softsendq: usize,  // queued output above this pauses reads until it drains
}

impl Conn {
    fn pending(&self) -> usize {
        self.wbuf.len() - self.wpos
    }
}

/// Reregister `t`'s epoll interest to match its current read/write intent, but only
/// if it changed. A paused connection drops READABLE (so the client stops being
/// serviced) while keeping WRITABLE to drain the backlog that paused it.
fn set_interest(poll: &mut Poll, c: &mut Conn, t: usize) {
    let want_read = !c.paused;
    let want_write = !c.wbuf.is_empty() || c.paused;
    if want_read == c.want_read && want_write == c.want_write {
        return;
    }
    c.want_read = want_read;
    c.want_write = want_write;
    let interest = match (want_read, want_write) {
        (true, true) => Interest::READABLE | Interest::WRITABLE,
        (false, true) => Interest::WRITABLE,
        // never both-false (paused ⟹ backlog ⟹ want_write); READABLE is a safe floor
        _ => Interest::READABLE,
    };
    let _ = poll.registry().reregister(&mut c.stream, Token(t), interest);
}

/// Run the client plaintext reactor on this thread. `listener` is an already-bound
/// mio listener (bound in `main` so a bind failure is fatal and fails fast).
pub fn run_reactor(
    mut listener: MioListener,
    core: Sender<Event>,
    counter: Arc<AtomicU64>,
    max_line: usize,
    max_sendq: usize,
) {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("reactor: cannot create poll: {e}");
            return;
        }
    };
    if poll
        .registry()
        .register(&mut listener, LISTENER, Interest::READABLE)
        .is_err()
    {
        eprintln!("reactor: cannot register listener");
        return;
    }
    let waker = match Waker::new(poll.registry(), WAKE) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            eprintln!("reactor: cannot create waker: {e}");
            return;
        }
    };
    let (out_tx, out_rx) = mpsc::channel::<Out>();

    let mut conns: HashMap<usize, Conn> = HashMap::new();
    let mut next_token = FIRST_CONN;
    let mut events = Events::with_capacity(1024);

    loop {
        if poll.poll(&mut events, None).is_err() {
            continue;
        }
        for event in events.iter() {
            match event.token() {
                LISTENER => loop {
                    match listener.accept() {
                        Ok((mut stream, _addr)) => {
                            let _ = stream.set_nodelay(true);
                            let token = next_token;
                            next_token += 1;
                            if poll
                                .registry()
                                .register(&mut stream, Token(token), Interest::READABLE)
                                .is_err()
                            {
                                continue;
                            }
                            let uid = counter.fetch_add(1, Ordering::Relaxed);
                            let addr = stream
                                .peer_addr()
                                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                            let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                            conns.insert(
                                token,
                                Conn {
                                    stream,
                                    uid,
                                    rbuf: Vec::new(),
                                    wbuf: Vec::new(),
                                    wpos: 0,
                                    want_read: true,
                                    want_write: false,
                                    closing: false,
                                    paused: false,
                                    recvq: max_line,
                                    hardsendq: max_sendq,
                                    softsendq: max_sendq,
                                },
                            );
                            let out = OutSink::Reactor {
                                token,
                                tx: out_tx.clone(),
                                waker: waker.clone(),
                            };
                            if core
                                .send(Event::Connect {
                                    uid,
                                    addr,
                                    out,
                                    sock: None,
                                    secure: false,
                                    certfp: None,
                                    local_port,
                                    link: false,
                                    outbound: false,
                                    websocket: false,
                                })
                                .is_err()
                            {
                                return; // core gone
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                },
                WAKE => {
                    // drain everything the core queued, then flush the touched conns
                    let mut touched: HashSet<usize> = HashSet::new();
                    while let Ok(msg) = out_rx.try_recv() {
                        match msg {
                            Out::Line(t, line) => {
                                if let Some(c) = conns.get_mut(&t) {
                                    if c.pending() + line.len() + 2 > c.hardsendq {
                                        // hardsendq: drop queued data and close
                                        c.wbuf.clear();
                                        c.wpos = 0;
                                        c.closing = true;
                                    } else {
                                        if c.wpos > 0 {
                                            c.wbuf.drain(..c.wpos); // reclaim written prefix
                                            c.wpos = 0;
                                        }
                                        c.wbuf.extend_from_slice(line.as_bytes());
                                        c.wbuf.extend_from_slice(b"\r\n");
                                        // softsendq: over the soft cap, stop reading
                                        // their commands until the backlog drains
                                        if c.pending() > c.softsendq {
                                            c.paused = true;
                                        }
                                    }
                                    touched.insert(t);
                                }
                            }
                            Out::Close(t) => {
                                if let Some(c) = conns.get_mut(&t) {
                                    c.closing = true;
                                    touched.insert(t);
                                }
                            }
                            Out::Limits {
                                token,
                                recvq,
                                hardsendq,
                                softsendq,
                            } => {
                                if let Some(c) = conns.get_mut(&token) {
                                    if let Some(v) = recvq {
                                        c.recvq = v;
                                    }
                                    if let Some(v) = hardsendq {
                                        c.hardsendq = v;
                                    }
                                    if let Some(v) = softsendq {
                                        c.softsendq = v;
                                    }
                                }
                            }
                        }
                    }
                    for t in touched {
                        flush_conn(&mut poll, &mut conns, t, &core);
                    }
                }
                Token(t) => {
                    if event.is_readable() {
                        read_conn(&mut poll, &mut conns, t, &core);
                    }
                    if event.is_writable() && conns.contains_key(&t) {
                        flush_conn(&mut poll, &mut conns, t, &core);
                    }
                }
            }
        }
    }
}

/// Drain readable bytes from `t` (edge-triggered: read until WouldBlock), frame
/// complete lines and forward them to the core; close on EOF/error.
fn read_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) {
    let mut chunk = [0u8; 8192];
    let mut lines: Vec<(Uid, String)> = Vec::new();
    let mut close = false;
    if let Some(c) = conns.get_mut(&t) {
        loop {
            match c.stream.read(&mut chunk) {
                Ok(0) => {
                    close = true;
                    break;
                }
                Ok(n) => {
                    c.rbuf.extend_from_slice(&chunk[..n]);
                    while let Some(pos) = c.rbuf.iter().position(|&b| b == b'\n') {
                        let raw: Vec<u8> = c.rbuf.drain(..=pos).collect();
                        let text = String::from_utf8_lossy(&raw);
                        let l = text.trim_end_matches(['\r', '\n']);
                        if !l.is_empty() {
                            lines.push((c.uid, l.to_string()));
                        }
                    }
                    if c.rbuf.len() > c.recvq {
                        c.rbuf.clear(); // overlong line with no newline: drop it
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    close = true;
                    break;
                }
            }
        }
    }
    for (uid, line) in lines {
        if core.send(Event::Line { uid, line }).is_err() {
            return;
        }
    }
    if close {
        close_conn(poll, conns, t, core);
    }
}

/// Write as much of `t`'s queued output as the socket accepts, adjust epoll
/// interest, and close once a `closing` connection's buffer is drained. If the
/// backlog dropped back under softsendq, un-pause reads and catch up (edge-triggered:
/// data that arrived while paused won't re-fire, so read it here).
fn flush_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) {
    let mut close = false;
    let mut unpaused = false;
    if let Some(c) = conns.get_mut(&t) {
        while c.wpos < c.wbuf.len() {
            match c.stream.write(&c.wbuf[c.wpos..]) {
                Ok(0) => break,
                Ok(n) => c.wpos += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    close = true;
                    break;
                }
            }
        }
        if c.wpos == c.wbuf.len() {
            c.wbuf.clear();
            c.wpos = 0;
        }
        if c.paused && c.pending() <= c.softsendq {
            c.paused = false;
            unpaused = true;
        }
        set_interest(poll, c, t);
        if c.closing && c.wbuf.is_empty() {
            close = true;
        }
    }
    if close {
        close_conn(poll, conns, t, core);
    } else if unpaused {
        read_conn(poll, conns, t, core); // catch reads missed while paused
    }
}

/// Deregister + drop `t`'s socket and tell the core the connection is gone.
fn close_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) {
    if let Some(mut c) = conns.remove(&t) {
        let _ = poll.registry().deregister(&mut c.stream);
        let uid = c.uid;
        drop(c); // closes the socket
        let _ = core.send(Event::Disconnect { uid });
    }
}

// === thread model: TLS + server links ========================================

/// Accept forever on a thread-per-connection listener (TLS or S2S). `tls` is the
/// backend to wrap sockets in (None ⇒ plaintext link). `counter` is shared with
/// the reactor so uids stay unique across every listener.
pub fn accept_loop(
    listener: TcpListener,
    core: Sender<Event>,
    tls: Option<Arc<dyn TlsBackend>>,
    counter: Arc<AtomicU64>,
    link: bool,
    max_line: usize,
) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Ok(addr) = stream.peer_addr() else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
        let uid = counter.fetch_add(1, Ordering::Relaxed);

        match &tls {
            None => {
                let Ok(reader) = stream.try_clone() else {
                    continue;
                };
                let Ok(shutdown) = stream.try_clone() else {
                    continue;
                };
                let (out_tx, out_rx) = mpsc::channel::<String>();
                thread::spawn(move || writer_loop(stream, out_rx));
                if core
                    .send(Event::Connect {
                        uid,
                        addr,
                        out: OutSink::Thread(out_tx),
                        sock: Some(shutdown),
                        secure: false,
                        certfp: None,
                        local_port,
                        link,
                        outbound: false,
                        websocket: false,
                    })
                    .is_err()
                {
                    break; // core gone
                }
                let core_tx = core.clone();
                thread::spawn(move || reader_loop(reader, uid, core_tx, max_line));
            }
            Some(backend) => {
                let backend = backend.clone();
                let core_tx = core.clone();
                thread::spawn(move || tls_conn(backend, stream, uid, addr, core_tx, link, max_line));
            }
        }
    }
}

/// Dial an outbound server link and wire it to the core (an `outbound` link that
/// introduces itself first). Used for auto-connecting to a configured uplink.
pub fn connect_link(addr: &str, core: Sender<Event>, counter: Arc<AtomicU64>, max_line: usize) {
    let stream = match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[link] cannot dial {addr}: {e}");
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let Ok(peer) = stream.peer_addr() else { return };
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let Ok(shutdown) = stream.try_clone() else {
        return;
    };
    let uid = counter.fetch_add(1, Ordering::Relaxed);
    let (out_tx, out_rx) = mpsc::channel::<String>();
    thread::spawn(move || writer_loop(stream, out_rx));
    if core
        .send(Event::Connect {
            uid,
            addr: peer,
            out: OutSink::Thread(out_tx),
            sock: Some(shutdown),
            secure: false,
            certfp: None,
            local_port: 0,
            link: true,
            outbound: true,
            websocket: false,
        })
        .is_err()
    {
        return;
    }
    thread::spawn(move || reader_loop(reader, uid, core, max_line));
}

// --- plaintext link: two blocking threads -----------------------------------

fn reader_loop(stream: TcpStream, uid: Uid, core: Sender<Event>, max_line: usize) {
    let mut buf = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match buf.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                if line.len() > max_line {
                    continue;
                }
                let l = line.trim_end_matches(['\r', '\n']);
                if l.is_empty() {
                    continue;
                }
                if core
                    .send(Event::Line {
                        uid,
                        line: l.to_string(),
                    })
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = core.send(Event::Disconnect { uid });
}

fn writer_loop(mut stream: TcpStream, rx: Receiver<String>) {
    // Ends when every sender (the user's `out`) is dropped by the core.
    for line in rx {
        if stream.write_all(line.as_bytes()).is_err() || stream.write_all(b"\r\n").is_err() {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

// --- TLS: one thread owning the session -------------------------------------

fn tls_conn(
    backend: Arc<dyn TlsBackend>,
    stream: TcpStream,
    uid: Uid,
    addr: SocketAddr,
    core: Sender<Event>,
    link: bool,
    max_line: usize,
) {
    // Keep a raw handle so the core can force the socket shut later.
    let Ok(shutdown) = stream.try_clone() else {
        return;
    };
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut conn = match backend.accept(stream) {
        Ok(c) => c,
        Err(_) => {
            let _ = shutdown.shutdown(Shutdown::Both);
            return; // handshake failed
        }
    };
    let certfp = conn.peer_cert_fp();
    let (out_tx, out_rx) = mpsc::channel::<String>();
    if core
        .send(Event::Connect {
            uid,
            addr,
            out: OutSink::Thread(out_tx),
            sock: Some(shutdown),
            secure: true,
            certfp,
            local_port,
            link,
            outbound: false,
            websocket: false,
        })
        .is_err()
    {
        conn.shutdown();
        return;
    }

    let _ = conn.set_read_timeout(Some(TLS_POLL));
    let mut acc: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    'io: loop {
        match conn.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                acc.extend_from_slice(&chunk[..n]);
                while let Some(pos) = acc.iter().position(|&b| b == b'\n') {
                    let raw: Vec<u8> = acc.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&raw);
                    let l = text.trim_end_matches(['\r', '\n']);
                    if !l.is_empty()
                        && core
                            .send(Event::Line {
                                uid,
                                line: l.to_string(),
                            })
                            .is_err()
                    {
                        break 'io;
                    }
                }
                if acc.len() > max_line {
                    acc.clear(); // overlong line with no newline: drop it
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

        // drain everything the core queued for this connection
        loop {
            match out_rx.try_recv() {
                Ok(line) => {
                    if conn.write_all(line.as_bytes()).is_err() || conn.write_all(b"\r\n").is_err()
                    {
                        break 'io;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // the core dropped us (user removed); nothing more to do
                    conn.shutdown();
                    return;
                }
            }
        }
        let _ = conn.flush();
    }
    conn.shutdown();
    let _ = core.send(Event::Disconnect { uid });
}
