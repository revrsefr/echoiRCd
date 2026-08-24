//! The socket engine: the I/O edge. Two coexisting models feed the one core:
//!
//! - **Client connections** run on a **pool of mio epoll reactors** — acceptors
//!   ([`run_acceptor`] for plaintext, [`accept_loop`] for TLS) round-robin connections
//!   across N worker threads ([`spawn_reactors`], one per core by default), each
//!   driving tens of thousands of sockets — plaintext and **direct TLS** alike, the
//!   handshake and crypto run non-blocking in the worker — so the daemon scales to
//!   hundreds of thousands of users without a thread per connection. The state core
//!   stays single-threaded and there is no async runtime; workers only frame lines and
//!   feed it Events, so the parallel I/O (including TLS crypto) needs no locks.
//! - **Proxied TLS** (a PROXY header before the handshake) and **server links** keep a
//!   thread per connection: few of them, and the pre-handshake header wants the
//!   simpler blocking path.
//!
//! Both hand the core the same [`OutSink`] output handle, so the core never
//! knows or cares which model a connection uses.

use crate::map::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::{TcpListener as MioListener, TcpStream as MioStream};
use mio::{Events, Interest, Poll, Token, Waker};

use crate::ircd::Event;
use crate::tls::{TlsBackend, TlsSession};
use crate::Uid;

/// Default recvq: longest single line we'll buffer before dropping it. Overridable
/// globally (`max_line`) and per connection class (`recvq`).
pub const DEFAULT_MAX_LINE: usize = 16 * 1024;
/// Default hardsendq: most bytes we'll queue to a slow client before dropping them
/// and closing. Overridable globally (`max_sendq`) and per class (`hardsendq`).
pub const DEFAULT_MAX_SENDQ: usize = 1 << 20; // 1 MiB
/// How long a TLS thread blocks on a read before draining its write queue.
const TLS_POLL: Duration = Duration::from_millis(100);

/// Collapse an IPv4-mapped IPv6 peer address (`::ffff:1.2.3.4`, which is how an IPv4
/// client shows up on a dual-stack `[::]` listener) back to a plain IPv4 `SocketAddr`,
/// so cloaking, bans, GeoIP, DNSBL and host display all see the real IPv4 address.
fn normalize_addr(a: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = a {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return SocketAddr::new(IpAddr::V4(v4), a.port());
        }
    }
    a
}

/// A queued output action the core hands the reactor: a line to write to a
/// connection, a request to flush-then-close it (sent when the core drops the
/// [`OutSink`], e.g. on quit), or a per-connection queue-limit override (from the
/// assigned connection class).
pub enum Out {
    Line(usize, LineBuf),
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
/// A line queued for delivery: either uniquely owned, or an `Arc` shared by every
/// recipient of a channel broadcast — so fanning one line out to N members allocates
/// it once, not N times. Both forms write the identical bytes to the wire.
pub enum LineBuf {
    Owned(String),
    Shared(Arc<str>),
}

impl LineBuf {
    fn bytes(&self) -> &[u8] {
        match self {
            LineBuf::Owned(s) => s.as_bytes(),
            LineBuf::Shared(a) => a.as_bytes(),
        }
    }
    fn len(&self) -> usize {
        match self {
            LineBuf::Owned(s) => s.len(),
            LineBuf::Shared(a) => a.len(),
        }
    }
    /// Materialise an owned `String` (a move for `Owned`, one copy for `Shared`) —
    /// for the thread-model sinks and the labeled-response capture buffer.
    pub fn into_string(self) -> String {
        match self {
            LineBuf::Owned(s) => s,
            LineBuf::Shared(a) => a.to_string(),
        }
    }
}

impl From<String> for LineBuf {
    fn from(s: String) -> Self {
        LineBuf::Owned(s)
    }
}

pub enum OutSink {
    Thread(Sender<String>),
    Reactor {
        token: usize,
        tx: Sender<Out>,
        waker: Arc<Waker>,
    },
}

impl OutSink {
    /// Queue one line for delivery (the writer appends CRLF). The reactor sink keeps
    /// a shared line shared (no copy); the thread sink materialises a `String`.
    pub fn send(&self, line: LineBuf) {
        match self {
            OutSink::Thread(s) => {
                let _ = s.send(line.into_string());
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

/// A reactor connection's socket: a raw plaintext stream, or a non-blocking TLS
/// session driven by the same reactor. Both expose the underlying mio socket for
/// poll registration, so the read/write/backpressure machinery is identical.
enum Sock {
    Plain(MioStream),
    Tls(Box<dyn TlsSession>),
}

impl Sock {
    /// The underlying socket, for poll (re)register/deregister.
    fn source(&mut self) -> &mut MioStream {
        match self {
            Sock::Plain(s) => s,
            Sock::Tls(t) => t.source(),
        }
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sock::Plain(s) => s.read(buf),
            Sock::Tls(t) => t.read(buf),
        }
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sock::Plain(s) => s.write(buf),
            Sock::Tls(t) => t.write(buf),
        }
    }
    /// Whether a TLS session still has outbound bytes buffered internally (rustls
    /// after a WouldBlock); a plaintext socket never buffers in-process.
    fn wants_write(&self) -> bool {
        match self {
            Sock::Plain(_) => false,
            Sock::Tls(t) => t.wants_write(),
        }
    }
    /// Push a TLS session's buffered ciphertext to the socket; no-op for plaintext.
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sock::Plain(_) => Ok(()),
            Sock::Tls(t) => t.flush(),
        }
    }
    /// Best-effort graceful close. TLS sends a close_notify alert; plaintext relies on
    /// the socket's own FIN when the stream drops.
    fn shutdown(&mut self) {
        if let Sock::Tls(t) = self {
            t.shutdown();
        }
    }
}

struct Conn {
    sock: Sock,
    uid: Uid,
    addr: SocketAddr, // peer, or the real client once a PROXY header is parsed
    local_port: u16,  // listener port (for the deferred-Connect case)
    rbuf: Vec<u8>,    // bytes read, awaiting a newline
    wbuf: Vec<u8>,    // bytes queued to write
    wpos: usize,      // how far into wbuf we've written
    want_read: bool,
    want_write: bool,
    closing: bool,     // flush wbuf, then close
    paused: bool,      // reads paused (softsendq backpressure); ⟺ pending > softsendq
    recvq: usize,      // max buffered unterminated-line bytes before dropping
    hardsendq: usize,  // max queued output bytes before dropping + closing
    softsendq: usize,  // queued output above this pauses reads until it drains
    handshaking: bool, // TLS: still negotiating; hold reads + the Connect until done
    proxy_pending: bool, // hold the Connect event until a PROXY header is consumed
    pending_out: Option<OutSink>, // the OutSink held for that deferred Connect
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
    // a TLS handshake may need to write (its flight) as well as read, so keep both
    // until it completes; after that, write when there's a backlog to drain — either
    // our own queued plaintext, or ciphertext still buffered inside a TLS session.
    let want_write = c.handshaking || !c.wbuf.is_empty() || c.paused || c.sock.wants_write();
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
    let _ = poll.registry().reregister(c.sock.source(), Token(t), interest);
}

/// Largest PROXY header we'll buffer before giving up (v1 ≤ 107, v2 header ≤ ~232).
const PROXY_MAX: usize = 256;

/// A freshly accepted client the acceptor hands to a reactor worker to adopt.
struct Accepted {
    stream: MioStream,
    uid: Uid,
    addr: SocketAddr,
    local_port: u16,
    via_proxy: bool,
    tls: Option<Arc<dyn TlsBackend>>, // Some ⇒ the worker negotiates TLS on this socket
}

/// The acceptor's handle to one reactor worker: its handoff queue and the waker that
/// nudges the worker to adopt whatever was queued. Cloneable so several acceptors
/// (plaintext + TLS) can share the same pool, each round-robining independently.
/// Opaque to callers — `main` only holds a `Vec` of these and passes it along.
#[derive(Clone)]
pub struct ReactorHandle {
    handoff: Sender<Accepted>,
    waker: Arc<Waker>,
}

/// Resolve the reactor-pool size. An explicit `io_threads` wins; 0 means auto — one
/// worker per CPU, floored at 1 and capped at 4 so a many-core box doesn't over-thread
/// the plaintext path (set `io_threads` explicitly to raise it).
fn resolve_io_threads(io_threads: usize) -> usize {
    if io_threads > 0 {
        return io_threads;
    }
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4)
}

/// Start the reactor worker pool and return the acceptors' handles to it. Sized by
/// `io_threads` (0 = auto: one worker per core, capped). Each worker runs its own poll
/// and connection map on its own core; the state core stays single-threaded — workers
/// only frame lines and feed it Events — so per-connection I/O (plaintext framing and
/// TLS crypto alike) scales across cores with no shared locking.
pub fn spawn_reactors(
    core: Sender<Event>,
    max_line: usize,
    max_sendq: usize,
    io_threads: usize,
    handshake_timeout: Option<Duration>,
) -> Vec<ReactorHandle> {
    let workers = resolve_io_threads(io_threads);
    let mut reactors = Vec::with_capacity(workers);
    for _ in 0..workers {
        match spawn_reactor(core.clone(), max_line, max_sendq, handshake_timeout) {
            Ok(h) => reactors.push(h),
            Err(e) => eprintln!("reactor: cannot start a worker: {e}"),
        }
    }
    eprintln!("echoircd reactor pool: {} worker thread(s)", reactors.len());
    reactors
}

/// Round-robin one accepted connection onto a worker and wake it to adopt the conn.
fn dispatch(reactors: &[ReactorHandle], rr: &mut usize, a: Accepted) {
    if reactors.is_empty() {
        return; // no workers: drop it (a.stream closes on drop)
    }
    let idx = *rr % reactors.len();
    *rr = rr.wrapping_add(1);
    if reactors[idx].handoff.send(a).is_ok() {
        let _ = reactors[idx].waker.wake();
    }
}

/// A token-bucket rate limiter keyed by source IP, checked at the accept edge so a
/// connection-churn flood is dropped before any per-connection state is allocated —
/// the cheapest possible rejection. Shared (behind a mutex) by the plaintext and TLS
/// acceptors, so one IP can't earn a fresh budget per listener. Off unless
/// `accept_rate` is configured. Complements the connclass *concurrent* clone caps with
/// a *rate* cap, and skips connections from trusted proxies (whose peer IP is the proxy).
pub struct AcceptLimiter {
    rate: f64,  // sustained new connections/sec per IP
    burst: f64, // bucket capacity — the instantaneous burst allowed per IP
    inner: Mutex<LimiterState>,
}

struct LimiterState {
    buckets: HashMap<IpAddr, (f64, Instant)>, // ip -> (tokens, last refill)
    last_prune: Instant,
}

impl AcceptLimiter {
    /// Build a limiter from config, or `None` when disabled (`rate` 0). `burst` 0
    /// defaults to `rate` (one second's worth).
    pub fn from_conf(rate: usize, burst: usize) -> Option<Arc<AcceptLimiter>> {
        if rate == 0 {
            return None;
        }
        let burst = if burst == 0 { rate } else { burst };
        Some(Arc::new(AcceptLimiter {
            rate: rate as f64,
            burst: burst.max(1) as f64,
            inner: Mutex::new(LimiterState {
                buckets: HashMap::default(),
                last_prune: Instant::now(),
            }),
        }))
    }

    /// Whether a new connection from `ip` is allowed now, consuming one token.
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // periodically forget IPs idle for a while, so memory tracks only active sources
        if now.duration_since(st.last_prune) >= Duration::from_secs(30) {
            st.buckets
                .retain(|_, &mut (_, last)| now.duration_since(last) < Duration::from_secs(60));
            st.last_prune = now;
        }
        let entry = st.buckets.entry(ip).or_insert((self.burst, now));
        let refilled =
            (entry.0 + self.rate * now.duration_since(entry.1).as_secs_f64()).min(self.burst);
        if refilled >= 1.0 {
            *entry = (refilled - 1.0, now);
            true
        } else {
            *entry = (refilled, now);
            false
        }
    }
}

/// True when a limiter is configured and this IP is over its accept rate.
fn rate_limited(limiter: &Option<Arc<AcceptLimiter>>, ip: IpAddr) -> bool {
    limiter.as_ref().map(|l| !l.allow(ip)).unwrap_or(false)
}

/// The plaintext client acceptor: owns the listener and round-robins each new
/// connection onto a reactor worker.
pub fn run_acceptor(
    mut listener: MioListener,
    reactors: Vec<ReactorHandle>,
    counter: Arc<AtomicU64>,
    proxy_trust: Vec<String>,
    limiter: Option<Arc<AcceptLimiter>>,
) {
    if reactors.is_empty() {
        eprintln!("acceptor: no worker threads; plaintext clients disabled");
        return;
    }
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acceptor: cannot create poll: {e}");
            return;
        }
    };
    if poll
        .registry()
        .register(&mut listener, LISTENER, Interest::READABLE)
        .is_err()
    {
        eprintln!("acceptor: cannot register listener");
        return;
    }
    let mut events = Events::with_capacity(64);
    let mut rr: usize = 0;
    loop {
        if poll.poll(&mut events, None).is_err() {
            continue;
        }
        // the listener is the only source registered here, so drain the accept queue
        for _ in events.iter() {
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let addr = normalize_addr(
                            stream
                                .peer_addr()
                                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                        );
                        // a connection from a trusted proxy leads with a PROXY header;
                        // the worker holds its Connect until that header is consumed so
                        // the core sees the real client IP.
                        let via_proxy = proxy_trust.iter().any(|g| {
                            crate::modules::connclass::ip_matches(g, &addr.ip().to_string())
                        });
                        // rate-limit direct clients at the edge; drop before allocating
                        // anything. Proxied clients carry the proxy's IP, so skip them.
                        if !via_proxy && rate_limited(&limiter, addr.ip()) {
                            continue; // stream drops here, nothing else touched
                        }
                        let _ = stream.set_nodelay(true);
                        let uid = counter.fetch_add(1, Ordering::Relaxed);
                        let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                        dispatch(
                            &reactors,
                            &mut rr,
                            Accepted {
                                stream,
                                uid,
                                addr,
                                local_port,
                                via_proxy,
                                tls: None,
                            },
                        );
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
    }
}

/// Spawn one reactor worker and return the acceptor's handle to it. The worker owns
/// its poll, connection map, and token space; tokens are reactor-local (each write is
/// routed to the owning worker by the `out_tx` baked into that connection's OutSink),
/// while uids come from the shared counter and stay globally unique.
fn spawn_reactor(
    core: Sender<Event>,
    max_line: usize,
    max_sendq: usize,
    handshake_timeout: Option<Duration>,
) -> io::Result<ReactorHandle> {
    let poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
    let (handoff_tx, handoff_rx) = mpsc::channel::<Accepted>();
    let (out_tx, out_rx) = mpsc::channel::<Out>();
    let handle = ReactorHandle {
        handoff: handoff_tx,
        waker: waker.clone(),
    };
    thread::spawn(move || {
        reactor_loop(
            poll,
            waker,
            handoff_rx,
            out_tx,
            out_rx,
            core,
            max_line,
            max_sendq,
            handshake_timeout,
        )
    });
    Ok(handle)
}

/// One reactor worker's event loop: adopt handed-off connections, drive their reads
/// and writes, and apply the output the core queued for them.
fn reactor_loop(
    mut poll: Poll,
    waker: Arc<Waker>,
    handoff_rx: Receiver<Accepted>,
    out_tx: Sender<Out>,
    out_rx: Receiver<Out>,
    core: Sender<Event>,
    max_line: usize,
    max_sendq: usize,
    handshake_timeout: Option<Duration>,
) {
    let mut conns: HashMap<usize, Conn> = HashMap::default();
    let mut next_token = FIRST_CONN;
    let mut events = Events::with_capacity(1024);
    // TLS conns still negotiating, with the deadline by which they must finish; a
    // stalled handshake holds no uid so nothing else would ever reap it.
    let mut pending_hs: Vec<(usize, Instant)> = Vec::new();
    // sockets that hit MAX_READ_PER_TURN with data still buffered (in the kernel OR,
    // for TLS, inside the session) — re-drained each turn so no line stalls.
    let mut pending_reads: Vec<usize> = Vec::new();

    loop {
        // poll immediately if reads are queued; else block, waking ~1s while a handshake
        // is pending to reap any that blew their deadline (slow-loris on the TLS port).
        let timeout = if !pending_reads.is_empty() {
            Some(Duration::ZERO)
        } else if !pending_hs.is_empty() {
            Some(Duration::from_millis(1000))
        } else {
            None
        };
        if poll.poll(&mut events, timeout).is_err() {
            continue;
        }
        if !pending_hs.is_empty() {
            let now = Instant::now();
            let mut expired = Vec::new();
            pending_hs.retain(|&(tok, dl)| match conns.get(&tok) {
                Some(c) if c.handshaking || c.proxy_pending => {
                    if now >= dl {
                        expired.push(tok);
                        false
                    } else {
                        true
                    }
                }
                _ => false, // handshake/proxy-header done, or the conn is already gone
            });
            for tok in expired {
                close_conn(&mut poll, &mut conns, tok, &core);
            }
        }
        for event in events.iter() {
            match event.token() {
                WAKE => {
                    // first adopt any connections the acceptor handed us, then apply
                    // the output the core queued and flush the connections it touched.
                    while let Ok(a) = handoff_rx.try_recv() {
                        let token = next_token;
                        next_token += 1;
                        // build the socket: a TLS conn negotiates non-blocking in this
                        // worker; a plaintext one is ready to read immediately.
                        let (mut sock, handshaking) = match a.tls {
                            Some(backend) => match backend.start(a.stream) {
                                Ok(sess) => (Sock::Tls(sess), true),
                                Err(_) => continue, // couldn't start TLS: drop it
                            },
                            None => (Sock::Plain(a.stream), false),
                        };
                        let interest = if handshaking {
                            Interest::READABLE | Interest::WRITABLE
                        } else {
                            Interest::READABLE
                        };
                        if poll
                            .registry()
                            .register(sock.source(), Token(token), interest)
                            .is_err()
                        {
                            continue;
                        }
                        let out = OutSink::Reactor {
                            token,
                            tx: out_tx.clone(),
                            waker: waker.clone(),
                        };
                        conns.insert(
                            token,
                            Conn {
                                sock,
                                uid: a.uid,
                                addr: a.addr,
                                local_port: a.local_port,
                                rbuf: Vec::new(),
                                wbuf: Vec::new(),
                                wpos: 0,
                                want_read: true,
                                want_write: handshaking,
                                closing: false,
                                paused: false,
                                recvq: max_line,
                                hardsendq: max_sendq,
                                softsendq: max_sendq,
                                handshaking,
                                proxy_pending: a.via_proxy,
                                pending_out: Some(out),
                            },
                        );
                        // reap a stalled TLS handshake OR a proxy-pending conn that never
                        // sends its PROXY header — neither has a uid yet, so nothing else
                        // would ever time it out.
                        if handshaking || a.via_proxy {
                            if let Some(d) = handshake_timeout {
                                pending_hs.push((token, Instant::now() + d));
                            }
                        }
                        // announce now only if nothing defers it: a TLS conn waits for
                        // its handshake, a proxy conn for its header.
                        if !a.via_proxy && !handshaking {
                            let out = conns.get_mut(&token).and_then(|c| c.pending_out.take());
                            if let Some(out) = out {
                                if core
                                    .send(Event::Connect {
                                        uid: a.uid,
                                        addr: a.addr,
                                        out,
                                        sock: None,
                                        secure: false,
                                        certfp: None,
                                        tls_info: None,
                                        local_port: a.local_port,
                                        link: false,
                                        outbound: false,
                                        websocket: false,
                                    })
                                    .is_err()
                                {
                                    return; // core gone
                                }
                            }
                        }
                    }
                    // drain everything the core queued, then flush the touched conns
                    let mut touched: HashSet<usize> = HashSet::default();
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
                                        c.wbuf.extend_from_slice(line.bytes());
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
                    // isolate per-connection I/O: a panic framing one client's bytes
                    // drops that client, never the reactor that serves all the others.
                    if event.is_readable() {
                        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            read_conn(&mut poll, &mut conns, t, &core)
                        }));
                        match r {
                            Ok(true) => pending_reads.push(t), // hit the per-turn cap
                            Ok(false) => {}
                            Err(_) => {
                                eprintln!("[reactor] recovered from a panic reading a socket; dropping that connection");
                                close_conn(&mut poll, &mut conns, t, &core);
                            }
                        }
                    }
                    if event.is_writable() && conns.contains_key(&t) {
                        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            flush_conn(&mut poll, &mut conns, t, &core)
                        }));
                        if r.is_err() {
                            eprintln!("[reactor] recovered from a panic writing a socket; dropping that connection");
                            close_conn(&mut poll, &mut conns, t, &core);
                        }
                    }
                }
            }
        }
        // re-drain sockets that hit the read cap: their leftover may be TLS plaintext
        // buffered in the session (kernel won't re-signal it). After events so fresh
        // events are serviced first; a still-capped socket re-queues for the next turn.
        if !pending_reads.is_empty() {
            for t in std::mem::take(&mut pending_reads) {
                if !conns.contains_key(&t) {
                    continue;
                }
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    read_conn(&mut poll, &mut conns, t, &core)
                }));
                match r {
                    Ok(true) => pending_reads.push(t),
                    Ok(false) => {}
                    Err(_) => {
                        eprintln!("[reactor] recovered from a panic re-reading a socket; dropping it");
                        close_conn(&mut poll, &mut conns, t, &core);
                    }
                }
            }
        }
    }
}

/// Drive a pending TLS handshake for `t`. Returns true once the connection is
/// established — its deferred Connect emitted with the peer's cert fingerprint, so
/// normal reads/writes may proceed — and false while it still needs I/O or was closed
/// on a fatal handshake error. A plaintext (or already-established) conn returns true.
fn try_handshake(
    poll: &mut Poll,
    conns: &mut HashMap<usize, Conn>,
    t: usize,
    core: &Sender<Event>,
) -> bool {
    let mut close = false;
    let mut connect: Option<(Uid, SocketAddr, u16, Option<String>, Option<String>, OutSink)> =
        None;
    if let Some(c) = conns.get_mut(&t) {
        if !c.handshaking {
            return true;
        }
        if let Sock::Tls(sess) = &mut c.sock {
            match sess.accept() {
                Ok(true) => {
                    c.handshaking = false;
                    let certfp = sess.peer_cert_fp();
                    let tls_info = sess.tls_info();
                    connect = c
                        .pending_out
                        .take()
                        .map(|out| (c.uid, c.addr, c.local_port, certfp, tls_info, out));
                    set_interest(poll, c, t); // handshake done: drop the extra WRITABLE
                }
                Ok(false) => return false, // still negotiating
                Err(_) => close = true,
            }
        } else {
            c.handshaking = false; // not TLS (shouldn't happen): treat as established
        }
    } else {
        return false;
    }
    if let Some((uid, addr, local_port, certfp, tls_info, out)) = connect {
        let _ = core.send(Event::Connect {
            uid,
            addr,
            out,
            sock: None,
            secure: true,
            certfp,
            tls_info,
            local_port,
            link: false,
            outbound: false,
            websocket: false,
        });
    }
    if close {
        close_conn(poll, conns, t, core);
        return false;
    }
    true
}

/// Most bytes drained from one socket per readable event before we stop, re-arm and
/// yield: bounds the per-turn line buffer and stops one flooding client from
/// monopolising the reactor (the rest waits in the kernel buffer for the next turn).
const MAX_READ_PER_TURN: usize = 64 * 1024;

/// Drain readable bytes from `t` (edge-triggered: read until WouldBlock), frame
/// complete lines and forward them to the core; close on EOF/error.
fn read_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) -> bool {
    // a TLS conn must finish negotiating before any application bytes flow
    if !try_handshake(poll, conns, t, core) {
        return false;
    }
    let mut chunk = [0u8; 8192];
    let mut lines: Vec<(Uid, String)> = Vec::new();
    // a deferred Connect (PROXY conn) to emit, before any lines from the same read
    let mut connect: Option<(Uid, SocketAddr, u16, bool, Option<String>, OutSink)> = None;
    let mut close = false;
    let mut read_total = 0usize;
    let mut capped = false;
    if let Some(c) = conns.get_mut(&t) {
        loop {
            match c.sock.read(&mut chunk) {
                Ok(0) => {
                    close = true;
                    break;
                }
                Ok(n) => {
                    c.rbuf.extend_from_slice(&chunk[..n]);
                    read_total += n;
                    if c.proxy_pending {
                        // a v2 header from a TLS-terminating proxy can forward the
                        // client's TLS status + cert fingerprint (see modules::proxy)
                        let mut psecure = false;
                        let mut pcertfp: Option<String> = None;
                        match crate::proxy::parse(&c.rbuf) {
                            (crate::proxy::Parsed::Need, _) => {
                                if c.rbuf.len() > PROXY_MAX {
                                    close = true;
                                    break;
                                }
                                continue; // header incomplete: read more
                            }
                            (crate::proxy::Parsed::Invalid, _) => {
                                close = true;
                                break;
                            }
                            (
                                crate::proxy::Parsed::Proxy {
                                    addr,
                                    secure,
                                    certfp,
                                },
                                used,
                            ) => {
                                c.addr = addr; // rewrite to the real client address
                                c.rbuf.drain(..used);
                                c.proxy_pending = false;
                                psecure = secure;
                                pcertfp = certfp;
                            }
                            (crate::proxy::Parsed::Local, used) => {
                                c.rbuf.drain(..used); // keep the peer addr
                                c.proxy_pending = false;
                            }
                        }
                        if !c.proxy_pending {
                            connect = c.pending_out.take().map(|out| {
                                (c.uid, c.addr, c.local_port, psecure, pcertfp, out)
                            });
                        }
                    }
                    if !c.proxy_pending {
                        while let Some(pos) = memchr::memchr(b'\n', &c.rbuf) {
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
                    // fairness + memory bound: after MAX_READ_PER_TURN bytes stop and
                    // re-arm, so one flooding client can't monopolise this reactor turn
                    if read_total >= MAX_READ_PER_TURN {
                        capped = true;
                        break;
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
    if let Some((uid, addr, local_port, secure, certfp, out)) = connect {
        if core
            .send(Event::Connect {
                uid,
                addr,
                out,
                sock: None,
                secure,
                certfp,
                tls_info: None,
                local_port,
                link: false,
                outbound: false,
                websocket: false,
            })
            .is_err()
        {
            return false;
        }
    }
    for (uid, line) in lines {
        if core.send(Event::Line { uid, line }).is_err() {
            return false;
        }
    }
    if close {
        close_conn(poll, conns, t, core);
    }
    // signal a hit on MAX_READ_PER_TURN so the reactor re-drains us next turn: the
    // leftover may be decrypted plaintext buffered inside the TLS session, which the
    // kernel would never re-signal — so we can't rely on an epoll re-arm here.
    capped && !close
}

/// Write as much of `t`'s queued output as the socket accepts, adjust epoll
/// interest, and close once a `closing` connection's buffer is drained. If the
/// backlog dropped back under softsendq, un-pause reads and catch up (edge-triggered:
/// data that arrived while paused won't re-fire, so read it here).
fn flush_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) {
    // a writable event during a TLS handshake advances it, not the (empty) write queue
    if !try_handshake(poll, conns, t, core) {
        return;
    }
    let mut close = false;
    let mut unpaused = false;
    if let Some(c) = conns.get_mut(&t) {
        while c.wpos < c.wbuf.len() {
            match c.sock.write(&c.wbuf[c.wpos..]) {
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
        // push any ciphertext a TLS session still holds buffered (rustls keeps it when
        // the socket filled mid-write); our plaintext queue draining doesn't mean the
        // socket has it all. WouldBlock leaves the rest for the next writable event.
        match c.sock.flush() {
            Ok(()) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => close = true,
        }
        if c.paused && c.pending() <= c.softsendq {
            c.paused = false;
            unpaused = true;
        }
        set_interest(poll, c, t);
        if c.closing && c.wbuf.is_empty() && !c.sock.wants_write() {
            close = true;
        }
    }
    if close {
        close_conn(poll, conns, t, core);
    } else if unpaused {
        let _ = read_conn(poll, conns, t, core); // catch reads missed while paused
    }
}

/// Deregister + drop `t`'s socket and tell the core the connection is gone.
fn close_conn(poll: &mut Poll, conns: &mut HashMap<usize, Conn>, t: usize, core: &Sender<Event>) {
    if let Some(mut c) = conns.remove(&t) {
        let _ = poll.registry().deregister(c.sock.source());
        // send a TLS close_notify for an established session (not a half-done handshake)
        if !c.handshaking {
            c.sock.shutdown();
        }
        let uid = c.uid;
        // a conn whose Connect was never emitted — a still-pending PROXY header or an
        // unfinished TLS handshake — must not send the core a Disconnect for a uid it
        // never saw
        let announced = !c.proxy_pending && !c.handshaking;
        drop(c); // closes the socket
        if announced {
            let _ = core.send(Event::Disconnect { uid });
        }
    }
}

// === thread model: TLS + server links ========================================

/// Accept forever on a listener (TLS or S2S). `tls` is the backend to wrap sockets in
/// (None ⇒ plaintext link). `counter` is shared with the reactor so uids stay unique
/// across every listener. `reactors` is the worker pool: a direct (non-proxy) TLS
/// client is handed off to it to negotiate non-blocking; a proxied TLS client (PROXY
/// header before the handshake) and every server link keep the thread path.
pub fn accept_loop(
    listener: TcpListener,
    core: Sender<Event>,
    tls: Option<Arc<dyn TlsBackend>>,
    counter: Arc<AtomicU64>,
    link: bool,
    max_line: usize,
    proxy_trust: Vec<String>,
    reactors: Vec<ReactorHandle>,
    limiter: Option<Arc<AcceptLimiter>>,
    handshake_timeout: Option<Duration>,
) {
    let mut rr: usize = 0;
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Ok(addr) = stream.peer_addr() else {
            continue;
        };
        let addr = normalize_addr(addr);
        // rate-limit direct client connections at the edge (not S2S links, not proxied)
        if !link {
            let via_proxy = proxy_trust
                .iter()
                .any(|g| crate::modules::connclass::ip_matches(g, &addr.ip().to_string()));
            if !via_proxy && rate_limited(&limiter, addr.ip()) {
                continue; // drop before any per-connection work
            }
        }
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
                        tls_info: None,
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
                let via_proxy = proxy_trust
                    .iter()
                    .any(|g| crate::modules::connclass::ip_matches(g, &addr.ip().to_string()));
                // direct TLS clients negotiate in the reactor pool (non-blocking, one
                // worker per core); a proxied client keeps the thread path so its
                // plaintext PROXY header is read before the handshake.
                if !via_proxy && !reactors.is_empty() && stream.set_nonblocking(true).is_ok() {
                    dispatch(
                        &reactors,
                        &mut rr,
                        Accepted {
                            stream: MioStream::from_std(stream),
                            uid,
                            addr,
                            local_port,
                            via_proxy: false,
                            tls: Some(backend.clone()),
                        },
                    );
                    continue;
                }
                let backend = backend.clone();
                let core_tx = core.clone();
                let pt = proxy_trust.clone();
                thread::spawn(move || {
                    tls_conn(
                        backend,
                        stream,
                        uid,
                        addr,
                        core_tx,
                        link,
                        max_line,
                        pt,
                        handshake_timeout,
                    )
                });
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
            tls_info: None,
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
    mut stream: TcpStream,
    uid: Uid,
    addr: SocketAddr,
    core: Sender<Event>,
    link: bool,
    max_line: usize,
    proxy_trust: Vec<String>,
    handshake_timeout: Option<Duration>,
) {
    // Keep a raw handle so the core can force the socket shut later.
    let Ok(shutdown) = stream.try_clone() else {
        return;
    };
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
    // a TLS client behind a trusted TCP proxy leads with a PROXY header (before the
    // TLS handshake); consume it and rewrite the client address.
    let addr = if proxy_trust
        .iter()
        .any(|g| crate::modules::connclass::ip_matches(g, &addr.ip().to_string()))
    {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        // echo terminates TLS on this listener, so only the client address is taken
        // from the header (its TLS TLVs would be redundant here).
        let real = match crate::proxy::read_header(&mut stream) {
            crate::proxy::Parsed::Proxy { addr, .. } => addr,
            crate::proxy::Parsed::Local => addr,
            _ => {
                let _ = shutdown.shutdown(Shutdown::Both);
                return;
            }
        };
        let _ = stream.set_read_timeout(None);
        real
    } else {
        addr
    };
    // Bound the blocking TLS handshake: a peer that stalls it would otherwise pin this
    // thread + socket forever (no uid yet, so nothing else reaps it). Reset to TLS_POLL
    // once the handshake completes (below), so it doesn't clip a live client's idle reads.
    let _ = stream.set_read_timeout(handshake_timeout);
    let mut conn = match backend.accept(stream) {
        Ok(c) => c,
        Err(_) => {
            let _ = shutdown.shutdown(Shutdown::Both);
            return; // handshake failed
        }
    };
    let certfp = conn.peer_cert_fp();
    let tls_info = conn.tls_info();
    let (out_tx, out_rx) = mpsc::channel::<String>();
    if core
        .send(Event::Connect {
            uid,
            addr,
            out: OutSink::Thread(out_tx),
            sock: Some(shutdown),
            secure: true,
            certfp,
            tls_info,
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
                while let Some(pos) = memchr::memchr(b'\n', &acc) {
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
