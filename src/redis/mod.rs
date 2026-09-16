//! Native, non-blocking Redis subsystem — the ephemeral / pub-sub companion to the
//! durable pgsql store. Same discipline as [`crate::database`]: a worker-thread pool
//! holds persistent connections and runs every command off-core, so a slow or stalled
//! Redis can never freeze the event loop. A module submits a command with a callback;
//! the pool runs it and the reply comes back as [`Event::RedisResult`], where the
//! callback runs with `&mut Server`. RESP2 wire, no `unsafe`, no deps.
//!
//! Redis is a *cache / counters / event-bus*, never the source of truth — durable
//! state stays in pgsql / services. The subsystem is inert unless `redis_host` is set,
//! and every path degrades gracefully when Redis is absent or down.
//!
//! ```ignore
//! redis::cmd(srv, &["GET", "rep:1.2.3.4"], move |srv, r| match r {
//!     Ok(v) => { /* v.as_str(), v.as_int() … */ }
//!     Err(e) => srv.log(&format!("redis: {e}")),
//! });
//! redis::publish(srv, "echoircd:events", "connect reverse");  // fire-and-forget bus
//! ```

pub mod resp;

use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::ircd::Event;
use crate::server::Server;
pub use resp::Value;

/// What a completed command hands back: the reply value, or an error string.
pub type RedisResult = Result<Value, String>;
type Callback = Box<dyn FnOnce(&mut Server, RedisResult) + Send>;

#[derive(Clone)]
struct RedisConfig {
    host: String,
    port: u16,
    password: String,
    db: i64, // SELECT index (0 = default)
    connect_timeout: Duration,
    io_timeout: Duration,
}

struct Req {
    id: u64, // 0 = fire-and-forget (reply discarded)
    args: Vec<Vec<u8>>,
}
type Queue = Arc<(Mutex<VecDeque<Req>>, Condvar)>;

/// Per-server Redis state (in `Server.ext`): the worker-pool submit queue, its cap,
/// and the in-core map of pending callbacks keyed by request id.
struct State {
    queue: Queue,
    queue_max: usize,
    pending: HashMap<u64, Callback>,
    next_id: u64,
}

/// Read `redis_*` config. Returns `None` (subsystem disabled) unless `redis_host` is set.
fn config(srv: &Server) -> Option<(RedisConfig, usize)> {
    let host = srv.conf("redis_host")?.trim().to_string();
    if host.is_empty() {
        return None;
    }
    let cfg = RedisConfig {
        host,
        port: srv.conf_num("redis_port", 6379u16),
        password: srv
            .conf("redis_password")
            .or_else(|| srv.conf("redis_pass"))
            .unwrap_or("")
            .to_string(),
        db: srv.conf_num("redis_db", 0i64),
        connect_timeout: Duration::from_secs(srv.conf_num("redis_connect_timeout", 5u64)),
        io_timeout: Duration::from_secs(srv.conf_num("redis_timeout", 30u64)),
    };
    let pool = srv.conf_num("redis_pool", 2usize).clamp(1, 16);
    Some((cfg, pool))
}

/// Spawn the worker pool at startup if `redis_host` is set. Called once from `Ircd::new`.
pub fn init(srv: &mut Server) {
    let Some((cfg, pool)) = config(srv) else {
        return; // no redis_host → subsystem stays inert
    };
    let queue_max = srv.conf_num("redis_queue_max", 1024usize).max(16);
    let event_tx = srv.event_tx.clone();
    let queue: Queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
    for _ in 0..pool {
        let (q, tx, c) = (queue.clone(), event_tx.clone(), cfg.clone());
        std::thread::spawn(move || run_worker(c, q, tx));
    }
    eprintln!(
        "echoircd: redis pool ({pool}) → {}:{}/{} (auth={})",
        cfg.host,
        cfg.port,
        cfg.db,
        !cfg.password.is_empty()
    );
    srv.ext.set(State {
        queue,
        queue_max,
        pending: HashMap::new(),
        next_id: 1,
    });
    // A one-shot PING confirms reachability at boot; the reply is logged when the loop runs.
    cmd(srv, &["PING"], |_srv, r| match r {
        Ok(_) => eprintln!("echoircd: redis reachable (PING ok)"),
        Err(e) => eprintln!("echoircd: redis unreachable at boot: {e}"),
    });
}

/// A persistent connection to Redis: a buffered reader + the raw stream for writes.
struct Conn {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl Conn {
    fn connect(cfg: &RedisConfig) -> Result<Conn, String> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let sa = addr
            .to_socket_addrs()
            .map_err(|e| format!("redis: resolve {addr}: {e}"))?
            .next()
            .ok_or_else(|| format!("redis: no address for {addr}"))?;
        let s = TcpStream::connect_timeout(&sa, cfg.connect_timeout)
            .map_err(|e| format!("redis: connect {addr}: {e}"))?;
        let _ = s.set_read_timeout(Some(cfg.io_timeout));
        let _ = s.set_write_timeout(Some(cfg.io_timeout));
        let _ = s.set_nodelay(true);
        let w = s.try_clone().map_err(|e| format!("redis: clone: {e}"))?;
        let mut conn = Conn {
            r: BufReader::new(s),
            w,
        };
        if !cfg.password.is_empty() {
            let reply = conn
                .command(&[b"AUTH".to_vec(), cfg.password.clone().into_bytes()])
                .map_err(|e| format!("redis: AUTH: {e}"))?;
            if let Value::Error(e) = reply {
                return Err(format!("redis: AUTH failed: {e}"));
            }
        }
        if cfg.db != 0 {
            let reply = conn
                .command(&[b"SELECT".to_vec(), cfg.db.to_string().into_bytes()])
                .map_err(|e| format!("redis: SELECT: {e}"))?;
            if let Value::Error(e) = reply {
                return Err(format!("redis: SELECT failed: {e}"));
            }
        }
        Ok(conn)
    }

    /// Send one command and read its reply. Transport failures surface as `Err`; a
    /// Redis logical error (`-ERR …`) comes back as `Ok(Value::Error(_))`.
    fn command(&mut self, args: &[Vec<u8>]) -> std::io::Result<Value> {
        self.w.write_all(&resp::encode(args))?;
        self.w.flush()?;
        resp::read_reply(&mut self.r)
    }
}

/// One persistent worker: owns a connection, pulls requests off the shared queue, runs
/// each command off the core, and injects the reply as an Event. A dead connection is
/// transparently reconnected once per request; a panic can't kill the worker.
fn run_worker(cfg: RedisConfig, queue: Queue, core_tx: SyncSender<Event>) {
    let mut conn: Option<Conn> = None;
    loop {
        let req = {
            let (lock, cv) = &*queue;
            let mut q = lock.lock().unwrap_or_else(|e| e.into_inner());
            while q.is_empty() {
                q = cv.wait(q).unwrap_or_else(|e| e.into_inner());
            }
            let Some(r) = q.pop_front() else { continue };
            r
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            execute(&mut conn, &cfg, &req)
        }))
        .unwrap_or_else(|_| {
            conn = None;
            Err("redis: worker recovered from a panicking command".into())
        });
        if core_tx
            .send(Event::RedisResult {
                id: req.id,
                result,
            })
            .is_err()
        {
            break; // core is gone — shutting down
        }
    }
}

/// Run one command: (re)connect if needed, then send. A transport error may just be a
/// connection the server dropped while idle, so reconnect and retry once.
fn execute(conn: &mut Option<Conn>, cfg: &RedisConfig, req: &Req) -> RedisResult {
    for attempt in 0..2 {
        if conn.is_none() {
            match Conn::connect(cfg) {
                Ok(c) => *conn = Some(c),
                Err(_) if attempt == 0 => continue,
                Err(e) => return Err(e),
            }
        }
        let c = conn.as_mut().unwrap();
        match c.command(&req.args) {
            Ok(Value::Error(e)) => return Err(format!("redis: {e}")),
            Ok(v) => return Ok(v),
            Err(_) if attempt == 0 => {
                *conn = None; // maybe a dropped idle connection — retry once
                continue;
            }
            Err(e) => return Err(format!("redis: {e}")),
        }
    }
    Err("redis: command failed".into())
}

/// Submit a Redis command; the callback runs later on the core with `&mut Server`. If
/// Redis isn't configured, the callback fires immediately with an error.
pub fn cmd<F>(srv: &mut Server, args: &[&str], cb: F)
where
    F: FnOnce(&mut Server, RedisResult) + Send + 'static,
{
    dispatch(srv, args.iter().map(|a| a.as_bytes().to_vec()).collect(), Some(Box::new(cb)));
}

/// Fire-and-forget command (reply discarded) — for cache writes, counters, PUBLISH.
pub fn fire(srv: &mut Server, args: &[&str]) {
    dispatch(srv, args.iter().map(|a| a.as_bytes().to_vec()).collect(), None);
}

/// PUBLISH `payload` to `channel` — the event bus. Fire-and-forget.
pub fn publish(srv: &mut Server, channel: &str, payload: &str) {
    dispatch(
        srv,
        vec![
            b"PUBLISH".to_vec(),
            channel.as_bytes().to_vec(),
            payload.as_bytes().to_vec(),
        ],
        None,
    );
}

/// Whether the Redis subsystem is configured/active.
pub fn active(srv: &Server) -> bool {
    srv.ext.get::<State>().is_some()
}

/// Publish a tab-separated event line to the configured bus channel
/// (`redis_event_channel`, default `echoircd:events`). A no-op — with no config read or
/// allocation — when Redis is inactive, so callers on hot paths pay nothing when it's off.
pub fn publish_event(srv: &mut Server, fields: &[&str]) {
    if !active(srv) {
        return;
    }
    let channel = srv
        .conf("redis_event_channel")
        .unwrap_or("echoircd:events")
        .to_string();
    publish(srv, &channel, &fields.join("\t"));
}

fn dispatch(srv: &mut Server, args: Vec<Vec<u8>>, cb: Option<Callback>) {
    let target = srv.ext.get::<State>().map(|st| (st.queue.clone(), st.queue_max));
    let Some((queue, max)) = target else {
        if let Some(cb) = cb {
            cb(srv, Err("redis: not configured (set redis_host)".into()));
        }
        return;
    };
    let id = match cb {
        Some(cb) => {
            let st = srv.ext.get_mut::<State>().expect("state present");
            let id = st.next_id;
            st.next_id = st.next_id.wrapping_add(1).max(1);
            st.pending.insert(id, cb);
            id
        }
        None => 0, // fire-and-forget
    };
    if !submit(&queue, Req { id, args }, max) && id != 0 {
        // backlog full — hand the callback its error rather than dropping it
        if let Some(cb) = srv
            .ext
            .get_mut::<State>()
            .and_then(|st| st.pending.remove(&id))
        {
            cb(srv, Err("redis: overloaded — command rejected (queue full)".into()));
        }
    }
}

fn submit(queue: &Queue, req: Req, max: usize) -> bool {
    let (lock, cv) = &**queue;
    let Ok(mut q) = lock.lock() else {
        return false;
    };
    if q.len() >= max {
        return false;
    }
    q.push_back(req);
    cv.notify_one();
    true
}

/// Deliver a completed command to its waiting callback. Called by the core when it
/// receives an [`Event::RedisResult`].
pub fn on_result(srv: &mut Server, id: u64, result: RedisResult) {
    if id == 0 {
        if let Err(e) = result {
            eprintln!("echoircd: redis command failed: {e}");
        }
        return;
    }
    let cb = srv
        .ext
        .get_mut::<State>()
        .and_then(|st| st.pending.remove(&id));
    if let Some(cb) = cb {
        cb(srv, result);
    }
}
