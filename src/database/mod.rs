//! Native, non-blocking SQL database subsystem.
//!
//! A worker-thread pool holds persistent database connections and runs every query
//! off-core, so a slow query or a stalled database can never freeze the event loop
//! (the same discipline as the DNS resolver and the disk writer). A module submits
//! a query with a callback; the pool runs it on a worker, and the result is
//! delivered back to the core as an [`Event::SqlResult`] where the callback runs
//! with `&mut Server`.
//!
//! `pgsql` is the first backend: a from-scratch PostgreSQL v3 wire-protocol client
//! (no `unsafe`, no libpq, no async runtime), on the openssl the daemon already
//! links for TLS and SCRAM-SHA-256 auth.
//!
//! ## Using it from a module
//! ```ignore
//! use crate::database;
//! database::query(
//!     srv,
//!     "INSERT INTO kv (k, v) VALUES ($1, $2) \
//!      ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
//!     vec![key.into(), value.into()],       // parameters — never string-concatenated
//!     move |srv, result| match result {     // runs back on the core with &mut Server
//!         Ok(rows) => { /* rows.get(0, "v"), rows.affected(), … */ }
//!         Err(e)   => { srv.log(&format!("db: {e}")); }
//!     },
//! );
//! ```

pub mod pgsql;
pub mod proto;
pub mod scram;

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::ircd::Event;
use crate::server::Server;
use pgsql::{PgConfig, PgConn, QueryResult};

/// A bind parameter. Everything is sent to PostgreSQL in text format; the server
/// coerces it to the column type. `impl From` conversions make call sites terse.
pub enum SqlValue {
    Null,
    Text(String),
    Int(i64),
    Bool(bool),
}

impl SqlValue {
    fn into_param(self) -> Option<Vec<u8>> {
        match self {
            SqlValue::Null => None,
            SqlValue::Text(s) => Some(s.into_bytes()),
            SqlValue::Int(n) => Some(n.to_string().into_bytes()),
            SqlValue::Bool(b) => Some(if b { b"t".to_vec() } else { b"f".to_vec() }),
        }
    }
}

impl From<&str> for SqlValue {
    fn from(s: &str) -> Self {
        SqlValue::Text(s.to_string())
    }
}
impl From<String> for SqlValue {
    fn from(s: String) -> Self {
        SqlValue::Text(s)
    }
}
impl From<i64> for SqlValue {
    fn from(n: i64) -> Self {
        SqlValue::Int(n)
    }
}
impl From<i32> for SqlValue {
    fn from(n: i32) -> Self {
        SqlValue::Int(n as i64)
    }
}
impl From<u64> for SqlValue {
    fn from(n: u64) -> Self {
        SqlValue::Int(n as i64)
    }
}
impl From<bool> for SqlValue {
    fn from(b: bool) -> Self {
        SqlValue::Bool(b)
    }
}
impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        v.map(Into::into).unwrap_or(SqlValue::Null)
    }
}

/// A query result: column names, the rows (text values, `None` = SQL NULL), and the
/// affected/returned row count from the CommandComplete tag.
pub struct SqlRows {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    affected: u64,
}

impl From<QueryResult> for SqlRows {
    fn from(q: QueryResult) -> Self {
        SqlRows {
            columns: q.columns,
            rows: q.rows,
            affected: q.affected,
        }
    }
}

impl SqlRows {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    /// Rows affected (INSERT/UPDATE/DELETE) or returned (SELECT).
    pub fn affected(&self) -> u64 {
        self.affected
    }
    /// The value at `(row, column-name)`, or `None` if out of range or SQL NULL.
    pub fn get(&self, row: usize, col: &str) -> Option<&str> {
        let ci = self.columns.iter().position(|c| c == col)?;
        self.rows.get(row)?.get(ci)?.as_deref()
    }
    /// The value at `(row, column-index)`.
    pub fn at(&self, row: usize, col: usize) -> Option<&str> {
        self.rows.get(row)?.get(col)?.as_deref()
    }
}

/// What a completed query hands back: the rows, or a human-readable error string.
pub type SqlResult = Result<SqlRows, String>;
type Callback = Box<dyn FnOnce(&mut Server, SqlResult) + Send>;

struct SqlRequest {
    id: u64,
    sql: String,
    params: Vec<Option<Vec<u8>>>,
}

type Queue = Arc<(Mutex<VecDeque<SqlRequest>>, Condvar)>;

/// Per-server database state (stored in `Server.ext`): the submit queue shared with
/// the worker pool, plus the in-core map of pending callbacks keyed by request id.
struct SqlState {
    queue: Queue,
    pending: HashMap<u64, Callback>,
    next_id: u64,
}

/// Read `pgsql_*` config. Returns `None` (subsystem disabled) unless `pgsql_host`
/// is set.
fn config(srv: &Server) -> Option<(PgConfig, usize)> {
    let host = srv.conf("pgsql_host")?.trim().to_string();
    if host.is_empty() {
        return None;
    }
    let user = srv.conf("pgsql_user").unwrap_or("postgres").to_string();
    let database = srv
        .conf("pgsql_database")
        .or_else(|| srv.conf("pgsql_db"))
        .map(str::to_string)
        .unwrap_or_else(|| user.clone());
    let cfg = PgConfig {
        host,
        port: srv.conf_num("pgsql_port", 5432u16),
        database,
        user,
        password: srv
            .conf("pgsql_password")
            .or_else(|| srv.conf("pgsql_pass"))
            .unwrap_or("")
            .to_string(),
        tls: srv.conf_bool("pgsql_tls", false),
        connect_timeout: Duration::from_secs(srv.conf_num("pgsql_connect_timeout", 5u64)),
        io_timeout: Duration::from_secs(srv.conf_num("pgsql_timeout", 30u64)),
    };
    let pool = srv.conf_num("pgsql_pool", 2usize).clamp(1, 16);
    Some((cfg, pool))
}

/// Spawn the worker pool at startup if a database is configured. Called once from
/// `Ircd::new` after the Server exists.
pub fn init(srv: &mut Server) {
    let Some((cfg, pool)) = config(srv) else {
        return; // no pgsql_host → subsystem stays inert
    };
    ensure_schema(&cfg); // the central store table must exist before any load/save
    let queue: Queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
    for _ in 0..pool {
        let (q, tx, c) = (queue.clone(), srv.event_tx.clone(), cfg.clone());
        std::thread::spawn(move || run_worker(c, q, tx));
    }
    eprintln!(
        "echoircd: pgsql pool ({pool}) → {}@{}:{}/{} (tls={})",
        cfg.user, cfg.host, cfg.port, cfg.database, cfg.tls
    );
    srv.ext.set(SqlState {
        queue,
        pending: HashMap::new(),
        next_id: 1,
    });
}

/// One persistent worker: owns a connection, pulls requests off the shared queue,
/// runs each query (blocking — but off the core), and injects the result as an
/// Event. A dead connection is transparently reconnected once per request.
fn run_worker(cfg: PgConfig, queue: Queue, core_tx: Sender<Event>) {
    let mut conn: Option<PgConn> = None;
    loop {
        let req = {
            let (lock, cv) = &*queue;
            let mut q = lock.lock().unwrap_or_else(|e| e.into_inner());
            while q.is_empty() {
                q = cv.wait(q).unwrap_or_else(|e| e.into_inner());
            }
            match q.pop_front() {
                Some(r) => r,
                None => continue,
            }
        };
        let result: SqlResult = 'run: {
            for attempt in 0..2 {
                if conn.is_none() {
                    match PgConn::connect(&cfg) {
                        Ok(c) => conn = Some(c),
                        Err(e) => break 'run Err(e),
                    }
                }
                match conn.as_mut().unwrap().query(&req.sql, &req.params) {
                    Ok(qr) => break 'run Ok(SqlRows::from(qr)),
                    // a transport error may just be a connection the server dropped
                    // while idle — reconnect and retry the query once, transparently
                    Err(e) if e.is_io() && attempt == 0 => {
                        conn = None;
                        continue;
                    }
                    Err(e) => break 'run Err(e.into_message()),
                }
            }
            Err("pgsql: query failed".into())
        };
        if core_tx
            .send(Event::SqlResult { id: req.id, result })
            .is_err()
        {
            break; // core is gone — the daemon is shutting down
        }
    }
}

/// Submit a parameterized query. The callback runs later on the core thread with
/// `&mut Server` and the result. If no database is configured, the callback is
/// invoked immediately with an error (so callers always get a reply).
pub fn query<F>(srv: &mut Server, sql: &str, params: Vec<SqlValue>, cb: F)
where
    F: FnOnce(&mut Server, SqlResult) + Send + 'static,
{
    let queue = srv.ext.get::<SqlState>().map(|st| st.queue.clone());
    let Some(queue) = queue else {
        cb(
            srv,
            Err("pgsql: database not configured (set pgsql_host)".into()),
        );
        return;
    };
    let id = {
        let st = srv.ext.get_mut::<SqlState>().expect("state present");
        let id = st.next_id;
        st.next_id = st.next_id.wrapping_add(1);
        st.pending.insert(id, Box::new(cb));
        id
    };
    let params: Vec<Option<Vec<u8>>> = params.into_iter().map(SqlValue::into_param).collect();
    submit(
        &queue,
        SqlRequest {
            id,
            sql: sql.to_string(),
            params,
        },
    );
}

/// Push a request onto the shared queue and wake one idle worker.
fn submit(queue: &Queue, req: SqlRequest) {
    let (lock, cv) = &**queue;
    if let Ok(mut q) = lock.lock() {
        q.push_back(req);
        cv.notify_one();
    }
}

/// Deliver a completed query to its waiting callback. Called by the core when it
/// receives an [`Event::SqlResult`].
pub fn on_result(srv: &mut Server, id: u64, result: SqlResult) {
    let cb = srv
        .ext
        .get_mut::<SqlState>()
        .and_then(|st| st.pending.remove(&id));
    match cb {
        Some(cb) => cb(srv, result),
        // id 0 (or an already-taken id): a fire-and-forget write — surface a failure
        None => {
            if let Err(e) = result {
                eprintln!("echoircd: pgsql write failed: {e}");
            }
        }
    }
}

// ── centralized store ────────────────────────────────────────────────────────
// The drop-in replacement for the scattered flat `.db` files: every module's whole
// serialized blob is one row in `echoircd_store(name, content, updated)`. Load the
// blob synchronously at startup, persist it asynchronously (off-core) on change.

const STORE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS echoircd_store \
     (name text PRIMARY KEY, content text NOT NULL, updated bigint NOT NULL DEFAULT 0)";
const STORE_UPSERT: &str =
    "INSERT INTO echoircd_store (name, content, updated) VALUES ($1, $2, $3) \
     ON CONFLICT (name) DO UPDATE SET content = EXCLUDED.content, updated = EXCLUDED.updated";

/// Whether a database is configured at all (the query API is available).
pub fn is_enabled(srv: &Server) -> bool {
    srv.ext.get::<SqlState>().is_some()
}

/// Whether persisted stores should live in the database. The database can be
/// *configured* (for the query API / a future sqlauth) yet persistence still
/// defaults to **flat files** — opt in explicitly with `store_backend = pgsql`.
pub fn stores_in_db(srv: &Server) -> bool {
    is_enabled(srv)
        && srv
            .conf("store_backend")
            .map(|v| v.eq_ignore_ascii_case("pgsql") || v.eq_ignore_ascii_case("postgres"))
            .unwrap_or(false)
}

/// Create the store table if missing (synchronous, at startup). Best-effort.
fn ensure_schema(cfg: &PgConfig) {
    let r = (|| -> Result<(), String> {
        let mut c = PgConn::connect(cfg)?;
        let out = c.query(STORE_SCHEMA, &[]).map_err(|e| e.into_message());
        c.close();
        out.map(|_| ())
    })();
    if let Err(e) = r {
        eprintln!("echoircd: pgsql store schema init failed: {e}");
    }
}

/// Load a store's blob, **database-first**, seeding the DB from the flat-file
/// `fallback` the first time it's empty (auto-migration). Synchronous — called at
/// startup before the event loop runs, where blocking is fine. On any DB error it
/// falls back to `fallback`, so a database hiccup never loses the on-disk data.
pub fn store_load_or_seed(srv: &Server, name: &str, fallback: Option<String>) -> Option<String> {
    if !stores_in_db(srv) {
        return fallback; // flat-file backend (the default)
    }
    let Some((cfg, _)) = config(srv) else {
        return fallback;
    };
    let loaded = (|| -> Result<Option<String>, String> {
        let mut c = PgConn::connect(&cfg)?;
        let key = Some(name.as_bytes().to_vec());
        let sel = c
            .query(
                "SELECT content FROM echoircd_store WHERE name = $1",
                &[key.clone()],
            )
            .map_err(|e| e.into_message())?;
        let existing = sel
            .rows
            .into_iter()
            .next()
            .and_then(|row| row.into_iter().next().flatten());
        let result = match existing {
            Some(content) => Some(content), // the DB is authoritative
            None => {
                // nothing stored yet — migrate the flat file in (synchronously, so
                // it lands before any later async save can race it)
                if let Some(ref content) = fallback {
                    let now = crate::server::now() as i64;
                    c.query(
                        STORE_UPSERT,
                        &[
                            key,
                            Some(content.clone().into_bytes()),
                            Some(now.to_string().into_bytes()),
                        ],
                    )
                    .map_err(|e| e.into_message())?;
                }
                fallback.clone()
            }
        };
        c.close();
        Ok(result)
    })();
    match loaded {
        Ok(v) => v,
        Err(e) => {
            eprintln!("echoircd: pgsql store load '{name}' failed ({e}); using flat file");
            fallback
        }
    }
}

/// Persist a store's blob asynchronously — fire-and-forget: it runs on the worker
/// pool and never blocks the core, and needs only `&Server` (no callback to
/// register). Request id 0 is reserved for these callback-less writes; a failure is
/// still logged by [`on_result`].
pub fn store_save(srv: &Server, name: &str, content: String) {
    let Some(st) = srv.ext.get::<SqlState>() else {
        return; // not configured — the caller keeps using its flat file
    };
    let params = vec![
        Some(name.as_bytes().to_vec()),
        Some(content.into_bytes()),
        Some((crate::server::now() as i64).to_string().into_bytes()),
    ];
    submit(
        &st.queue,
        SqlRequest {
            id: 0, // fire-and-forget
            sql: STORE_UPSERT.to_string(),
            params,
        },
    );
}

/// Uniform load for a persisted store: the central DB when `store_backend = pgsql`
/// (seeded from the flat file on first run), else the flat file. The flat file is
/// always read so it can seed / back a database fallback. `None` ⇒ nothing yet.
pub fn persist_load(srv: &Server, name: &str, path: &str) -> Option<String> {
    let file = std::fs::read_to_string(path).ok();
    store_load_or_seed(srv, name, file)
}

/// Uniform save for a persisted store: to the central DB when `store_backend =
/// pgsql`, else the flat file — both off-core, so neither can stall the core.
pub fn persist_save(srv: &Server, name: &str, path: &str, content: String) {
    if stores_in_db(srv) {
        store_save(srv, name, content);
    } else {
        srv.disk_write(path.to_string(), content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlvalue_text_encoding() {
        assert_eq!(SqlValue::from("hi").into_param(), Some(b"hi".to_vec()));
        assert_eq!(SqlValue::from(42i64).into_param(), Some(b"42".to_vec()));
        assert_eq!(SqlValue::from(true).into_param(), Some(b"t".to_vec()));
        assert_eq!(SqlValue::Null.into_param(), None);
        assert_eq!(SqlValue::from(None::<&str>).into_param(), None);
        assert_eq!(SqlValue::from(Some("x")).into_param(), Some(b"x".to_vec()));
    }

    // End-to-end async path: submit → worker pool → PgConn → Event::SqlResult,
    // against a real database. Ignored by default (needs PG); run with:
    //   PG_TEST_USER=echoircd_t PG_TEST_PASS=… PG_TEST_DB=echoircd_t \
    //   cargo test --lib database::tests::async_worker_roundtrip -- --ignored
    #[test]
    #[ignore]
    fn async_worker_roundtrip() {
        use std::sync::mpsc;
        let cfg = PgConfig {
            host: std::env::var("PG_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: 5432,
            database: std::env::var("PG_TEST_DB").unwrap_or_else(|_| "echoircd_t".into()),
            user: std::env::var("PG_TEST_USER").unwrap_or_else(|_| "echoircd_t".into()),
            password: std::env::var("PG_TEST_PASS").unwrap_or_default(),
            tls: false,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
        };
        let queue: Queue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn({
            let q = queue.clone();
            move || run_worker(cfg, q, tx)
        });
        submit(
            &queue,
            SqlRequest {
                id: 7,
                sql: "SELECT $1::text AS v".into(),
                params: vec![Some(b"hello".to_vec())],
            },
        );
        match rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a result event")
        {
            Event::SqlResult { id, result } => {
                assert_eq!(id, 7);
                assert_eq!(result.expect("ok").get(0, "v"), Some("hello"));
            }
            _ => panic!("expected Event::SqlResult"),
        }
    }

    #[test]
    fn sqlrows_lookup_by_name_and_index() {
        let r = SqlRows {
            columns: vec!["k".into(), "v".into()],
            rows: vec![vec![Some("key".into()), None]],
            affected: 1,
        };
        assert_eq!(r.get(0, "k"), Some("key"));
        assert_eq!(r.get(0, "v"), None); // SQL NULL
        assert_eq!(r.at(0, 0), Some("key"));
        assert_eq!(r.get(0, "missing"), None);
        assert_eq!(r.affected(), 1);
        assert!(!r.is_empty() && r.len() == 1);
    }
}
