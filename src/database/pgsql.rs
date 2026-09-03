//! A from-scratch, blocking PostgreSQL v3 client. It runs on a database worker
//! thread (never the core), so a slow query or a stalled server can't freeze the
//! event loop. Supports trust / cleartext / MD5 / SCRAM-SHA-256 auth and optional
//! TLS, and executes parameterized queries via the extended protocol (so callers
//! never build SQL by string-concatenation → no injection).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::proto::{self, Auth, Backend};
use super::scram::{md5_password, Scram};

/// Connection settings for one PostgreSQL server.
#[derive(Clone)]
pub struct PgConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
    pub tls: bool,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

// A hand-written Debug that never prints the password, so the connection config is
// safe to log or embed in an error/panic message.
impl std::fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &"***")
            .field("tls", &self.tls)
            .field("connect_timeout", &self.connect_timeout)
            .field("io_timeout", &self.io_timeout)
            .finish()
    }
}

/// The result of a query: column names, the rows (text values, `None` = SQL NULL),
/// and the affected/returned row count from the CommandComplete tag.
#[derive(Debug, Default)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub affected: u64,
}

/// A query failure, split so the worker can tell a recoverable SQL error (the
/// connection stays usable) from a transport error (reconnect before the next query).
#[derive(Debug)]
pub enum QueryError {
    Sql(String),
    Io(String),
}

impl QueryError {
    pub fn into_message(self) -> String {
        match self {
            QueryError::Sql(s) | QueryError::Io(s) => s,
        }
    }
    pub fn is_io(&self) -> bool {
        matches!(self, QueryError::Io(_))
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

pub struct PgConn {
    stream: Box<dyn Stream>,
}

fn err<T>(msg: impl Into<String>) -> Result<T, String> {
    Err(msg.into())
}

impl PgConn {
    /// Connect, negotiate TLS if requested, run the startup + authentication
    /// handshake, and drain to the first ReadyForQuery.
    pub fn connect(cfg: &PgConfig) -> Result<PgConn, String> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let sock = addr
            .to_socket_addrs_first()
            .and_then(|a| TcpStream::connect_timeout(&a, cfg.connect_timeout))
            .map_err(|e| format!("pgsql: connect {addr}: {e}"))?;
        sock.set_read_timeout(Some(cfg.io_timeout)).ok();
        sock.set_write_timeout(Some(cfg.io_timeout)).ok();
        sock.set_nodelay(true).ok();

        let stream: Box<dyn Stream> = if cfg.tls {
            maybe_tls(sock, &cfg.host)?
        } else {
            Box::new(sock)
        };

        let mut conn = PgConn { stream };
        conn.write(&proto::startup(&cfg.user, &cfg.database))?;
        conn.authenticate(cfg)?;
        conn.drain_to_ready()?;
        // Ask the server to cancel a runaway query itself, matched to our socket
        // read timeout — so a slow query surfaces as a clean SQL error on a still-
        // usable connection instead of a socket timeout that forces a reconnect.
        let ms = cfg.io_timeout.as_millis();
        if ms > 0 {
            conn.query(&format!("SET statement_timeout = {ms}"), &[])
                .map_err(QueryError::into_message)?;
        }
        Ok(conn)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(bytes)
            .and_then(|_| self.stream.flush())
            .map_err(|e| format!("pgsql: write: {e}"))
    }

    fn read(&mut self) -> Result<Backend, String> {
        proto::read_message(&mut self.stream).map_err(|e| format!("pgsql: read: {e}"))
    }

    /// The authentication exchange — loops until AuthenticationOk or an error.
    fn authenticate(&mut self, cfg: &PgConfig) -> Result<(), String> {
        loop {
            match self.read()? {
                Backend::Auth(Auth::Ok) => return Ok(()),
                Backend::Auth(Auth::Cleartext) => {
                    self.write(&proto::password(&cfg.password))?;
                }
                Backend::Auth(Auth::Md5(salt)) => {
                    let token = md5_password(&cfg.user, &cfg.password, &salt);
                    self.write(&proto::password(&token))?;
                }
                Backend::Auth(Auth::Sasl(mechs)) => {
                    if !mechs.iter().any(|m| m == "SCRAM-SHA-256") {
                        return err(format!("pgsql: no supported SASL mechanism in {mechs:?}"));
                    }
                    self.scram_exchange(cfg)?;
                }
                Backend::Auth(Auth::Other(n)) => {
                    return err(format!("pgsql: unsupported auth method {n}"));
                }
                Backend::Error(e) => return err(e),
                Backend::Notice(_) | Backend::ParameterStatus(..) => {}
                other => return err(format!("pgsql: unexpected message during auth: {other:?}")),
            }
        }
    }

    fn scram_exchange(&mut self, cfg: &PgConfig) -> Result<(), String> {
        let mut scram = Scram::new();
        self.write(&proto::sasl_initial("SCRAM-SHA-256", &scram.client_first()))?;
        // server-first
        let server_first = match self.read()? {
            Backend::Auth(Auth::SaslContinue(d)) => String::from_utf8_lossy(&d).into_owned(),
            Backend::Error(e) => return err(e),
            other => return err(format!("pgsql: expected SASLContinue, got {other:?}")),
        };
        let client_final = scram.client_final(&cfg.password, &server_first)?;
        self.write(&proto::sasl_response(&client_final))?;
        // server-final
        match self.read()? {
            Backend::Auth(Auth::SaslFinal(d)) => {
                scram.verify(&String::from_utf8_lossy(&d))?;
            }
            Backend::Error(e) => return err(e),
            other => return err(format!("pgsql: expected SASLFinal, got {other:?}")),
        }
        Ok(())
    }

    /// Consume ParameterStatus / BackendKeyData / etc. up to the ReadyForQuery that
    /// ends the startup phase.
    fn drain_to_ready(&mut self) -> Result<(), String> {
        loop {
            match self.read()? {
                Backend::ReadyForQuery(_) => return Ok(()),
                Backend::Error(e) => return err(e),
                _ => {}
            }
        }
    }

    /// Run one parameterized statement (extended protocol: Parse/Bind/Describe/
    /// Execute/Sync). `params` are text values; `None` binds a SQL NULL.
    pub fn query(
        &mut self,
        sql: &str,
        params: &[Option<Vec<u8>>],
    ) -> Result<QueryResult, QueryError> {
        let mut batch = Vec::new();
        batch.extend_from_slice(&proto::parse(sql));
        batch.extend_from_slice(&proto::bind(params));
        batch.extend_from_slice(&proto::describe_portal());
        batch.extend_from_slice(&proto::execute());
        batch.extend_from_slice(&proto::sync());
        self.write(&batch).map_err(QueryError::Io)?;

        let mut out = QueryResult::default();
        let mut failure: Option<String> = None;
        loop {
            match self.read().map_err(QueryError::Io)? {
                Backend::RowDescription(cols) => out.columns = cols,
                Backend::DataRow(vals) => out.rows.push(vals),
                Backend::CommandComplete(tag) => out.affected = affected_from_tag(&tag),
                // On error the server discards messages until our Sync; keep reading
                // until ReadyForQuery so the connection stays usable for the next query.
                Backend::Error(e) => failure = Some(e),
                Backend::ReadyForQuery(_) => break,
                _ => {}
            }
        }
        match failure {
            Some(e) => Err(QueryError::Sql(e)),
            None => Ok(out),
        }
    }

    /// Run several parameterized statements as one transaction on this connection: any
    /// failure rolls the whole batch back, so a crash or error can't leave a partially
    /// written table. Used for atomic snapshot replaces of a normalized store.
    pub fn query_tx(&mut self, stmts: &[(String, Vec<Option<Vec<u8>>>)]) -> Result<(), QueryError> {
        self.query("BEGIN", &[])?;
        for (sql, params) in stmts {
            if let Err(e) = self.query(sql, params) {
                let _ = self.query("ROLLBACK", &[]);
                return Err(e);
            }
        }
        self.query("COMMIT", &[]).map(|_| ())
    }

    /// Best-effort graceful close.
    pub fn close(&mut self) {
        let _ = self.write(&proto::terminate());
    }
}

/// `"INSERT 0 3"` / `"UPDATE 2"` / `"DELETE 1"` / `"SELECT 5"` → the trailing count.
fn affected_from_tag(tag: &str) -> u64 {
    tag.split_whitespace()
        .last()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Send SSLRequest, and on the server's `S` wrap the socket in an openssl client
/// stream (encryption only — cert verification is intentionally not required, so an
/// internal DB with a self-signed cert works, matching libpq `sslmode=require`).
fn maybe_tls(sock: TcpStream, host: &str) -> Result<Box<dyn Stream>, String> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut s = sock;
    s.write_all(&proto::ssl_request())
        .map_err(|e| format!("pgsql: SSLRequest: {e}"))?;
    let mut reply = [0u8; 1];
    s.read_exact(&mut reply)
        .map_err(|e| format!("pgsql: SSLRequest reply: {e}"))?;
    if reply[0] != b'S' {
        return err("pgsql: server refused TLS (set pgsql_tls no, or enable ssl on the server)");
    }
    let mut b = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| format!("pgsql: TLS init: {e}"))?;
    b.set_verify(SslVerifyMode::NONE);
    let connector = b.build();
    let mut conf = connector
        .configure()
        .map_err(|e| format!("pgsql: TLS config: {e}"))?;
    conf.set_verify_hostname(false);
    let tls = conf
        .connect(host, s)
        .map_err(|e| format!("pgsql: TLS handshake: {e}"))?;
    Ok(Box::new(tls))
}

/// Tiny helper: resolve `host:port` to the first socket address.
trait FirstAddr {
    fn to_socket_addrs_first(&self) -> io::Result<std::net::SocketAddr>;
}
impl FirstAddr for String {
    fn to_socket_addrs_first(&self) -> io::Result<std::net::SocketAddr> {
        use std::net::ToSocketAddrs;
        self.to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affected_count_parses_command_tags() {
        assert_eq!(affected_from_tag("INSERT 0 3"), 3);
        assert_eq!(affected_from_tag("UPDATE 2"), 2);
        assert_eq!(affected_from_tag("DELETE 1"), 1);
        assert_eq!(affected_from_tag("SELECT 5"), 5);
        assert_eq!(affected_from_tag("CREATE TABLE"), 0);
    }

    // Live round-trip against a real PostgreSQL. Ignored by default (needs a DB);
    // run with the env vars set:
    //   PG_TEST_HOST=127.0.0.1 PG_TEST_USER=echoircd_t PG_TEST_PASS=... \
    //   PG_TEST_DB=echoircd_t cargo test --lib database::pgsql -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_roundtrip() {
        let cfg = PgConfig {
            host: std::env::var("PG_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("PG_TEST_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(5432),
            database: std::env::var("PG_TEST_DB").unwrap_or_else(|_| "echoircd_t".into()),
            user: std::env::var("PG_TEST_USER").unwrap_or_else(|_| "echoircd_t".into()),
            password: std::env::var("PG_TEST_PASS").unwrap_or_default(),
            tls: std::env::var("PG_TEST_TLS").is_ok(),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
        };
        let mut c = PgConn::connect(&cfg).expect("connect+auth");
        c.query("CREATE TEMP TABLE t (k text primary key, v text)", &[])
            .unwrap();
        let r = c
            .query(
                "INSERT INTO t (k,v) VALUES ($1,$2)",
                &[Some(b"hello".to_vec()), Some(b"world".to_vec())],
            )
            .unwrap();
        assert_eq!(r.affected, 1);
        let r = c
            .query("SELECT k,v FROM t WHERE k=$1", &[Some(b"hello".to_vec())])
            .unwrap();
        assert_eq!(r.columns, vec!["k", "v"]);
        assert_eq!(
            r.rows,
            vec![vec![Some("hello".into()), Some("world".into())]]
        );

        // transactional snapshot replace: a bad row rolls the whole batch back
        c.query("CREATE TEMP TABLE rep (addr text primary key, score bigint)", &[])
            .unwrap();
        c.query_tx(&[
            ("INSERT INTO rep (addr, score) VALUES ($1, $2)".into(), vec![Some(b"a".to_vec()), Some(b"1".to_vec())]),
            ("INSERT INTO rep (addr, score) VALUES ($1, $2)".into(), vec![Some(b"b".to_vec()), Some(b"2".to_vec())]),
        ])
        .expect("commit");
        assert_eq!(c.query("SELECT count(*) FROM rep", &[]).unwrap().rows[0][0], Some("2".into()));
        // a duplicate key mid-batch must abort and leave the table unchanged
        assert!(c
            .query_tx(&[
                ("DELETE FROM rep".into(), vec![]),
                ("INSERT INTO rep (addr, score) VALUES ($1, $2)".into(), vec![Some(b"a".to_vec()), Some(b"9".to_vec())]),
                ("INSERT INTO rep (addr, score) VALUES ($1, $2)".into(), vec![Some(b"a".to_vec()), Some(b"9".to_vec())]),
            ])
            .is_err());
        assert_eq!(c.query("SELECT count(*) FROM rep", &[]).unwrap().rows[0][0], Some("2".into()));
        c.close();
    }
}
