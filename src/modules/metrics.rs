//! metrics — an optional Prometheus/OpenMetrics endpoint. Enable with
//! `metrics_bind = 127.0.0.1:9100` in the config (off by default).
//!
//! Counters live in a process-wide `Arc<Metrics>` of atomics: the core bumps them
//! inline (a relaxed atomic add, no lock, no event round-trip), and a tiny HTTP
//! thread reads them on scrape. Gauges (current users/channels/servers) are
//! republished each tick by the core, which owns that state.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

use crate::config::Config;

/// Every metric echoircd exposes. Counters only ever increase; gauges are set to
/// the live count each tick.
#[derive(Default)]
pub struct Metrics {
    // counters (monotonic)
    pub commands: AtomicU64,
    pub messages: AtomicU64,
    pub connects: AtomicU64,
    pub pgsql_queries: AtomicU64,
    pub pgsql_errors: AtomicU64,
    pub pgsql_dropped: AtomicU64,
    // gauges (republished each tick)
    pub users: AtomicU64,
    pub channels: AtomicU64,
    pub servers: AtomicU64,
    pub links: AtomicU64,
    pub pgsql_queue_depth: AtomicU64,
}

static METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();

/// The shared metrics handle (created on first use). The core and the HTTP scrape
/// thread both call this, so they see the same atomics.
pub fn handle() -> Arc<Metrics> {
    METRICS.get_or_init(|| Arc::new(Metrics::default())).clone()
}

/// Render the current values in OpenMetrics/Prometheus text exposition format.
fn render(m: &Metrics) -> String {
    let mut o = String::new();
    let counter = |o: &mut String, name: &str, help: &str, v: u64| {
        o.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"
        ));
    };
    let gauge = |o: &mut String, name: &str, help: &str, v: u64| {
        o.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}\n"
        ));
    };
    counter(
        &mut o,
        "echoircd_commands_total",
        "Commands dispatched.",
        m.commands.load(Relaxed),
    );
    counter(
        &mut o,
        "echoircd_messages_total",
        "PRIVMSG/NOTICE handled.",
        m.messages.load(Relaxed),
    );
    counter(
        &mut o,
        "echoircd_connects_total",
        "Client registrations completed.",
        m.connects.load(Relaxed),
    );
    gauge(
        &mut o,
        "echoircd_users",
        "Registered users online.",
        m.users.load(Relaxed),
    );
    gauge(
        &mut o,
        "echoircd_channels",
        "Channels in existence.",
        m.channels.load(Relaxed),
    );
    gauge(
        &mut o,
        "echoircd_servers",
        "Servers known on the network.",
        m.servers.load(Relaxed),
    );
    gauge(
        &mut o,
        "echoircd_links",
        "Direct server links.",
        m.links.load(Relaxed),
    );
    counter(
        &mut o,
        "echoircd_pgsql_queries_total",
        "Database queries executed by the worker pool.",
        m.pgsql_queries.load(Relaxed),
    );
    counter(
        &mut o,
        "echoircd_pgsql_errors_total",
        "Database queries that returned an error.",
        m.pgsql_errors.load(Relaxed),
    );
    counter(
        &mut o,
        "echoircd_pgsql_dropped_total",
        "Database queries refused because the submit queue was full.",
        m.pgsql_dropped.load(Relaxed),
    );
    gauge(
        &mut o,
        "echoircd_pgsql_queue_depth",
        "Database queries currently waiting in the submit queue.",
        m.pgsql_queue_depth.load(Relaxed),
    );
    o
}

/// Start the scrape endpoint if `metrics_bind` is configured. Serves any GET with
/// the exposition text; it carries no secrets, so bind it somewhere private.
pub fn maybe_start(cfg: &Config) {
    let Some(bind) = cfg
        .raw
        .get("metrics_bind")
        .and_then(|v| v.last())
        .filter(|s| !s.is_empty())
    else {
        return;
    };
    let bind = bind.to_string();
    let metrics = handle();
    match TcpListener::bind(&bind) {
        Ok(listener) => {
            eprintln!("echoircd metrics (OpenMetrics) on {bind}");
            std::thread::spawn(move || serve(listener, metrics));
        }
        Err(e) => eprintln!("echoircd: cannot bind metrics {bind}: {e}"),
    }
}

fn serve(listener: TcpListener, metrics: Arc<Metrics>) {
    for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        // Bound how long one (possibly slow/hostile) client can hold this
        // single-threaded scrape loop — without a timeout a client that connects
        // and never sends would block every future scrape (slowloris).
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(5)));
        // read (and ignore) the request head, then reply — this is a scrape, no routing
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let body = render(&metrics);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = s.write_all(resp.as_bytes());
    }
}
