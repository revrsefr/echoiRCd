//! echoIRCd entry point: read config, bind the plaintext (and, if configured,
//! the TLS) listener, then run the single-threaded core while the accept loops
//! feed it connections.
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use echoircd::config::Config;
use echoircd::ircd::{Event, Ircd};
use echoircd::socketengine;
use echoircd::tls::{OpensslBackend, TlsBackend};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "echoircd.conf".to_string());
    let cfg = Config::load(&path);

    // precompute the bcrypt constants off-thread so the first hash never stalls the core
    thread::spawn(echoircd::bcrypt::warm);

    eprintln!(
        "echoircd {} (network {}, server {})",
        env!("CARGO_PKG_VERSION"),
        cfg.network,
        cfg.servername
    );
    // Plaintext client listeners. `bind` is repeatable; a bare `[::]` binds IPv4+IPv6
    // (dual-stack). Bind each as a mio listener and exit only if none could bind, so an
    // unavailable family (e.g. no IPv6) degrades gracefully instead of taking us down.
    let plaintext_binds: Vec<String> = if cfg.bind.is_empty() {
        vec!["127.0.0.1:6767".to_string()]
    } else {
        cfg.bind.clone()
    };
    let mut client_listeners: Vec<mio::net::TcpListener> = Vec::new();
    for b in &plaintext_binds {
        match b.parse::<std::net::SocketAddr>() {
            Ok(a) => match mio::net::TcpListener::bind(a) {
                Ok(l) => {
                    eprintln!("echoircd plaintext on {b}");
                    client_listeners.push(l);
                }
                Err(e) => eprintln!("echoircd: cannot bind {b}: {e}"),
            },
            Err(e) => eprintln!("echoircd: bad bind address {b}: {e}"),
        }
    }
    if client_listeners.is_empty() {
        eprintln!("echoircd: no plaintext listener could bind; exiting");
        std::process::exit(1);
    }

    // global queue limits (per-class overrides layer on top of these in the reactor)
    let raw_num = |k: &str, d: usize| {
        cfg.raw
            .get(k)
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
    };
    let max_line = raw_num("max_line", socketengine::DEFAULT_MAX_LINE);
    let max_sendq = raw_num("max_sendq", socketengine::DEFAULT_MAX_SENDQ);
    // reactor-pool size (0 = auto: one worker per core, capped)
    let io_threads = raw_num("io_threads", 0);
    // reap a TLS handshake that stalls this long (0 = never); guards the TLS port
    // against connections that open but never negotiate
    let hs = raw_num("tls_handshake_timeout", 15);
    let handshake_timeout = (hs > 0).then(|| Duration::from_secs(hs as u64));
    // per-IP accept-rate limit (0 = off): drop connection-churn floods at the edge
    let accept_limiter =
        socketengine::AcceptLimiter::from_conf(raw_num("accept_rate", 0), raw_num("accept_burst", 0));
    // trusted PROXY-protocol source globs (reactor rewrites the client IP from them)
    let proxy_trust: Vec<String> = cfg.raw.get("proxy").cloned().unwrap_or_default();

    // one uid counter shared by every listener (and by CONNECT) so ids stay unique
    let counter = Arc::new(AtomicU64::new(1));

    let (tx, rx) = mpsc::channel();
    let core_cfg = cfg.clone();
    let core_tx = tx.clone(); // the core self-injects events (DNS results)
    let core_counter = counter.clone();
    // watchdog: the core stores when it started the current event into `core_busy`
    // (0 = idle); a separate thread warns if it stays stuck past `watchdog_ms`.
    let wd_base = Instant::now();
    let core_busy = Arc::new(AtomicU64::new(0));
    let watchdog_ms = raw_num("watchdog_ms", 5000) as u64; // 0 = off
    if watchdog_ms > 0 {
        let (wb, base) = (core_busy.clone(), wd_base);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(1000));
            let cur = wb.load(Ordering::Relaxed);
            if cur != 0 {
                let stuck = (base.elapsed().as_millis() as u64).saturating_sub(cur);
                if stuck > watchdog_ms {
                    eprintln!(
                        "[watchdog] core thread stuck ~{stuck}ms on one event — a handler is blocking the whole server"
                    );
                }
            }
        });
    }
    let (busy, base) = (core_busy, wd_base);
    let core = thread::spawn(move || Ircd::new(core_cfg, core_tx, core_counter).run(rx, busy, base));

    // background timer: drives ping/idle timeouts
    let tick_tx = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(echoircd::server::TICK_SECS));
        if tick_tx.send(Event::Tick).is_err() {
            break;
        }
    });

    // reactor worker pool: shared by the plaintext acceptor and the direct-TLS
    // acceptor, so client I/O (framing + TLS crypto) spreads across cores.
    let reactors =
        socketengine::spawn_reactors(tx.clone(), max_line, max_sendq, io_threads, handshake_timeout);

    // optional TLS listeners (bind_tls, repeatable + tls_cert + tls_key). A cert/bind
    // problem disables TLS but never takes the plaintext listeners down.
    if !cfg.bind_tls.is_empty() {
        // per-hostname SNI certs: `tls_sni = <hostname> <cert> <key>` (repeatable)
        let sni: Vec<(String, String, String)> = cfg
            .raw
            .get("tls_sni")
            .map(|v| {
                v.iter()
                    .filter_map(|line| {
                        let mut it = line.split_whitespace();
                        match (it.next(), it.next(), it.next()) {
                            (Some(h), Some(c), Some(k)) => {
                                Some((h.to_string(), c.to_string(), k.to_string()))
                            }
                            _ => None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        match (&cfg.tls_cert, &cfg.tls_key) {
            (Some(cert), Some(key)) => match OpensslBackend::new(cert, key, sni) {
                Ok(backend) => {
                    let backend = Arc::new(backend);
                    // publish for REHASH-triggered cert reload
                    let _ = echoircd::tls::TLS_RELOAD.set(backend.clone());
                    let backend: Arc<dyn TlsBackend> = backend;
                    for bind_tls in &cfg.bind_tls {
                        match TcpListener::bind(bind_tls) {
                            Ok(tls_listener) => {
                                eprintln!("echoircd TLS on {bind_tls} (openssl)");
                                let tls_tx = tx.clone();
                                let tls_counter = counter.clone();
                                let tls_proxy_trust = proxy_trust.clone();
                                let tls_reactors = reactors.clone();
                                let tls_limiter = accept_limiter.clone();
                                let backend = backend.clone();
                                thread::spawn(move || {
                                    socketengine::accept_loop(
                                        tls_listener,
                                        tls_tx,
                                        Some(backend),
                                        tls_counter,
                                        false,
                                        max_line,
                                        tls_proxy_trust,
                                        tls_reactors,
                                        tls_limiter,
                                        handshake_timeout,
                                    )
                                });
                            }
                            Err(e) => eprintln!("echoircd: cannot bind TLS {bind_tls}: {e}"),
                        }
                    }
                }
                Err(e) => eprintln!("echoircd: TLS disabled (cert/key error): {e}"),
            },
            _ => eprintln!("echoircd: bind_tls set but tls_cert/tls_key missing; TLS disabled"),
        }
    }

    // server-to-server link listeners (bind_server, repeatable — see crate::link)
    for bind_srv in &cfg.bind_server {
        match TcpListener::bind(bind_srv) {
            Ok(sl) => {
                eprintln!("echoircd S2S link listener on {bind_srv} (sid {})", cfg.sid);
                let s_tx = tx.clone();
                let s_counter = counter.clone();
                thread::spawn(move || {
                    // links stay on the thread path: no reactor handoff, no rate limit
                    socketengine::accept_loop(
                        sl,
                        s_tx,
                        None,
                        s_counter,
                        true,
                        max_line,
                        Vec::new(),
                        Vec::new(),
                        None,
                        handshake_timeout,
                    )
                });
            }
            Err(e) => eprintln!("echoircd: cannot bind server port {bind_srv}: {e}"),
        }
    }

    // optional JSON-RPC-over-HTTP control interface (see crate::modules::rpc)
    echoircd::modules::rpc::maybe_start(&cfg, tx.clone());

    // optional WebSocket transport for browser IRC clients (see crate::websocket)
    echoircd::websocket::maybe_start(&cfg, tx.clone(), counter.clone());

    // dial any autoconnect uplinks (after a short delay so the peer can boot)
    for block in cfg.links.iter().filter(|b| b.autoconnect) {
        let addr = format!("{}:{}", block.ip, block.port);
        let u_tx = tx.clone();
        let u_counter = counter.clone();
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(2));
            socketengine::connect_link(&addr, u_tx, u_counter, max_line);
        });
    }

    // client plaintext connections: one acceptor per listener, all round-robining
    // onto the shared reactor pool
    for listener in client_listeners {
        let (r, c, pt, lim) = (
            reactors.clone(),
            counter.clone(),
            proxy_trust.clone(),
            accept_limiter.clone(),
        );
        thread::spawn(move || socketengine::run_acceptor(listener, r, c, pt, lim));
    }
    let _ = core.join();
}
