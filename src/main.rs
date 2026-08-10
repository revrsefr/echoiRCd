//! echoIRCd entry point: read config, bind the plaintext (and, if configured,
//! the TLS) listener, then run the single-threaded core while the accept loops
//! feed it connections.
#![forbid(unsafe_code)]

use std::net::TcpListener;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use echoircd::config::Config;
use echoircd::ircd::{Event, Ircd};
use echoircd::socketengine;
use echoircd::tls::{OpensslBackend, TlsBackend};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "echoircd.conf".to_string());
    let cfg = Config::load(&path);

    // Client plaintext connections run on the mio reactor, so bind a mio listener
    // (fail fast if the main port is taken).
    let bind_addr: std::net::SocketAddr = match cfg.bind.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("echoircd: bad bind address {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };
    let client_listener = match mio::net::TcpListener::bind(bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("echoircd: cannot bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };
    eprintln!(
        "echoircd {} on {} (network {}, server {})",
        env!("CARGO_PKG_VERSION"),
        cfg.bind,
        cfg.network,
        cfg.servername
    );

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

    // one uid counter shared by every listener (and by CONNECT) so ids stay unique
    let counter = Arc::new(AtomicU64::new(1));

    let (tx, rx) = mpsc::channel();
    let core_cfg = cfg.clone();
    let core_tx = tx.clone(); // the core self-injects events (DNS results)
    let core_counter = counter.clone();
    let core = thread::spawn(move || Ircd::new(core_cfg, core_tx, core_counter).run(rx));

    // background timer: drives ping/idle timeouts
    let tick_tx = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(echoircd::server::TICK_SECS));
        if tick_tx.send(Event::Tick).is_err() {
            break;
        }
    });

    // optional TLS listener (bind_tls + tls_cert + tls_key). A cert/bind problem
    // disables TLS but never takes the plaintext listener down.
    if let (Some(bind_tls), Some(cert), Some(key)) = (&cfg.bind_tls, &cfg.tls_cert, &cfg.tls_key) {
        match OpensslBackend::new(cert, key) {
            Ok(backend) => match TcpListener::bind(bind_tls) {
                Ok(tls_listener) => {
                    eprintln!("echoircd TLS on {bind_tls} (openssl)");
                    let backend: Arc<dyn TlsBackend> = Arc::new(backend);
                    let tls_tx = tx.clone();
                    let tls_counter = counter.clone();
                    thread::spawn(move || {
                        socketengine::accept_loop(
                            tls_listener,
                            tls_tx,
                            Some(backend),
                            tls_counter,
                            false,
                            max_line,
                        )
                    });
                }
                Err(e) => eprintln!("echoircd: cannot bind TLS {bind_tls}: {e}"),
            },
            Err(e) => eprintln!("echoircd: TLS disabled (cert/key error): {e}"),
        }
    }

    // server-to-server link listener (see crate::link)
    if let Some(bind_srv) = &cfg.bind_server {
        match TcpListener::bind(bind_srv) {
            Ok(sl) => {
                eprintln!("echoircd S2S link listener on {bind_srv} (sid {})", cfg.sid);
                let s_tx = tx.clone();
                let s_counter = counter.clone();
                thread::spawn(move || {
                    socketengine::accept_loop(sl, s_tx, None, s_counter, true, max_line)
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

    // client plaintext connections: one mio reactor thread drives them all
    thread::spawn(move || {
        socketengine::run_reactor(client_listener, tx, counter, max_line, max_sendq)
    });
    let _ = core.join();
}
