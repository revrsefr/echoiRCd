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

    let listener = match TcpListener::bind(&cfg.bind) {
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

    let (tx, rx) = mpsc::channel();
    let core_cfg = cfg.clone();
    let core = thread::spawn(move || Ircd::new(core_cfg).run(rx));

    // background timer: drives ping/idle timeouts
    let tick_tx = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(echoircd::server::TICK_SECS));
        if tick_tx.send(Event::Tick).is_err() {
            break;
        }
    });

    // one uid counter shared by every listener so ids stay unique
    let counter = Arc::new(AtomicU64::new(1));

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
                thread::spawn(move || socketengine::accept_loop(sl, s_tx, None, s_counter, true));
            }
            Err(e) => eprintln!("echoircd: cannot bind server port {bind_srv}: {e}"),
        }
    }

    // dial any autoconnect uplinks (after a short delay so the peer can boot)
    for block in cfg.links.iter().filter(|b| b.autoconnect) {
        let addr = format!("{}:{}", block.ip, block.port);
        let u_tx = tx.clone();
        let u_counter = counter.clone();
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(2));
            socketengine::connect_link(&addr, u_tx, u_counter);
        });
    }

    socketengine::accept_loop(listener, tx, None, counter, false);
    let _ = core.join();
}
