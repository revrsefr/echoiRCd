//! echoIRCd entry point: read config, bind the plaintext (and, if configured,
//! the TLS) listener, then run the single-threaded core while the accept loops
//! feed it connections.
#![forbid(unsafe_code)]

// mimalloc as the global allocator: an IRC core allocates a short-lived String per
// message per recipient (tags + body), so allocator throughput is on the hot path.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

/// Is `pid` a live echoircd process?
fn is_echoircd(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "echoircd")
        .unwrap_or(false)
}

/// Find the running echoircd server for `cfgpath` by scanning /proc — the fallback
/// when the pidfile is missing or stale (a throwaway instance clobbered it).
/// Prefers a process whose command line names the same config; else a lone server.
fn find_server(cfgpath: &str, self_pid: u32) -> Option<u32> {
    let want = std::fs::canonicalize(cfgpath).ok();
    let mut servers: Vec<(u32, bool)> = Vec::new();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == self_pid || !is_echoircd(pid) {
            continue;
        }
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let args: Vec<String> = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if args.iter().any(|a| a == "rehash") {
            continue; // a `rehash` CLI invocation, not the server
        }
        let matches = args
            .iter()
            .skip(1)
            .any(|a| a == cfgpath || (want.is_some() && std::fs::canonicalize(a).ok() == want));
        servers.push((pid, matches));
    }
    servers
        .iter()
        .find(|(_, m)| *m)
        .map(|(p, _)| *p)
        .or_else(|| (servers.len() == 1).then(|| servers[0].0))
}

/// `echoircd rehash [config]`: locate the running server (pidfile fast-path, else
/// a /proc scan) and send it SIGHUP so it reloads its config in place. No unsafe —
/// the signal is sent via the `kill` command.
fn rehash_cli(cfgpath: &str) -> i32 {
    let cfg = Config::load(cfgpath);
    let pidfile = cfg
        .raw
        .get("pidfile")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "echoircd.pid".to_string());
    let self_pid = std::process::id();
    // Trust the pidfile only if it names a live echoircd; otherwise find the server
    // via /proc, since a throwaway instance sharing this config may have clobbered it.
    let from_file = std::fs::read_to_string(&pidfile)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&p| is_echoircd(p));
    let Some(pid) = from_file.or_else(|| find_server(cfgpath, self_pid)) else {
        eprintln!("echoircd: no running echoircd for {cfgpath} — start the server first.");
        return 1;
    };
    println!("rehashing server config file.");
    let sent = std::process::Command::new("kill")
        .args(["-s", "HUP", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    if !sent {
        eprintln!("echoircd: could not signal pid {pid}.");
        return 1;
    }
    // Self-heal a stale/clobbered pidfile so the fast path works next time.
    if from_file != Some(pid) && !pidfile.is_empty() {
        let _ = std::fs::write(&pidfile, format!("{pid}\n"));
    }
    println!("server configuration is reloaded.");
    0
}

/// `echoircd mkpasswd [cost]`: read a password from stdin and print its bcrypt
/// hash — a config-ready oper password value. Reads stdin (not argv) so the
/// password never lands in `ps`/shell history via the command line.
fn mkpasswd_cli(cost_arg: Option<&str>) -> i32 {
    use std::io::Read;
    let cost: u32 = cost_arg.and_then(|c| c.parse().ok()).unwrap_or(11);
    let mut pw = String::new();
    if std::io::stdin().read_to_string(&mut pw).is_err() {
        eprintln!("echoircd: could not read password from stdin");
        return 1;
    }
    let pw = pw.trim_end_matches(['\n', '\r']);
    if pw.is_empty() {
        eprintln!("echoircd: empty password");
        return 1;
    }
    match echoircd::bcrypt::hash(cost, pw) {
        // self-check: only emit a hash our own verify accepts
        Some(h) if echoircd::bcrypt::verify(&h, pw) => {
            println!("{h}");
            0
        }
        _ => {
            eprintln!("echoircd: bcrypt hashing failed");
            1
        }
    }
}

/// `echoircd checkconfig [config]`: parse a config and print a deterministic,
/// sorted dump of every key/value it produces. Two configs (e.g. flat vs block
/// format) that dump identically parse identically.
fn checkconfig_cli(path: &str) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("echoircd: cannot read config {path}: {e}");
            return 1;
        }
    };
    // Structural validation against the block schema (unknown block/field, missing
    // required field, bad number/bool). Report every finding with its line.
    let (errs, warns) = echoircd::config::validate_config(&text);
    for w in &warns {
        eprintln!("echoircd: {path}:{}: warning: {}", w.line, w.msg);
    }
    for e in &errs {
        if e.line == 0 {
            eprintln!("echoircd: {path}: error: {}", e.msg);
        } else {
            eprintln!("echoircd: {path}:{}: error: {}", e.line, e.msg);
        }
    }
    let Some(c) = echoircd::config::Config::try_load(path) else {
        eprintln!("echoircd: cannot read config {path}");
        return 1;
    };
    print!("{}", c.dump());
    if !errs.is_empty() {
        eprintln!("echoircd: {} configuration error(s)", errs.len());
        return 1;
    }
    if c.servername.is_empty() {
        eprintln!("echoircd: WARNING — servername is empty");
        return 2;
    }
    eprintln!("echoircd: configuration OK ({} warning(s))", warns.len());
    0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    // `echoircd rehash [config]` signals a running server instead of booting one.
    if first.as_deref() == Some("rehash") {
        let cfgpath = args.next().unwrap_or_else(|| "echoircd.conf".to_string());
        std::process::exit(rehash_cli(&cfgpath));
    }
    // `echoircd mkpasswd [cost]` hashes a password (from stdin) and exits.
    if first.as_deref() == Some("mkpasswd") {
        std::process::exit(mkpasswd_cli(args.next().as_deref()));
    }
    // `echoircd checkconfig [config]` parses a config and prints a sorted dump
    // of every key/value (for validating a config or diffing two of them).
    if first.as_deref() == Some("checkconfig") {
        let cfgpath = args.next().unwrap_or_else(|| "echoircd.conf".to_string());
        std::process::exit(checkconfig_cli(&cfgpath));
    }
    // `echoircd version` (or `--version`/`-V`) prints the build string and exits —
    // WITHOUT booting a daemon (a bare unknown arg is treated as a config path below).
    if matches!(first.as_deref(), Some("version" | "--version" | "-V")) {
        println!("{}", echoircd::server::version_comment());
        std::process::exit(0);
    }
    let path = first.unwrap_or_else(|| "echoircd.conf".to_string());
    // Validate the config against the block schema before booting. A missing file
    // is fine (built-in defaults); a present-but-broken config refuses to start so
    // a typo'd block/field is caught here instead of silently ignored.
    if let Ok(text) = std::fs::read_to_string(&path) {
        let (errs, warns) = echoircd::config::validate_config(&text);
        for w in &warns {
            eprintln!("echoircd: {path}:{}: config warning: {}", w.line, w.msg);
        }
        if !errs.is_empty() {
            for e in &errs {
                if e.line == 0 {
                    eprintln!("echoircd: {path}: config error: {}", e.msg);
                } else {
                    eprintln!("echoircd: {path}:{}: config error: {}", e.line, e.msg);
                }
            }
            eprintln!(
                "echoircd: {} configuration error(s); refusing to start (run `echoircd checkconfig {path}`)",
                errs.len()
            );
            std::process::exit(1);
        }
    }
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
    // Graceful-upgrade handover: adopt any inherited listeners (parsed once, split by
    // role), and register every listener's fd so SIGUSR2 can hand them all to the next
    // binary. `inherited` is empty on a normal start.
    let mut inherited = echoircd::upgrade::inherited();
    let upgrade_reg = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
        &'static str,
        std::os::fd::RawFd,
    )>::new()));
    let register_fd = |role: &'static str, fd: std::os::fd::RawFd| {
        if let Ok(mut r) = upgrade_reg.lock() {
            r.push((role, fd));
        }
    };

    let mut client_listeners: Vec<mio::net::TcpListener> = Vec::new();
    for l in echoircd::upgrade::take(&mut inherited, "client") {
        if l.set_nonblocking(true).is_ok() {
            client_listeners.push(mio::net::TcpListener::from_std(l));
        }
    }
    if !client_listeners.is_empty() {
        eprintln!(
            "echoircd: adopted {} plaintext listener(s) across the upgrade",
            client_listeners.len()
        );
    } else {
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
    }
    if client_listeners.is_empty() {
        eprintln!("echoircd: no plaintext listener could bind; exiting");
        std::process::exit(1);
    }
    for l in &client_listeners {
        register_fd("client", std::os::fd::AsRawFd::as_raw_fd(l));
    }

    // Write a pidfile only when `pidfile` is configured, so throwaway instances in
    // the same directory (e.g. the integration-test harness) can't clobber a real
    // server's pidfile and leave `echoircd rehash` pointing at a dead process.
    if let Some(pidfile) = cfg
        .raw
        .get("pidfile")
        .and_then(|v| v.first())
        .filter(|p| !p.is_empty())
    {
        if let Err(e) = std::fs::write(pidfile, format!("{}\n", std::process::id())) {
            eprintln!("echoircd: could not write pidfile {pidfile}: {e}");
        }
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
    let accept_limiter = socketengine::AcceptLimiter::from_conf(
        raw_num("accept_rate", 0),
        raw_num("accept_burst", 0),
    );
    // trusted PROXY-protocol source globs (reactor rewrites the client IP from them)
    let proxy_trust: Vec<String> = cfg.raw.get("proxy").cloned().unwrap_or_default();

    // one uid counter shared by every listener (and by CONNECT) so ids stay unique
    let counter = Arc::new(AtomicU64::new(1));

    // Bounded core event queue: reactor/worker producers backpressure when the core
    // falls behind, instead of the queue growing until OOM. The core thread never
    // sends to it inline (only worker threads do), so a full queue can't deadlock it.
    let core_queue_max: usize = cfg
        .raw
        .get("core_queue_max")
        .and_then(|v| v.first())
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(16384);
    let (tx, rx) = mpsc::sync_channel(core_queue_max);
    let core_cfg = cfg.clone();
    let core_tx = tx.clone(); // the core self-injects events (DNS results)
    let core_counter = counter.clone();
    // watchdog: the core stores when it started the current event into `core_busy`
    // (0 = idle); a separate thread warns if it stays stuck past `watchdog_ms`.
    let wd_base = Instant::now();
    let core_busy = Arc::new(AtomicU64::new(0));
    // the core writes a short label of the current event here; the watchdog and the
    // slow-event snote read it so a stall names its culprit, not just a duration.
    let core_label = Arc::new(std::sync::Mutex::new(String::new()));
    let watchdog_ms = raw_num("watchdog_ms", 5000) as u64; // 0 = off
    if watchdog_ms > 0 {
        let (wb, base, wl) = (core_busy.clone(), wd_base, core_label.clone());
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(1000));
            let cur = wb.load(Ordering::Relaxed);
            if cur != 0 {
                let stuck = (base.elapsed().as_millis() as u64).saturating_sub(cur);
                if stuck > watchdog_ms {
                    let what = wl
                        .lock()
                        .map(|g| g.clone())
                        .unwrap_or_else(|e| e.into_inner().clone());
                    eprintln!(
                        "[watchdog] core thread stuck ~{stuck}ms on '{what}' — a handler is blocking the whole server"
                    );
                }
            }
        });
    }
    let (busy, base) = (core_busy, wd_base);
    let core = thread::spawn(move || {
        Ircd::new(core_cfg, core_tx, core_counter).run(rx, busy, base, core_label)
    });

    // background timer: drives ping/idle timeouts
    let tick_tx = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(std::time::Duration::from_secs(echoircd::server::TICK_SECS));
        if tick_tx.send(Event::Tick).is_err() {
            break;
        }
    });

    // SIGHUP → live config rehash (the mechanism the `rehash` CLI uses).
    match signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP]) {
        Ok(mut signals) => {
            let sig_tx = tx.clone();
            thread::spawn(move || {
                for _ in signals.forever() {
                    if sig_tx.send(Event::Rehash).is_err() {
                        break;
                    }
                }
            });
        }
        Err(e) => eprintln!("echoircd: SIGHUP handler unavailable: {e}"),
    }

    // SIGUSR2 → graceful binary upgrade: re-exec the new build in place, handing over
    // the listening sockets so there's no rebind gap or refused-connection window.
    match signal_hook::iterator::Signals::new([signal_hook::consts::SIGUSR2]) {
        Ok(mut signals) => {
            let reg = upgrade_reg.clone();
            thread::spawn(move || {
                for _ in signals.forever() {
                    let fds = reg.lock().map(|g| g.clone()).unwrap_or_default();
                    eprintln!(
                        "echoircd: SIGUSR2 — graceful upgrade, re-exec preserving {} listener(s)",
                        fds.len()
                    );
                    let e = echoircd::upgrade::reexec(&fds);
                    eprintln!("echoircd: upgrade re-exec failed, staying up: {e}");
                }
            });
        }
        Err(e) => eprintln!("echoircd: SIGUSR2 handler unavailable: {e}"),
    }

    // reactor worker pool: shared by the plaintext acceptor and the direct-TLS
    // acceptor, so client I/O (framing + TLS crypto) spreads across cores.
    let reactors = socketengine::spawn_reactors(
        tx.clone(),
        max_line,
        max_sendq,
        io_threads,
        handshake_timeout,
    );

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
            (Some(cert), Some(key)) => {
                // pick the TLS backend: pure-Rust rustls (opt-in via tls_backend =
                // rustls) or openssl (the default). Both satisfy the same trait.
                let use_rustls = cfg
                    .raw
                    .get("tls_backend")
                    .and_then(|v| v.first())
                    .is_some_and(|s| s.eq_ignore_ascii_case("rustls"));
                let backend: Option<Arc<dyn TlsBackend>> = if use_rustls {
                    match echoircd::tls_rustls::RustlsBackend::new(cert, key, sni) {
                        Ok(b) => {
                            let b = Arc::new(b);
                            let _ = echoircd::tls::TLS_RELOAD.set(b.clone());
                            eprintln!("echoircd TLS backend: rustls");
                            Some(b as Arc<dyn TlsBackend>)
                        }
                        Err(e) => {
                            eprintln!("echoircd: TLS disabled (rustls cert/key error): {e}");
                            None
                        }
                    }
                } else {
                    match OpensslBackend::new(cert, key, sni) {
                        Ok(b) => {
                            let b = Arc::new(b);
                            let _ = echoircd::tls::TLS_RELOAD.set(b.clone()); // REHASH cert reload
                            eprintln!("echoircd TLS backend: openssl");
                            Some(b as Arc<dyn TlsBackend>)
                        }
                        Err(e) => {
                            eprintln!("echoircd: TLS disabled (cert/key error): {e}");
                            None
                        }
                    }
                };
                if let Some(backend) = backend {
                    let mut tls_listeners = echoircd::upgrade::take(&mut inherited, "tls");
                    if tls_listeners.is_empty() {
                        for bind_tls in &cfg.bind_tls {
                            match TcpListener::bind(bind_tls) {
                                Ok(l) => {
                                    eprintln!("echoircd TLS on {bind_tls}");
                                    tls_listeners.push(l);
                                }
                                Err(e) => eprintln!("echoircd: cannot bind TLS {bind_tls}: {e}"),
                            }
                        }
                    } else {
                        eprintln!(
                            "echoircd: adopted {} TLS listener(s) across the upgrade",
                            tls_listeners.len()
                        );
                    }
                    for tls_listener in tls_listeners {
                        register_fd("tls", std::os::fd::AsRawFd::as_raw_fd(&tls_listener));
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
                }
            }
            _ => eprintln!("echoircd: bind_tls set but tls_cert/tls_key missing; TLS disabled"),
        }
    }

    // server-to-server link listeners (bind_server, repeatable — see crate::link)
    let mut server_listeners = echoircd::upgrade::take(&mut inherited, "server");
    if server_listeners.is_empty() {
        for bind_srv in &cfg.bind_server {
            match TcpListener::bind(bind_srv) {
                Ok(sl) => {
                    eprintln!("echoircd S2S link listener on {bind_srv} (sid {})", cfg.sid);
                    server_listeners.push(sl);
                }
                Err(e) => eprintln!("echoircd: cannot bind server port {bind_srv}: {e}"),
            }
        }
    } else {
        eprintln!(
            "echoircd: adopted {} S2S listener(s) across the upgrade",
            server_listeners.len()
        );
    }
    for sl in server_listeners {
        register_fd("server", std::os::fd::AsRawFd::as_raw_fd(&sl));
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

    // optional JSON-RPC-over-HTTP control interface (see crate::modules::rpc)
    echoircd::modules::rpc::maybe_start(&cfg, tx.clone());

    // optional OpenMetrics/Prometheus scrape endpoint (metrics_bind = host:port)
    echoircd::modules::metrics::maybe_start(&cfg);

    // optional WebSocket transport for browser IRC clients (see crate::websocket)
    echoircd::websocket::maybe_start(
        &cfg,
        tx.clone(),
        counter.clone(),
        &mut inherited,
        &upgrade_reg,
    );

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
