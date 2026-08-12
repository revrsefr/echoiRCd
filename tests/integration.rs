//! End-to-end tests: spawn the real `echoircd` binary on ephemeral ports and drive it
//! as a client would. Covers the reactor pool (cross-worker delivery), TLS in the
//! reactor (handshake, cross-transport, the secure marker, the stalled-handshake reap),
//! and core routing (PRIVMSG, nick collision).
//!
//! Each test owns its own server on its own ports and kills the child in `Drop` — by
//! PID, never by process name — so the suite can't touch anything it didn't start.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};

/// Grab a free localhost port by binding :0 and releasing it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A throwaway self-signed cert/key (PEM) for the TLS listener.
fn gen_cert() -> (String, String) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509};

    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "echo.test").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = b.build();
    (
        String::from_utf8(cert.to_pem().unwrap()).unwrap(),
        String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
    )
}

/// A running echoircd child plus the ports it listens on. Killed + cleaned on drop.
struct Server {
    child: Child,
    plain: u16,
    tls: u16,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Server {
    fn start(io_threads: usize, tls: bool, hs_timeout: u32) -> Server {
        let (plain, tlsp, s2s) = (free_port(), free_port(), free_port());
        let dir = std::env::temp_dir().join(format!("echoircd-it-{}-{plain}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut conf = format!(
            "servername = it.test\nnetwork = itNet\nbind = 127.0.0.1:{plain}\n\
             bind_server = 127.0.0.1:{s2s}\nsid = 1AA\nmotd = hi\nio_threads = {io_threads}\n"
        );
        if tls {
            let (cert, key) = gen_cert();
            let (cp, kp) = (dir.join("cert.pem"), dir.join("key.pem"));
            std::fs::write(&cp, cert).unwrap();
            std::fs::write(&kp, key).unwrap();
            conf.push_str(&format!(
                "bind_tls = 127.0.0.1:{tlsp}\ntls_cert = {}\ntls_key = {}\n\
                 tls_handshake_timeout = {hs_timeout}\n",
                cp.display(),
                kp.display()
            ));
        }
        let cpath = dir.join("echoircd.conf");
        std::fs::write(&cpath, conf).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_echoircd"))
            .arg(&cpath)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn echoircd");
        let srv = Server { child, plain, tls: tlsp, dir };
        srv.wait_ready();
        srv
    }

    /// Block until a full NICK/USER registration succeeds, so the whole pipeline
    /// (acceptor + reactor + core) is proven up before the test proceeds.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", self.plain)) {
                s.set_read_timeout(Some(Duration::from_millis(400))).ok();
                let _ = s.write_all(b"NICK probe\r\nUSER probe 0 * :probe\r\n");
                if read_until(&mut s, " 001 ", Duration::from_secs(2)) {
                    let _ = s.write_all(b"QUIT :ready\r\n");
                    drop(s);
                    thread::sleep(Duration::from_millis(200));
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("server never became ready");
    }

    fn plain_client(&self, nick: &str) -> TcpStream {
        let mut s = TcpStream::connect(("127.0.0.1", self.plain)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        register(&mut s, nick);
        s
    }

    fn tls_client(&self, nick: &str) -> SslStream<TcpStream> {
        let tcp = TcpStream::connect(("127.0.0.1", self.tls)).unwrap();
        let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
        b.set_verify(SslVerifyMode::NONE);
        let mut s = b
            .build()
            .configure()
            .unwrap()
            .verify_hostname(false)
            .connect("echo.test", tcp)
            .unwrap();
        s.get_ref()
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        register(&mut s, nick);
        s
    }
}

/// Read until `needle` appears or `timeout` elapses; returns whether it was seen.
/// Relies on the stream having a read timeout so reads don't block forever.
fn read_until<S: Read>(s: &mut S, needle: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while Instant::now() < deadline {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&buf).contains(needle) {
                    return true;
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).contains(needle)
}

fn register<S: Read + Write>(s: &mut S, nick: &str) {
    s.write_all(format!("NICK {nick}\r\nUSER {nick} 0 * :{nick}\r\n").as_bytes())
        .unwrap();
    assert!(
        read_until(s, " 001 ", Duration::from_secs(5)),
        "no 001 welcome for {nick}"
    );
}

fn line<S: Write>(s: &mut S, l: &str) {
    s.write_all(format!("{l}\r\n").as_bytes()).unwrap();
}

#[test]
fn plaintext_registration_privmsg_and_collision() {
    let srv = Server::start(2, false, 0);
    let mut a = srv.plain_client("alice");
    let mut b = srv.plain_client("bob");
    line(&mut a, "JOIN #x");
    line(&mut b, "JOIN #x");
    read_until(&mut a, "JOIN", Duration::from_secs(2));
    read_until(&mut b, "JOIN", Duration::from_secs(2));
    line(&mut a, "PRIVMSG #x :hello-bob");
    assert!(
        read_until(&mut b, "hello-bob", Duration::from_secs(3)),
        "bob never received alice's channel message"
    );

    // a third client can't steal alice's nick
    let mut c = TcpStream::connect(("127.0.0.1", srv.plain)).unwrap();
    c.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    line(&mut c, "NICK alice");
    assert!(
        read_until(&mut c, " 433 ", Duration::from_secs(3)),
        "expected 433 nick-in-use"
    );
}

#[test]
fn reactor_pool_cross_worker_delivery() {
    // 3 workers: the clients land on different reactors, yet a channel message from one
    // must reach every other — proving the single core routes across workers.
    let srv = Server::start(3, false, 0);
    let mut clients: Vec<TcpStream> = (0..6).map(|i| srv.plain_client(&format!("u{i}"))).collect();
    for c in clients.iter_mut() {
        line(c, "JOIN #pool");
    }
    for c in clients.iter_mut() {
        read_until(c, "JOIN", Duration::from_secs(2));
    }
    line(&mut clients[0], "PRIVMSG #pool :ping-all");
    for (i, c) in clients.iter_mut().enumerate().skip(1) {
        assert!(
            read_until(c, "ping-all", Duration::from_secs(3)),
            "client u{i} (a different reactor worker) missed the message"
        );
    }
}

#[test]
fn tls_in_reactor_handshake_and_cross_transport() {
    let srv = Server::start(2, true, 15);
    let mut t = srv.tls_client("secure1"); // full handshake happens inside a worker
    let mut p = srv.plain_client("plain1");
    line(&mut t, "JOIN #z");
    line(&mut p, "JOIN #z");
    read_until(&mut t, "JOIN", Duration::from_secs(2));
    read_until(&mut p, "JOIN", Duration::from_secs(2));

    line(&mut t, "PRIVMSG #z :from-tls");
    assert!(
        read_until(&mut p, "from-tls", Duration::from_secs(3)),
        "TLS -> plaintext delivery failed"
    );
    line(&mut p, "PRIVMSG #z :from-plain");
    assert!(
        read_until(&mut t, "from-plain", Duration::from_secs(3)),
        "plaintext -> TLS delivery failed"
    );

    // the TLS user is flagged secure (671 in WHOIS)
    line(&mut p, "WHOIS secure1");
    assert!(
        read_until(&mut p, " 671 ", Duration::from_secs(3)),
        "TLS user not reported as using a secure connection"
    );
}

#[test]
fn tls_stalled_handshake_is_reaped() {
    // 2s handshake timeout: a raw TCP connection to the TLS port that never negotiates
    // must be closed by the server, not leaked.
    let srv = Server::start(2, true, 2);
    let mut raw = TcpStream::connect(("127.0.0.1", srv.tls)).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 16];
    let closed = matches!(raw.read(&mut buf), Ok(0)); // server closed → EOF
    let elapsed = start.elapsed();
    assert!(closed, "stalled TLS handshake was not closed by the server");
    assert!(
        elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(5),
        "reap timing off: {elapsed:?} (expected ~2s)"
    );
}
