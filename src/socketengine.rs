//! The socket engine: the I/O edge. Accept connections and, per socket, ferry
//! the wire to/from the core. Plaintext sockets get a blocking reader thread +
//! writer thread; TLS sockets get one thread that owns the session and polls
//! (a single TLS object can't be split across two threads). The core never
//! touches a socket except to shut it down. (InspIRCd has a `socketengines/`
//! dir of epoll/kqueue/select backends; ours is threads.)

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::ircd::Event;
use crate::tls::TlsBackend;
use crate::Uid;

/// Longest single line we'll buffer before dropping it (crude flood guard).
const MAX_LINE: usize = 16 * 1024;
/// How long a TLS thread blocks on a read before draining its write queue.
const TLS_POLL: Duration = Duration::from_millis(100);

/// Accept forever, wiring each connection to the core. `tls` = the backend to
/// wrap sockets in (None for a plaintext listener). `counter` is shared across
/// every listener so uids stay unique.
pub fn accept_loop(
    listener: TcpListener,
    core: Sender<Event>,
    tls: Option<Arc<dyn TlsBackend>>,
    counter: Arc<AtomicU64>,
    link: bool,
) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let Ok(addr) = stream.peer_addr() else {
            continue;
        };
        let _ = stream.set_nodelay(true);
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
                        out: out_tx,
                        sock: shutdown,
                        secure: false,
                        link,
                        outbound: false,
                    })
                    .is_err()
                {
                    break; // core gone
                }
                let core_tx = core.clone();
                thread::spawn(move || reader_loop(reader, uid, core_tx));
            }
            Some(backend) => {
                let backend = backend.clone();
                let core_tx = core.clone();
                thread::spawn(move || tls_conn(backend, stream, uid, addr, core_tx, link));
            }
        }
    }
}

/// Dial an outbound server link and wire it to the core (an `outbound` link that
/// introduces itself first). Used for auto-connecting to a configured uplink.
pub fn connect_link(addr: &str, core: Sender<Event>, counter: Arc<AtomicU64>) {
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
            out: out_tx,
            sock: shutdown,
            secure: false,
            link: true,
            outbound: true,
        })
        .is_err()
    {
        return;
    }
    thread::spawn(move || reader_loop(reader, uid, core));
}

// --- plaintext: two blocking threads ----------------------------------------

fn reader_loop(stream: TcpStream, uid: Uid, core: Sender<Event>) {
    let mut buf = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match buf.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                if line.len() > MAX_LINE {
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
    stream: TcpStream,
    uid: Uid,
    addr: SocketAddr,
    core: Sender<Event>,
    link: bool,
) {
    // Keep a raw handle so the core can force the socket shut later.
    let Ok(shutdown) = stream.try_clone() else {
        return;
    };
    let mut conn = match backend.accept(stream) {
        Ok(c) => c,
        Err(_) => {
            let _ = shutdown.shutdown(Shutdown::Both);
            return; // handshake failed
        }
    };
    let (out_tx, out_rx) = mpsc::channel::<String>();
    if core
        .send(Event::Connect {
            uid,
            addr,
            out: out_tx,
            sock: shutdown,
            secure: true,
            link,
            outbound: false,
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
                while let Some(pos) = acc.iter().position(|&b| b == b'\n') {
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
                if acc.len() > MAX_LINE {
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
