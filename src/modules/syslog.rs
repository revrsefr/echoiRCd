//! syslog — mirror the server-notice / log stream to the system logger. Off unless
//! `syslog = yes`. Sends to a local Unix datagram socket (`syslog_target`, default
//! `/dev/log`) or, when the target looks like `host:port`, over UDP. Messages are
//! RFC 3164 `<PRI>TAG[pid]: msg`; the receiving daemon stamps the time.
//!
//! ```text
//! syslog          = yes
//! syslog_target   = /dev/log        # or e.g. 10.0.0.5:514 for a remote collector
//! syslog_facility = daemon          # kern user mail daemon auth ... local0..local7
//! syslog_tag      = echoircd
//! ```
//!
//! The socket is cached per target on the core thread (snotice is single-threaded),
//! reopened only when the configured target changes.

use std::cell::RefCell;
use std::net::UdpSocket;
use std::os::unix::net::UnixDatagram;

use crate::server::Server;

/// An opened syslog transport.
enum Sink {
    Unix(UnixDatagram),
    Udp(UdpSocket, String), // socket + "host:port" destination
}

thread_local! {
    /// (target-string, sink) cached for the current config; reopened on change.
    static SINK: RefCell<Option<(String, Sink)>> = const { RefCell::new(None) };
}

/// Syslog facility name → numeric code (RFC 3164 §4.1.1).
fn facility(name: &str) -> u8 {
    match name.to_ascii_lowercase().as_str() {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 3, // daemon
    }
}

/// Open the transport for `target` (`host:port` ⇒ UDP, else a Unix datagram path).
fn open(target: &str) -> Option<Sink> {
    if target.contains(':') && !target.starts_with('/') {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .or_else(|_| UdpSocket::bind("[::]:0"))
            .ok()?;
        Some(Sink::Udp(sock, target.to_string()))
    } else {
        let sock = UnixDatagram::unbound().ok()?;
        sock.connect(target).ok()?;
        Some(Sink::Unix(sock))
    }
}

/// Tee `msg` to syslog when enabled. Called at the tail of [`Server::snotice`].
pub fn tee(s: &Server, msg: &str) {
    if !s.conf_bool("syslog", false) {
        SINK.with(|c| *c.borrow_mut() = None); // dropped/disabled: forget any socket
        return;
    }
    let target = s
        .conf("syslog_target")
        .map(str::to_string)
        .unwrap_or_else(|| "/dev/log".to_string());
    let tag = s.conf("syslog_tag").unwrap_or("echoircd");
    // severity "notice" (5); PRI = facility*8 + severity
    let pri = facility(s.conf("syslog_facility").unwrap_or("daemon")) as u16 * 8 + 5;
    // Neutralise control chars (esp. CR/LF): an snotice can carry user-influenced
    // text (nick/realname/quit reason), and a raw newline would forge a syslog record.
    let safe: String = msg
        .chars()
        .map(|c| if (c as u32) < 0x20 || c == '\x7f' { ' ' } else { c })
        .collect();
    let line = format!("<{pri}>{tag}[{}]: {safe}", std::process::id());
    SINK.with(|cell| {
        let mut slot = cell.borrow_mut();
        // (re)open if the target changed or nothing is open yet
        let need_open = match slot.as_ref() {
            Some((t, _)) => t != &target,
            None => true,
        };
        if need_open {
            *slot = open(&target).map(|sink| (target.clone(), sink));
        }
        if let Some((_, sink)) = slot.as_ref() {
            let ok = match sink {
                Sink::Unix(sock) => sock.send(line.as_bytes()).is_ok(),
                Sink::Udp(sock, dst) => {
                    // UDP is fire-and-forget: a transient send error shouldn't force a
                    // re-bind + re-resolve on the very next notice. Keep the socket.
                    let _ = sock.send_to(line.as_bytes(), dst);
                    true
                }
            };
            if !ok {
                *slot = None; // (Unix datagram socket only) reopen next time
            }
        }
    });
}
