//! TLS backends: a [`TlsBackend`] wraps an accepted socket in a TLS session; the
//! socket engine then drives the resulting [`TlsConn`] for any listener that has a
//! backend attached.
//!
//! This backend is openssl. An alternative backend (e.g. rustls) only has to
//! implement these same two traits and it slots straight in.

use crate::map::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use mio::net::TcpStream as MioStream;
use openssl::hash::MessageDigest;
use openssl::ssl::{
    ErrorCode, NameType, SniError, Ssl, SslAcceptor, SslAcceptorBuilder, SslContext, SslFiletype,
    SslMethod, SslMode, SslRef, SslStream, SslVerifyMode,
};

/// A hot-reloadable TLS certificate source (implemented by the openssl backend);
/// the core calls [`reload`](CertReload::reload) on REHASH so a renewed cert is
/// picked up without a restart.
pub trait CertReload: Send + Sync {
    fn reload(&self) -> io::Result<()>;
}

/// The process-wide TLS backend, set once at startup so REHASH can trigger a cert
/// reload without threading a handle through the core thread.
pub static TLS_RELOAD: OnceLock<Arc<dyn CertReload>> = OnceLock::new();

/// A live TLS connection: read/write plaintext, tune the read timeout (the
/// socket engine polls with one to interleave reads and queued writes), and shut
/// it down. The concrete backend type stays hidden behind this.
pub trait TlsConn: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn shutdown(&self);
    /// SHA-256 fingerprint (lowercase hex) of the peer's certificate, if it sent
    /// one. Drives SASL EXTERNAL / CertFP.
    fn peer_cert_fp(&self) -> Option<String>;
    /// `<version>/<group>/<cipher>` summary of the session for the WHOIS 671
    /// sslinfo line, if the backend can report it.
    fn tls_info(&self) -> Option<String> {
        None
    }
    /// The SNI hostname the client requested during the TLS handshake, if any.
    fn sni(&self) -> Option<String> {
        None
    }
}

/// A non-blocking TLS session the reactor drives itself over a mio socket. The
/// handshake and all reads/writes surface `WouldBlock` (mapped from OpenSSL's
/// WANT_READ/WANT_WRITE) so the worker can register interest and come back later
/// instead of blocking a whole thread on one connection.
pub trait TlsSession: Send {
    /// Drive the server handshake: `Ok(true)` once complete, `Ok(false)` while it
    /// still needs I/O, `Err` on a fatal handshake failure.
    fn accept(&mut self) -> io::Result<bool>;
    /// Decrypt application data. `Ok(0)` means the peer sent a clean TLS close.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Encrypt+queue application data; returns the plaintext bytes accepted.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    /// Whether the session still holds outbound TLS bytes not yet pushed to the
    /// socket. rustls buffers ciphertext internally when the socket is full;
    /// openssl surfaces backpressure through `write`, so it never buffers.
    fn wants_write(&self) -> bool {
        false
    }
    /// Push any buffered outbound TLS bytes to the socket. `WouldBlock` leaves the
    /// remainder for the next writable event; a no-op when nothing is buffered.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    /// The underlying mio socket, for the reactor's poll (re)registration.
    fn source(&mut self) -> &mut MioStream;
    /// SHA-256 fingerprint of the peer certificate (CertFP / SASL EXTERNAL), if any.
    fn peer_cert_fp(&self) -> Option<String>;
    /// `<version>/<group>/<cipher>` summary of the session for WHOIS 671, if any.
    fn tls_info(&self) -> Option<String> {
        None
    }
    /// The SNI hostname the client requested during the TLS handshake, if any.
    fn sni(&self) -> Option<String> {
        None
    }
    fn shutdown(&mut self);
}

/// A TLS backend: wraps an accepted socket in a TLS session — either blocking
/// ([`accept`], the thread-per-connection path) or non-blocking ([`start`], the
/// reactor path).
pub trait TlsBackend: Send + Sync {
    fn accept(&self, sock: TcpStream) -> io::Result<Box<dyn TlsConn>>;
    fn start(&self, sock: MioStream) -> io::Result<Box<dyn TlsSession>>;
}

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

// --- openssl backend --------------------------------------------------------

/// A PEM certificate chain + private key on disk.
struct CertPaths {
    cert: String,
    key: String,
}

pub struct OpensslBackend {
    // Swapped atomically by `reload` so renewed certs apply without a restart; read
    // only at connection-accept time (infrequent), so the lock is never hot.
    acceptor: RwLock<SslAcceptor>,
    primary: CertPaths,
    sni: Vec<(String, CertPaths)>, // hostname -> cert/key (SNI)
}

/// Apply the common server settings to a builder: the cert/key, an always-accept
/// client-cert request (for SASL EXTERNAL / CertFP; we never validate the chain —
/// services match the fingerprint), and the non-blocking write modes the reactor needs.
fn configure(b: &mut SslAcceptorBuilder, cert: &str, key: &str) -> io::Result<()> {
    b.set_private_key_file(key, SslFiletype::PEM).map_err(err)?;
    b.set_certificate_chain_file(cert).map_err(err)?;
    b.check_private_key().map_err(err)?;
    b.set_verify_callback(SslVerifyMode::PEER, |_valid, _ctx| true);
    b.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
    Ok(())
}

/// A standalone configured context for one SNI hostname.
fn build_ctx(cert: &str, key: &str) -> io::Result<SslContext> {
    // _v5 = Mozilla intermediate v5 (TLS 1.2 + 1.3); the non-v5 profile caps at 1.2.
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(err)?;
    configure(&mut b, cert, key)?;
    Ok(b.build().into_context())
}

/// Build the acceptor for the primary cert, with a servername callback that
/// switches to a per-hostname context when the client's SNI matches an `sni` entry.
fn build_acceptor(primary: &CertPaths, sni: &[(String, CertPaths)]) -> io::Result<SslAcceptor> {
    let mut map: HashMap<String, SslContext> = HashMap::default();
    for (host, cp) in sni {
        map.insert(host.to_ascii_lowercase(), build_ctx(&cp.cert, &cp.key)?);
    }
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(err)?;
    configure(&mut b, &primary.cert, &primary.key)?;
    if !map.is_empty() {
        b.set_servername_callback(move |ssl, _alert| {
            if let Some(name) = ssl.servername(NameType::HOST_NAME) {
                if let Some(ctx) = map.get(&name.to_ascii_lowercase()) {
                    ssl.set_ssl_context(ctx)
                        .map_err(|_| SniError::ALERT_FATAL)?;
                }
            }
            Ok(())
        });
    }
    Ok(b.build())
}

impl OpensslBackend {
    /// Build an acceptor from a PEM certificate chain + private key, with optional
    /// per-hostname SNI certs `(hostname, cert, key)`.
    pub fn new(
        cert: &str,
        key: &str,
        sni: Vec<(String, String, String)>,
    ) -> io::Result<OpensslBackend> {
        let primary = CertPaths {
            cert: cert.to_string(),
            key: key.to_string(),
        };
        let sni: Vec<(String, CertPaths)> = sni
            .into_iter()
            .map(|(h, c, k)| (h, CertPaths { cert: c, key: k }))
            .collect();
        let acceptor = build_acceptor(&primary, &sni)?;
        Ok(OpensslBackend {
            acceptor: RwLock::new(acceptor),
            primary,
            sni,
        })
    }

    /// Rebuild the acceptor from the cert files on disk (renewed certs) and swap it
    /// in; existing connections keep the context they handshook with.
    pub fn reload(&self) -> io::Result<()> {
        let fresh = build_acceptor(&self.primary, &self.sni)?;
        *self.acceptor.write().unwrap() = fresh;
        Ok(())
    }
}

impl CertReload for OpensslBackend {
    fn reload(&self) -> io::Result<()> {
        OpensslBackend::reload(self)
    }
}

impl TlsBackend for OpensslBackend {
    fn accept(&self, sock: TcpStream) -> io::Result<Box<dyn TlsConn>> {
        let stream = self.acceptor.read().unwrap().accept(sock).map_err(err)?;
        Ok(Box::new(OpensslConn(stream)))
    }

    fn start(&self, sock: MioStream) -> io::Result<Box<dyn TlsSession>> {
        let ssl = Ssl::new(self.acceptor.read().unwrap().context()).map_err(err)?;
        // handshake isn't driven here: SslStream::new just binds the socket; the
        // reactor calls accept() as the socket becomes readable/writable.
        let stream = SslStream::new(ssl, sock).map_err(err)?;
        Ok(Box::new(OpensslSession(stream)))
    }
}

struct OpensslSession(SslStream<MioStream>);

/// Map an OpenSSL ssl error to the reactor's io model: WANT_READ/WANT_WRITE ⇒
/// `WouldBlock` (retry when ready), everything else ⇒ a real error.
fn ssl_io_err(e: openssl::ssl::Error) -> io::Error {
    match e.code() {
        ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => io::ErrorKind::WouldBlock.into(),
        _ => e.into_io_error().unwrap_or_else(io::Error::other),
    }
}

/// `<version>/<group>/<cipher>` for the WHOIS 671 sslinfo line, e.g.
/// `TLSv1.3/X25519MLKEM768/TLS_CHACHA20_POLY1305_SHA256`. The key-exchange group
/// comes from `sslgroup` (SSL_get0_group_name); it's omitted when OpenSSL can't
/// report it (TLS 1.2, or before the handshake completes).
fn openssl_tls_info(ssl: &SslRef) -> Option<String> {
    let cipher = ssl.current_cipher()?.name();
    let ver = ssl.version_str();
    match sslgroup::group_name(ssl) {
        Some(g) if !g.is_empty() => Some(format!("{ver}/{g}/{cipher}")),
        _ => Some(format!("{ver}/{cipher}")),
    }
}

impl TlsSession for OpensslSession {
    fn accept(&mut self) -> io::Result<bool> {
        match self.0.accept() {
            Ok(()) => Ok(true),
            Err(e) => match e.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Ok(false),
                _ => Err(e.into_io_error().unwrap_or_else(io::Error::other)),
            },
        }
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.ssl_read(buf) {
            Ok(n) => Ok(n),
            // a clean TLS close is EOF, like a plaintext socket returning 0
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => Ok(0),
            Err(e) => Err(ssl_io_err(e)),
        }
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.ssl_write(buf).map_err(ssl_io_err)
    }
    fn source(&mut self) -> &mut MioStream {
        self.0.get_mut()
    }
    fn peer_cert_fp(&self) -> Option<String> {
        let cert = self.0.ssl().peer_certificate()?;
        let digest = cert.digest(MessageDigest::sha256()).ok()?;
        Some(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
    fn tls_info(&self) -> Option<String> {
        openssl_tls_info(self.0.ssl())
    }
    fn sni(&self) -> Option<String> {
        self.0
            .ssl()
            .servername(NameType::HOST_NAME)
            .map(String::from)
    }
    fn shutdown(&mut self) {
        // best-effort TLS close_notify, then close the socket. Non-blocking, so a
        // WouldBlock just means the alert is queued — we don't wait for the peer's.
        let _ = self.0.shutdown();
        let _ = self.0.get_ref().shutdown(Shutdown::Both);
    }
}

struct OpensslConn(SslStream<TcpStream>);

impl TlsConn for OpensslConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.get_ref().set_read_timeout(dur)
    }
    fn shutdown(&self) {
        let _ = self.0.get_ref().shutdown(Shutdown::Both);
    }
    fn peer_cert_fp(&self) -> Option<String> {
        let cert = self.0.ssl().peer_certificate()?;
        let digest = cert.digest(MessageDigest::sha256()).ok()?;
        Some(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
    fn tls_info(&self) -> Option<String> {
        openssl_tls_info(self.0.ssl())
    }
    fn sni(&self) -> Option<String> {
        self.0
            .ssl()
            .servername(NameType::HOST_NAME)
            .map(String::from)
    }
}
