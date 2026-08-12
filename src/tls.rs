//! TLS backends: a [`TlsBackend`] wraps an accepted socket in a TLS session; the
//! socket engine then drives the resulting [`TlsConn`] for any listener that has a
//! backend attached.
//!
//! This backend is openssl. An alternative backend (e.g. rustls) only has to
//! implement these same two traits and it slots straight in.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use mio::net::TcpStream as MioStream;
use openssl::hash::MessageDigest;
use openssl::ssl::{
    ErrorCode, Ssl, SslAcceptor, SslFiletype, SslMethod, SslMode, SslStream, SslVerifyMode,
};

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
    /// The underlying mio socket, for the reactor's poll (re)registration.
    fn source(&mut self) -> &mut MioStream;
    /// SHA-256 fingerprint of the peer certificate (CertFP / SASL EXTERNAL), if any.
    fn peer_cert_fp(&self) -> Option<String>;
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

pub struct OpensslBackend {
    acceptor: SslAcceptor,
}

impl OpensslBackend {
    /// Build an acceptor from a PEM certificate chain + private key.
    pub fn new(cert: &str, key: &str) -> io::Result<OpensslBackend> {
        let mut b = SslAcceptor::mozilla_intermediate(SslMethod::tls()).map_err(err)?;
        b.set_private_key_file(key, SslFiletype::PEM).map_err(err)?;
        b.set_certificate_chain_file(cert).map_err(err)?;
        b.check_private_key().map_err(err)?;
        // Request (but don't require) a client cert so SASL EXTERNAL / CertFP can
        // read its fingerprint. We never validate the chain — services match the
        // fingerprint to an account — so the callback always accepts.
        b.set_verify_callback(SslVerifyMode::PEER, |_valid, _ctx| true);
        // The reactor drives writes non-blocking and may retry SSL_write with a moved
        // or grown buffer after a WouldBlock; allow that and partial progress so a slow
        // TLS reader can't wedge a worker.
        b.set_mode(SslMode::ENABLE_PARTIAL_WRITE | SslMode::ACCEPT_MOVING_WRITE_BUFFER);
        Ok(OpensslBackend {
            acceptor: b.build(),
        })
    }
}

impl TlsBackend for OpensslBackend {
    fn accept(&self, sock: TcpStream) -> io::Result<Box<dyn TlsConn>> {
        let stream = self.acceptor.accept(sock).map_err(err)?;
        Ok(Box::new(OpensslConn(stream)))
    }

    fn start(&self, sock: MioStream) -> io::Result<Box<dyn TlsSession>> {
        let ssl = Ssl::new(self.acceptor.context()).map_err(err)?;
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
}
