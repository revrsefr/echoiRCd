//! TLS backends — echoIRCd's answer to InspIRCd's `IOHook` seam and its
//! `ssl_openssl` / `ssl_gnutls` modules. A [`TlsBackend`] wraps an accepted
//! socket in a TLS session; the socket engine then drives the resulting
//! [`TlsConn`] for any listener that has a backend attached.
//!
//! This backend is openssl. The `openssl` crate keeps all its `unsafe` internal,
//! so the daemon itself stays `#![forbid(unsafe_code)]`. A pure-Rust `rustls`
//! backend (or a gnutls one) only has to implement these same two traits and it
//! slots straight in — exactly the pluggable-provider shape InspIRCd uses.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};

/// A live TLS connection: read/write plaintext, tune the read timeout (the
/// socket engine polls with one to interleave reads and queued writes), and shut
/// it down. The concrete backend type stays hidden behind this.
pub trait TlsConn: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn shutdown(&self);
}

/// A TLS backend: performs the server-side handshake on an accepted socket.
pub trait TlsBackend: Send + Sync {
    fn accept(&self, sock: TcpStream) -> io::Result<Box<dyn TlsConn>>;
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
}
