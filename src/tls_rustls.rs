//! Pure-Rust TLS backend (rustls), an alternative to the openssl backend behind the
//! same [`TlsBackend`]/[`TlsConn`]/[`TlsSession`] traits. Opt in with
//! `tls_backend = rustls` in the config; the default stays openssl. No C/FFI in the
//! daemon itself — rustls keeps its `unsafe` internal like every other crate.
//!
//! Client certs are requested but never chain-validated (services identify a user by
//! the cert *fingerprint*, not a CA), mirroring the openssl backend's always-accept
//! verify callback. The client's CertificateVerify signature IS still checked, so
//! CertFP / SASL EXTERNAL keeps proving the client holds the matching private key.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use mio::net::TcpStream as MioStream;
use openssl::hash::{hash, MessageDigest};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection, SignatureScheme,
};

use crate::map::HashMap;
use crate::tls::{CertReload, TlsBackend, TlsConn, TlsSession};

fn err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

struct CertPaths {
    cert: String,
    key: String,
}

pub struct RustlsBackend {
    // Swapped by `reload` on REHASH so renewed certs apply without a restart; read
    // only at connection-accept time (infrequent), so the lock is never hot.
    config: RwLock<Arc<ServerConfig>>,
    primary: CertPaths,
    sni: Vec<(String, CertPaths)>,
    provider: Arc<CryptoProvider>,
}

/// Load a PEM chain + private key into a rustls `CertifiedKey`.
fn load_key(cert: &str, key: &str, provider: &CryptoProvider) -> io::Result<Arc<CertifiedKey>> {
    let cert_pem = std::fs::read(cert)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(err)?;
    if certs.is_empty() {
        return Err(err(format!("no certificates in {cert}")));
    }
    let key_pem = std::fs::read(key)?;
    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(err)?
        .ok_or_else(|| err(format!("no private key in {key}")))?;
    let signing_key = provider.key_provider.load_private_key(key_der).map_err(err)?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Per-hostname cert selection: the SNI name's cert, else the primary. Mirrors the
/// openssl backend's servername callback (no validation of the SNI cert here).
#[derive(Debug)]
struct SniResolver {
    default: Arc<CertifiedKey>,
    by_host: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = hello.server_name() {
            if let Some(ck) = self.by_host.get(&name.to_ascii_lowercase()) {
                return Some(ck.clone());
            }
        }
        Some(self.default.clone())
    }
}

/// Accept any client certificate (we fingerprint, never chain-validate) but still
/// verify the handshake signature so CertFP can't be spoofed without the key.
#[derive(Debug)]
struct AcceptAnyClientCert {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end: &CertificateDer,
        _intermediates: &[CertificateDer],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
}

/// SHA-256 fingerprint (lowercase hex) of the peer's leaf certificate, matching the
/// openssl backend's format so CertFP is identical across backends.
fn fp_of(certs: Option<&[CertificateDer<'_>]>) -> Option<String> {
    let cert = certs?.first()?;
    let digest = hash(MessageDigest::sha256(), cert.as_ref()).ok()?;
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn build_config(
    primary: &CertPaths,
    sni: &[(String, CertPaths)],
    provider: &Arc<CryptoProvider>,
) -> io::Result<Arc<ServerConfig>> {
    let default = load_key(&primary.cert, &primary.key, provider)?;
    let mut by_host: HashMap<String, Arc<CertifiedKey>> = HashMap::default();
    for (h, cp) in sni {
        by_host.insert(h.to_ascii_lowercase(), load_key(&cp.cert, &cp.key, provider)?);
    }
    let resolver = Arc::new(SniResolver { default, by_host });
    let verifier = Arc::new(AcceptAnyClientCert {
        provider: provider.clone(),
    });
    let cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(err)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    Ok(Arc::new(cfg))
}

impl RustlsBackend {
    pub fn new(cert: &str, key: &str, sni: Vec<(String, String, String)>) -> io::Result<RustlsBackend> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let primary = CertPaths {
            cert: cert.to_string(),
            key: key.to_string(),
        };
        let sni: Vec<(String, CertPaths)> = sni
            .into_iter()
            .map(|(h, c, k)| (h, CertPaths { cert: c, key: k }))
            .collect();
        let config = build_config(&primary, &sni, &provider)?;
        Ok(RustlsBackend {
            config: RwLock::new(config),
            primary,
            sni,
            provider,
        })
    }

    pub fn reload(&self) -> io::Result<()> {
        let fresh = build_config(&self.primary, &self.sni, &self.provider)?;
        *self.config.write().unwrap() = fresh;
        Ok(())
    }

    fn cfg(&self) -> Arc<ServerConfig> {
        self.config.read().unwrap().clone()
    }
}

impl CertReload for RustlsBackend {
    fn reload(&self) -> io::Result<()> {
        RustlsBackend::reload(self)
    }
}

impl TlsBackend for RustlsBackend {
    fn accept(&self, mut sock: TcpStream) -> io::Result<Box<dyn TlsConn>> {
        let mut conn = ServerConnection::new(self.cfg()).map_err(err)?;
        // complete the handshake now, on the (blocking) socket, like openssl's accept
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(err)?;
        }
        Ok(Box::new(RustlsConn { conn, sock }))
    }

    fn start(&self, sock: MioStream) -> io::Result<Box<dyn TlsSession>> {
        let mut conn = ServerConnection::new(self.cfg()).map_err(err)?;
        // bound the buffered plaintext so a slow-reading client makes writer().write()
        // return short (backpressure) instead of growing without limit; the reactor's
        // sendq caps then govern it, matching the openssl backend.
        conn.set_buffer_limit(Some(256 * 1024));
        Ok(Box::new(RustlsSession { conn, sock }))
    }
}

// --- blocking connection (thread-per-conn path) -----------------------------
struct RustlsConn {
    conn: ServerConnection,
    sock: TcpStream,
}

impl TlsConn for RustlsConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).read(buf)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).write_all(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).flush()
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(dur)
    }
    fn shutdown(&self) {
        let _ = self.sock.shutdown(Shutdown::Both);
    }
    fn peer_cert_fp(&self) -> Option<String> {
        fp_of(self.conn.peer_certificates())
    }
}

// --- non-blocking session (reactor path) ------------------------------------
struct RustlsSession {
    conn: ServerConnection,
    sock: MioStream,
}

impl RustlsSession {
    /// Drain any decryptable TLS records the socket has for us, processing each.
    /// `WouldBlock`/EOF just stop the loop — the caller checks state afterwards.
    fn pump_read(&mut self) -> io::Result<()> {
        loop {
            match self.conn.read_tls(&mut self.sock) {
                Ok(0) => return Ok(()), // socket EOF; reader() will report the close
                Ok(_) => self.conn.process_new_packets().map_err(err)?,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            };
        }
    }
    /// Flush rustls's pending outbound TLS bytes to the socket; a full socket
    /// (`WouldBlock`) just leaves them buffered for the next writable event.
    fn pump_write(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.sock) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl TlsSession for RustlsSession {
    fn accept(&mut self) -> io::Result<bool> {
        self.pump_read()?;
        self.pump_write()?; // handshake flight, and session tickets once it's done
        Ok(!self.conn.is_handshaking())
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.pump_read()?;
        self.pump_write()?; // process_new_packets can queue writes (alerts, key updates)
        match self.conn.reader().read(buf) {
            Ok(n) => Ok(n), // Ok(0) = clean close_notify, like a plaintext EOF
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(e) => Err(e),
        }
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(buf)?;
        self.pump_write()?;
        Ok(n)
    }
    fn wants_write(&self) -> bool {
        // rustls holds encrypted bytes when the socket filled mid-flush; the reactor
        // must keep WRITABLE interest and drain them, or a burst strands here.
        self.conn.wants_write()
    }
    fn flush(&mut self) -> io::Result<()> {
        self.pump_write()
    }
    fn source(&mut self) -> &mut MioStream {
        &mut self.sock
    }
    fn peer_cert_fp(&self) -> Option<String> {
        fp_of(self.conn.peer_certificates())
    }
    fn shutdown(&mut self) {
        self.conn.send_close_notify();
        let _ = self.pump_write();
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}
