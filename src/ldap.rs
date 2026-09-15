//! A tiny, dependency-free LDAPv3 client — just enough for authentication: a single
//! **simple bind** (RFC 4511), hand-rolled BER/ASN.1, over plain TCP or `ldaps://` TLS
//! (the openssl already linked for the rest of the daemon). Used by `ldapoper` to verify
//! an operator's password against a directory (Active Directory / OpenLDAP) instead of a
//! local hash. Blocking — callers run it off the core thread (via `spawn_crypto`).
//!
//! No unauthenticated binds: an empty password is treated as an auth failure, never sent
//! (an LDAP simple bind with an empty password is an *anonymous* bind that most servers
//! accept — that would turn a blank password into a successful login).

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

// --- BER encoding (definite lengths only) ------------------------------------

/// A BER definite length: short form (<128) or long form.
fn ber_len(n: usize) -> Vec<u8> {
    if n < 128 {
        return vec![n as u8];
    }
    let mut b = Vec::new();
    let mut v = n;
    while v > 0 {
        b.push((v & 0xff) as u8);
        v >>= 8;
    }
    b.reverse();
    let mut out = vec![0x80 | b.len() as u8];
    out.extend_from_slice(&b);
    out
}

/// A tag-length-value with the given tag byte wrapping `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// A BER INTEGER (0x02) for a small non-negative value (message id, version).
fn ber_int(v: u32) -> Vec<u8> {
    if v == 0 {
        return tlv(0x02, &[0]);
    }
    let mut bytes = Vec::new();
    let mut n = v;
    while n != 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0); // keep it positive
    }
    tlv(0x02, &bytes)
}

/// Encode a `BindRequest` LDAPMessage: version 3, simple auth (DN + password).
fn bind_request(msg_id: u32, dn: &str, password: &str) -> Vec<u8> {
    let mut br = Vec::new();
    br.extend_from_slice(&ber_int(3)); // version = 3
    br.extend_from_slice(&tlv(0x04, dn.as_bytes())); // name (LDAPDN)
    br.extend_from_slice(&tlv(0x80, password.as_bytes())); // [0] simple auth
    let bind = tlv(0x60, &br); // [APPLICATION 0] BindRequest
    let mut lm = ber_int(msg_id);
    lm.extend_from_slice(&bind);
    tlv(0x30, &lm) // LDAPMessage SEQUENCE
}

// --- BER decoding ------------------------------------------------------------

/// Read one TLV at `pos`: `(tag, value_start, value_end)`. `None` on truncation, an
/// unsupported indefinite/oversized length, or an out-of-range value.
fn read_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *buf.get(pos)?;
    let l0 = *buf.get(pos + 1)? as usize;
    let (len, vstart) = if l0 < 128 {
        (l0, pos + 2)
    } else {
        let nbytes = l0 & 0x7f;
        if nbytes == 0 || nbytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..nbytes {
            len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
        }
        (len, pos + 2 + nbytes)
    };
    let vend = vstart.checked_add(len)?;
    if vend > buf.len() {
        return None;
    }
    Some((tag, vstart, vend))
}

/// Extract the `resultCode` from a `BindResponse` LDAPMessage. `None` if malformed.
/// `0` = success; `49` = invalid credentials; other non-zero = other failures.
pub fn parse_bind_result(msg: &[u8]) -> Option<u32> {
    let (tag, vs, _ve) = read_tlv(msg, 0)?; // LDAPMessage SEQUENCE
    if tag != 0x30 {
        return None;
    }
    let (t_id, _, id_end) = read_tlv(msg, vs)?; // messageID INTEGER
    if t_id != 0x02 {
        return None;
    }
    let (t_op, op_vs, _) = read_tlv(msg, id_end)?; // protocolOp
    if t_op != 0x61 {
        return None; // not a BindResponse [APPLICATION 1]
    }
    let (t_rc, rc_vs, rc_ve) = read_tlv(msg, op_vs)?; // resultCode ENUMERATED
    if t_rc != 0x0a || rc_ve - rc_vs == 0 || rc_ve - rc_vs > 4 {
        return None;
    }
    let mut code = 0u32;
    for i in rc_vs..rc_ve {
        code = (code << 8) | msg[i] as u32;
    }
    Some(code)
}

// --- transport ---------------------------------------------------------------

/// Read exactly one LDAPMessage (a BER SEQUENCE) from the stream: the tag + definite
/// length header, then the body. Bounded to 1 MiB so a hostile length can't OOM us.
fn read_message(s: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut two = [0u8; 2];
    s.read_exact(&mut two).map_err(|e| e.to_string())?;
    let mut msg = vec![two[0], two[1]];
    let l0 = two[1];
    let body_len = if l0 < 128 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("bad LDAP length".into());
        }
        let mut lb = vec![0u8; n];
        s.read_exact(&mut lb).map_err(|e| e.to_string())?;
        let mut len = 0usize;
        for &b in &lb {
            len = (len << 8) | b as usize;
        }
        msg.extend_from_slice(&lb);
        len
    };
    if body_len > 1 << 20 {
        return Err("LDAP message too large".into());
    }
    let mut body = vec![0u8; body_len];
    s.read_exact(&mut body).map_err(|e| e.to_string())?;
    msg.extend_from_slice(&body);
    Ok(msg)
}

/// Verify `password` for `dn` against the directory at `server` (`ldap://host[:port]` or
/// `ldaps://host[:port]`) with a simple bind. `Ok(true)` = authenticated, `Ok(false)` =
/// bad credentials, `Err` = a connection/protocol problem. `verify` controls TLS
/// certificate + hostname verification for `ldaps://`.
pub fn simple_bind(
    server: &str,
    dn: &str,
    password: &str,
    verify: bool,
    timeout: Duration,
) -> Result<bool, String> {
    if password.is_empty() {
        return Ok(false); // never send an anonymous/unauthenticated bind
    }
    let (tls, rest) = match server.strip_prefix("ldaps://") {
        Some(r) => (true, r),
        None => (false, server.strip_prefix("ldap://").unwrap_or(server)),
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "bad LDAP port".to_string())?),
        None => (rest, if tls { 636 } else { 389 }),
    };
    if host.is_empty() {
        return Err("empty LDAP host".into());
    }
    let req = bind_request(1, dn, password);
    let stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    let resp = if tls {
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
        if !verify {
            b.set_verify(SslVerifyMode::NONE);
        }
        let mut s = b.build().connect(host, stream).map_err(|e| e.to_string())?;
        s.write_all(&req).map_err(|e| e.to_string())?;
        read_message(&mut s)?
    } else {
        let mut s = stream;
        s.write_all(&req).map_err(|e| e.to_string())?;
        read_message(&mut s)?
    };
    match parse_bind_result(&resp) {
        Some(0) => Ok(true),
        Some(_) => Ok(false),
        None => Err("malformed LDAP bind response".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn bind_request_encodes_ber() {
        // dn "cn=a", password "b", messageID 1
        let got = bind_request(1, "cn=a", "b");
        let want = [
            0x30, 0x11, // LDAPMessage SEQUENCE, len 17
            0x02, 0x01, 0x01, // messageID 1
            0x60, 0x0c, // BindRequest [APPLICATION 0], len 12
            0x02, 0x01, 0x03, // version 3
            0x04, 0x04, 0x63, 0x6e, 0x3d, 0x61, // name "cn=a"
            0x80, 0x01, 0x62, // [0] simple auth "b"
        ];
        assert_eq!(got, want);
    }

    fn bind_response(code: u32) -> Vec<u8> {
        // BindResponse{ resultCode=code, matchedDN="", diagnosticMessage="" }
        let mut inner = tlv(0x0a, &[code as u8]); // ENUMERATED
        inner.extend_from_slice(&tlv(0x04, b"")); // matchedDN
        inner.extend_from_slice(&tlv(0x04, b"")); // diagnosticMessage
        let br = tlv(0x61, &inner);
        let mut lm = ber_int(1);
        lm.extend_from_slice(&br);
        tlv(0x30, &lm)
    }

    #[test]
    fn parses_bind_result_codes() {
        assert_eq!(parse_bind_result(&bind_response(0)), Some(0)); // success
        assert_eq!(parse_bind_result(&bind_response(49)), Some(49)); // invalid creds
        assert_eq!(parse_bind_result(b""), None); // empty
        assert_eq!(parse_bind_result(&[0x30, 0x02, 0x02, 0x01]), None); // truncated
        assert_eq!(parse_bind_result(&[0x02, 0x01, 0x01]), None); // not a SEQUENCE
    }

    #[test]
    fn empty_password_is_rejected_without_a_connection() {
        // must not even attempt to connect (no anonymous bind); returns Ok(false)
        assert_eq!(
            simple_bind("ldap://127.0.0.1:1", "cn=x", "", true, Duration::from_millis(50)),
            Ok(false)
        );
    }

    proptest! {
        // The response parser eats data from a configured-but-untrusted directory; no
        // byte string may panic it (pointer-free, but lengths are attacker-controlled).
        #[test]
        fn parse_bind_result_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_bind_result(&bytes);
        }
    }
}
