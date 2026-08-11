//! HAProxy PROXY protocol (v1 text + v2 binary) — the header a trusted load
//! balancer / TCP proxy prepends to a connection to carry the real client address.
//! Only the source address is needed; when the header says LOCAL (a health check)
//! or an address family we don't translate, the original peer address is kept.
//!
//! Enabled per source with `proxy = <ip glob>` (repeatable); connections from a
//! matching proxy must lead with a PROXY header, which is stripped before the first
//! IRC byte so `add_conn`'s connect-time checks see the real client IP.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The 12-byte v2 signature.
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// A v1 line is at most 107 bytes including CRLF.
const V1_MAX: usize = 107;

/// The result of trying to parse a PROXY header from a byte prefix.
pub enum Parsed {
    /// A full header giving the real client (source) address, plus any TLS metadata
    /// a v2 header forwarded (a TLS-terminating proxy sets `secure` and, if it
    /// forwards one, the client cert `certfp`).
    Proxy {
        addr: SocketAddr,
        secure: bool,
        certfp: Option<String>,
    },
    /// A full header with no address to apply (LOCAL / unsupported family).
    Local,
    /// Not enough bytes yet — read more and retry.
    Need,
    /// Not a valid PROXY header.
    Invalid,
}

/// Try to parse a PROXY header at the start of `buf`. Returns the parse result and,
/// when a full header was consumed, how many bytes it occupied.
pub fn parse(buf: &[u8]) -> (Parsed, usize) {
    let vlen = buf.len().min(12);
    if buf[..vlen] == V2_SIG[..vlen] {
        if buf.len() < 12 {
            return (Parsed::Need, 0);
        }
        return parse_v2(buf);
    }
    if buf.starts_with(b"PROXY ") {
        return parse_v1(buf);
    }
    if buf.len() < 6 && b"PROXY "[..buf.len()] == *buf {
        return (Parsed::Need, 0); // still could become "PROXY "
    }
    (Parsed::Invalid, 0)
}

/// Blocking-read exactly one PROXY header from `r` for the thread-model paths (TLS).
/// Reads a byte at a time and re-parses, so it never consumes bytes past the header
/// (which would corrupt the following TLS handshake).
pub fn read_header<R: Read>(r: &mut R) -> Parsed {
    let mut buf = Vec::with_capacity(64);
    let mut one = [0u8; 1];
    loop {
        match r.read(&mut one) {
            Ok(0) | Err(_) => return Parsed::Invalid,
            Ok(_) => buf.push(one[0]),
        }
        if buf.len() > 256 {
            return Parsed::Invalid;
        }
        match parse(&buf) {
            (Parsed::Need, _) => continue,
            (result, _) => return result, // complete: used == buf.len() by construction
        }
    }
}

fn parse_v1(buf: &[u8]) -> (Parsed, usize) {
    let Some(nl) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() > V1_MAX {
            (Parsed::Invalid, 0)
        } else {
            (Parsed::Need, 0)
        };
    };
    let consumed = nl + 2;
    let Ok(line) = std::str::from_utf8(&buf[..nl]) else {
        return (Parsed::Invalid, consumed);
    };
    let p: Vec<&str> = line.split(' ').collect();
    if p.len() < 2 {
        return (Parsed::Invalid, consumed);
    }
    match p[1] {
        "TCP4" | "TCP6" => {
            if p.len() != 6 {
                return (Parsed::Invalid, consumed);
            }
            match (p[2].parse::<IpAddr>(), p[4].parse::<u16>()) {
                (Ok(ip), Ok(port)) => (
                    Parsed::Proxy {
                        addr: SocketAddr::new(ip, port),
                        secure: false,
                        certfp: None,
                    },
                    consumed,
                ),
                _ => (Parsed::Invalid, consumed),
            }
        }
        "UNKNOWN" => (Parsed::Local, consumed),
        _ => (Parsed::Invalid, consumed),
    }
}

fn parse_v2(buf: &[u8]) -> (Parsed, usize) {
    if buf.len() < 16 {
        return (Parsed::Need, 0);
    }
    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 2 {
        return (Parsed::Invalid, 0);
    }
    let cmd = ver_cmd & 0x0f;
    let family = buf[13] >> 4;
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = 16 + len;
    if buf.len() < total {
        return (Parsed::Need, 0);
    }
    if cmd == 0 {
        return (Parsed::Local, total); // LOCAL (health check)
    }
    if cmd != 1 {
        return (Parsed::Invalid, total);
    }
    let a = &buf[16..total];
    let (addr, fixed) = match family {
        1 if len >= 12 => {
            let src = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            let sport = u16::from_be_bytes([a[8], a[9]]);
            (SocketAddr::new(IpAddr::V4(src), sport), 12)
        }
        2 if len >= 36 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&a[0..16]);
            let sport = u16::from_be_bytes([a[32], a[33]]);
            (SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), sport), 36)
        }
        _ => return (Parsed::Local, total), // AF_UNIX / unspecified: keep peer addr
    };
    // any bytes after the fixed address are TLVs: a TLS-terminating proxy may
    // forward the client's TLS status (PP2_TYPE_SSL) and cert fingerprint (CERTFP)
    let (secure, certfp) = parse_v2_tlvs(&a[fixed..]);
    (
        Parsed::Proxy {
            addr,
            secure,
            certfp,
        },
        total,
    )
}

// PROXY v2 TLV types we care about.
const PP2_TYPE_SSL: u8 = 0x20;
const PP2_TYPE_CERTFP: u8 = 0xE0;
const PP2_CLIENT_SSL: u8 = 0x01;

/// Walk the v2 TLV block: `type(1) len(2, big-endian) value(len)`. Returns whether
/// the client was on TLS and its forwarded cert fingerprint, if any.
fn parse_v2_tlvs(mut tlv: &[u8]) -> (bool, Option<String>) {
    let mut secure = false;
    let mut certfp = None;
    while tlv.len() >= 3 {
        let ttype = tlv[0];
        let tlen = u16::from_be_bytes([tlv[1], tlv[2]]) as usize;
        if tlv.len() < 3 + tlen {
            break; // truncated TLV
        }
        let val = &tlv[3..3 + tlen];
        match ttype {
            PP2_TYPE_SSL => {
                if !val.is_empty() && val[0] & PP2_CLIENT_SSL != 0 {
                    secure = true;
                }
            }
            PP2_TYPE_CERTFP => {
                if let Ok(s) = std::str::from_utf8(val) {
                    if !s.is_empty() && s.len() <= 128 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
                        certfp = Some(s.to_string());
                    }
                }
            }
            _ => {}
        }
        tlv = &tlv[3 + tlen..];
    }
    (secure, certfp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(p: &Parsed) -> Option<SocketAddr> {
        match p {
            Parsed::Proxy { addr, .. } => Some(*addr),
            _ => None,
        }
    }

    #[test]
    fn v1_tcp4() {
        let (r, n) = parse(b"PROXY TCP4 192.0.2.9 10.0.0.1 56324 6667\r\nNICK bob\r\n");
        assert_eq!(src(&r).unwrap().to_string(), "192.0.2.9:56324");
        assert_eq!(n, 42); // header up to and including CRLF
    }

    #[test]
    fn v1_partial_needs_more() {
        assert!(matches!(parse(b"PROXY TCP4 192.0.2.9 10.0"), (Parsed::Need, _)));
        assert!(matches!(parse(b"PRO"), (Parsed::Need, _)));
    }

    #[test]
    fn v1_unknown_is_local() {
        assert!(matches!(parse(b"PROXY UNKNOWN\r\n"), (Parsed::Local, _)));
    }

    #[test]
    fn v1_garbage_invalid() {
        assert!(matches!(parse(b"HELLO THERE\r\n"), (Parsed::Invalid, _)));
        assert!(matches!(parse(b"PROXY TCP4 bad ip x y\r\n"), (Parsed::Invalid, _)));
    }

    #[test]
    fn v2_ipv4() {
        let mut h = V2_SIG.to_vec();
        h.push(0x21); // v2, PROXY
        h.push(0x11); // AF_INET, STREAM
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[203, 0, 113, 7]); // src ip
        h.extend_from_slice(&[10, 0, 0, 1]); // dst ip
        h.extend_from_slice(&0xC000u16.to_be_bytes()); // src port 49152
        h.extend_from_slice(&6667u16.to_be_bytes()); // dst port
        h.extend_from_slice(b"NICK x\r\n");
        let (r, n) = parse(&h);
        assert_eq!(src(&r).unwrap().to_string(), "203.0.113.7:49152");
        assert_eq!(n, 28);
    }

    #[test]
    fn v2_tls_tlvs() {
        // a TLS-terminating proxy forwards PP2_TYPE_SSL (client-on-TLS) + CERTFP
        let mut h = V2_SIG.to_vec();
        h.push(0x21); // v2, PROXY
        h.push(0x11); // AF_INET, STREAM
        h.extend_from_slice(&31u16.to_be_bytes()); // 12 addr + 8 SSL TLV + 11 CERTFP TLV
        h.extend_from_slice(&[198, 51, 100, 10]); // src
        h.extend_from_slice(&[10, 0, 0, 1]); // dst
        h.extend_from_slice(&5000u16.to_be_bytes());
        h.extend_from_slice(&443u16.to_be_bytes());
        h.push(0x20); // PP2_TYPE_SSL
        h.extend_from_slice(&5u16.to_be_bytes());
        h.extend_from_slice(&[0x01, 0, 0, 0, 0]); // client=PP2_CLIENT_SSL, verify=0
        h.push(0xE0); // PP2_TYPE_CERTFP
        h.extend_from_slice(&8u16.to_be_bytes());
        h.extend_from_slice(b"abcd1234");
        match parse(&h).0 {
            Parsed::Proxy {
                addr,
                secure,
                certfp,
            } => {
                assert_eq!(addr.to_string(), "198.51.100.10:5000");
                assert!(secure);
                assert_eq!(certfp.as_deref(), Some("abcd1234"));
            }
            _ => panic!("expected Proxy"),
        }
    }

    #[test]
    fn v2_partial_and_local() {
        assert!(matches!(parse(&V2_SIG[..8]), (Parsed::Need, _)));
        let mut h = V2_SIG.to_vec();
        h.push(0x20); // v2, LOCAL
        h.push(0x00);
        h.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(parse(&h), (Parsed::Local, 16)));
    }
}
