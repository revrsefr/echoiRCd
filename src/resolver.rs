//! Reverse-DNS host resolution — echoIRCd's answer to InspIRCd's async resolver,
//! done from scratch with std UDP (no DNS crate, no `unsafe`). Given a client IP
//! it looks up the PTR record and **forward-confirms** it (the name must resolve
//! back to the same IP, so a client can't fake a hostname — same anti-spoofing
//! InspIRCd does). Best-effort: any failure returns `None` and the caller keeps
//! the IP. It runs off the core thread, so it never blocks the daemon, and it's
//! bounded in time (the UDP read timeout) and in concurrency (`try_acquire`).

use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How long to wait for the DNS server before giving up.
pub const DNS_TIMEOUT: Duration = Duration::from_millis(2500);
/// Cap on concurrent in-flight lookups (one short-lived thread each), so a
/// connection flood can't spawn unbounded resolver threads.
const MAX_ACTIVE: usize = 512;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

const QTYPE_PTR: u16 = 12;
const QCLASS_IN: u16 = 1;

/// Reserve a lookup slot; `false` if too many are already in flight.
pub fn try_acquire() -> bool {
    // bump then check, so this is a simple bounded gate
    if ACTIVE.fetch_add(1, Ordering::Relaxed) < MAX_ACTIVE {
        true
    } else {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        false
    }
}

/// Release a slot taken by [`try_acquire`] (call once the lookup is done).
pub fn release() {
    ACTIVE.fetch_sub(1, Ordering::Relaxed);
}

/// Reverse-resolve `ip` and forward-confirm. `Some(host)` only if a PTR exists
/// and that host resolves back to `ip`.
pub fn reverse_confirmed(ip: IpAddr, timeout: Duration) -> Option<String> {
    let ns = nameserver();
    let ptr = ptr_lookup(&ns, &reverse_name(ip), timeout)?;
    // forward-confirm: the resolved name must map back to this IP
    let ok = (ptr.as_str(), 0u16)
        .to_socket_addrs()
        .ok()?
        .any(|sa| sa.ip() == ip);
    (ok && !ptr.is_empty()).then_some(ptr)
}

/// The `in-addr.arpa` / `ip6.arpa` reverse name for `ip`.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(72);
            for octet in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", octet & 0xf, octet >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// First `nameserver` in /etc/resolv.conf, else a sensible fallback.
fn nameserver() -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver ") {
                let ns = rest.trim();
                if !ns.is_empty() {
                    return format!("{ns}:53");
                }
            }
        }
    }
    "1.1.1.1:53".to_string()
}

/// Send a PTR query for `qname` to `ns` and return the first PTR answer name.
fn ptr_lookup(ns: &str, qname: &str, timeout: Duration) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .or_else(|_| UdpSocket::bind("[::]:0"))
        .ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;

    let id: u16 = 0x4543; // fixed query id ("EC"); we match it on the reply
    let mut query = Vec::with_capacity(qname.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    query.extend_from_slice(&[0, 1]); // QDCOUNT=1
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    encode_name(&mut query, qname);
    query.extend_from_slice(&QTYPE_PTR.to_be_bytes());
    query.extend_from_slice(&QCLASS_IN.to_be_bytes());

    sock.send_to(&query, ns).ok()?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).ok()?;
    parse_ptr_reply(&buf[..n], id)
}

/// Encode a dotted name into wire format (length-prefixed labels + root 0).
fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// Parse a DNS reply for the first PTR answer's name. Fully bounds-checked — the
/// packet is untrusted, so nothing here may panic or loop forever.
fn parse_ptr_reply(msg: &[u8], want_id: u16) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != want_id {
        return None;
    }
    if msg[3] & 0x0f != 0 {
        return None; // rcode != NOERROR
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    if an == 0 {
        return None;
    }
    let mut pos = 12;
    // skip the questions
    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4)?; // qtype + qclass
        if pos > msg.len() {
            return None;
        }
    }
    // walk the answer records
    for _ in 0..an {
        pos = skip_name(msg, pos)?; // name
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > msg.len() {
            return None;
        }
        if rtype == QTYPE_PTR {
            return read_name(msg, rdata, 0).map(|(name, _)| name);
        }
        pos = rdata + rdlen;
    }
    None
}

/// Advance past a name (labels + optional compression pointer), returning the
/// offset just after it (a pointer ends the name in-place).
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2); // 2-byte compression pointer ends the name
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize)?;
        if pos > msg.len() {
            return None;
        }
    }
}

/// Decode a (possibly compressed) name at `pos`. `jumps` guards against pointer
/// loops. Returns the dotted name and the offset after the name in the record.
fn read_name(msg: &[u8], mut pos: usize, jumps: u32) -> Option<(String, usize)> {
    if jumps > 32 {
        return None; // too many compression jumps — malformed/hostile
    }
    let mut out = String::new();
    let mut after: Option<usize> = None;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let ptr = ((len as usize & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            let end = after.unwrap_or(pos + 2);
            let (rest, _) = read_name(msg, ptr, jumps + 1)?;
            if !rest.is_empty() {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&rest);
            }
            return Some((out, end));
        }
        if len == 0 {
            return Some((out, after.unwrap_or(pos + 1)));
        }
        let start = pos + 1;
        let stop = start.checked_add(len as usize)?;
        let label = msg.get(start..stop)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label));
        pos = stop;
        after.get_or_insert(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            "4.3.2.1.in-addr.arpa"
        );
        let v6 = reverse_name(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert!(v6.ends_with("ip6.arpa") && v6.starts_with("1.0.0.0."));
    }

    // End-to-end round trip against the real resolver — proves query build → send
    // → recv → parse → forward-confirm works. Needs network, so it's #[ignore]d;
    // run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs network"]
    fn live_reverse_lookup_of_public_ips() {
        let one = reverse_confirmed(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), DNS_TIMEOUT);
        assert_eq!(one.as_deref(), Some("one.one.one.one"), "got {one:?}");
        let g = reverse_confirmed(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), DNS_TIMEOUT);
        assert_eq!(g.as_deref(), Some("dns.google"), "got {g:?}");
    }

    #[test]
    fn parses_a_ptr_reply() {
        // hand-built reply: id EC, 1 question, 1 PTR answer "host.example" using
        // a compression pointer back to "example" in the question.
        let mut m = Vec::new();
        m.extend_from_slice(&0x4543u16.to_be_bytes()); // id
        m.extend_from_slice(&[0x81, 0x80]); // flags: response, RD, RA, NOERROR
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // qd=1 an=1
                                                        // question: 1.0.0.127.in-addr.arpa PTR IN  (we just need a name to skip)
        let qstart = m.len();
        super::encode_name(&mut m, "example");
        m.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        m.extend_from_slice(&QCLASS_IN.to_be_bytes());
        // answer: name = pointer to question name, PTR, rdata = "host" + ptr(qname)
        m.extend_from_slice(&[0xc0, qstart as u8]);
        m.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        m.extend_from_slice(&QCLASS_IN.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 60]); // ttl
        let rd = vec![4, b'h', b'o', b's', b't', 0xc0, qstart as u8];
        m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        m.extend_from_slice(&rd);
        assert_eq!(parse_ptr_reply(&m, 0x4543).as_deref(), Some("host.example"));
        assert_eq!(parse_ptr_reply(&m, 0x9999), None); // wrong id
    }
}
