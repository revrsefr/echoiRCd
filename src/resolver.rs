//! DNS lookups over std UDP (no DNS crate). Two things:
//!
//!   * **reverse-DNS**: PTR-resolve a client IP and **forward-confirm** it (the name
//!     must resolve back to the same IP, so a client can't fake a hostname);
//!   * **DNSBL**: reverse the client's v4 octets under a blocklist zone and A-lookup
//!     it, reporting the listing reply.
//!
//! Best-effort: any failure returns "not found / clean" and the caller keeps the
//! IP. Runs off the core thread (never blocks the daemon), bounded in time (the UDP
//! read timeout) and in concurrency (`try_acquire`).

use crate::map::HashMap;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long to wait for the DNS server before giving up.
pub const DNS_TIMEOUT: Duration = Duration::from_millis(2500);
/// Cap on concurrent in-flight lookups (one short-lived thread each), so a
/// connection flood can't spawn unbounded resolver threads.
const MAX_ACTIVE: usize = 512;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

// --- caches -------------------------------------------------------------------
// Memoize lookups so reconnects and clients sharing an IP (NAT/CGNAT, bouncers)
// skip the network entirely. These Mutexes are internal to the resolver worker
// threads — the single-threaded core never touches them, so the "no locks in the
// core" rule still holds. Entries store their expiry `Instant`; a bounded map
// (purge-expired, then clear on a pathological unique-IP flood) caps memory.
const CACHE_CAP: usize = 65_536;
const NS_TTL: Duration = Duration::from_secs(30); // re-read resolv.conf at most this often
const RDNS_TTL_HIT: Duration = Duration::from_secs(600); // resolved hostname
const RDNS_TTL_MISS: Duration = Duration::from_secs(60); // no/unconfirmed PTR
const A_TTL_HIT: Duration = Duration::from_secs(300); // A record present (e.g. DNSBL listing)
const A_TTL_MISS: Duration = Duration::from_secs(120); // NXDOMAIN / no A (e.g. not listed)

/// A lazily-initialised, expiry-tagged lookup cache keyed by `K` holding `V`.
type Cache<K, V> = OnceLock<Mutex<HashMap<K, (V, Instant)>>>;

static NS_CACHE: Mutex<Option<(String, Instant)>> = Mutex::new(None);
static RDNS_CACHE: Cache<IpAddr, Option<String>> = OnceLock::new();
static A_CACHE: Cache<String, Option<Ipv4Addr>> = OnceLock::new();

/// Keep a cache map bounded: once it hits the cap, drop expired entries, and if
/// it's *still* full (a flood of distinct fresh IPs), clear it — degrading to
/// no-cache rather than growing without bound.
fn evict_if_full<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, (V, Instant)>) {
    if map.len() >= CACHE_CAP {
        let now = Instant::now();
        map.retain(|_, (_, exp)| *exp > now);
        if map.len() >= CACHE_CAP {
            map.clear();
        }
    }
}

const QTYPE_A: u16 = 1;
const QTYPE_PTR: u16 = 12;
const QTYPE_SRV: u16 = 33;
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
/// and that host resolves back to `ip`. Cached by IP so reconnects and clients
/// behind the same NAT resolve instantly.
pub fn reverse_confirmed(ip: IpAddr, timeout: Duration) -> Option<String> {
    let cache = RDNS_CACHE.get_or_init(|| Mutex::new(HashMap::default()));
    if let Ok(g) = cache.lock() {
        if let Some((val, exp)) = g.get(&ip) {
            if Instant::now() < *exp {
                return val.clone();
            }
        }
    }
    let val = resolve_reverse(ip, timeout);
    let ttl = if val.is_some() {
        RDNS_TTL_HIT
    } else {
        RDNS_TTL_MISS
    };
    if let Ok(mut g) = cache.lock() {
        evict_if_full(&mut g);
        g.insert(ip, (val.clone(), Instant::now() + ttl));
    }
    val
}

/// The actual reverse lookup + forward-confirm (uncached; see `reverse_confirmed`).
fn resolve_reverse(ip: IpAddr, timeout: Duration) -> Option<String> {
    let ns = nameserver();
    let ptr = ptr_lookup(&ns, &reverse_name(ip), timeout)?;
    // forward-confirm: the resolved name must map back to this IP
    let ok = (ptr.as_str(), 0u16)
        .to_socket_addrs()
        .ok()?
        .any(|sa| sa.ip() == ip);
    (ok && !ptr.is_empty()).then_some(ptr)
}

/// The reversed digit/nibble labels for `ip`, without any suffix — `1.2.3.4` →
/// `4.3.2.1`, `2001:db8::1` → the 32 reversed hex nibbles. PTR appends
/// `.in-addr.arpa` / `.ip6.arpa`; DNSBL appends the blocklist zone.
pub fn reverse_labels(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(64);
            for octet in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", octet & 0xf, octet >> 4));
            }
            s.pop(); // drop the trailing '.'
            s
        }
    }
}

/// The `in-addr.arpa` / `ip6.arpa` reverse name for `ip` (for PTR lookups).
fn reverse_name(ip: IpAddr) -> String {
    let suffix = if ip.is_ipv4() {
        "in-addr.arpa"
    } else {
        "ip6.arpa"
    };
    format!("{}.{suffix}", reverse_labels(ip))
}

/// First `nameserver` in /etc/resolv.conf, else a sensible fallback — cached for
/// `NS_TTL` so we don't stat+read the file on every single DNS query.
fn nameserver() -> String {
    if let Ok(mut g) = NS_CACHE.lock() {
        if let Some((ns, at)) = g.as_ref() {
            if at.elapsed() < NS_TTL {
                return ns.clone();
            }
        }
        let ns = read_nameserver();
        *g = Some((ns.clone(), Instant::now()));
        return ns;
    }
    read_nameserver()
}

/// Read the first `nameserver` from /etc/resolv.conf (uncached; see `nameserver`).
fn read_nameserver() -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver ") {
                let ns = rest.trim();
                if !ns.is_empty() {
                    // bracket a bare IPv6 literal so `ns:53` parses as a SocketAddr
                    return if ns.contains(':') && !ns.starts_with('[') {
                        format!("[{ns}]:53")
                    } else {
                        format!("{ns}:53")
                    };
                }
            }
        }
    }
    "1.1.1.1:53".to_string()
}

/// A random 16-bit DNS transaction id from the CSPRNG. Combined with the
/// connected socket, an off-path attacker can neither guess the id nor deliver a
/// reply from a spoofed source, so cache-poisoning of rDNS/DNSBL is infeasible.
fn rand_txid() -> u16 {
    let mut b = [0u8; 2];
    match openssl::rand::rand_bytes(&mut b) {
        Ok(()) => u16::from_be_bytes(b),
        Err(_) => 0x4543, // RNG failure (never observed) — still validated on parse
    }
}

/// Build a `qtype` query for `qname`, send it to `ns`, and return the raw reply
/// (with the transaction id validated).
fn send_query(ns: &str, qname: &str, qtype: u16, id: u16, timeout: Duration) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .or_else(|_| UdpSocket::bind("[::]:0"))
        .ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    // Connect to the nameserver: the kernel then drops any datagram from a
    // different source, so an off-path attacker can't inject a spoofed reply.
    // (An unconnected `recv` would accept a forged answer from any IP.)
    sock.connect(ns).ok()?;
    let mut query = Vec::with_capacity(qname.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    query.extend_from_slice(&[0, 1]); // QDCOUNT=1
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    encode_name(&mut query, qname);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&QCLASS_IN.to_be_bytes());
    sock.send(&query).ok()?;
    let mut buf = [0u8; 1500];
    let n = sock.recv(&mut buf).ok()?;
    if n < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    Some(buf[..n].to_vec())
}

/// Send a PTR query for `qname` to `ns` and return the first PTR answer name.
fn ptr_lookup(ns: &str, qname: &str, timeout: Duration) -> Option<String> {
    let id = rand_txid();
    let reply = send_query(ns, qname, QTYPE_PTR, id, timeout)?;
    parse_ptr_reply(&reply, id)
}

/// Resolve `qname`'s first A record. Generic — the DNSBL module builds a
/// `<reversed-ip>.<zone>` name and calls this to test a listing. Cached by qname
/// so repeat DNSBL checks for the same IP+zone don't re-hit the network.
pub fn a_lookup(qname: &str, timeout: Duration) -> Option<Ipv4Addr> {
    let cache = A_CACHE.get_or_init(|| Mutex::new(HashMap::default()));
    if let Ok(g) = cache.lock() {
        if let Some((val, exp)) = g.get(qname) {
            if Instant::now() < *exp {
                return *val;
            }
        }
    }
    let id = rand_txid();
    let val = send_query(&nameserver(), qname, QTYPE_A, id, timeout)
        .and_then(|reply| parse_a_reply(&reply, id));
    let ttl = if val.is_some() { A_TTL_HIT } else { A_TTL_MISS };
    if let Ok(mut g) = cache.lock() {
        evict_if_full(&mut g);
        g.insert(qname.to_string(), (val, Instant::now() + ttl));
    }
    val
}

/// Resolve ALL of `qname`'s A records (not just the first). A DNSBL may list an IP
/// under several classes at once (e.g. Tor exit + spamtrap), so a code-filtered check
/// needs every returned class, not whichever the resolver happened to order first.
/// Uncached — used only on the DNSBL connect path.
pub fn a_lookup_all(qname: &str, timeout: Duration) -> Vec<Ipv4Addr> {
    let id = rand_txid();
    send_query(&nameserver(), qname, QTYPE_A, id, timeout)
        .map(|reply| parse_a_reply_all(&reply, id))
        .unwrap_or_default()
}

/// Resolve SRV records for `qname` (e.g. `_xmpp-client._tcp.example.com`) and return
/// `(target_host, port)` candidates in RFC 2782 order: ascending priority, then
/// descending weight. Empty on NXDOMAIN / error / a `.` target (service disabled). No
/// caching — the only caller (the XMPP bridge) connects rarely.
pub fn srv_lookup(qname: &str, timeout: Duration) -> Vec<(String, u16)> {
    let id = rand_txid();
    match send_query(&nameserver(), qname, QTYPE_SRV, id, timeout) {
        Some(reply) => parse_srv_reply(&reply, id),
        None => Vec::new(),
    }
}

fn parse_srv_reply(msg: &[u8], want_id: u16) -> Vec<(String, u16)> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != want_id || msg[3] & 0x0f != 0 {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        pos = match skip_name(msg, pos).and_then(|p| p.checked_add(4)) {
            Some(p) if p <= msg.len() => p,
            _ => return Vec::new(),
        };
    }
    let mut recs: Vec<(u16, u16, u16, String)> = Vec::new(); // priority, weight, port, target
    for _ in 0..an {
        let Some(p) = skip_name(msg, pos) else { break };
        pos = p;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        if rtype == QTYPE_SRV && rdlen >= 7 {
            let priority = u16::from_be_bytes([msg[rdata], msg[rdata + 1]]);
            let weight = u16::from_be_bytes([msg[rdata + 2], msg[rdata + 3]]);
            let port = u16::from_be_bytes([msg[rdata + 4], msg[rdata + 5]]);
            if let Some((target, _)) = read_name(msg, rdata + 6, 0) {
                if !target.is_empty() {
                    recs.push((priority, weight, port, target));
                }
            }
        }
        pos = rdata + rdlen;
    }
    recs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    recs.into_iter().map(|(_, _, port, t)| (t, port)).collect()
}

/// Parse a DNS reply for the first A record (4-byte address). Bounds-checked.
fn parse_a_reply(msg: &[u8], want_id: u16) -> Option<Ipv4Addr> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != want_id {
        return None;
    }
    if msg[3] & 0x0f != 0 {
        return None; // rcode != NOERROR (e.g. NXDOMAIN = not listed)
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    if an == 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4)?;
        if pos > msg.len() {
            return None;
        }
    }
    for _ in 0..an {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > msg.len() {
            return None;
        }
        if rtype == QTYPE_A && rdlen == 4 {
            return Some(Ipv4Addr::new(
                msg[rdata],
                msg[rdata + 1],
                msg[rdata + 2],
                msg[rdata + 3],
            ));
        }
        pos = rdata + rdlen;
    }
    None
}

/// Like [`parse_a_reply`] but collects EVERY A record (all listing classes). Fully
/// bounds-checked — the packet is untrusted.
fn parse_a_reply_all(msg: &[u8], want_id: u16) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != want_id || msg[3] & 0x0f != 0 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qd {
        pos = match skip_name(msg, pos).and_then(|p| p.checked_add(4)) {
            Some(p) if p <= msg.len() => p,
            _ => return out,
        };
    }
    for _ in 0..an {
        let Some(p) = skip_name(msg, pos) else { break };
        pos = p;
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        if rtype == QTYPE_A && rdlen == 4 {
            out.push(Ipv4Addr::new(
                msg[rdata],
                msg[rdata + 1],
                msg[rdata + 2],
                msg[rdata + 3],
            ));
        }
        pos = rdata + rdlen;
    }
    out
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
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    proptest! {
        // The DNS reply parsers eat untrusted network data — spoofable, and for DNSBL the
        // queried nameserver is attacker-adjacent. Pointer compression is a classic parser
        // loop/DoS, so no byte string may panic or hang them (the `jumps` cap bounds loops).
        #[test]
        fn dns_parsers_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..600),
            id in any::<u16>(),
        ) {
            let _ = parse_a_reply(&bytes, id);
            let _ = parse_ptr_reply(&bytes, id);
            let _ = parse_srv_reply(&bytes, id);
        }
    }

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

    #[test]
    fn parses_srv_reply_ordered() {
        // two SRV answers; the lower-priority target must sort first
        let id = 0x1234u16;
        let mut m = Vec::new();
        m.extend_from_slice(&id.to_be_bytes());
        m.extend_from_slice(&[0x81, 0x80]);
        m.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 0]); // qd=1 an=2
        super::encode_name(&mut m, "_xmpp-client._tcp.example.com");
        m.extend_from_slice(&QTYPE_SRV.to_be_bytes());
        m.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let mut answer = |prio: u16, port: u16, target: &str, m: &mut Vec<u8>| {
            super::encode_name(m, "_xmpp-client._tcp.example.com");
            m.extend_from_slice(&QTYPE_SRV.to_be_bytes());
            m.extend_from_slice(&QCLASS_IN.to_be_bytes());
            m.extend_from_slice(&[0, 0, 0, 60]);
            let mut rd = Vec::new();
            rd.extend_from_slice(&prio.to_be_bytes());
            rd.extend_from_slice(&5u16.to_be_bytes()); // weight
            rd.extend_from_slice(&port.to_be_bytes());
            super::encode_name(&mut rd, target);
            m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            m.extend_from_slice(&rd);
        };
        answer(20, 5223, "backup.example.com", &mut m);
        answer(10, 5222, "primary.example.com", &mut m);
        let recs = parse_srv_reply(&m, id);
        assert_eq!(
            recs,
            vec![
                ("primary.example.com".to_string(), 5222),
                ("backup.example.com".to_string(), 5223),
            ]
        );
        assert!(parse_srv_reply(&m, 0x9999).is_empty()); // wrong id
    }
}
