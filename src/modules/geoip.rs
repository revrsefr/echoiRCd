//! geoip — native MaxMind DB (`.mmdb`) country lookup, with the `G:<cc>` geoban
//! extban, the `GEOIP` command and a WHOIS country line. The `maxminddb` crate is
//! off-limits (openssl+mio only), so the binary format is parsed by hand in pure
//! std: the metadata section, the record-size-aware search tree, and the typed data
//! decoder — no crate, no `unsafe`, no C FFI.
//!
//! Config: `geoip_database = /path/to/GeoLite2-Country.mmdb` (loaded once at boot).
//!
//! Behaviour reference: InspIRCd's `m_geo_maxmind` + `m_geoban` + `m_geocmd`.
//! Original native Rust.

use std::net::IpAddr;
use std::sync::Arc;

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const SEPARATOR: usize = 16;

/// A loaded MaxMind DB, cached in `Server.ext`.
pub struct GeoDb(pub Arc<Mmdb>);

/// A resolved country: the ISO 3166-1 alpha-2 code (for the `G:` geoban) and the
/// full English name (for display).
pub struct Country {
    pub iso: String,
    pub name: String,
}

/// A parsed `.mmdb` file: the raw bytes plus the tree geometry from its metadata.
pub struct Mmdb {
    data: Vec<u8>,
    node_count: usize,
    node_byte_size: usize, // record_size * 2 / 8
    record_size: u32,
    data_start: usize, // node_count*node_byte_size + 16 (first byte after the separator)
    ip_version: u16,
}

/// Big-endian value of up to 8 bytes.
fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

/// A cursor over the data section for pointer-aware decoding. `base` is the offset
/// pointers are relative to (the start of the section being decoded).
struct Decoder<'a> {
    data: &'a [u8],
    base: usize,
}

impl<'a> Decoder<'a> {
    /// Parse the control byte at `off`: returns `(type, size, payload_offset)`.
    /// Not used for pointers (they encode size differently — see `resolve`).
    fn control(&self, off: usize) -> Option<(u8, usize, usize)> {
        let b = *self.data.get(off)?;
        let mut typ = b >> 5;
        let mut o = off + 1;
        if typ == 0 {
            typ = 7 + *self.data.get(o)?;
            o += 1;
        }
        let mut size = (b & 0x1f) as usize;
        if size >= 29 {
            match size {
                29 => {
                    size = 29 + *self.data.get(o)? as usize;
                    o += 1;
                }
                30 => {
                    size = 285 + be(self.data.get(o..o + 2)?) as usize;
                    o += 2;
                }
                _ => {
                    size = 65821 + be(self.data.get(o..o + 3)?) as usize;
                    o += 3;
                }
            }
        }
        Some((typ, size, o))
    }

    /// Follow pointer(s) at `off` to the concrete value offset (non-pointers pass
    /// through). Depth-limited against malformed data.
    fn resolve(&self, off: usize, depth: u8) -> Option<usize> {
        if depth > 8 {
            return None;
        }
        let b = *self.data.get(off)?;
        if b >> 5 != 1 {
            return Some(off);
        }
        let ps = ((b >> 3) & 0x3) as usize;
        let v0 = (b & 0x7) as usize;
        let ptr = match ps {
            0 => (v0 << 8) | *self.data.get(off + 1)? as usize,
            1 => ((v0 << 16) | be(self.data.get(off + 1..off + 3)?) as usize) + 2048,
            2 => ((v0 << 24) | be(self.data.get(off + 1..off + 4)?) as usize) + 526336,
            _ => be(self.data.get(off + 1..off + 5)?) as usize,
        };
        self.resolve(self.base + ptr, depth + 1)
    }

    /// The number of bytes the value at `off` occupies (pointers are 2–5 bytes; not
    /// followed). Recurses into maps/arrays. Returns 0 on malformed input.
    fn value_len(&self, off: usize) -> usize {
        let b = match self.data.get(off) {
            Some(&b) => b,
            None => return 0,
        };
        if b >> 5 == 1 {
            return 1 + ((b >> 3) & 0x3) as usize + 1; // 2..=5 bytes
        }
        let Some((typ, size, payload)) = self.control(off) else {
            return 0;
        };
        let header = payload - off;
        match typ {
            7 => {
                // map: `size` key/value pairs
                let mut cur = payload;
                for _ in 0..size {
                    cur += self.value_len(cur); // key
                    cur += self.value_len(cur); // value
                }
                cur - off
            }
            11 => {
                // array: `size` elements
                let mut cur = payload;
                for _ in 0..size {
                    cur += self.value_len(cur);
                }
                cur - off
            }
            14 => header,          // bool: value is in the size field, no payload
            _ => header + size,    // string/bytes/ints/float/double
        }
    }

    /// Read a UTF-8 string at `off` (following pointers).
    fn string(&self, off: usize) -> Option<String> {
        let off = self.resolve(off, 0)?;
        let (typ, size, payload) = self.control(off)?;
        if typ != 2 {
            return None;
        }
        std::str::from_utf8(self.data.get(payload..payload + size)?)
            .ok()
            .map(str::to_string)
    }

    /// Read an unsigned integer at `off` (following pointers).
    fn uint(&self, off: usize) -> Option<u64> {
        let off = self.resolve(off, 0)?;
        let (typ, size, payload) = self.control(off)?;
        if !matches!(typ, 5 | 6 | 9 | 10) {
            return None;
        }
        Some(be(self.data.get(payload..payload + size)?))
    }

    /// The value offset for `key` in the map at `off` (following pointers).
    fn map_get(&self, off: usize, key: &str) -> Option<usize> {
        let off = self.resolve(off, 0)?;
        let (typ, size, payload) = self.control(off)?;
        if typ != 7 {
            return None;
        }
        let mut cur = payload;
        for _ in 0..size {
            let k = self.string(cur)?;
            cur += self.value_len(cur);
            if k == key {
                return Some(cur);
            }
            cur += self.value_len(cur);
        }
        None
    }
}

impl Mmdb {
    /// Load and parse an `.mmdb` file.
    pub fn open(path: &str) -> Option<Mmdb> {
        let data = std::fs::read(path).ok()?;
        let marker = data.windows(MARKER.len()).rposition(|w| w == MARKER)?;
        let meta = marker + MARKER.len();
        let d = Decoder { data: &data, base: meta };
        let node_count = d.uint(d.map_get(meta, "node_count")?)? as usize;
        let record_size = d.uint(d.map_get(meta, "record_size")?)? as u32;
        let ip_version = d.uint(d.map_get(meta, "ip_version")?)? as u16;
        if !matches!(record_size, 24 | 28 | 32) || node_count == 0 {
            return None;
        }
        let node_byte_size = record_size as usize * 2 / 8;
        let data_start = node_count * node_byte_size + SEPARATOR;
        Some(Mmdb {
            data,
            node_count,
            node_byte_size,
            record_size,
            data_start,
            ip_version,
        })
    }

    /// The left (bit=false) or right (bit=true) record of tree `node`.
    fn record(&self, node: usize, bit: bool) -> Option<usize> {
        let base = node * self.node_byte_size;
        match self.record_size {
            24 => {
                let o = base + if bit { 3 } else { 0 };
                Some(be(self.data.get(o..o + 3)?) as usize)
            }
            28 => {
                let mid = *self.data.get(base + 3)?;
                if bit {
                    Some(((mid as usize & 0x0f) << 24) | be(self.data.get(base + 4..base + 7)?) as usize)
                } else {
                    Some(((mid as usize >> 4) << 24) | be(self.data.get(base..base + 3)?) as usize)
                }
            }
            _ => {
                let o = base + if bit { 4 } else { 0 };
                Some(be(self.data.get(o..o + 4)?) as usize)
            }
        }
    }

    /// The country for `ip` — ISO code plus English name — if the database has one.
    pub fn country(&self, ip: IpAddr) -> Option<Country> {
        // build the bit path; IPv4 in an IPv6 db is prefixed with 96 zero bits
        let mut bits: Vec<bool> = Vec::with_capacity(128);
        match ip {
            IpAddr::V4(a) => {
                if self.ip_version == 6 {
                    bits.extend(std::iter::repeat(false).take(96));
                }
                for byte in a.octets() {
                    for i in (0..8).rev() {
                        bits.push((byte >> i) & 1 == 1);
                    }
                }
            }
            IpAddr::V6(a) => {
                for byte in a.octets() {
                    for i in (0..8).rev() {
                        bits.push((byte >> i) & 1 == 1);
                    }
                }
            }
        }
        let mut node = 0usize;
        for bit in bits {
            if node >= self.node_count {
                return None;
            }
            let rec = self.record(node, bit)?;
            if rec == self.node_count {
                return None; // no data
            }
            if rec > self.node_count {
                // data pointer: abs = tree_size + (rec - node_count)
                let abs = (self.data_start - SEPARATOR) + rec - self.node_count;
                let d = Decoder {
                    data: &self.data,
                    base: self.data_start,
                };
                let country = d.map_get(abs, "country")?;
                let iso = d.string(d.map_get(country, "iso_code")?)?;
                // country.names.en — the `names` submap is usually a shared pointer;
                // map_get/string follow it. Fall back to the code if it's absent.
                let name = d
                    .map_get(country, "names")
                    .and_then(|names| d.map_get(names, "en"))
                    .and_then(|en| d.string(en))
                    .unwrap_or_else(|| iso.clone());
                return Some(Country { iso, name });
            }
            node = rec;
        }
        None
    }
}

/// Load the configured database into `Server.ext` at boot. Called from `Ircd::new`.
pub fn init(s: &mut Server) {
    let Some(path) = s.conf("geoip_database").map(str::to_string) else {
        return;
    };
    match Mmdb::open(&path) {
        Some(db) => {
            s.ext.set(GeoDb(Arc::new(db)));
            eprintln!("echoircd: loaded GeoIP database {path}");
        }
        None => eprintln!("echoircd: could not read GeoIP database {path}"),
    }
}

/// The country of `ip` per the loaded database (ISO code uppercased).
pub fn lookup(s: &Server, ip: IpAddr) -> Option<Country> {
    s.ext.get::<GeoDb>().and_then(|db| db.0.country(ip)).map(|c| Country {
        iso: c.iso.to_ascii_uppercase(),
        name: c.name,
    })
}

/// The `G:<cc>` geoban match: does `uid`'s country code equal (case-insensitively)
/// one of the codes in the extban? Dispatched from `Server::ban_list_hit`.
pub fn geoban_match(s: &Server, uid: Uid, spec: &str) -> bool {
    let Some(ip) = s.users.get(&uid).map(|u| u.addr.ip()) else {
        return false;
    };
    match lookup(s, ip) {
        Some(c) => spec
            .split(',')
            .any(|want| want.trim().eq_ignore_ascii_case(&c.iso)),
        None => false,
    }
}

/// A WHOIS line (opers only) naming the target's country.
pub fn whois_line(s: &Server, tuid: Uid) -> Option<String> {
    let ip = s.users.get(&tuid).map(|u| u.addr.ip())?;
    lookup(s, ip).map(|c| format!("is connecting from country {}", c.name))
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(GeoIpCmd)]
}

/// GEOIP `<nick|ip>` — oper command reporting the country of a user or raw IP.
struct GeoIpCmd;
impl Command for GeoIpCmd {
    fn name(&self) -> &'static str {
        "GEOIP"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let target = &params[0];
        let ip = s
            .find_nick(target)
            .and_then(|t| s.users.get(&t))
            .map(|u| u.addr.ip())
            .or_else(|| target.parse::<IpAddr>().ok());
        let nick = s.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        let msg = match ip {
            None => format!("GEOIP: no such nick, and {target} is not an IP"),
            Some(ip) => match lookup(s, ip) {
                Some(c) => format!("GEOIP: {target} ({ip}) is in {} ({})", c.name, c.iso),
                None => format!("GEOIP: no country found for {target} ({ip})"),
            },
        };
        s.send(uid, format!(":{} NOTICE {nick} :*** {msg}", s.name));
        CmdResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // A real GeoLite2-Country.mmdb if one is present; otherwise the test no-ops so
    // CI (which has no database) stays green.
    const DB_CANDIDATES: &[&str] = &[
        "/home/debian/irc/ircd/inspircd/run/conf/geodata/GeoLite2-Country.mmdb",
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    ];

    fn load() -> Option<Mmdb> {
        DB_CANDIDATES.iter().find_map(|p| Mmdb::open(p))
    }

    #[test]
    fn known_ips_resolve() {
        let Some(db) = load() else {
            return;
        };
        // 8.8.8.8 (Google DNS) is US, "United States", in every GeoLite2 vintage.
        let us = db.country(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        assert_eq!(us.iso, "US");
        assert_eq!(us.name, "United States");
        // A private address has no country record.
        assert!(db.country(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
        // IPv6 traversal (Google public DNS) also resolves to US.
        assert_eq!(
            db.country("2001:4860:4860::8888".parse().unwrap()).unwrap().iso,
            "US"
        );
    }
}
