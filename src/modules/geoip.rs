//! MaxMind DB (`.mmdb`) geolocation: country + city + ASN, with the `G:<cc>` geoban
//! extban, the `GEOIP` command, a WHOIS "connecting from …" line and the connect-snote
//! `geo:` field. The binary format is parsed by hand: the metadata section, the
//! record-size-aware search tree, and the typed data decoder — so it reads any
//! MaxMind-schema db (Country, City, ASN, or DB-IP equivalents).
//!
//! Config (loaded once at boot):
//!   `geoip_database     = /path/to/GeoLite2-City.mmdb`   # country + city
//!   `geoip_asn_database = /path/to/GeoLite2-ASN.mmdb`     # optional: AS number + org

use std::net::IpAddr;
use std::sync::Arc;

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
const SEPARATOR: usize = 16;
/// Recursion cap for the typed-value decoder (see `Mmdb::value_len`).
const MAX_MMDB_DEPTH: u8 = 32;

/// A loaded MaxMind DB, cached in `Server.ext`.
pub struct GeoDb(pub Arc<Mmdb>);

/// A resolved country: the ISO 3166-1 alpha-2 code (for the `G:` geoban) and the
/// full English name (for display).
pub struct Country {
    pub iso: String,
    pub name: String,
}

/// A resolved location from a City database: country plus the (optional) city name.
pub struct Geo {
    pub country_iso: String,
    pub country_name: String,
    pub city: Option<String>,
}

/// A resolved autonomous system from an ASN database.
pub struct Asn {
    pub number: u32,
    pub org: String,
}

/// The ASN database, cached separately in `Server.ext`. MaxMind ships ASN as its own
/// `.mmdb`, distinct from the Country/City geolocation database.
pub struct GeoAsnDb(pub Arc<Mmdb>);

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
    ///
    /// `MAX_MMDB_DEPTH` caps nesting — real GeoIP records are 3–4 deep; the cap only
    /// exists so a hostile file can't overflow the stack.
    fn value_len(&self, off: usize, depth: u8) -> usize {
        // Bound recursion (a crafted, deeply-nested .mmdb would otherwise overflow the
        // stack). A valid value is never 0 bytes, so 0 doubles as a "malformed" signal
        // callers bail on — which also stops a huge `size` from spinning with no progress.
        if depth > MAX_MMDB_DEPTH {
            return 0;
        }
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
                    let k = self.value_len(cur, depth + 1); // key
                    let v = self.value_len(cur + k, depth + 1); // value
                    if k == 0 || v == 0 {
                        return 0; // malformed or too deep
                    }
                    cur += k + v;
                }
                cur - off
            }
            11 => {
                // array: `size` elements
                let mut cur = payload;
                for _ in 0..size {
                    let v = self.value_len(cur, depth + 1);
                    if v == 0 {
                        return 0;
                    }
                    cur += v;
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
            let klen = self.value_len(cur, 0);
            if klen == 0 {
                return None; // malformed
            }
            cur += klen;
            if k == key {
                return Some(cur);
            }
            let vlen = self.value_len(cur, 0);
            if vlen == 0 {
                return None;
            }
            cur += vlen;
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

    /// Walk the search tree for `ip` and return the absolute offset of its data record
    /// in the data section, or `None` if the address isn't in the tree.
    fn find(&self, ip: IpAddr) -> Option<usize> {
        // build the bit path; IPv4 in an IPv6 db is prefixed with 96 zero bits
        let mut bits: Vec<bool> = Vec::with_capacity(128);
        match ip {
            IpAddr::V4(a) => {
                if self.ip_version == 6 {
                    bits.extend(std::iter::repeat_n(false, 96));
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
                return Some((self.data_start - SEPARATOR) + rec - self.node_count);
            }
            node = rec;
        }
        None
    }

    fn decoder(&self) -> Decoder<'_> {
        Decoder { data: &self.data, base: self.data_start }
    }

    /// The country for `ip` — ISO code plus English name — if the database has one.
    pub fn country(&self, ip: IpAddr) -> Option<Country> {
        let abs = self.find(ip)?;
        let d = self.decoder();
        let country = d.map_get(abs, "country")?;
        let iso = d.string(d.map_get(country, "iso_code")?)?;
        // country.names.en — the `names` submap is usually a shared pointer; map_get/
        // string follow it. Fall back to the code if it's absent.
        let name = d
            .map_get(country, "names")
            .and_then(|names| d.map_get(names, "en"))
            .and_then(|en| d.string(en))
            .unwrap_or_else(|| iso.clone());
        Some(Country { iso, name })
    }

    /// Country **and** city for `ip` in a single tree walk, from a City database.
    /// `city` is `None` on a Country-only db or when the record carries no city name.
    pub fn geo(&self, ip: IpAddr) -> Option<Geo> {
        let abs = self.find(ip)?;
        let d = self.decoder();
        let country = d.map_get(abs, "country")?;
        let iso = d.string(d.map_get(country, "iso_code")?)?;
        let name = d
            .map_get(country, "names")
            .and_then(|names| d.map_get(names, "en"))
            .and_then(|en| d.string(en))
            .unwrap_or_else(|| iso.clone());
        let city = d
            .map_get(abs, "city")
            .and_then(|city| d.map_get(city, "names"))
            .and_then(|names| d.map_get(names, "en"))
            .and_then(|en| d.string(en));
        Some(Geo { country_iso: iso, country_name: name, city })
    }

    /// The autonomous system (number + organisation) for `ip`, from a GeoLite2-ASN
    /// database. `None` if this db has no ASN record for the address.
    pub fn asn(&self, ip: IpAddr) -> Option<Asn> {
        let abs = self.find(ip)?;
        let d = self.decoder();
        let number = d.map_get(abs, "autonomous_system_number").and_then(|o| d.uint(o))?;
        let org = d
            .map_get(abs, "autonomous_system_organization")
            .and_then(|o| d.string(o))
            .unwrap_or_default();
        Some(Asn { number: number as u32, org })
    }
}

/// Load the configured database into `Server.ext` at boot. Called from `Ircd::new`.
pub fn init(s: &mut Server) {
    if let Some(path) = s.conf("geoip_database").map(str::to_string) {
        match Mmdb::open(&path) {
            Some(db) => {
                s.ext.set(GeoDb(Arc::new(db)));
                eprintln!("echoircd: loaded GeoIP database {path}");
            }
            None => eprintln!("echoircd: could not read GeoIP database {path}"),
        }
    }
    // Optional, separate ASN database (GeoLite2-ASN.mmdb) — adds AS number + org.
    if let Some(path) = s.conf("geoip_asn_database").map(str::to_string) {
        match Mmdb::open(&path) {
            Some(db) => {
                s.ext.set(GeoAsnDb(Arc::new(db)));
                eprintln!("echoircd: loaded GeoIP ASN database {path}");
            }
            None => eprintln!("echoircd: could not read GeoIP ASN database {path}"),
        }
    }
}

/// The country of `ip` per the loaded database (ISO code uppercased).
pub fn lookup(s: &Server, ip: IpAddr) -> Option<Country> {
    s.ext.get::<GeoDb>().and_then(|db| db.0.country(ip)).map(|c| Country {
        iso: c.iso.to_ascii_uppercase(),
        name: c.name,
    })
}

/// The ASN of `ip` from the ASN database, if one is loaded and has a record for it.
pub fn asn(s: &Server, ip: IpAddr) -> Option<Asn> {
    s.ext.get::<GeoAsnDb>().and_then(|db| db.0.asn(ip))
}

/// A compact geo descriptor for `ip`, e.g. `FR/Paris (AS3215 Orange S.A.)`. Degrades
/// gracefully to `FR/Paris`, `FR`, `(AS3215 …)`, or `None` depending on which databases
/// are loaded and what they hold for the address.
pub fn describe(s: &Server, ip: IpAddr) -> Option<String> {
    let geo = s.ext.get::<GeoDb>().and_then(|db| db.0.geo(ip));
    let a = asn(s, ip);
    let mut out = String::new();
    if let Some(g) = &geo {
        out.push_str(&g.country_iso.to_ascii_uppercase());
        if let Some(city) = &g.city {
            out.push('/');
            out.push_str(city);
        }
    }
    if let Some(a) = &a {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str("(AS");
        out.push_str(&a.number.to_string());
        if !a.org.is_empty() {
            out.push(' ');
            out.push_str(&a.org);
        }
        out.push(')');
    }
    (!out.is_empty()).then_some(out)
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

/// A WHOIS line (opers only) naming where the target is connecting from: country,
/// city (if a City db is loaded), and AS number + org (if an ASN db is loaded).
pub fn whois_line(s: &Server, tuid: Uid) -> Option<String> {
    let ip = s.users.get(&tuid).map(|u| u.addr.ip())?;
    let g = s.ext.get::<GeoDb>().and_then(|db| db.0.geo(ip))?;
    let mut loc = g.country_name;
    if let Some(city) = g.city {
        loc.push('/');
        loc.push_str(&city);
    }
    let mut line = format!("is connecting from {loc}");
    if let Some(a) = asn(s, ip) {
        if a.org.is_empty() {
            line.push_str(&format!(" (AS{})", a.number));
        } else {
            line.push_str(&format!(" (AS{} {})", a.number, a.org));
        }
    }
    Some(line)
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
            Some(ip) => match describe(s, ip) {
                Some(desc) => format!("GEOIP: {target} ({ip}) — {desc}"),
                None => format!("GEOIP: no geo data for {target} ({ip})"),
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

    // Use a database from the env var if set, else common locations; the test
    // no-ops when none is present so CI stays green.
    const DB_CANDIDATES: &[&str] = &[
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        "/etc/echoircd/GeoLite2-Country.mmdb",
    ];

    fn load() -> Option<Mmdb> {
        std::env::var("ECHOIRCD_TEST_MMDB")
            .ok()
            .and_then(|p| Mmdb::open(&p))
            .or_else(|| DB_CANDIDATES.iter().find_map(|p| Mmdb::open(p)))
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

    #[test]
    fn city_db_resolves_country_and_city() {
        let Some(p) = std::env::var("ECHOIRCD_TEST_CITY_MMDB").ok() else {
            return;
        };
        let Some(db) = Mmdb::open(&p) else { return };
        // country extraction works on a City db (same nesting as the Country db)
        let g = db.geo(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        assert_eq!(g.country_iso, "US");
        assert!(db.geo(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
        // city extraction: at least one well-known IP should carry a city name
        let with_city = ["81.2.69.142", "128.101.101.101", "1.1.1.1", "24.24.24.24"]
            .iter()
            .filter_map(|s| db.geo(s.parse().ok()?))
            .any(|g| g.city.is_some());
        assert!(with_city, "City db should yield a city name for at least one known IP");
    }

    #[test]
    fn asn_db_resolves_number_and_org() {
        let Some(p) = std::env::var("ECHOIRCD_TEST_ASN_MMDB").ok() else {
            return;
        };
        let Some(db) = Mmdb::open(&p) else { return };
        let a = db.asn(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        assert_eq!(a.number, 15169); // Google LLC
        assert!(a.org.to_lowercase().contains("google"), "org was {:?}", a.org);
        assert!(db.asn(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }
}
