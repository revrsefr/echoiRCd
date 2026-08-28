//! ASN (autonomous system) as a core lookup, backed by the GeoLite2-ASN `.mmdb` the
//! geoip module loads (`geoip_asn_database`). Exposes `lookup`/`of` so any subsystem —
//! connect classes, security groups, extbans, WHOIS — can match a client on its origin
//! AS number, plus the `parse_list` config helper the matchers share.
//!
//! There's no separate database or `init` here: MaxMind ships ASN as its own db, which
//! geoip already parses with its hand-rolled MMDB reader; this module is the thin,
//! core-level seam other code calls, so ASN matching lives in one place.

use std::net::IpAddr;

use crate::server::Server;
use crate::Uid;

/// The origin AS number for `ip`, from the loaded ASN database. `None` when no ASN db
/// is configured or the address has no record.
pub fn lookup(s: &Server, ip: IpAddr) -> Option<u32> {
    crate::modules::geoip::asn(s, ip).map(|a| a.number)
}

/// The AS number **and** organisation for `ip`, if available (for display / WHOIS).
pub fn full(s: &Server, ip: IpAddr) -> Option<(u32, String)> {
    crate::modules::geoip::asn(s, ip).map(|a| (a.number, a.org))
}

/// The origin AS of user `uid`, resolved from its connecting IP.
pub fn of(s: &Server, uid: Uid) -> Option<u32> {
    let ip = s.users.get(&uid)?.addr.ip();
    lookup(s, ip)
}

/// Parse a config value — `3215,15169`, `AS3215 AS15169`, or a mix — into AS numbers.
/// A leading `AS`/`as` on a token is optional; unparseable tokens are dropped.
pub fn parse_list(v: &str) -> Vec<u32> {
    v.split([',', ' '])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| {
            let n = t.strip_prefix("AS").or_else(|| t.strip_prefix("as")).unwrap_or(t);
            n.parse::<u32>().ok()
        })
        .collect()
}

/// Whether `uid`'s origin AS is one of `list`. An empty `list` is "no ASN constraint"
/// and never matches here — callers treat an empty list as "criterion absent".
pub fn user_in(s: &Server, uid: Uid, list: &[u32]) -> bool {
    !list.is_empty() && of(s, uid).is_some_and(|a| list.contains(&a))
}

/// The `A:<asn[,asn]>` matching extban: is `uid`'s origin AS one of the listed AS
/// numbers? The `AS` prefix is optional — e.g. `+b A:15169` or `+b A:AS3215,16276`.
pub fn extban_match(s: &Server, uid: Uid, spec: &str) -> bool {
    user_in(s, uid, &parse_list(spec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_forms() {
        assert_eq!(parse_list("3215,15169"), vec![3215, 15169]);
        assert_eq!(parse_list("AS3215 AS15169"), vec![3215, 15169]);
        assert_eq!(parse_list(" as16276 , 3215 "), vec![16276, 3215]);
        assert_eq!(parse_list("3215,,bogus,15169"), vec![3215, 15169]);
        assert!(parse_list("").is_empty());
        assert!(parse_list("notanumber").is_empty());
    }
}
