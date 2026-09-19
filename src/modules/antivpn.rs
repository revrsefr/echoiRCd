//! antivpn — block connections from KNOWN-BAD VPN / open-proxy IPs by querying a DNS
//! blocklist, exactly like dnsbl, and acting only when the list flags the IP as a
//! proxy/VPN class. The curated list decides which addresses are bad — this does NOT
//! block a whole network or every VPN, only IPs a blocklist has flagged. DNS only,
//! no HTTP.
//!
//! It builds code-filtered DNSBL zone(s) and hands them to the connection-time DNSBL
//! check. The default list is DroneBL, whose reply classes 8/9/10/11/14 are proxies and
//! 19 is "abused VPN service"; only those classes trigger the action, so an IP merely
//! listed for something else (or not listed) is left alone.
//!
//! Config (read at load and rehash — no restart):
//!   antivpn          = off | mark | kill | zline | kline | gline   (action on a hit)
//!   antivpn_bl       = <dns zone>          (repeatable; default dnsbl.dronebl.org)
//!   antivpn_codes    = 8,9,10,11,14,19     (reply classes counted as proxy/VPN)
//!   antivpn_reason   = "…"                  (%ip% / %dnsbl% / %class% supported)
//!   antivpn_duration = 86400                (ban seconds for the *line actions)

use crate::config::Config;
use crate::modules::dnsbl::DnsblZone;

/// The code-filtered DNSBL zone(s) implementing the antivpn policy, added to the
/// connect-time DNSBL check by `Config::load`. Empty when `antivpn` is off/unset.
pub fn zones(cfg: &Config) -> Vec<DnsblZone> {
    let action = match cfg
        .raw
        .get("antivpn")
        .and_then(|v| v.first())
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("off") | Some("") | Some("no") => return Vec::new(),
        Some("yes") | Some("on") => "mark".to_string(),
        Some(a) => a.to_string(),
    };
    let mut domains: Vec<String> = cfg
        .raw
        .get("antivpn_bl")
        .cloned()
        .unwrap_or_default()
        .iter()
        .flat_map(|v| v.split([',', ' ']).map(str::to_string))
        .filter(|s| !s.is_empty())
        .collect();
    if domains.is_empty() {
        domains.push("dnsbl.dronebl.org".to_string());
    }
    // proxy + abused-VPN reply classes (DroneBL scheme) unless overridden
    let codes: Vec<u8> = cfg
        .raw
        .get("antivpn_codes")
        .and_then(|v| v.first())
        .map(|s| {
            s.split([',', ' '])
                .filter_map(|x| x.trim().parse().ok())
                .collect::<Vec<u8>>()
        })
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| vec![8, 9, 10, 11, 14, 19]);
    let reason = cfg
        .raw
        .get("antivpn_reason")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "VPN / open proxy not allowed here (%class%)".to_string());
    let duration = cfg
        .raw
        .get("antivpn_duration")
        .and_then(|v| v.first())
        .and_then(|d| crate::xline::parse_duration(d));
    domains
        .into_iter()
        .map(|domain| DnsblZone {
            name: "VPN/proxy".to_string(),
            domain,
            action: Some(action.clone()),
            duration,
            reason: Some(reason.clone()),
            codes: codes.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(kvs: &[(&str, &str)]) -> Config {
        let mut c = Config::default();
        for (k, v) in kvs {
            c.raw.entry(k.to_string()).or_default().push(v.to_string());
        }
        c
    }

    #[test]
    fn off_by_default() {
        assert!(zones(&Config::default()).is_empty());
        assert!(zones(&cfg(&[("antivpn", "off")])).is_empty());
    }

    #[test]
    fn builds_default_dronebl_zone() {
        let z = zones(&cfg(&[("antivpn", "zline")]));
        assert_eq!(z.len(), 1);
        assert_eq!(z[0].domain, "dnsbl.dronebl.org");
        assert_eq!(z[0].action.as_deref(), Some("zline"));
        assert_eq!(z[0].codes, vec![8, 9, 10, 11, 14, 19]); // proxy/VPN classes only
    }

    #[test]
    fn custom_zone_and_codes() {
        let z = zones(&cfg(&[
            ("antivpn", "kill"),
            ("antivpn_bl", "vpn.example.net"),
            ("antivpn_codes", "2,3"),
        ]));
        assert_eq!(z[0].domain, "vpn.example.net");
        assert_eq!(z[0].codes, vec![2, 3]);
    }
}
