//! antivpn — flag connections that originate from VPN / hosting / datacenter networks
//! by the autonomous system (ASN) they come from, using the GeoLite2-ASN data the geoip
//! module already loads. Offline, instant, no external query. Catches datacenter- and
//! cloud-hosted VPNs and bots; a residential-IP VPN looks like an ISP and is NOT caught
//! (only a paid anonymous-IP database or an API would see those). Off by default.
//!
//! IRC caveat: many legitimate users run a bouncer (ZNC) on a cheap VPS, which lives on
//! a hosting ASN. So `antivpn_exempt_registered` (default yes) lets anyone logged into
//! an account through, and `mark` (report only) is the recommended first action.
//!
//! Config: `antivpn` = off | mark | kill | zline; `antivpn_asn` = ASN list (space/comma,
//! repeatable; falls back to a curated default); `antivpn_reason`, `antivpn_duration`
//! (zline length), `antivpn_exempt_registered` (default yes), `antivpn_exempt_ip`.

use crate::server::Server;
use crate::xline::XKind;
use crate::Uid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Off,
    Mark,  // snotice, let them in
    Kill,  // disconnect
    Zline, // z-line the IP and disconnect
}

fn action(s: &Server) -> Action {
    match s.conf("antivpn").map(|v| v.to_ascii_lowercase()).as_deref() {
        Some("mark") | Some("yes") | Some("on") => Action::Mark,
        Some("kill") => Action::Kill,
        Some("zline") => Action::Zline,
        _ => Action::Off,
    }
}

/// The VPN/hosting ASN list — configured `antivpn_asn`, or a curated default when unset.
fn asn_list(s: &Server) -> Vec<u32> {
    let configured: Vec<u32> = s
        .conf_all("antivpn_asn")
        .iter()
        .flat_map(|v| crate::modules::asn::parse_list(v))
        .collect();
    if !configured.is_empty() {
        return configured;
    }
    // well-known VPN / hosting / datacenter ASNs — extend via antivpn_asn. Note several
    // of these host legitimate bouncers, so pair with mark + exempt_registered.
    vec![
        14061,  // DigitalOcean
        16509,  // Amazon AWS
        14618,  // Amazon AWS
        16276,  // OVH
        24940,  // Hetzner
        20473,  // The Constant Company / Vultr
        63949,  // Akamai / Linode
        9009,   // M247
        136787, // TEFINCOM (NordVPN)
        51852,  // PrivateLayer
    ]
}

/// Check a registering user against the VPN/hosting ASN policy. Returns `true` if the
/// connection was refused (the caller must stop). Called from `welcome`, so the account
/// (SASL) is already known.
pub fn check(s: &mut Server, uid: Uid) -> bool {
    let act = action(s);
    if act == Action::Off {
        return false;
    }
    let Some((oper, account, ip, nick)) = s
        .users
        .get(&uid)
        .map(|u| (u.flags.oper, u.account.is_some(), u.addr.ip(), u.nick.clone()))
    else {
        return false;
    };
    if oper || ip.is_loopback() {
        return false;
    }
    if account && s.conf_bool("antivpn_exempt_registered", true) {
        return false; // a logged-in account holder on a VPS/VPN is trusted
    }
    let ip_s = ip.to_string();
    if s.conf_all("antivpn_exempt_ip")
        .iter()
        .any(|r| crate::modules::connclass::ip_matches(r, &ip_s))
    {
        return false;
    }
    let Some(asn) = crate::modules::asn::lookup(s, ip) else {
        return false; // no ASN data for this address — can't judge
    };
    if !asn_list(s).contains(&asn) {
        return false;
    }

    // flagged: the client is on a VPN / hosting ASN
    let asn_s = asn.to_string();
    let m = s.trf(
        "antivpn: {0} ({1}) connects from a VPN/hosting network (AS{2})",
        &[nick.as_str(), ip_s.as_str(), asn_s.as_str()],
    );
    s.snotice_c('c', &m);
    if act == Action::Mark {
        return false; // reported, allowed through
    }

    let reason = s
        .conf("antivpn_reason")
        .unwrap_or("VPN / open proxy / hosting network not allowed here")
        .to_string();
    if act == Action::Zline {
        let dur = s
            .conf("antivpn_duration")
            .and_then(crate::xline::parse_duration)
            .unwrap_or(86400);
        s.add_xline(
            XKind::Zline,
            &ip_s,
            dur,
            "antivpn",
            &format!("{reason} (AS{asn})"),
        );
    }
    let name = s.name.clone();
    s.send(uid, format!(":{name} NOTICE {nick} :{reason}"));
    s.send(uid, format!("ERROR :Closing link: ({reason})"));
    s.remove_user(uid, "VPN/hosting network");
    true
}
