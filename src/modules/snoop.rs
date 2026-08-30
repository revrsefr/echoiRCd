//! A tiny example module: log connects, joins and quits to stderr. It exercises
//! the hook wiring end-to-end and is the template for real modules.

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

pub struct Snoop;

impl Module for Snoop {
    fn name(&self) -> &'static str {
        "snoop"
    }
    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        // `conf_bool`/`snotice_c` are `&self`, so we can hold the `&User` borrow and
        // reference its fields directly instead of cloning them out.
        let (nick, ident, host, cloak, vhost, port, sni, account, secure, tls_info, websocket, ip) = {
            let Some(u) = srv.users.get(&uid) else {
                return;
            };
            (
                u.nick.clone(),
                u.ident.clone(),
                u.host.clone(),
                u.cloak.clone(),
                u.vhost.clone(),
                u.port,
                u.sni.clone(),
                u.account.clone(),
                u.secure,
                u.tls_info.clone(),
                u.flags.via_websocket,
                u.addr.ip(),
            )
        };
        // The host other users see: vhost > +x cloak > real host. snoop is registered
        // ahead of the cloak module, so u.cloak is still empty here — derive it now
        // (compute_cloak is deterministic) so the notice shows the +x mask, not the raw
        // host. Falls back to the real host when cloaking is disabled.
        let shown_host = if let Some(v) = vhost.filter(|v| !v.is_empty()) {
            v
        } else if !cloak.is_empty() {
            cloak
        } else {
            crate::modules::cloak::compute_cloak(srv, uid).unwrap_or(host)
        };
        if srv.conf_bool("snoop_stderr", false) {
            eprintln!("[snoop] connect {nick} ({ident}@{shown_host})");
        }
        // The notice is rendered per-viewer: the sensitive fields — the raw IP and the
        // geo/ASN — go only to opers holding the users/auspex privilege; lower opers get a
        // redaction. The rest (cloak hostmask, port, transport, security, sni, account) is
        // identical for all, and the server log always keeps the full detail. Prose + field
        // labels come from the locale catalog so a translated build reads naturally.
        let (fam, ip_s) = match ip {
            std::net::IpAddr::V4(v4) => ("ipv4", v4.to_string()),
            std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ("ipv4", v4.to_string()),
                None => ("ipv6", v6.to_string()),
            },
        };
        let redacted_val = srv.trf("🔒 restricted", &[]);
        let head = srv.trf(
            "Client connecting: {0} ({1}@{2})",
            &[nick.as_str(), ident.as_str(), shown_host.as_str()],
        );
        // the connecting address, tagged by family (an ipv4-mapped v6 shows its ipv4 form)
        let ip_full = srv.trf(", {0}:{1}", &[fam, ip_s.as_str()]);
        let ip_red = srv.trf(", {0}:{1}", &[fam, redacted_val.as_str()]);
        let port_seg = srv.trf(", port: {0}", &[port.to_string().as_str()]);
        // transport + security (WebSocket clients arrive on the wss listener via
        // nginx/Orbit; TLS clients get the negotiated version/cipher).
        let mut trans = String::new();
        if websocket {
            trans.push_str(&srv.trf(", websocket", &[]));
        }
        if secure {
            match &tls_info {
                Some(info) => trans.push_str(&srv.trf(", tls: {0}", &[info.as_str()])),
                None => trans.push_str(&srv.trf(", secure", &[])),
            }
        }
        // geo: GeoIP country/city (+ ASN when that db is loaded) — sensitive like the IP
        let (geo_full, geo_red) = match crate::modules::geoip::describe(srv, ip) {
            Some(g) => (
                srv.trf(", geo: {0}", &[g.as_str()]),
                srv.trf(", geo: {0}", &[redacted_val.as_str()]),
            ),
            None => (String::new(), String::new()),
        };
        let mut tail = String::new();
        if let Some(sni) = &sni {
            tail.push_str(&srv.trf(", sni: {0}", &[sni.as_str()]));
        }
        if let Some(acct) = &account {
            tail.push_str(&srv.trf(", account: {0}", &[acct.as_str()]));
        }
        let full = format!("{head}{ip_full}{port_seg}{trans}{geo_full}{tail}");
        let redacted = format!("{head}{ip_red}{port_seg}{trans}{geo_red}{tail}");
        srv.snotice_c_gated('c', &full, &redacted, |u| {
            crate::modules::opertypes::user_has_priv(u, crate::modules::opertypes::privs::USERS_AUSPEX)
        });
    }
    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {
        if srv.conf_bool("snoop_stderr", false) {
            if let Some(u) = srv.users.get(&uid) {
                eprintln!("[snoop] {} joined {chan}", u.nick);
            }
        }
    }
    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {
        // Only announce clients that actually registered. A health/liveness probe — or
        // any client that drops mid-handshake — never fired a connect notice, so it must
        // not fire an exit notice either, else it spams the +q snomask on every probe.
        // (on_user_quit itself still fires for unregistered users so modules reclaim
        // their per-uid state; only this operator-facing notice is gated.)
        let Some(nick) = srv
            .users
            .get(&uid)
            .filter(|u| u.registered)
            .map(|u| u.nick.clone())
        else {
            return;
        };
        if srv.conf_bool("snoop_stderr", false) {
            eprintln!("[snoop] quit uid={uid} ({reason})");
        }
        let m = srv.trf("Client exiting: {0} ({1})", &[nick.as_str(), reason]);
        srv.snotice_c('q', &m);
    }
}
