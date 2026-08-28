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
        let (nick, ident, host, port, sni, account, secure, tls_info, websocket, ip) = {
            let Some(u) = srv.users.get(&uid) else {
                return;
            };
            (
                u.nick.clone(),
                u.ident.clone(),
                u.host.clone(),
                u.port,
                u.sni.clone(),
                u.account.clone(),
                u.secure,
                u.tls_info.clone(),
                u.flags.via_websocket,
                u.addr.ip(),
            )
        };
        if srv.conf_bool("snoop_stderr", false) {
            eprintln!("[snoop] connect {nick} ({ident}@{host})");
        }
        // port is always shown; sni/account only when present. Prose + field labels come
        // from the locale catalog so a translated build reads naturally.
        let mut msg = srv.trf(
            "Client connecting: {0} ({1}@{2})",
            &[nick.as_str(), ident.as_str(), host.as_str()],
        );
        let port_s = port.to_string();
        msg.push_str(&srv.trf(", port: {0}", &[port_s.as_str()]));
        // transport + security of this connection (WebSocket clients arrive on the wss
        // listener via nginx/Orbit; TLS clients get the negotiated version/cipher).
        if websocket {
            msg.push_str(&srv.trf(", websocket", &[]));
        }
        if secure {
            match &tls_info {
                Some(info) => msg.push_str(&srv.trf(", tls: {0}", &[info.as_str()])),
                None => msg.push_str(&srv.trf(", secure", &[])),
            }
        }
        // where the client is connecting from: GeoIP country/city (+ ASN if that db is loaded)
        if let Some(geo) = crate::modules::geoip::describe(srv, ip) {
            msg.push_str(&srv.trf(", geo: {0}", &[geo.as_str()]));
        }
        if let Some(sni) = &sni {
            msg.push_str(&srv.trf(", sni: {0}", &[sni.as_str()]));
        }
        if let Some(acct) = &account {
            msg.push_str(&srv.trf(", account: {0}", &[acct.as_str()]));
        }
        srv.snotice_c('c', &msg);
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
