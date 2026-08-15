//! cloudflare_challenge: gate registration behind a challenge verified by an
//! IP-bound HS256 JWT, presented via the `VERIFYCHALLENGE <token>` command. A
//! validly-signed, unexpired, IP-matching token is sufficient proof; no backend
//! call is made.
//!
//! Off unless `cloudflare_challenge = yes` with `cloudflare_secret` +
//! `cloudflare_url` set. The passed-verification set lives in `Server.ext`.

use std::collections::HashSet;

use crate::command::{CmdResult, Command};
use crate::http::json_str;
use crate::module::{ModResult, Module};
use crate::modules::jwt;
use crate::server::{now, Server};
use crate::Uid;

/// uids that have cleared the Cloudflare challenge this connection. In `Server.ext`.
#[derive(Default)]
struct Passed(HashSet<Uid>);

fn enabled(s: &Server) -> bool {
    s.conf_bool("cloudflare_challenge", false)
        && s.conf("cloudflare_secret").is_some_and(|v| !v.is_empty())
        && s.conf("cloudflare_url").is_some_and(|v| !v.is_empty())
}

fn passed(s: &Server, uid: Uid) -> bool {
    s.ext
        .get::<Passed>()
        .map(|v| v.0.contains(&uid))
        .unwrap_or(false)
}

fn port_whitelisted(s: &Server, uid: Uid) -> bool {
    let Some(port) = s.users.get(&uid).map(|u| u.addr.port()) else {
        return false;
    };
    s.conf_all("cloudflare_whitelistports").iter().any(|line| {
        line.split([',', ' '])
            .filter(|x| !x.is_empty())
            .any(|p| p.parse::<u16>() == Ok(port))
    })
}

fn make_token(s: &Server, uid: Uid) -> Option<String> {
    let secret = s.conf("cloudflare_secret")?;
    let issuer = s.conf("cloudflare_issuer").unwrap_or("echoIRCd");
    let ttl = s.conf_num("cloudflare_ttl", 1800i64);
    let ip = s.users.get(&uid)?.addr.ip().to_string();
    let n = now() as i64;
    let claims = format!(
        r#"{{"iss":"{issuer}","ip":"{ip}","iat":{n},"exp":{}}}"#,
        n + ttl
    );
    jwt::sign_hs256(&claims, secret)
}

pub struct CloudflareChallenge;

impl Module for CloudflareChallenge {
    fn name(&self) -> &'static str {
        "cloudflare_challenge"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(p) = s.ext.get_mut::<Passed>() {
            p.0.remove(&uid);
        }
    }

    fn on_user_register(&mut self, srv: &mut Server, uid: Uid) -> ModResult {
        if !enabled(srv) || srv.is_oper(uid) {
            return ModResult::Passthru;
        }
        if passed(srv, uid) || port_whitelisted(srv, uid) {
            return ModResult::Passthru;
        }
        let (nick, token) = (
            srv.users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default(),
            make_token(srv, uid),
        );
        if let Some(token) = token {
            let base = srv.conf("cloudflare_url").unwrap_or("");
            let sep = if base.contains('?') { '&' } else { '?' };
            let link = format!("{base}{sep}token={token}");
            let template = srv
                .conf("cloudflare_message")
                .unwrap_or("*** Cloudflare Challenge: verify your connection at {url}")
                .to_string();
            let msg = template.replace("{url}", &link);
            srv.send(uid, format!(":{} NOTICE {nick} :{msg}", srv.name));
        }
        ModResult::Deny
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(VerifyChallenge)]
}

/// VERIFYCHALLENGE `<token>` — present the signed Cloudflare challenge token.
struct VerifyChallenge;
impl Command for VerifyChallenge {
    fn name(&self) -> &'static str {
        "VERIFYCHALLENGE"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !enabled(s) {
            return CmdResult::Ok;
        }
        let token = params[0].clone();
        let secret = s.conf("cloudflare_secret").unwrap_or("").to_string();
        let issuer = s
            .conf("cloudflare_issuer")
            .unwrap_or("echoIRCd")
            .to_string();
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        let ip = s
            .users
            .get(&uid)
            .map(|u| u.addr.ip().to_string())
            .unwrap_or_default();

        let fail = |s: &mut Server, why: &str| {
            s.send(
                uid,
                format!(":{} NOTICE {nick} :*** Cloudflare Challenge: {why}", s.name),
            );
            CmdResult::Fail
        };

        let Some(claims) = jwt::verify_hs256(&token, &secret) else {
            return fail(s, "invalid or tampered token. Reconnect and verify again.");
        };
        if json_str(&claims, "iss").as_deref() != Some(issuer.as_str()) {
            return fail(s, "token issuer mismatch.");
        }
        if json_str(&claims, "ip").as_deref() != Some(ip.as_str()) {
            return fail(s, "token IP does not match. Reconnect and verify again.");
        }
        if jwt::claim_num(&claims, "exp").unwrap_or(0) <= now() as i64 {
            return fail(s, "token has expired. Please verify again.");
        }
        s.ext
            .get_or_insert_with::<Passed>(Passed::default)
            .0
            .insert(uid);
        s.send(
            uid,
            format!(
                ":{} NOTICE {nick} :*** Cloudflare Challenge: verification successful — you may continue.",
                s.name
            ),
        );
        CmdResult::Ok
    }
}
