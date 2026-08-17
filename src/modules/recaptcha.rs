//! Gate registration behind a human-verification step. An unverified user is handed
//! a one-time, IP-bound HS256 JWT and a URL to solve a reCAPTCHA at; once solved they
//! present the signed token back with `CAPTCHA <token>` and the connection is allowed.
//!
//! Modes:
//!   * JWT-only (default): a validly-signed, unexpired, IP-matching token is proof
//!     enough — no backend call, so it works standalone.
//!   * backend (`recaptcha_checkurl` set): additionally POST the token to a backend
//!     that confirms the captcha was actually solved (async, via `Server::spawn_http`).
//!
//! The token binds to the client IP (not the per-connection id) so a token earned
//! in a browser survives the reconnect. Off unless `recaptcha = yes` and both
//! `recaptcha_secret` and `recaptcha_url` are set. All config-driven; the only
//! state (who has passed) lives in `Server.ext`.

use std::collections::HashSet;

use crate::command::{CmdResult, Command};
use crate::http::json_str;
use crate::module::{ModResult, Module};
use crate::modules::jwt;
use crate::server::{now, Server};
use crate::Uid;

/// The set of uids that have passed verification this connection. In `Server.ext`.
#[derive(Default)]
struct Verified(HashSet<Uid>);

/// The set of uids already handed a challenge, so a held client sending extra
/// commands doesn't get the challenge notice re-issued each time. In `Server.ext`.
#[derive(Default)]
struct Challenged(HashSet<Uid>);

fn enabled(s: &Server) -> bool {
    s.conf_bool("recaptcha", false)
        && s.conf("recaptcha_secret").is_some_and(|v| !v.is_empty())
        && s.conf("recaptcha_url").is_some_and(|v| !v.is_empty())
}

fn is_verified(s: &Server, uid: Uid) -> bool {
    s.ext
        .get::<Verified>()
        .map(|v| v.0.contains(&uid))
        .unwrap_or(false)
}

/// Whether the user's source port is in `recaptcha_whitelistports` (skip captcha).
fn port_whitelisted(s: &Server, uid: Uid) -> bool {
    let Some(port) = s.users.get(&uid).map(|u| u.addr.port()) else {
        return false;
    };
    s.conf_all("recaptcha_whitelistports").iter().any(|line| {
        line.split([',', ' '])
            .filter(|x| !x.is_empty())
            .any(|p| p.parse::<u16>() == Ok(port))
    })
}

/// Build the IP-bound challenge token for `uid`.
fn make_token(s: &Server, uid: Uid) -> Option<String> {
    let secret = s.conf("recaptcha_secret")?;
    let issuer = s.conf("recaptcha_issuer").unwrap_or("echoIRCd");
    let ttl = s.conf_num("recaptcha_ttl", 1800i64);
    let ip = s.users.get(&uid)?.addr.ip().to_string();
    let n = now() as i64;
    let claims = format!(
        r#"{{"iss":"{issuer}","ip":"{ip}","iat":{n},"exp":{}}}"#,
        n + ttl
    );
    jwt::sign_hs256(&claims, secret)
}

pub struct ReCaptcha;

impl Module for ReCaptcha {
    fn name(&self) -> &'static str {
        "recaptcha"
    }
    fn on_user_quit(&mut self, s: &mut Server, uid: Uid, _reason: &str) {
        if let Some(v) = s.ext.get_mut::<Verified>() {
            v.0.remove(&uid);
        }
        if let Some(c) = s.ext.get_mut::<Challenged>() {
            c.0.remove(&uid);
        }
    }

    fn on_user_register(&mut self, srv: &mut Server, uid: Uid) -> ModResult {
        if !enabled(srv) || srv.is_oper(uid) {
            return ModResult::Passthru;
        }
        if is_verified(srv, uid) || port_whitelisted(srv, uid) {
            return ModResult::Passthru;
        }
        // issue the challenge exactly once; later held attempts just keep holding
        if srv
            .ext
            .get::<Challenged>()
            .is_some_and(|c| c.0.contains(&uid))
        {
            return ModResult::Hold;
        }
        srv.ext
            .get_or_insert_with::<Challenged>(Challenged::default)
            .0
            .insert(uid);
        // hand out a challenge and hold the link until they verify
        let (nick, token) = (
            srv.users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default(),
            make_token(srv, uid),
        );
        if let Some(token) = token {
            let base = srv.conf("recaptcha_url").unwrap_or("");
            let sep = if base.contains('?') { '&' } else { '?' };
            let link = format!("{base}{sep}token={token}");
            let template = srv
                .conf("recaptcha_message")
                .unwrap_or("*** reCAPTCHA: verify your connection at {url}")
                .to_string();
            let msg = template.replace("{url}", &link);
            srv.send(uid, format!(":{} NOTICE {nick} :{msg}", srv.name));
        }
        // Hold the connection for the challenge (CAPTCHA <token>), don't tear it down.
        ModResult::Hold
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Captcha)]
}

/// Mark `uid` verified (used by the sync path and the async backend callback).
fn mark_verified(s: &mut Server, uid: Uid) {
    s.ext
        .get_or_insert_with::<Verified>(Verified::default)
        .0
        .insert(uid);
    let nick = s
        .users
        .get(&uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    s.send(
        uid,
        format!(
            ":{} NOTICE {nick} :*** reCAPTCHA: verification successful — you may continue.",
            s.name
        ),
    );
}

/// CAPTCHA `<token>` — present the signed verification token. Usable during the
/// handshake (before registration completes).
struct Captcha;
impl Command for Captcha {
    fn name(&self) -> &'static str {
        "CAPTCHA"
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
        let secret = s.conf("recaptcha_secret").unwrap_or("").to_string();
        let issuer = s.conf("recaptcha_issuer").unwrap_or("echoIRCd").to_string();
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
                format!(":{} NOTICE {nick} :*** reCAPTCHA: {why}", s.name),
            );
            CmdResult::Fail
        };

        let Some(claims) = jwt::verify_hs256(&token, &secret) else {
            return fail(
                s,
                "invalid or tampered token. Please reconnect and verify again.",
            );
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
        // JWT-only mode: a validly-signed, unexpired, IP-matching token is proof.
        mark_verified(s, uid);
        CmdResult::Ok
    }
}
