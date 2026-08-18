//! account_registration — IRCv3 `draft/account-registration` (`REGISTER` / `VERIFY`
//! commands and the cap advertising them), bridged to a configurable HTTP accounts
//! API. POSTs form-encoded fields with an `X-API-Key` header.
//!
//! The API call runs on a worker thread (`Server::spawn_http`) and its result comes
//! back as `Event::HttpResult` → [`on_http_result`], so a slow endpoint never blocks
//! the core. On success (and when `acctregister_autologin`) the user is logged into
//! the new account. Per-IP rate-limit state lives in `Server.ext`.
//!
//! Config (all under flat keys):
//!   account_registration = yes        enable
//!   acctregister_registerurl = <url>  POST username,email,password,client_ip,port
//!   acctregister_verifyurl   = <url>  POST username,code
//!   acctregister_apikey      = <key>  sent as X-API-Key
//!   acctregister_emailrequired = yes  require a real email (advertise email-required)
//!   acctregister_beforeconnect = yes  allow REGISTER before the handshake completes
//!   acctregister_autologin     = yes  log in on success
//!   acctregister_requiretls    = yes  refuse REGISTER on a plaintext link
//!   acctregister_ratecount = 3        max REGISTER attempts per IP …
//!   acctregister_ratetime  = 3600     … per this many seconds

use crate::map::HashMap;

use crate::command::{CmdResult, Command};
use crate::http::{json_str, urlencode};
use crate::module::Module;
use crate::server::{now, Server};
use crate::Uid;

/// Per-IP REGISTER attempt timestamps, for rate limiting. Stored in `Server.ext`.
#[derive(Default)]
struct RateState(HashMap<String, Vec<u64>>);

/// Ticks the rate-limit table: prunes each IP's timestamps to the window and drops
/// IPs with none left, so the map can't accumulate one entry per distinct IP that
/// ever issued a REGISTER over the process lifetime.
pub struct AcctRegGc;
impl Module for AcctRegGc {
    fn name(&self) -> &'static str {
        "account_registration"
    }
    fn on_tick(&mut self, s: &mut Server) {
        let window = s.conf_num("acctregister_ratetime", 3600u64);
        let n = now();
        if let Some(st) = s.ext.get_mut::<RateState>() {
            st.0.retain(|_, hist| {
                hist.retain(|&t| n.saturating_sub(t) < window);
                !hist.is_empty()
            });
        }
    }
}

fn enabled(s: &Server) -> bool {
    s.conf_bool("account_registration", false) && s.conf("acctregister_registerurl").is_some()
}

/// The value tokens advertised on the `draft/account-registration` cap (302). Empty
/// when the module is disabled (so the cap is advertised bare / not at all).
pub fn cap_tokens(s: &Server) -> String {
    if !enabled(s) {
        return String::new();
    }
    let mut toks = vec!["custom-account-name"];
    if s.conf_bool("acctregister_beforeconnect", true) {
        toks.push("before-connect");
    }
    if s.conf_bool("acctregister_emailrequired", true) {
        toks.push("email-required");
    }
    toks.join(",")
}

fn apikey_headers(s: &Server) -> Vec<(String, String)> {
    match s.conf("acctregister_apikey") {
        Some(k) if !k.is_empty() => vec![("X-API-Key".to_string(), k.to_string())],
        _ => Vec::new(),
    }
}

/// Rate-limit a REGISTER from `ip`; true when the attempt is within budget.
fn rate_ok(s: &mut Server, ip: &str) -> bool {
    let count = s.conf_num("acctregister_ratecount", 3u32);
    let window = s.conf_num("acctregister_ratetime", 3600u64);
    if count == 0 {
        return true;
    }
    let n = now();
    let st = s.ext.get_or_insert_with::<RateState>(RateState::default);
    let hist = st.0.entry(ip.to_string()).or_default();
    hist.retain(|&t| n.saturating_sub(t) < window);
    if hist.len() as u32 >= count {
        return false;
    }
    hist.push(n);
    true
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Register), Box::new(Verify)]
}

/// REGISTER `<account> <email> <password>` — `<account>` may be `*` for the current
/// nick. IRCv3 `draft/account-registration`.
struct Register;
impl Command for Register {
    fn name(&self) -> &'static str {
        "REGISTER"
    }
    fn min_params(&self) -> usize {
        0
    }
    fn before_reg(&self) -> bool {
        true // allow before-connect; the handler re-checks the config gate
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !enabled(s) {
            s.fail(
                uid,
                "REGISTER",
                "TEMPORARILY_UNAVAILABLE",
                "Account registration is disabled.",
            );
            return CmdResult::Fail;
        }
        if params.len() < 3 {
            s.fail(
                uid,
                "REGISTER",
                "INVALID_PARAMS",
                "Syntax: REGISTER <account|*> <email> <password>",
            );
            return CmdResult::Fail;
        }
        let registered = s.users.get(&uid).map(|u| u.registered).unwrap_or(false);
        if !registered && !s.conf_bool("acctregister_beforeconnect", true) {
            s.fail(
                uid,
                "REGISTER",
                "COMPLETE_CONNECTION_REQUIRED",
                "Finish connecting before registering.",
            );
            return CmdResult::Fail;
        }
        let (secure, nick, ip, port) = match s.users.get(&uid) {
            Some(u) => (
                u.secure,
                u.nick.clone(),
                u.addr.ip().to_string(),
                u.addr.port(),
            ),
            None => return CmdResult::Fail,
        };
        if s.conf_bool("acctregister_requiretls", true) && !secure {
            s.fail(
                uid,
                "REGISTER",
                "REG_UNAVAILABLE",
                "Registration requires a TLS connection.",
            );
            return CmdResult::Fail;
        }
        let account = if params[0] == "*" {
            nick.clone()
        } else {
            params[0].clone()
        };
        if account.is_empty() {
            s.fail(
                uid,
                "REGISTER",
                "ACCOUNT_NAME_MUST_BE_NICK",
                "Choose an account name (or set a nick first).",
            );
            return CmdResult::Fail;
        }
        let email = params[1].clone();
        if s.conf_bool("acctregister_emailrequired", true) && (email == "*" || email.is_empty()) {
            s.fail(
                uid,
                "REGISTER",
                "INVALID_EMAIL",
                "A valid email address is required.",
            );
            return CmdResult::Fail;
        }
        if !rate_ok(s, &ip) {
            s.fail(
                uid,
                "REGISTER",
                "RATE_LIMITED",
                "Too many registration attempts. Please wait.",
            );
            return CmdResult::Fail;
        }

        let url = s.conf("acctregister_registerurl").unwrap_or("").to_string();
        let body = format!(
            "username={}&email={}&password={}&client_ip={}&port={}",
            urlencode(&account),
            urlencode(&email),
            urlencode(&params[2]),
            urlencode(&ip),
            port
        );
        s.spawn_http(
            uid,
            format!("acctreg:register:{account}"),
            url,
            body,
            apikey_headers(s),
        );
        CmdResult::Ok
    }
}

/// VERIFY `<account> <code>` — confirm a pending registration with an emailed code.
struct Verify;
impl Command for Verify {
    fn name(&self) -> &'static str {
        "VERIFY"
    }
    fn min_params(&self) -> usize {
        0
    }
    fn before_reg(&self) -> bool {
        true
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !enabled(s) || s.conf("acctregister_verifyurl").is_none() {
            s.fail(
                uid,
                "VERIFY",
                "TEMPORARILY_UNAVAILABLE",
                "Account verification is disabled.",
            );
            return CmdResult::Fail;
        }
        if params.len() < 2 {
            s.fail(
                uid,
                "VERIFY",
                "INVALID_PARAMS",
                "Syntax: VERIFY <account> <code>",
            );
            return CmdResult::Fail;
        }
        let account = params[0].clone();
        let url = s.conf("acctregister_verifyurl").unwrap_or("").to_string();
        let body = format!(
            "username={}&code={}",
            urlencode(&account),
            urlencode(&params[1])
        );
        s.spawn_http(
            uid,
            format!("acctreg:verify:{account}"),
            url,
            body,
            apikey_headers(s),
        );
        CmdResult::Ok
    }
}

/// Truthy JSON field? Matches `"key":true` (whitespace-tolerant) in `body`.
fn json_true(body: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    if let Some(pos) = body.find(&needle) {
        let after = &body[pos + needle.len()..];
        if let Some(colon) = after.find(':') {
            return after[colon + 1..].trim_start().starts_with("true");
        }
    }
    false
}

/// Called from the core when a REGISTER/VERIFY HTTP call finishes. `detail` is
/// `"register:<account>"` or `"verify:<account>"`.
pub fn on_http_result(s: &mut Server, uid: Uid, detail: &str, status: u16, body: &str) {
    let Some((kind, account)) = detail.split_once(':') else {
        return;
    };
    if !s.users.contains_key(&uid) {
        return; // user vanished while the request was in flight
    }
    let verb = if kind == "verify" {
        "VERIFY"
    } else {
        "REGISTER"
    };
    let msg = json_str(body, "message")
        .or_else(|| json_str(body, "error"))
        .unwrap_or_else(|| "Account service response.".to_string());

    // transport failure
    if status == 0 {
        s.fail(
            uid,
            verb,
            "TEMPORARILY_UNAVAILABLE",
            "The account service is unreachable. Try again later.",
        );
        return;
    }
    let ok = (200..300).contains(&status) && json_true(body, "success");
    if !ok {
        let code = json_str(body, "code").unwrap_or_else(|| "REGISTRATION_FAILED".to_string());
        s.send(
            uid,
            format!(":{} FAIL {verb} {code} {account} :{msg}", s.name),
        );
        return;
    }

    let autologin = s.conf_bool("acctregister_autologin", true);
    if kind == "register" && json_true(body, "verification_required") {
        s.send(
            uid,
            format!(
                ":{} REGISTER VERIFICATION_REQUIRED {account} :{msg}",
                s.name
            ),
        );
        return;
    }
    s.send(uid, format!(":{} {verb} SUCCESS {account} :{msg}", s.name));
    if autologin {
        s.set_login(uid, account);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_true_detects_boolean() {
        assert!(json_true(r#"{"success": true}"#, "success"));
        assert!(json_true(r#"{"success":true,"x":1}"#, "success"));
        assert!(!json_true(r#"{"success": false}"#, "success"));
        assert!(!json_true(r#"{"other": true}"#, "success"));
    }
}
