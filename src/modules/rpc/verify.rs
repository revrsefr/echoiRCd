//! Verification RPC provider: `verify.pass`. The verification web page pushes a
//! solved challenge token here after its Turnstile check; the daemon runs the same
//! JWT checks as CAPTCHA/VERIFYCHALLENGE (signature, expiry) and clears the token's
//! IP via [`verify_common`], so held connections from that IP auto-complete.

use super::json::obj;
use super::RpcError;
use crate::http::json_str;
use crate::modules::{jwt, verify_common};
use crate::server::{now, Server};

pub fn handle(s: &mut Server, action: &str, params: &str) -> Result<String, RpcError> {
    match action {
        "pass" => {
            let token =
                json_str(params, "token").ok_or_else(|| RpcError::invalid_params("token required"))?;
            // Signed by whichever gate issued it — try both HS256 secrets.
            let secrets: Vec<String> = ["cloudflare_secret", "recaptcha_secret"]
                .into_iter()
                .filter_map(|k| s.conf(k))
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect();
            let claims = secrets
                .iter()
                .find_map(|sec| jwt::verify_hs256(&token, sec))
                .ok_or_else(|| RpcError::not_found("invalid or tampered token"))?;
            if jwt::claim_num(&claims, "exp").unwrap_or(0) <= now() as i64 {
                return Err(RpcError::not_found("token has expired"));
            }
            let exp = jwt::claim_num(&claims, "exp").unwrap_or(0).max(0) as u64;
            let ip = json_str(&claims, "ip").ok_or_else(|| RpcError::not_found("token missing ip"))?;
            verify_common::mark_ip(s, &ip, exp);
            Ok(obj(&[("verified", "true".into()), ("ip", format!("\"{ip}\""))]))
        }
        _ => Err(RpcError::method_not_found(&format!("verify.{action}"))),
    }
}
