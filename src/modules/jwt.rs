//! jwt — a tiny, dependency-free JSON Web Token (HS256) helper shared by the
//! captcha / challenge modules (recaptcha, cloudflare_challenge, cloudfire) and
//! `ircv3_extjwt`. Sign and verify only what echoIRCd needs: compact JWS, HMAC-
//! SHA256, base64url — all on OpenSSL (already a dependency), no `unsafe`, no crate.
//!
//! This is not a general JWT library: claims are passed and returned as raw JSON
//! text, so callers use [`crate::http::json_str`] / [`claim_num`] to read fields.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// base64url (no padding) of arbitrary bytes.
pub(crate) fn b64url(data: &[u8]) -> String {
    let std = openssl::base64::encode_block(data);
    std.trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Decode base64url (no padding) back to bytes.
#[allow(clippy::manual_is_multiple_of)] // is_multiple_of is unstable on our MSRV
pub(crate) fn unb64url(s: &str) -> Option<Vec<u8>> {
    let mut std = s.replace('-', "+").replace('_', "/");
    while std.len() % 4 != 0 {
        std.push('=');
    }
    openssl::base64::decode_block(&std).ok()
}

/// `HMAC-SHA256(secret, data)`.
fn hmac(secret: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let key = PKey::hmac(secret).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key).ok()?;
    signer.update(data).ok()?;
    signer.sign_to_vec().ok()
}

/// Sign a compact HS256 JWT with the given raw-JSON `claims` and `secret`.
pub fn sign_hs256(claims_json: &str, secret: &str) -> Option<String> {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = b64url(claims_json.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = b64url(&hmac(secret.as_bytes(), signing_input.as_bytes())?);
    Some(format!("{signing_input}.{sig}"))
}

/// Verify a compact HS256 JWT against `secret`; on success return the decoded
/// claims as raw JSON text. Signature check is constant-time. Does NOT check
/// `exp`/`iss` — the caller inspects the returned claims for those.
pub fn verify_hs256(token: &str, secret: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let want = hmac(secret.as_bytes(), signing_input.as_bytes())?;
    let got = unb64url(parts[2])?;
    if got.len() != want.len() || !openssl::memcmp::eq(&got, &want) {
        return None;
    }
    let claims = unb64url(parts[1])?;
    String::from_utf8(claims).ok()
}

/// Read a numeric claim (e.g. `exp`, `iat`) from raw-JSON claims text. Matches `key`
/// only as a *top-level* object key (depth 1) immediately followed by `:`, so a claim
/// whose string *value* contains `"exp":…` can't spoof what a verifier reads.
pub fn claim_num(claims_json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let bytes = claims_json.as_bytes();
    let (mut depth, mut in_str, mut esc, mut i) = (0i32, false, false, 0usize);
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                // a real top-level key is `"key"` at depth 1 followed by `:`
                if depth == 1 && claims_json[i..].starts_with(&needle) {
                    let rest = claims_json[i + needle.len()..].trim_start();
                    if let Some(tail) = rest.strip_prefix(':') {
                        let tail = tail.trim_start();
                        let end = tail
                            .find(|c: char| !c.is_ascii_digit() && c != '-')
                            .unwrap_or(tail.len());
                        return tail[..end].parse().ok();
                    }
                }
                in_str = true;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrips() {
        let claims = r#"{"iss":"echo","sub":"0AAAAA","ip":"1.2.3.4","exp":9999999999}"#;
        let tok = sign_hs256(claims, "topsecret").unwrap();
        assert_eq!(tok.split('.').count(), 3);
        let got = verify_hs256(&tok, "topsecret").unwrap();
        assert_eq!(got, claims);
    }

    #[test]
    fn wrong_secret_or_tamper_fails() {
        let tok = sign_hs256(r#"{"a":1}"#, "k1").unwrap();
        assert!(verify_hs256(&tok, "k2").is_none()); // wrong key
        let mut bad = tok.clone();
        bad.push('x'); // tamper the signature
        assert!(verify_hs256(&bad, "k1").is_none());
        assert!(verify_hs256("only.two", "k1").is_none()); // malformed
    }

    #[test]
    fn reads_numeric_claims() {
        let c = r#"{"iss":"e","exp":1730000000,"iat":1729998200}"#;
        assert_eq!(claim_num(c, "exp"), Some(1730000000));
        assert_eq!(claim_num(c, "iat"), Some(1729998200));
        assert_eq!(claim_num(c, "nope"), None);
        // a nested object's key must not be read as the top-level claim
        assert_eq!(claim_num(r#"{"data":{"exp":999},"exp":42}"#, "exp"), Some(42));
        // a string value containing `"exp":` must not spoof it
        assert_eq!(claim_num("{\"note\":\"\\\"exp\\\":13\",\"exp\":7}", "exp"), Some(7));
    }
}
