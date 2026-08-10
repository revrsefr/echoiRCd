//! Replaces a user's ident with a stable, opaque 12-character token derived from
//! their IP, so the username field leaks nothing yet stays constant per address.
//!
//! The token is the first 6 bytes of `HMAC-SHA256(hashident_key, ip)`, hex-encoded
//! (12 chars). Off unless `hashident = yes` and a `hashident_key` secret is set;
//! the key is what makes the mapping unforgeable. Applied once, right after connect.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::module::Module;
use crate::server::Server;
use crate::Uid;

/// `HMAC-SHA256(key, data)` via OpenSSL, or `None` on any OpenSSL error.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let pkey = PKey::hmac(key).ok()?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
    signer.update(data).ok()?;
    signer.sign_to_vec().ok()
}

/// The 12-char hashed ident for `ip` under `key`, or `None` if HMAC fails.
fn hashed_ident(key: &str, ip: &str) -> Option<String> {
    let mac = hmac_sha256(key.as_bytes(), ip.as_bytes())?;
    let mut out = String::with_capacity(12);
    for b in mac.iter().take(6) {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    Some(out)
}

pub struct HashIdent;

impl Module for HashIdent {
    fn name(&self) -> &'static str {
        "hashident"
    }

    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        if !srv.conf_bool("hashident", false) {
            return;
        }
        let Some(key) = srv.conf("hashident_key").filter(|k| !k.is_empty()) else {
            return; // no secret configured → do nothing (fail safe)
        };
        let key = key.to_string();
        let ip = match srv.users.get(&uid) {
            Some(u) => u.addr.ip().to_string(),
            None => return,
        };
        if let Some(ident) = hashed_ident(&key, &ip) {
            if let Some(u) = srv.users.get_mut(&uid) {
                u.ident = ident;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_is_12_hex_chars_and_stable() {
        let a = hashed_ident("secretkey", "203.0.113.7").unwrap();
        let b = hashed_ident("secretkey", "203.0.113.7").unwrap();
        assert_eq!(a, b); // same ip+key → same ident
        assert_eq!(a.len(), 12);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_key_or_ip_changes_it() {
        let base = hashed_ident("k1", "203.0.113.7").unwrap();
        assert_ne!(base, hashed_ident("k2", "203.0.113.7").unwrap());
        assert_ne!(base, hashed_ident("k1", "203.0.113.8").unwrap());
    }
}
