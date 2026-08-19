//! Hashed `<oper>` passwords plus a `/MKPASSWD` helper, backed by OpenSSL.
//! Verifies stored hashes and generates new ones (md5, sha1, sha2, pbkdf2).
//!
//! A stored password is either plaintext (no recognised prefix) or `"<algo>:<hex>"`:
//!   * `md5:` `sha1:` `sha256:` `sha512:` — a plain hex digest of the password
//!   * `pbkdf2:<iters>:<salthex>:<hashhex>` — PBKDF2-HMAC-SHA256, salted
//!   * `$2b$<cost>$...` — bcrypt (see [`crate::bcrypt`]); MKPASSWD accepts a
//!     `bcrypt` or `bcrypt:<cost>` algorithm
//!
//! Comparisons are constant-time (`openssl::memcmp`). The OPER handler calls [`verify`].

use openssl::hash::{hash, MessageDigest};
use openssl::pkcs5::pbkdf2_hmac;
use openssl::rand::rand_bytes;

use crate::command::{CmdResult, Command};
use crate::numeric::ERR_NOPRIVILEGES;
use crate::server::Server;
use crate::Uid;

/// The OpenSSL digest for a named simple algorithm.
fn digest_for(algo: &str) -> Option<MessageDigest> {
    match algo.to_ascii_lowercase().as_str() {
        "md5" => Some(MessageDigest::md5()),
        "sha1" => Some(MessageDigest::sha1()),
        "sha256" | "sha2" | "sha-256" => Some(MessageDigest::sha256()),
        "sha512" | "sha-512" => Some(MessageDigest::sha512()),
        _ => None,
    }
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Decode a lowercase/uppercase hex string to bytes (None on bad input).
#[allow(clippy::manual_is_multiple_of)] // is_multiple_of is unstable on our MSRV
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Constant-time equality (guards against timing attacks on the compare).
/// `openssl::memcmp::eq` requires equal-length inputs, so short-circuit first.
/// Shared comparator for any secret check (passwords, gateway/vhost secrets).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

/// Upper bound on PBKDF2 iterations honoured from a stored credential. Legitimate
/// work factors are well under this; a larger value (from a corrupt or hostile
/// credential string) would pin a worker thread, so we reject it instead.
const MAX_PBKDF2_ITERS: usize = 10_000_000;

/// PBKDF2-HMAC-SHA256 of `pass` with `salt` and `iters`, `len` bytes out.
fn pbkdf2(pass: &str, salt: &[u8], iters: usize, len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    pbkdf2_hmac(
        pass.as_bytes(),
        salt,
        iters,
        MessageDigest::sha256(),
        &mut out,
    )
    .ok()?;
    Some(out)
}

/// Verify `plaintext` against a `stored` credential. Plaintext (no known prefix)
/// falls back to a constant-time string compare, so existing configs keep working.
pub fn verify(stored: &str, plaintext: &str) -> bool {
    // bcrypt: $2a$/$2b$/$2y$<cost>$<salt><hash>
    if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$") {
        return crate::bcrypt::verify(stored, plaintext);
    }
    // pbkdf2:<iters>:<salthex>:<hashhex>
    if let Some(rest) = stored.strip_prefix("pbkdf2:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            if let (Ok(iters), Some(salt), Some(want)) =
                (parts[0].parse::<usize>(), unhex(parts[1]), unhex(parts[2]))
            {
                if !(1..=MAX_PBKDF2_ITERS).contains(&iters) {
                    return false; // absurd/zero work factor — refuse, don't compute
                }
                if let Some(got) = pbkdf2(plaintext, &salt, iters, want.len()) {
                    return ct_eq(&got, &want);
                }
            }
        }
        return false;
    }
    // <algo>:<hex>
    if let Some((algo, want_hex)) = stored.split_once(':') {
        if let Some(md) = digest_for(algo) {
            if let (Ok(got), Some(want)) = (hash(md, plaintext.as_bytes()), unhex(want_hex)) {
                return ct_eq(&got, &want);
            }
            return false;
        }
    }
    // plaintext
    ct_eq(stored.as_bytes(), plaintext.as_bytes())
}

/// Produce a stored-credential string for `algo` over `plaintext`. For pbkdf2 a
/// fresh 16-byte salt and 60000 iterations are used.
fn make(algo: &str, plaintext: &str) -> Option<String> {
    // bcrypt, optionally "bcrypt:<cost>" (default cost 10)
    let lower = algo.to_ascii_lowercase();
    if lower == "bcrypt" || lower.starts_with("bcrypt:") {
        let cost = lower
            .strip_prefix("bcrypt:")
            .and_then(|c| c.parse().ok())
            .unwrap_or(10);
        return crate::bcrypt::hash(cost, plaintext);
    }
    if algo.eq_ignore_ascii_case("pbkdf2") {
        let mut salt = [0u8; 16];
        rand_bytes(&mut salt).ok()?;
        let iters = 60000usize;
        let out = pbkdf2(plaintext, &salt, iters, 32)?;
        return Some(format!("pbkdf2:{iters}:{}:{}", hex(&salt), hex(&out)));
    }
    let md = digest_for(algo)?;
    let d = hash(md, plaintext.as_bytes()).ok()?;
    Some(format!("{}:{}", algo.to_ascii_lowercase(), hex(&d)))
}

/// Whether *verifying* this stored credential is a deliberately-slow KDF (bcrypt or
/// pbkdf2) that should run off the core thread rather than inline.
pub fn is_slow(stored: &str) -> bool {
    stored.starts_with("$2") || stored.starts_with("pbkdf2:")
}

/// Whether *producing* a hash with this algorithm name is a slow KDF (for MKPASSWD).
pub fn is_slow_algo(algo: &str) -> bool {
    let a = algo.to_ascii_lowercase();
    a == "bcrypt" || a.starts_with("bcrypt:") || a == "pbkdf2"
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(MkPasswd)]
}

/// MKPASSWD — `MKPASSWD <algo> <password>`. Oper-only; returns a config-ready
/// hashed credential. Algorithms: md5, sha1, sha256, sha512, pbkdf2.
struct MkPasswd;
impl Command for MkPasswd {
    fn name(&self) -> &'static str {
        "MKPASSWD"
    }
    fn min_params(&self) -> usize {
        2
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.is_oper(uid) {
            s.numeric(
                uid,
                ERR_NOPRIVILEGES,
                ":Permission Denied- You're not an IRC operator",
            );
            return CmdResult::Fail;
        }
        let (algo, pass) = (params[0].clone(), params[1].clone());
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        // a KDF (bcrypt / pbkdf2) is slow — hash it off the core thread (result comes
        // back as MkpasswdResult) so an oper's MKPASSWD can't freeze the whole server.
        if is_slow_algo(&algo) {
            let started = s.spawn_crypto(move || {
                let hash = make(&algo, &pass);
                crate::ircd::Event::MkpasswdResult { uid, algo, hash }
            });
            if !started {
                s.send(
                    uid,
                    format!(":{} NOTICE {nick} :Busy hashing, try again", s.name),
                );
            }
            return CmdResult::Ok;
        }
        match make(&algo, &pass) {
            Some(hashed) => {
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :{algo} hashed password: {hashed}",
                        s.name
                    ),
                );
                CmdResult::Ok
            }
            None => {
                s.send(
                    uid,
                    format!(
                        ":{} NOTICE {nick} :Unknown hash '{algo}' (try md5, sha1, sha256, sha512, pbkdf2, bcrypt)",
                        s.name
                    ),
                );
                CmdResult::Fail
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_roundtrips() {
        assert!(verify("hunter2", "hunter2"));
        assert!(!verify("hunter2", "wrong"));
    }

    #[test]
    fn simple_digests_roundtrip() {
        for algo in ["md5", "sha1", "sha256", "sha512"] {
            let stored = make(algo, "s3cret").unwrap();
            assert!(verify(&stored, "s3cret"), "{algo} should verify");
            assert!(!verify(&stored, "nope"), "{algo} should reject wrong");
        }
    }

    #[test]
    fn pbkdf2_roundtrips() {
        let stored = make("pbkdf2", "correct horse").unwrap();
        assert!(stored.starts_with("pbkdf2:60000:"));
        assert!(verify(&stored, "correct horse"));
        assert!(!verify(&stored, "battery staple"));
    }

    #[test]
    fn known_sha256_vector() {
        // sha256("abc")
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify(&format!("sha256:{h}"), "abc"));
    }
}
