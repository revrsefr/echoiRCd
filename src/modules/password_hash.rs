//! password_hash — hashed `<oper>` passwords plus a `/MKPASSWD` helper to make
//! them. This is echoIRCd's answer to InspIRCd's hash-provider family (md5, sha1,
//! sha2, pbkdf2): one module, backed entirely by OpenSSL (already a dependency),
//! that both verifies a stored hash against a supplied password and generates new
//! hashes for the config.
//!
//! A stored password is either plaintext (no recognised prefix — backward
//! compatible) or `"<algo>:<hex>"`:
//!   * `md5:` `sha1:` `sha256:` `sha512:` — a plain hex digest of the password
//!   * `pbkdf2:<iters>:<salthex>:<hashhex>` — PBKDF2-HMAC-SHA256, salted
//!
//! Comparisons are constant-time (`openssl::memcmp`). Everything is self-contained
//! here; the OPER handler just calls [`verify`].

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
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

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
    // pbkdf2:<iters>:<salthex>:<hashhex>
    if let Some(rest) = stored.strip_prefix("pbkdf2:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() == 3 {
            if let (Ok(iters), Some(salt), Some(want)) =
                (parts[0].parse::<usize>(), unhex(parts[1]), unhex(parts[2]))
            {
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
        let (algo, pass) = (&params[0], &params[1]);
        let nick = s
            .users
            .get(&uid)
            .map(|u| u.nick.clone())
            .unwrap_or_default();
        match make(algo, pass) {
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
                        ":{} NOTICE {nick} :Unknown hash '{algo}' (try md5, sha1, sha256, sha512, pbkdf2)",
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
