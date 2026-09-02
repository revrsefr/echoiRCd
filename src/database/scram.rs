//! PostgreSQL authentication crypto: SCRAM-SHA-256 (RFC 5802 / RFC 7677, the modern
//! PostgreSQL default) and the legacy MD5 scheme — all built on the openssl
//! primitives the daemon already links, so no new deps and no `unsafe`.

use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;

fn sha256(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::sha256(), data)
        .map(|d| d.to_vec())
        .unwrap_or_default()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // openssl needs a non-empty HMAC key; SCRAM keys never are, but guard anyway.
    let Ok(pkey) = PKey::hmac(if key.is_empty() { b"\0" } else { key }) else {
        return Vec::new();
    };
    let Ok(mut signer) = Signer::new(MessageDigest::sha256(), &pkey) else {
        return Vec::new();
    };
    if signer.update(data).is_err() {
        return Vec::new();
    }
    signer.sign_to_vec().unwrap_or_default()
}

fn pbkdf2(password: &[u8], salt: &[u8], iterations: usize) -> Vec<u8> {
    let mut out = vec![0u8; 32]; // SHA-256 → 32-byte derived key
    if openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        iterations,
        MessageDigest::sha256(),
        &mut out,
    )
    .is_err()
    {
        return Vec::new();
    }
    out
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn b64(data: &[u8]) -> String {
    openssl::base64::encode_block(data)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    openssl::base64::decode_block(s).ok()
}

/// A fresh, printable client nonce (base64 of random bytes — never contains a comma,
/// so it is a valid SCRAM nonce).
fn gen_nonce() -> String {
    let mut buf = [0u8; 18];
    let _ = openssl::rand::rand_bytes(&mut buf);
    b64(&buf)
}

/// Drives the client side of one SCRAM-SHA-256 exchange. Create it, send
/// [`client_first`], feed the server-first to [`client_final`], then verify the
/// server-final with [`verify`].
pub struct Scram {
    client_nonce: String,
    client_first_bare: String,
    // filled once the server-first message is processed
    salted_password: Vec<u8>,
    auth_message: String,
}

impl Scram {
    pub fn new() -> Scram {
        // Empty SCRAM username: PostgreSQL takes the login name from the startup
        // packet and ignores the SCRAM `n=` field.
        Scram::build("", gen_nonce())
    }

    fn build(username: &str, client_nonce: String) -> Scram {
        // SCRAM username escaping (RFC 5802): `=`→`=3D`, `,`→`=2C`. Empty ⇒ no-op.
        let esc = username.replace('=', "=3D").replace(',', "=2C");
        let client_first_bare = format!("n={esc},r={client_nonce}");
        Scram {
            client_nonce,
            client_first_bare,
            salted_password: Vec::new(),
            auth_message: String::new(),
        }
    }

    /// Deterministic constructor for tests (fixed username + client nonce).
    #[cfg(test)]
    fn with_creds(username: &str, client_nonce: &str) -> Scram {
        Scram::build(username, client_nonce.to_string())
    }

    /// The `client-first-message` (with the `n,,` gs2-header — no channel binding).
    pub fn client_first(&self) -> String {
        format!("n,,{}", self.client_first_bare)
    }

    /// Process the server-first message and produce the `client-final-message`.
    /// Errors on a malformed message or a server nonce that doesn't extend ours.
    pub fn client_final(&mut self, password: &str, server_first: &str) -> Result<String, String> {
        let (mut rnonce, mut salt_b64, mut iter_s) = (None, None, None);
        for field in server_first.split(',') {
            match field.split_once('=') {
                Some(("r", v)) => rnonce = Some(v),
                Some(("s", v)) => salt_b64 = Some(v),
                Some(("i", v)) => iter_s = Some(v),
                _ => {}
            }
        }
        let rnonce = rnonce.ok_or("scram: server-first missing r=")?;
        let salt = salt_b64
            .and_then(unb64)
            .ok_or("scram: server-first bad salt")?;
        let iterations: usize = iter_s
            .and_then(|s| s.parse().ok())
            .ok_or("scram: server-first bad iteration count")?;
        if !rnonce.starts_with(&self.client_nonce) || rnonce == self.client_nonce {
            return Err("scram: server nonce does not extend the client nonce".into());
        }

        self.salted_password = pbkdf2(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&self.salted_password, b"Client Key");
        let stored_key = sha256(&client_key);

        // channel-binding data `c=biws` == base64("n,,")
        let client_final_no_proof = format!("c=biws,r={rnonce}");
        self.auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_no_proof
        );
        let client_sig = hmac_sha256(&stored_key, self.auth_message.as_bytes());
        let client_proof = xor(&client_key, &client_sig);
        Ok(format!("{client_final_no_proof},p={}", b64(&client_proof)))
    }

    /// Verify the server-final message (`v=<ServerSignature>`) proves the server
    /// also knew the password — completes mutual authentication.
    pub fn verify(&self, server_final: &str) -> Result<(), String> {
        let v = server_final
            .split(',')
            .find_map(|f| f.strip_prefix("v="))
            .ok_or("scram: server-final missing v=")?;
        let server_key = hmac_sha256(&self.salted_password, b"Server Key");
        let server_sig = hmac_sha256(&server_key, self.auth_message.as_bytes());
        if unb64(v).as_deref() == Some(server_sig.as_slice()) {
            Ok(())
        } else {
            Err("scram: server signature mismatch (bad password or MITM)".into())
        }
    }
}

impl Default for Scram {
    fn default() -> Self {
        Scram::new()
    }
}

/// The legacy `AuthenticationMD5Password` response body:
/// `"md5" + md5_hex( md5_hex(password + user) + salt )`.
pub fn md5_password(user: &str, password: &str, salt: &[u8; 4]) -> String {
    let hex = |b: &[u8]| {
        hash(MessageDigest::md5(), b)
            .map(|d| d.iter().map(|x| format!("{x:02x}")).collect::<String>())
            .unwrap_or_default()
    };
    let inner = hex(&[password.as_bytes(), user.as_bytes()].concat());
    let outer = hex(&[inner.as_bytes(), salt].concat());
    format!("md5{outer}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 §3 worked example (user "user", password "pencil").
    #[test]
    fn scram_sha256_rfc7677_vector() {
        let mut s = Scram::with_creds("user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(s.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let final_msg = s.client_final("pencil", server_first).unwrap();
        assert_eq!(
            final_msg,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        s.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        // a tampered server signature is rejected
        assert!(s
            .verify("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .is_err());
    }

    #[test]
    fn scram_rejects_forged_nonce() {
        let mut s = Scram::with_creds("", "clientNONCE123");
        // server nonce must start with the client nonce
        assert!(s
            .client_final("pw", "r=WRONG,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
            .is_err());
    }

    #[test]
    fn md5_password_matches_known_shape() {
        // "md5" + 32 hex chars
        let out = md5_password("bob", "secret", &[1, 2, 3, 4]);
        assert!(out.starts_with("md5") && out.len() == 35);
        assert!(out[3..].bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
