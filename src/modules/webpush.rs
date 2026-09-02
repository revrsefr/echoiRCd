//! draft/webpush — Web Push notifications (RFC 8291 payload encryption + RFC 8292
//! VAPID) so a client (e.g. Orbit) is notified of a PM / highlight while its tab is
//! backgrounded (away) or gone.
//!
//! Wire contract (matches the IRCv3 draft + Orbit's client):
//!   * ISUPPORT `VAPID=<base64url P-256 public key>` and the `draft/webpush` cap tell
//!     the client this server's application-server key.
//!   * `WEBPUSH REGISTER <endpoint> p256dh=<b64url>;auth=<b64url>` subscribes;
//!     `WEBPUSH UNREGISTER <endpoint>` removes it.
//!   * On a PM or nick-highlight to an away subscriber, the server encrypts a small
//!     JSON copy (RFC 8291 `aes128gcm`) and POSTs it — off the core thread — to the
//!     push endpoint with a VAPID `Authorization` header.
//!
//! All crypto is OpenSSL (already a dependency); no `unsafe`, no extra crate. Subscriptions
//! are keyed by account (persisted, like markread) so they survive a reconnect. Off when
//! `webpush = no`; the VAPID keypair is generated + persisted on first start.

use crate::command::{CmdResult, Command};
use crate::map::HashMap;
use crate::module::{ModResult, Module};
use crate::modules::jwt::b64url;
use crate::server::{now, Server};
use crate::Uid;

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{encrypt_aead, Cipher};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ─────────────────────────── VAPID key + subscriptions ───────────────────────────

/// The persistent server VAPID keypair and its advertised public key.
pub struct Vapid {
    pem: Vec<u8>,        // the P-256 private key, PEM (for signing the VAPID JWT)
    pub pub_b64: String, // uncompressed public point, base64url — the VAPID public key
}

/// One push subscription: the endpoint URL and the client's key material.
#[derive(Clone)]
pub struct Sub {
    pub endpoint: String,
    pub p256dh: Vec<u8>, // client public key, 65-byte uncompressed point
    pub auth: Vec<u8>,   // 16-byte auth secret
}

/// identity (account, else nick) -> its subscriptions.
#[derive(Default)]
pub struct Subs(pub HashMap<String, Vec<Sub>>);

fn group() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 available")
}

fn vapid_path(s: &Server) -> String {
    match s.conf("webpush_vapid_file") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => format!("{}.webpush-vapid", s.conf_path),
    }
}

fn subs_path(s: &Server) -> String {
    match s.conf("webpush_database") {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => format!("{}.webpush", s.conf_path),
    }
}

/// The push identity for `uid`: the account when logged in (so it survives a reconnect),
/// else the current nick lowercased (session-scoped).
fn identity(s: &Server, uid: Uid) -> String {
    s.users
        .get(&uid)
        .map(|u| {
            u.account
                .clone()
                .map(|a| a.to_ascii_lowercase())
                .unwrap_or_else(|| u.nick.to_ascii_lowercase())
        })
        .unwrap_or_default()
}

/// Load (or first-time generate + persist) the VAPID keypair, and restore stored
/// subscriptions. Called once from `Ircd::new`.
pub fn load(s: &mut Server) {
    let g = group();
    let path = vapid_path(s);
    let ec = std::fs::read(&path)
        .ok()
        .and_then(|pem| EcKey::private_key_from_pem(&pem).ok())
        .unwrap_or_else(|| {
            let k = EcKey::generate(&g).expect("EC keygen");
            if let Ok(pem) = k.private_key_to_pem() {
                let _ = std::fs::write(&path, &pem);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
            }
            k
        });
    let mut ctx = BigNumContext::new().expect("bn ctx");
    let pubpt = ec
        .public_key()
        .to_bytes(&g, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .expect("pub point");
    let pem = ec.private_key_to_pem().unwrap_or_default();
    let vapid = Vapid {
        pem,
        pub_b64: b64url(&pubpt),
    };
    let _ = s.ext.get_or_insert_with::<Vapid>(move || vapid);

    // subscriptions
    if let Some(text) = crate::database::persist_load(s, "webpush_subs", &subs_path(s)) {
        let store = s.ext.get_or_insert_with::<Subs>(Subs::default);
        for line in text.lines() {
            let f: Vec<&str> = line.split(' ').collect();
            if f.len() != 4 || line.starts_with('#') {
                continue;
            }
            if let (Some(p), Some(a)) = (
                crate::modules::jwt::unb64url(f[2]),
                crate::modules::jwt::unb64url(f[3]),
            ) {
                store.0.entry(f[0].to_string()).or_default().push(Sub {
                    endpoint: f[1].to_string(),
                    p256dh: p,
                    auth: a,
                });
            }
        }
    }
}

/// Persist the subscription store (durable across restart). Off-core via `disk_write`.
fn save(s: &Server) {
    let Some(store) = s.ext.get::<Subs>() else {
        return;
    };
    let mut out = String::from("# echoircd web-push subscriptions — auto-generated\n");
    let mut ids: Vec<&String> = store.0.keys().collect();
    ids.sort();
    for id in ids {
        for sub in &store.0[id] {
            out.push_str(&format!(
                "{id} {} {} {}\n",
                sub.endpoint,
                b64url(&sub.p256dh),
                b64url(&sub.auth)
            ));
        }
    }
    crate::database::persist_save(s, "webpush_subs", &subs_path(s), out);
}

/// The ISUPPORT `VAPID=<key>` token, advertised in the welcome burst. `None` when
/// web-push is disabled or the key failed to load.
pub fn isupport(s: &Server) -> Option<String> {
    if !s.conf_bool("webpush", true) {
        return None;
    }
    s.ext.get::<Vapid>().map(|v| format!("VAPID={}", v.pub_b64))
}

// ─────────────────────────────── crypto (RFC 8291/8292) ──────────────────────────

fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let k = PKey::hmac(key).ok()?;
    let mut si = Signer::new(MessageDigest::sha256(), &k).ok()?;
    si.update(data).ok()?;
    si.sign_to_vec().ok()
}

/// HKDF-SHA256 (extract + expand) → `len` bytes.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let prk = hmac_sha256(salt, ikm)?; // Extract
    let mut okm = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut ctr: u8 = 1;
    while okm.len() < len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(ctr);
        t = hmac_sha256(&prk, &input)?;
        okm.extend_from_slice(&t);
        ctr = ctr.checked_add(1)?;
    }
    okm.truncate(len);
    Some(okm)
}

/// Encrypt `payload` for a subscription's `ua_public` (65-byte point) + `auth` secret,
/// producing an RFC 8188 `aes128gcm` body (RFC 8291). Fresh ephemeral key per call.
fn encrypt_payload(payload: &[u8], ua_public: &[u8], auth: &[u8]) -> Option<Vec<u8>> {
    let g = group();
    let mut ctx = BigNumContext::new().ok()?;
    let ua_point = EcPoint::from_bytes(&g, ua_public, &mut ctx).ok()?;
    let ua_pkey = PKey::from_ec_key(EcKey::from_public_key(&g, &ua_point).ok()?).ok()?;
    let as_ec = EcKey::generate(&g).ok()?;
    let as_public = as_ec
        .public_key()
        .to_bytes(&g, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .ok()?;
    let as_pkey = PKey::from_ec_key(as_ec).ok()?;
    let mut deriver = Deriver::new(&as_pkey).ok()?;
    deriver.set_peer(&ua_pkey).ok()?;
    let ecdh = deriver.derive_to_vec().ok()?;

    let mut key_info = b"WebPush: info\x00".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(&as_public);
    let ikm = hkdf(auth, &ecdh, &key_info, 32)?;

    let mut salt = [0u8; 16];
    openssl::rand::rand_bytes(&mut salt).ok()?;
    let cek = hkdf(&salt, &ikm, b"Content-Encoding: aes128gcm\x00", 16)?;
    let nonce = hkdf(&salt, &ikm, b"Content-Encoding: nonce\x00", 12)?;

    let mut record = payload.to_vec();
    record.push(0x02); // single-record padding delimiter
    let mut tag = [0u8; 16];
    let ct = encrypt_aead(
        Cipher::aes_128_gcm(),
        &cek,
        Some(&nonce),
        &[],
        &record,
        &mut tag,
    )
    .ok()?;

    // header: salt(16) | rs(4, BE) | idlen(1) | keyid(as_public) ; then ciphertext|tag
    let mut body = Vec::with_capacity(21 + as_public.len() + ct.len() + 16);
    body.extend_from_slice(&salt);
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&ct);
    body.extend_from_slice(&tag);
    Some(body)
}

/// The `Authorization: vapid t=<jwt>,k=<key>` header for a push to `aud` (the endpoint
/// origin), signing an ES256 JWT with the VAPID private key.
fn vapid_auth(vapid: &Vapid, aud: &str, sub: &str) -> Option<(String, String)> {
    let ec = EcKey::private_key_from_pem(&vapid.pem).ok()?;
    let pkey = PKey::from_ec_key(ec).ok()?;
    let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
    let exp = now() as i64 + 12 * 3600;
    let claims = format!(r#"{{"aud":"{aud}","exp":{exp},"sub":"{sub}"}}"#);
    let signing_input = format!("{header}.{}", b64url(claims.as_bytes()));
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
    signer.update(signing_input.as_bytes()).ok()?;
    let der = signer.sign_to_vec().ok()?;
    let sig = EcdsaSig::from_der(&der).ok()?;
    let mut raw = sig.r().to_vec_padded(32).ok()?;
    raw.extend_from_slice(&sig.s().to_vec_padded(32).ok()?);
    let jwt = format!("{signing_input}.{}", b64url(&raw));
    Some((
        "Authorization".to_string(),
        format!("vapid t={jwt},k={}", vapid.pub_b64),
    ))
}

/// scheme://host of a URL (the VAPID audience), dropping the path.
fn origin(url: &str) -> String {
    match url.split_once("://") {
        Some((sch, rest)) => format!("{sch}://{}", rest.split('/').next().unwrap_or(rest)),
        None => url.to_string(),
    }
}

/// POST an encrypted push off the core thread (bounded concurrency; fire-and-forget).
fn deliver(sub: Sub, body: Vec<u8>, auth: (String, String), ttl: u64, verify: bool) {
    static ACTIVE: AtomicUsize = AtomicUsize::new(0);
    if ACTIVE.fetch_add(1, Ordering::Relaxed) >= 64 {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    std::thread::spawn(move || {
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                ACTIVE.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let _g = Guard;
        let headers = vec![
            auth,
            ("Content-Encoding".to_string(), "aes128gcm".to_string()),
            ("TTL".to_string(), ttl.to_string()),
        ];
        let _ = crate::http::post_bytes(
            &sub.endpoint,
            "application/octet-stream",
            &body,
            &headers,
            Duration::from_secs(15),
            verify,
        );
    });
}

/// JSON-escape a string into `out`.
fn esc(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

fn payload_json(from: &str, target: &str, text: &str) -> String {
    let mut j = String::from("{\"from\":\"");
    esc(&mut j, from);
    j.push_str("\",\"target\":\"");
    esc(&mut j, target);
    j.push_str("\",\"body\":\"");
    esc(&mut j, text);
    j.push_str("\"}");
    j
}

/// Whether `nick` appears as a whole word in `text` (a highlight).
fn mentions(text: &str, nick: &str) -> bool {
    let n = nick.to_ascii_lowercase();
    text.to_ascii_lowercase()
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ',' | ':' | ';' | '.' | '!' | '?' | '<' | '>' | '(' | ')' | '"'
                )
        })
        .any(|w| w == n)
}

// ─────────────────────────────── module + command ───────────────────────────────

pub struct WebPush;

impl Module for WebPush {
    fn name(&self) -> &'static str {
        "webpush"
    }

    fn on_pre_message(&mut self, s: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
        // Fire pushes as a side effect; never affect delivery of the message itself.
        maybe_push(s, uid, target, text);
        ModResult::Passthru
    }
}

/// Encrypt + queue a push to every away subscriber the message would notify.
fn maybe_push(s: &Server, from_uid: Uid, target: &str, text: &str) {
    if !s.conf_bool("webpush", true) || s.ext.get::<Vapid>().is_none() {
        return;
    }
    let sender = s
        .users
        .get(&from_uid)
        .map(|u| u.nick.clone())
        .unwrap_or_default();
    // who to notify: a PM's target, or channel members whose nick is highlighted
    let mut recips: Vec<Uid> = Vec::new();
    if target.starts_with('#') {
        if let Some(ch) = s.channels.get(&target.to_ascii_lowercase()) {
            for &m in ch.members.keys() {
                if m != from_uid {
                    if let Some(u) = s.users.get(&m) {
                        if mentions(text, &u.nick) {
                            recips.push(m);
                        }
                    }
                }
            }
        }
    } else if let Some(tu) = s.find_nick(target) {
        if tu != from_uid {
            recips.push(tu);
        }
    }
    if recips.is_empty() {
        return;
    }
    let away_only = s.conf_bool("webpush_away_only", true);
    let ttl = s.conf_num("webpush_ttl", 259200u64);
    let contact = s
        .conf("webpush_sub")
        .map(|c| c.to_string())
        .unwrap_or_else(|| format!("mailto:webpush@{}", s.name));
    let verify = s.conf_bool("http_tls_verify", true);
    let Some(vapid) = s.ext.get::<Vapid>() else {
        return;
    };
    let Some(store) = s.ext.get::<Subs>() else {
        return;
    };
    for r in recips {
        let Some(u) = s.users.get(&r) else { continue };
        if away_only && u.flags.away.is_none() {
            continue; // client marks itself away when backgrounded
        }
        let Some(subs) = store.0.get(&identity(s, r)) else {
            continue;
        };
        let payload = payload_json(&sender, target, text);
        for sub in subs {
            if let Some(body) = encrypt_payload(payload.as_bytes(), &sub.p256dh, &sub.auth) {
                if let Some(auth) = vapid_auth(vapid, &origin(&sub.endpoint), &contact) {
                    deliver(sub.clone(), body, auth, ttl, verify);
                }
            }
        }
    }
}

pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(WebPushCmd)]
}

struct WebPushCmd;
impl Command for WebPushCmd {
    fn name(&self) -> &'static str {
        "WEBPUSH"
    }
    fn min_params(&self) -> usize {
        1
    }
    fn handle(&self, s: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        if !s.conf_bool("webpush", true) || s.ext.get::<Vapid>().is_none() {
            s.fail(
                uid,
                "WEBPUSH",
                "TEMPORARILY_UNAVAILABLE",
                "Web push is not available",
            );
            return CmdResult::Fail;
        }
        match params[0].to_ascii_uppercase().as_str() {
            "REGISTER" => {
                if params.len() < 3 {
                    s.fail(
                        uid,
                        "WEBPUSH",
                        "NEED_MORE_PARAMS",
                        "WEBPUSH REGISTER <endpoint> <keys>",
                    );
                    return CmdResult::Fail;
                }
                let endpoint = params[1].clone();
                if !endpoint.starts_with("https://") {
                    s.fail(uid, "WEBPUSH", "INVALID_PARAMS", "endpoint must be https");
                    return CmdResult::Fail;
                }
                let (mut p256dh, mut auth) = (None, None);
                for kv in params[2].split(';') {
                    match kv.split_once('=') {
                        Some(("p256dh", v)) => p256dh = crate::modules::jwt::unb64url(v),
                        Some(("auth", v)) => auth = crate::modules::jwt::unb64url(v),
                        _ => {}
                    }
                }
                let (Some(p256dh), Some(auth)) = (p256dh, auth) else {
                    s.fail(
                        uid,
                        "WEBPUSH",
                        "INVALID_PARAMS",
                        "keys must be p256dh=<b64url>;auth=<b64url>",
                    );
                    return CmdResult::Fail;
                };
                if p256dh.len() != 65 || auth.len() != 16 {
                    s.fail(uid, "WEBPUSH", "INVALID_PARAMS", "bad key length");
                    return CmdResult::Fail;
                }
                let id = identity(s, uid);
                {
                    let store = s.ext.get_or_insert_with::<Subs>(Subs::default);
                    let list = store.0.entry(id).or_default();
                    list.retain(|x| x.endpoint != endpoint); // replace an existing sub
                    list.push(Sub {
                        endpoint: endpoint.clone(),
                        p256dh,
                        auth,
                    });
                }
                save(s);
                s.send(uid, format!(":{} WEBPUSH REGISTER {endpoint}", s.name));
                CmdResult::Ok
            }
            "UNREGISTER" => {
                let Some(endpoint) = params.get(1) else {
                    s.fail(
                        uid,
                        "WEBPUSH",
                        "NEED_MORE_PARAMS",
                        "WEBPUSH UNREGISTER <endpoint>",
                    );
                    return CmdResult::Fail;
                };
                let id = identity(s, uid);
                if let Some(store) = s.ext.get_mut::<Subs>() {
                    if let Some(list) = store.0.get_mut(&id) {
                        list.retain(|x| &x.endpoint != endpoint);
                        if list.is_empty() {
                            store.0.remove(&id);
                        }
                    }
                }
                save(s);
                s.send(uid, format!(":{} WEBPUSH UNREGISTER {endpoint}", s.name));
                CmdResult::Ok
            }
            other => {
                s.fail(
                    uid,
                    "WEBPUSH",
                    "INVALID_PARAMS",
                    &format!("unknown WEBPUSH subcommand {other}"),
                );
                CmdResult::Fail
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Test Case 1 — validates HKDF-SHA256 (the trickiest primitive).
    #[test]
    fn hkdf_matches_rfc5869() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf(&salt, &ikm, &info, 42).unwrap();
        let want =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let got: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, want);
    }

    // Encrypt for a fresh UA keypair, then decrypt as the UA would (RFC 8291 reverse):
    // recovering the plaintext proves ECDH + HKDF + AES-GCM + the aes128gcm framing.
    #[test]
    fn encrypt_roundtrips_like_a_browser() {
        let g = group();
        let ua = EcKey::generate(&g).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let ua_pub = ua
            .public_key()
            .to_bytes(&g, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let mut auth = [0u8; 16];
        openssl::rand::rand_bytes(&mut auth).unwrap();
        let plain = b"hi \xf0\x9f\x8d\x89 push";
        let body = encrypt_payload(plain, &ua_pub, &auth).unwrap();

        // --- decrypt (what the browser/service-worker does) ---
        let salt = &body[0..16];
        let idlen = body[20] as usize;
        let as_public = &body[21..21 + idlen];
        let ciphertext = &body[21 + idlen..];
        let as_pkey = PKey::from_ec_key(
            EcKey::from_public_key(&g, &EcPoint::from_bytes(&g, as_public, &mut ctx).unwrap())
                .unwrap(),
        )
        .unwrap();
        let ua_pkey = PKey::from_ec_key(ua.clone()).unwrap();
        let mut d = Deriver::new(&ua_pkey).unwrap();
        d.set_peer(&as_pkey).unwrap();
        let ecdh = d.derive_to_vec().unwrap();
        let mut key_info = b"WebPush: info\x00".to_vec();
        key_info.extend_from_slice(&ua_pub);
        key_info.extend_from_slice(as_public);
        let ikm = hkdf(&auth, &ecdh, &key_info, 32).unwrap();
        let cek = hkdf(salt, &ikm, b"Content-Encoding: aes128gcm\x00", 16).unwrap();
        let nonce = hkdf(salt, &ikm, b"Content-Encoding: nonce\x00", 12).unwrap();
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let rec =
            openssl::symm::decrypt_aead(Cipher::aes_128_gcm(), &cek, Some(&nonce), &[], ct, tag)
                .unwrap();
        let end = rec.iter().rposition(|&b| b == 0x02).unwrap();
        assert_eq!(&rec[..end], plain);
    }

    #[test]
    fn mentions_word_boundary() {
        assert!(mentions("hey bob, look", "bob"));
        assert!(mentions("BOB!", "bob"));
        assert!(!mentions("bobby is here", "bob"));
    }
}
