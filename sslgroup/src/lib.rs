//! Reads the negotiated TLS key-exchange group name (e.g. `X25519MLKEM768`) via
//! OpenSSL's `SSL_get0_group_name`, which the safe `openssl` crate does not expose.
//! Isolated in its own crate so the daemon can stay `#![forbid(unsafe_code)]` — the
//! single `unsafe` FFI call lives here, exactly like the FFI inside `openssl`/`ring`.

use foreign_types::ForeignTypeRef;
use openssl::ssl::SslRef;
use std::ffi::CStr;

/// The TLS key-exchange group name for an accepted session (OpenSSL 3.2+), or
/// `None` if unavailable (before the handshake, or an OpenSSL without the API).
pub fn group_name(ssl: &SslRef) -> Option<String> {
    // SAFETY: `ssl` is a live, accepted `SSL`. `SSL_get0_group_name` returns a
    // NUL-terminated string OpenSSL owns for the session's lifetime; we copy it out
    // here, so the borrow does not escape.
    unsafe {
        let name = openssl_sys::SSL_get0_group_name(ssl.as_ptr());
        if name.is_null() {
            return None;
        }
        CStr::from_ptr(name).to_str().ok().map(String::from)
    }
}
