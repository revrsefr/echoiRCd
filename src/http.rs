//! Minimal blocking HTTP/HTTPS client — `std::net::TcpStream` + openssl for TLS.
//! No new crate, no `unsafe`. Modules that talk to external APIs (account
//! registration, captcha verification, …) use this from a **worker thread** and
//! deliver the result back to the core as an [`crate::ircd::Event`], exactly like
//! the DNS/DNSBL lookups — so a slow or hung endpoint never blocks the main loop.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

/// POST `body` to `url` with `content_type` and extra `headers`. Blocking.
/// Returns `(status_code, response_body)` or an error string.
pub fn post(
    url: &str,
    content_type: &str,
    body: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<(u16, String), String> {
    let (scheme, rest) = url.split_once("://").ok_or("bad url (no scheme)")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let https = scheme.eq_ignore_ascii_case("https");
    let (host, port): (&str, u16) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(if https { 443 } else { 80 })),
        None => (hostport, if https { 443 } else { 80 }),
    };

    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: echoIRCd\r\nAccept: */*\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);

    let stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let raw = if https {
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
        b.set_verify(SslVerifyMode::NONE); // APIs are usually behind a trusted reverse proxy
        let connector = b.build();
        let mut tls = connector.connect(host, stream).map_err(|e| e.to_string())?;
        tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf); // close => EOF (Connection: close)
        buf
    } else {
        let mut s = stream;
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        buf
    };

    let resp = String::from_utf8_lossy(&raw).into_owned();
    let (head, rbody) = resp.split_once("\r\n\r\n").unwrap_or((resp.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    let chunked = head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");
    let out = if chunked {
        dechunk(rbody)
    } else {
        rbody.to_string()
    };
    Ok((status, out))
}

/// Decode an HTTP/1.1 chunked body (best effort).
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        if size == 0 || after.len() < size {
            out.push_str(&after[..after.len().min(size)]);
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or(&after[size..]);
    }
    out
}

/// application/x-www-form-urlencoded escape of a single value.
pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Pull a top-level `"key": value` out of a flat JSON object — dependency-free,
/// good enough for the small, known API responses these modules parse.
pub fn json_str(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let start = body.find(&pat)? + pat.len();
    let after_colon = body[start..].find(':')? + start + 1;
    let rest = body[after_colon..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = r.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => return Some(out),
                _ => out.push(ch),
            }
        }
        None
    } else {
        let end = rest.find([',', '}', '\n']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}
