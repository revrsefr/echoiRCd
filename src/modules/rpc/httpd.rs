//! The RPC HTTP server: a blocking listener thread that accepts a connection,
//! reads one HTTP request, authenticates it, and forwards the JSON-RPC body to the
//! core as `Event::RpcRequest` — then writes back whatever the core replies. Low
//! volume (admin tooling), so thread-per-connection is fine. Native `TcpStream`
//! only; no `unsafe`, no new crate.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use crate::ircd::Event;

const MAX_REQUEST: usize = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const CORE_TIMEOUT: Duration = Duration::from_secs(15);

/// Accept loop. Never returns while the listener is alive.
pub fn serve(listener: TcpListener, tx: Sender<Event>, user: String, token: String) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let (tx, user, token) = (tx.clone(), user.clone(), token.clone());
        std::thread::spawn(move || {
            let _ = handle(stream, &tx, &user, &token);
        });
    }
}

/// Constant-time-ish equality (length-guarded so OpenSSL's memcmp is safe).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a, b)
}

/// Verify the `Authorization` header carries the right token, via HTTP Basic
/// (`base64(user:token)`) or Bearer (`token`).
fn auth_ok(header: Option<&str>, user: &str, token: &str) -> bool {
    let Some(h) = header else { return false };
    if let Some(b64) = h
        .strip_prefix("Basic ")
        .or_else(|| h.strip_prefix("basic "))
    {
        let Ok(raw) = openssl::base64::decode_block(b64.trim()) else {
            return false;
        };
        let Ok(text) = String::from_utf8(raw) else {
            return false;
        };
        let Some((u, t)) = text.split_once(':') else {
            return false;
        };
        return ct_eq(u.as_bytes(), user.as_bytes()) && ct_eq(t.as_bytes(), token.as_bytes());
    }
    if let Some(bearer) = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))
    {
        return ct_eq(bearer.trim().as_bytes(), token.as_bytes());
    }
    false
}

fn handle(
    mut stream: TcpStream,
    tx: &Sender<Event>,
    user: &str,
    token: &str,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    // read until we have the full header block, then the declared body — whether
    // it's Content-Length-framed or Transfer-Encoding: chunked (like InspIRCd's
    // http_parser handles). Body starts 4 bytes past the header terminator.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut head_end = None;
    let mut framing = Framing::Length(0);
    loop {
        if head_end.is_none() {
            if let Some(pos) = find_headers_end(&buf) {
                head_end = Some(pos);
                framing = framing_of(&buf[..pos]);
            }
        }
        if let Some(he) = head_end {
            let body = &buf[(he + 4).min(buf.len())..];
            let done = match framing {
                Framing::Length(n) => body.len() >= n,
                Framing::Chunked => chunked_complete(body),
            };
            if done {
                break;
            }
        }
        if buf.len() > MAX_REQUEST {
            return respond(&mut stream, 413, "Payload Too Large", "{}");
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let Some(he) = head_end else {
        return respond(&mut stream, 400, "Bad Request", "{}");
    };
    let header_text = String::from_utf8_lossy(&buf[..he]).into_owned();
    let raw_body = &buf[(he + 4).min(buf.len())..];
    let body = match framing {
        Framing::Length(n) => {
            String::from_utf8_lossy(&raw_body[..n.min(raw_body.len())]).into_owned()
        }
        Framing::Chunked => crate::http::dechunk(&String::from_utf8_lossy(raw_body)),
    };

    // request line: only POST is accepted
    let first = header_text.lines().next().unwrap_or("");
    if !first
        .split_whitespace()
        .next()
        .is_some_and(|m| m.eq_ignore_ascii_case("POST"))
    {
        return respond(&mut stream, 405, "Method Not Allowed", "{}");
    }

    // authenticate
    let authz = header_line(&header_text, "authorization");
    if !auth_ok(authz.as_deref(), user, token) {
        return respond_with(
            &mut stream,
            401,
            "Unauthorized",
            "{\"error\":\"authentication required\"}",
            Some("WWW-Authenticate: Basic realm=\"echoircd-rpc\""),
        );
    }

    // parse the JSON-RPC request
    let method = super::json::get_str(&body, "method");
    let id = super::json::get_raw(&body, "id").unwrap_or_else(|| "null".to_string());
    let params = super::json::get_raw(&body, "params").unwrap_or_else(|| "{}".to_string());
    let Some(method) = method else {
        let env = super::envelope(
            "",
            &id,
            Err(super::RpcError {
                code: -32600,
                message: "Invalid Request: no method".into(),
            }),
        );
        return respond(&mut stream, 200, "OK", &env);
    };

    // hand off to the core and wait for its reply
    let (rtx, rrx) = channel::<String>();
    if tx
        .send(Event::RpcRequest {
            method: method.clone(),
            params,
            id: id.clone(),
            reply: rtx,
        })
        .is_err()
    {
        return respond(&mut stream, 503, "Service Unavailable", "{}");
    }
    match rrx.recv_timeout(CORE_TIMEOUT) {
        Ok(resp) => respond(&mut stream, 200, "OK", &resp),
        Err(_) => {
            let env = super::envelope(
                &method,
                &id,
                Err(super::RpcError::internal("core did not respond in time")),
            );
            respond(&mut stream, 504, "Gateway Timeout", &env)
        }
    }
}

/// Index of the `\r\n\r\n` that ends the header block.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// How the request body is framed.
enum Framing {
    Length(usize),
    Chunked,
}

/// Decide the body framing from the header block: `Transfer-Encoding: chunked`
/// wins over `Content-Length` (per RFC 7230); otherwise the declared length (0).
fn framing_of(head: &[u8]) -> Framing {
    let text = String::from_utf8_lossy(head);
    let chunked = header_line(&text, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        Framing::Chunked
    } else {
        let len = header_line(&text, "content-length")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        Framing::Length(len)
    }
}

/// Whether a chunked body is fully received: walk the chunk-size prefixes until a
/// terminating `0`-size chunk. Returns false if the buffer ends mid-chunk (read more).
fn chunked_complete(body: &[u8]) -> bool {
    let mut i = 0;
    loop {
        let Some(nl) = find_from(body, i, b"\r\n") else {
            return false; // size line not fully arrived yet
        };
        let size = std::str::from_utf8(&body[i..nl])
            .ok()
            .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok());
        let Some(size) = size else { return false };
        if size == 0 {
            return true; // terminating chunk seen
        }
        i = nl + 2 + size + 2; // skip CRLF + data + trailing CRLF
        if i > body.len() {
            return false;
        }
    }
}

/// Index of `needle` in `hay` at or after `from`.
fn find_from(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// The value of a header, matched case-insensitively.
fn header_line(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

fn respond(stream: &mut TcpStream, code: u16, text: &str, body: &str) -> std::io::Result<()> {
    respond_with(stream, code, text, body, None)
}

fn respond_with(
    stream: &mut TcpStream,
    code: u16,
    text: &str,
    body: &str,
    extra: Option<&str>,
) -> std::io::Result<()> {
    let extra = extra.map(|e| format!("{e}\r\n")).unwrap_or_default();
    let resp = format!(
        "HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}
