//! wsguard — flags WebSocket connections that don't look like they came from a real
//! browser, so terminal tools (websocat / wscat / curl) and simple bots poking the
//! ws:// or wss:// port stand out from genuine web clients.
//!
//! The idea: when a browser opens a WebSocket (`new WebSocket(...)` in JS) the browser
//! itself sends a rich, consistent set of request headers the page's script cannot
//! control or omit — `Origin`, a real `User-Agent`, `Sec-WebSocket-Extensions`
//! (permessage-deflate), `Accept-Encoding`, `Accept-Language`, `Sec-WebSocket-Version:
//! 13`. A command-line tool or a bare bot handshake carries almost none of these. We
//! score that gap against a browser profile and act on a threshold.
//!
//! Honest limit: a determined bot can copy a real browser handshake byte-for-byte, so
//! every header here is forgeable. This is not a proof of a browser — it catches the
//! lazy fakes (terminal tools, off-the-shelf ws libraries, naive flood scripts) cheaply
//! and raises the cost for the rest. Off by default; `report` (snotice only) is the safe
//! first setting.

use std::net::IpAddr;

use crate::config::Config;
use crate::server::Server;
use crate::xline::XKind;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Off,
    Report, // snotice only, let the client through
    Reject, // snotice + refuse the handshake
    Zline,  // snotice + z-line the IP (and refuse)
}

/// Resolved config, built once at startup and carried on the WS I/O threads (which
/// have no `&Server`). Every weight/threshold/list is a conf key.
#[derive(Clone)]
pub struct WsGuardCfg {
    pub mode: Mode,
    pub threshold: u32,
    w_no_ua: u32,
    w_nonbrowser_ua: u32,
    w_tool_ua: u32,
    w_no_origin: u32,
    w_no_extensions: u32,
    w_no_accept_encoding: u32,
    w_no_accept_language: u32,
    w_bad_version: u32,
    w_few_headers: u32,
    min_headers: usize,
    tools: Vec<String>,          // User-Agent substrings that mark a non-browser tool
    exempt_origins: Vec<String>, // Origin globs to skip scoring for (trusted clients)
}

fn first(cfg: &Config, k: &str) -> Option<String> {
    cfg.raw.get(k).and_then(|v| v.first()).cloned()
}
fn num(cfg: &Config, k: &str, d: u32) -> u32 {
    first(cfg, k).and_then(|s| s.parse().ok()).unwrap_or(d)
}

/// Read `wsguard*` config into a `WsGuardCfg`. Off unless `wsguard` is set.
pub fn read(cfg: &Config) -> WsGuardCfg {
    let mode = match first(cfg, "wsguard").as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("report") | Some("yes") | Some("on") => Mode::Report,
        Some("reject") => Mode::Reject,
        Some("zline") => Mode::Zline,
        _ => Mode::Off,
    };
    // accept either one space/comma-separated line or repeated `wsguard_tools` lines
    let tools: Vec<String> = match cfg.raw.get("wsguard_tools") {
        Some(v) => v
            .iter()
            .flat_map(|s| s.split([' ', ',', '\t']))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect(),
        None => [
            "websocat",
            "wscat",
            "curl",
            "python",
            "go-http-client",
            "okhttp",
            "libwebsockets",
            "websocket-client",
            "aiohttp",
            "httpx",
            "wget",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    };
    WsGuardCfg {
        mode,
        threshold: num(cfg, "wsguard_threshold", 5),
        w_no_ua: num(cfg, "wsguard_w_no_ua", 3),
        w_nonbrowser_ua: num(cfg, "wsguard_w_nonbrowser_ua", 2),
        w_tool_ua: num(cfg, "wsguard_w_tool_ua", 5),
        w_no_origin: num(cfg, "wsguard_w_no_origin", 1),
        w_no_extensions: num(cfg, "wsguard_w_no_extensions", 2),
        w_no_accept_encoding: num(cfg, "wsguard_w_no_accept_encoding", 1),
        w_no_accept_language: num(cfg, "wsguard_w_no_accept_language", 1),
        w_bad_version: num(cfg, "wsguard_w_bad_version", 3),
        w_few_headers: num(cfg, "wsguard_w_few_headers", 2),
        min_headers: num(cfg, "wsguard_min_headers", 6) as usize,
        tools,
        exempt_origins: cfg.raw.get("wsguard_exempt_origin").cloned().unwrap_or_default(),
    }
}

/// Case-insensitive header lookup from the raw HTTP request block.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// A short list of tokens that appear in every real browser's `User-Agent`.
const BROWSER_UA: [&str; 8] = [
    "mozilla",
    "applewebkit",
    "gecko",
    "chrome",
    "safari",
    "firefox",
    "edg",
    "opera",
];

/// Score a WebSocket handshake against a browser profile. Returns the reason string
/// when the score reaches the threshold (flagged), else `None`. Pure — no I/O.
pub fn assess(head: &str, cfg: &WsGuardCfg) -> Option<String> {
    if cfg.mode == Mode::Off {
        return None;
    }
    let origin = header(head, "origin");
    if let Some(o) = origin {
        if cfg
            .exempt_origins
            .iter()
            .any(|g| crate::channels::glob_match(g, o))
        {
            return None; // a trusted client origin — never scored
        }
    }
    let mut score = 0u32;
    let mut reasons: Vec<&str> = Vec::new();
    let mut add = |w: u32, r: &'static str| {
        if w > 0 {
            score += w;
            reasons.push(r);
        }
    };

    let ua = header(head, "user-agent").unwrap_or("");
    let ua_l = ua.to_ascii_lowercase();
    if ua.is_empty() {
        add(cfg.w_no_ua, "no-user-agent");
    } else if !BROWSER_UA.iter().any(|b| ua_l.contains(b)) {
        add(cfg.w_nonbrowser_ua, "non-browser-user-agent");
    }
    if cfg.tools.iter().any(|t| ua_l.contains(&t.to_ascii_lowercase())) {
        add(cfg.w_tool_ua, "known-tool-user-agent");
    }
    if origin.is_none() {
        add(cfg.w_no_origin, "no-origin");
    }
    if header(head, "sec-websocket-extensions").is_none() {
        add(cfg.w_no_extensions, "no-extensions");
    }
    if header(head, "accept-encoding").is_none() {
        add(cfg.w_no_accept_encoding, "no-accept-encoding");
    }
    if header(head, "accept-language").is_none() {
        add(cfg.w_no_accept_language, "no-accept-language");
    }
    if header(head, "sec-websocket-version").is_some_and(|v| v != "13") {
        add(cfg.w_bad_version, "ws-version-not-13");
    }
    let nhdr = head.lines().skip(1).filter(|l| l.contains(':')).count();
    if nhdr < cfg.min_headers {
        add(cfg.w_few_headers, "few-headers");
    }

    (score >= cfg.threshold).then(|| format!("score {score} [{}]", reasons.join(",")))
}

/// Core-side handler for a flagged WebSocket handshake (from `Event::WsFake`): tell the
/// opers, and z-line the IP if the mode asked for it.
pub fn on_fake(s: &mut Server, ip: IpAddr, reason: String, ban: bool) {
    let ip_s = ip.to_string();
    let m = s.trf(
        "wsguard: non-browser WebSocket handshake from {0} ({1})",
        &[ip_s.as_str(), reason.as_str()],
    );
    s.snotice_c('c', &m);
    if ban && !ban_exempt(s, ip, &ip_s) {
        let dur = s.conf_num("wsguard_zline_duration", 3600u64);
        s.add_xline(
            XKind::Zline,
            &ip_s,
            dur,
            "wsguard",
            &format!("fake WebSocket: {reason}"),
        );
    }
}

/// Never z-line loopback, a configured WS reverse proxy (`ws_proxyranges`), or an
/// admin-exempted range (`wsguard_exempt_ip`). A fake reported as one of these means
/// the real client IP wasn't forwarded, so banning it would take out the proxy / local
/// infrastructure rather than the abuser. The detection is still reported either way.
fn ban_exempt(s: &Server, ip: IpAddr, ip_s: &str) -> bool {
    if ip.is_loopback() {
        return true;
    }
    let listed = |key: &str| {
        s.conf_all(key)
            .iter()
            .any(|r| crate::modules::connclass::ip_matches(r, ip_s))
    };
    listed("ws_proxyranges") || listed("wsguard_exempt_ip")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: Mode) -> WsGuardCfg {
        let mut c = read(&Config::default());
        c.mode = mode;
        c
    }

    const BROWSER: &str = "GET / HTTP/1.1\r\nHost: irc.x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\nOrigin: https://chat.x\r\nUser-Agent: Mozilla/5.0 (X11) AppleWebKit/537 Chrome/120\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US\r\n\r\n";
    const WEBSOCAT: &str = "GET / HTTP/1.1\r\nHost: irc.x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nUser-Agent: websocat/1.11\r\n\r\n";

    #[test]
    fn real_browser_passes() {
        assert!(assess(BROWSER, &cfg(Mode::Report)).is_none());
    }

    #[test]
    fn websocat_is_flagged() {
        assert!(assess(WEBSOCAT, &cfg(Mode::Report)).is_some());
    }

    #[test]
    fn off_never_flags() {
        assert!(assess(WEBSOCAT, &cfg(Mode::Off)).is_none());
    }
}
