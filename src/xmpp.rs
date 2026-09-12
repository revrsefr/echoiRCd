//! Minimal XMPP client-to-server MUC bridge worker: SRV lookup + TCP + STARTTLS
//! (openssl), SASL (SCRAM-SHA-1 preferred, PLAIN fallback), resource bind, and a
//! Multi-User-Chat join. Runs on its own thread; inbound groupchat messages become
//! [`Event::BridgeIn`], outbound lines arrive over an mpsc channel. Not a general XMPP
//! stack — only what a channel bridge needs. Dropping the outbound `Sender` (a bridge
//! reload) closes the stream and ends the thread.

use crate::ircd::Event;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::time::{Duration, Instant};

pub struct Config {
    pub jid: String, // bare jid: user@domain
    pub password: String,
    pub server: Option<String>, // optional host[:port] override for the c2s connect
    pub room: String,           // MUC room jid: room@conference.domain
    pub nick: String,           // MUC nickname
    pub channel: String,        // IRC channel key, tagged onto every Event::BridgeIn
    pub core: SyncSender<Event>,
    pub rx: Receiver<String>, // IRC -> XMPP lines
}

pub fn spawn(cfg: Config) {
    std::thread::spawn(move || {
        if let Err(e) = run(cfg) {
            eprintln!("echoircd: xmpp bridge: {e}");
        }
    });
}

/// The wire, which upgrades in place from plaintext TCP to TLS at STARTTLS.
enum Wire {
    Plain(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
}
impl Wire {
    fn write_all(&mut self, b: &[u8]) -> std::io::Result<()> {
        match self {
            Wire::Plain(s) => s.write_all(b),
            Wire::Tls(s) => s.write_all(b),
        }
    }
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Wire::Plain(s) => s.read(buf),
            Wire::Tls(s) => s.read(buf),
        }
    }
    fn set_read_timeout(&mut self, d: Option<Duration>) {
        match self {
            Wire::Plain(s) => {
                s.set_read_timeout(d).ok();
            }
            Wire::Tls(s) => {
                s.get_ref().set_read_timeout(d).ok();
            }
        }
    }
    fn starttls(self, domain: &str) -> Result<Wire, String> {
        let tcp = match self {
            Wire::Plain(t) => t,
            Wire::Tls(_) => return Err("starttls on an already-TLS stream".into()),
        };
        let b = SslConnector::builder(SslMethod::tls_client()).map_err(|e| e.to_string())?;
        let connector = b.build();
        let tls = connector
            .connect(domain, tcp)
            .map_err(|e| format!("TLS handshake: {e}"))?;
        Ok(Wire::Tls(Box::new(tls)))
    }
}

fn send(w: &mut Wire, s: &str) -> Result<(), String> {
    w.write_all(s.as_bytes()).map_err(|e| e.to_string())
}

fn stream_header(domain: &str) -> String {
    format!(
        "<?xml version='1.0'?><stream:stream to='{domain}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )
}

fn run(cfg: Config) -> Result<(), String> {
    let (user, domain) = cfg.jid.split_once('@').ok_or("jid must be user@domain")?;
    let (user, domain) = (user.to_string(), domain.to_string());
    let (host, port) = match &cfg.server {
        Some(s) => match s.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(5222)),
            None => (s.clone(), 5222u16),
        },
        // RFC 6120: resolve the c2s SRV record; fall back to the domain on :5222.
        None => crate::resolver::srv_lookup(
            &format!("_xmpp-client._tcp.{domain}"),
            Duration::from_secs(5),
        )
        .into_iter()
        .next()
        .unwrap_or((domain.clone(), 5222)),
    };

    let tcp = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let mut wire = Wire::Plain(tcp);
    let mut buf: Vec<u8> = Vec::new();

    // open stream, read features, negotiate STARTTLS
    send(&mut wire, &stream_header(&domain))?;
    wait_for(&mut wire, &mut buf, "stream:features")?;
    send(
        &mut wire,
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )?;
    let t = read_token(&mut wire, &mut buf)?;
    if !t.contains("proceed") {
        return Err(format!("STARTTLS refused: {t}"));
    }
    wire = wire.starttls(&domain)?;
    wire.set_read_timeout(Some(Duration::from_secs(10)));
    buf.clear();

    // re-open over TLS, then SASL with the strongest offered mechanism
    send(&mut wire, &stream_header(&domain))?;
    let feats = wait_for(&mut wire, &mut buf, "stream:features")?;
    let mechs = parse_mechs(&feats);
    if mechs.iter().any(|m| m == "SCRAM-SHA-1") {
        sasl_scram_sha1(&mut wire, &mut buf, &user, &cfg.password)?;
    } else if mechs.iter().any(|m| m == "PLAIN") {
        sasl_plain(&mut wire, &mut buf, &user, &cfg.password)?;
    } else {
        return Err("no supported SASL mechanism offered (need SCRAM-SHA-1 or PLAIN)".into());
    }
    buf.clear();

    // re-open over authenticated stream, bind a resource, join the room
    send(&mut wire, &stream_header(&domain))?;
    wait_for(&mut wire, &mut buf, "stream:features")?;
    send(
        &mut wire,
        &format!(
            "<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>\
             <resource>{}</resource></bind></iq>",
            xml_escape(&cfg.nick)
        ),
    )?;
    let _ = wait_for(&mut wire, &mut buf, "bind1");
    let to = format!("{}/{}", cfg.room, cfg.nick);
    send(
        &mut wire,
        &format!(
            "<presence to='{}'><x xmlns='http://jabber.org/protocol/muc'>\
             <history maxchars='0'/></x></presence>",
            xml_escape(&to)
        ),
    )?;

    // steady state: short read timeout so we cycle for outbound + shutdown
    wire.set_read_timeout(Some(Duration::from_millis(500)));
    let mut last_ka = Instant::now();
    let mut rbuf = [0u8; 8192];
    loop {
        // drain IRC -> XMPP
        loop {
            match cfg.rx.try_recv() {
                Ok(line) => {
                    let stanza = format!(
                        "<message to='{}' type='groupchat'><body>{}</body></message>",
                        xml_escape(&cfg.room),
                        xml_escape(&line)
                    );
                    if send(&mut wire, &stanza).is_err() {
                        return Ok(());
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = send(&mut wire, "</stream:stream>");
                    return Ok(());
                }
            }
        }
        if last_ka.elapsed() >= Duration::from_secs(30) {
            let _ = send(&mut wire, " ");
            last_ka = Instant::now();
        }
        match wire.read(&mut rbuf) {
            Ok(0) => return Ok(()), // server closed
            Ok(n) => buf.extend_from_slice(&rbuf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e.to_string()),
        }
        while let Some(tok) = take_token(&mut buf) {
            handle_stanza(&cfg, &mut wire, &tok);
        }
    }
}

/// Read tokens until one contains `needle`; returns it. Errors on EOF / a ~15s stall.
fn wait_for(w: &mut Wire, buf: &mut Vec<u8>, needle: &str) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let t = read_token_until(w, buf, deadline)?;
        if t.contains(needle) {
            return Ok(t);
        }
    }
}

/// The next token, whatever it is. Errors on EOF / a ~15s stall.
fn read_token(w: &mut Wire, buf: &mut Vec<u8>) -> Result<String, String> {
    read_token_until(w, buf, Instant::now() + Duration::from_secs(15))
}

fn read_token_until(w: &mut Wire, buf: &mut Vec<u8>, deadline: Instant) -> Result<String, String> {
    let mut rbuf = [0u8; 8192];
    loop {
        if let Some(tok) = take_token(buf) {
            return Ok(tok);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for server".into());
        }
        match w.read(&mut rbuf) {
            Ok(0) => return Err("stream closed by server".into()),
            Ok(n) => buf.extend_from_slice(&rbuf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn handle_stanza(cfg: &Config, w: &mut Wire, tok: &str) {
    if tok.starts_with("<message") {
        if !(tok.contains("type='groupchat'") || tok.contains("type=\"groupchat\"")) {
            return;
        }
        if tok.contains("<delay") {
            return; // history / offline replay
        }
        let from = attr(tok, "from").unwrap_or_default();
        // room-level (no resource) or our own reflected message → ignore
        let resource = match from.rsplit_once('/') {
            Some((_, r)) if !r.is_empty() => r.to_string(),
            _ => return,
        };
        if resource == cfg.nick {
            return;
        }
        let Some(body) = extract_body(tok) else {
            return;
        };
        let text = xml_unescape(&body);
        if text.is_empty() {
            return;
        }
        let _ = cfg.core.send(Event::BridgeIn {
            channel: cfg.channel.clone(),
            sender: resource,
            text,
        });
    } else if tok.starts_with("<iq")
        && tok.contains("<ping")
        && (tok.contains("type='get'") || tok.contains("type=\"get\""))
    {
        // XEP-0199 ping → pong
        let from = attr(tok, "from").unwrap_or_default();
        let id = attr(tok, "id").unwrap_or_default();
        let _ = send(
            w,
            &format!(
                "<iq type='result' to='{}' id='{}'/>",
                xml_escape(&from),
                xml_escape(&id)
            ),
        );
    }
}

/// The `<mechanism>NAME</mechanism>` names advertised in a `<stream:features>` token.
fn parse_mechs(features: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = features;
    while let Some(s) = rest.find("<mechanism>") {
        let after = &rest[s + 11..];
        match after.find("</mechanism>") {
            Some(e) => {
                out.push(after[..e].trim().to_string());
                rest = &after[e + 12..];
            }
            None => break,
        }
    }
    out
}

/// SASL PLAIN: `base64(\0authcid\0passwd)`, safe over the TLS the caller has by now.
fn sasl_plain(w: &mut Wire, buf: &mut Vec<u8>, user: &str, pass: &str) -> Result<(), String> {
    let b64 = openssl::base64::encode_block(format!("\0{user}\0{pass}").as_bytes());
    send(
        w,
        &format!("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{b64}</auth>"),
    )?;
    let t = read_token(w, buf)?;
    if t.contains("success") {
        Ok(())
    } else {
        Err("SASL PLAIN authentication failed".into())
    }
}

/// SASL SCRAM-SHA-1 (RFC 5802) — the password never crosses the wire; also verifies the
/// server signature so a MITM that lacks it can't complete the exchange.
fn sasl_scram_sha1(w: &mut Wire, buf: &mut Vec<u8>, user: &str, pass: &str) -> Result<(), String> {
    let mut nonce = [0u8; 18];
    openssl::rand::rand_bytes(&mut nonce).map_err(|e| e.to_string())?;
    let cnonce = openssl::base64::encode_block(&nonce);
    let client_first_bare = format!("n={},r={cnonce}", sasl_escape(user));
    let client_first = format!("n,,{client_first_bare}");
    send(
        w,
        &format!(
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>{}</auth>",
            openssl::base64::encode_block(client_first.as_bytes())
        ),
    )?;

    let chal = read_token(w, buf)?;
    let server_first = inner_text(&chal, "challenge")
        .and_then(|b| openssl::base64::decode_block(&b).ok())
        .and_then(|v| String::from_utf8(v).ok())
        .ok_or("SCRAM: bad challenge")?;
    let snonce = scram_field(&server_first, 'r').ok_or("SCRAM: no server nonce")?;
    let salt = scram_field(&server_first, 's')
        .and_then(|b| openssl::base64::decode_block(&b).ok())
        .ok_or("SCRAM: no salt")?;
    let iters: usize = scram_field(&server_first, 'i')
        .and_then(|v| v.parse().ok())
        .ok_or("SCRAM: no iteration count")?;
    if !snonce.starts_with(&cnonce) {
        return Err("SCRAM: server nonce does not extend ours".into());
    }

    let salted = pbkdf2_sha1(pass.as_bytes(), &salt, iters);
    let client_key = hmac_sha1(&salted, b"Client Key");
    let stored_key = sha1(&client_key);
    let client_final_bare = format!("c=biws,r={snonce}");
    let auth_msg = format!("{client_first_bare},{server_first},{client_final_bare}");
    let client_sig = hmac_sha1(&stored_key, auth_msg.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_sig.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let client_final = format!(
        "{client_final_bare},p={}",
        openssl::base64::encode_block(&proof)
    );
    send(
        w,
        &format!(
            "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</response>",
            openssl::base64::encode_block(client_final.as_bytes())
        ),
    )?;

    let succ = read_token(w, buf)?;
    if !succ.contains("success") {
        return Err("SCRAM: authentication failed".into());
    }
    // verify the server proof (v=) when present
    if let Some(v) = inner_text(&succ, "success")
        .and_then(|b| openssl::base64::decode_block(&b).ok())
        .and_then(|d| String::from_utf8(d).ok())
        .and_then(|sf| scram_field(&sf, 'v'))
    {
        let server_key = hmac_sha1(&salted, b"Server Key");
        let server_sig = hmac_sha1(&server_key, auth_msg.as_bytes());
        if openssl::base64::encode_block(&server_sig) != v {
            return Err("SCRAM: server signature mismatch".into());
        }
    }
    Ok(())
}

/// Value of comma-delimited SCRAM attribute `key` (e.g. `r`, `s`, `i`, `v`).
fn scram_field(msg: &str, key: char) -> Option<String> {
    let pfx = format!("{key}=");
    msg.split(',')
        .find_map(|p| p.strip_prefix(&pfx))
        .map(|s| s.to_string())
}

/// SCRAM username escaping: `=` → `=3D`, `,` → `=2C`.
fn sasl_escape(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

fn sha1(d: &[u8]) -> Vec<u8> {
    openssl::hash::hash(openssl::hash::MessageDigest::sha1(), d)
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
    let k = match PKey::hmac(if key.is_empty() { &[0] } else { key }) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    let mut s = match Signer::new(MessageDigest::sha1(), &k) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    if s.update(data).is_err() {
        return Vec::new();
    }
    s.sign_to_vec().unwrap_or_default()
}

fn pbkdf2_sha1(pass: &[u8], salt: &[u8], iters: usize) -> Vec<u8> {
    let mut out = vec![0u8; 20];
    if openssl::pkcs5::pbkdf2_hmac(
        pass,
        salt,
        iters,
        openssl::hash::MessageDigest::sha1(),
        &mut out,
    )
    .is_err()
    {
        return Vec::new();
    }
    out
}

/// Pull the next top-level XML token from `buf`, consuming its bytes. `None` if `buf`
/// doesn't yet hold a complete token. Handles the `<?xml?>` decl, the unbalanced
/// `<stream:stream>` open/close, self-closing tags, and balanced elements (quote- and
/// depth-aware, so `>` inside an attribute or a nested child doesn't fool it).
fn take_token(buf: &mut Vec<u8>) -> Option<String> {
    // trim leading whitespace
    let mut i = 0;
    while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i > 0 {
        buf.drain(..i);
    }
    if buf.is_empty() {
        return None;
    }
    if buf[0] != b'<' {
        // stray character data between stanzas — drop up to the next tag
        match buf.iter().position(|&c| c == b'<') {
            Some(p) => {
                buf.drain(..p);
            }
            None => {
                buf.clear();
                return None;
            }
        }
    }
    // <?xml ... ?>
    if buf.starts_with(b"<?") {
        return find_seq(buf, b"?>").map(|e| {
            let tok = String::from_utf8_lossy(&buf[..e + 2]).into_owned();
            buf.drain(..e + 2);
            tok
        });
    }
    let (name, first_end, self_closed, is_closing) = read_tag(buf, 0)?;
    // the stream wrapper open/close are not balanced elements — return as-is
    if name == "stream:stream" || self_closed || is_closing {
        let tok = String::from_utf8_lossy(&buf[..first_end]).into_owned();
        buf.drain(..first_end);
        return Some(tok);
    }
    // balanced element: walk tags tracking depth
    let mut depth = 1i32;
    let mut pos = first_end;
    while depth > 0 {
        let lt = find_from(buf, pos, b'<')?;
        let (_nm, tend, sc, closing) = read_tag(buf, lt)?;
        if closing {
            depth -= 1;
        } else if !sc {
            depth += 1;
        }
        pos = tend;
    }
    let tok = String::from_utf8_lossy(&buf[..pos]).into_owned();
    buf.drain(..pos);
    Some(tok)
}

/// Read one `<...>` tag beginning at `b[at]`. Returns (name, index-just-past-`>`,
/// self_closed, is_closing). `is_closing` is a `</foo>` end tag; `self_closed` a
/// `<foo/>`. Name is the element name (without the leading `/` of a close tag). `None`
/// if the tag isn't fully present yet.
fn read_tag(b: &[u8], at: usize) -> Option<(String, usize, bool, bool)> {
    if at >= b.len() || b[at] != b'<' {
        return None;
    }
    let is_closing = b.get(at + 1) == Some(&b'/');
    let mut i = if is_closing { at + 2 } else { at + 1 };
    let mut in_str = false;
    let mut quote = 0u8;
    let mut name = String::new();
    let mut reading_name = true;
    while i < b.len() {
        let c = b[i];
        if in_str {
            if c == quote {
                in_str = false;
            }
        } else if c == b'"' || c == b'\'' {
            in_str = true;
            quote = c;
            reading_name = false;
        } else if c == b'>' {
            let self_closed = i > at && b[i - 1] == b'/';
            return Some((name, i + 1, self_closed, is_closing));
        } else if reading_name {
            if matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b'/') {
                reading_name = false;
            } else {
                name.push(c as char);
            }
        }
        i += 1;
    }
    None
}

fn find_from(b: &[u8], from: usize, byte: u8) -> Option<usize> {
    b.iter()
        .skip(from)
        .position(|&c| c == byte)
        .map(|p| p + from)
}

fn find_seq(b: &[u8], seq: &[u8]) -> Option<usize> {
    b.windows(seq.len()).position(|w| w == seq)
}

/// The value of attribute `name` in an element's start tag (`name='v'` or `name="v"`).
fn attr(tag: &str, name: &str) -> Option<String> {
    for q in ['\'', '"'] {
        let pat = format!("{name}={q}");
        if let Some(s) = tag.find(&pat) {
            let rest = &tag[s + pat.len()..];
            if let Some(e) = rest.find(q) {
                return Some(xml_unescape(&rest[..e]));
            }
        }
    }
    None
}

/// Raw text between the first `<elem ...>` and its `</elem>`. `None` if absent or a
/// self-closing empty tag.
fn inner_text(xml: &str, elem: &str) -> Option<String> {
    let start = xml.find(&format!("<{elem}"))?;
    let gt = xml[start..].find('>')? + start;
    if xml.as_bytes().get(gt.wrapping_sub(1)) == Some(&b'/') {
        return None; // <elem/>
    }
    let close = xml[gt + 1..].find(&format!("</{elem}>"))? + gt + 1;
    Some(xml[gt + 1..close].trim().to_string())
}

/// Text of the first `<body>…</body>` in a message stanza.
fn extract_body(msg: &str) -> Option<String> {
    inner_text(msg, "body")
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        if let Some(semi) = after.find(';') {
            let ent = &after[1..semi];
            match ent {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "apos" => out.push('\''),
                "quot" => out.push('"'),
                _ => {
                    let cp = if let Some(hex) =
                        ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok()
                    } else if let Some(dec) = ent.strip_prefix('#') {
                        dec.parse().ok()
                    } else {
                        None
                    };
                    match cp.and_then(char::from_u32) {
                        Some(ch) => out.push(ch),
                        None => out.push_str(&after[..=semi]), // unknown entity, keep verbatim
                    }
                }
            }
            rest = &after[semi + 1..];
        } else {
            out.push_str(after);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(s: &str) -> (Vec<u8>, Option<String>) {
        let mut b = s.as_bytes().to_vec();
        let t = take_token(&mut b);
        (b, t)
    }

    #[test]
    fn tokenizes_stream_and_stanzas() {
        // stream open is returned unbalanced, then a balanced features element
        let mut b = b"<?xml version='1.0'?><stream:stream to='x' version='1.0'><stream:features><mechanisms/></stream:features>".to_vec();
        assert!(take_token(&mut b).unwrap().starts_with("<?xml"));
        assert!(take_token(&mut b).unwrap().starts_with("<stream:stream"));
        let feat = take_token(&mut b).unwrap();
        assert!(feat.starts_with("<stream:features") && feat.ends_with("</stream:features>"));
        assert!(take_token(&mut b).is_none());
    }

    #[test]
    fn balanced_handles_quotes_and_nesting() {
        let m =
            "<message from='r@c/bob' type='groupchat'><body>a &gt; b</body><x a='&gt;'/></message>";
        let (rest, t) = tok(m);
        assert_eq!(t.as_deref(), Some(m));
        assert!(rest.is_empty());
    }

    #[test]
    fn incomplete_returns_none() {
        let mut b = b"<message type='groupchat'><body>hi".to_vec();
        assert!(take_token(&mut b).is_none());
        b.extend_from_slice(b"</body></message>");
        assert!(take_token(&mut b).unwrap().ends_with("</message>"));
    }

    #[test]
    fn self_closing_token() {
        let (_r, t) = tok("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
        assert!(t.unwrap().contains("proceed"));
    }

    #[test]
    fn attr_and_body() {
        let m = "<message from='room@conf/alice' type='groupchat'><body>hello &amp; hi</body></message>";
        assert_eq!(attr(m, "from").as_deref(), Some("room@conf/alice"));
        assert_eq!(extract_body(m).as_deref(), Some("hello &amp; hi"));
        assert_eq!(xml_unescape(&extract_body(m).unwrap()), "hello & hi");
    }

    #[test]
    fn escape_roundtrip() {
        let s = "a<b>c&d'e\"f";
        assert_eq!(xml_unescape(&xml_escape(s)), s);
        assert_eq!(xml_unescape("&#65;&#x42;"), "AB");
    }

    #[test]
    fn empty_body_is_none() {
        assert_eq!(extract_body("<message><body/></message>"), None);
    }

    #[test]
    fn parses_sasl_mechanisms() {
        let f = "<stream:features><mechanisms xmlns='urn:...'>\
                 <mechanism>SCRAM-SHA-1</mechanism><mechanism>PLAIN</mechanism>\
                 </mechanisms></stream:features>";
        assert_eq!(parse_mechs(f), vec!["SCRAM-SHA-1", "PLAIN"]);
    }

    #[test]
    fn scram_field_and_escape() {
        let sf = "r=abc123,s=QSXCR+Q6sek8bf92,i=4096";
        assert_eq!(scram_field(sf, 'r').as_deref(), Some("abc123"));
        assert_eq!(scram_field(sf, 'i').as_deref(), Some("4096"));
        assert_eq!(scram_field(sf, 'x'), None);
        assert_eq!(sasl_escape("a=b,c"), "a=3Db=2Cc");
    }

    #[test]
    fn inner_text_extracts() {
        assert_eq!(
            inner_text("<challenge xmlns='x'>Zm9v</challenge>", "challenge").as_deref(),
            Some("Zm9v")
        );
        assert_eq!(inner_text("<success/>", "success"), None);
    }

    // RFC 5802 §5 SCRAM-SHA-1 worked example — proves pbkdf2/hmac/sha1 + the proof XOR.
    #[test]
    fn scram_sha1_rfc5802_vector() {
        let salt = openssl::base64::decode_block("QSXCR+Q6sek8bf92").unwrap();
        let salted = pbkdf2_sha1(b"pencil", &salt, 4096);
        let client_key = hmac_sha1(&salted, b"Client Key");
        let stored_key = sha1(&client_key);
        let auth_msg = "n=user,r=fyko+d2lbbFgONRv9qkxdawL,\
             r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,\
             c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j";
        let client_sig = hmac_sha1(&stored_key, auth_msg.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(
            openssl::base64::encode_block(&proof),
            "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        );
        let server_key = hmac_sha1(&salted, b"Server Key");
        let server_sig = hmac_sha1(&server_key, auth_msg.as_bytes());
        assert_eq!(
            openssl::base64::encode_block(&server_sig),
            "rmF9pqV8S7suAoZWja4dJRkFsKQ="
        );
    }
}
