//! PostgreSQL frontend/backend protocol v3 — message framing (RFC-equivalent: the
//! documented libpq wire format). Frontend builders return ready-to-write byte
//! vectors; [`read_message`] parses one backend message off a blocking stream.
//! Everything is big-endian (network order); no `unsafe`, no external crate.

use std::io::{self, Read};

const PROTOCOL_3_0: i32 = 196608; // 3 << 16
const SSL_REQUEST_CODE: i32 = 80877103;

// ---- little writer helpers -------------------------------------------------

fn put_i16(buf: &mut Vec<u8>, v: i16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_be_bytes());
}
/// A C-string: raw bytes then a NUL terminator.
fn put_cstr(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}
/// Wrap a body as `tag Int32(len) body`, where len counts itself + the body.
fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + body.len());
    v.push(tag);
    put_i32(&mut v, (body.len() + 4) as i32);
    v.extend_from_slice(body);
    v
}

// ---- frontend messages -----------------------------------------------------

/// The startup packet (no type byte): protocol version + parameter pairs.
pub fn startup(user: &str, database: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_i32(&mut body, PROTOCOL_3_0);
    put_cstr(&mut body, "user");
    put_cstr(&mut body, user);
    put_cstr(&mut body, "database");
    put_cstr(&mut body, database);
    put_cstr(&mut body, "client_encoding");
    put_cstr(&mut body, "UTF8");
    body.push(0); // end of parameters
    let mut v = Vec::with_capacity(body.len() + 4);
    put_i32(&mut v, (body.len() + 4) as i32);
    v.extend_from_slice(&body);
    v
}

/// SSLRequest — asks the server whether it will speak TLS before startup.
pub fn ssl_request() -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    put_i32(&mut v, 8);
    put_i32(&mut v, SSL_REQUEST_CODE);
    v
}

/// PasswordMessage — cleartext or the `md5…` digest.
pub fn password(pw: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, pw);
    framed(b'p', &body)
}

/// SASLInitialResponse: mechanism name + the client-first-message.
pub fn sasl_initial(mechanism: &str, initial: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, mechanism);
    put_i32(&mut body, initial.len() as i32);
    body.extend_from_slice(initial.as_bytes());
    framed(b'p', &body)
}

/// SASLResponse: the client-final-message.
pub fn sasl_response(data: &str) -> Vec<u8> {
    framed(b'p', data.as_bytes())
}

/// Simple Query.
pub fn query(sql: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, sql);
    framed(b'Q', &body)
}

/// Parse (unnamed statement, no declared parameter types — the server infers them).
pub fn parse(sql: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, ""); // unnamed prepared statement
    put_cstr(&mut body, sql);
    put_i16(&mut body, 0); // 0 parameter type OIDs
    framed(b'P', &body)
}

/// Bind the unnamed statement to the unnamed portal, all parameters + results in
/// TEXT format. `None` binds a SQL NULL.
pub fn bind(params: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, ""); // portal
    put_cstr(&mut body, ""); // statement
    put_i16(&mut body, 1); // one parameter format code…
    put_i16(&mut body, 0); // …= text, applied to every parameter
    put_i16(&mut body, params.len() as i16);
    for p in params {
        match p {
            None => put_i32(&mut body, -1),
            Some(bytes) => {
                put_i32(&mut body, bytes.len() as i32);
                body.extend_from_slice(bytes);
            }
        }
    }
    put_i16(&mut body, 1); // one result format code…
    put_i16(&mut body, 0); // …= text, for every column
    framed(b'B', &body)
}

/// Describe the unnamed portal (so the server sends a RowDescription).
pub fn describe_portal() -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'P');
    put_cstr(&mut body, "");
    framed(b'D', &body)
}

/// Execute the unnamed portal with no row limit.
pub fn execute() -> Vec<u8> {
    let mut body = Vec::new();
    put_cstr(&mut body, ""); // portal
    put_i32(&mut body, 0); // unlimited rows
    framed(b'E', &body)
}

pub fn sync() -> Vec<u8> {
    framed(b'S', &[])
}

pub fn terminate() -> Vec<u8> {
    framed(b'X', &[])
}

// ---- backend messages ------------------------------------------------------

/// The authentication sub-kinds carried by an `R` message.
#[derive(Debug, PartialEq)]
pub enum Auth {
    Ok,
    Cleartext,
    Md5([u8; 4]),
    Sasl(Vec<String>),     // mechanism list
    SaslContinue(Vec<u8>), // server-first-message
    SaslFinal(Vec<u8>),    // server-final-message
    Other(i32),            // e.g. GSS/Kerberos — unsupported
}

/// A parsed backend message (only the variants the client acts on; the rest are
/// coalesced into [`Backend::Ignore`]).
#[derive(Debug, PartialEq)]
pub enum Backend {
    Auth(Auth),
    ParameterStatus(String, String),
    ReadyForQuery(u8),
    RowDescription(Vec<String>),
    DataRow(Vec<Option<String>>),
    CommandComplete(String),
    Error(String),
    Notice(String),
    Ignore, // BackendKeyData / ParseComplete / BindComplete / NoData / empty / …
}

fn rd_i16(b: &[u8], at: &mut usize) -> Option<i16> {
    let v = b.get(*at..*at + 2)?;
    *at += 2;
    Some(i16::from_be_bytes([v[0], v[1]]))
}
fn rd_i32(b: &[u8], at: &mut usize) -> Option<i32> {
    let v = b.get(*at..*at + 4)?;
    *at += 4;
    Some(i32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}
fn rd_cstr(b: &[u8], at: &mut usize) -> Option<String> {
    let start = *at;
    let end = start + b.get(start..)?.iter().position(|&c| c == 0)?;
    let s = String::from_utf8_lossy(&b[start..end]).into_owned();
    *at = end + 1;
    Some(s)
}

/// Read exactly one backend message (type byte + length-prefixed body) from a
/// blocking stream and parse it. A short read or malformed frame is an error.
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Backend> {
    let mut hdr = [0u8; 5];
    r.read_exact(&mut hdr)?;
    let tag = hdr[0];
    let len = i32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    if !(4..=0x4000_0000).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pgsql: bad message length",
        ));
    }
    let mut body = vec![0u8; (len - 4) as usize];
    r.read_exact(&mut body)?;
    Ok(parse_body(tag, &body))
}

fn parse_body(tag: u8, body: &[u8]) -> Backend {
    let mut at = 0usize;
    let bad = || Backend::Error("pgsql: malformed backend message".into());
    match tag {
        b'R' => match rd_i32(body, &mut at) {
            Some(0) => Backend::Auth(Auth::Ok),
            Some(3) => Backend::Auth(Auth::Cleartext),
            Some(5) => match body.get(4..8) {
                Some(s) => Backend::Auth(Auth::Md5([s[0], s[1], s[2], s[3]])),
                None => bad(),
            },
            Some(10) => {
                let mut mechs = Vec::new();
                while let Some(m) = rd_cstr(body, &mut at) {
                    if m.is_empty() {
                        break;
                    }
                    mechs.push(m);
                }
                Backend::Auth(Auth::Sasl(mechs))
            }
            Some(11) => Backend::Auth(Auth::SaslContinue(body[at..].to_vec())),
            Some(12) => Backend::Auth(Auth::SaslFinal(body[at..].to_vec())),
            Some(other) => Backend::Auth(Auth::Other(other)),
            None => bad(),
        },
        b'S' => match (rd_cstr(body, &mut at), rd_cstr(body, &mut at)) {
            (Some(k), Some(v)) => Backend::ParameterStatus(k, v),
            _ => bad(),
        },
        b'Z' => match body.first() {
            Some(&s) => Backend::ReadyForQuery(s),
            None => bad(),
        },
        b'T' => {
            let Some(n) = rd_i16(body, &mut at) else {
                return bad();
            };
            let mut cols = Vec::with_capacity(n.max(0) as usize);
            for _ in 0..n.max(0) {
                let Some(name) = rd_cstr(body, &mut at) else {
                    return bad();
                };
                at += 18; // tableOid(4) col(2) typeOid(4) typeLen(2) typeMod(4) fmt(2)
                cols.push(name);
            }
            Backend::RowDescription(cols)
        }
        b'D' => {
            let Some(n) = rd_i16(body, &mut at) else {
                return bad();
            };
            let mut vals = Vec::with_capacity(n.max(0) as usize);
            for _ in 0..n.max(0) {
                let Some(len) = rd_i32(body, &mut at) else {
                    return bad();
                };
                if len < 0 {
                    vals.push(None);
                } else {
                    let end = at + len as usize;
                    let Some(slice) = body.get(at..end) else {
                        return bad();
                    };
                    vals.push(Some(String::from_utf8_lossy(slice).into_owned()));
                    at = end;
                }
            }
            Backend::DataRow(vals)
        }
        b'C' => match rd_cstr(body, &mut at) {
            Some(s) => Backend::CommandComplete(s),
            None => bad(),
        },
        b'E' | b'N' => {
            let (mut sev, mut code, mut msg) = (String::new(), String::new(), String::new());
            while let Some(&ftype) = body.get(at) {
                if ftype == 0 {
                    break;
                }
                at += 1;
                let Some(val) = rd_cstr(body, &mut at) else {
                    break;
                };
                match ftype {
                    b'S' => sev = val,
                    b'C' => code = val,
                    b'M' => msg = val,
                    _ => {}
                }
            }
            let text = format!("{sev} {code}: {msg}").trim().to_string();
            if tag == b'E' {
                Backend::Error(text)
            } else {
                Backend::Notice(text)
            }
        }
        // BackendKeyData(K) ParseComplete(1) BindComplete(2) CloseComplete(3)
        // NoData(n) PortalSuspended(s) EmptyQuery(I) ParameterDescription(t) …
        _ => Backend::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_frames_length_and_params() {
        let m = startup("bob", "irc");
        let len = i32::from_be_bytes([m[0], m[1], m[2], m[3]]) as usize;
        assert_eq!(len, m.len()); // length prefix counts the whole packet
        assert_eq!(&m[4..8], &PROTOCOL_3_0.to_be_bytes());
        assert!(m.windows(4).any(|w| w == b"user"));
        assert_eq!(*m.last().unwrap(), 0); // trailing param terminator
    }

    #[test]
    fn query_message_is_tagged_and_null_terminated() {
        let m = query("SELECT 1");
        assert_eq!(m[0], b'Q');
        let len = i32::from_be_bytes([m[1], m[2], m[3], m[4]]) as usize;
        assert_eq!(len, m.len() - 1); // length excludes the type byte
        assert_eq!(*m.last().unwrap(), 0);
    }

    #[test]
    fn bind_encodes_params_and_nulls() {
        let m = bind(&[Some(b"42".to_vec()), None]);
        assert_eq!(m[0], b'B');
        // a NULL is encoded as length -1
        assert!(m.windows(4).any(|w| w == (-1i32).to_be_bytes()));
        // the text value "42" appears verbatim
        assert!(m.windows(2).any(|w| w == b"42"));
    }

    /// Round-trip: hand-build a couple of backend frames and parse them.
    #[test]
    fn parses_auth_rowdesc_datarow_and_error() {
        // AuthenticationMD5Password: 'R', len, Int32(5), 4 salt bytes
        let mut r = Vec::new();
        r.push(b'R');
        r.extend_from_slice(&(4 + 4 + 4i32).to_be_bytes());
        r.extend_from_slice(&5i32.to_be_bytes());
        r.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            read_message(&mut &r[..]).unwrap(),
            Backend::Auth(Auth::Md5([1, 2, 3, 4]))
        );

        // RowDescription with one column "id"
        let mut body = Vec::new();
        put_i16(&mut body, 1);
        put_cstr(&mut body, "id");
        body.extend_from_slice(&[0u8; 18]);
        let msg = framed(b'T', &body);
        assert_eq!(
            read_message(&mut &msg[..]).unwrap(),
            Backend::RowDescription(vec!["id".into()])
        );

        // DataRow: one column "7", one NULL
        let mut body = Vec::new();
        put_i16(&mut body, 2);
        put_i32(&mut body, 1);
        body.push(b'7');
        put_i32(&mut body, -1);
        let msg = framed(b'D', &body);
        assert_eq!(
            read_message(&mut &msg[..]).unwrap(),
            Backend::DataRow(vec![Some("7".into()), None])
        );

        // ErrorResponse: severity + code + message
        let mut body = Vec::new();
        body.push(b'S');
        put_cstr(&mut body, "FATAL");
        body.push(b'C');
        put_cstr(&mut body, "28P01");
        body.push(b'M');
        put_cstr(&mut body, "password authentication failed");
        body.push(0);
        let msg = framed(b'E', &body);
        assert_eq!(
            read_message(&mut &msg[..]).unwrap(),
            Backend::Error("FATAL 28P01: password authentication failed".into())
        );
    }
}
