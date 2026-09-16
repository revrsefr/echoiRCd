//! Minimal RESP (REdis Serialization Protocol, v2) codec — no unsafe, no deps.
//! Enough to drive the command + pub/sub client: encode a command as an array of
//! bulk strings, decode a reply (simple string, error, integer, bulk, array, nil).

use std::io::{self, BufRead};

/// A decoded RESP reply.
#[derive(Debug, Clone)]
pub enum Value {
    Nil,
    Int(i64),
    Simple(String), // +OK
    Bulk(Vec<u8>),  // $<len> …
    Array(Vec<Value>),
    Error(String), // -ERR …
}

impl Value {
    /// The bulk/simple body as a UTF-8 string (lossy), or `None` for other kinds.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Value::Bulk(b) => Some(String::from_utf8_lossy(b).into_owned()),
            Value::Simple(s) => Some(s.clone()),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }
    /// The array elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(v) => Some(v),
            _ => None,
        }
    }
}

/// Encode a command as a RESP array of bulk strings: `*N\r\n$len\r\narg\r\n…`.
pub fn encode(args: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + args.iter().map(|a| a.len() + 16).sum::<usize>());
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Read one RESP reply from a buffered reader (blocking — runs off the core).
pub fn read_reply<R: BufRead>(r: &mut R) -> io::Result<Value> {
    let mut line = Vec::new();
    read_line(r, &mut line)?;
    let Some((&tag, rest)) = line.split_first() else {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty RESP line"));
    };
    let text = String::from_utf8_lossy(rest);
    match tag {
        b'+' => Ok(Value::Simple(text.into_owned())),
        b'-' => Ok(Value::Error(text.into_owned())),
        b':' => Ok(Value::Int(text.trim().parse().map_err(bad)?)),
        b'$' => {
            let n: i64 = text.trim().parse().map_err(bad)?;
            if n < 0 {
                return Ok(Value::Nil);
            }
            let mut buf = vec![0u8; n as usize + 2]; // payload + CRLF
            r.read_exact(&mut buf)?;
            buf.truncate(n as usize);
            Ok(Value::Bulk(buf))
        }
        b'*' => {
            let n: i64 = text.trim().parse().map_err(bad)?;
            if n < 0 {
                return Ok(Value::Nil);
            }
            let mut items = Vec::with_capacity(n.min(1024) as usize);
            for _ in 0..n {
                items.push(read_reply(r)?);
            }
            Ok(Value::Array(items))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown RESP tag")),
    }
}

/// Read one line, stripping the trailing CRLF (or bare LF).
fn read_line<R: BufRead>(r: &mut R, out: &mut Vec<u8>) -> io::Result<()> {
    out.clear();
    if r.read_until(b'\n', out)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
    }
    while matches!(out.last(), Some(b'\n' | b'\r')) {
        out.pop();
    }
    Ok(())
}

fn bad<E>(_: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed RESP number")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn encode_is_a_resp_array() {
        assert_eq!(encode(&[b"GET".to_vec(), b"k".to_vec()]), b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n");
    }

    #[test]
    fn decodes_each_reply_type() {
        let mut r = BufReader::new(&b"+OK\r\n"[..]);
        assert!(matches!(read_reply(&mut r).unwrap(), Value::Simple(s) if s == "OK"));
        let mut r = BufReader::new(&b":42\r\n"[..]);
        assert_eq!(read_reply(&mut r).unwrap().as_int(), Some(42));
        let mut r = BufReader::new(&b"$5\r\nhello\r\n"[..]);
        assert_eq!(read_reply(&mut r).unwrap().as_str().as_deref(), Some("hello"));
        let mut r = BufReader::new(&b"$-1\r\n"[..]);
        assert!(matches!(read_reply(&mut r).unwrap(), Value::Nil));
        let mut r = BufReader::new(&b"-ERR nope\r\n"[..]);
        assert!(matches!(read_reply(&mut r).unwrap(), Value::Error(e) if e == "ERR nope"));
        let mut r = BufReader::new(&b"*2\r\n$3\r\nfoo\r\n:7\r\n"[..]);
        let v = read_reply(&mut r).unwrap();
        let a = v.as_array().unwrap();
        assert_eq!(a[0].as_str().as_deref(), Some("foo"));
        assert_eq!(a[1].as_int(), Some(7));
    }
}
