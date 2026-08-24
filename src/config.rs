//! Tiny `key = value` config (no XML, no deps).
//!
//! ```text
//! servername = echo.devtronic.pro
//! network    = echoNet
//! bind       = 127.0.0.1:6767
//! motd       = Welcome to echoIRCd
//! oper       = god secret                        # name + password (+ optional level)
//! oper       = god password=<hash>               # same, named form (fp=/type= style)
//! oper       = god * fp=<sha256-cert-fp>         # cert-only login (no password)
//! oper       = god password=<hash> fp=<cert-fp>  # password AND matching cert
//! ```

use crate::map::HashMap;

/// Parse a boolean config value (`yes`/`no`/`true`/`false`/`on`/`off`/`1`/`0`).
pub fn yesish(v: &str) -> bool {
    !matches!(
        v.to_ascii_lowercase().as_str(),
        "off" | "no" | "false" | "0"
    )
}

/// Whether an oper token is a `key=value` option rather than the positional
/// password (so `oper = <name> password=<hash> fp=<fp>` isn't misread as having
/// the literal password `password=<hash>`).
fn is_oper_option(tok: &str) -> bool {
    tok.starts_with("password=")
        || tok.starts_with("fp=")
        || tok.starts_with("certfp=")
        || tok.starts_with("type=")
}

/// A server-link block: how to authenticate a peer named `name` (and, if
/// `autoconnect`, where to dial it). Passwords are the shared link secret.
#[derive(Clone)]
pub struct LinkBlock {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub password: String,
    pub autoconnect: bool,
}

/// An oper login: `oper = <name> [<password|*> | password=<hash>] [level]
/// [fp=<sha256-fingerprint>] [type=<id>]`. The password may be given positionally
/// or as a `password=` token; `*` (or an absent password with a `fp=`) means no
/// password is checked (cert-only login); a `fp=` token requires the user's TLS
/// client-certificate SHA-256 fingerprint to match.
#[derive(Clone, Default)]
pub struct OperBlock {
    pub name: String,
    pub password: String,
    pub level: u32,
    pub fingerprint: Option<String>,
    pub oper_type: Option<String>,
}

/// Per-SNI branding: a client that connected via `host` (TLS SNI) is shown
/// `servername`/`network` instead of the global ones — one daemon, multiple
/// network identities. Repeatable.
#[derive(Clone, Default)]
pub struct BrandBlock {
    pub host: String,
    pub servername: String,
    pub network: String,
}

/// A trusted WEBIRC gateway: after presenting `password` it may rewrite a client's
/// real host + IP. `ipmask` (empty = any) restricts which source addresses may use
/// this block.
#[derive(Clone)]
pub struct WebircGateway {
    pub password: String,
    pub name: String,
    pub ipmask: String,
}

/// A +G censor rule: substitute `find` -> `replace` in channel text; an empty
/// `replace` blocks the message instead of rewriting it.
#[derive(Clone)]
pub struct CensorRule {
    pub find: String,
    pub replace: String,
}

/// Config for the `antimixedutf8` module (blocks mixed-script look-alike spam).
#[derive(Clone)]
pub struct AntiMixedCfg {
    pub enable: bool,
    pub threshold: u32,
    pub minlen: usize,
    pub action: String, // block | kill | gline | kline | zline
    pub duration: u64,  // seconds, for the *line actions
    pub reason: String,
    pub block_msg: String, // notice text sent on the "block" action
    pub check_channel: bool,
    pub check_private: bool,
}

impl Default for AntiMixedCfg {
    fn default() -> AntiMixedCfg {
        AntiMixedCfg {
            enable: false,
            threshold: 8,
            minlen: 10,
            action: "block".to_string(),
            duration: 3600,
            reason: "Mixed-script text (spam).".to_string(),
            block_msg: "Your message contains mixed look-alike characters often used by \
                        spam. Please rewrite it and try again."
                .to_string(),
            check_channel: true,
            check_private: true,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub servername: String,
    pub network: String,
    pub bind: Vec<String>,      // plaintext client listeners (repeatable; e.g. [::]:6667)
    pub bind_tls: Vec<String>,  // TLS client listeners (repeatable; e.g. [::]:6697)
    pub tls_cert: Option<String>, // PEM certificate chain
    pub tls_key: Option<String>,  // PEM private key
    pub motd: Vec<String>,
    pub opers: Vec<OperBlock>,                 // oper logins (see OperBlock)
    pub brands: Vec<BrandBlock>,               // per-SNI server/network branding
    pub cloak_key: Option<String>,             // secret key for host cloaking (+x); None = off
    pub sid: String,                           // this server's 3-char server id (S2S)
    pub serverdesc: String,                    // this server's description
    pub bind_server: Vec<String>,              // server-to-server link listeners (repeatable)
    pub links: Vec<LinkBlock>,                 // peers we accept / dial
    pub conf_path: String,                     // where this was loaded from (for REHASH)
    pub censor: Vec<CensorRule>,       // +G bad words (empty replace = block)
    pub amu: AntiMixedCfg,             // antimixedutf8 module config
    pub resolve_hosts: bool,           // reverse-DNS clients on connect (default on)
    pub use_resolved_host: bool,       // put the resolved hostname in the hostmask (default on)
    pub dnsbl_zones: Vec<crate::modules::dnsbl::DnsblZone>, // DNS blocklists to check on connect
    pub dnsbl_action: String,          // mark | kline | gline | zline (on a hit)
    pub dnsbl_reason: String,          // ban reason for a DNSBL hit
    pub sasl_server: String,           // linked services server that handles SASL ("" = none)
    pub webirc: Vec<WebircGateway>,            // trusted web gateways
    /// Every `key = value` line, captured raw so modules read their own settings
    /// via `Server::conf*` — no per-module field bloats this struct or `Server`.
    pub raw: HashMap<String, Vec<String>>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            servername: "echo.local".to_string(),
            network: "echoNet".to_string(),
            bind: Vec::new(),
            bind_tls: Vec::new(),
            tls_cert: None,
            tls_key: None,
            motd: Vec::new(),
            opers: Vec::new(),
            brands: Vec::new(),
            cloak_key: None,
            sid: "0AA".to_string(),
            serverdesc: "echoIRCd server".to_string(),
            bind_server: Vec::new(),
            links: Vec::new(),
            conf_path: "echoircd.conf".to_string(),
            censor: Vec::new(),
            amu: AntiMixedCfg::default(),
            resolve_hosts: true,
            use_resolved_host: true,
            dnsbl_zones: Vec::new(),
            dnsbl_action: "mark".to_string(),
            dnsbl_reason: "Your host is listed in a DNS blocklist".to_string(),
            sasl_server: String::new(),
            webirc: Vec::new(),
            raw: HashMap::default(),
        }
    }
}

impl Config {
    /// Read a config file, falling back to defaults for anything missing. A
    /// missing file is not an error — you get the defaults.
    pub fn load(path: &str) -> Config {
        let mut c = Config {
            conf_path: path.to_string(),
            ..Config::default()
        };
        if let Ok(text) = std::fs::read_to_string(path) {
            Self::parse_into(&mut c, &text);
        }
        c
    }

    /// Like [`load`](Config::load) but returns `None` if the file can't be read,
    /// so REHASH can keep the running config instead of resetting to defaults.
    pub fn try_load(path: &str) -> Option<Config> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut c = Config {
            conf_path: path.to_string(),
            ..Config::default()
        };
        Self::parse_into(&mut c, &text);
        Some(c)
    }

    /// A deterministic text dump of every parsed key/value (sorted), used by
    /// `echoircd checkconfig` to compare two configs regardless of source format.
    pub fn dump(&self) -> String {
        let mut keys: Vec<&String> = self.raw.keys().collect();
        keys.sort();
        let mut out = String::new();
        for k in keys {
            for v in &self.raw[k] {
                out.push_str(k);
                out.push_str(" = ");
                out.push_str(v);
                out.push('\n');
            }
        }
        out
    }

    // small helper is defined at module scope (see `yesish`).

    /// Parse `key = value` lines into `c`; unknown keys and comments are ignored.
    fn parse_into(c: &mut Config, text: &str) {
        // Two accepted syntaxes: the brace/block format and the legacy flat
        // `key = value` format. A top-level `name {` selects blocks, which are
        // translated to the flat form and re-parsed through this same path, so
        // the two formats can never diverge.
        if looks_like_blocks(text) {
            let flat = blocks_to_flat(text);
            Self::parse_into(c, &flat);
            return;
        }
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            // Every line is captured raw so a module can read its own settings via
            // `Server::conf*` without a typed field bloating config.rs / server.rs.
            c.raw.entry(k.to_string()).or_default().push(v.to_string());
            match k {
                "servername" | "server" => c.servername = v.to_string(),
                "network" => c.network = v.to_string(),
                "bind" => c.bind.push(v.to_string()),
                "bind_tls" => c.bind_tls.push(v.to_string()),
                "tls_cert" => c.tls_cert = Some(v.to_string()),
                "tls_key" => c.tls_key = Some(v.to_string()),
                "cloak_key" => c.cloak_key = Some(v.to_string()),
                "sid" => c.sid = v.to_string(),
                "serverdesc" | "description" => c.serverdesc = v.to_string(),
                "bind_server" => c.bind_server.push(v.to_string()),
                "link" => {
                    // link = <name> <ip> <port> <password> [autoconnect]
                    let t: Vec<&str> = v.split_whitespace().collect();
                    if t.len() >= 4 {
                        if let Ok(port) = t[2].parse::<u16>() {
                            c.links.push(LinkBlock {
                                name: t[0].to_string(),
                                ip: t[1].to_string(),
                                port,
                                password: t[3].to_string(),
                                autoconnect: t.get(4).is_some_and(|a| {
                                    a.eq_ignore_ascii_case("autoconnect")
                                        || a.eq_ignore_ascii_case("connect")
                                }),
                            });
                        }
                    }
                }
                "motd" => c.motd.push(v.to_string()),
                "brand" => {
                    // brand = <host> [servername=<sv>] [network=<nw>]
                    let mut it = v.split_whitespace();
                    if let Some(host) = it.next() {
                        let mut b = BrandBlock {
                            host: host.to_ascii_lowercase(),
                            ..Default::default()
                        };
                        for tok in it {
                            if let Some(s) = tok.strip_prefix("servername=") {
                                b.servername = s.to_string();
                            } else if let Some(n) = tok.strip_prefix("network=") {
                                b.network = n.to_string();
                            }
                        }
                        c.brands.push(b);
                    }
                }
                "oper" => {
                    let mut it = v.split_whitespace().peekable();
                    if let Some(n) = it.next() {
                        let mut b = OperBlock {
                            name: n.to_string(),
                            ..Default::default()
                        };
                        // Back-compat: a bare second token (not a `key=value` option)
                        // is the positional password (`*` = cert-only), matching the
                        // old `oper = <name> <password|*> ...` form.
                        if let Some(tok) = it.peek() {
                            if !is_oper_option(tok) {
                                b.password = tok.to_string();
                                it.next();
                            }
                        }
                        // Named options in any order: `password=` (preferred),
                        // `fp=`/`certfp=` the required TLS cert fingerprint, `type=`
                        // the oper type; a bare number is the operlevel.
                        for tok in it {
                            if let Some(pw) = tok.strip_prefix("password=") {
                                b.password = pw.to_string();
                            } else if let Some(fp) =
                                tok.strip_prefix("fp=").or_else(|| tok.strip_prefix("certfp="))
                            {
                                b.fingerprint = Some(fp.to_ascii_lowercase());
                            } else if let Some(t) = tok.strip_prefix("type=") {
                                b.oper_type = Some(t.to_string());
                            } else if let Ok(l) = tok.parse::<u32>() {
                                b.level = l;
                            }
                        }
                        // A block with no credential at all (no password, no cert
                        // fingerprint) would let anyone oper up — refuse it, as the
                        // old parser did by requiring a password token.
                        if !b.password.is_empty() || b.fingerprint.is_some() {
                            c.opers.push(b);
                        }
                    }
                }
                // +G censor word: `badword = <find> [replace]` (no replace ⇒ block)
                "badword" => {
                    let mut it = v.splitn(2, char::is_whitespace);
                    if let Some(find) = it.next().filter(|f| !f.is_empty()) {
                        let replace = it.next().unwrap_or("").trim().to_string();
                        c.censor.push(CensorRule { find: find.to_string(), replace });
                    }
                }
                "antimixedutf8" | "amu" => {
                    c.amu.enable =
                        matches!(v.to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1")
                }
                "amu_threshold" => {
                    if let Ok(n) = v.parse() {
                        c.amu.threshold = n;
                    }
                }
                "amu_minlen" => {
                    if let Ok(n) = v.parse() {
                        c.amu.minlen = n;
                    }
                }
                "amu_action" => c.amu.action = v.to_string(),
                "amu_duration" => {
                    if let Some(d) = crate::xline::parse_duration(v) {
                        c.amu.duration = d;
                    }
                }
                "amu_reason" => c.amu.reason = v.to_string(),
                "amu_message" => c.amu.block_msg = v.to_string(),
                "amu_target" => {
                    let t = v.to_ascii_lowercase();
                    c.amu.check_channel = t == "both" || t == "channel";
                    c.amu.check_private = t == "both" || t == "private";
                }
                "resolve_hosts" | "resolvehosts" | "dns" => {
                    c.resolve_hosts = !matches!(
                        v.to_ascii_lowercase().as_str(),
                        "off" | "false" | "no" | "0"
                    )
                }
                "use_resolved_host" | "resolved_hostmask" | "hostmask_dns" => {
                    c.use_resolved_host = !matches!(
                        v.to_ascii_lowercase().as_str(),
                        "off" | "false" | "no" | "0"
                    )
                }
                "dnsbl" | "dnsbl_zone" => {
                    if let Some(z) = crate::modules::dnsbl::parse_zone(v) {
                        c.dnsbl_zones.push(z);
                    }
                }
                "dnsbl_action" => c.dnsbl_action = v.to_ascii_lowercase(),
                "dnsbl_reason" => c.dnsbl_reason = v.to_string(),
                "sasl_server" | "sasl_target" => c.sasl_server = v.to_string(),
                "webirc" => {
                    // webirc = <password> [gateway-name] [ip-mask]
                    let mut it = v.split_whitespace();
                    if let Some(pass) = it.next() {
                        let gw = it.next().unwrap_or("webirc").to_string();
                        let mask = it.next().unwrap_or("").to_string();
                        c.webirc.push(WebircGateway {
                            password: pass.to_string(),
                            name: gw,
                            ipmask: mask,
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

// ─── block/brace config parser ──────────────────────────────────────────────
// The brace format (`server { name "x"; ... }`) is translated to the flat
// `key = value` text that `parse_into` already understands, so both syntaxes
// funnel through one code path and can never diverge. Structural blocks map
// their short field names onto the internal keys / entity line grammars; every
// other block (`set`, `limits`, …) is cosmetic grouping whose fields are flat
// keys, so the long tail of module options needs no per-key mapping.

#[derive(PartialEq, Eq)]
enum Tok {
    Open,
    Close,
    Semi,
    Word(String),
}

/// A file is in block format if some non-comment line is `identifier {` — the
/// flat `key = value` format never puts a bare identifier before an unquoted `{`.
fn looks_like_blocks(text: &str) -> bool {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        if let Some(pos) = line.find('{') {
            let head = line[..pos].trim();
            if !head.is_empty()
                && !head.contains('=')
                && head
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                return true;
            }
        }
    }
    false
}

/// Tokenize the block format: `{ } ;`, quoted strings, and bare words. Line
/// (`#`, `//`) and block (`/* */`) comments are skipped.
fn tokenize(text: &str) -> Vec<Tok> {
    let c: Vec<char> = text.chars().collect();
    let n = c.len();
    let mut i = 0;
    let mut toks = Vec::new();
    while i < n {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        if ch == '#' || (ch == '/' && i + 1 < n && c[i + 1] == '/') {
            while i < n && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && i + 1 < n && c[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(c[i] == '*' && c[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        match ch {
            '{' => {
                toks.push(Tok::Open);
                i += 1;
            }
            '}' => {
                toks.push(Tok::Close);
                i += 1;
            }
            ';' => {
                toks.push(Tok::Semi);
                i += 1;
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                while i < n {
                    if c[i] == '\\' && i + 1 < n {
                        s.push(match c[i + 1] {
                            'n' => '\n',
                            't' => '\t',
                            o => o,
                        });
                        i += 2;
                        continue;
                    }
                    if c[i] == '"' {
                        i += 1;
                        break;
                    }
                    s.push(c[i]);
                    i += 1;
                }
                toks.push(Tok::Word(s));
            }
            _ => {
                let mut s = String::new();
                while i < n {
                    let x = c[i];
                    if x.is_whitespace() || x == '{' || x == '}' || x == ';' || x == '"' {
                        break;
                    }
                    if x == '#' {
                        break;
                    }
                    if x == '/' && i + 1 < n && (c[i + 1] == '/' || c[i + 1] == '*') {
                        break;
                    }
                    s.push(x);
                    i += 1;
                }
                toks.push(Tok::Word(s));
            }
        }
    }
    toks
}

/// Translate block syntax into the equivalent flat `key = value` text.
fn blocks_to_flat(text: &str) -> String {
    let toks = tokenize(text);
    let n = toks.len();
    let mut i = 0;
    let mut out = String::new();
    while i < n {
        let name = match &toks[i] {
            Tok::Word(w) => w.clone(),
            _ => {
                i += 1;
                continue;
            }
        };
        i += 1;
        if i < n && toks[i] == Tok::Open {
            i += 1;
            let mut fields: Vec<(String, String)> = Vec::new();
            while i < n && toks[i] != Tok::Close {
                let field = match &toks[i] {
                    Tok::Word(w) => w.clone(),
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                i += 1;
                let mut vals = Vec::new();
                while i < n && toks[i] != Tok::Semi && toks[i] != Tok::Close {
                    if let Tok::Word(w) = &toks[i] {
                        vals.push(w.clone());
                    }
                    i += 1;
                }
                if i < n && toks[i] == Tok::Semi {
                    i += 1;
                }
                fields.push((field, vals.join(" ")));
            }
            if i < n {
                i += 1; // consume `}`
            }
            emit_block(&mut out, &name, &fields);
        } else {
            // top-level `key value... ;` with no braces
            let mut vals = Vec::new();
            while i < n && toks[i] != Tok::Semi {
                if let Tok::Word(w) = &toks[i] {
                    vals.push(w.clone());
                }
                i += 1;
            }
            if i < n {
                i += 1;
            }
            emit_line(&mut out, &name, &vals.join(" "));
        }
    }
    out
}

fn emit_line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(&value.replace('\n', " "));
    out.push('\n');
}

/// Expand one block into flat `key = value` lines.
fn emit_block(out: &mut String, name: &str, fields: &[(String, String)]) {
    let get = |k: &str| {
        fields
            .iter()
            .find(|(f, _)| f.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    };
    match name.to_ascii_lowercase().as_str() {
        "server" => {
            if let Some(v) = get("name") {
                emit_line(out, "servername", v);
            }
            if let Some(v) = get("network") {
                emit_line(out, "network", v);
            }
            if let Some(v) = get("sid") {
                emit_line(out, "sid", v);
            }
            if let Some(v) = get("description").or_else(|| get("desc")) {
                emit_line(out, "description", v);
            }
            if let Some(v) = get("pidfile") {
                emit_line(out, "pidfile", v);
            }
        }
        "tls" => {
            // backend/cert/key map to their tls_ keys; any other field (sni,
            // handshake_timeout, …) passes through as tls_<field>, repeatable.
            for (f, v) in fields {
                let fl = f.to_ascii_lowercase();
                let key = match fl.as_str() {
                    "backend" => "tls_backend".to_string(),
                    "cert" => "tls_cert".to_string(),
                    "key" => "tls_key".to_string(),
                    other => format!("tls_{other}"),
                };
                emit_line(out, &key, v);
            }
        }
        "cloak" => {
            if let Some(v) = get("key") {
                emit_line(out, "cloak_key", v);
            }
            if let Some(v) = get("method") {
                emit_line(out, "cloak_method", v);
            }
            if let Some(v) = get("static_host").or_else(|| get("static")) {
                emit_line(out, "cloak_static_host", v);
            }
            if let Some(v) = get("account_prefix") {
                emit_line(out, "cloak_account_prefix", v);
            }
            if let Some(v) = get("cert_prefix") {
                emit_line(out, "cloak_cert_prefix", v);
            }
        }
        "brand" => {
            if let Some(host) = get("host") {
                let mut line = host.to_string();
                if let Some(v) = get("servername") {
                    line.push_str(" servername=");
                    line.push_str(v);
                }
                if let Some(v) = get("network") {
                    line.push_str(" network=");
                    line.push_str(v);
                }
                emit_line(out, "brand", &line);
            }
        }
        "listen" => {
            if let (Some(ip), Some(port)) = (get("ip"), get("port")) {
                let addr = if ip.contains(':') && !ip.starts_with('[') {
                    format!("[{ip}]:{port}")
                } else {
                    format!("{ip}:{port}")
                };
                let key = if get("type").is_some_and(|t| t.eq_ignore_ascii_case("server")) {
                    "bind_server"
                } else if get("wss").is_some_and(yesish) {
                    "bind_wss"
                } else if get("tls").is_some_and(yesish) {
                    "bind_tls"
                } else {
                    "bind"
                };
                emit_line(out, key, &addr);
            }
        }
        "oper" => {
            if let Some(nm) = get("name") {
                let mut line = nm.to_string();
                if let Some(pw) = get("password") {
                    line.push_str(" password=");
                    line.push_str(pw);
                }
                if let Some(fp) = get("fingerprint")
                    .or_else(|| get("fp"))
                    .or_else(|| get("certfp"))
                {
                    line.push_str(" fp=");
                    line.push_str(fp);
                }
                if let Some(t) = get("type") {
                    line.push_str(" type=");
                    line.push_str(t);
                }
                if let Some(l) = get("level") {
                    line.push(' ');
                    line.push_str(l);
                }
                emit_line(out, "oper", &line);
            }
        }
        n @ ("opertype" | "class") => {
            if let Some(nm) = get("name") {
                let mut line = nm.to_string();
                for (f, v) in fields {
                    if f.eq_ignore_ascii_case("name") {
                        continue;
                    }
                    line.push(' ');
                    line.push_str(f);
                    line.push('=');
                    line.push_str(v);
                }
                emit_line(out, n, &line);
            }
        }
        "link" => {
            if let (Some(nm), Some(ip), Some(port), Some(pw)) =
                (get("name"), get("ip"), get("port"), get("password"))
            {
                let mut line = format!("{nm} {ip} {port} {pw}");
                if get("autoconnect").is_some_and(yesish) {
                    line.push_str(" autoconnect");
                }
                emit_line(out, "link", &line);
                // `services yes` also marks the peer as a U-lined services server.
                if get("services").is_some_and(yesish) || get("uline").is_some_and(yesish) {
                    emit_line(out, "uline", nm);
                }
            }
        }
        "webirc" => {
            if let Some(pw) = get("password") {
                let gw = get("name").or_else(|| get("gateway")).unwrap_or("webirc");
                let mask = get("mask").or_else(|| get("ipmask")).unwrap_or("");
                emit_line(out, "webirc", format!("{pw} {gw} {mask}").trim_end());
            }
        }
        motd @ ("motd" | "opermotd") => {
            for (f, v) in fields {
                let line = if v.is_empty() {
                    f.clone()
                } else {
                    format!("{f} {v}")
                };
                emit_line(out, motd, &line);
            }
        }
        // grouping blocks (set, limits, …): each field is a flat key; a bare
        // field with no value (`operprefix;`) enables it.
        _ => {
            for (f, v) in fields {
                emit_line(out, f, if v.is_empty() { "yes" } else { v });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opers(text: &str) -> Vec<OperBlock> {
        let mut c = Config::default();
        Config::parse_into(&mut c, text);
        c.opers
    }

    fn cfg(text: &str) -> Config {
        let mut c = Config::default();
        Config::parse_into(&mut c, text);
        c
    }

    #[test]
    fn block_server_and_set() {
        let c = cfg(r#"
            server {
                name    "irc.example.org";
                network "ExampleNet";
                sid     0AB;
            }
            set {
                operprefix yes;
                nicklen    30;
            }
        "#);
        assert_eq!(c.servername, "irc.example.org");
        assert_eq!(c.network, "ExampleNet");
        assert_eq!(c.sid, "0AB");
        assert_eq!(c.raw.get("operprefix").map(|v| v[0].as_str()), Some("yes"));
        assert_eq!(c.raw.get("nicklen").map(|v| v[0].as_str()), Some("30"));
    }

    #[test]
    fn block_oper_and_credential_guard() {
        let c = cfg(r#"
            oper {
                name     "reverse";
                password "$2b$11$abc.def/ghi";
                type     netadmin;
            }
            oper { name "ghost"; }   // no credential -> dropped
        "#);
        assert_eq!(c.opers.len(), 1);
        assert_eq!(c.opers[0].name, "reverse");
        assert_eq!(c.opers[0].password, "$2b$11$abc.def/ghi");
        assert_eq!(c.opers[0].oper_type.as_deref(), Some("netadmin"));
    }

    #[test]
    fn block_listen_picks_bind_key() {
        let c = cfg(r#"
            listen { ip "*"; port 6667; }
            listen { ip "*"; port 6697; tls yes; }
            listen { ip 127.0.0.1; port 7700; type server; }
        "#);
        assert!(c.bind.iter().any(|b| b == "*:6667"));
        assert!(c.bind_tls.iter().any(|b| b == "*:6697"));
        assert!(c.bind_server.iter().any(|b| b == "127.0.0.1:7700"));
    }

    #[test]
    fn block_link_and_comments() {
        let c = cfg(r#"
            # a link block, mixed comment styles
            link {
                name        "services.example.org";
                ip          127.0.0.1;  /* loopback */
                port        7700;
                password    "s3cr3t";
                autoconnect yes;
            }
        "#);
        assert_eq!(c.links.len(), 1);
        assert_eq!(c.links[0].name, "services.example.org");
        assert_eq!(c.links[0].port, 7700);
        assert_eq!(c.links[0].password, "s3cr3t");
        assert!(c.links[0].autoconnect);
    }

    #[test]
    fn block_and_flat_agree() {
        let flat = cfg("servername = irc.x\noper = reverse password=$2b$11$z type=netadmin\n");
        let block = cfg(
            "server { name \"irc.x\"; }\noper { name reverse; password \"$2b$11$z\"; type netadmin; }\n",
        );
        assert_eq!(flat.servername, block.servername);
        assert_eq!(flat.opers.len(), block.opers.len());
        assert_eq!(flat.opers[0].password, block.opers[0].password);
        assert_eq!(flat.opers[0].oper_type, block.opers[0].oper_type);
    }

    #[test]
    fn shipped_example_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/echoircd.conf.example");
        let text = std::fs::read_to_string(path).expect("example config present");
        let c = cfg(&text);
        assert_eq!(c.servername, "irc.example.net");
        assert_eq!(c.network, "ExampleNet");
        assert!(c.bind.iter().any(|b| b.ends_with(":6667")));
        assert!(c.bind_tls.iter().any(|b| b.ends_with(":6697")));
        assert!(c.bind_server.iter().any(|b| b.ends_with(":7000")));
        assert_eq!(c.tls_cert.as_deref(), Some("./tls/cert.pem"));
        assert_eq!(c.opers.len(), 1);
        assert_eq!(c.opers[0].name, "admin");
        assert_eq!(c.opers[0].oper_type.as_deref(), Some("netadmin"));
        assert!(c.motd.len() >= 2);
        assert_eq!(
            c.raw.get("resolve_hosts").map(|v| v[0].as_str()),
            Some("yes")
        );
    }

    #[test]
    fn block_cloak_and_uline() {
        let c = cfg(r#"
            cloak { key "s3cret"; method "sha256"; static_host "user.example.org"; }
            link { name "svc.example.org"; ip 127.0.0.1; port 7700; password "p"; services yes; }
        "#);
        assert_eq!(c.cloak_key.as_deref(), Some("s3cret"));
        assert_eq!(c.raw.get("cloak_method").map(|v| v[0].as_str()), Some("sha256"));
        assert_eq!(
            c.raw.get("cloak_static_host").map(|v| v[0].as_str()),
            Some("user.example.org")
        );
        assert_eq!(c.raw.get("uline").map(|v| v[0].as_str()), Some("svc.example.org"));
    }

    #[test]
    fn block_repeated_list_field() {
        let c = cfg("modules { alias \"NS NickServ\"; alias \"CS ChanServ\"; }");
        let al = c.raw.get("alias").unwrap();
        assert_eq!(al.len(), 2);
        assert_eq!(al[0], "NS NickServ");
        assert_eq!(al[1], "CS ChanServ");
    }

    #[test]
    fn block_quoted_string_with_spaces() {
        let c = cfg("server { name \"irc.x\"; description \"A friendly server\"; }");
        assert_eq!(c.serverdesc, "A friendly server");
    }

    #[test]
    fn positional_password_still_parses() {
        let o = opers("oper = god secret 5 fp=ABC type=netadmin");
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].name, "god");
        assert_eq!(o[0].password, "secret");
        assert_eq!(o[0].level, 5);
        assert_eq!(o[0].fingerprint.as_deref(), Some("abc"));
        assert_eq!(o[0].oper_type.as_deref(), Some("netadmin"));
    }

    #[test]
    fn star_positional_is_cert_only() {
        let o = opers("oper = god * fp=abc");
        assert_eq!(o[0].password, "*");
        assert_eq!(o[0].fingerprint.as_deref(), Some("abc"));
    }

    #[test]
    fn numeric_positional_password_is_not_a_level() {
        // a bare second token is the password even when numeric (back-compat)
        let o = opers("oper = god 12345");
        assert_eq!(o[0].password, "12345");
        assert_eq!(o[0].level, 0);
    }

    #[test]
    fn named_password_token() {
        let o = opers("oper = reverse password=$2b$11$abc.def/ghi fp=FF type=netadmin");
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].name, "reverse");
        assert_eq!(o[0].password, "$2b$11$abc.def/ghi");
        assert_eq!(o[0].fingerprint.as_deref(), Some("ff"));
        assert_eq!(o[0].oper_type.as_deref(), Some("netadmin"));
    }

    #[test]
    fn named_password_order_independent() {
        let o = opers("oper = reverse type=admin fp=aa password=hunter2 3");
        assert_eq!(o[0].password, "hunter2");
        assert_eq!(o[0].level, 3);
        assert_eq!(o[0].fingerprint.as_deref(), Some("aa"));
        assert_eq!(o[0].oper_type.as_deref(), Some("admin"));
    }

    #[test]
    fn credential_less_block_is_rejected() {
        // no password and no fp would let anyone oper up — must be dropped
        assert!(opers("oper = nobody").is_empty());
        assert!(opers("oper = nobody type=netadmin").is_empty());
    }
}
