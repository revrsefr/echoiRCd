//! Tiny `key = value` config, same spirit as rubot.conf (no XML, no deps).
//!
//! ```text
//! servername = echo.devtronic.pro
//! network    = echoNet
//! bind       = 127.0.0.1:6767
//! motd       = Welcome to echoIRCd
//! oper       = god secret
//! ```

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
    pub bind: String,
    pub bind_tls: Option<String>, // e.g. 0.0.0.0:6697 — the TLS listener
    pub tls_cert: Option<String>, // PEM certificate chain
    pub tls_key: Option<String>,  // PEM private key
    pub motd: Vec<String>,
    pub opers: Vec<(String, String)>,          // (name, password)
    pub cloak_key: Option<String>,             // secret key for host cloaking (+x); None = off
    pub sid: String,                           // this server's 3-char server id (S2S)
    pub serverdesc: String,                    // this server's description
    pub bind_server: Option<String>,           // the server-to-server link listener
    pub links: Vec<LinkBlock>,                 // peers we accept / dial
    pub conf_path: String,                     // where this was loaded from (for REHASH)
    pub censor: Vec<(String, String)>, // +G bad words: (find, replace); empty replace = block
    pub amu: AntiMixedCfg,             // antimixedutf8 module config
    pub resolve_hosts: bool,           // reverse-DNS clients on connect (default on)
    pub use_resolved_host: bool,       // put the resolved hostname in the hostmask (default on)
    pub dnsbl_zones: Vec<String>,      // DNS blocklist zones to check on connect
    pub dnsbl_action: String,          // mark | kline | gline | zline (on a hit)
    pub dnsbl_reason: String,          // ban reason for a DNSBL hit
    pub sasl_server: String,           // linked services server that handles SASL ("" = none)
    pub webirc: Vec<(String, String, String)>, // web gateways: (password, name, ip-mask)
    pub opermotd: Vec<String>,         // OPERMOTD text, one line per entry
    pub vhosts: Vec<(String, String, String)>, // self-service vhosts: (user, pass, host)
    pub aliases: Vec<(String, String)>, // command aliases: (name, target-nick)
    pub connflood: Option<(u32, u64)>, // (max conns, per secs) from one IP before refusing
}

impl Default for Config {
    fn default() -> Config {
        Config {
            servername: "echo.local".to_string(),
            network: "echoNet".to_string(),
            bind: "127.0.0.1:6767".to_string(),
            bind_tls: None,
            tls_cert: None,
            tls_key: None,
            motd: Vec::new(),
            opers: Vec::new(),
            cloak_key: None,
            sid: "0AA".to_string(),
            serverdesc: "echoIRCd server".to_string(),
            bind_server: None,
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
            opermotd: Vec::new(),
            vhosts: Vec::new(),
            aliases: Vec::new(),
            connflood: None,
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
    /// so REHASH can keep the running config instead of resetting to defaults —
    /// the way InspIRCd keeps the old config when a reload fails.
    pub fn try_load(path: &str) -> Option<Config> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut c = Config {
            conf_path: path.to_string(),
            ..Config::default()
        };
        Self::parse_into(&mut c, &text);
        Some(c)
    }

    /// Parse `key = value` lines into `c`; unknown keys and comments are ignored.
    fn parse_into(c: &mut Config, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            match k {
                "servername" | "server" => c.servername = v.to_string(),
                "network" => c.network = v.to_string(),
                "bind" => c.bind = v.to_string(),
                "bind_tls" => c.bind_tls = Some(v.to_string()),
                "tls_cert" => c.tls_cert = Some(v.to_string()),
                "tls_key" => c.tls_key = Some(v.to_string()),
                "cloak_key" => c.cloak_key = Some(v.to_string()),
                "sid" => c.sid = v.to_string(),
                "serverdesc" | "description" => c.serverdesc = v.to_string(),
                "bind_server" => c.bind_server = Some(v.to_string()),
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
                "oper" => {
                    let mut it = v.split_whitespace();
                    if let (Some(n), Some(p)) = (it.next(), it.next()) {
                        c.opers.push((n.to_string(), p.to_string()));
                    }
                }
                // +G censor word: `badword = <find> [replace]` (no replace ⇒ block)
                "badword" => {
                    let mut it = v.splitn(2, char::is_whitespace);
                    if let Some(find) = it.next().filter(|f| !f.is_empty()) {
                        let replace = it.next().unwrap_or("").trim().to_string();
                        c.censor.push((find.to_string(), replace));
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
                    if !v.is_empty() {
                        c.dnsbl_zones.push(v.to_string());
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
                        c.webirc.push((pass.to_string(), gw, mask));
                    }
                }
                "opermotd" => c.opermotd.push(v.to_string()),
                "vhost" => {
                    // vhost = <user> <pass> <host>
                    let mut it = v.split_whitespace();
                    if let (Some(u), Some(p), Some(h)) = (it.next(), it.next(), it.next()) {
                        c.vhosts.push((u.to_string(), p.to_string(), h.to_string()));
                    }
                }
                "alias" => {
                    // alias = <command> <target-nick>   (e.g. `alias = NS NickServ`)
                    let mut it = v.split_whitespace();
                    if let (Some(name), Some(target)) = (it.next(), it.next()) {
                        c.aliases
                            .push((name.to_ascii_uppercase(), target.to_string()));
                    }
                }
                "connflood" => {
                    // connflood = <max> <secs>  — refuse >max connections/secs from one IP
                    let mut it = v.split_whitespace();
                    if let (Some(mx), Some(sc)) = (it.next(), it.next()) {
                        if let (Ok(mx), Ok(sc)) = (mx.parse::<u32>(), sc.parse::<u64>()) {
                            if mx > 0 && sc > 0 {
                                c.connflood = Some((mx, sc));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
