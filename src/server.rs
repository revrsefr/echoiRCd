//! The engine core: the `Server` struct that owns all state, the output
//! primitives (send / numeric / to_channel) and the connection lifecycle.
//! Per-subsystem behaviour lives beside its data — [`crate::users`] and
//! [`crate::channels`] add their own `impl Server` blocks. No locks: only the
//! single core thread ever holds a `Server`.

use std::cell::RefCell;
use crate::map::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::channels::Channel;
use crate::config::{Config, LinkBlock};
use crate::extensible::Extensible;
use crate::ircd::Event;
use crate::link::{Link, RemoteServer, RemoteUser};
use crate::module::Hook;
use crate::modules::dnsbl;
use crate::resolver;
use crate::socketengine::{LineBuf, OutSink};
use crate::users::{Caps, User, UserFlags};
use crate::xline::XLine;
use crate::Uid;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The wire version token, major only (e.g. `echoircd-5`), for 002/004/351.
pub const RELEASE: &str = env!("CARGO_PKG_VERSION_MAJOR");
// Build provenance, captured by build.rs.
pub const GIT_HASH: &str = env!("ECHOIRCD_GIT_HASH");
pub const GIT_DIRTY: &str = env!("ECHOIRCD_GIT_DIRTY");
pub const COMMIT_DATE: &str = env!("ECHOIRCD_COMMIT_DATE");
pub const RUSTC: &str = env!("ECHOIRCD_RUSTC");
pub const TARGET: &str = env!("ECHOIRCD_TARGET");

/// The `RPL_VERSION` (351) comment: full version, build, and toolchain.
pub fn version_comment() -> String {
    format!("echoircd {VERSION} · {GIT_HASH}{GIT_DIRTY} · built {COMMIT_DATE} · rustc {RUSTC} · {TARGET}")
}

/// Background timer cadence + idle/ping timeouts, in seconds.
pub const TICK_SECS: u64 = 15;
pub const PING_AFTER: u64 = 90;
pub const PING_TIMEOUT: u64 = 60;
pub const REG_TIMEOUT: u64 = 60;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a unix timestamp as an IRCv3 `server-time` tag value
/// (`2026-08-05T07:58:03.000Z`), computing the civil date with std only.
/// The UTC civil date/time for a unix timestamp: `(year, month, day, hour,
/// minute, second)`. Howard Hinnant's days-from-civil, inverted — the single
/// place the calendar conversion lives, shared by `iso_time` and `long_date`.
fn civil(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let days = (secs / 86400) as i64;
    let (h, mi, s) = ((secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, h, mi, s)
}

pub fn iso_time(secs: u64) -> String {
    let (y, m, d, h, mi, s) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.000Z")
}

/// A unix time as `Fri 28 Aug 2026 13:45:29` (UTC) — the long form used in the
/// XLINE server notice for a ban's absolute expiry: the shared [`civil`]
/// conversion plus a weekday (1970-01-01 was a Thursday).
pub fn long_date(secs: u64) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m, d, h, mi, s) = civil(secs);
    let wd = (secs / 86400 + 4) % 7; // days since the epoch Thursday; 0 = Sunday
    format!(
        "{} {d:02} {} {y:04} {h:02}:{mi:02}:{s:02}",
        WD[wd as usize],
        MO[(m - 1) as usize]
    )
}

/// Parse an IRCv3 `server-time` value (`2026-08-08T19:52:42.000Z`) back to unix
/// seconds — the inverse of [`iso_time`], for CHATHISTORY `timestamp=` selectors.
pub fn parse_iso(s: &str) -> Option<u64> {
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let mo: i64 = d.next()?.parse().ok()?;
    let da: i64 = d.next()?.parse().ok()?;
    let time = time.trim_end_matches('Z').split('.').next()?;
    let mut t = time.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let se: i64 = t.next().unwrap_or("0").parse().ok()?;
    // bound every field to a sane range: keeps the arithmetic below well inside i64
    // (a client-supplied huge year/day would otherwise overflow and panic)
    if !(0..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&da)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&mi)
        || !(0..=60).contains(&se)
    {
        return None;
    }
    // civil date -> days since 1970-01-01
    let yy = y - i64::from(mo <= 2);
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se).max(0) as u64)
}

/// A recently-departed identity, kept for WHOWAS.
pub struct WhowasEntry {
    pub nick: String,
    pub ident: String,
    pub host: String,
    pub realname: String,
    pub account: Option<String>,
    pub ts: u64,
}

/// One captured server log line (fed by `snotice`), for the RPC `log.tail` /
/// `log.events` methods. In-memory ring, not a log file.
pub struct LogLine {
    pub id: u64,
    pub ts: u64,
    pub msg: String,
}

/// The rolling server-log ring plus its monotonic sequence counter.
#[derive(Default)]
pub struct LogState {
    pub seq: u64,
    pub ring: VecDeque<LogLine>,
}

pub struct Server {
    pub name: String,
    pub network: String,
    pub created: u64,
    pub motd: Vec<String>,
    pub users: HashMap<Uid, User>,
    pub nick_index: HashMap<String, Uid>,   // lower nick -> uid
    pub channels: HashMap<String, Channel>, // lower name -> channel
    pub events: VecDeque<Hook>,
    pub opers: Vec<crate::config::OperBlock>, // oper logins from config
    pub brands: Vec<crate::config::BrandBlock>, // per-SNI server/network branding
    pub catalog: crate::i18n::Catalog, // active-locale message catalog (i18n; en = passthrough)
    pub help: crate::help::HelpBook,   // active-locale /HELP topics (help/<code>.conf)
    pub cloak_key: Option<String>,    // host-cloaking key (see modules::cloak)
    pub line_ctags: String,           // client-only tags of the line being handled
    // --- server-to-server (see crate::link) ---
    pub sid: String,                               // this server's 3-char id
    pub server_desc: String,                       // this server's description
    pub link_blocks: Vec<LinkBlock>,               // peers to accept / dial
    pub links: HashMap<Uid, Link>,                 // local link connections
    pub servers: HashMap<String, RemoteServer>,    // sid -> linked server
    pub uuid_counter: u64,                         // mints local user UIDs
    pub msgid_counter: u64,                        // mints IRCv3 `msgid` message tags
    pub uuid_local: HashMap<String, Uid>,          // local users, by network uuid
    pub remote_users: HashMap<String, RemoteUser>, // users on other servers
    pub remote_nick: HashMap<String, String>,      // lower nick -> remote uuid
    pub whowas: VecDeque<WhowasEntry>,             // recent nick history (WHOWAS)
    pub conf_path: String,                         // config path, for REHASH
    pub xlines: Vec<XLine>,                        // server bans (KLINE/GLINE/ZLINE)
    pub mode_sudo: bool,                           // SAMODE/SAKICK: bypass rank checks
    pub in_redirect: bool,                         // +L: guards against redirect loops
    pub censor: Vec<crate::config::CensorRule>,    // +G bad words
    pub amu: crate::config::AntiMixedCfg,          // antimixedutf8 module config
    pub resolve_hosts: bool,                       // reverse-DNS clients on connect
    pub use_resolved_host: bool,                   // apply the resolved name to the hostmask
    pub dnsbl_zones: Vec<crate::modules::dnsbl::DnsblZone>, // DNS blocklists checked on connect
    pub dnsbl_action: String,                      // mark | kline | gline | zline
    pub dnsbl_reason: String,                      // ban reason on a DNSBL hit
    pub sasl_server: String,                       // services server that handles SASL
    pub webirc: Vec<crate::config::WebircGateway>, // trusted web gateways
    /// Every `key = value` line from the config, so each module reads its own
    /// settings via [`Server::conf`] / [`conf_all`] / [`conf_bool`] / [`conf_num`]
    /// — no per-module field lives on this struct (module-per-file rule).
    pub raw_config: HashMap<String, Vec<String>>,
    /// Bumped on every rehash. Modules that parse config into a hot-path structure
    /// cache it in `ext` tagged with this value and re-parse only when it changes,
    /// so a REHASH can never leave a stale cache (see e.g. `modules::disable`).
    pub config_gen: u64,
    /// How many accept lists contain each (lowercased) nick. A quit only scans every
    /// user's accept list when the departing nick is actually accepted by someone —
    /// the common case (count 0) skips the O(users) scan. Maintained solely through
    /// `accept_add`/`accept_remove` and the quit path.
    pub accepted_nicks: HashMap<String, u32>,
    /// Reverse index (lowercased) nick -> uids WATCHing / MONITORing it, so an
    /// online/offline flip notifies only the watchers instead of scanning every user.
    /// Maintained solely through the `watch_index_*` / `monitor_index_*` helpers and quit.
    pub watch_by: HashMap<String, HashSet<Uid>>,
    pub monitor_by: HashMap<String, HashSet<Uid>>,
    // labeled-response: while Some((uid, buf)), that client's own responses are
    // diverted into `buf` instead of the socket, so `on_line` can wrap them with
    // the command's `label` (single tag, BATCH, or ACK). RefCell because the
    // output primitives are `&self`.
    pub label_capture: RefCell<Option<(Uid, Vec<String>)>>,
    /// Rolling in-memory server log (fed by `snotice`), read by the RPC log methods.
    pub log: RefCell<LogState>,
    pub event_tx: Sender<Event>,      // self-inject events (DNS results)
    pub conn_counter: Arc<AtomicU64>, // mints connection uids (for CONNECT dials)
    /// Module-owned server state, keyed by type. Each `modules/*.rs` stores its
    /// own struct here so features live in their own file instead of this one.
    pub ext: Extensible,
    /// Prometheus counters/gauges, shared with the scrape thread (modules::metrics).
    pub metrics: Arc<crate::modules::metrics::Metrics>,
}

impl Server {
    pub fn new(cfg: Config, event_tx: Sender<Event>, conn_counter: Arc<AtomicU64>) -> Server {
        let (catalog, i18n_warn) = crate::i18n::Catalog::load(
            cfg.raw.get("locale_dir").and_then(|v| v.last()).map(String::as_str).unwrap_or("lang"),
            cfg.raw.get("locale").and_then(|v| v.last()).map(String::as_str).unwrap_or("en"),
        );
        for w in &i18n_warn {
            eprintln!("echoircd: {w}");
        }
        let (help, help_warn) = crate::help::HelpBook::load(
            cfg.raw.get("help_dir").and_then(|v| v.last()).map(String::as_str).unwrap_or("help"),
            cfg.raw.get("locale").and_then(|v| v.last()).map(String::as_str).unwrap_or("en"),
        );
        for w in &help_warn {
            eprintln!("echoircd: {w}");
        }
        Server {
            name: cfg.servername,
            network: cfg.network,
            created: now(),
            motd: cfg.motd,
            users: HashMap::default(),
            nick_index: HashMap::default(),
            channels: HashMap::default(),
            events: VecDeque::new(),
            opers: cfg.opers,
            brands: cfg.brands,
            catalog,
            help,
            cloak_key: cfg.cloak_key,
            line_ctags: String::new(),
            sid: cfg.sid,
            server_desc: cfg.serverdesc,
            link_blocks: cfg.links,
            links: HashMap::default(),
            servers: HashMap::default(),
            uuid_counter: 0,
            msgid_counter: 0,
            uuid_local: HashMap::default(),
            remote_users: HashMap::default(),
            remote_nick: HashMap::default(),
            whowas: VecDeque::new(),
            conf_path: cfg.conf_path,
            xlines: Vec::new(),
            mode_sudo: false,
            in_redirect: false,
            censor: cfg.censor,
            amu: cfg.amu,
            resolve_hosts: cfg.resolve_hosts,
            use_resolved_host: cfg.use_resolved_host,
            dnsbl_zones: cfg.dnsbl_zones,
            dnsbl_action: cfg.dnsbl_action,
            dnsbl_reason: cfg.dnsbl_reason,
            sasl_server: cfg.sasl_server,
            webirc: cfg.webirc,
            raw_config: cfg.raw,
            config_gen: 0,
            accepted_nicks: HashMap::default(),
            watch_by: HashMap::default(),
            monitor_by: HashMap::default(),
            label_capture: RefCell::new(None),
            log: RefCell::new(LogState::default()),
            event_tx,
            conn_counter,
            ext: Extensible::default(),
            metrics: crate::modules::metrics::handle(),
        }
    }

    /// The last value set for config `key` (`None` if unset). Modules read their
    /// own settings through here so no per-module field bloats `Server`/`Config`.
    pub fn conf(&self, key: &str) -> Option<&str> {
        self.raw_config
            .get(key)
            .and_then(|v| v.last())
            .map(|s| s.as_str())
    }

    /// Every value set for `key` (repeated lines, e.g. `securitygroup`, `motd`).
    pub fn conf_all(&self, key: &str) -> &[String] {
        self.raw_config
            .get(key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// A boolean config value (`yes`/`no`/…); `default` when the key is unset.
    pub fn conf_bool(&self, key: &str, default: bool) -> bool {
        self.conf(key).map(crate::config::yesish).unwrap_or(default)
    }

    /// A parsed config value; `default` when unset or unparseable.
    pub fn conf_num<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        self.conf(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// Translate a whole English string to the active locale (fallback: the input).
    /// `en`/passthrough returns the borrow unchanged — zero cost.
    #[inline]
    pub fn tr<'a>(&'a self, english: &'a str) -> &'a str {
        self.catalog.tr(english)
    }

    /// Translate an English template, then fill its `{0}`/`{1}`… placeholders. Use at
    /// call sites whose prose interpolates data (word order may differ per language).
    pub fn trf(&self, template: &str, args: &[&str]) -> String {
        crate::i18n::render(self.catalog.tr(template), args)
    }

    /// Apply a freshly-loaded config to the running server — the shared body of
    /// REHASH and the `server.rehash` RPC. Reloads the typed fields **and**
    /// `raw_config`, so modules reading via `conf*` see the new values too.
    pub fn apply_config(&mut self, fresh: crate::config::Config) {
        self.motd = fresh.motd;
        self.opers = fresh.opers;
        self.brands = fresh.brands;
        self.cloak_key = fresh.cloak_key;
        self.censor = fresh.censor;
        self.amu = fresh.amu;
        self.resolve_hosts = fresh.resolve_hosts;
        self.use_resolved_host = fresh.use_resolved_host;
        self.dnsbl_zones = fresh.dnsbl_zones;
        self.dnsbl_action = fresh.dnsbl_action;
        self.dnsbl_reason = fresh.dnsbl_reason;
        self.sasl_server = fresh.sasl_server;
        self.webirc = fresh.webirc;
        let (catalog, i18n_warn) = crate::i18n::Catalog::load(
            fresh.raw.get("locale_dir").and_then(|v| v.last()).map(String::as_str).unwrap_or("lang"),
            fresh.raw.get("locale").and_then(|v| v.last()).map(String::as_str).unwrap_or("en"),
        );
        for w in &i18n_warn {
            eprintln!("echoircd: {w}");
        }
        self.catalog = catalog;
        let (help, help_warn) = crate::help::HelpBook::load(
            fresh.raw.get("help_dir").and_then(|v| v.last()).map(String::as_str).unwrap_or("help"),
            fresh.raw.get("locale").and_then(|v| v.last()).map(String::as_str).unwrap_or("en"),
        );
        for w in &help_warn {
            eprintln!("echoircd: {w}");
        }
        self.help = help;
        self.raw_config = fresh.raw;
        self.config_gen = self.config_gen.wrapping_add(1); // invalidate module config caches
        // Re-evaluate which linked servers are services against the fresh
        // `uline`/`sasl_server` config (re-evaluated on every rehash).
        let names: Vec<(String, String)> = self
            .servers
            .iter()
            .map(|(sid, srv)| (sid.clone(), srv.name.clone()))
            .collect();
        for (sid, name) in names {
            let (is_service, silent_service) = self.uline_match(&name);
            if let Some(srv) = self.servers.get_mut(&sid) {
                srv.is_service = is_service;
                srv.silent_service = silent_service;
            }
        }
        // reload TLS certs from disk so a renewed cert applies without a restart
        // (no-op when TLS isn't configured).
        if let Some(r) = crate::tls::TLS_RELOAD.get() {
            if let Err(e) = r.reload() {
                eprintln!("[rehash] TLS cert reload failed: {e}");
            }
        }
    }

    /// Remember an identity for WHOWAS (capped ring, newest first).
    pub fn push_whowas(
        &mut self,
        nick: &str,
        ident: &str,
        host: &str,
        realname: &str,
        account: Option<String>,
    ) {
        if nick.is_empty() {
            return;
        }
        self.whowas.push_front(WhowasEntry {
            nick: nick.to_string(),
            ident: ident.to_string(),
            host: host.to_string(),
            realname: realname.to_string(),
            account,
            ts: now(),
        });
        let cap = self.conf_num("whowas_maxentries", 256usize);
        while self.whowas.len() > cap {
            self.whowas.pop_back();
        }
    }

    // --- connection lifecycle ------------------------------------------------

    pub fn add_conn(
        &mut self,
        uid: Uid,
        addr: SocketAddr,
        out: OutSink,
        sock: Option<TcpStream>,
        secure: bool,
        certfp: Option<String>,
        tls_info: Option<String>,
        sni: Option<String>,
        local_port: u16,
    ) {
        let (brand_server, brand_network) = self.resolve_brand(sni.as_deref());
        let uuid = self.next_uuid();
        self.uuid_local.insert(uuid.clone(), uid);
        let ip = addr.ip();
        self.users.insert(
            uid,
            User {
                uid,
                uuid,
                nick: String::new(),
                ident: String::new(),
                realname: String::new(),
                host: addr.ip().to_string(),
                cloak: String::new(),
                vhost: None,
                secure,
                certfp,
                tls_info,
                sni,
                brand_server,
                brand_network,
                account: None,
                signon: now(),
                nick_ts: now(),
                addr,
                port: local_port,
                registered: false,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: now(),
                ping_sent: false,
                ext: Extensible::default(),
                out,
                sock,
            },
        );

        // connflood — refuse an IP that's opening connections too fast (see modules::connflood)
        if crate::modules::connflood::over_limit(self, ip) {
            let m = self.trf("Closing link: (Too many connections from your IP)", &[]);
            self.send(uid, format!("ERROR :{m}"));
            self.remove_user(uid, "Connection throttled");
            return;
        }

        // connectban — z-line an IP range that opens too many connections (see modules::connectban)
        crate::modules::connectban::on_connect(self, ip);

        // connectclass — assign a connection class; a deny class or per-IP cap rejects
        if let Some(reason) = crate::modules::connclass::assign(self, uid) {
            let m = self.trf("Closing link: ({0})", &[reason.as_str()]);
            self.send(uid, format!("ERROR :{m}"));
            self.remove_user(uid, &reason);
            return;
        }
        // push any per-class queue caps (recvq/hardsendq/softsendq) to the reactor
        let caps = (
            crate::modules::connclass::recvq(self, uid),
            crate::modules::connclass::hardsendq(self, uid),
            crate::modules::connclass::softsendq(self, uid),
        );
        if caps.0.is_some() || caps.1.is_some() || caps.2.is_some() {
            if let Some(u) = self.users.get(&uid) {
                u.out.set_limits(caps.0, caps.1, caps.2);
            }
        }

        // ident: optionally ask the client's host who owns the connection (only when
        // the class or global config wants it — see modules::ident). Holds
        // registration via ident_pending until the reply arrives.
        crate::modules::ident::dispatch(self, uid);
        // a connection class may opt out of reverse-DNS (resolvehostnames=no)
        let do_rdns = self.resolve_hosts && crate::modules::connclass::resolve_hostnames(self, uid);
        // The resolver worker only needs the zone domains to reverse the IP under;
        // per-zone action/reason are looked up back on the core thread on a hit.
        let zones: Vec<String> = self.dnsbl_zones.iter().map(|z| z.domain.clone()).collect();
        if do_rdns {
            self.notice_star(uid, "Looking up your hostname...");
        }
        if (do_rdns || !zones.is_empty()) && resolver::try_acquire() {
            if let Some(u) = self.users.get_mut(&uid) {
                u.dns_pending = true; // hold registration until the lookups return
            }
            let tx = self.event_tx.clone();
            thread::spawn(move || {
                // rDNS and DNSBL are independent (DNSBL only needs the IP), so run
                // them concurrently — the client waits on max(rdns, dnsbl), not the
                // sum. Only spin up the extra thread when both are actually needed.
                let (host, dnsbl) = if do_rdns && !zones.is_empty() {
                    let job =
                        thread::spawn(move || dnsbl::check(ip, &zones, resolver::DNS_TIMEOUT));
                    let host = resolver::reverse_confirmed(ip, resolver::DNS_TIMEOUT);
                    (host, job.join().unwrap_or(dnsbl::Outcome::Skipped))
                } else if do_rdns {
                    (
                        resolver::reverse_confirmed(ip, resolver::DNS_TIMEOUT),
                        dnsbl::Outcome::Skipped,
                    )
                } else {
                    (None, dnsbl::check(ip, &zones, resolver::DNS_TIMEOUT))
                };
                resolver::release();
                let _ = tx.send(Event::ResolvedHost { uid, host, dnsbl });
            });
        } else if do_rdns {
            // wanted rDNS but couldn't start (too many in flight): keep the IP
            self.notice_star(
                uid,
                "Couldn't look up your hostname; using your IP address instead",
            );
        }
        // conn_waitpong: optionally hold registration until the client PONGs a cookie
        crate::modules::conn_waitpong::arm(self, uid);
    }

    /// Fire an HTTP POST on a worker thread and deliver `(status, body)` back to
    /// the core as `Event::HttpResult { uid, tag, .. }` — the same self-injection
    /// pattern as the DNS resolver, so a slow endpoint never blocks the main loop.
    /// `tag` is `"<module>:<detail>"`; the core routes the reply by its prefix.
    /// Returns `false` when at capacity (`http_max_concurrent`, default 32) so the
    /// caller can reject instead of spawning an unbounded number of threads — a
    /// pre-auth flood (e.g. VERIFY) would otherwise exhaust threads and hammer the
    /// backend. A `Drop` guard keeps the counter correct even if the task panics.
    pub fn spawn_http(
        &self,
        uid: Uid,
        tag: String,
        url: String,
        body: String,
        headers: Vec<(String, String)>,
    ) -> bool {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                ACTIVE.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let max = self.conf_num("http_max_concurrent", 32usize);
        if ACTIVE.fetch_add(1, Ordering::Relaxed) >= max {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        let tx = self.event_tx.clone();
        let verify = self.conf_bool("http_tls_verify", true);
        std::thread::spawn(move || {
            let _guard = Guard; // decrements even on panic
            let (status, body) = crate::http::post(
                &url,
                "application/x-www-form-urlencoded",
                &body,
                &headers,
                std::time::Duration::from_secs(10),
                verify,
            )
            .unwrap_or((0, String::new()));
            let _ = tx.send(crate::ircd::Event::HttpResult {
                uid,
                tag,
                status,
                body,
            });
        });
        true
    }

    /// Run an expensive credential operation (a KDF: bcrypt / pbkdf2) on a worker
    /// thread and deliver its result back as the `Event` the closure builds. These
    /// hashes are deliberately slow (tens to hundreds of ms), so running one inline
    /// would freeze the single-threaded core — and a flood of them (OPER, TITLE, …)
    /// against a KDF credential would be a trivial DoS. Bounded so the flood can't
    /// spawn unlimited threads; returns `false` when at capacity (the caller then
    /// rejects the attempt). A `Drop` guard keeps the counter correct even if the
    /// closure panics.
    pub fn spawn_crypto<F>(&self, f: F) -> bool
    where
        F: FnOnce() -> crate::ircd::Event + Send + 'static,
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ACTIVE: AtomicUsize = AtomicUsize::new(0);
        const MAX_ACTIVE: usize = 16;
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                ACTIVE.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if ACTIVE.fetch_add(1, Ordering::Relaxed) >= MAX_ACTIVE {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        let tx = self.event_tx.clone();
        std::thread::spawn(move || {
            let _guard = Guard; // decrements even on panic
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                // a panic here can't reach the core (we don't know which Event to send);
                // log it so a stuck request is diagnosable instead of silent.
                Err(_) => eprintln!("[worker] a background crypto/http task panicked; its request was dropped"),
            }
        });
        true
    }

    /// Fire-and-forget full-snapshot write of `contents` to `path`. The core thread
    /// hands the buffer to a dedicated background writer and returns immediately, so a
    /// slow or full disk never stalls the event loop. Writes coalesce per path (newest
    /// content wins), so a backed-up writer stays bounded at one pending snapshot per
    /// file — safe precisely because each write is the complete current state.
    pub fn disk_write(&self, path: String, contents: String) {
        use crate::map::HashMap;
        use std::sync::{Condvar, Mutex, OnceLock};
        type Pending = std::sync::Arc<(Mutex<HashMap<String, String>>, Condvar)>;
        static WRITER: OnceLock<Pending> = OnceLock::new();
        let pending = WRITER.get_or_init(|| {
            let p: Pending = std::sync::Arc::new((Mutex::new(HashMap::default()), Condvar::new()));
            let worker = p.clone();
            std::thread::spawn(move || {
                let (lock, cv) = &*worker;
                loop {
                    let batch = {
                        let mut map = lock.lock().unwrap_or_else(|e| e.into_inner());
                        while map.is_empty() {
                            map = cv.wait(map).unwrap_or_else(|e| e.into_inner());
                        }
                        std::mem::take(&mut *map) // drain, releasing the lock before writing
                    };
                    for (path, contents) in batch {
                        // write a sibling temp then rename over the target: rename is
                        // atomic, so a crash mid-write can never leave a truncated
                        // snapshot — the file on disk is always a complete prior state.
                        let tmp = format!("{path}.tmp");
                        if std::fs::write(&tmp, &contents).is_ok() {
                            let _ = std::fs::rename(&tmp, &path);
                        }
                    }
                }
            });
            p
        });
        let (lock, cv) = &**pending;
        if let Ok(mut map) = lock.lock() {
            map.insert(path, contents);
            cv.notify_one();
        }
    }

    /// A pre-registration `:server NOTICE * :*** <msg>` line.
    pub(crate) fn notice_star(&self, uid: Uid, msg: &str) {
        self.send(uid, format!(":{} NOTICE * :*** {msg}", self.name));
    }

    /// While a client's connect-time DNS/DNSBL lookups are still running, hold its
    /// handshake lines instead of processing them, so the "*** ..." notices print
    /// as one contiguous block rather than interleaving with the CAP/NICK replies.
    /// Returns true if `line` was buffered. Bounded — past the cap, lines pass
    /// through (interleaved output rather than dropped input).
    pub fn defer_if_resolving(&mut self, uid: Uid, line: &str) -> bool {
        const MAX_DEFERRED: usize = 32;
        match self.users.get_mut(&uid) {
            Some(u) if u.dns_pending && u.deferred.len() < MAX_DEFERRED => {
                u.deferred.push(line.to_string());
                true
            }
            _ => false,
        }
    }

    /// Take and clear the handshake lines held while `uid`'s lookups ran, to replay
    /// once the notice block has printed.
    pub fn take_deferred(&mut self, uid: Uid) -> Vec<String> {
        self.users
            .get_mut(&uid)
            .map(|u| std::mem::take(&mut u.deferred))
            .unwrap_or_default()
    }

    /// A client's reverse-DNS lookup finished. Set the resolved host (so WHOIS,
    /// bans and cloaking use the hostname, not the IP), tell the client, and clear
    /// the flag that was holding their registration.
    pub fn on_resolved(&mut self, uid: Uid, host: Option<String>, outcome: dnsbl::Outcome) {
        // hostname result (only announced if the lookup was attempted)
        match &host {
            Some(h) => self.notice_star(uid, &format!("Found your hostname ({h})")),
            None if self.resolve_hosts => self.notice_star(
                uid,
                "Couldn't look up your hostname; using your IP address instead",
            ),
            None => {}
        }
        let apply = self.use_resolved_host;
        if let Some(u) = self.users.get_mut(&uid) {
            // `use_resolved_host = off` keeps the IP in the hostmask even though the
            // name was resolved and reported above.
            if apply {
                if let Some(h) = host {
                    u.host = h;
                }
            }
        }
        // DNSBL notices + action (see `modules::dnsbl`). May close the connection
        // if the zone is listed and the action bans.
        dnsbl::report(self, uid, outcome);
        // release the registration hold (no-op if a DNSBL ban already removed them)
        if let Some(u) = self.users.get_mut(&uid) {
            u.dns_pending = false;
        }
    }

    /// Mark a user as quitting; the core turns this into a full quit after the
    /// current command returns (so hooks fire while the user still exists).
    pub fn mark_quit(&mut self, uid: Uid, reason: String) {
        if let Some(u) = self.users.get_mut(&uid) {
            u.quitting = Some(reason);
        }
    }

    pub fn take_quit(&mut self, uid: Uid) -> Option<String> {
        self.users.get_mut(&uid).and_then(|u| u.quitting.take())
    }

    /// Remove a user: broadcast QUIT to everyone sharing a channel, drop them
    /// from all channels, free the nick, and close the socket.
    /// Add `nick_low` (already lowercased) to `uid`'s callerid accept list and bump
    /// the reverse count. Caller has already checked it's absent and under the cap.
    pub fn accept_add(&mut self, uid: Uid, nick_low: String) {
        if self.users.get_mut(&uid).map(|u| u.accept.push(nick_low.clone())).is_none() {
            return;
        }
        *self.accepted_nicks.entry(nick_low).or_insert(0) += 1;
    }

    /// Remove `nick_low` from `uid`'s accept list and decrement the reverse count.
    pub fn accept_remove(&mut self, uid: Uid, nick_low: &str) {
        let removed = self
            .users
            .get_mut(&uid)
            .map(|u| {
                let before = u.accept.len();
                u.accept.retain(|x| x != nick_low);
                before != u.accept.len()
            })
            .unwrap_or(false);
        if removed {
            if let Some(c) = self.accepted_nicks.get_mut(nick_low) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.accepted_nicks.remove(nick_low);
                }
            }
        }
    }

    pub fn remove_user(&mut self, uid: Uid, reason: &str) {
        let Some(user) = self.users.remove(&uid) else {
            return;
        };
        // the departing user's own accept list vanishes with them — drop its nicks
        // from the reverse count
        for n in &user.accept {
            if let Some(c) = self.accepted_nicks.get_mut(n) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    self.accepted_nicks.remove(n);
                }
            }
        }
        // drop this user from the WATCH/MONITOR reverse indexes
        for n in &user.watch {
            if let Some(set) = self.watch_by.get_mut(n) {
                set.remove(&uid);
                if set.is_empty() {
                    self.watch_by.remove(n);
                }
            }
        }
        for n in &user.monitor {
            if let Some(set) = self.monitor_by.get_mut(n) {
                set.remove(&uid);
                if set.is_empty() {
                    self.monitor_by.remove(n);
                }
            }
        }
        self.uuid_local.remove(&user.uuid);
        if user.registered {
            self.push_whowas(
                &user.nick,
                &user.ident,
                user.host_display(),
                &user.realname,
                user.account.clone(),
            );
            self.propagate(&format!(":{} QUIT :{reason}", user.uuid), None); // tell links
        }
        // The socket is not force-shut here. When `user` drops at the end of this
        // function its `out` Sender drops with it, so the writer thread drains any
        // still-queued lines — e.g. a KILL / x-line ERROR — and then closes the
        // socket itself once the channel is empty.
        if !user.nick.is_empty() {
            self.nick_index.remove(&user.nick.to_ascii_lowercase());
            // Scrub the departed nick from every +g callerid ACCEPT list, so a new
            // user grabbing this nick can't inherit its acceptance and bypass a gate.
            // The reverse count lets us skip the O(users) scan unless someone actually
            // accepted this nick (the common case).
            let low = user.nick.to_ascii_lowercase();
            if self.accepted_nicks.remove(&low).unwrap_or(0) > 0 {
                for u in self.users.values_mut() {
                    u.accept.retain(|n| n != &low);
                }
            }
        }
        if user.registered {
            let line = format!(":{} QUIT :{reason}", user.prefix());
            let mut seen: HashSet<Uid> = HashSet::default();
            for key in &user.channels {
                if let Some(ch) = self.channels.get_mut(key) {
                    // +D delayjoin: if their JOIN here was never announced, no QUIT either
                    let hidden = ch.members.get(&uid).map(|m| m.hidden).unwrap_or(false);
                    ch.members.remove(&uid);
                    if !hidden {
                        for &m in ch.members.keys() {
                            seen.insert(m);
                        }
                    }
                }
            }
            for m in seen {
                self.send(m, line.clone());
            }
            // Scrub any pending +i invite for this user from channels they never joined
            // (a member consumes their invite on join; a never-joined invite for a now-
            // departed uid would otherwise linger forever on a persistent channel).
            // The `invited` reverse index gives the exact channels, so this is O(pending
            // invites) rather than a scan of every channel on the network.
            for key in &user.invited {
                if let Some(ch) = self.channels.get_mut(key) {
                    ch.invites.remove(&uid);
                }
            }
            self.channels.retain(|_, c| c.keep_alive());
            self.watch_notify_offline(&user.nick); // tell WATCH/MONITOR watchers
        }
    }

    // --- output primitives ---------------------------------------------------

    /// Queue one raw line to a connection (no-op if it's gone).
    pub fn send(&self, uid: Uid, line: String) {
        if let Some(u) = self.users.get(&uid) {
            // server-time: tag sourced (`:prefix …`) lines for clients that asked
            let line = if u.caps.server_time && line.starts_with(':') {
                format!("@time={} {line}", iso_time(now()))
            } else {
                line
            };
            self.emit_to(uid, line.into());
        }
    }

    /// Final hop for one line to a client: diverted into the labeled-response
    /// capture buffer when one is active for `uid`, otherwise written to the wire.
    fn emit_to(&self, uid: Uid, line: LineBuf) {
        if let Ok(mut cap) = self.label_capture.try_borrow_mut() {
            if let Some((cuid, buf)) = cap.as_mut() {
                if *cuid == uid {
                    buf.push(line.into_string());
                    return;
                }
            }
        }
        if let Some(u) = self.users.get(&uid) {
            u.out.send(line);
        }
    }

    /// Send a numeric: `:server NNN <target> <rest>`. `<target>` is the client's
    /// nick, or `*` before it has one.
    /// The ISUPPORT (005) token blocks this server advertises — the fixed set plus
    /// the config-driven module tokens (ICON, FILEHOST). Each entry is a token block
    /// without the trailing `:are supported by this server`. Shared by the welcome
    /// burst and the `ISUPPORT` command (draft/extended-isupport).
    pub fn isupport_lines(&self, network: &str) -> Vec<String> {
        // advertised limits mirror the (config-driven) values actually enforced
        let maxwatch = self.conf_num("maxwatch", crate::watch::WATCH_MAX);
        let maxmon = self.conf_num("maxmonitor", crate::watch::MONITOR_MAX);
        let maxsil = self.conf_num("maxsilence", crate::watch::SILENCE_MAX);
        let chathist = crate::modules::chathistory::limit(self);
        let maxnick = self.conf_num("maxnick", 30usize);
        let maxchan = self.conf_num("maxchannel", 50usize);
        let maxmodes = self.conf_num("modes", 20usize).max(1);
        // operprefix/ojoin add the server oper prefix `y` above owner; sigils are
        // config-overridable (see modules::customprefix)
        let include_oper = self.conf_bool("operprefix", false) || self.conf_bool("ojoin", false);
        let prefix = crate::modules::customprefix::isupport(include_oper);
        let mut tokens: Vec<String> = format!(
            "CHANTYPES=# PREFIX={prefix} CHANMODES=beIgXw,k,lfjFLHBJdK,ACDGMNOPQRSTUcimnprstuz EXTBAN=,aGAbcgjmnrsy ACCOUNTEXTBAN=a BOT=B WATCH={maxwatch} MONITOR={maxmon} SILENCE={maxsil} CALLERID=g WHOX CHATHISTORY={chathist} MSGREFTYPES=timestamp,msgid UTF8ONLY CASEMAPPING=ascii NICKLEN={maxnick} CHANNELLEN={maxchan} MODES={maxmodes} NETWORK={}",
            network
        )
        .split(' ')
        .map(String::from)
        .collect();
        if let Some(tok) = crate::modules::network_icon::isupport(self) {
            tokens.push(tok);
        }
        if let Some(tok) = crate::modules::filehost::isupport(self) {
            tokens.push(tok);
        }
        if let Some(tok) = crate::modules::webpush::isupport(self) {
            tokens.push(tok);
        }
        // at most 13 tokens per 005 line (the RFC-suggested cap) so strict clients
        // don't truncate trailing tokens
        tokens.chunks(13).map(|c| c.join(" ")).collect()
    }

    /// Emit the ISUPPORT numerics to `uid`. When `batched` (the client negotiated
    /// `draft/extended-isupport` + `batch`), wrap them in a `draft/isupport` BATCH so
    /// the multi-line set arrives atomically.
    pub fn send_isupport(&mut self, uid: Uid, batched: bool) {
        let lines = self.isupport_lines(self.disp_network(uid));
        if batched {
            let nick = self
                .users
                .get(&uid)
                .map(|u| u.nick.clone())
                .unwrap_or_default();
            let bref = self.next_msgid().replace('-', "");
            self.send(uid, format!(":{} BATCH +{bref} draft/isupport", self.name));
            for l in &lines {
                self.send(
                    uid,
                    format!(
                        "@batch={bref} :{} {:03} {nick} {l} :are supported by this server",
                        self.name,
                        crate::numeric::RPL_ISUPPORT
                    ),
                );
            }
            self.send(uid, format!(":{} BATCH -{bref}", self.name));
        } else {
            for l in &lines {
                self.numeric(
                    uid,
                    crate::numeric::RPL_ISUPPORT,
                    &format!("{l} :are supported by this server"),
                );
            }
        }
    }

    /// The server name shown to `uid`: its per-SNI brand, or the global name.
    pub fn disp_name(&self, uid: Uid) -> &str {
        self.users
            .get(&uid)
            .and_then(|u| u.brand_server.as_deref())
            .unwrap_or(&self.name)
    }

    /// The network name shown to `uid`: its per-SNI brand, or the global network.
    pub fn disp_network(&self, uid: Uid) -> &str {
        self.users
            .get(&uid)
            .and_then(|u| u.brand_network.as_deref())
            .unwrap_or(&self.network)
    }

    /// Resolve the per-SNI brand for a new connection: match its TLS SNI host
    /// against the configured `brand` blocks, returning the display servername +
    /// network (each `None` = no brand, use the globals).
    fn resolve_brand(&self, sni: Option<&str>) -> (Option<String>, Option<String>) {
        let host = match sni {
            Some(h) if !h.is_empty() => h.to_ascii_lowercase(),
            _ => return (None, None),
        };
        for b in &self.brands {
            if b.host == host {
                let sv = (!b.servername.is_empty()).then(|| b.servername.clone());
                let nw = (!b.network.is_empty()).then(|| b.network.clone());
                return (sv, nw);
            }
        }
        (None, None)
    }

    pub fn numeric(&self, uid: Uid, code: u16, rest: &str) {
        let line = {
            let u = self.users.get(&uid);
            let target = u
                .map(|u| if u.nick.is_empty() { "*" } else { u.nick.as_str() })
                .unwrap_or("*");
            // per-SNI brand as the message source (falls back to the global name)
            let srv = u
                .and_then(|u| u.brand_server.as_deref())
                .unwrap_or(&self.name);
            let rest = self.catalog.tr_numeric(rest);
            format!(":{srv} {code:03} {target} {rest}")
        };
        self.send(uid, line);
    }

    /// Send a server notice to every operator who has snomask (+s) on.
    /// Record one server-notice line in the rolling log (for RPC log.tail/events).
    fn log_push(&self, msg: &str) {
        let mut lg = self.log.borrow_mut();
        lg.seq += 1;
        let id = lg.seq;
        lg.ring.push_back(LogLine {
            id,
            ts: now(),
            msg: msg.to_string(),
        });
        while lg.ring.len() > 1000 {
            lg.ring.pop_front();
        }
    }

    /// Deliver a `*** msg` server notice to `uid`, folding in that recipient's
    /// server-time + `draft/json-log` tags — the two tags every server notice may
    /// carry. `jval` is the per-notice escaped json-log value, shared across
    /// recipients (`""` when nobody negotiated the cap). One path for both
    /// `snotice` and `announce`, so tagging is consistent no matter the caller.
    fn deliver_server_notice(&self, uid: Uid, msg: &str, jval: &str) {
        let Some(u) = self.users.get(&uid) else {
            return;
        };
        let nick = u.nick.clone();
        // Localize the prose for the recipient; the log/chanlog/syslog tees keep the
        // English source. Static snotice/announce text auto-translates here (like the
        // numeric chokepoint); already-templated dynamic text passes through unchanged.
        let msg = self.catalog.tr(msg);
        let mut tags: Vec<String> = Vec::new();
        if u.caps.server_time {
            tags.push(format!("time={}", iso_time(now())));
        }
        if u.caps.json_log && !jval.is_empty() {
            tags.push(format!("draft/json-log={jval}"));
        }
        let base = format!(":{} NOTICE {nick} :*** {msg}", self.name);
        let line = if tags.is_empty() {
            base
        } else {
            format!("@{} {base}", tags.join(";"))
        };
        self.emit_to(uid, line.into());
    }

    /// The escaped json-log value for `msg`, or `""` if none of `targets` want it
    /// (so the JSON isn't built when no recipient has the cap).
    fn json_log_value(&self, msg: &str, targets: &[Uid]) -> String {
        let wanted = targets
            .iter()
            .any(|u| self.users.get(u).map(|x| x.caps.json_log).unwrap_or(false));
        if wanted {
            crate::modules::jsonlog::tag_value(self, msg)
        } else {
            String::new()
        }
    }

    /// Send a server notice to every operator who has snomask (+s) on.
    /// A server notice in the general `a` (announcement) category.
    pub fn snotice(&self, msg: &str) {
        self.snotice_c('a', msg);
    }

    /// A server notice tagged with snomask category `cat` — only opers whose snomask
    /// (`+s`) subscribes to that letter receive it. Logging tees are unconditional.
    pub fn snotice_c(&self, cat: char, msg: &str) {
        self.log_push(msg);
        let opers: Vec<Uid> = self
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper && u.flags.snomask_cats.contains(cat))
            .map(|(&u, _)| u)
            .collect();
        let jval = self.json_log_value(msg, &opers);
        for o in opers {
            self.deliver_server_notice(o, msg, &jval);
        }
        crate::modules::chanlog::tee(self, cat, msg);
        crate::modules::syslog::tee(self, msg);
        crate::modules::log_json::tee(self, msg);
    }

    /// Like [`Self::snotice_c`], but redacted per viewer: each `+c` oper for whom
    /// `allow(&user)` is false receives `redacted` instead of `full`. The server log and
    /// the chan/syslog/json tees always record the full line, so nothing is lost for audit.
    pub fn snotice_c_gated(
        &self,
        cat: char,
        full: &str,
        redacted: &str,
        allow: impl Fn(&crate::users::User) -> bool,
    ) {
        self.log_push(full);
        let recips: Vec<(Uid, bool)> = self
            .users
            .iter()
            .filter(|(_, u)| u.flags.oper && u.flags.snomask_cats.contains(cat))
            .map(|(&uid, u)| (uid, allow(u)))
            .collect();
        let uids: Vec<Uid> = recips.iter().map(|(u, _)| *u).collect();
        let jfull = self.json_log_value(full, &uids);
        let jred = self.json_log_value(redacted, &uids);
        for (o, revealed) in recips {
            if revealed {
                self.deliver_server_notice(o, full, &jfull);
            } else {
                self.deliver_server_notice(o, redacted, &jred);
            }
        }
        crate::modules::chanlog::tee(self, cat, full);
        crate::modules::syslog::tee(self, full);
        crate::modules::log_json::tee(self, full);
    }

    /// Broadcast a `*** msg` server NOTICE to *every* registered local user — for
    /// server-wide announcements everyone should see (e.g. a config reload). Goes
    /// through the same tagged path as `snotice`, so cap-holders get the server-time
    /// + `draft/json-log` tags and the line is recorded in the server log.
    pub fn announce(&self, msg: &str) {
        self.log_push(msg);
        let targets: Vec<Uid> = self
            .users
            .iter()
            .filter(|(_, u)| u.registered && !u.nick.is_empty())
            .map(|(&u, _)| u)
            .collect();
        let jval = self.json_log_value(msg, &targets);
        for u in targets {
            self.deliver_server_notice(u, msg, &jval);
        }
    }

    /// IRCv3 standard reply (`FAIL`/`WARN`/`NOTE`): structured, machine-readable
    /// command feedback. Sent in the `:server FAIL <command> <code> :<desc>` form
    /// to clients that negotiated `standard-replies`; others get the description as
    /// a plain server NOTICE so the human-readable text still reaches them.
    pub fn fail(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "FAIL", command, code, desc);
    }
    pub fn warn(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "WARN", command, code, desc);
    }
    pub fn note(&self, uid: Uid, command: &str, code: &str, desc: &str) {
        self.standard_reply(uid, "NOTE", command, code, desc);
    }
    fn standard_reply(&self, uid: Uid, kind: &str, command: &str, code: &str, desc: &str) {
        let cap = self
            .users
            .get(&uid)
            .map(|u| u.caps.standard_replies)
            .unwrap_or(false);
        if cap {
            self.send(
                uid,
                format!(":{} {kind} {command} {code} :{desc}", self.name),
            );
        } else {
            let nick = self
                .users
                .get(&uid)
                .map(|u| {
                    if u.nick.is_empty() {
                        "*".to_string()
                    } else {
                        u.nick.clone()
                    }
                })
                .unwrap_or_else(|| "*".to_string());
            self.send(uid, format!(":{} NOTICE {nick} :{desc}", self.name));
        }
    }

    /// Send a line to every member of a channel, optionally skipping one uid. The
    /// line is allocated once and shared (`Arc`) across all recipients — a big
    /// channel broadcast no longer clones the string per member. A `server-time`
    /// member gets a time-tagged variant, itself built once and shared.
    pub fn to_channel(&self, key: &str, line: &str, except: Option<Uid>) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        let plain: std::sync::Arc<str> = std::sync::Arc::from(line);
        let sourced = line.starts_with(':'); // only `:prefix …` lines carry server-time
        let mut tagged: Option<std::sync::Arc<str>> = None;
        for &uid in ch.members.keys() {
            if Some(uid) == except {
                continue;
            }
            let want_time = sourced
                && self
                    .users
                    .get(&uid)
                    .map(|u| u.caps.server_time)
                    .unwrap_or(false);
            let buf = if want_time {
                let t = tagged.get_or_insert_with(|| {
                    std::sync::Arc::from(format!("@time={} {line}", iso_time(now())).as_str())
                });
                LineBuf::Shared(t.clone())
            } else {
                LineBuf::Shared(plain.clone())
            };
            self.emit_to(uid, buf);
        }
    }

    /// Fan an already-composed S2S channel message (`:prefix PRIVMSG #c :text`) out
    /// to local members, sharing the line by `Arc` instead of cloning a String per
    /// recipient. When `service`, message-tags clients get the `echo/services` badge;
    /// server-time and +D deaf filtering are applied per recipient. At most three
    /// distinct lines are built (plain / time-tagged / service-tagged) whatever the
    /// channel size.
    pub fn relay_channel_message(&self, key: &str, base: &str, service: bool) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        let sourced = base.starts_with(':'); // only `:prefix …` lines carry server-time
        let plain: std::sync::Arc<str> = std::sync::Arc::from(base);
        let tagged: Option<std::sync::Arc<str>> =
            service.then(|| std::sync::Arc::from(format!("@echo/services {base}").as_str()));
        let mut plain_time: Option<std::sync::Arc<str>> = None;
        for &m in ch.members.keys() {
            let Some(u) = self.users.get(&m) else {
                continue;
            };
            if u.flags.deaf {
                continue;
            }
            // a service-badged line already carries a tag block, so — as before — it
            // isn't additionally server-time tagged.
            let buf = if service && u.caps.message_tags {
                LineBuf::Shared(tagged.clone().unwrap())
            } else if sourced && u.caps.server_time {
                let t = plain_time.get_or_insert_with(|| {
                    std::sync::Arc::from(format!("@time={} {base}", iso_time(now())).as_str())
                });
                LineBuf::Shared(t.clone())
            } else {
                LineBuf::Shared(plain.clone())
            };
            self.emit_to(m, buf);
        }
    }

    /// Send a message body (`:prefix CMD …`) from `src` to `uid`, composing its
    /// IRCv3 tag prefix from *that recipient's* caps: `time=` (server-time),
    /// `account=` (account-tag, from the sender's login) plus the client-only tags
    /// `ctags` and `msgid` (message-tags). For PRIVMSG / NOTICE / TAGMSG delivery.
    pub fn send_tagged(&self, uid: Uid, src: Uid, ctags: &str, msgid: &str, body: &str) {
        if let Some(u) = self.users.get(&uid) {
            let mut tags: Vec<String> = Vec::new();
            if u.caps.server_time {
                tags.push(format!("time={}", iso_time(now())));
            }
            // account-tag: label a message with the sender's services account, so
            // recipients see who's authenticated without a separate WHOIS.
            if u.caps.account_tag {
                if let Some(acct) = self.users.get(&src).and_then(|su| su.account.as_deref()) {
                    tags.push(format!("account={acct}"));
                }
            }
            // msgid (IRCv3): a unique, server-assigned id per message so clients
            // can reference it (reactions, replies, redaction). Tag-only feature,
            // so it goes to message-tags clients alongside any client `+`-tags.
            if u.caps.message_tags {
                if !msgid.is_empty() {
                    tags.push(format!("msgid={msgid}"));
                }
                if !ctags.is_empty() {
                    tags.push(ctags.to_string());
                }
            }
            let line = if tags.is_empty() {
                body.to_string()
            } else {
                format!("@{} {body}", tags.join(";"))
            };
            self.emit_to(uid, line.into());
        }
    }

    /// Fan a channel PRIVMSG/NOTICE out to every eligible member, allocating the
    /// line at most once per distinct capability profile (server-time / account-tag
    /// / message-tags) and sharing it by `Arc` — instead of formatting a fresh
    /// String per member. The tag *values* (time, account, msgid, ctags) are the
    /// same for the whole message, so a big channel needs ≤8 lines, not N. Excludes
    /// the sender (echo-message is a separate single send) and +D deaf members;
    /// `op_only` (+U) limits delivery to half-ops and above.
    pub fn to_channel_tagged(
        &self,
        key: &str,
        src: Uid,
        ctags: &str,
        msgid: &str,
        body: &str,
        op_only: bool,
    ) {
        let Some(ch) = self.channels.get(key) else {
            return;
        };
        let members: Vec<Uid> = ch.members.keys().copied().collect();
        let time_tag = format!("time={}", iso_time(now()));
        let account = self.users.get(&src).and_then(|su| su.account.clone());
        // SIGNORE (mutual server-ignore): the sender's mask + list, hoisted once.
        let src_mask = self.users.get(&src).map(|su| su.prefix()).unwrap_or_default();
        let src_signore: Vec<String> =
            self.users.get(&src).map(|su| su.signore.clone()).unwrap_or_default();
        // users/ignore-privdeaf: this sender's channel messages reach +D deaf members
        let src_reaches_deaf =
            crate::modules::opertypes::has_priv(self, src, crate::modules::opertypes::privs::USERS_IGNORE_PRIVDEAF);
        // one cached line per (server_time, account_tag, message_tags) combination
        let mut cache: [Option<std::sync::Arc<str>>; 8] = std::array::from_fn(|_| None);
        for m in members {
            if m == src {
                continue;
            }
            let Some(u) = self.users.get(&m) else {
                continue;
            };
            if u.flags.deaf && !src_reaches_deaf {
                continue;
            }
            // SIGNORE: skip a member mutually server-ignored with the sender
            if (!src_signore.is_empty() || !u.signore.is_empty())
                && (src_signore.iter().any(|p| crate::channels::glob_match(p, &u.prefix()))
                    || u.signore.iter().any(|p| crate::channels::glob_match(p, &src_mask)))
            {
                continue;
            }
            if op_only && self.rank(m, key) < crate::channels::RANK_HALFOP {
                continue;
            }
            let st = u.caps.server_time;
            let at = u.caps.account_tag && account.is_some();
            let mt = u.caps.message_tags;
            let idx = st as usize | (at as usize) << 1 | (mt as usize) << 2;
            let line = cache[idx]
                .get_or_insert_with(|| {
                    let mut tags: Vec<String> = Vec::new();
                    if st {
                        tags.push(time_tag.clone());
                    }
                    if at {
                        tags.push(format!("account={}", account.as_deref().unwrap_or_default()));
                    }
                    if mt {
                        if !msgid.is_empty() {
                            tags.push(format!("msgid={msgid}"));
                        }
                        if !ctags.is_empty() {
                            tags.push(ctags.to_string());
                        }
                    }
                    let s = if tags.is_empty() {
                        body.to_string()
                    } else {
                        format!("@{} {body}", tags.join(";"))
                    };
                    std::sync::Arc::from(s.as_str())
                })
                .clone();
            self.emit_to(m, LineBuf::Shared(line));
        }
    }

    /// Mint a unique IRCv3 `msgid` for one message. Generated once per PRIVMSG/
    /// NOTICE/TAGMSG and shared across all its recipients so they correlate.
    /// `<server-start>-<counter>` in hex: unique for this run, distinct across
    /// restarts (the start time changes).
    pub fn next_msgid(&mut self) -> String {
        self.msgid_counter = self.msgid_counter.wrapping_add(1);
        format!("{:x}-{:x}", self.created, self.msgid_counter)
    }

    /// Send `line` to every user sharing a channel with `uid` (except `uid`) whose
    /// capabilities satisfy `want`. Drives away-/account-/chghost-/setname-notify.
    pub fn notify_peers(&self, uid: Uid, line: &str, want: fn(&Caps) -> bool) {
        let chans: Vec<String> = self
            .users
            .get(&uid)
            .map(|u| u.channels.iter().cloned().collect())
            .unwrap_or_default();
        let mut seen: HashSet<Uid> = HashSet::default();
        for k in &chans {
            if let Some(ch) = self.channels.get(k) {
                for &m in ch.members.keys() {
                    seen.insert(m);
                }
            }
        }
        // extended-monitor (IRCv3): clients that MONITOR this nick and negotiated
        // `extended-monitor` are treated as able to see it — so away/account/
        // chghost/setname reach them even without a shared channel. The `want`
        // filter below still requires the matching base cap, per spec.
        if let Some(low) = self.users.get(&uid).map(|u| u.nick.to_ascii_lowercase()) {
            for (&m, u) in &self.users {
                if u.caps.extended_monitor && u.monitor.contains(&low) {
                    seen.insert(m);
                }
            }
        }
        for m in seen {
            if m != uid && self.users.get(&m).map(|u| want(&u.caps)).unwrap_or(false) {
                self.send(m, line.to_string());
            }
        }
    }

    /// Change a user's displayed host and/or ident (CHGHOST/CHGIDENT/SETHOST/
    /// SETIDENT). Announces it via the `chghost` cap to peers that speak it and
    /// to the user, and sends RPL_HOSTHIDDEN (396) when the host changed. Local
    /// scope for now.
    pub fn change_host_ident(&mut self, uid: Uid, new_ident: Option<&str>, new_host: Option<&str>) {
        self.change_host_ident_inner(uid, new_ident, new_host, true);
    }

    /// Like [`change_host_ident`] but does NOT propagate over S2S — for applying an
    /// inbound CHGHOST/CHGIDENT (the link layer already relayed it; re-propagating
    /// would echo it back toward its origin).
    pub fn change_host_ident_quiet(
        &mut self,
        uid: Uid,
        new_ident: Option<&str>,
        new_host: Option<&str>,
    ) {
        self.change_host_ident_inner(uid, new_ident, new_host, false);
    }

    fn change_host_ident_inner(
        &mut self,
        uid: Uid,
        new_ident: Option<&str>,
        new_host: Option<&str>,
        propagate: bool,
    ) {
        let Some(u) = self.users.get(&uid) else {
            return;
        };
        let old_prefix = u.prefix();
        if let Some(h) = new_host {
            if let Some(u) = self.users.get_mut(&uid) {
                u.vhost = Some(h.to_string());
            }
        }
        if let Some(i) = new_ident {
            if let Some(u) = self.users.get_mut(&uid) {
                u.ident = i.to_string();
            }
        }
        let (ident, host, aware) = {
            let u = &self.users[&uid];
            (
                u.ident.clone(),
                u.host_display().to_string(),
                u.caps.chghost,
            )
        };
        // chghost-cap peers (and, if it speaks it, the user) get a CHGHOST line
        let line = format!(":{old_prefix} CHGHOST {ident} {host}");
        self.notify_peers(uid, &line, |c| c.chghost);
        if aware {
            self.send(uid, line);
        }
        // propagate to linked servers so their view stays in sync (echoIRCd applies an
        // inbound ENCAP CHGHOST/CHGIDENT; a peer that doesn't understand ENCAP ignores
        // it). Skipped when applying an inbound change, so it isn't echoed to its origin.
        if propagate && !self.links.is_empty() {
            let (uuid, sid) = (self.users[&uid].uuid.clone(), self.sid.clone());
            if let Some(i) = new_ident {
                self.propagate(&format!(":{sid} ENCAP * CHGIDENT {uuid} {i}"), None);
            }
            if let Some(h) = new_host {
                self.propagate(&format!(":{sid} ENCAP * CHGHOST {uuid} {h}"), None);
            }
        }
        // hostcycle — clients WITHOUT the chghost cap only learn the new host via a
        // PART+JOIN, so cycle them through each shared channel (chghost peers already
        // got the CHGHOST line above). Prefix modes are re-sent so they don't appear
        // de-opped.
        if new_host.is_some() || new_ident.is_some() {
            let (nick, new_prefix, acct, realname) = {
                let u = &self.users[&uid];
                (
                    u.nick.clone(),
                    u.prefix(),
                    u.account.clone().unwrap_or_else(|| "*".to_string()),
                    u.realname.clone(),
                )
            };
            let chans: Vec<String> = self.users[&uid].channels.iter().cloned().collect();
            for key in chans {
                let Some(ch) = self.channels.get(&key) else {
                    continue;
                };
                let name = ch.name.clone();
                let modes: String = ch
                    .members
                    .get(&uid)
                    .map(|mem| {
                        let mut s = String::new();
                        for (on, c) in [
                            (mem.owner(), 'q'),
                            (mem.admin(), 'a'),
                            (mem.op(), 'o'),
                            (mem.halfop(), 'h'),
                            (mem.voice(), 'v'),
                        ] {
                            if on {
                                s.push(c);
                            }
                        }
                        s
                    })
                    .unwrap_or_default();
                let recips: Vec<(Uid, bool)> = ch
                    .members
                    .keys()
                    .copied()
                    .filter(|&m| m != uid)
                    .filter_map(|m| {
                        self.users
                            .get(&m)
                            .filter(|u| !u.caps.chghost)
                            .map(|u| (m, u.caps.extended_join))
                    })
                    .collect();
                for (m, extjoin) in recips {
                    self.send(m, format!(":{old_prefix} PART {name} :Changing host"));
                    let joinline = if extjoin {
                        format!(":{new_prefix} JOIN {name} {acct} :{realname}")
                    } else {
                        format!(":{new_prefix} JOIN {name}")
                    };
                    self.send(m, joinline);
                    if !modes.is_empty() {
                        let args = vec![nick.clone(); modes.len()].join(" ");
                        self.send(m, format!(":{} MODE {name} +{modes} {args}", self.name));
                    }
                }
            }
        }
        if new_host.is_some() {
            self.numeric(
                uid,
                crate::numeric::RPL_HOSTHIDDEN,
                &format!("{host} :is now your displayed host"),
            );
        }
    }

    /// Decide which connections to PING and which to drop, given `now`.
    /// Returns `(to_ping, to_quit)`. Pure over the state, so it's unit-testable.
    pub fn idle_check(&self, now: u64) -> (Vec<Uid>, Vec<Uid>) {
        let reg_timeout = self.conf_num("registration_timeout", REG_TIMEOUT);
        let ping_after = self.conf_num("ping_frequency", PING_AFTER);
        let ping_timeout = self.conf_num("ping_timeout", PING_TIMEOUT);
        let mut ping = Vec::new();
        let mut quit = Vec::new();
        for (&uid, u) in &self.users {
            let idle = now.saturating_sub(u.last_active);
            // a connection class may override the registration timeout / ping frequency
            let reg_to = crate::modules::connclass::reg_timeout(self, uid).unwrap_or(reg_timeout);
            let pa = crate::modules::connclass::ping_freq(self, uid).unwrap_or(ping_after);
            if !u.registered {
                if idle >= reg_to {
                    quit.push(uid); // never registered in time
                }
            } else if u.ping_sent {
                if idle >= pa + ping_timeout {
                    quit.push(uid); // no reply to the server PING
                }
            } else if idle >= pa {
                ping.push(uid); // idle — poke it
            }
        }
        (ping, quit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::valid_chan;
    use crate::users::{valid_nick, User, UserFlags};
    use std::sync::mpsc::{self, Receiver};

    #[test]
    fn version_token_and_comment() {
        assert_eq!(RELEASE, "5");
        let c = version_comment();
        assert!(c.starts_with("echoircd 5.0.0 \u{b7}"), "unexpected: {c}");
        assert!(c.contains("rustc ") && c.contains("built "));
    }

    /// Insert a registered user with an output channel readable in the test.
    fn add_user(s: &mut Server, uid: Uid, nick: &str) -> Receiver<String> {
        let (tx, rx) = mpsc::channel();
        s.users.insert(
            uid,
            User {
                uid,
                uuid: format!("TST{uid:06}"),
                nick: nick.to_string(),
                ident: "u".to_string(),
                realname: "real".to_string(),
                host: "localhost".to_string(),
                cloak: String::new(),
                vhost: None,
                secure: false,
                certfp: None,
                tls_info: None,
                sni: None,
                brand_server: None,
                brand_network: None,
                account: None,
                signon: 0,
                nick_ts: 0,
                addr: "127.0.0.1:1".parse().unwrap(),
                port: 6667,
                registered: true,
                dns_pending: false,
                ident_pending: false,
                auth_pending: false,
                waitpong: None,
                class: None,
                pass: None,
                deferred: Vec::new(),
                cap: false,
                cap_302: false,
                caps: Caps::default(),
                sasl_mech: None,
                channels: HashSet::default(),
                invited: HashSet::default(),
                watch: Vec::new(),
                monitor: Vec::new(),
                silence: Vec::new(),
                signore: Vec::new(),
                accept: Vec::new(),
                quitting: None,
                flags: UserFlags::default(),
                last_active: 0,
                ping_sent: false,
                ext: Extensible::default(),
                out: OutSink::Thread(tx),
                sock: None,
            },
        );
        s.nick_index.insert(nick.to_ascii_lowercase(), uid);
        rx
    }

    fn srv() -> Server {
        let (tx, _rx) = mpsc::channel();
        Server::new(Config::default(), tx, Arc::new(AtomicU64::new(1)))
    }

    // The tick purge reclaims per-member flood state of users who left, and +J
    // rejoin-block entries whose window elapsed — the slow high-churn leak.
    #[test]
    fn purge_flood_state_reclaims_departed_and_expired() {
        use crate::channels::{Channel, Member};
        let mut s = srv();
        let mut c = Channel::new("#c");
        c.members.insert(1, Member::default()); // uid 1 is a current member
        c.msgflood_hits.insert(1, vec![now()]); // member -> kept
        c.msgflood_hits.insert(99, vec![now()]); // departed -> dropped
        c.modes.kicknorejoin = Some(60);
        c.recent_kicks.insert(99, now().saturating_sub(120)); // expired -> dropped
        c.recent_kicks.insert(88, now()); // still within window -> kept
        s.channels.insert("#c".into(), c);
        s.purge_flood_state();
        let ch = &s.channels["#c"];
        assert!(ch.msgflood_hits.contains_key(&1));
        assert!(!ch.msgflood_hits.contains_key(&99), "departed member's +f state dropped");
        assert!(!ch.recent_kicks.contains_key(&99), "expired +J entry dropped");
        assert!(ch.recent_kicks.contains_key(&88), "fresh +J entry kept");
    }

    #[test]
    fn resolved_host_applied_only_when_configured() {
        let mut s = srv(); // use_resolved_host = true (default)
        let _a = add_user(&mut s, 1, "ann"); // host starts "localhost"
        s.on_resolved(
            1,
            Some("host.example.net".to_string()),
            dnsbl::Outcome::Skipped,
        );
        assert_eq!(s.users[&1].host, "host.example.net");
        assert!(!s.users[&1].dns_pending);

        s.use_resolved_host = false; // resolve + report, but keep the IP in the mask
        let _b = add_user(&mut s, 2, "bob");
        s.on_resolved(
            2,
            Some("host.example.net".to_string()),
            dnsbl::Outcome::Skipped,
        );
        assert_eq!(s.users[&2].host, "localhost");
        assert!(!s.users[&2].dns_pending); // registration still un-held either way
    }

    #[test]
    fn long_date_formats_weekday_and_month() {
        // 1970-01-01 was a Thursday; step across a day and a month boundary.
        assert_eq!(super::long_date(0), "Thu 01 Jan 1970 00:00:00");
        assert_eq!(super::long_date(86400), "Fri 02 Jan 1970 00:00:00");
        assert_eq!(super::long_date(86400 * 31), "Sun 01 Feb 1970 00:00:00");
    }

    #[test]
    fn xline_add_remove_expire_all_notify() {
        let mut s = srv();
        s.name = "irc.test".to_string();
        s.conf_path = std::env::temp_dir().join("echo-xline-notify-test").display().to_string();
        let orx = add_user(&mut s, 1, "op");
        if let Some(u) = s.users.get_mut(&1) {
            u.flags.oper = true;
            u.flags.snomask = true;
            u.flags.snomask_cats = "x".to_string();
        }
        // permanent G-line, then removed → "permanent", no remaining clause
        s.add_xline(crate::xline::XKind::Gline, "*@bad.example", 0, "op", "spam");
        assert!(s.remove_xline(crate::xline::XKind::Gline, "*@bad.example", "op"));
        assert!(!s.remove_xline(crate::xline::XKind::Gline, "*@bad.example", "op")); // gone: no re-announce
        // timed K-line removed early → reports the time it had left
        s.add_xline(crate::xline::XKind::Kline, "*@foo.example", 604800, "op", "temp");
        assert!(s.remove_xline(crate::xline::XKind::Kline, "*@foo.example", "op"));
        // a timed Z-line whose expiry is forced into the past, then purged
        s.add_xline(crate::xline::XKind::Zline, "192.0.2.5", 3600, "op", "temp2");
        for x in s.xlines.iter_mut() {
            if x.mask == "192.0.2.5" {
                x.expires = 1;
            }
        }
        s.purge_xlines();
        let joined: String =
            std::iter::from_fn(|| orx.try_recv().ok()).collect::<Vec<_>>().join("\n");
        assert!(joined.contains("XLINE: op added a permanent G-line on *@bad.example: spam"), "add: {joined}");
        assert!(joined.contains("XLINE: op removed a permanent G-line on *@bad.example"), "remove permanent: {joined}");
        assert!(
            joined.contains("XLINE: op removed a timed K-line on *@foo.example (") && joined.contains("remaining)"),
            "remove timed shows remaining: {joined}"
        );
        assert!(joined.contains("XLINE: Z-line on 192.0.2.5 expired"), "expire: {joined}");
    }

    #[test]
    fn chanlog_routes_by_snomask() {
        use crate::channels::{Channel, Member};
        let mut s = srv();
        // #xlog takes only x-line (x) notices; #all takes every category
        s.raw_config.insert("chanlog".to_string(), vec!["#xlog x".to_string(), "#all".to_string()]);
        let rx = add_user(&mut s, 1, "logbot");
        for name in ["#xlog", "#all"] {
            let mut c = Channel::new(name);
            c.members.insert(1, Member::default());
            s.channels.insert(name.to_string(), c);
        }
        s.snotice_c('x', "XLINEMSG");
        s.snotice_c('c', "CONNMSG");
        let lines: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let logged = |chan: &str, needle: &str| {
            lines.iter().any(|l| l.contains(&format!("PRIVMSG {chan} :")) && l.contains(needle))
        };
        assert!(logged("#xlog", "XLINEMSG"), "x-line notice goes to #xlog: {lines:?}");
        assert!(logged("#all", "XLINEMSG"), "x-line notice goes to #all: {lines:?}");
        assert!(!logged("#xlog", "CONNMSG"), "connect notice filtered out of #xlog: {lines:?}");
        assert!(logged("#all", "CONNMSG"), "connect notice goes to #all: {lines:?}");
    }

    #[test]
    fn post_connect_login_notifies_opers() {
        let mut s = srv();
        // an operator watching client (c) notices
        let orx = add_user(&mut s, 1, "watcher");
        if let Some(u) = s.users.get_mut(&1) {
            u.flags.oper = true;
            u.flags.snomask = true;
            u.flags.snomask_cats = "c".to_string();
        }
        // a REGISTERED user logging in after connecting -> the notice fires
        let _a = add_user(&mut s, 2, "alice");
        if let Some(u) = s.users.get_mut(&2) {
            u.registered = true;
        }
        s.set_login(2, "aliceacct");
        // a not-yet-registered user (SASL at connect) -> silent, since the connect
        // notice already carries the account
        let _b = add_user(&mut s, 3, "bob");
        if let Some(u) = s.users.get_mut(&3) {
            u.registered = false;
        }
        s.set_login(3, "bobacct");
        let seen: String = std::iter::from_fn(|| orx.try_recv().ok())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            seen.contains("Client alice is now logged in as aliceacct"),
            "post-connect login fires the notice: {seen}"
        );
        assert!(
            !seen.contains("bob is now logged in"),
            "an at-connect (unregistered) login stays silent: {seen}"
        );
    }

    #[test]
    fn banned_user_message_shows_expiry() {
        let mut s = srv();
        s.conf_path = std::env::temp_dir().join("echo-ban-expiry-test").display().to_string();
        // permanent K-line: reason only, no expiry tail
        s.add_xline(crate::xline::XKind::Kline, "*@perm.example", 0, "op", "spam");
        let perm = s.matched_xline("bob", "perm.example", "1.2.3.4").unwrap();
        assert_eq!(perm, "K-lined: spam", "permanent ban shows no expiry: {perm}");
        // timed Z-line: reason + when it lifts
        s.add_xline(crate::xline::XKind::Zline, "5.6.7.8", 604800, "op", "botnet");
        let timed = s.matched_xline("bob", "any.host", "5.6.7.8").unwrap();
        assert!(timed.starts_with("Z-lined: botnet (expires in "), "timed ban shows expiry: {timed}");
        assert!(timed.contains(" on ") && timed.ends_with(')'), "with an absolute date: {timed}");
    }

    #[test]
    fn dnsbl_hit_emits_expected_snotices() {
        use std::net::Ipv4Addr;
        let mut s = srv();
        s.name = "irc.test".to_string();
        s.conf_path = std::env::temp_dir().join("echo-dnsbl-test").display().to_string();
        // an operator watching the xline (x) and dnsbl (d) snomasks
        let orx = add_user(&mut s, 1, "watcher");
        if let Some(u) = s.users.get_mut(&1) {
            u.flags.oper = true;
            u.flags.snomask = true;
            u.flags.snomask_cats = "xd".to_string();
        }
        // the connecting user tripping the blocklist — a distinct IP so the ban
        // doesn't also match the watcher (add_user gives everyone 127.0.0.1).
        let _brx = add_user(&mut s, 2, "badguy");
        if let Some(u) = s.users.get_mut(&2) {
            u.addr = "[2a06:1700:0:12::1]:6667".parse().unwrap();
        }
        s.dnsbl_zones = vec![crate::modules::dnsbl::parse_zone(
            "domain=torexit.dan.me.uk name=\"Tor exit node\" action=zline duration=1w \
             reason=\"Tor exit nodes are not allowed on this network. \
             See https://metrics.torproject.org/rs.html#search/%ip% for more information.\"",
        )
        .unwrap()];
        crate::modules::dnsbl::report(
            &mut s,
            2,
            crate::modules::dnsbl::Outcome::Hit {
                zone: "torexit.dan.me.uk".to_string(),
                reply: Ipv4Addr::new(127, 0, 0, 2),
            },
        );
        let joined: String =
            std::iter::from_fn(|| orx.try_recv().ok()).collect::<Vec<_>>().join("\n");
        assert!(
            joined.contains(
                "XLINE: dnsbl@irc.test added a timed Z-line on 2a06:1700:0:12::1, expires in 1 week (on "
            ),
            "xline notice: {joined}"
        );
        assert!(
            joined.contains("detected as being on the 'torexit.dan.me.uk' DNSBL: Tor exit node"),
            "dnsbl notice: {joined}"
        );
        assert!(joined.contains("search/2a06:1700:0:12::1 for more information."), "%ip% substituted: {joined}");
        assert!(!joined.contains("%ip%"), "no literal %ip% left: {joined}");
    }

    #[test]
    fn join_broadcasts_and_tracks_membership() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        let brx = add_user(&mut s, 2, "bob");
        s.join(1, "#c", None); // ann creates -> gets @
        s.join(2, "#c", None); // bob joins

        assert!(s.channels["#c"].members[&1].op());
        assert!(!s.channels["#c"].members[&2].op());
        assert_eq!(s.channels["#c"].members.len(), 2);

        let ann: Vec<String> = arx.try_iter().collect();
        assert!(ann
            .iter()
            .any(|l| l.contains("JOIN #c") && l.contains("ann!")));
        assert!(ann
            .iter()
            .any(|l| l.contains(":bob!") && l.contains("JOIN #c")));
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(bob.iter().any(|l| l.contains("353") && l.contains("@ann")));
    }

    #[test]
    fn rename_moves_channel_and_notifies_by_cap() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann"); // op, cap-aware
        let brx = add_user(&mut s, 2, "bob"); // no cap
        s.users.get_mut(&1).unwrap().caps.channel_rename = true;
        s.join(1, "#old", None); // ann creates -> op
        s.join(2, "#old", None);
        let _ = arx.try_iter().count(); // drain the join chatter
        let _ = brx.try_iter().count();

        let key = s.rename_channel("#old", "#new", "ann!u@localhost", "moving");
        assert_eq!(key.as_deref(), Some("#new"));
        assert!(!s.channels.contains_key("#old"), "old key gone");
        assert!(s.channels.contains_key("#new"), "new key present");
        assert_eq!(s.channels["#new"].members.len(), 2, "membership preserved");
        assert!(s.users[&1].channels.contains("#new") && !s.users[&1].channels.contains("#old"));
        assert!(s.users[&2].channels.contains("#new") && !s.users[&2].channels.contains("#old"));

        // The cap holder sees a RENAME; the plain client is walked PART -> JOIN.
        let ann: Vec<String> = arx.try_iter().collect();
        assert!(ann.iter().any(|l| l.contains("RENAME #old #new")), "cap client got RENAME: {ann:?}");
        assert!(!ann.iter().any(|l| l.contains("PART #old")), "cap client not PARTed");
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(bob.iter().any(|l| l.contains("PART #old")), "plain client PARTed: {bob:?}");
        assert!(bob.iter().any(|l| l.contains("JOIN #new")), "plain client re-JOINed");
        assert!(!bob.iter().any(|l| l.contains("RENAME")), "plain client got no RENAME");
    }

    #[test]
    fn rename_case_only_keeps_key_and_skips_fallback() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        s.join(1, "#chan", None);
        let _ = arx.try_iter().count();
        let key = s.rename_channel("#chan", "#Chan", "ann!u@localhost", "");
        assert_eq!(key.as_deref(), Some("#chan"), "key unchanged on a case-only rename");
        assert_eq!(s.channels["#chan"].name, "#Chan", "display casing updated");
        // Non-cap member: the spec says no PART/JOIN fallback for a case change.
        let ann: Vec<String> = arx.try_iter().collect();
        assert!(!ann.iter().any(|l| l.contains("PART")), "no fallback on case-only: {ann:?}");
    }

    #[test]
    fn to_channel_tagged_shares_and_tags_by_profile() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann"); // plain
        let brx = add_user(&mut s, 2, "bob"); // server-time
        let crx = add_user(&mut s, 3, "cara"); // message-tags + account-tag
        let drx = add_user(&mut s, 4, "dave"); // the sender (has an account)
        s.users.get_mut(&2).unwrap().caps.server_time = true;
        s.users.get_mut(&3).unwrap().caps.message_tags = true;
        s.users.get_mut(&3).unwrap().caps.account_tag = true;
        s.users.get_mut(&4).unwrap().account = Some("dv".into());
        for u in [1, 2, 3, 4] {
            s.join(u, "#c", None);
        }
        for rx in [&arx, &brx, &crx, &drx] {
            let _ = rx.try_iter().count();
        }
        s.to_channel_tagged("#c", 4, "", "abc123", ":dave!u@h PRIVMSG #c :hi", false);
        let ann: Vec<String> = arx.try_iter().collect();
        let bob: Vec<String> = brx.try_iter().collect();
        let cara: Vec<String> = crx.try_iter().collect();
        let dave: Vec<String> = drx.try_iter().collect();
        assert!(ann.iter().any(|l| l == ":dave!u@h PRIVMSG #c :hi"), "plain untagged: {ann:?}");
        assert!(
            bob.iter().any(|l| l.starts_with("@time=") && l.ends_with(":dave!u@h PRIVMSG #c :hi")),
            "server-time tagged: {bob:?}"
        );
        assert!(
            cara.iter().any(|l| l.contains("account=dv") && l.contains("msgid=abc123")),
            "message-tags+account-tag both present: {cara:?}"
        );
        assert!(dave.is_empty(), "sender is excluded from the fanout: {dave:?}");
    }

    #[test]
    fn to_channel_shares_line_and_tags_server_time_members() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann"); // plain (no server-time)
        let brx = add_user(&mut s, 2, "bob");
        s.users.get_mut(&2).unwrap().caps.server_time = true;
        s.join(1, "#c", None);
        s.join(2, "#c", None);
        let _ = arx.try_iter().count();
        let _ = brx.try_iter().count();
        s.to_channel("#c", ":x!u@h TOPIC #c :hi", None);
        let ann: Vec<String> = arx.try_iter().collect();
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(
            ann.iter().any(|l| l == ":x!u@h TOPIC #c :hi"),
            "plain member gets the untagged line: {ann:?}"
        );
        assert!(
            bob.iter()
                .any(|l| l.starts_with("@time=") && l.ends_with(":x!u@h TOPIC #c :hi")),
            "server-time member gets the @time= variant: {bob:?}"
        );
    }

    #[test]
    fn isupport_advertises_bot_and_account_extban() {
        let s = srv();
        let joined = s.isupport_lines(&s.network).join(" ");
        assert!(joined.contains("BOT=B"), "bot-mode letter: {joined}");
        assert!(joined.contains("ACCOUNTEXTBAN=a"), "account-extban token: {joined}");
        assert!(joined.contains("EXTBAN=,aG"), "'a' listed in EXTBAN: {joined}");
    }

    #[test]
    fn account_extban_matches_by_account_glob() {
        let mut s = srv();
        add_user(&mut s, 1, "ann");
        s.users.get_mut(&1).unwrap().account = Some("spammer".into());
        add_user(&mut s, 2, "bob"); // no account
        assert!(crate::modules::accountban::matches(&s, 1, "spam*"));
        assert!(!crate::modules::accountban::matches(&s, 1, "other"));
        assert!(!crate::modules::accountban::matches(&s, 2, "*"), "no account never matches");
    }

    #[test]
    fn no_implicit_names_suppresses_the_join_names_burst() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        s.users.get_mut(&1).unwrap().caps.no_implicit_names = true;
        s.join(1, "#c", None);
        let al: Vec<String> = arx.try_iter().collect();
        assert!(al.iter().any(|l| l.contains("JOIN #c")), "still gets its JOIN");
        assert!(!al.iter().any(|l| l.contains(" 353 ")), "no NAMREPLY: {al:?}");
        assert!(!al.iter().any(|l| l.contains(" 366 ")), "no ENDOFNAMES");
        // a client without the cap still gets the implicit NAMES
        let brx = add_user(&mut s, 2, "bob");
        s.join(2, "#c", None);
        let bl: Vec<String> = brx.try_iter().collect();
        assert!(bl.iter().any(|l| l.contains(" 353 ")) && bl.iter().any(|l| l.contains(" 366 ")));
    }

    #[test]
    fn nick_change_reindexes_and_notifies_channel() {
        let mut s = srv();
        let arx = add_user(&mut s, 1, "ann");
        add_user(&mut s, 2, "bob");
        s.join(1, "#c", None);
        s.join(2, "#c", None);
        s.set_nick(1, "annie");
        assert_eq!(s.find_nick("annie"), Some(1));
        assert_eq!(s.find_nick("ann"), None);
        let ann: Vec<String> = arx.try_iter().collect();
        assert!(ann
            .iter()
            .any(|l| l.contains("NICK :annie") && l.contains("ann!")));
    }

    #[test]
    fn quit_frees_the_nick_and_tells_neighbors() {
        let mut s = srv();
        add_user(&mut s, 1, "ann");
        let brx = add_user(&mut s, 2, "bob");
        s.join(1, "#c", None);
        s.join(2, "#c", None);
        s.remove_user(1, "bye");
        assert!(s.find_nick("ann").is_none());
        assert!(!s.channels["#c"].members.contains_key(&1));
        let bob: Vec<String> = brx.try_iter().collect();
        assert!(bob
            .iter()
            .any(|l| l.contains(":ann!") && l.contains("QUIT :bye")));
    }

    #[test]
    fn moderated_channel_needs_voice() {
        let mut s = srv();
        add_user(&mut s, 1, "ann");
        add_user(&mut s, 2, "bob");
        s.join(1, "#c", None); // ann = op
        s.join(2, "#c", None);
        s.channels.get_mut("#c").unwrap().modes.moderated = true;
        assert!(s.is_op(1, "#c") && !s.is_op(2, "#c"));
        assert!(s.is_member(2, "#c"));
    }

    #[test]
    fn secure_only_channel_rejects_plaintext() {
        let mut s = srv();
        add_user(&mut s, 1, "tls");
        s.users.get_mut(&1).unwrap().secure = true; // on TLS
        add_user(&mut s, 2, "plain"); // add_user defaults secure=false
        s.join(1, "#z", None); // tls creates -> op
        s.channels.get_mut("#z").unwrap().modes.secure_only = true;
        s.join(2, "#z", None); // plaintext tries to join
        assert!(s.is_member(1, "#z")); // the TLS user stays
        assert!(!s.is_member(2, "#z")); // the plaintext user is refused
    }

    #[test]
    fn reg_only_channel_rejects_unregistered() {
        let mut s = srv();
        add_user(&mut s, 1, "member");
        s.users.get_mut(&1).unwrap().account = Some("acct".to_string()); // logged in
        add_user(&mut s, 2, "guest"); // account None
        s.join(1, "#r", None); // logged-in user creates -> op
        s.channels.get_mut("#r").unwrap().modes.reg_only = true;
        s.join(2, "#r", None); // guest tries to join
        assert!(s.is_member(1, "#r")); // the logged-in user stays
        assert!(!s.is_member(2, "#r")); // the guest is refused
    }

    #[test]
    fn iso_time_formats_server_time() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_000_000_000), "2001-09-09T01:46:40.000Z");
    }

    #[test]
    fn nick_and_chan_validation() {
        assert!(valid_nick("reverse", 30));
        assert!(valid_nick("[abc]`", 30));
        assert!(!valid_nick("1abc", 30)); // can't start with a digit
        assert!(!valid_nick("", 30));
        assert!(valid_chan("#argentina", 50));
        assert!(!valid_chan("argentina", 50));
        assert!(!valid_chan("#a b", 50));
    }

    #[test]
    fn idle_check_pings_then_times_out() {
        let mut s = srv();
        add_user(&mut s, 1, "ann"); // registered, last_active = 0
        let now = 1000;
        let (ping, quit) = s.idle_check(now);
        assert_eq!(ping, vec![1]); // idle -> PING
        assert!(quit.is_empty());

        s.users.get_mut(&1).unwrap().ping_sent = true;
        let (ping, quit) = s.idle_check(now);
        assert!(ping.is_empty()); // already pinged
        assert_eq!(quit, vec![1]); // no reply -> ping timeout

        s.users.get_mut(&1).unwrap().ping_sent = false;
        s.users.get_mut(&1).unwrap().last_active = now;
        let (ping, quit) = s.idle_check(now);
        assert!(ping.is_empty() && quit.is_empty()); // active -> left alone

        s.users.get_mut(&1).unwrap().registered = false;
        s.users.get_mut(&1).unwrap().last_active = 0;
        let (_, quit) = s.idle_check(now);
        assert_eq!(quit, vec![1]); // unregistered + idle -> registration timeout
    }
}
