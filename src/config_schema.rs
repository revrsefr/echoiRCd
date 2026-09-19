//! Declarative schema for the block config format — the set of blocks echoIRCd
//! accepts, in canonical order, and the fields legal inside each.
//!
//! `config::validate_config` checks every loaded config against this table. For a
//! **structural** block (`server`, `listen`, `oper`, …) an unknown field, a missing
//! required field, a duplicate of a non-repeatable block, or a malformed numeric /
//! boolean value is a hard error, reported with its line number — so a typo is
//! caught at load instead of being silently dropped. A **grouping** block's fields
//! flatten to plain runtime keys; a field that is not a known key is a soft warning
//! (the key universe includes keys read through per-module helpers that cannot all
//! be enumerated statically, so an unknown grouping field never blocks boot).
//!
//! The order of `BLOCKS` is the canonical order a config should be written in and
//! the order `echoircd.conf.example` follows.

/// Whether a block maps to fixed internal fields (strict) or is a flat-key group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Structural,
    Grouping,
}

/// The value shape of a structural field (drives the load-time type check).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ft {
    /// Free text.
    Str,
    /// Must parse as a non-negative integer.
    Int,
    /// A boolean: `yes`/`no`/`true`/`false`/`on`/`off`/`1`/`0`, or bare (= yes).
    Flag,
}

/// One legal field of a structural block. `names[0]` is canonical; the rest are aliases.
pub struct FieldSpec {
    pub names: &'static [&'static str],
    pub ft: Ft,
    pub required: bool,
}

/// One legal block.
pub struct BlockSpec {
    pub name: &'static str,
    pub kind: Kind,
    /// May appear more than once (listen, oper, link, …).
    pub repeatable: bool,
    /// At least one must be present for a usable server (server, listen).
    pub required: bool,
    /// Body is free-form quoted lines rather than named fields (motd / opermotd).
    pub lines: bool,
    /// Legal fields (structural only; empty for grouping blocks and line blocks).
    pub fields: &'static [FieldSpec],
}

impl BlockSpec {
    /// Look up a field by name or alias (case-insensitive).
    pub fn field(&self, name: &str) -> Option<&'static FieldSpec> {
        self.fields
            .iter()
            .find(|f| f.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
    }
}

macro_rules! f {
    ($ft:ident, $req:expr, $($n:literal),+) => {
        FieldSpec { names: &[$($n),+], ft: Ft::$ft, required: $req }
    };
}

// ── structural field tables ──────────────────────────────────────────────────
const SERVER: &[FieldSpec] = &[
    f!(Str, true, "name"),
    f!(Str, false, "network"),
    f!(Str, true, "sid"),
    f!(Str, false, "description", "desc"),
    f!(Str, false, "pidfile"),
];
const LISTEN: &[FieldSpec] = &[
    f!(Str, true, "ip"),
    f!(Int, true, "port"),
    f!(Str, false, "type"),
    f!(Flag, false, "tls"),
    f!(Flag, false, "wss"),
    f!(Flag, false, "ws"),
];
const TLS: &[FieldSpec] = &[
    f!(Str, false, "cert"),
    f!(Str, false, "key"),
    f!(Str, false, "backend"),
    f!(Str, false, "sni"),
    f!(Int, false, "handshake_timeout"),
];
const BRAND: &[FieldSpec] = &[
    f!(Str, true, "host"),
    f!(Str, false, "servername"),
    f!(Str, false, "network"),
];
const OPER: &[FieldSpec] = &[
    f!(Str, true, "name"),
    f!(Str, false, "password"),
    f!(Str, false, "fingerprint", "fp", "certfp"),
    f!(Str, false, "type"),
    f!(Str, false, "rsakey", "key"),
    f!(Str, false, "ldapdn"),
    f!(Int, false, "level"),
];
const CLASS: &[FieldSpec] = &[
    f!(Str, true, "name"),
    f!(Str, false, "commands"),
    f!(Str, false, "privs"),
    f!(Str, false, "snomasks"),
    f!(Str, false, "usermodes"),
    f!(Str, false, "chanmodes"),
];
const OPERTYPE: &[FieldSpec] = &[
    f!(Str, true, "name"),
    f!(Str, false, "classes"),
    f!(Str, false, "modes"),
    f!(Str, false, "title"),
    f!(Int, false, "level"),
];
const LINK: &[FieldSpec] = &[
    f!(Str, true, "name"),
    f!(Str, true, "ip"),
    f!(Int, true, "port"),
    f!(Str, false, "password"),
    f!(Flag, false, "autoconnect"),
    f!(Flag, false, "services", "uline"),
];
const SERVICES: &[FieldSpec] = &[f!(Str, false, "sasl_server")];
const WEBIRC: &[FieldSpec] = &[
    f!(Str, true, "password"),
    f!(Str, false, "name", "gateway"),
    f!(Str, false, "mask", "ipmask"),
];
const CLOAK: &[FieldSpec] = &[
    f!(Str, false, "key"),
    f!(Str, false, "method"),
    f!(Str, false, "static_host", "static"),
    f!(Str, false, "account_prefix"),
    f!(Str, false, "cert_prefix"),
];

macro_rules! structural {
    ($name:literal, $rep:expr, $req:expr, $fields:expr) => {
        BlockSpec {
            name: $name,
            kind: Kind::Structural,
            repeatable: $rep,
            required: $req,
            lines: false,
            fields: $fields,
        }
    };
}
macro_rules! lines_block {
    ($name:literal) => {
        BlockSpec {
            name: $name,
            kind: Kind::Structural,
            repeatable: false,
            required: false,
            lines: true,
            fields: &[],
        }
    };
}
macro_rules! group {
    ($name:literal, $rep:expr) => {
        BlockSpec {
            name: $name,
            kind: Kind::Grouping,
            repeatable: $rep,
            required: false,
            lines: false,
            fields: &[],
        }
    };
}

/// Every block echoIRCd accepts, in canonical order.
pub static BLOCKS: &[BlockSpec] = &[
    // identity & core listeners
    structural!("server", false, true, SERVER),
    group!("options", false),
    group!("set", false),
    structural!("listen", true, true, LISTEN),
    structural!("tls", false, false, TLS),
    lines_block!("motd"),
    lines_block!("opermotd"),
    structural!("brand", true, false, BRAND),
    // operators
    structural!("oper", true, false, OPER),
    structural!("class", true, false, CLASS),
    structural!("opertype", true, false, OPERTYPE),
    // linking & gateways
    structural!("link", true, false, LINK),
    structural!("services", false, false, SERVICES),
    structural!("webirc", true, false, WEBIRC),
    // host handling
    structural!("cloak", false, false, CLOAK),
    group!("dns", false),
    group!("dnsbl", true),
    // limits & tuning
    group!("limits", false),
    group!("timeouts", false),
    group!("flood", false),
    group!("connections", false),
    group!("classes", false),
    group!("sts", false),
    // operator & channel behaviour
    group!("opers", false),
    group!("channelvis", false),
    group!("channels", false),
    group!("users", false),
    // accounts & verification
    group!("accounts", false),
    group!("verification", false),
    group!("control", false),
    // anti-abuse
    group!("antiabuse", false),
    group!("restrictions", false),
    group!("reputation", false),
    group!("securitygroups", false),
    // observability & storage
    group!("logging", false),
    group!("database", false),
    group!("redis", false),
    group!("sqlquery", false),
    // modules & transports
    group!("modules", false),
    group!("websocket", false),
];

/// Look up a block spec by name (case-insensitive).
pub fn block(name: &str) -> Option<&'static BlockSpec> {
    BLOCKS.iter().find(|b| b.name.eq_ignore_ascii_case(name))
}

/// True if `k` is a runtime key the daemon is known to read (drives the soft
/// unknown-field warning for grouping blocks).
pub fn is_known_key(k: &str) -> bool {
    KNOWN_KEYS.iter().any(|n| n.eq_ignore_ascii_case(k))
}

include!("config_known_keys.rs");
