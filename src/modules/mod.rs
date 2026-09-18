//! Optional, pluggable modules. Most hook lifecycle events via the
//! [`crate::module::Module`] trait; [`dnsbl`] is the exception — it's driven from
//! the connection lifecycle rather than the hook bus, but lives here as its own
//! self-contained unit.

pub mod account_registration;
pub mod accountban;
pub mod antimixedutf8;
pub mod antirandom;
pub mod asn;
pub mod autodrop;
pub mod autoop;
pub mod banredirect;
pub mod blockamsg;
pub mod masshighlight;
pub mod bridge;
pub mod chanlog;
pub mod channames;
pub mod channelban;
pub mod chathistory;
pub mod classban;
pub mod clearmode;
pub mod cloak;
pub mod clones;
pub mod cloudflare_challenge;
pub mod conn_waitpong;
pub mod connclass;
pub mod connectban;
pub mod connflood;
pub mod customprefix;
pub mod customtitle;
pub mod dccallow;
pub mod denychans;
pub mod disable;
pub mod dnsbl;
pub mod event_playback;
pub mod extbanbanlist;
pub mod extended_isupport;
pub mod extjwt;
pub mod filehost;
pub mod filter;
pub mod flood;
pub mod geoip;
pub mod globops;
pub mod hashident;
pub mod hidelist;
pub mod hidemode;
pub mod hidewhois;
pub mod ident;
pub mod irccloudtags;
pub mod jsonlog;
pub mod jumpserver;
pub mod jwt;
pub mod lockserv;
pub mod log_json;
pub mod maphide;
pub mod markread;
pub mod metadata;
pub mod metrics;
pub mod metricslog;
pub mod modenotice;
pub mod multiline;
pub mod namedmodes;
pub mod network_icon;
pub mod ojoin;
pub mod operlevels;
pub mod operprefix;
pub mod opertypes;
pub mod password_hash;
pub mod pattern;
pub mod permchannels;
pub mod profilelink;
pub mod randquote;
pub mod realnameban;
pub mod recaptcha;
pub mod relaymsg;
pub mod reputation;
pub mod require_auth;
pub mod restrictchans;
pub mod restrictcommands;
pub mod restrictmsg;
pub mod rmode;
pub mod rpc;
pub mod securelist;
pub mod securitygroups;
pub mod serverban;
pub mod showfile;
pub mod snoop;
pub mod solvemsg;
pub mod sqlquery;
pub mod syslog;
pub mod targetlimit;
pub mod tline;
pub mod userip;
pub mod verify_common;
pub mod webpush;
pub mod whoisport;
pub mod xlinetools;

use crate::command::Command;
use crate::module::Module;

/// The modules loaded at boot. (Later: load by name from the config.)
pub fn default_modules() -> Vec<Box<dyn Module>> {
    vec![
        Box::new(snoop::Snoop),
        Box::new(flood::Flood),
        Box::new(cloak::Cloak),
        Box::new(antimixedutf8::AntiMixedUtf8),
        Box::new(filter::Filter),
        Box::new(metadata::Metadata),
        Box::new(markread::MarkRead),
        Box::new(multiline::Multiline),
        Box::new(reputation::ReputationMod::default()),
        Box::new(connflood::ConnFlood),
        Box::new(antirandom::AntiRandom),
        Box::new(restrictcommands::RestrictCommands),
        Box::new(restrictmsg::RestrictMsg),
        Box::new(blockamsg::BlockAmsg),
        Box::new(masshighlight::MassHighlight),
        Box::new(connectban::ConnectBan),
        Box::new(securelist::SecureList),
        Box::new(hashident::HashIdent),
        Box::new(recaptcha::ReCaptcha),
        Box::new(cloudflare_challenge::CloudflareChallenge),
        Box::new(filehost::FileHost),
        Box::new(irccloudtags::IrcCloudTags),
        Box::new(randquote::RandQuote),
        Box::new(disable::Disable),
        Box::new(maphide::MapHide),
        Box::new(dccallow::DccAllow),
        Box::new(solvemsg::SolveMsg),
        Box::new(autoop::AutoOp),
        Box::new(autodrop::AutoDrop),
        Box::new(operprefix::OperPrefix),
        Box::new(opertypes::OperTypes),
        Box::new(permchannels::PermChannels::default()),
        Box::new(chathistory::ChatHistoryGc),
        Box::new(event_playback::EventPlayback),
        Box::new(webpush::WebPush),
        Box::new(targetlimit::TargetLimit),
        Box::new(bridge::Bridge),
        Box::new(metricslog::MetricsLog::default()),
        Box::new(account_registration::AcctRegGc),
    ]
}

/// The names of the modules loaded at boot (drives the `module.list` RPC).
pub fn module_names() -> Vec<String> {
    default_modules()
        .iter()
        .map(|m| m.name().to_string())
        .collect()
}

/// `(name, description)` for every hook-bus module loaded at boot.
pub fn hooked_module_list() -> Vec<(String, String)> {
    default_modules()
        .iter()
        .map(|m| (m.name().to_string(), m.description().to_string()))
        .collect()
}

/// Modules that register through paths other than the hook bus — commands, channel/user
/// modes, extbans, the connection lifecycle, WHOIS and log targets — and so aren't in
/// `default_modules()`. Listed here so `/MODULES` reflects the full compiled-in module set.
pub fn extra_module_list() -> Vec<(&'static str, &'static str)> {
    vec![
        ("accountban", "a: extban — match/ban a user by their services account"),
        ("asn", "Autonomous-system (ASN) lookups from the GeoLite2-ASN database"),
        ("banredirect", "Ban +b mask$#chan bounces the banned user into #chan"),
        ("chanlog", "Mirrors the oper server-notice (snotice) stream into a channel"),
        ("channames", "Restricts which characters may appear in new channel names"),
        ("channelban", "j: extban — match/ban a user by another channel they are in"),
        ("classban", "C: extban — match/ban a user by their connect class name"),
        ("clearmode", "CLEARMODE — strip all channel modes and the +b/+e/+I lists at once"),
        ("clones", "CLONES — list local IPs with multiple connections (clone floods)"),
        ("connclass", "Connection classes — match clients by IP/host, apply per-class limits"),
        ("conn_waitpong", "Holds registration until the client answers a PING cookie (bot filter)"),
        ("customprefix", "Reconfigures channel prefix tiers and defines new status prefixes"),
        ("customtitle", "TITLE — claim a configured WHOIS title (and optional vhost)"),
        ("denychans", "Forbids joining channels matching a badchan glob (optional redirect)"),
        ("dnsbl", "DNS blocklist checks on connect (per-zone action)"),
        ("extbanbanlist", "b: extban — match a user who is on another channel's ban list"),
        ("extended_isupport", "draft/extended-isupport — client can re-request ISUPPORT on demand"),
        ("extjwt", "EXTJWT — signed JWT proving a client's IRC identity to external services"),
        ("geoip", "MaxMind geolocation (country/city/ASN), the G: geoban and GEOIP command"),
        ("globops", "GLOBOPS — send a message to all opers via the server-notice stream"),
        ("hidelist", "Hides a channel list mode's entries (e.g. +b) from members below a rank"),
        ("hidemode", "Hides specific mode changes from members below a rank"),
        ("hidewhois", "Hides sensitive WHOIS lines (server, idle, secure) from ordinary users"),
        ("ident", "Optional RFC 1413 ident lookups on connect"),
        ("jsonlog", "draft/json-log cap — an oper's server notices delivered as structured JSON"),
        ("jumpserver", "JUMPSERVER — redirect new connections to another server (RPL_REDIR)"),
        ("lockserv", "LOCKSERV/UNLOCKSERV — stop and resume new local connections"),
        ("log_json", "Appends the log/snotice stream to a file as JSON lines (JSONL)"),
        ("metrics", "Optional Prometheus/OpenMetrics HTTP endpoint"),
        ("modenotice", "MODENOTICE — message all local users who have given user modes"),
        ("namedmodes", "PROP — set/query channel modes by long name instead of letter"),
        ("network_icon", "Advertises a network icon URL via the ICON ISUPPORT token"),
        ("ojoin", "OJOIN — an oper joins a channel as network staff with the oper prefix"),
        ("operlevels", "Numeric oper levels — a lower-level oper can't KILL a higher one"),
        ("password_hash", "Hashed oper passwords + the MKPASSWD helper (OpenSSL-backed)"),
        ("profilelink", "Adds a profile URL to WHOIS for logged-in users"),
        ("realnameban", "r: extban — match/ban a user by real name (GECOS)"),
        ("relaymsg", "RELAYMSG (draft/relaymsg) — relay a message under a foreign nick"),
        ("require_auth", "ALINE/GALINE — force matching masks to log in (SASL) before registering"),
        ("restrictchans", "Only opers may create channels (optional per-glob whitelist)"),
        ("rmode", "RMODE — bulk-remove entries from a channel list mode (+b/+e/+I) by glob"),
        ("rpc", "JSON-RPC control API over HTTP (list/kill users, bans, rehash)"),
        ("securitygroups", "Named security groups — reusable user-matching sets for policy"),
        ("serverban", "s: extban — match/ban a user by the server they are on"),
        ("showfile", "Serves a configured text file as its own command"),
        ("slowmode", "Channel mode +W — per-user message rate limit (count:secs)"),
        ("sqlquery", "SQLQUERY — a read-only SQL console over IRC for administrators"),
        ("syslog", "Mirrors the log/snotice stream to the system logger (syslog)"),
        ("tline", "TLINE — report how many connected users a K/G/Z-line mask would hit"),
        ("userip", "USERIP — show a user's ident and real IP (RPL_USERIP)"),
        ("whoisport", "Shows opers, in WHOIS, which listener port the target connected to"),
        ("xlinetools", "XSEARCH/XCOUNT/XREMOVE/XCOPY — search and manage x-lines"),
    ]
}

/// `(name, description)` for every module in the build, sorted by name — drives `/MODULES`.
pub fn module_list() -> Vec<(String, String)> {
    let mut list = hooked_module_list();
    list.extend(
        extra_module_list()
            .into_iter()
            .map(|(n, d)| (n.to_string(), d.to_string())),
    );
    list.sort_by(|a, b| a.0.cmp(&b.0));
    list
}

/// Commands contributed by modules (chained into the core command table), so a
/// module that adds a command keeps it in its own file.
pub fn module_commands() -> Vec<Box<dyn Command>> {
    filter::commands()
        .into_iter()
        .chain(metadata::commands())
        .chain(markread::commands())
        .chain(multiline::commands())
        .chain(chathistory::commands())
        .chain(reputation::commands())
        .chain(securitygroups::commands())
        .chain(password_hash::commands())
        .chain(account_registration::commands())
        .chain(recaptcha::commands())
        .chain(cloudflare_challenge::commands())
        .chain(extjwt::commands())
        .chain(filehost::commands())
        .chain(extended_isupport::commands())
        .chain(tline::commands())
        .chain(rmode::commands())
        .chain(clearmode::commands())
        .chain(customtitle::commands())
        .chain(dccallow::commands())
        .chain(geoip::commands())
        .chain(globops::commands())
        .chain(relaymsg::commands())
        .chain(ojoin::commands())
        .chain(namedmodes::commands())
        .chain(webpush::commands())
        .chain(sqlquery::commands())
        .chain(bridge::commands())
        .chain(metricslog::commands())
        .chain(clones::commands())
        .chain(userip::commands())
        .chain(modenotice::commands())
        .chain(lockserv::commands())
        .chain(jumpserver::commands())
        .chain(xlinetools::commands())
        .chain(require_auth::commands())
        .collect()
}
