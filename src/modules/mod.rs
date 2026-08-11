//! Optional, pluggable modules. Most hook lifecycle events via the
//! [`crate::module::Module`] trait; [`dnsbl`] is the exception — it's driven from
//! the connection lifecycle rather than the hook bus, but lives here as its own
//! self-contained unit.

pub mod account_registration;
pub mod antimixedutf8;
pub mod antirandom;
pub mod autodrop;
pub mod autoop;
pub mod banredirect;
pub mod blockamsg;
pub mod channames;
pub mod channelban;
pub mod chanlog;
pub mod chathistory;
pub mod cloak;
pub mod cloudflare_challenge;
pub mod conn_waitpong;
pub mod connclass;
pub mod connectban;
pub mod connflood;
pub mod customtitle;
pub mod dccallow;
pub mod denychans;
pub mod disable;
pub mod dnsbl;
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
pub mod jwt;
pub mod log_json;
pub mod maphide;
pub mod markread;
pub mod metadata;
pub mod multiline;
pub mod network_icon;
pub mod ojoin;
pub mod operlevels;
pub mod operprefix;
pub mod password_hash;
pub mod profilelink;
pub mod randquote;
pub mod realnameban;
pub mod recaptcha;
pub mod relaymsg;
pub mod reputation;
pub mod restrictchans;
pub mod restrictcommands;
pub mod restrictmsg;
pub mod rmode;
pub mod rpc;
pub mod securelist;
pub mod securitygroups;
pub mod serverban;
pub mod showfile;
pub mod solvemsg;
pub mod snoop;
pub mod syslog;
pub mod tline;
pub mod whoisport;

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
    ]
}

/// The names of the modules loaded at boot (drives the `module.list` RPC).
pub fn module_names() -> Vec<String> {
    default_modules()
        .iter()
        .map(|m| m.name().to_string())
        .collect()
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
        .chain(customtitle::commands())
        .chain(dccallow::commands())
        .chain(geoip::commands())
        .chain(globops::commands())
        .chain(relaymsg::commands())
        .chain(ojoin::commands())
        .collect()
}
