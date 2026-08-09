//! Optional, pluggable modules — echoIRCd's answer to InspIRCd's `src/modules/`.
//! Most hook lifecycle events via the [`crate::module::Module`] trait; [`dnsbl`]
//! is the exception — it's driven straight from the connection lifecycle rather
//! than the hook bus, but lives here as its own self-contained unit.

pub mod antimixedutf8;
pub mod antirandom;
pub mod blockamsg;
pub mod channelban;
pub mod chathistory;
pub mod cloak;
pub mod connectban;
pub mod connflood;
pub mod dnsbl;
pub mod filter;
pub mod flood;
pub mod hidewhois;
pub mod markread;
pub mod metadata;
pub mod multiline;
pub mod network_icon;
pub mod profilelink;
pub mod realnameban;
pub mod reputation;
pub mod restrictcommands;
pub mod restrictmsg;
pub mod securitygroups;
pub mod serverban;
pub mod snoop;
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
    ]
}

/// Commands contributed by modules (chained into the core command table), so a
/// module that adds a command keeps it in its own file, InspIRCd-style.
pub fn module_commands() -> Vec<Box<dyn Command>> {
    filter::commands()
        .into_iter()
        .chain(metadata::commands())
        .chain(markread::commands())
        .chain(multiline::commands())
        .chain(chathistory::commands())
        .chain(reputation::commands())
        .chain(securitygroups::commands())
        .collect()
}
