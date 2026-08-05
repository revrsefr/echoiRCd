//! Optional, pluggable modules — echoIRCd's answer to InspIRCd's `src/modules/`.
//! Each hooks lifecycle events via the [`crate::module::Module`] trait.

pub mod antimixedutf8;
pub mod cloak;
pub mod flood;
pub mod snoop;

use crate::module::Module;

/// The modules loaded at boot. (Later: load by name from the config.)
pub fn default_modules() -> Vec<Box<dyn Module>> {
    vec![
        Box::new(snoop::Snoop),
        Box::new(flood::Flood),
        Box::new(cloak::Cloak),
        Box::new(antimixedutf8::AntiMixedUtf8),
    ]
}
