//! Built-in commands. Each module exposes `commands()`; [`command_table`]
//! assembles the registry the core dispatches through.

pub mod core_channel;
pub mod core_extra;
pub mod core_info;
pub mod core_message;
pub mod core_mode;
pub mod core_oper;
pub mod core_rehash;
pub mod core_user;
pub mod core_watch;

use crate::map::HashMap;

use crate::command::Command;

pub fn command_table() -> HashMap<&'static str, Box<dyn Command>> {
    let mut m: HashMap<&'static str, Box<dyn Command>> = HashMap::default();
    for c in core_user::commands()
        .into_iter()
        .chain(core_channel::commands())
        .chain(core_message::commands())
        .chain(core_mode::commands())
        .chain(core_oper::commands())
        .chain(core_rehash::commands())
        .chain(core_info::commands())
        .chain(core_extra::commands())
        .chain(core_watch::commands())
        .chain(crate::modules::module_commands())
    {
        m.insert(c.name(), c);
    }
    m
}
