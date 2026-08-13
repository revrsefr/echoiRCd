# The `Command` trait

A command is a stateless handler registered by name. Implement
`crate::command::Command`:

```rust
pub trait Command: Send {
    fn name(&self) -> &'static str;          // upper-case; also the registry key
    fn min_params(&self) -> usize { 0 }      // fewer args ⇒ core replies 461, skips you
    fn before_reg(&self) -> bool { false }   // may it run before registration?
    fn handle(&self, srv: &mut Server, uid: Uid, params: &[String]) -> CmdResult;
}

pub enum CmdResult { Ok, Fail }              // Fail is for your own bookkeeping/logging
```

The core does the boilerplate for you before `handle` is called:

- **Arity** — if the client sent fewer than `min_params` arguments, the core
  replies `461 ERR_NEEDMOREPARAMS` and never calls you.
- **Registration gate** — unless `before_reg()` returns `true`, the command is
  refused until the client has registered. Only handshake commands
  (`NICK`/`USER`/`CAP`/`PING`/`QUIT` and the like) set `before_reg`.
- **Module pre-hooks** — `on_pre_command` runs first and may `Deny` you.

Inside `handle`, `params` is the already-split argument list (the trailing
`:parameter` is a single element). Return `CmdResult::Ok` / `Fail`.

## A minimal command

```rust
use crate::command::{CmdResult, Command};
use crate::server::Server;
use crate::Uid;

pub struct Ping2;

impl Command for Ping2 {
    fn name(&self) -> &'static str { "PING2" }
    fn min_params(&self) -> usize { 1 }
    fn handle(&self, srv: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
        let nick = srv.users.get(&uid).map(|u| u.nick.clone()).unwrap_or_default();
        srv.send(uid, format!(":{} PONG {} :{}", srv.name, nick, params[0]));
        CmdResult::Ok
    }
}
```

## Replying to the client

Use the [`Server`](server.md#sending) helpers rather than building raw lines by
hand where you can:

- `srv.numeric(uid, code, rest)` — send a numeric reply (`005`, `461`, …).
- `srv.send(uid, line)` — send a fully-formed protocol line.
- `srv.fail(uid, command, code, desc)` / `warn(...)` / `note(...)` — IRCv3
  standard replies (`FAIL` / `WARN` / `NOTE`) for clients that support them.
- `srv.snotice(msg)` — a server notice to opers (for staff-facing feedback).

## Registering

A module exposes its commands from a `commands()` function returning boxed
handlers:

```rust
pub fn commands() -> Vec<Box<dyn Command>> {
    vec![Box::new(Ping2)]
}
```

Then chain it into `module_commands()` in `src/modules/mod.rs`:

```rust
pub fn module_commands() -> Vec<Box<dyn Command>> {
    filter::commands()
        // …existing chains…
        .chain(mymod::commands())
        .collect()
}
```

Command names are the registry key and must be unique and upper-case. The
`abbreviation` feature lets clients invoke a command by a unique prefix, so avoid
names that are prefixes of unrelated commands where it matters.

## Oper-only and gated commands

There is no separate "oper command" type — gate inside `handle`:

```rust
fn handle(&self, srv: &mut Server, uid: Uid, params: &[String]) -> CmdResult {
    if !srv.is_oper(uid) {
        srv.numeric(uid, 481, ":Permission Denied- You're not an IRC operator");
        return CmdResult::Fail;
    }
    // …privileged work…
    CmdResult::Ok
}
```

See [the `Server` API](server.md) for lookups, permissions, config, and off-core
work.
