# Module developer API

This is the reference for extending echoIRCd. The server has five extension
points, all ordinary Rust trait objects compiled into the binary — there is no
plugin ABI and no dynamic loading:

| You want to… | Implement | Registered in | Reference |
|--------------|-----------|---------------|-----------|
| Add a command | [`Command`](commands.md) | `modules/mod.rs::module_commands()` | [commands](commands.md) |
| Add a channel/user mode | [`ChanMode`](modes.md) / [`UserMode`](modes.md) | `mode.rs::CHAN_MODES` / `USER_MODES` | [modes](modes.md) |
| Hook lifecycle events | [`Module`](modules.md) | `modules/mod.rs::default_modules()` | [modules](modules.md) |
| Store per-user / per-server state | [`Extensible`](server.md#per-entity-state) typemap | — | [server](server.md) |
| Call into the server | the [`Server`](server.md) API | — | [server](server.md) |

## The mental model — read this first

**Everything runs on one thread.** A single core thread owns every `User` and
`Channel`. Your command handlers, mode handlers, and module hooks are all called
on that thread with `&mut Server`. That means:

- **Your code is plain synchronous Rust.** No `async`, no `.await`, no `Send +
  'static` futures, no `Arc<Mutex<…>>`. You read and mutate `Server` directly.
- **You must never block.** A slow operation (a KDF hash, a network call, a big
  disk write) would freeze the whole server. Offload it — see
  [off-core work](server.md#off-core-work) — and handle the result as an event.
- **State is safe by construction.** Users and channels are referenced by `Uid` /
  channel-key handles, not pointers, so there are no dangling references.

## Project conventions

Modules in this codebase follow a few hard rules — match them:

1. **One module per file** in `src/modules/`. A module is self-contained; it does
   not add fields to `Server` or `Config`.
2. **State goes in the `Extensible` typemap**, not in new struct fields — attach
   per-user data to `User.ext`, per-server (and per-channel, keyed by name) data
   to `Server.ext`. It is dropped automatically with its owner. See
   [per-entity state](server.md#per-entity-state).
3. **Read settings through the config accessors** (`conf`, `conf_all`, `conf_num`,
   `conf_bool`) — never hardcode a tunable value; expose it as a config key with a
   literal default.
4. **Register in the table**, don't touch the parser or the dispatcher. Adding a
   command / mode / module is one new file plus one line in a registration table.
5. **Stay self-contained.** A module shouldn't pull in a heavy new dependency —
   the primitives you'll reach for (an HTTP client, a regex engine, base64, the
   hashing/KDF helpers) already live in the tree; reuse them.

## Write your first module in five steps

A module that logs connects and quits — the canonical template
(`src/modules/snoop.rs`):

**1. Create the file** `src/modules/hello.rs`:

```rust
//! hello — a tiny example module.
use crate::module::Module;
use crate::server::Server;
use crate::Uid;

pub struct Hello;

impl Module for Hello {
    fn name(&self) -> &'static str {
        "hello"
    }
    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {
        if let Some(u) = srv.users.get(&uid) {
            srv.snotice(&format!("hello: {} connected", u.nick));
        }
    }
}
```

**2. Declare the file** in `src/modules/mod.rs`:

```rust
pub mod hello;
```

**3. Register the module** in the same file's `default_modules()`:

```rust
pub fn default_modules() -> Vec<Box<dyn Module>> {
    vec![
        // …existing modules…
        Box::new(hello::Hello),
    ]
}
```

**4. (Only if it adds a command)** expose a `commands()` function from your module
and chain it into `module_commands()` — see [commands](commands.md).

**5. Build and test:**

```sh
cargo build && cargo test
```

That's it — `hello` is now a first-class part of the server.

## Where to go next

- [The `Module` trait](modules.md) — every lifecycle hook and how to block actions.
- [Commands](commands.md) — add a command and reply to clients.
- [Modes](modes.md) — add a channel or user mode.
- [The `Server` API](server.md) — sending, lookups, permissions, config, state,
  and off-core work.
