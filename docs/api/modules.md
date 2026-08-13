# The `Module` trait

A module hooks lifecycle events. Implement `crate::module::Module` on a struct and
register it in `default_modules()`. Every method has a default, so implement only
the hooks you need.

```rust
pub trait Module: Send {
    fn name(&self) -> &'static str;

    // pre-hooks — fired inline, can Deny the action
    fn on_user_register(&mut self, srv: &mut Server, uid: Uid) -> ModResult { ModResult::Passthru }
    fn on_pre_command(&mut self, srv: &mut Server, uid: Uid, cmd: &str, params: &[String]) -> ModResult { ModResult::Passthru }
    fn on_pre_message(&mut self, srv: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult { ModResult::Passthru }

    // notify-hooks — informational, fired after the fact
    fn on_user_connect(&mut self, srv: &mut Server, uid: Uid) {}
    fn on_post_command(&mut self, srv: &mut Server, uid: Uid, cmd: &str) {}
    fn on_join(&mut self, srv: &mut Server, uid: Uid, chan: &str) {}
    fn on_part(&mut self, srv: &mut Server, uid: Uid, chan: &str, reason: &str) {}
    fn on_user_quit(&mut self, srv: &mut Server, uid: Uid, reason: &str) {}
    fn on_tick(&mut self, srv: &mut Server) {}
}
```

Note the receiver is `&mut self`: unlike commands and modes (which are stateless
`&self` handlers), a module instance can hold its own fields. In practice, prefer
the [`Extensible` typemap](server.md#per-entity-state) for per-user / per-channel
state so it lives and dies with its owner; use `self` fields only for
module-global state.

## Pre-hooks (can deny)

Pre-hooks run **inline, before** the action they gate, and return a `ModResult`:

```rust
pub enum ModResult {
    Passthru,  // no opinion — let other modules and the core decide
    Allow,     // force-allow: skip the remaining checks
    Deny,      // block the action
}
```

| Hook | Fires | `Deny` effect |
|------|-------|---------------|
| `on_user_register` | last gate before a client finishes registration | refuses the connection |
| `on_pre_command` | before any command runs | swallows the command silently |
| `on_pre_message` | before a `PRIVMSG` / `NOTICE` is delivered | drops the message |

Return `Deny` to block, `Allow` to force it through (bypassing other checks), or
`Passthru` to abstain. When you `Deny`, send the user an explanation yourself
(e.g. `srv.numeric(...)` or `srv.fail(...)`), since the core just stops.

```rust
fn on_pre_message(&mut self, srv: &mut Server, uid: Uid, target: &str, text: &str) -> ModResult {
    if text.contains("badword") && !srv.is_oper(uid) {
        srv.numeric(uid, 404, &format!("{target} :Message blocked"));
        return ModResult::Deny;
    }
    ModResult::Passthru
}
```

## Notify-hooks (informational)

Notify-hooks run **after** the event, drained from a queue once the triggering
command finishes. They can't block, but they get `&mut Server`, so they can act —
send lines, force a join, update state.

| Hook | Fires when |
|------|-----------|
| `on_user_connect` | a client has fully registered |
| `on_post_command` | after a command completes |
| `on_join` | a user joined a channel |
| `on_part` | a user left a channel |
| `on_user_quit` | a user is disconnecting (still exists during the call) |
| `on_tick` | the background timer, every `TICK_SECS` |

Because notify-hooks fire from a queue, a hook can itself cause more events (e.g.
force a join) without re-entering the module list — no surprises.

## Timed work

Use `on_tick` for periodic jobs (expiring entries, saving state, scoring). It runs
on the core thread, so keep it cheap; for a big write, hand it to
[`disk_write`](server.md#off-core-work) rather than blocking.

```rust
fn on_tick(&mut self, srv: &mut Server) {
    let store = srv.ext.get_or_insert_with::<MyStore>(MyStore::default);
    store.expire(crate::server::now());
    // persist off-core so a slow disk can't stall the core:
    srv.disk_write(format!("{}.mystore", srv.conf_path), store.serialize());
}
```

## Registering

Add your module to `src/modules/mod.rs`:

```rust
pub mod mymod;                       // declare the file
// …in default_modules():
Box::new(mymod::MyMod),              // add to the vec
```

Order in the vec is the order pre-hooks are consulted; the first `Deny` (or
`Allow`) wins.

See [commands](commands.md) if your module also adds commands, and
[the `Server` API](server.md) for everything you can call from a hook.
