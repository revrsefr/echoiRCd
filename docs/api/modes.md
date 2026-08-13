# Writing modes

Modes are stateless `&'static` handler objects. The `MODE` parser dispatches each
letter to its handler, so adding a mode is a new handler plus one line in a table —
you never touch the parser. See the [mode reference](../modes.md) for the existing
letters (don't collide).

## User modes — the `UserMode` trait

```rust
pub trait UserMode: Sync {
    fn letter(&self) -> char;
    /// Apply +/- to the user; return true if it took effect (so the change is echoed).
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool;
}
```

A user-mode handler is typically a zero-sized struct. Store the actual flag on the
user (existing flags live in `UserFlags`; module-specific state goes in
[`User.ext`](server.md#per-entity-state)).

```rust
struct BotMode;
impl UserMode for BotMode {
    fn letter(&self) -> char { 'B' }
    fn apply(&self, s: &mut Server, uid: Uid, adding: bool) -> bool {
        match s.users.get_mut(&uid) {
            Some(u) => { u.flags.bot = adding; true }
            None => false,
        }
    }
}
static BOT: BotMode = BotMode;
```

Register it in `src/mode.rs` by adding `&BOT` to the `USER_MODES` slice.

## Channel modes — the `ChanMode` trait

```rust
pub trait ChanMode: Sync {
    fn letter(&self) -> char;
    /// Whether this sign consumes an argument (taken only if one remains).
    fn wants_param(&self, adding: bool) -> bool;
    /// A list mode (like +b): a no-arg query is just viewing, so it needn't
    /// require operator rank. Default false.
    fn is_list(&self) -> bool { false }
    /// Apply +/- to channel `key` (display name `chan`) on behalf of `uid`.
    fn apply(&self, s: &mut Server, chan: &str, key: &str, uid: Uid,
             adding: bool, param: Option<&str>) -> Applied;
}

pub enum Applied {
    No,                    // nothing to echo (no-op, rejected, or a list query)
    Yes(Option<String>),  // echo the change; Some(param) appends a parameter
}
```

Key points:

- `key` is the channel's lookup key (lower-cased name); `chan` is the display name.
  Look the channel up with `s.channels.get_mut(key)`.
- `wants_param` controls whether the parser hands you a `param`. Return `true` for
  a mode that takes an argument (a key, a limit, a mask); parameterless flags
  return `false`.
- Return `Applied::Yes(None)` for a flag that flipped, `Applied::Yes(Some(p))` to
  echo a parameter (e.g. the limit you set), or `Applied::No` if nothing changed
  or you rejected it.
- **Enforce permissions yourself.** For an ordinary settable mode, check the
  caller's rank (`s.rank(uid, key) >= RANK_OP`) before applying and reply/refuse
  if they're not allowed.

```rust
struct NoCtcp;
impl ChanMode for NoCtcp {
    fn letter(&self) -> char { 'C' }
    fn wants_param(&self, _adding: bool) -> bool { false }
    fn apply(&self, s: &mut Server, _chan: &str, key: &str, uid: Uid,
             adding: bool, _param: Option<&str>) -> Applied {
        if s.rank(uid, key) < crate::channels::RANK_OP { return Applied::No; }
        match s.channels.get_mut(key) {
            Some(c) if c.modes.no_ctcp != adding => { c.modes.no_ctcp = adding; Applied::Yes(None) }
            _ => Applied::No,
        }
    }
}
static NO_CTCP: NoCtcp = NoCtcp;
```

Register it in `src/mode.rs` by adding `&NO_CTCP` to the `CHAN_MODES` slice, and
add its letter to the `CHANMODES=` group in the ISUPPORT string (`server.rs`) so
clients learn about it.

## List modes

Set `is_list() -> true` and `wants_param() -> true`. A no-argument use is a list
query (rank-free); an argument adds/removes an entry. The built-in list modes
(`+b`, `+e`, `+I`, …) share a common `ListMode` handler parameterised by kind —
follow that pattern for a new list.

## Named-mode access

Every channel mode is also reachable by long name through the `PROP` command
(`namedmodes`) without extra work on your part — the mapping is derived from the
registered handlers.
