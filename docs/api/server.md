# The `Server` API

`Server` is the whole server state, passed as `&mut Server` to every command,
mode, and module hook. This is the surface you call from a module. Signatures are
abbreviated; see `src/server.rs` for the exact ones.

## The data model

- **`Uid`** — an opaque handle for a user (not a pointer). Look users up with it;
  it can't dangle.
- **`srv.users: HashMap<Uid, User>`** — every local and remote user. A `User` has
  `nick`, `ident`, `host`, `realname`, `account`, `flags`, `ext`, and more.
- **`srv.channels: HashMap<String, Channel>`** — keyed by the **lower-cased** name.
  A `Channel` has its members, `modes` (a `ChanModes` struct), topic, and ban
  lists.
- **`srv.name`, `srv.network`** — this server's name and the network name.
- **`srv.conf_path`** — the path to the loaded config file (useful for sibling
  data files).

```rust
let nick = srv.users.get(&uid).map(|u| u.nick.clone());
let count = srv.channels.get(&key).map(|c| c.members.len());
```

## Per-entity state

Attach your own typed state through the `Extensible` typemap instead of adding
struct fields. It is keyed by Rust type and dropped automatically with its owner.

- **`srv.ext`** — per-server state. For **per-channel** state, key your value by
  channel name inside a map stored here (channels themselves have no `ext`).
- **`srv.users[&uid].ext`** — per-user state.

```rust
#[derive(Default)]
struct Counter(u32);

let c = srv.ext.get_or_insert_with::<Counter>(Counter::default);
c.0 += 1;

if let Some(u) = srv.users.get_mut(&uid) {
    u.ext.set(MyUserState { /* … */ });
}
```

`Extensible` methods: `get::<T>()`, `get_mut::<T>()`, `set::<T>(v)`,
`get_or_insert_with::<T>(f)`, `take::<T>()`.

## Configuration

Never hardcode a tunable — read it, with a literal default:

| Method | Returns |
|--------|---------|
| `srv.conf(key)` | `Option<&str>` — the single value, if set |
| `srv.conf_all(key)` | all values for a repeatable key |
| `srv.conf_bool(key, default)` | a `yes`/`on`/`true` flag |
| `srv.conf_num(key, default)` | any `FromStr` number |

```rust
let threshold = srv.conf_num("mymod_threshold", 8u32);
let enabled = srv.conf_bool("mymod", false);
for line in srv.conf_all("mymod_rule") { /* … */ }
```

## Sending

| Method | Sends |
|--------|-------|
| `srv.send(uid, line)` | a fully-formed protocol line to one user |
| `srv.numeric(uid, code, rest)` | a numeric reply (`005`, `461`, …) |
| `srv.fail(uid, cmd, code, desc)` / `warn(...)` / `note(...)` | IRCv3 standard replies |
| `srv.to_channel(key, line, except)` | a line to every member (optionally excluding one) |
| `srv.snotice(msg)` | a server notice to subscribed opers |
| `srv.announce(msg)` | a global notice to all users |
| `srv.notify_peers(uid, line, want)` | send to a user's common-channel peers whose caps match |

```rust
srv.numeric(uid, 481, ":Permission Denied- You're not an IRC operator");
srv.to_channel(&key, format!(":{} NOTICE {} :hi", srv.name, chan), Some(uid));
```

## Lookups & permissions

| Method | Result |
|--------|--------|
| `srv.is_oper(uid)` | is the user an IRC operator? |
| `srv.rank(uid, key)` | the user's channel rank (compare to `RANK_*`) |
| `srv.is_member(uid, key)` | is the user in the channel? |
| `srv.extban_active(uid, key, kind)` | does an acting extban of `kind` apply to them here? |

Rank constants (from `crate::channels`): `RANK_OWNER`, `RANK_ADMIN`, `RANK_OP`,
`RANK_HALFOP`, `RANK_VOICE`.

```rust
if srv.rank(uid, &key) >= crate::channels::RANK_OP { /* ops-only */ }
```

## Mutating users

| Method | Effect |
|--------|--------|
| `srv.change_host_ident(uid, new_ident, new_host)` | change a user's displayed ident/host (drives `chghost`) |
| `srv.oper_up(uid)` | mark a user as an operator |
| `srv.remove_user(uid, reason)` | disconnect a user cleanly |

## Off-core work

The core thread must never block. Offload slow work:

- **`srv.disk_write(path, contents)`** — fire-and-forget, coalescing, atomic
  (temp + rename) file write. Use this for saving state; a slow disk can't stall
  the core. **No result to handle** — the simplest offload.
- **`srv.spawn_crypto(closure)`** — run a bounded, CPU-heavy job (a KDF hash) on a
  worker thread. Returns `false` if at capacity.
- **`srv.spawn_http(...)`** — an outbound HTTP request on a worker thread.

`spawn_crypto` / `spawn_http` deliver their result back as a core `Event`, so
wiring a *new* async result type touches the core event enum in `src/ircd.rs`;
`disk_write` needs nothing extra. Prefer `disk_write` for persistence and
`on_tick` for periodic jobs.

```rust
// good: persist off-core from a hook
srv.disk_write(format!("{}.mystore", srv.conf_path), store.serialize());
```

## Time

`crate::server::now()` → unix seconds. `iso_time(secs)` / `parse_iso(s)` convert to
and from ISO-8601 (used for `server-time` tags and timestamps).

## Rules of the road

- Do the work synchronously and quickly; **never block** — offload instead.
- Reference users/channels by `Uid` / key; don't cache references across events.
- Keep state in `ext`, read settings via `conf*`, and register in the tables. See
  the [conventions](README.md#project-conventions).
