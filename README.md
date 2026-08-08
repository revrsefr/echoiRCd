# echoIRCd

A from-scratch IRC daemon written in **native Rust**. The architecture is
*inspired by* InspIRCd's shape — commands as objects, modes as handler objects,
modules with lifecycle hooks — but every line is original Rust, not a port or a
translation. Design goals: `#![forbid(unsafe_code)]`, dependency-light (just two
small crates — `openssl` for TLS and `mio` for the epoll socket engine), and
lock-free (a single core thread owns all state).

> Status: early but capable. It boots, registers clients, speaks a large chunk of
> the IRC + IRCv3 protocol (see **What works**), and one reactor thread has served
> 5,000 concurrent connections in testing. Not battle-tested yet.

## Run it

```sh
cp echoircd.conf.example echoircd.conf   # then edit: oper pass, cloak_key, TLS paths
cargo run --release                      # reads ./echoircd.conf
# point a client at it, e.g.  /server 127.0.0.1 6667
```

Config is plain `key = value` (see `echoircd.conf.example`). Your real
`echoircd.conf` is gitignored because it holds secrets (oper password, cloak
key, link password) — never commit it. For TLS, generate a cert/key into `tls/`
(the example config has the one-liner).

## Architecture

A single **core thread** owns every `User` and `Channel`, so command and module
code is plain single-threaded logic over `&mut Server` — no `Arc<Mutex<…>>`
anywhere. The I/O edge feeds it events over mpsc channels:

- **Client connections run on one `mio` epoll reactor thread.** The daemon drives
  tens of thousands of sockets without a thread per connection — measured at 5,000
  concurrent clients on **4 threads total**, and it scales toward ~50k (use a
  release build and a high `LimitNOFILE`). This is the readiness layer Tokio is
  built on, but without pulling in an async runtime, so the single-threaded core
  is untouched.
- **TLS and server links** keep a thread per connection — there are few of them,
  and a TLS session can't be split across reader/writer threads.

Both models hand the core the same `OutSink`, so it never knows or cares which one
a connection uses.

Where this improves on the C++ original it's inspired by: `Uid` handles instead
of raw `User*` (no use-after-free, no cull list), an `Extensible` typemap instead
of `void*` module data (freed automatically on drop), `&str` slices instead of
`char*`, and compiled-in trait objects instead of a fragile `.so` ABI.

### The two extension points

- **Commands** (`src/command.rs`, `src/coremods/`) — a handler declares `name`,
  `min_params`, `before_reg` and `handle(&mut Server, uid, params)`, registered
  in `command_table()`. Adding a command is one struct + one table line.
- **Modes** (`src/mode.rs`) — channel/user modes are handler objects
  (`ChanMode` / `UserMode`) in a table; adding a mode never touches the parser.
- **Modules** (`src/module.rs`, `src/modules/`) — lifecycle hooks. *Pre-hooks*
  (`on_user_register`, `on_pre_command`, `on_pre_message`) return a `ModResult`
  and can **Deny**; *notify-hooks* fire from a queue after the command.

## What works

- Registration (`CAP`/`NICK`/`USER`), `PING`/`PONG` with idle + registration
  timeouts, welcome burst (001–005) + ISUPPORT.
- `JOIN`/`PART`/`NAMES`/`TOPIC`/`KICK`/`INVITE`, `PRIVMSG`/`NOTICE`/`TAGMSG`,
  `NICK`, `WHO`/`WHOIS`/`WHOWAS`, `LIST`, `AWAY`, `QUIT`, `MOTD`/`LUSERS`.
- **Full mode set** as handler objects: prefixes `+qaohv`, lists `+beI`, and
  `+klmntispzONCTcSRMGu` plus flood/rate modes `+f/+j/+F`, redirect `+L`, word
  filter `+g`, and acting **extbans** `m:`/`c:`/`n:`.
- **IRC operators**: `OPER`/`KILL`/`WALLOPS`/`GLOBOPS`, `SAJOIN`/`SAPART`/`SANICK`/
  `SAMODE`/`SATOPIC`/`SAKICK`, `CHGHOST`/`CHGIDENT`/`SETHOST`/`SETIDENT`,
  `KLINE`/`GLINE`/`ZLINE` + `STATS`, snomasks (`+s`), `DIE`/`RESTART`, and a
  reload-safe **`REHASH`** (keeps the running config if the file can't be read,
  and announces the reload to every connected user).
- **IRCv3**: `CAP` negotiation, `server-time`, `message-tags` + **`msgid`**,
  `multi-prefix`, `away-notify`, `account-notify`, `extended-join`, `chghost`,
  `userhost-in-names`, `echo-message`, `invite-notify`, `setname`,
  `extended-monitor`, `SASL` (PLAIN, relayed to services), `WATCH`/`MONITOR`,
  `SILENCE`, and `ACCEPT` + user `+g` **callerid** (only accepted users may PM you).
- **Reverse-DNS on connect**: the classic `*** Looking up your hostname...`
  connection notices, backed by a *real* forward-confirmed PTR resolver written
  from scratch over UDP (no DNS crate) — resolves clients to hostnames, off the
  core thread, fail-safe to the IP. Configurable (`resolve_hosts`,
  `use_resolved_host`).
- **TLS** (openssl) with `sslinfo`; keyed-SHA-256 host **cloaking** (`+x`);
  **services-ready accounts** (`SVSLOGIN`/`SVSLOGOUT`, account-gated `+r/+R/+M`)
  — the ircd is *ready* for an external services package, it is not one itself.
- **Server-to-server linking**: handshake, UID/FJOIN netburst, cross-server
  users and channels, nick-collision handling, netsplit.
- An **antimixedutf8** anti-spam module (blocks mixed-script look-alike spam).

## Provenance

echoIRCd is original Rust. InspIRCd is a reference for *behaviour and API shape*
only — no code is copied or translated. `scripts/native-rust-guard.sh` enforces
this (no `unsafe`, no C/FFI, dependencies limited to `openssl` + `mio`, and no
copy/translation wording in comments); it runs on every edit.

## License

See the repository for licensing.
