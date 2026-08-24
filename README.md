<div align="center">

# echoIRCd

**A memory-safe IRCv3 server written in Rust.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](Cargo.toml)
[![Language: Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![IRCv3](https://img.shields.io/badge/IRCv3-supported-blueviolet.svg)](https://ircv3.net)

</div>

## About

echoIRCd is a full IRC + IRCv3 server. A single lock-free **core thread** owns all
state; a **pool of epoll reactor threads** (one per core) drives the connections
around it — TLS crypto and all — with no async runtime. It ships **100+ commands**,
the **complete channel & user mode set**, **30+ IRCv3 capabilities**,
server-to-server linking, a services interface, TLS, WebSocket, GeoIP, layered
anti-spam, a Prometheus metrics endpoint, and a JSON-RPC control plane — with every
operational limit exposed as a config key.

## Features

- **Full IRC core** — registration, channels (`JOIN`/`PART`/`KICK`/`INVITE`/
  `KNOCK`/`CYCLE`/`REMOVE`/`TOPIC`), messaging (`PRIVMSG`/`NOTICE`/`TAGMSG`, CTCP),
  and info (`WHO`/`WHOIS`/`WHOWAS`/`LIST`/`STATS`/`MAP`/`LUSERS`/`MOTD`).
- **Complete mode set** — prefixes `qaohv` (plus a network-staff `!` prefix), list
  modes `beIgXw`, keyed/limit/flood/redirect/history/anticaps params, the full flag
  set, all the standard user modes, and matching + acting **extbans**.
- **IRCv3** — message-tags (+msgid), server-time, labeled-response, batch,
  echo-message, account-tag, **CHATHISTORY**, **multiline**, **message-redaction**,
  **read-marker**, **relaymsg**, SASL, standard-replies, and `WATCH`/`MONITOR`/
  `SILENCE`/caller-id.
- **Operators** — `OPER`/`KILL`/`WALLOPS`/`GLOBOPS`, the `SA*`/`CHG*`/`SET*`
  override toolbox, x-lines (`K`/`G`/`Z`/`E`/`SHUN`/`QLINE`/`CBAN`/`RLINE`)
  persisted to disk, staff prefix (`operprefix`/`OJOIN`), oper levels, rank-gated
  `hidelist`/`hidemode`, and a reload-safe `REHASH`.
- **Services & accounts** — SASL PLAIN/EXTERNAL relayed over the link, the `SVS*` /
  `ENCAP` / `METADATA` interface, account-gated modes, and optional ircd-side
  account registration (`REGISTER`/`VERIFY`).
- **Server-to-server linking** — `UID`/`FJOIN` netburst, cross-server users and
  channels, multi-hop routing, TS-based nick-collision handling, and clean
  netsplit/rejoin.
- **Security & anti-spam** — TLS with client-cert fingerprints, keyed host
  cloaking, DNSBL, per-IP connection/message flood limits, mixed-script & random
  (drone) detection, CAPTCHA / PONG-cookie / arithmetic gates, and DCC filtering.
- **Transports** — plaintext, TLS (OpenSSL or rustls backend), a native WebSocket
  layer (`ws://` / `wss://`), and the PROXY protocol (v1/v2) behind a load balancer.
- **GeoIP** — a MaxMind `.mmdb` reader with a `G:<cc>` geoban, `GEOIP` command, and
  a WHOIS country line.
- **Control & observability** — a token-authenticated JSON-RPC plane over HTTP, and
  an optional OpenMetrics/Prometheus endpoint.

## Quick start

```sh
git clone https://git.devtronic.pro/fedserv/echoIRCd
cd echoIRCd
cargo build --release
cp echoircd.conf.example echoircd.conf     # edit: servername, cloak_key, TLS paths
printf '%s' 'my-oper-pass' | ./target/release/echoircd mkpasswd   # → bcrypt hash for the oper block
./target/release/echoircd                  # start (reads ./echoircd.conf)
```

Then point a client at it: `/server 127.0.0.1 6667` (or `6697` for TLS once a
certificate is configured).

## Documentation

The full manual lives in [`docs/`](docs/):

- [Building & running](docs/building.md) · [Configuration](docs/configuration.md) · [Architecture](docs/architecture.md)
- [Channel & user modes](docs/modes.md) · [Operators](docs/operators.md) · [Server linking & services](docs/linking.md)
- [IRCv3](docs/ircv3.md) · [Anti-abuse & flood protection](docs/anti-abuse.md) · [Deployment](docs/deployment.md)
- [Module developer API](docs/api/) — write your own commands, modes, and modules.

## Configuration

Configuration is a single file (default `./echoircd.conf`) in a **brace/block
format** — or the original flat `key = value` form; both are accepted and the
parser auto-detects which one a file uses:

```text
server { name "irc.example.net"; network "ExampleNet"; }
listen { ip "*"; port 6697; tls yes; }
oper   { name "admin"; password "$2b$…"; type netadmin; }
```

See [`echoircd.conf.example`](echoircd.conf.example) for the full, annotated set of
keys — every operational limit is a config key with a built-in default, and most
settings apply on `REHASH` without a restart. Three helper subcommands round it out:

- `echoircd mkpasswd` — read a password from stdin, print a bcrypt hash for an `oper` block.
- `echoircd checkconfig [file]` — parse a config and dump its keys, to validate one or diff two.
- `echoircd rehash` — signal the running server to reload its config in place.

Your live `echoircd.conf` is gitignored — it holds secrets (oper password, cloak
key, link password), so never commit it. Generate a TLS certificate into `tls/`
with the one-liner in the example config.

## Architecture

A single **core thread** owns every `User` and `Channel`, so command and module
code is ordinary single-threaded logic over `&mut Server` — no `Arc<Mutex<…>>`
anywhere. The I/O edge feeds it events over channels:

- **A pool of `mio` epoll reactors** drives client sockets — an acceptor
  round-robins each connection onto a worker (one per core by default), and each
  worker frames lines and runs **TLS handshakes and record crypto non-blocking**
  in-thread. Socket work and crypto spread across cores while the state core stays
  single-threaded and lock-free. (Proxied TLS and server links keep a thread each;
  there are few of them.)
- **Resilience is built in.** Slow work (KDF hashing, DNS, disk snapshots) runs off
  the core so a flood can't freeze it; each event and each connection's I/O is
  panic-isolated so one bad client can't crash the server; a watchdog flags a stuck
  core; and half-open/stalled connections are reaped on a timer.

**Why a raw reactor and not async?** IRC is one large shared mutable graph, and
almost every command mutates it and then broadcasts. With one thread owning all of
it, handlers are plain synchronous code — no locks, no `.await`, no `Send + 'static`
bounds. A multi-threaded async runtime would force that shared state behind mutexes
or an actor mailbox, and a channel broadcast is serialized anyway, so you'd pay for
parallelism the workload can't use. `mio` is the same readiness layer async runtimes
build on, so you keep the scaling without the runtime. What *does* parallelize — the
socket syscalls and TLS crypto — runs in the reactor pool; scaling past one machine
is done by linking servers, not threading one harder.

Memory safety is structural: `Uid` handles instead of raw pointers, an `Extensible`
typemap instead of `void*` module data (freed on drop), and compiled-in trait
objects instead of a fragile plugin ABI. **Full design notes:**
[`docs/architecture.md`](docs/architecture.md).

## Extending

Three small extension points, each one file + one table line — full reference and a
tutorial in [`docs/api/`](docs/api/):

- **Commands** (`src/command.rs`, `src/coremods/`) — a handler with `name`,
  `min_params`, `before_reg`, `handle(&mut Server, uid, params)`.
- **Modes** (`src/mode.rs`) — channel/user modes as `ChanMode` / `UserMode` handler
  objects; adding one never touches the parser.
- **Modules** (`src/module.rs`, `src/modules/`) — lifecycle hooks; pre-hooks can
  **Deny** a register/command/message, notify-hooks fire after.

## Links

- **Repository** — <https://git.devtronic.pro/fedserv/echoIRCd>
- **Issues** — <https://git.devtronic.pro/fedserv/echoIRCd/issues>
- **Documentation** — [`docs/`](docs/)
- **Config reference** — [`echoircd.conf.example`](echoircd.conf.example)

## License

echoIRCd is released under the [MIT License](Cargo.toml).
