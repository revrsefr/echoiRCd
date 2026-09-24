<div align="center">

# echoIRCd

An IRC server written in Rust, from scratch.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

[echoircd.org](https://echoircd.org) · [docs](https://echoircd.org/docs) · live network `irc.echoircd.org` (6697 TLS, 6667 plain)

</div>

## What it is

echoIRCd is a full IRC daemon. It handles the client protocol and the IRCv3
extensions on top of it, links to other servers, runs a services interface, and
bridges channels to Telegram, Matrix and XMPP without an external appservice. It
also does TLS and WebSocket, host cloaking, GeoIP, layered anti-abuse, optional
PostgreSQL and Redis backing, and a JSON-RPC control plane. It's the software that
runs the echoircd.org network.

The protocol target is the living IRC spec at
[modern.ircdocs.horse](https://modern.ircdocs.horse) (which consolidates the old
RFCs 1459 and 2812), plus the IRCv3 capabilities. There's no async runtime: one
thread owns all the state, and a pool of epoll reactors handles the sockets and TLS
around it. The reasoning is in [Architecture](#architecture).

## Building and running

```sh
git clone https://git.devtronic.pro/echo/echoIRCd
cd echoIRCd
cargo build --release
cp echoircd.conf.example echoircd.conf     # set servername, cloak_key, TLS paths
printf '%s' 'my-oper-pass' | ./target/release/echoircd mkpasswd   # bcrypt hash for the oper block
./target/release/echoircd                  # reads ./echoircd.conf
```

Then point a client at `127.0.0.1 6667`, or `6697` once you've set up a certificate.

## What's in it

- **IRC core.** Registration, channels (`JOIN`/`PART`/`KICK`/`INVITE`/`KNOCK`/
  `CYCLE`/`REMOVE`/`TOPIC`), messaging (`PRIVMSG`/`NOTICE`/`TAGMSG`, CTCP), and the
  info commands (`WHO`/`WHOIS`/`WHOWAS`/`LIST`/`STATS`/`MAP`/`LUSERS`/`MOTD`).
- **The full mode set.** Prefixes `qaohv` (plus a `!` staff prefix), list modes
  `beIgXw`, the keyed/limit/flood/redirect/history/anticaps parameters, the standard
  user modes, and matching and acting extbans.
- **IRCv3.** message-tags, server-time, labeled-response, batch, echo-message,
  account-tag, CHATHISTORY and event-playback, multiline, message-redaction,
  read-marker, relaymsg, web-push (VAPID, RFC 8291), SASL (PLAIN, EXTERNAL,
  SCRAM-SHA-256), standard-replies, and `WATCH`/`MONITOR`/`SILENCE`/caller-id.
- **Operators.** `OPER`/`KILL`/`WALLOPS`/`GLOBOPS`, the `SA*`/`CHG*`/`SET*`
  override commands, `CLEARMODE`, and x-lines (`K`/`G`/`Z`/`E`/`SHUN`/`QLINE`/
  `CBAN`/`RLINE`/`JUPE`) that persist to disk. Oper types and classes define which
  commands, named privileges (like `users/auspex` or `channels/override`) and
  usermode/chanmode letters each oper gets, all tunable. LDAP authentication for
  the `OPER` password is optional.
- **Services and accounts.** SASL relayed over the link, the `SVS*` / `ENCAP` /
  `METADATA` interface, account-gated modes, and optional server-side account
  registration (`REGISTER`/`VERIFY`).
- **Server linking.** `UID`/`FJOIN` netburst, users and channels shared across
  servers, multi-hop routing, TS-based nick-collision handling, and clean
  netsplit/rejoin.
- **Protocol bridges.** Bridge a channel to Telegram, Matrix or XMPP from inside
  the daemon. A remote sender can appear as a spoofed source (`relay` mode) or as a
  real virtual member that shows up in `WHO`/`NAMES` (`puppet` mode). Routes are
  added and reloaded live with the `BRIDGE` command.
- **Database and event bus.** A non-blocking PostgreSQL client on an off-core
  worker pool, with named connection pools. Reputation, x-lines, read-markers,
  permanent channels and web-push subscriptions can persist to tables, and a
  read-only `/SQL` console gives admins query access over IRC. A matching Redis
  subsystem publishes an event bus (connects, quits, joins/parts, nick changes,
  kicks, opers, x-lines) for outside tooling.
- **Anti-abuse.** TLS client-cert fingerprints, host cloaking, DNSBL (plus a
  code-filtered proxy/VPN list), a WebSocket handshake check that flags fake
  browsers, per-IP connection and message flood limits, a target-change throttle,
  per-address reputation scoring, mixed-script and drone detection, CAPTCHA /
  PONG-cookie / arithmetic gates, and DCC filtering.
- **Transports.** Plaintext, TLS (OpenSSL or rustls), a native WebSocket layer
  (`ws://` and `wss://`), and the PROXY protocol (v1/v2) behind a load balancer.
- **Live upgrades.** `SIGUSR2` re-execs a new binary and hands over every listener
  (plaintext, TLS, WebSocket and server links) across the exec, so rolling out a
  build doesn't drop the listening sockets.
- **GeoIP.** A MaxMind `.mmdb` reader, with a `G:<cc>` geoban, a `GEOIP` command,
  and a country line in WHOIS.
- **Localization.** `locale fr` (or `es`, `ru`, `de`, `it`, `pt-BR`) makes the
  server render its numerics, notices and messages from `lang/<code>.conf`, while
  protocol tokens, IDs and the wire format stay canonical. English is the default
  and costs nothing; a language switches live on `REHASH`. Add one by dropping in a
  translated catalog, no rebuild.
- **Control and metrics.** A token-authenticated JSON-RPC plane over HTTP, an
  optional OpenMetrics/Prometheus endpoint, and the same counters as JSON over IRC
  (the `METRICS` command).

## Configuration

Configuration is a single file (default `./echoircd.conf`). It accepts a
brace/block form or the older flat `key = value` form, and auto-detects which one a
file uses:

```text
server { name "irc.example.net"; network "ExampleNet"; }
listen { ip "*"; port 6697; tls yes; }
oper   { name "admin"; password "$2b$…"; type netadmin; }
```

See [`echoircd.conf.example`](echoircd.conf.example) for the full annotated set.
Every operational limit is a key with a default, and most settings apply on
`REHASH` without a restart. The file is checked on load: an unknown block, an
unknown or misspelled field, a missing required field, or a duplicated single-use
block is a fatal error with a line number, rather than being silently ignored.

Three helper subcommands:

- `echoircd mkpasswd` — read a password from stdin, print a bcrypt hash.
- `echoircd checkconfig [file]` — validate a config against the schema and dump its
  resolved keys.
- `echoircd rehash` — tell a running server to reload its config in place.

Your live `echoircd.conf` is gitignored, because it holds secrets (oper password,
cloak key, link password). Don't commit it.

## Architecture

One core thread owns every `User` and `Channel`, so command and module code is
ordinary single-threaded logic over `&mut Server`, with no `Arc<Mutex<…>>`. The I/O
edge feeds it events over a bounded channel, so under load producers apply
backpressure instead of growing an unbounded queue.

- A pool of `mio` epoll reactors drives the client sockets. An acceptor
  round-robins each connection onto a worker (one per core by default), and each
  worker frames lines and runs the TLS handshake and record crypto in-thread,
  non-blocking. Socket work and crypto spread across cores while the state core
  stays single-threaded. (Proxied TLS and server links keep a thread each; there
  are few of them.)
- Slow or blocking work runs off the core: KDF hashing, DNS, disk snapshots,
  database queries, the outbound HTTP for bridges and verification gates, and the
  XMPP stream. A flood or a slow endpoint can't freeze the core. Each event and
  each connection's I/O is panic-isolated so one bad client can't take the server
  down, a watchdog flags a stuck core, stalled connections are reaped on a timer,
  and `SIGUSR2` rolls out a rebuild without dropping the listeners.

Why a raw reactor instead of async: IRC is one large shared mutable graph, and
almost every command mutates it and then broadcasts. With one thread owning all of
it, handlers are plain synchronous code, with no locks, no `.await`, and no
`Send + 'static` bounds. A multi-threaded async runtime would push that shared
state behind mutexes or an actor mailbox, and the broadcast is serialized anyway,
so you'd pay for parallelism the workload can't use. `mio` is the same readiness
layer async runtimes are built on, so you keep the scaling without the runtime. The
part that does parallelize (the socket syscalls and TLS crypto) runs in the reactor
pool. Scaling past one machine is done by linking servers.

State is handle-based rather than pointer-based: `Uid` handles instead of raw
pointers, an `Extensible` typemap for module data (dropped with the connection),
and compiled-in trait objects instead of a plugin ABI. Full notes are in
[`docs/architecture.md`](docs/architecture.md).

## Writing modules

Three extension points, each one file plus one line in a table. Reference and a
tutorial in [`docs/api/`](docs/api/):

- **Commands** (`src/command.rs`, `src/coremods/`): a handler with `name`,
  `min_params`, `before_reg`, and `handle(&mut Server, uid, params)`.
- **Modes** (`src/mode.rs`): channel and user modes as `ChanMode` / `UserMode`
  objects. Adding one never touches the parser.
- **Modules** (`src/module.rs`, `src/modules/`): lifecycle hooks. A pre-hook can
  deny a register, command or message; notify-hooks fire after.

## Documentation

The manual is in [`docs/`](docs/): [building](docs/building.md),
[configuration](docs/configuration.md), [architecture](docs/architecture.md),
[modes](docs/modes.md), [operators](docs/operators.md),
[linking and services](docs/linking.md), [IRCv3](docs/ircv3.md),
[anti-abuse](docs/anti-abuse.md), [deployment](docs/deployment.md), and the
[module API](docs/api/).

## The network

echoIRCd's own support network runs on echoIRCd:

- Server: `irc.devtronic.pro` (TLS `6697`, plain `6667`)
- `#echoiRCd` — support and development
- `#devs` — general developer chat

Quick connect: `ircs://irc.devtronic.pro:6697/%23echoiRCd`

## Links

- Repository: <https://git.devtronic.pro/echo/echoIRCd>
- Issues: <https://git.devtronic.pro/echo/echoIRCd/issues>
- Config reference: [`echoircd.conf.example`](echoircd.conf.example)

## License

MIT. See [`Cargo.toml`](Cargo.toml).
