# Building & running

## Prerequisites

- A stable **Rust** toolchain (`cargo`, `rustc`).
- **OpenSSL** development headers (the `openssl` crate links against the system
  library) — e.g. `libssl-dev` on Debian/Ubuntu.

That's it. There are exactly two dependencies: `openssl` and `mio`.

## Build

```sh
git clone https://git.devtronic.pro/fedserv/echoIRCd
cd echoIRCd

# development build (fast to compile, slow to run)
cargo build

# release build — ALWAYS use this in production; the debug build is unoptimized
# and far slower on the CPU-bound paths (TLS, hashing, cloaking, line parsing)
cargo build --release
```

The binaries land in `target/debug/echoircd` and `target/release/echoircd`.

## Run

echoircd takes one argument, the path to a config file (default `./echoircd.conf`):

```sh
cp echoircd.conf.example echoircd.conf     # then edit: oper pass, cloak_key, TLS paths
cargo run --release                        # reads ./echoircd.conf
# or run the binary directly:
./target/release/echoircd /path/to/echoircd.conf
```

Point a client at it: `/server 127.0.0.1 6667`, or `6697` for TLS once a
certificate is configured. See [configuration](configuration.md) for every
setting and [deployment](deployment.md) for running it as a supervised service.

> Your live `echoircd.conf` is gitignored on purpose — it holds secrets (oper
> password, cloak key, link password). Never commit it.

## Tests

```sh
cargo test                        # unit + integration tests
cargo test --test integration     # just the end-to-end suite
```

The integration suite spawns the real binary on ephemeral ports and drives it as
a client — covering reactor-pool cross-worker delivery, TLS-in-reactor handshakes,
the stalled-handshake reap, the accept-rate limiter, and nick collisions. It
tracks and kills its child processes by PID, never by name.

## The originality guard

Every source edit is checked by `scripts/native-rust-guard.sh`, which enforces the
project's invariants:

- no `unsafe` (the crate is `#![forbid(unsafe_code)]`),
- no C / FFI,
- dependencies limited to `openssl` + `mio`,
- and no code copied or translated from any other project — everything is
  original Rust.

Run it on a file directly with `bash scripts/native-rust-guard.sh <file>`.

## Project layout

```text
src/
  main.rs          startup: config, listeners, the reactor pool, the core thread
  ircd.rs          the core event loop and event types
  server.rs        the Server: all state, plus helpers (send, snotice, off-core work)
  socketengine.rs  the I/O edge: reactor pool, acceptor, TLS-in-reactor, links
  tls.rs           the TLS backend (OpenSSL) — blocking + non-blocking sessions
  channels.rs      Channel, membership, and the channel mode struct
  users.rs         User and session state
  mode.rs          ChanMode / UserMode traits and the mode registry
  command.rs       the Command trait
  module.rs        the module lifecycle-hook trait
  coremods/        built-in commands (registration, channels, messaging, oper, …)
  modules/         optional, pluggable modules (~70 of them)
tests/             end-to-end integration tests
deploy/            production systemd units + firewall script
docs/              this manual
```

## Extending

Three extension points, each one file plus one table entry:

- **Commands** (`src/command.rs`, `src/coremods/`) — a handler with `name`,
  `min_params`, `before_reg`, and `handle(&mut Server, uid, params)`.
- **Modes** (`src/mode.rs`) — channel/user modes as `ChanMode` / `UserMode`
  handler objects; adding one never touches the parser.
- **Modules** (`src/module.rs`, `src/modules/`) — lifecycle hooks; pre-hooks can
  **Deny** a register/command/message, notify-hooks fire after.
