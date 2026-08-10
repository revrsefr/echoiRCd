# echoIRCd

A from-scratch IRC daemon written in Rust. Commands are objects, modes are
handler objects, and modules hook lifecycle events. Design goals:
`#![forbid(unsafe_code)]`, dependency-light (just two small crates — `openssl`
for TLS and `mio` for the epoll socket engine), and lock-free (a single core
thread owns all state).

> Status: capable and broad. It speaks a large slice of the IRC + IRCv3 protocol
> — **100+ commands**, the full channel/user mode set, **28 IRCv3 capabilities**,
> and **~55 pluggable modules** — with server-to-server linking, a services
> interface, TLS, WebSocket, GeoIP and a JSON-RPC control plane. One reactor thread
> has served 5,000 concurrent connections in testing. Not battle-tested yet.

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
  release build and a high `LimitNOFILE`). It's a bare epoll/kqueue readiness
  reactor — no async runtime is pulled in, so the single-threaded core is
  untouched.
- **TLS and server links** keep a thread per connection — there are few of them,
  and a TLS session can't be split across reader/writer threads.

Both models hand the core the same `OutSink`, so it never knows or cares which one
a connection uses.

Memory-safety by design: `Uid` handles instead of raw pointers (no use-after-free,
no cull list), an `Extensible` typemap instead of `void*` module data (freed
automatically on drop), `&str` slices, and compiled-in trait objects instead of a
fragile `.so` ABI.

### Why a raw reactor, not async?

IRC is one big shared mutable graph (users, channels, the nick index), and almost
every command mutates it and then broadcasts. With one thread owning all of it,
handlers are plain `&mut Server` code — no locks, no `.await`, no `Send + 'static`
bounds. A multi-threaded async runtime would force that shared state behind
mutexes or an actor mailbox, and a channel broadcast is serialized anyway, so
you'd pay locking cost for parallelism the workload can't use. `mio` is the same
readiness layer async runtimes are built on, so you keep the C50k scaling without
the runtime. CPU-heavy or blocking work (DNS, TLS, outbound HTTP) is pushed to its
own threads; the network scales out by **linking servers**, not by adding cores to
one process.

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

### Registration & session
- `CAP` negotiation, `NICK`/`USER`, `PING`/`PONG` with configurable idle +
  registration timeouts, welcome burst (001–005) + ISUPPORT (optionally batched).
- `WEBIRC` (real client IP from a trusted web gateway), `conn_waitpong` (require a
  PONG cookie before registering — filters bots), `autodrop` (silently drop
  pre-registration HTTP scanners), configurable nick/channel length limits.

### Channels
- `JOIN`/`PART`/`NAMES`/`TOPIC`/`KICK`/`INVITE`, plus `KNOCK`, `CYCLE`, `REMOVE`,
  `UNINVITE`.
- Bans / excepts / invex, ban **redirect** (`+b mask$#chan`), and matching +
  acting **extbans** (below).

### Messaging
- `PRIVMSG`/`NOTICE`/`TAGMSG`, CTCP handling, `echo-message`, per-message `msgid`,
  `server-time`, `account-tag`.
- **CHATHISTORY** (`draft/chathistory`: `LATEST`/`BEFORE`/`AFTER`/`AROUND`/`BETWEEN`
  /`TARGETS`) with the `+H` join backlog, **REDACT** (`draft/message-redaction`),
  **MARKREAD** (`draft/read-marker`), and **multiline** (`draft/multiline`).
- **RELAYMSG** (`draft/relaymsg`) — bridge messages under a spoofed relay nick.

### The full mode set
- **Prefixes** `+qaohv` (`~&@%+`), plus an optional network-staff prefix `+y` (`!`)
  above owner (`operprefix` / `OJOIN`).
- **List modes** `+b` ban, `+e` except, `+I` invex, `+g` word filter, `+X`
  exemptchanops, `+w` auto-status.
- **Parametered** `+k` key, `+l` limit, `+f` message-flood, `+j` join-flood, `+F`
  nick-flood, `+L` redirect-when-full, `+H` history, `+B` anticaps, `+J`
  kick-no-rejoin, `+d` delay-msg, `+K` no-repeat.
- **Flags** `+imnpstz`, `+O` oper-only, `+N` no-nick, `+C` no-CTCP, `+T` no-notice,
  `+c` no-colour, `+S` strip-colour, `+R` reg-only, `+M` reg-moderated, `+G` censor,
  `+u` auditorium, `+Q` no-kicks, `+A` allow-invite, `+P` permanent, `+U`
  op-moderated, `+D` delay-join.
- **User modes** `+i w o x s g` plus `+B` bot, `+D` deaf, `+I` hide-chans, `+H`
  hide-oper, `+r` logged-in, `+R` reg-only-PM, `+z` TLS-only-PM, `+W` show-whois,
  `+h` helpop, `+c` common-chans-only.
- **Extbans** — matching `g:` security-group, `y:` reputation, `r:` realname,
  `j:` in-channel, `s:` server, `G:` country, `b:` other-channel's ban list; acting
  `m:` mute, `c:` no-colour, `n:` no-nick.

### Operators
- `OPER`/`KILL`/`WALLOPS`/`GLOBOPS`, snomasks (`+s`) with an optional `chanlog`.
- Overrides: `SAJOIN`/`SAPART`/`SANICK`/`SAMODE`/`SATOPIC`/`SAKICK`/`SAQUIT`,
  `CHGHOST`/`CHGIDENT`/`CHGNAME`/`SETHOST`/`SETIDENT`/`SETIDLE`, `NICKLOCK`/
  `NICKUNLOCK`, `SWHOIS`, `CHECK`, `CLEARCHAN`, `ALLTIME`, `OPERMOTD`, `VHOST`,
  `TITLE`, oper-override-with-accountability, `operprefix`/`OJOIN`, `hidelist`/
  `hidemode`.
- **X-lines** `KLINE`/`GLINE`/`ZLINE`/`ELINE`/`SHUN`/`QLINE`/`CBAN`, persisted to
  disk and restored on boot; `STATS`; on-demand `CONNECT`; `DIE`/`RESTART`; and a
  reload-safe **`REHASH`** (keeps the running config if the file can't be read).

### IRCv3 capabilities
`sasl`, `server-time`, `message-tags` (+ `msgid`), `multi-prefix`, `away-notify`,
`account-notify`, `extended-join`, `chghost`, `userhost-in-names`, `echo-message`,
`invite-notify`, `setname`, `extended-monitor`, `account-tag`, `standard-replies`,
`labeled-response`, `batch`, `cap-notify`, and drafts `chathistory`,
`message-redaction`, `pre-away`, `metadata-2`, `multiline`, `account-registration`,
`json-log`, `extended-isupport`, `relaymsg` — plus `WATCH`/`MONITOR`/`SILENCE` and
`ACCEPT` (+ `+g` callerid).

### Services interface & accounts
- **SASL** PLAIN + EXTERNAL (TLS client-cert), relayed to an external services
  server over S2S.
- `SVSNICK`/`SVSJOIN`/`SVSPART`/`SVSMODE`/`SVSLOGIN`/`SVSLOGOUT`, `ENCAP`,
  `METADATA`; account-gated modes (`+r`/`+R`/`+M`). The ircd is *ready* for an
  external services package — it is not one itself.
- Optional ircd-side account **registration** (`REGISTER`/`VERIFY` over an HTTP
  API), CAPTCHA gating, and `EXTJWT` / file-host tokens.

### Server-to-server linking
Handshake, `UID`/`FJOIN` netburst, cross-server users and channels, multi-hop
routing, nick-collision handling, and clean netsplit.

### Anti-abuse
`antimixedutf8` (look-alike script spam), `antirandom` (gibberish nicks), message
flood (`+f`) + global rate limits, `connflood`/`connectban` (connection floods),
`blockamsg`, `securelist`, `dnsbl`, CAPTCHA / challenge gating, `solvemsg`
(arithmetic gate), `dccallow` (DCC filtering), `conn_waitpong`, `autodrop`.

### GeoIP
A **native MaxMind `.mmdb` reader** (no crate): the `G:<cc>` geoban extban, a
`GEOIP` oper command, and a country line in WHOIS.

### TLS, cloaking, transports
- **TLS** (openssl) with `SSLINFO`, cert fingerprints, and `+z` secure-only.
- Keyed-SHA-256 host **cloaking** (`+x`).
- A **native WebSocket transport** (`ws://` and `wss://`) with real-IP / scheme
  behind a trusted proxy.
- Reverse-DNS on connect via a from-scratch forward-confirmed PTR resolver over
  UDP (no DNS crate), off the core thread, fail-safe to the IP.

### JSON-RPC control plane
A native inbound HTTP server + JSON-RPC interface (no `serde`, no `hyper`) with
token auth and ~30 methods across core/user/channel/server/stats/ban/message.

### Native building blocks
Everything is hand-rolled to stay dependency-light and `unsafe`-free: the DNS
resolver, JWT (HS256), JSON scan/build, the mmdb reader, an HTTP client, and
password hashing (`md5`/`sha1`/`sha256`/`sha512`/`pbkdf2`).

### Everything is configurable
Limits, thresholds, durations, timeouts and list sizes are all config keys — the
literal in code is only the default; nothing operational is hardcoded.

## Originality

echoIRCd is original Rust — no code is copied or translated from any other
project. `scripts/native-rust-guard.sh` enforces this (no `unsafe`, no C/FFI, and
dependencies limited to `openssl` + `mio`); it runs on every edit.

## License

See the repository for licensing.
