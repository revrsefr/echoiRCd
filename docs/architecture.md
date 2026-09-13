# Architecture

echoIRCd is built around one idea: **all shared state lives on a single thread,
and everything that can be parallelized without touching that state is pushed off
of it.** This page explains what that means, why it was chosen, and how the pieces
fit.

## The core thread

A single **core thread** owns every `User` and `Channel` in a `Server` struct.
Command handlers, mode handlers, and module hooks are all ordinary synchronous
functions that take `&mut Server` and mutate it directly. There is no
`Arc<Mutex<…>>`, no `RwLock`, no actor mailbox, and no `.await` anywhere in the
command path.

The core runs one loop:

```text
for ev in rx {          // rx is a bounded channel fed by the I/O edge
    handle_event(ev)    // Connect / Line / Disconnect / Tick / async results
}
```

Every state change funnels through this loop, so there is exactly one writer to
the state graph and no data races are possible by construction.

The channel is **bounded** (`core_queue_max`): if the core ever falls behind,
producers on the I/O edge block instead of growing an unbounded backlog until the
process runs out of memory. The core never enqueues to itself inline, so a full
queue can slow producers but can never deadlock the loop.

### Why not an async runtime?

IRC is one large shared mutable graph. Almost every command reads part of it,
mutates part of it, and then broadcasts to many connections — a channel message
touches the send buffers of everyone in the channel, a nick change updates a
global map and notifies every common-channel peer, and so on. This workload has
two properties that decide the design:

1. **The write set is global and interconnected.** You cannot cleanly shard the
   state by connection, because messages cross shards constantly.
2. **The per-message CPU cost is tiny.** Parse a line, look up a channel, append
   bytes to some send buffers. It is almost entirely I/O-bound.

Put those together and a multi-threaded async runtime buys you nothing here:
you'd have to wrap the shared graph in a global lock (serializing everything you
just spread across threads) or an actor that processes messages one at a time
(a single-threaded loop with extra steps). Meanwhile you'd pay for `Send +
'static` bounds on every future and a scheduler you don't need. So the core stays
single-threaded and lock-free, and `mio` provides the same readiness layer an
async runtime would build on — without the runtime.

The thing that single-threaded state *can't* do is use more than one core. That's
fine, because the two things that actually benefit from multiple cores — the
socket syscalls and the TLS crypto — don't touch shared state at all. They run in
the reactor pool.

## The reactor pool

Client connections are served by a **pool of reactor threads**, sized by
`io_threads` (default: one per CPU, capped). The shape is:

```text
                 ┌──────────── acceptor ────────────┐
   listener ───▶ │ accept(), pick a worker (round-  │
                 │ robin), hand off the socket       │
                 └───────┬──────────┬──────────┬─────┘
                         ▼          ▼          ▼
                    reactor 0   reactor 1   reactor N     (each: its own mio poll,
                    its own conns map, its own token space)
                         │          │          │
                         └──────────┴──────────┘
                                    ▼
                          Event channel ──▶ core thread (single, lock-free)
```

- One **acceptor** owns the listener, accepts connections, and round-robins each
  new socket onto a worker.
- Each **worker** runs its own `mio` poll loop over its own shard of connections.
  It reads bytes, frames complete lines, and sends the core `Line` / `Connect` /
  `Disconnect` events. Tokens are worker-local; the shared atomic counter only
  mints globally-unique `Uid`s.
- The **core** processes those events serially. Output flows back the other way:
  when the core writes to a connection, the write is routed to the owning worker,
  which drains it to the socket.

Because workers only frame bytes and feed the core, and the core owns all state,
the parallel part needs **no shared locking** — the only cross-thread contact is
the lock-free event channel.

## The I/O models

Three transports coexist behind one `OutSink` handle, so the core never knows or
cares which one a connection uses:

| Transport | Model | Notes |
|-----------|-------|-------|
| **Plaintext clients** | reactor pool | The common case; one worker frames many sockets. |
| **Direct TLS clients** | reactor pool | The handshake and record crypto run **non-blocking inside the worker**, driven off a `mio` socket by the configured TLS backend (OpenSSL by default, or rustls via `tls_backend = rustls`). TLS work spreads across cores like everything else. |
| **Proxied TLS** (a PROXY header before the handshake) | thread per connection | Reading the pre-handshake header wants the simpler blocking path; there are few of these. |
| **Server links** | thread per connection | A handful of long-lived peers; not worth multiplexing. |

Scaling out to more machines is done by **linking servers** (see
[linking](linking.md)), not by threading one server harder — the single core is
the correct unit, and the network grows by adding nodes.

### Outbound & background work

The same event-channel discipline covers everything the core reaches *out* to, so
a slow remote can never block it. Each runs on its own thread(s) and hands its
result back to the core as an event; none can touch `Server` state directly:

- **HTTP client** — a request runs on a bounded worker pool and returns as an
  `HttpResult` event. It backs the connection-verification gates and the protocol
  bridges (the Telegram and Matrix long-poll / send calls).
- **Database pool** — a non-blocking PostgreSQL client. Queries are submitted to a
  bounded queue and their rows come back as `SqlResult`; a panicking query is
  isolated and the pool keeps serving.
- **XMPP bridge** — a persistent TLS XML-stream client on its own thread. Inbound
  group-chat lines arrive as `BridgeIn` events; outbound lines are handed to the
  worker over a channel. Dropping that channel (a bridge reload) closes the stream
  and ends the thread.

A bridged message is injected through the same tagged send path a relayed message
uses, which bypasses the outbound message hook, so a bridge can never feed its own
output back into itself.

## Resilience

A single-threaded core has an obvious risk: one slow or crashing thing could
freeze or kill everyone. Each of those failure modes is closed off:

- **Nothing slow runs inline.** Deliberately-slow work is offloaded to bounded
  worker threads and delivered back as an event:
  - **KDF password hashing** (bcrypt / pbkdf2) for `OPER`, `PASS` connect-class
    checks, `TITLE`, and `MKPASSWD` — a flood of auth attempts can't freeze the
    core.
  - **DNS, ident, and HTTP** requests — the HTTP path also drives the connection
    verification gates and the protocol bridges' Telegram/Matrix calls.
  - **Database queries** on a non-blocking connection pool, and the **XMPP bridge**
    on a dedicated stream thread.
  - **Disk snapshot writes** (reputation, channel metadata, X-lines) go through a
    coalescing background writer, so a slow or full disk never stalls the event
    loop. Writes are **atomic** (temp file + rename), so a crash mid-write can't
    leave a truncated file.
- **A slow core can't exhaust memory.** The event channel is bounded
  (`core_queue_max`); when the core falls behind, the I/O edge applies backpressure
  instead of buffering without limit.
- **Admission stays O(1).** Connection-class and per-IP clone limits are checked
  against incremental counters, not by scanning every connected user on each
  connect, so a reconnect storm (e.g. netsplit recovery) stays linear.
- **One panic can't take down the server.** Each event is handled inside
  `catch_unwind`, and in the reactor each connection's reads/writes are isolated —
  a panic parsing one client's bytes drops *that* client and logs it, never the
  worker that serves everyone else.
- **A stuck core is visible.** A watchdog thread reads a shared "busy since"
  marker and logs if the core stays on one event past `watchdog_ms`; slow events
  also raise a server notice (`slow_command_ms`). In production a liveness probe
  restarts the service if a register round-trip stops answering.
- **Half-open connections are reaped.** A connection that never registers is
  dropped after `registration_timeout`; a TLS connection that opens the port but
  never negotiates is dropped after `tls_handshake_timeout`.

See [anti-abuse](anti-abuse.md) for how these combine with flood limits and
kernel-level filtering.

## Live binary upgrades

A rebuilt binary is rolled out without ever closing the listening sockets. On
`SIGUSR2` the server re-execs the new build and passes it the open listener file
descriptors — plaintext, TLS, WebSocket, and server-link ports — which the new
process **adopts by role** instead of re-binding. Listeners are bound with
`SO_REUSEPORT`, so even the brief overlap between old and new can't fail with
"address already in use", and there is no window in which a connecting client is
refused.

In-flight sessions are not migrated across the exec — the new process is a fresh
address space, so existing clients reconnect — but because the listeners are
handed over rather than rebound, a reconnect always lands on an open port. The two
low-level file-descriptor operations this needs are the only place the daemon
touches them; the crate itself stays `#![forbid(unsafe_code)]`.

## Memory safety

Safety is structural, not just a matter of avoiding raw pointers:

- **Handles, not pointers.** Users and channels are referenced by `Uid` /
  channel-key handles looked up in maps, so there are no dangling references and
  no use-after-free — a `Uid` is monotonic and never reused, so a stale handle
  resolves to nothing rather than to the wrong user.
- **A typemap, not `void*`.** Modules attach per-user / per-channel / per-server
  state through an `Extensible` typemap keyed by Rust type; it's dropped
  automatically with its owner, so module state can't leak or be freed twice.
- **Trait objects, not a plugin ABI.** Commands, modes, and modules are
  compiled-in trait objects. There is no dynamic-loading FFI boundary to get
  wrong.

## Tuning knobs

| Setting | Effect |
|---------|--------|
| `io_threads` | Reactor workers; `0` = auto (one per core, capped). Raise for very high connection/packet rates. |
| `core_queue_max` | Depth of the core's bounded event queue; the I/O edge backpressures when it fills (default 16384). |
| `max_line` / `max_sendq` | Per-connection receive/send-queue caps (per-class overrides exist). |
| `slow_command_ms` / `watchdog_ms` | Core-health visibility. |
| `tls_handshake_timeout` | Reap stalled TLS handshakes. |
| `LimitNOFILE` (OS) | File-descriptor ceiling; must be high to reach tens of thousands of connections. |

For a serious deployment, always run a **release build** — a debug build is
unoptimized and dramatically slower on the CPU-bound paths (TLS, hashing,
cloaking, parsing). See [deployment](deployment.md).
