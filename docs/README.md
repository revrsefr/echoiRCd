# echoIRCd documentation

echoIRCd is a memory-safe IRC + IRCv3 server written in Rust. A single lock-free
core thread owns all state; a pool of epoll reactor threads drives the connections
around it — TLS crypto and all — with no async runtime.

This folder is the reference manual. Start with whichever fits what you're doing:

| Doc | What's in it |
|-----|--------------|
| [Building & running](building.md) | Prerequisites, debug/release builds, tests, project layout. |
| [Configuration](configuration.md) | The config file format and a grouped reference of every setting. |
| [Architecture](architecture.md) | The single-threaded core + reactor-pool design, the I/O models, resilience, and memory safety. Read this to understand *why* it's built the way it is. |
| [Channel & user modes](modes.md) | Every prefix, list, parameter, and flag mode, plus extbans. |
| [Operators](operators.md) | The oper system, oper levels, snomasks, the override toolbox, and X-lines. |
| [Server linking & services](linking.md) | Server-to-server links, the netburst, routing, and the services / SASL interface. |
| [IRCv3](ircv3.md) | The advertised capabilities and the notable extensions. |
| [Anti-abuse & flood protection](anti-abuse.md) | The layered defenses, from the accept edge up to the application, and how they fit with kernel/upstream filtering. |
| [Deployment](deployment.md) | Running in production: release builds, a supervised service, log shipping, reverse proxies, and firewall hardening. |
| [**Module developer API**](api/) | Write your own commands, modes, and modules — the trait reference, the `Server` API, and a first-module tutorial. |

## At a glance

- **Full IRC core** — registration, channels, messaging, and the informational
  command set (100+ commands total).
- **Complete mode set** — the standard prefixes plus a staff prefix, list modes,
  keyed/limit/flood/redirect/history/anticaps parameters, the full flag set, and
  matching + acting extbans. See [modes](modes.md).
- **IRCv3** — a broad capability set including message-tags, server-time,
  labeled-response, batch, echo-message, account-tag, CHATHISTORY, multiline,
  message-redaction, read-marker, and relaymsg. See [IRCv3](ircv3.md).
- **Operators & services** — a rich oper toolbox with oper levels, X-lines
  persisted to disk, and a services interface (SASL over links, the `SVS*` /
  `ENCAP` / `METADATA` set, account-gated modes).
- **Transports** — plaintext, TLS (OpenSSL or rustls backend, with client-cert
  fingerprints), a native WebSocket layer, and the PROXY protocol behind a load
  balancer.
- **Security** — keyed host cloaking, DNSBL, GeoIP, layered connection/message
  flood limits, and script/gibberish spam detection.
- **Control & observability** — a token-authenticated JSON-RPC plane over HTTP and
  an optional OpenMetrics/Prometheus endpoint. See [configuration](configuration.md).

## Design in one paragraph

One **core thread** owns every user and channel, so command and module code is
ordinary single-threaded logic over `&mut Server` — no locks anywhere. The I/O
edge is a **pool of reactor workers** (one per core by default): they accept
connections, frame lines, and run TLS crypto, then hand the core plain events
over a channel. The core can't be frozen by slow work (KDF hashing, DNS, disk
writes all run off-thread), can't be killed by one bad connection (panics are
isolated per event and per connection), and is watched by a liveness thread. See
[architecture](architecture.md) for the full story.
