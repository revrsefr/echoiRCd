# Configuration

The config is a plain `key = value` text file (default `./echoircd.conf`). Some
keys repeat to build a list (`motd`, `oper`, `link`, `connectclass`, `dnsbl`,
`securitygroup`, …). Comments start with `#`.

The shipped [`echoircd.conf.example`](../echoircd.conf.example) is the fully
annotated master reference — every key with its default. This page organizes those
keys by topic. **Every operational limit is a config key**; nothing is hardcoded.
Most settings apply on `REHASH` without a restart.

> `echoircd.conf` is gitignored because it holds secrets (oper password, cloak
> key, link password). Never commit your live config.

## Server identity

| Key | Meaning |
|-----|---------|
| `servername` | This server's name (e.g. `irc.example.net`). |
| `network` | Network name (advertised in ISUPPORT). |
| `sid` | Server ID for linking — 3 chars, first a digit (e.g. `0AA`). |
| `serverdesc` | Human-readable server description. |
| `motd` | Message of the day; repeat the key for extra lines. |

## Listeners & TLS

| Key | Meaning |
|-----|---------|
| `bind` | Plaintext client listener, `ip:port` (e.g. `0.0.0.0:6667`). |
| `bind_tls` | TLS client listener (e.g. `0.0.0.0:6697`). |
| `tls_cert` / `tls_key` | PEM certificate + private key for TLS (and `wss://`). |
| `tls_sni` | Serve a different cert for a given hostname (`<host> <cert> <key>`, repeatable). |
| `tls_backend` | `openssl` (default) or `rustls` (pure-Rust, no system OpenSSL). |
| `bind_server` | Server-to-server link listener (see [linking](linking.md)). |

Generate a self-signed cert to start:

```sh
openssl req -x509 -newkey rsa:2048 -keyout tls/key.pem -out tls/cert.pem \
        -days 3650 -nodes -subj "/CN=irc.example.net"
```

## I/O & performance

| Key | Default | Meaning |
|-----|---------|---------|
| `io_threads` | `0` (auto) | Reactor workers; `0` = one per core, capped. |
| `max_line` | `16384` | Max bytes in one line / receive queue. |
| `max_sendq` | `1048576` | Max queued output before a slow client is dropped. |
| `tls_handshake_timeout` | `15` | Drop a TLS conn that stalls mid-handshake (secs; `0` = off). |
| `slow_command_ms` | `200` | Server-notice when one event takes at least this long (`0` = off). |
| `watchdog_ms` | `5000` | Log if the core is stuck on one event this long (`0` = off). |

## Connection classes

`connectclass = <name> key=value …` — per-class connection policy. Each line
matches connecting clients by IP/host mask (glob **or** CIDR) and optional
TLS/port; the first match wins, else the global limits apply. Masks are tested at
connect (against the IP) and re-tested at registration (against the resolved
host).

Key options: `allow=<mask[,mask]>`, `deny=yes`, `parent=<name>` (inherit),
`requiressl=yes|trusted`, `password=<pw>` + `hash=<algo>`, `port=<p[,p]>`,
`localmax=<n>` (per-IP, this server), `globalmax=<n>` (per-IP, network-wide),
`limit=<n>` (total users in class), `maxchans=<n>`, `pingfreq=<secs>`,
`timeout=<secs>` (registration), `modes=<+modes>`, `recvq` / `hardsendq` /
`softsendq` (queue caps), `fakelag=no` (disconnect flooders instead of throttling),
`penaltythreshold` / `commandrate` (flood window), `useident=yes`,
`requireident=yes`, `resolvehostnames=no`, `maxconnwarn=yes`.

```text
connectclass = trusted allow=10.0.0.0/8  maxchans=200 pingfreq=120 fakelag=no
connectclass = secure  allow=*  requiressl=yes  password=sha256:<hex> hash=sha256
connectclass = vpn     allow=*  parent=trusted localmax=2 maxchans=20 modes=+ix
connectclass = banned  allow=1.2.3.0/24 deny=yes
connectclass_required = yes    # refuse clients matching no allow class (default no)
```

## Connection policy & timeouts

| Key | Default | Meaning |
|-----|---------|---------|
| `registration_timeout` | `60` | Drop clients that never send NICK+USER in time. |
| `ping_frequency` | `90` | Send a PING after this much idle. |
| `ping_timeout` | `60` | Then drop if no PONG within this much longer. |
| `resolve_hosts` | `on` | Do reverse DNS on connect. |
| `use_resolved_host` | `on` | Use the resolved host in the mask (else keep the IP). |
| `useident` / `requireident` / `ident_timeout` | off / off / `5` | RFC 1413 ident lookups. |
| `conn_waitpong` | off | Hold registration until the client PONGs a cookie (bot filter). |
| `abbreviation` | off | Let a unique command prefix resolve (`WHOI` → `WHOIS`). |

## Operators

| Key | Meaning |
|-----|---------|
| `oper = <name> <password> [level]` | An oper account; the password may be hashed (see `MKPASSWD`). Optional numeric [oper level](operators.md). |
| `opermotd` | A line shown to opers via `/OPERMOTD` (repeatable). |
| `operprefix` | Give every oper a `!` prefix in their channels. |
| `ojoin` / `ojoin_op` | Enable `/OJOIN` (join as staff, with op unless `ojoin_op = no`). |

## Linking & services

| Key | Meaning |
|-----|---------|
| `link = <name> <ip> <port> <password> [autoconnect]` | A peer server; password is a shared secret. |
| `sasl_server` | The linked server that handles SASL (relayed AUTHENTICATE). Unset disables SASL. |
| `webirc = <password> [gateway] [ip-mask]` | Trust a web gateway's `WEBIRC` (real client host/IP). |

See [linking](linking.md) for the full picture.

## Anti-abuse

| Key | Meaning |
|-----|---------|
| `accept_rate` / `accept_burst` | Per-IP new-connection rate limit at the accept edge (`0` = off). |
| `flood_messages` / `flood_seconds` | Per-user message-rate limit (opers exempt). |
| `connflood = <max> <secs>` | Refuse an IP opening more than `max` connections per `secs`. |
| `dnsbl` / `dnsbl_action` / `dnsbl_reason` / `dnsbl_duration` | DNS blocklist checks (`mark` / `kill` / `kline` / `gline` / `zline`). |
| `antimixedutf8` + `amu_*` | Block spam mixing look-alike scripts. |
| `badword = <find> [replacement]` | `+G` censor list. |
| `autodrop_commands` | Silently drop pre-registration clients that send these (HTTP scanners). |
| `solvemsg` | Make un-vouched users answer an arithmetic question before their PMs deliver. |
| `dccallow_*` | Filter unwanted DCC transfers. |

See [anti-abuse](anti-abuse.md) for how these layer together.

## Identity & privacy

| Key | Meaning |
|-----|---------|
| `cloak_key` | Secret for host cloaking (`+x`). A long random hex string; changing it re-cloaks everyone. |
| `vhost = <user> <pass> <host>` | A self-service vhost claimable with `/VHOST`. |
| `customprefix` | Reconfigure prefix tiers or define brand-new prefixes. |
| `hidewhois` + `hidewhois_*` | Hide sensitive WHOIS lines from ordinary users. |
| `hidemode = <mode> <rank>` / `hidelist = <mode> <rank>` | Restrict who sees mode changes / list-mode entries. |

## GeoIP, reputation & security groups

| Key | Meaning |
|-----|---------|
| `geoip_database` | Path to a MaxMind `GeoLite2-Country.mmdb`; enables the `G:<cc>` extban, `GEOIP` command, WHOIS country. |
| `reputation_*` / `reputationexpire` | Per-address reputation scoring and the `y:<score>` extban. |
| `securitygroup = <name> [criteria…]` | A named user set usable as the `g:<name>` extban. |

## Logging

| Key | Meaning |
|-----|---------|
| `syslog` + `syslog_target` / `syslog_facility` / `syslog_tag` | Mirror the notice/log stream to the system logger (`/dev/log` or `host:port`). |
| `log_json` | Append the notice/log stream to a file as JSON lines. |
| `chanlog` | Mirror the oper server-notice stream into a channel. |

## Control & observability

| Key | Meaning |
|-----|---------|
| `metrics_bind` | Bind an OpenMetrics/Prometheus scrape endpoint (`ip:port`, plaintext HTTP GET). Off unless set — expose it privately or behind a proxy. |
| `rpc` + `rpc_bind` | Enable the JSON-RPC control plane and bind its HTTP listener. Both required to turn it on. |
| `rpc_user` / `rpc_token` | Credentials for the control plane — sent as HTTP Basic (`user:token`) or Bearer. Bind privately; the token is a shared secret. |

## Transports

| Key | Meaning |
|-----|---------|
| `proxy = <glob\|CIDR>` | Trust the PROXY protocol header from these sources (real client IP). Repeatable. |
| `bind_ws` / `bind_wss` | WebSocket listeners (`ws://` / `wss://`). |
| `ws_origin`, `ws_proxyranges`, `ws_trust_proxy`, `ws_timeout`, … | WebSocket policy — see the example config. |

## Advertised limits

Each is a config key with a built-in default; set a line only to override.

| Key | Default | | Key | Default |
|-----|---------|-|-----|---------|
| `maxnick` | `30` | | `maxwatch` | `128` |
| `maxchannel` | `50` | | `maxmonitor` | `128` |
| `whowas_maxentries` | `256` | | `maxsilence` | `32` |
| `chathistory_limit` | `256` | | `maxaccept` | `64` |
| `multiline_maxbytes` | `4096` | | `multiline_maxlines` | `24` |

For the complete, per-key annotated list including every module's options, see
[`echoircd.conf.example`](../echoircd.conf.example).
