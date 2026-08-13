# Operators

IRC operators ("opers") are staff with elevated privileges. This page covers
becoming an oper, the command toolbox, snomasks, and the ban ("X-line") system.

## Becoming an operator

Define oper accounts in the config:

```text
oper = admin CHANGE_THIS_PASSWORD          # plaintext (fine behind a private config)
oper = helper sha256:<hex>                 # or a hashed password
oper = root  $2b$12$…                       # bcrypt is supported too
```

A client authenticates with `/OPER <name> <password>`, gains user mode `+o`, and
(optionally) a staff prefix — see [operprefix](configuration.md). Generate a
hashed password with the oper-only `/MKPASSWD <algo> <password>` command
(`md5`, `sha1`, `sha256`, `sha512`, `pbkdf2`, `bcrypt`). KDF hashes are verified
off the core thread, so an `OPER` flood can't freeze the server.

### Oper levels

An `oper` block may carry a trailing numeric **level** (`oper = <name> <pass>
<level>`). Levels gate sensitive actions — for example, a higher-level oper can't
be `KILL`ed by a lower-level one. Levels are advisory policy layered on top of the
`+o` flag.

## Snomasks

Server-notice masks (`+s`) subscribe an oper to categories of the server's live
event stream — connects, floods, link events, and so on. Set them as a
mode parameter, e.g. `/MODE yournick +s +ck`. The stream can also be mirrored to
a channel (`chanlog`), a file (`log_json`), or the system logger (`syslog`).

## User & network management

| Command | Purpose |
|---------|---------|
| `KILL <nick> :<reason>` | Disconnect a user from the network. |
| `WALLOPS :<msg>` | Message all `+w` users. |
| `GLOBOPS :<msg>` | Message all opers. |
| `SHUN <mask> [dur] :<reason>` | Silence a user (they stay connected but can't act). |
| `CHECK <nick\|#chan\|mask>` | Deep inspection of a user, channel, or mask. |
| `GEOIP <nick\|ip>` | Country lookup (needs `geoip_database`). |
| `TLINE <mask>` | How many connected users a proposed ban mask would hit. |

## X-lines (bans)

Bans are persisted to disk and survive restarts. Expired entries are purged
automatically.

| Command | Bans by | Scope |
|---------|---------|-------|
| `KLINE <mask> [dur] :<reason>` | user@host | this server |
| `GLINE <mask> [dur] :<reason>` | user@host | whole network |
| `ZLINE <ip> [dur] :<reason>` | IP / CIDR | whole network (cheapest — pre-DNS) |
| `ELINE <mask> [dur] :<reason>` | user@host | exemption from other X-lines |
| `QLINE <mask> [dur] :<reason>` | nick mask | reserve/forbid nicknames |
| `CBAN <#mask> [dur] :<reason>` | channel name | forbid joining/creating |
| `RLINE <regex> [dur] :<reason>` | `nick!user@host realname` regex | native regex engine |
| `TBAN <#chan> <dur> <mask>` | a timed `+b` on one channel | auto-lifts |

Durations accept human forms (`1d`, `2h`, `30m`); `0` or omitted means permanent.

## Override toolbox

Force actions an ordinary user couldn't take. These change a target's identity or
state directly.

| Command | Effect |
|---------|--------|
| `SANICK <nick> <new>` | Force a nick change. |
| `SAJOIN <nick> <#chan>` / `SAPART` | Force join / part. |
| `SAKICK <#chan> <nick>` | Force a kick. |
| `SAMODE <target> <modes>` | Set modes with server authority. |
| `SATOPIC <#chan> :<topic>` | Force a topic. |
| `SAQUIT <nick> :<reason>` | Force a quit. |
| `CHGHOST` / `CHGIDENT` / `CHGNAME` | Change a user's displayed host / ident / real name. |
| `SETHOST` / `SETIDENT` / `SETNAME` | Change your *own* host / ident / real name. |
| `SWHOIS <nick> :<line>` | Add a custom WHOIS line to a user. |
| `NICKLOCK` / `NICKUNLOCK` | Freeze / release a user's nick. |
| `CLEARCHAN <#chan>` | Clear a channel (kick everyone / reset it). |
| `SETIDLE <secs>` | Adjust your reported idle time. |

## Services-side commands

These are the interface a linked services package drives (see
[linking](linking.md)): `SVSNICK`, `SVSJOIN`, `SVSPART`, `SVSMODE`, `SVSLOGIN`,
`SVSLOGOUT`, plus `SVSHOLD` / `SVSTOPIC` / `SVSOPER` / `SVSCMODE` and generic
`ENCAP` / `METADATA`.

## Server management

| Command | Effect |
|---------|--------|
| `REHASH` | Re-read the config and apply every setting that can change at runtime. |
| `CONNECT <server>` | Dial a configured uplink. |
| `DIE` / `RESTART` | Shut down / restart the daemon. |
| `MAP` / `LINKS` | Show the network topology (hideable from non-opers). |

## Diagnostics

`STATS <char>`, `SSLINFO <nick>` (TLS/cert details), `REPUTATION <nick\|ip>`,
`SECURITYGROUPS`, and `FILTER` (manage spam/word filters at runtime).
