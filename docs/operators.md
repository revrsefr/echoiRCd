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

### Oper types

An `oper` block can name a **type** with `type=<id>` — a role that decides what the
oper may actually do, what usermodes and snomasks they get on oper-up, and how their
`/WHOIS` reads (`is a <title>`). An oper with **no** `type` keeps full access (every
oper command and privilege), so existing blocks are unaffected.

A type is built from reusable **classes** — capability bundles across three axes:
**commands** (which oper commands run), **privileges** (named permissions checked at
sensitive points — see below), and **modes** (which oper-only usermodes/chanmodes may
be set):

```text
# class = <id> [commands=<A,B,…|*>] [privs=<x,y|*>] [usermodes=<letters|*>] \
#              [chanmodes=<letters|*>] [snomasks=<letters|*>]
class = ban       commands=KILL,KLINE,GLINE,ZLINE,QLINE,ELINE,RLINE,SHUN,CBAN,CHECK snomasks=kx
class = auspex    privs=users/auspex,channels/auspex,servers/auspex
class = override  commands=SAJOIN,SAPART,SANICK,SAKICK,SAMODE,SATOPIC,SAQUIT,CLEARCHAN privs=channels/override,users/flood

# opertype = <id> classes=<a,b|*> [commands=…] [privs=…] [usermodes=…] [chanmodes=…] \
#            [modes=+iw] [snomasks=+cg] [vhost=host.name] [title=Nice_Title] [level=N]
opertype = netadmin classes=* modes=+iw snomasks=+* title=Network_Administrator level=100

oper = alice sha256:<hex> type=netadmin
```

Every list accepts `*` for "all" and a leading `-` on a token to **remove** one, so
`commands=*,-DIE` is every command except `DIE` and `privs=*,-users/auspex` is every
privilege but that. A type's `modes`/`snomasks` are auto-applied at oper-up — distinct
from the `usermodes`/`chanmodes` **allowlists**, which cap which oper-only modes the
type may *set* (unset ⇒ unrestricted). `vhost` (if given) replaces the host; `title`
(underscores become spaces) is the `/WHOIS` line; `level` folds into the [oper
level](#oper-levels). Running a command, setting an oper mode, or exercising a
privilege the type doesn't grant is refused.

Five types ship **built-in**, so `type=<id>` works with no `class`/`opertype` config —
override or extend any by defining one with the same id:

| id | title | grants |
|----|-------|--------|
| `helpop` | Help Operator | +ih, oper snomask — a titled helper, no privileged commands |
| `globop` | GlobOp | + `WALLOPS`/`GLOBOPS` + announce snomasks |
| `admin` | Administrator | + `KILL`/x-lines/`SHUN`/`CHECK`, `SA*` override (`channels/override`, `users/flood`), `CHG*`/`SET*` |
| `servadmin` | Services Administrator | + the `SVS*` services commands |
| `netadmin` | Network Administrator | everything (`commands=*`, `privs=*`), plus `CONNECT`/`SQUIT`/`DIE`/`RESTART` |

Only `netadmin` holds **privileges** by default; grant the built-in `auspex` class (or
specific privileges) to any other type that should see through privacy.

### Privileges

Named permissions the daemon checks wherever it protects something beyond a plain
command. Assign them via `privs=` on a class or type (`*` = all, `-x` removes one):

| Privilege | Grants |
|-----------|--------|
| `users/auspex` | a user's real host+IP and geo in `/WHOIS` & `/WHO`, `+i` users you share no channel with, `+I` hidden channel lists, and the IP/geo fields of the connect notice |
| `channels/auspex` | secret/private (`+s`/`+p`) channels and their members in `/LIST`, `/WHO`, `/WHOIS`, `/NAMES` |
| `servers/auspex` | U-lined/services servers otherwise hidden by `hideservices` in `/MAP` & `/LINKS` |
| `channels/override` | join through `+k`/`+b`/`+i`/`+l`/`+z`/`+R`/`+J`, a `CBAN`, and the max-channels cap |
| `channels/restricted-create` | create a new channel while `restrictchans` is on |
| `channels/ignore-nonicks` | change nick while on a `+N` (no-nick-change) channel |
| `users/flood` | exemption from the message- and join-flood limits |
| `users/ignore-commonchans` | message a `+c` user without sharing a common channel |
| `users/ignore-callerid` | message a `+g` (caller-ID) user without being on their accept list |
| `users/ignore-privdeaf` | reach a `+D` (deaf) user with your channel messages despite their deafness |
| `users/ignore-restrictmsg` | private-message anyone while `restrictmsg` is on |
| `users/secret-whois` | `/WHOIS` a `+W` (showwhois) user without notifying them |
| `servers/use-disabled-commands` | use a command turned off by `disabled_commands` |
| `servers/ignore-securelist` | bypass the `securelist` LIST hold for fresh connections |
| `servers/ignore-blockamsg` | send `/AMSG`-style multi-channel messages the `blockamsg` module blocks |

The built-in `override` class carries the channel/message/anti-spam bypasses
(`channels/restricted-create`, `channels/ignore-nonicks`, `users/ignore-restrictmsg`,
`servers/ignore-securelist`, `servers/ignore-blockamsg`), `auspex` carries the
see-through-privacy set (the three `*/auspex` plus `users/secret-whois`,
`users/ignore-callerid` and `users/ignore-privdeaf`), and `servers/use-disabled-commands`
sits on the `server` class.

## Snomasks

Server-notice masks (`+s`) subscribe an oper to categories of the server's live
event stream — connects, floods, link events, and so on. Set them as a
mode parameter, e.g. `/MODE yournick +s +ck`. The stream can also be mirrored to
a channel (`chanlog`), a file (`log_json`), or the system logger (`syslog`).

The `+c` (connect) notice shows each client's nick, `+x` cloak, listener port,
transport (WebSocket / TLS) and account; its **real IP** and **GeoIP/ASN** are shown
only to opers holding `users/auspex` — everyone else on `+c` sees those two fields
redacted, while the server log always keeps the full line.

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
