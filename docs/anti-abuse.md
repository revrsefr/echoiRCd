# Anti-abuse & flood protection

Abuse is stopped at whichever layer can stop it most cheaply. Being honest about
which layer owns which threat matters, because the daemon **cannot** defend
against some attacks no matter how it's written.

## The three layers

```text
┌─ upstream / provider ─┐  volumetric floods (large SYN / UDP), amplification
│  (scrubbing, e.g. VAC) │  → only the network above you can absorb these
├─ host kernel / firewall┤  SYN cookies, per-IP connection-rate, conntrack caps
│                        │  → cheap kernel drops before the daemon is involved
├─ echoIRCd (application)┤  connection & message floods, clones, spam content
└────────────────────────┘  → everything that survives to a real IRC session
```

**What the daemon can't do:** a **SYN flood** is spoofed TCP handshake packets
that exhaust the kernel's backlog *before* `accept()` ever returns — kernel
territory (enable `net.ipv4.tcp_syncookies`). A **UDP flood** is pure bandwidth
exhaustion, and since IRC is TCP-only the packets never reach the application at
all. Both are volumetric and are handled by the **kernel and the upstream
provider**, not by Rust. Everything below is what the application *can* do:
stop abusive *sessions and content*.

## Application layer (echoIRCd)

### At the accept edge

Rejected before any per-connection state is allocated — the cheapest point:

- **`accept_rate` / `accept_burst`** — a per-source-IP token bucket. A source
  opening connections faster than the rate has its socket dropped immediately.
  Off by default; trusted proxies and server links are exempt. Complements the
  *concurrent* clone caps below with a *rate* cap.
- **`connflood = <max> <secs>`** and **connectban** — refuse, and optionally
  z-line, an IP that opens too many connections too fast.

### Per connection

- **Clone caps** — connection classes cap concurrent connections per IP with
  `localmax` (this server) and `globalmax` (network-wide).
- **`registration_timeout`** — a connection that never sends NICK+USER is dropped.
- **`tls_handshake_timeout`** — a TLS connection that opens the port but never
  negotiates is reaped (it holds no session, so nothing else would).
- **`conn_waitpong`** — hold registration until the client answers a server PING
  with the exact cookie. Real clients auto-reply; dumb bots never do.
- **recvq / hardsendq / softsendq** — per-connection queue caps bound memory; a
  client past `softsendq` has its reads paused (backpressure), and past
  `hardsendq` is dropped.

### Per message (flood control)

- **Fakelag** — `flood_messages` per `flood_seconds` (opers exempt) throttles a
  client sending too fast; per class, `fakelag=no` disconnects instead of
  throttling. Channel modes `+f` / `+j` / `+F` add per-channel message / join /
  nick-change flood limits.

### Reputation & network bans

- **Reputation** — every address accrues a score over time; the `y:<score>`
  extban bans by it (`+b y:<100`).
- **DNSBL** — check connecting IPs against DNS blocklists (`mark` / `kill` /
  `kline` / `gline` / `zline`). Each `dnsbl` zone may carry its own
  `name` / `action` / `duration` / `reason` (the reason supports `%ip%`), or fall
  back to the global defaults.
- **X-lines** — persistent `K` / `G` / `Z` / `Q` / `CBAN` / `RLINE` bans (see
  [operators](operators.md)).

### Spam content

Modules that inspect *what* users do:

| Module / setting | Catches |
|------------------|---------|
| `antirandom` | Random-looking (drone) nick/ident/realname. |
| `antimixedutf8` | Words mixing look-alike Unicode scripts. |
| `filter` / `badword` (`+G`) | Configured spam phrases / words. |
| `solvemsg` | Un-vouched users must answer an arithmetic question before PMs deliver. |
| `recaptcha` / `cloudflare_challenge` | Human-verification gate at registration. |
| `autodrop` | Pre-registration clients that blurt HTTP verbs (scanners). |
| `blockamsg` | Mass `/amsg` / `/ame` spam. |
| `restrictmsg` / `restrictcommands` / `restrictchans` / `denychans` / `channames` | Constrain who may PM, run commands, or create/name channels. |
| `dccallow` | Unwanted DCC transfers. |
| Security groups | Named user sets (`g:<name>` extban) for policy by trust level. |

## Kernel / firewall layer

The repo ships [`deploy/firewalld-echoircd.sh`](../deploy/firewalld-echoircd.sh),
a per-source-IP connection-rate limit installed through firewalld's direct-rule
interface (so firewalld owns it and won't flush it on reload):

```sh
sudo deploy/firewalld-echoircd.sh add     # 30/s burst 60 per IP on the IRC ports
sudo deploy/firewalld-echoircd.sh del     # remove
sudo deploy/firewalld-echoircd.sh show
```

It's **safe by design**: a policy-`ACCEPT` rule that only drops the rate-limited
*excess* to the client ports, loopback-exempt, changing no other policy. This
drops connection-churn floods in the kernel before they cost the daemon anything —
the same job as `accept_rate`, one layer lower. On a host without firewalld, the
equivalent is an `iptables`/`nftables` `hashlimit` rule, or an upstream WAF.

## A recommended baseline

1. **Kernel:** `net.ipv4.tcp_syncookies = 1` (usually already on).
2. **Firewall:** the firewalld script above (or an equivalent per-IP rate limit).
3. **Daemon:** set `accept_rate` / `accept_burst`; keep `registration_timeout`
   and `tls_handshake_timeout` at sane values; enable `conn_waitpong` if bots are
   a problem; add DNSBL zones; use connection classes with `localmax` / `globalmax`
   to cap clones.
4. **Upstream:** rely on your provider's DDoS scrubbing for volumetric attacks —
   nothing on the host can absorb a saturating flood.

Keep the firewall rate and `accept_rate` roughly aligned so the two layers agree,
and pick values generous enough that a real shared-NAT never trips them (a single
client never opens dozens of connections per second).
