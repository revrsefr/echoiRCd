# Server linking & services

Multiple echoIRCd servers form one network by **linking**. Users and channels are
shared across all servers, and a services package (accounts, nick/channel
registration) attaches as just another linked server.

## Setting up a link

Each server needs a unique **SID** (3 characters, first a digit) and a link
listener:

```text
sid         = 0AA
bind_server = 0.0.0.0:7000
```

Then declare each peer, with a shared-secret password on both sides:

```text
# link = <name> <ip> <port> <password> [autoconnect]
link = peer.example.net 203.0.113.5 7000 SHARED_LINK_SECRET autoconnect
```

`autoconnect` dials the peer on startup; otherwise an oper runs
`/CONNECT peer.example.net`. Link connections use the thread-per-connection I/O
model (there are only a handful of them) — see [architecture](architecture.md).

## The netburst

When two servers link, they exchange a **burst** that synchronizes state:

- **Servers** — every server the peer knows, so the topology is complete.
- **Users** — each as a `UID` introduction carrying nick, ident, host, real name,
  modes, account, and cloak.
- **Channels** — each as an `FJOIN` carrying the member list with their status
  prefixes, plus the channel's modes, topic, and ban lists.

After the burst both sides have identical state and stay in sync by propagating
every subsequent change.

## Routing, collisions & netsplits

- **Multi-hop routing** — a message for a remote user is forwarded hop-by-hop
  toward the server that owns them; the ircd tracks which direction each SID lies.
- **Nick collisions** — if the same nick appears on both sides of a new link, the
  collision is resolved deterministically (by sign-on time / UID) so the network
  converges to one owner.
- **Netsplits** — when a link drops, every user and channel behind it is cleanly
  removed locally and re-introduced on reconnect via a fresh burst.

## Services & accounts

echoIRCd stays a **pure ircd**: it does not implement NickServ/ChanServ itself.
Instead it carries the *interface* a services package uses, and services run as a
linked server. That interface is:

### SASL

Client authentication is relayed to the configured services server:

```text
sasl_server = services.example.net
```

- **PLAIN** — the client's credentials are forwarded to services over the link.
- **EXTERNAL** — the client must be on TLS with a client certificate; its
  fingerprint (CertFP) is forwarded, so services can match it to an account with
  no password.

With `sasl_server` unset, SASL is disabled.

### Account state & gated modes

A logged-in user carries an **account** name (advertised via `account-tag` /
`extended-join` / WHOIS, and user mode `+r`). Modes and channel policies can be
gated on being logged in — e.g. channel `+R` (registered users only may join),
`+M` (only registered may speak), and the `g:<group>` / account-based extbans.

### The services command set

Services drive the network through the `SVS*` family and generic transports:

- `SVSNICK`, `SVSJOIN`, `SVSPART`, `SVSMODE` — act on a user's nick/membership/modes.
- `SVSLOGIN` / `SVSLOGOUT` — set or clear a user's account.
- `SVSHOLD`, `SVSTOPIC`, `SVSOPER`, `SVSCMODE` — hold a nick, set a topic, grant
  oper, set channel modes with service authority.
- `ENCAP` — an encapsulated command routed to a specific server.
- `METADATA` — attach arbitrary key/value data to users and channels.

### Optional ircd-side registration

Independently of a services package, the server can offer IRCv3
`draft/account-registration` directly: a client uses `REGISTER` / `VERIFY` to
create and confirm an account.

## Web gateways (WEBIRC)

A trusted web-based client gateway (the browser-to-IRC kind) can declare the real
client's host and IP so users don't all appear to come from the gateway:

```text
# webirc = <password> [gateway-name] [ip-mask]
webirc = WEBIRC_SECRET mygateway 203.0.113.9
```

The `ip-mask` restricts which source IP may use the password — always set it. The
gateway sends a `WEBIRC` line at connect with the password and the real client
details.

> For browser clients connecting *directly* (no gateway), use the native
> [WebSocket transport](configuration.md#transports) instead.
