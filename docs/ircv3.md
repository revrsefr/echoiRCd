# IRCv3

echoIRCd implements a broad set of [IRCv3](https://ircv3.net) capabilities. A
client negotiates them with `CAP LS` / `CAP REQ`; `cap-notify` keeps the client
informed as they change. This page groups what's supported.

## Message tags & framing

| Capability | What it adds |
|------------|--------------|
| `message-tags` (+ `msgid`) | Arbitrary message tags, and a unique `msgid` on messages. |
| `server-time` | A `time` tag with the server's timestamp on each message. |
| `account-tag` | The sender's logged-in account as a tag. |
| `echo-message` | The server echoes your own `PRIVMSG`/`NOTICE` back to you. |
| `labeled-response` | Correlate a response batch to the command that caused it. |
| `batch` | Group related messages (history playback, netjoins, …). |
| `standard-replies` | Structured `FAIL` / `WARN` / `NOTE` replies. |
| `TAGMSG` | A tag-only message (e.g. typing / reactions) with no text body. |

## Membership & identity

| Capability | What it adds |
|------------|--------------|
| `extended-join` | Account and real name included in `JOIN`. |
| `account-notify` | Notified when a user logs in / out of an account. |
| `away-notify` | Notified when a user's away state changes. |
| `chghost` | Notified when a user's host/ident changes (instead of a rejoin). |
| `setname` | Change your real name in-session (`SETNAME`). |
| `multi-prefix` | See all of a member's status prefixes at once. |
| `userhost-in-names` | Full `nick!user@host` in `NAMES`. |
| `invite-notify` | Channel ops see invites to their channel. |
| `draft/pre-away` | Send `AWAY` during registration so away state is set before the first `JOIN`. |
| `no-implicit-names` | Suppress the automatic `NAMES` reply on `JOIN` (the client asks when it wants it). |
| `draft/channel-rename` | `RENAME` a channel in place, keeping membership. |

## Authentication

| Capability | What it adds |
|------------|--------------|
| `sasl` | `AUTHENTICATE` with **PLAIN** or **EXTERNAL** (client-cert / CertFP), relayed to the services server. See [linking](linking.md). |
| `draft/account-registration` | Create and confirm an account in-band with `REGISTER` / `VERIFY`. |

## History & messaging

| Capability | What it adds |
|------------|--------------|
| `draft/chathistory` | `CHATHISTORY` — fetch recent messages for a conversation. |
| `draft/message-redaction` | `REDACT` — delete/redact a prior message. |
| `draft/multiline` | Send one logical message spanning multiple lines. |
| `draft/read-marker` | `MARKREAD` — set/query the last-read point of a conversation. |
| `draft/relaymsg` | `RELAYMSG` — speak under a spoofed relay nick (for bridges). |

## Monitoring & notifications

`MONITOR` (+ `extended-monitor`), the legacy `WATCH` list, `SILENCE`, and
caller-id (`ACCEPT` + user mode `+g`) let clients track other users' presence and
control who may message them.

## Metadata & misc

| Capability / feature | What it adds |
|----------------------|--------------|
| `draft/metadata-2` | `METADATA` key/value data on users and channels. |
| `draft/extended-isupport` | Re-request the current ISUPPORT tokens on demand. |
| `draft/json-log` | Stream the server log to an oper as JSON. |
| `sts` | Strict Transport Security — tell a client to upgrade to TLS and pin that for a duration (opt-in via `sts_duration` / `sts_port` / `sts_preload`). |
| `EXTJWT` | A short-lived, server-signed HS256 token a client can present elsewhere. |
| network icon / profile link | Advertise a network icon and per-account profile URLs. |

## ISUPPORT

On registration the server advertises its limits and features via `RPL_ISUPPORT`
(005), including `PREFIX`, `CHANMODES`, `EXTBAN` (see [modes](modes.md)), `WHOX`,
`CHATHISTORY`, `MONITOR` / `WATCH` / `SILENCE` sizes, `NICKLEN` / `CHANNELLEN`,
`CASEMAPPING=ascii`, `UTF8ONLY`, and `NETWORK`.
