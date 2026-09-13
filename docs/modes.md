# Channel & user modes

This is the full mode set echoIRCd advertises. The authoritative ISUPPORT string
is:

```text
PREFIX=(qaohv)~&@%+  CHANMODES=beIgXw,k,lfjFLHBJdK,ACDGMNOPQRSTUcimnpstuz
EXTBAN=,Gbcgjmnrsy
```

`CHANMODES` groups modes into four types: **A** = list modes (always take a mask),
**B** = always take a parameter, **C** = take a parameter only when set, **D** =
flags with no parameter.

## Channel status (prefix) modes

Granted to members; each has a name prefix shown before the nick.

| Mode | Prefix | Rank | Meaning |
|------|--------|------|---------|
| `+q` | `~` | owner | Channel owner — full control. |
| `+a` | `&` | admin | Protected/admin — like op, can't be kicked/deopped by ops. |
| `+o` | `@` | op | Channel operator. |
| `+h` | `%` | halfop | Half-operator — a reduced op. |
| `+v` | `+` | voice | May speak when the channel is `+m`. |

Network staff (IRC operators) can additionally carry a `!` prefix (mode `y`) via
[operprefix](operators.md), which ranks above owner.

## List modes (type A)

Take a mask and maintain a list; `MODE #chan +b` with no argument lists entries.

| Mode | Name | Meaning |
|------|------|---------|
| `+b` | ban | Ban a `nick!user@host` mask (accepts [extbans](#extbans)). |
| `+e` | ban exempt | A mask exempt from `+b`. |
| `+I` | invite exempt | A mask that may join a `+i` channel without an invite. |
| `+g` | filter | Block matching users from speaking (a channel-scoped mute list). |
| `+X` | exempt-chanops | Masks whose members bypass selected restrictions. |
| `+w` | auto-status | `+w <prefix>:<hostmask>` grants a status prefix on join, e.g. `+w o:*!*@trusted.host` (auto-op), `+w v:*!*@*.friend.net` (auto-voice). |

## Parameter modes

**Type B — always a parameter:**

| Mode | Meaning |
|------|---------|
| `+k <key>` | Channel key; must be supplied to join. |

**Type C — a parameter only when setting:**

| Mode | Meaning |
|------|---------|
| `+l <n>` | Member limit. |
| `+f [*]<lines>:<secs>` | Message flood: kick past `lines` messages in `secs`; a leading `*` also bans. |
| `+j <count>:<secs>` | Join flood throttle. |
| `+F <count>:<secs>` | Nick-change flood throttle. |
| `+L <#target>` | Redirect joiners here when the channel is full/keyed/invite-only. |
| `+H <lines>:<secs>` | Replay recent messages to joiners (in-channel history). |
| `+B <percent>` | Anti-caps: block messages that are more than `percent` uppercase. |
| `+J <secs>` | Block rejoin for `secs` after a kick. |
| `+d <secs>` | New joiners can't speak for `secs`. |
| `+K <n>` | Block a line repeated within a member's last `n` messages. |

## Flag modes (type D)

No parameter.

| Mode | Meaning | | Mode | Meaning |
|------|---------|-|------|---------|
| `+i` | invite-only | | `+S` | strip formatting/colour |
| `+m` | moderated (only `+ov` speak) | | `+R` | registered users only may join |
| `+n` | no external messages | | `+M` | only registered users may speak |
| `+p` | private (hidden from WHOIS) | | `+G` | censor configured bad words |
| `+s` | secret | | `+u` | auditorium (hide non-ops) |
| `+t` | only ops set the topic | | `+Q` | KICK disabled |
| `+z` | TLS-only join | | `+A` | any member may INVITE |
| `+O` | opers only may join | | `+P` | permanent (survives 0 members) |
| `+N` | no nick changes while joined | | `+U` | op-moderated (unprivileged msgs go to ops) |
| `+C` | block CTCP | | `+D` | delay-join (hide JOIN until they speak) |
| `+T` | block NOTICEs | | `+c` | reject formatting/colour |
| `+E` | end-to-end encrypted — every message must carry the `+E2E <ciphertext>` envelope; the server relays it verbatim and holds no key. Joining requires the `echoircd/e2e` client capability, and the mode can only be set when every member already has it | | | |

Channel modes can also be set or queried by long name with the `PROP` command
(e.g. `PROP #chan moderated=on`).

## User modes

| Mode | Meaning |
|------|---------|
| `+i` | invisible (hidden from WHO / global `WHOIS` channel list) |
| `+w` | receive `WALLOPS` |
| `+o` | IRC operator (set only via `OPER`) |
| `+x` | cloaked host (keyed masking; usually auto-set on connect) |
| `+r` | logged into an account (server-set; can't be self-applied) |
| `+z` | only accept private messages from TLS-connected users |
| `+B` | flagged as a bot |
| `+D` | deaf — ignore channel messages |
| `+I` | hide your channel list in WHOIS |
| `+H` | hide your oper status |
| `+R` | block private messages from users not logged into an account |
| `+g` | caller-id — only people you `ACCEPT` may message you |
| `+W` | be notified when someone WHOISes you |
| `+c` | block private messages from users with no common channel |
| `+h` | available for help (helpop; oper-settable) |
| `+s` | server-notice mask — see [snomasks](operators.md#snomasks) |

## Extbans

Extended bans extend any ban-style list (`+b`, `+e`, `+I`, `+g`, …) beyond plain
host masks. `EXTBAN=,Gbcgjmnrsy` — there is no prefix character; a ban simply
starts with the extban letter and a colon.

**Matching extbans** — match a user by something other than host, usable with any
list mode:

| Extban | Matches |
|--------|---------|
| `g:<name>` | members of a named [security group](configuration.md). |
| `y:<score>` | [reputation](configuration.md) score, e.g. `y:<100` (below 100), `y:>500`. |
| `r:<mask>` | real name (GECOS). |
| `j:<#chan>` | users who are also in `#chan`. |
| `s:<mask>` | the server a user is on. |
| `G:<cc>` | GeoIP country code, e.g. `G:CN,RU`. |
| `b:<#chan>` | anyone banned in `#chan` (shares a ban list between channels). |

**Acting extbans** — change *what* matched users can do rather than blocking them
outright (used with `+b`):

| Extban | Effect on matched users |
|--------|-------------------------|
| `m:<mask>` | muted — can't speak (but stay joined). |
| `c:<mask>` | can't send formatting/colour. |
| `n:<mask>` | can't change nick. |

Example — quarantine everyone from a bad network to read-only, and bounce a
spammer to another channel:

```text
/MODE #main +b m:*!*@*.spammer.net
/MODE #main +b *!*@*.badhost$#quarantine
```
