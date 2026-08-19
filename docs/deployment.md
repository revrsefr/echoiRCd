# Deployment

Running echoIRCd in production. The repo ships ready-to-use units and scripts in
[`deploy/`](../deploy).

## 1. Build a release binary

Always run the **release** build in production — a debug build is unoptimized and
far slower on the CPU-bound paths (TLS crypto, password hashing, cloaking, line
parsing):

```sh
cargo build --release
```

## 2. Pin the binary

Copy the release binary to a **stable path** and run *that*, not `target/`. This
decouples "what's running" from "what you're compiling" — a stray `cargo build`
can never change what a restart would launch:

```sh
mkdir -p bin
cp target/release/echoircd bin/echoircd
```

`bin/` is gitignored. **Deploying an update** is then: build release → copy over
`bin/echoircd` → restart the service.

## 3. Supervise it with systemd

[`deploy/echoircd-dev.service`](../deploy/echoircd-dev.service) runs the pinned
binary, restarts on failure, raises the file-descriptor limit, and starts on boot:

```ini
[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/echoIRCd
LimitNOFILE=200000
ExecStart=/path/to/echoIRCd/bin/echoircd /path/to/echoIRCd/echoircd.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Install it (adjust the paths / `User` first):

```sh
sudo cp deploy/echoircd-dev.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now echoircd-dev.service
```

`LimitNOFILE` is what lets the reactor pool reach tens of thousands of
connections — each connection is a file descriptor. `Restart=on-failure` means a
crash self-heals instead of leaving the network down.

## 4. Add a liveness probe

`Restart=on-failure` catches a *crash*, but not a *hang* (a process that's alive
but stopped answering). [`deploy/echoircd-liveness.timer`](../deploy/echoircd-liveness.timer)
runs [`scripts/liveness.sh`](../scripts/liveness.sh) every couple of minutes: it
does a real NICK/USER register round-trip on the plaintext port and restarts the
service if it doesn't get a welcome.

```sh
sudo cp deploy/echoircd-liveness.service deploy/echoircd-liveness.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now echoircd-liveness.timer
```

## 5. Harden the firewall

Add the kernel-layer connection-rate limit (see [anti-abuse](anti-abuse.md)):

```sh
sudo deploy/firewalld-echoircd.sh add
```

For volumetric (SYN/UDP) floods, rely on your upstream provider's scrubbing —
nothing on the host can absorb a saturating flood.

## Behind a reverse proxy / load balancer

If a TCP proxy (HAProxy, nginx stream) sits in front, enable the **PROXY protocol**
so the real client IP is used instead of the proxy's:

```text
proxy = 10.0.0.0/8      # trust the PROXY header from these sources (repeatable)
```

A connection from a trusted proxy must lead with a PROXY (v1 or v2) header. This
applies to the plaintext and TLS client listeners; for browser clients over
WebSocket, use `ws_proxyranges` with `X-Forwarded-For` instead.

## Log shipping & metrics

| Setting | Sends the notice/log stream to |
|---------|--------------------------------|
| `syslog = yes` (+ `syslog_target`) | the system logger (`/dev/log` or `host:port`) |
| `log_json = <path>` | a file, as JSON lines (easy to ingest) |
| `chanlog = #snotices` | an in-network channel staff can watch |

The core also surfaces its own health: `slow_command_ms` raises a notice when an
event runs long, and `watchdog_ms` logs if the core is stuck.

For a metrics pipeline, bind the OpenMetrics/Prometheus endpoint with
`metrics_bind = 127.0.0.1:9109` and scrape it (counters for commands / messages /
connects, gauges for users / channels / servers / links). For scripted control,
the JSON-RPC plane (`rpc` / `rpc_bind` / `rpc_token`) exposes admin operations over
HTTP. Bind both privately — on loopback or behind the reverse proxy, never on a
public interface.

## TLS certificates

Point `tls_cert` / `tls_key` at your PEM files (the same pair serves `bind_tls`
and `wss://`). After renewing a certificate, `REHASH` reloads it without dropping
the server. Client-certificate fingerprints are read automatically for SASL
EXTERNAL / CertFP.

## Updating checklist

1. `git pull` && `cargo build --release`
2. `cargo test` (the integration suite spawns the binary and exercises the real
   paths)
3. `cp target/release/echoircd bin/echoircd`
4. `sudo systemctl restart echoircd-dev.service`
5. Confirm: `systemctl is-active echoircd-dev.service`, then check a client
   connects on the TLS port.
