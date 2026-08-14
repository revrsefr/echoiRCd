#!/usr/bin/env bash
# echoIRCd liveness probe: prove the acceptor + core are alive and responsive with a
# pre-registration PING/PONG round-trip, and restart the daemon if it doesn't answer.
# Catches a hung core (process alive but not serving), which Restart=on-failure can't.
#
# It deliberately does NOT register (no NICK/USER), so it never triggers connect/quit
# server-notices — the probe is invisible in the oper snotice stream. Run by
# echoircd-liveness.timer.
set -u
PORT="${1:-6767}"

if python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    # a pre-registration PING is answered with a PONG, without creating a client session
    s.sendall(b"PING :liveness\r\n")
    data = b""
    end = time.time() + 6
    while time.time() < end:
        d = s.recv(4096)
        if not d:
            break
        data += d
        if b"PONG" in data:
            break
    s.close()
    sys.exit(0 if b"PONG" in data else 1)
except OSError:
    sys.exit(1)
PY
then
    exit 0
fi

echo "echoircd liveness: no PONG from 127.0.0.1:${PORT} within timeout — restarting echoircd-dev.service"
systemctl restart echoircd-dev.service
