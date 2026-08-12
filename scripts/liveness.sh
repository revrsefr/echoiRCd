#!/usr/bin/env bash
# echoIRCd liveness probe: do a real NICK/USER register round-trip on the plaintext
# port and, if the daemon doesn't answer with a 001 welcome, restart it. Catches a
# hung core (process alive but not serving), which Restart=on-failure alone can't.
# Run by echoircd-liveness.timer.
set -u
PORT="${1:-6767}"

if python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    s.sendall(b"NICK livecheck\r\nUSER lc 0 * :liveness\r\n")
    data = b""
    end = time.time() + 6
    while time.time() < end:
        d = s.recv(4096)
        if not d:
            break
        data += d
        if b" 001 " in data:
            break
    try:
        s.sendall(b"QUIT :liveness\r\n")
    except OSError:
        pass
    s.close()
    sys.exit(0 if b" 001 " in data else 1)
except OSError:
    sys.exit(1)
PY
then
    exit 0
fi

echo "echoircd liveness: no 001 from 127.0.0.1:${PORT} within timeout — restarting echoircd-dev.service"
systemctl restart echoircd-dev.service
