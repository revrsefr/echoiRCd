#!/usr/bin/env bash
# echoIRCd kernel-layer flood mitigation — defense-in-depth on top of the ircd's own
# per-IP `accept_rate` limiter. Drops excess NEW connections to the IRC client ports
# (per source IP) in the kernel, before they ever reach the daemon.
#
# THIS BOX RUNS firewalld, so the rule is installed through firewalld's DIRECT interface
# (`firewall-cmd --direct`). firewalld then owns the rule — it won't be flushed on a
# `firewall-cmd --reload`, and `--permanent` persists it across reboot. (A raw
# `iptables -I INPUT ...` would be silently wiped the next time firewalld rebuilds its
# ruleset, which is why that approach is wrong here.)
#
# SAFE: it only DROPs the rate-limited *excess* to 6767/6770. It changes no zone,
# service, or default policy; ports 6767/6770 stay open as firewalld already has them.
# Loopback is exempt (the liveness probe + local tools). Idempotent and one-command
# removable.
#
#   Apply:   sudo deploy/firewalld-echoircd.sh add
#   Remove:  sudo deploy/firewalld-echoircd.sh del
#   Show:    sudo deploy/firewalld-echoircd.sh show
#
# Uses iptables `hashlimit` (per-source-IP). firewalld rich rules can't express this —
# their `limit` is a single global token bucket, not per-source — so a direct rule is
# the right tool. IPv4 only (the ircd binds 0.0.0.0); add an ipv6 rule if you ever bind ::.
set -u

PORTS="6767,6770"       # IRC client ports (plaintext + TLS); S2S 7700 intentionally left alone
RATE="30/second"        # sustained NEW connections/sec per source IP
BURST="60"              # instantaneous burst allowed per source IP
ACTION="${1:-}"

# the raw rule (added into INPUT at priority 0 = top): drop NEW conns to the IRC ports
# from any single source IP that exceeds the rate. `! -i lo` exempts loopback.
RULE=(ipv4 filter INPUT 0
    ! -i lo -p tcp -m multiport --dports "$PORTS"
    -m conntrack --ctstate NEW
    -m hashlimit --hashlimit-name ircrate --hashlimit-mode srcip
    --hashlimit-above "$RATE" --hashlimit-burst "$BURST"
    -j DROP)

add_one() { firewall-cmd "$@" --direct --add-rule "${RULE[@]}"; }
del_one() { firewall-cmd "$@" --direct --remove-rule "${RULE[@]}" >/dev/null 2>&1 || true; }

case "$ACTION" in
    add)
        del_one            # runtime: clear any prior copy (idempotent)
        del_one --permanent
        add_one            # runtime (takes effect now)
        add_one --permanent  # persists across reboot / reload
        echo "echoircd rate-limit added via firewalld direct rule: ports ${PORTS}, ${RATE} burst ${BURST} per source IP (runtime + permanent)"
        ;;
    del)
        del_one
        del_one --permanent
        echo "echoircd rate-limit removed (runtime + permanent)"
        ;;
    show)
        echo "== runtime direct rules =="; firewall-cmd --direct --get-all-rules
        echo "== permanent direct rules =="; firewall-cmd --permanent --direct --get-all-rules
        ;;
    *)
        echo "usage: $0 {add|del|show}" >&2
        exit 1
        ;;
esac
