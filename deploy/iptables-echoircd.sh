#!/usr/bin/env bash
# echoIRCd kernel-layer flood mitigation — defense-in-depth on top of the ircd's own
# per-IP `accept_rate` limiter. Drops excess NEW connections to the IRC client ports
# (per source IP) in the kernel, before they ever reach the daemon.
#
# SAFE BY DESIGN: it only appends DROP rules for the rate-limited *excess* to ports
# 6767/6770. The INPUT policy stays ACCEPT, so SSH, established connections, Docker,
# and every other service are untouched. Loopback is exempt (the liveness probe + local
# tools live there). Easy to remove, and it never changes any default policy.
#
#   Apply:   sudo deploy/iptables-echoircd.sh add
#   Remove:  sudo deploy/iptables-echoircd.sh del
#   Show:    sudo iptables -L INPUT -n -v | grep -iE '6767|6770'
#
# NOT persistent across reboot on its own — persist with `netfilter-persistent save`
# (iptables-persistent) or re-run from a boot unit. Review interaction with Docker's
# own rules first if you persist it.
#
# nftables equivalent (if you ever install nft), per-source-IP:
#   tcp dport { 6767, 6770 } ct state new \
#     meter ircrate { ip saddr limit rate over 30/second burst 60 packets } drop
set -u

PORTS="6767,6770"       # IRC client ports (plaintext + TLS); S2S 7700 intentionally left alone
RATE="30/second"        # sustained NEW connections/sec per source IP
BURST="60"              # instantaneous burst allowed per source IP
ACTION="${1:-}"

# iptables for IPv4, plus ip6tables only when it's installed (this host is v4-only).
IPT_CMDS=(iptables)
command -v ip6tables >/dev/null 2>&1 && IPT_CMDS+=(ip6tables)

# Apply the same rule to each available table. $1 is the op: -I (insert) or -D (delete).
rule() {
    local op="$1" ipt
    for ipt in "${IPT_CMDS[@]}"; do
        "$ipt" "$op" INPUT ! -i lo -p tcp -m multiport --dports "$PORTS" \
            -m conntrack --ctstate NEW \
            -m hashlimit --hashlimit-name ircrate --hashlimit-mode srcip \
            --hashlimit-above "$RATE" --hashlimit-burst "$BURST" \
            -j DROP 2>/dev/null || true
    done
}

case "$ACTION" in
    add)
        rule -D   # remove any prior copy first, so re-running never stacks duplicates
        rule -I
        echo "echoircd rate-limit installed: ports ${PORTS}, ${RATE} burst ${BURST} per source IP (v4+v6)"
        ;;
    del)
        rule -D
        echo "echoircd rate-limit removed"
        ;;
    *)
        echo "usage: $0 {add|del}" >&2
        exit 1
        ;;
esac
