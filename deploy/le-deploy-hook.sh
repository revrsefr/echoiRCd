#!/usr/bin/env bash
# Let's Encrypt deploy hook for echoIRCd.
#
# echoircd runs as an unprivileged user and can't read /etc/letsencrypt/live
# (privkey.pem is root-only). This copies the renewed cert+key into the location
# echoircd already reads (its tls/ dir), owned by that user, then restarts it.
#
# Runs in two ways:
#   * manually, to install the cert the first time:   sudo deploy/le-deploy-hook.sh
#   * automatically by certbot on renewal — symlink it into
#     /etc/letsencrypt/renewal-hooks/deploy/ so `certbot renew` invokes it.
# When certbot runs it, $RENEWED_LINEAGE names the cert that was renewed; we act
# only for ours (and always, when run by hand with no such variable set).
set -eu

DOMAIN=irc.devtronic.pro
SRC=/etc/letsencrypt/live/$DOMAIN
DST=/home/debian/irc/ircd/echoIRCd/tls
UNIT=echoircd-dev.service

# skip other certs when certbot fires this for a renewal that isn't ours
if [ -n "${RENEWED_LINEAGE:-}" ] && [ "$RENEWED_LINEAGE" != "$SRC" ]; then
    exit 0
fi

# only restart if the cert actually changed (so an unrelated renewal is a no-op)
changed=0
cmp -s "$SRC/fullchain.pem" "$DST/cert.pem" || changed=1

install -o debian -g debian -m 644 "$SRC/fullchain.pem" "$DST/cert.pem"
install -o debian -g debian -m 640 "$SRC/privkey.pem"   "$DST/key.pem"

if [ "$changed" = 1 ]; then
    systemctl restart "$UNIT"
    echo "echoircd: installed LE cert for $DOMAIN and restarted $UNIT"
else
    echo "echoircd: LE cert for $DOMAIN unchanged; nothing to do"
fi
