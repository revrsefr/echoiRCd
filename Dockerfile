# echoIRCd container image.
#
# The release binary is COPYed in, so build it first, then build the image:
#   cargo build --release
#   docker build -t git.devtronic.pro/echo/echoircd:$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2) .
#
# Run it (plaintext 6667 out of the box; mount your own config for TLS/opers/links):
#   docker run -p 6667:6667 git.devtronic.pro/echo/echoircd
#   docker run -p 6697:6697 -v $PWD/echoircd.conf:/etc/echoircd/echoircd.conf \
#              -v $PWD/tls:/etc/echoircd/tls git.devtronic.pro/echo/echoircd
FROM debian:trixie-slim

LABEL org.opencontainers.image.source="https://git.devtronic.pro/echo/echoIRCd" \
      org.opencontainers.image.title="echoIRCd" \
      org.opencontainers.image.description="A from-scratch IRC daemon written in Rust." \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10000 -s /usr/sbin/nologin echoircd

COPY target/release/echoircd /usr/local/bin/echoircd
COPY echoircd.conf.example   /etc/echoircd/echoircd.conf.example
COPY docker/default.conf     /etc/echoircd/echoircd.conf

# 6667 plaintext · 6697 direct TLS · 7799 WebSocket (wss) · 7700 server-to-server
EXPOSE 6667 6697 7700 7799

USER echoircd
WORKDIR /etc/echoircd
ENTRYPOINT ["/usr/local/bin/echoircd"]
CMD ["/etc/echoircd/echoircd.conf"]
