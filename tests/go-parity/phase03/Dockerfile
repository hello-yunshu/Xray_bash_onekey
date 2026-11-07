# Phase 03 Bridge container systemd probe. The base digest is pinned so the
# evidence recorded in docs/go/PHASE_03_REPORT.md stays reproducible.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

# Ubuntu builds the stream core as a dynamic module, so libnginx-mod-stream is
# required for the relay fixture's stream block. nginx itself is 1.24 with
# --with-stream_ssl_module/--with-stream_ssl_preread_module.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps python3 \
        nginx libnginx-mod-stream openssl jq gettext bc util-linux \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/usr/lib/systemd/systemd"]
