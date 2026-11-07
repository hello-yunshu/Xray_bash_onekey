# Phase 02 container systemd probe. Base digest is pinned so the evidence
# recorded in docs/go/PHASE_02_REPORT.md stays reproducible.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps python3 \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/usr/lib/systemd/systemd"]
