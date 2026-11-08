# Disposable systemd image for the A2 real-Bash-install capture.
# Base digest matches phase02 so the Ubuntu userspace is identical.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps \
        python3 expect jq \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/usr/lib/systemd/systemd"]
