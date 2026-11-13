# Disposable systemd image for the bash-vs-Go differential suite (P1).
#
# The base digest is the same Ubuntu 24.04 the P0/a2 baseline used, so the
# userspace stays identical to the already-verified A2 runs. Only suite
# dependencies are added on top; a2's own Dockerfile is left untouched.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps \
        python3 python3-pip python3-pexpect expect jq \
        nftables iptables cron openssl gettext \
        bc git lsof qrencode iputils-ping nmap \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/usr/lib/systemd/systemd"]
