# Disposable systemd image for the bash-vs-Go differential suite (P1).
#
# The base digest is the same Ubuntu 24.04 the P0/a2 baseline used, so the
# userspace stays identical to the already-verified A2 runs. Only suite
# dependencies are added on top; a2's own Dockerfile is left untouched.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive

# fail2ban is needed by OPS-19. The image has no sshd, so the distro's
# `[sshd] enabled = true` default cannot work: it makes fail2ban-server exit
# 255 ("Have not found any log file for sshd jail") and makes
# `fail2ban-client -t` reject every generated config. OPS-19 exercises the
# Nginx jails, so the sshd default is dropped for both sides alike.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates curl iproute2 procps \
        python3 python3-pip python3-pexpect expect jq \
        nftables iptables cron openssl gettext \
        fail2ban \
        bc git lsof qrencode iputils-ping nmap \
    && rm -f /etc/fail2ban/jail.d/defaults-debian.conf \
    && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3

CMD ["/usr/lib/systemd/systemd"]
