FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bc \
    curl \
    dbus \
    git \
    jq \
    lsof \
    python3 \
    qrencode \
    cron \
    gettext \
    socat \
    nmap \
    iputils-ping \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dev \
    iptables \
    iptables-persistent \
    procps \
    psmisc \
    ca-certificates \
    gnupg \
    unzip \
    tar \
    gzip \
    vim \
    netcat-openbsd \
    sysvinit-utils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -f nogroup && \
    id nobody >/dev/null 2>&1 || useradd -g nogroup -s /usr/sbin/nologin nobody

RUN mkdir -p /etc/idleleo/conf/xray \
    /etc/idleleo/conf/nginx \
    /etc/idleleo/cert \
    /etc/idleleo/info \
    /etc/idleleo/logs \
    /etc/idleleo/tmp \
    /usr/local/bin \
    /usr/local/etc/xray \
    /usr/local/nginx \
    /var/log/xray \
    /var/spool/cron/crontabs

COPY fake-systemctl /usr/local/bin/systemctl
RUN chmod +x /usr/local/bin/systemctl

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

WORKDIR /etc/idleleo

COPY . /etc/idleleo/

RUN ln -sf /etc/idleleo/install.sh /usr/bin/idleleo && \
    ln -sf /etc/idleleo/conf/xray/config.json /usr/local/etc/xray/config.json && \
    mkdir -p /root/.acme.sh && \
    chmod +x /etc/idleleo/install.sh /etc/idleleo/auto_update.sh /etc/idleleo/ssl_update.sh /etc/idleleo/fail2ban_manager.sh /etc/idleleo/file_manager.sh

RUN echo '* soft nofile 65536' >> /etc/security/limits.conf && \
    echo '* hard nofile 65536' >> /etc/security/limits.conf

EXPOSE 443 80

VOLUME ["/etc/idleleo/conf", "/etc/idleleo/cert", "/etc/idleleo/info", "/var/log/xray", "/root/.acme.sh"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["idleleo"]
