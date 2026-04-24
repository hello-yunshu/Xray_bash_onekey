FROM debian:bookworm-slim

ARG XRAY_VERSION=26.3.27
ARG NGINX_BUILD_VERSION=2026.04.14

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bc \
    ca-certificates \
    cron \
    curl \
    dbus \
    fail2ban \
    gettext \
    git \
    gnupg \
    gzip \
    iftop \
    iptables \
    iptables-persistent \
    jq \
    lsof \
    netcat-openbsd \
    nmap \
    openssl \
    procps \
    psmisc \
    python3 \
    qrencode \
    socat \
    sysvinit-utils \
    unzip \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -f nogroup && \
    id nobody >/dev/null 2>&1 || useradd -g nogroup -s /usr/sbin/nologin nobody

RUN temp_dir=$(mktemp -d) && cd "$temp_dir" && \
    nginx_filename="xray-nginx-custom-$(dpkg --print-architecture).tar.gz" && \
    curl -L -o "$nginx_filename" "https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${NGINX_BUILD_VERSION}/$nginx_filename" && \
    tar -xzf "$nginx_filename" && \
    mv ./nginx /usr/local/nginx && \
    cd / && rm -rf "$temp_dir"

RUN curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install -f --version v${XRAY_VERSION} && \
    rm -f /usr/local/etc/xray/config.json

COPY fake-systemctl /usr/local/bin/systemctl
RUN chmod +x /usr/local/bin/systemctl

WORKDIR /etc/idleleo

COPY . /etc/idleleo/

RUN ln -sf /etc/idleleo/install.sh /usr/bin/idleleo && \
    ln -sf /etc/idleleo/conf/xray/config.json /usr/local/etc/xray/config.json && \
    chmod +x /etc/idleleo/install.sh /etc/idleleo/auto_update.sh \
    /etc/idleleo/ssl_update.sh /etc/idleleo/fail2ban_manager.sh \
    /etc/idleleo/file_manager.sh && \
    mkdir -p /etc/idleleo/conf/xray /etc/idleleo/conf/nginx \
    /etc/idleleo/cert /etc/idleleo/info /etc/idleleo/logs \
    /etc/idleleo/tmp /var/log/xray /root/.acme.sh

RUN mkdir -p /etc/systemd/system && \
    printf '[Unit]\nDescription=Xray Service\n[Service]\nType=simple\nExecStart=/usr/local/bin/xray run -config /etc/idleleo/conf/xray/config.json\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/xray.service && \
    printf '[Unit]\nDescription=NGINX HTTP and reverse proxy server\n[Service]\nType=forking\nPIDFile=/usr/local/nginx/logs/nginx.pid\nExecStart=/usr/local/nginx/sbin/nginx\nExecReload=/usr/local/nginx/sbin/nginx -s reload\nExecStop=/bin/kill -s QUIT \\$MAINPID\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/nginx.service && \
    echo '* soft nofile 65536' >> /etc/security/limits.conf && \
    echo '* hard nofile 65536' >> /etc/security/limits.conf

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 443 80

VOLUME ["/etc/idleleo/conf", "/etc/idleleo/cert", "/etc/idleleo/info", "/var/log/xray", "/root/.acme.sh"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["idleleo"]
