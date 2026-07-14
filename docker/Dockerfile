FROM debian:bookworm-slim

ARG XRAY_VERSION
ARG NGINX_BUILD_VERSION

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
    iptables \
    iptables-persistent \
    jq \
    lsof \
    netcat-openbsd \
    openssl \
    procps \
    psmisc \
    python3 \
    qrencode \
    socat \
    sysvinit-utils \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -f nogroup && \
    id nobody >/dev/null 2>&1 || useradd -g nogroup -s /usr/sbin/nologin nobody

RUN VERSIONS_JSON=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 \
    https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json) && \
    XRAY_VERSION=${XRAY_VERSION:-$(echo "$VERSIONS_JSON" | jq -r '.xray_online_version')} && \
    NGINX_BUILD_VERSION=${NGINX_BUILD_VERSION:-$(echo "$VERSIONS_JSON" | jq -r '.nginx_build_online_version')} && \
    echo "XRAY_VERSION=${XRAY_VERSION}" >> /etc/idleleo_build_versions && \
    echo "NGINX_BUILD_VERSION=${NGINX_BUILD_VERSION}" >> /etc/idleleo_build_versions

RUN . /etc/idleleo_build_versions && \
    temp_dir=$(mktemp -d) && cd "$temp_dir" && \
    base_url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${NGINX_BUILD_VERSION}" && \
    case "$(dpkg --print-architecture)" in \
      amd64) nginx_arch="x86"; nginx_filename="xray-nginx-custom-x86.tar.gz" ;; \
      arm64) nginx_arch="arm"; nginx_filename="xray-nginx-custom-arm.tar.gz" ;; \
      *) echo "Unsupported architecture: $(dpkg --print-architecture)" && exit 1 ;; \
    esac && \
    if curl -fL -o release-manifest.json "$base_url/release-manifest.json"; then \
      manifest_filename="$(jq -r --arg arch "$nginx_arch" '.assets[]? | select(.arch == $arch) | .filename // empty' release-manifest.json | head -n 1)" && \
      manifest_sha256="$(jq -r --arg arch "$nginx_arch" '.assets[]? | select(.arch == $arch) | .sha256 // empty' release-manifest.json | head -n 1)" && \
      if [ -n "$manifest_filename" ]; then nginx_filename="$manifest_filename"; fi; \
    fi && \
    curl -fL -o "$nginx_filename" "$base_url/$nginx_filename" && \
    if [ -n "$manifest_sha256" ] && [ "$manifest_sha256" != "null" ]; then echo "$manifest_sha256  $nginx_filename" | sha256sum -c -; fi && \
    tar -xzf "$nginx_filename" && \
    mv ./nginx /usr/local/nginx && \
    cd / && rm -rf "$temp_dir"

COPY docker/fake-systemctl /usr/local/bin/systemctl
RUN chmod +x /usr/local/bin/systemctl

# BuildKit 的 RUN 环境没有运行时容器自带的 /.dockerenv；提前创建标记并提供
# fake-systemctl，让 Xray 官方安装器按其 Docker 分支安装服务文件。
RUN touch /.dockerenv && \
    . /etc/idleleo_build_versions && \
    curl -fL -o /tmp/xray-install-release.sh https://github.com/XTLS/Xray-install/raw/main/install-release.sh && \
    bash /tmp/xray-install-release.sh install -f --version v${XRAY_VERSION} && \
    rm -f /tmp/xray-install-release.sh /usr/local/etc/xray/config.json

WORKDIR /etc/idleleo

COPY install.sh /etc/idleleo/install.sh
COPY scripts/auto_update.sh /etc/idleleo/scripts/auto_update.sh
COPY scripts/fail2ban_manager.sh /etc/idleleo/scripts/fail2ban_manager.sh
COPY scripts/file_manager.sh /etc/idleleo/scripts/file_manager.sh
COPY scripts/traffic_blocker.sh /etc/idleleo/scripts/traffic_blocker.sh
COPY scripts/ssl_update.sh /etc/idleleo/scripts/ssl_update.sh
COPY scripts/geo_update.sh /etc/idleleo/scripts/geo_update.sh
COPY i18n/languages/ /etc/idleleo/languages/

RUN ln -sf /etc/idleleo/install.sh /usr/bin/idleleo && \
    ln -sf /etc/idleleo/conf/xray/config.json /usr/local/etc/xray/config.json && \
    ln -sf /etc/idleleo/share/xray /usr/local/share/xray && \
    chmod +x /etc/idleleo/install.sh /etc/idleleo/scripts/auto_update.sh \
    /etc/idleleo/scripts/fail2ban_manager.sh \
    /etc/idleleo/scripts/file_manager.sh /etc/idleleo/scripts/traffic_blocker.sh \
    /etc/idleleo/scripts/ssl_update.sh /etc/idleleo/scripts/geo_update.sh && \
    mkdir -p /etc/idleleo/conf/xray /etc/idleleo/conf/nginx \
    /etc/idleleo/cert /etc/idleleo/info /etc/idleleo/logs \
    /etc/idleleo/tmp /etc/idleleo/share/xray /etc/idleleo/scripts \
    /var/log/xray /root/.acme.sh

RUN mkdir -p /etc/systemd/system && \
    printf '[Unit]\nDescription=Xray Service\n[Service]\nType=simple\nExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/xray.service && \
    printf '[Unit]\nDescription=NGINX HTTP and reverse proxy server\n[Service]\nType=forking\nPIDFile=/usr/local/nginx/logs/nginx.pid\nExecStart=/usr/local/nginx/sbin/nginx\nExecReload=/usr/local/nginx/sbin/nginx -s reload\nExecStop=/bin/kill -s QUIT \\$MAINPID\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/nginx.service && \
    echo '* soft nofile 65536' >> /etc/security/limits.conf && \
    echo '* hard nofile 65536' >> /etc/security/limits.conf

COPY docker/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test ! -f /etc/idleleo/conf/xray/config.json || pgrep -f "/usr/local/bin/xray" > /dev/null 2>&1 || exit 1

EXPOSE 443 80

VOLUME ["/etc/idleleo/conf", "/etc/idleleo/cert", "/etc/idleleo/info", "/var/log/xray", "/root/.acme.sh"]

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["idleleo"]
