set -u
XRAY_BIN="/work/evidence/f24-work/container-root/usr/local/bin/xray"
NGINX_BIN="/work/evidence/f24-work/container-root/usr/local/nginx/sbin/nginx"
XRAY_CONF="/work/evidence/f24-work/container-root/etc/idleleo/conf/xray/config.json"
NGINX_CONF="/work/evidence/f24-work/container-root/usr/local/nginx/conf/nginx.conf"
GO_IDLELEO=/nonexistent
STOPPING=0
systemctl() { echo "$*" >> "/work/evidence/f24-work/systemctl-baseline.log"; }
command() { return 1; }
_f2b_configured() { return 1; }
_go_container() { return 1; }
_start_services() {
    if _go_container; then
        echo "[entrypoint] Starting managed services (Go container mode)..."
        _go_up
        return
    fi
    if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
        echo "[entrypoint] Starting Xray..."
        systemctl start xray
    fi
    if [[ -f "$NGINX_CONF" ]] && [[ -x "$NGINX_BIN" ]]; then
        echo "[entrypoint] Starting Nginx..."
        systemctl start nginx
    fi
    if command -v fail2ban-client >/dev/null 2>&1 && _f2b_configured; then
        echo "[entrypoint] Starting Fail2ban..."
        systemctl start fail2ban
    fi
}
_stop_services() {
    if [[ "$STOPPING" -eq 1 ]]; then return; fi
    STOPPING=1
    echo "[entrypoint] Stopping services..."
    if _go_container; then
        _go_down 2>/dev/null || true
        echo "[entrypoint] Services stopped."
        return
    fi
    if command -v fail2ban-client >/dev/null 2>&1 && _f2b_configured; then
        systemctl stop fail2ban 2>/dev/null || true
    fi
    if [[ -f "$NGINX_CONF" ]] && [[ -x "$NGINX_BIN" ]]; then
        systemctl stop nginx 2>/dev/null || true
    fi
    if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
        systemctl stop xray 2>/dev/null || true
    fi
    echo "[entrypoint] Services stopped."
}
_start_services
_stop_services
