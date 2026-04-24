#!/bin/bash
set -e

export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

XRAY_BIN="/usr/local/bin/xray"
NGINX_BIN="/usr/local/nginx/sbin/nginx"
XRAY_CONF="/etc/idleleo/conf/xray/config.json"
NGINX_CONF="/usr/local/nginx/conf/nginx.conf"

_start_cron() {
    pgrep -f "cron" >/dev/null 2>&1 || cron
}

_start_services() {
    if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
        echo "[entrypoint] Starting Xray..."
        systemctl start xray
    fi
    if [[ -f "$NGINX_CONF" ]] && [[ -x "$NGINX_BIN" ]]; then
        echo "[entrypoint] Starting Nginx..."
        systemctl start nginx
    fi
}

STOPPING=0

_stop_services() {
    if [[ "$STOPPING" -eq 1 ]]; then return; fi
    STOPPING=1
    echo "[entrypoint] Stopping services..."
    if [[ -f /usr/local/nginx/logs/nginx.pid ]]; then
        "$NGINX_BIN" -s stop 2>/dev/null || true
    fi
    pkill -f "$NGINX_BIN" 2>/dev/null || true
    if [[ -f /var/run/xray.pid ]]; then
        kill "$(cat /var/run/xray.pid 2>/dev/null)" 2>/dev/null || true
    fi
    pkill -f "$XRAY_BIN" 2>/dev/null || true
    echo "[entrypoint] Services stopped."
}

_watchdog() {
    while [[ "$STOPPING" -eq 0 ]]; do
        if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
            if ! systemctl -q is-active xray 2>/dev/null; then
                echo "[watchdog] Xray not running, restarting..."
                systemctl start xray
            fi
        fi
        if [[ -f "$NGINX_CONF" ]] && [[ -x "$NGINX_BIN" ]]; then
            if ! systemctl -q is-active nginx 2>/dev/null; then
                echo "[watchdog] Nginx not running, restarting..."
                systemctl start nginx
            fi
        fi
        sleep 30
    done
}

trap '_stop_services; exit 0' SIGTERM SIGINT SIGQUIT

_start_cron

case "${1:-idleleo}" in
    idleleo)
        if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
            _start_services
            echo "[entrypoint] Services started. Launching management script..."
            echo "[entrypoint] Type 'exit' to return to daemon mode."
            bash /etc/idleleo/install.sh
            echo "[entrypoint] Entering daemon mode..."
            _watchdog
        else
            echo "[entrypoint] No config found. Launching install script..."
            bash /etc/idleleo/install.sh
            if [[ -f "$XRAY_CONF" ]]; then
                _start_services
                echo "[entrypoint] Installation complete. Entering daemon mode..."
            else
                echo "[entrypoint] No config. Entering daemon mode..."
            fi
            _watchdog
        fi
        ;;
    start)
        _start_services
        echo "[entrypoint] Services started. Daemon mode."
        _watchdog
        ;;
    shell|bash)
        _start_services
        echo "[entrypoint] Services started. Opening shell..."
        /bin/bash
        echo "[entrypoint] Entering daemon mode..."
        _watchdog
        ;;
    *)
        _start_services
        exec "$@"
        ;;
esac
