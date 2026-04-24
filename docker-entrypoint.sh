#!/bin/bash

export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

XRAY_BIN="/usr/local/bin/xray"
NGINX_BIN="/usr/local/nginx/sbin/nginx"
XRAY_CONF="/etc/idleleo/conf/xray/config.json"
NGINX_CONF="/usr/local/nginx/conf/nginx.conf"
XRAY_PID_FILE="/var/run/xray.pid"
NGINX_PID_FILE="/usr/local/nginx/logs/nginx.pid"

_start_cron() {
    if ! pgrep -f "cron" >/dev/null 2>&1; then
        cron
    fi
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

_stop_services() {
    echo "[entrypoint] Stopping services..."
    systemctl stop nginx 2>/dev/null
    systemctl stop xray 2>/dev/null
}

_watchdog() {
    while true; do
        if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
            if ! systemctl -q is-active xray 2>/dev/null; then
                echo "[watchdog] Xray is not running, restarting..."
                systemctl start xray
            fi
        fi

        if [[ -f "$NGINX_CONF" ]] && [[ -x "$NGINX_BIN" ]]; then
            if ! systemctl -q is-active nginx 2>/dev/null; then
                echo "[watchdog] Nginx is not running, restarting..."
                systemctl start nginx
            fi
        fi

        sleep 30
    done
}

trap '_stop_services; exit 0' SIGTERM SIGINT SIGQUIT

_start_cron

case "$1" in
    idleleo)
        if [[ -f "$XRAY_CONF" ]] && [[ -x "$XRAY_BIN" ]]; then
            echo "[entrypoint] Detected existing Xray configuration, starting services..."
            _start_services
            echo "[entrypoint] Services started. Launching management script..."
            echo "[entrypoint] Type 'exit' to return to daemon mode."
            bash /etc/idleleo/install.sh
            echo "[entrypoint] Management script exited. Entering daemon mode..."
            _watchdog
        else
            echo "[entrypoint] No existing configuration found. Launching install script..."
            bash /etc/idleleo/install.sh
            if [[ -f "$XRAY_CONF" ]]; then
                echo "[entrypoint] Installation complete. Starting services..."
                _start_services
                echo "[entrypoint] Services started. Entering daemon mode..."
                _watchdog
            else
                echo "[entrypoint] No configuration found. Entering daemon mode (services not started)..."
                _watchdog
            fi
        fi
        ;;
    start)
        _start_services
        echo "[entrypoint] Services started. Entering daemon mode..."
        _watchdog
        ;;
    shell|bash)
        _start_services
        echo "[entrypoint] Services started. Opening shell..."
        /bin/bash
        echo "[entrypoint] Shell exited. Entering daemon mode..."
        _watchdog
        ;;
    *)
        _start_services
        echo "[entrypoint] Services started. Executing: $*"
        exec "$@"
        ;;
esac
