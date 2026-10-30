#!/usr/bin/env bash
# Run only in a disposable Linux host/container, as root, with real Xray.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ $(id -u) == 0 ]] || { echo 'root required'; exit 1; }
binary=${XRAY_TEST_BINARY:-/usr/local/bin/xray}
[[ -x "$binary" ]] || { echo 'real Xray binary required'; exit 1; }
id xray >/dev/null 2>&1 || useradd --system xray
fixture=$(mktemp -d)
pid=''
trap '[[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; rm -rf "$fixture"' EXIT
chmod 755 "$fixture"
export _TEST_MODE=1
source "$ROOT/install.sh" >/dev/null 2>&1
unset _TEST_MODE
log_echo() { :; }
gettext() { printf '%s' "$1"; }
idleleo_dir="$fixture/idleleo"
idleleo_conf_dir="$idleleo_dir/conf"
xray_conf_dir="$idleleo_conf_dir/xray"
xray_conf="$xray_conf_dir/config.json"
xray_default_conf="$fixture/default/config.json"
xray_systemd_file="$fixture/xray.service"
nginx_dir="$fixture/no-nginx"
xray_install_config_file="$idleleo_conf_dir/install_config.json"
ssl_chainpath="$idleleo_dir/cert"
xray_info_file="$idleleo_dir/info/client.txt"
printf '[Service]\nUser=xray\nGroup=xray\n' > "$xray_systemd_file"

for scenario in fresh-umask077 legacy-nobody legacy-root already-current; do
    mkdir -p "$xray_conf_dir" "${xray_default_conf%/*}"
    # Known disposable fixtures; never run these operations on a user's tree.
    chmod 700 "$idleleo_dir" "$idleleo_conf_dir" "$xray_conf_dir" "${xray_default_conf%/*}"
    printf '{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}\n' > "$xray_conf"
    chmod 600 "$xray_conf"
    case "$scenario" in
        legacy-nobody) chown nobody "$xray_conf" ;;
        already-current) chown xray "$xray_conf" ;;
        *) chown root "$xray_conf" ;;
    esac
    ln -sf "$xray_conf" "$xray_default_conf"
    if runuser -u xray -- test -r "$xray_default_conf"; then
        echo 'invalid fixture: inaccessible parent was readable'; exit 1
    fi
    harden_config_permissions
    xray_privilege_escalation
    runuser -u xray -- "$binary" run -test -config "$xray_default_conf" >/dev/null
    # Verify actual process startup as well as parse-only access.
    runuser -u xray -- "$binary" run -config "$xray_default_conf" >/dev/null 2>&1 &
    pid=$!
    sleep 1
    kill -0 "$pid"
    kill "$pid"
    wait "$pid" 2>/dev/null || true
    pid=''
    [[ $(stat -c %a "$xray_conf") == 600 ]]
    echo "PASS: $scenario -> service user reads default symlink and starts real Xray"
done

# A failed directory repair must abort permission preparation.
chmod() { return 1; }
if xray_privilege_escalation; then
    echo 'permission failure was ignored'; exit 1
fi
echo 'PASS: directory repair failure propagates'
