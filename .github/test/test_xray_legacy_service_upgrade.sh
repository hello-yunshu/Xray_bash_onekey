#!/usr/bin/env bash
# Destructive to the test installation: disposable CI Linux runners only.
# Exercise the production installer/update helper and real systemd, rather
# than replacing systemctl or the installer with stubs.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
[[ $(id -u) == 0 ]] || exit 1
export _TEST_MODE=1
source "$ROOT/install.sh" >/dev/null 2>&1
unset _TEST_MODE
log_echo() { printf '%s\n' "$*"; }
gettext() { printf '%s' "$1"; }
read_version
judge_mode
for legacy in nobody root; do
    group=$(id -gn "$legacy")
    # Model a working older install, including a non-public config directory.
    sed -i -E "s/^User=.*/User=$legacy/; s/^Group=.*/Group=$group/" "$xray_systemd_file"
    xray_privilege_escalation
    systemctl daemon-reload
    systemctl restart xray
    sleep 2
    systemctl is-active --quiet xray
    before_sha=$(sha256sum "$xray_conf" | cut -d' ' -f1)
    xray_install_pinned_and_check "$xray_online_version"
    sleep 2
    health_check_xray_update "$xray_online_version"
    [[ $(sha256sum "$xray_conf" | cut -d' ' -f1) == "$before_sha" ]]
    user=$(systemctl show xray -p User --value)
    runuser -u "$user" -- test -r "$xray_default_conf"
    runuser -u "$user" -- test -w /var/log/xray
    echo "PASS: working legacy $legacy service -> pinned official installer -> healthy $user service; config unchanged"
done
