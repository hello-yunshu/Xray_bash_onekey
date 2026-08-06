#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'root required' >&2; exit 77; }
DESTDIR=${DESTDIR:-}
root() { printf '%s%s' "$DESTDIR" "$1"; }
purge=0
[[ ${1:-} == --purge ]] && purge=1
units=(rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer)
if [[ -z "$DESTDIR" ]]; then
    systemctl disable --now "${units[@]}" >/dev/null 2>&1 || true
fi
for unit in "${units[@]}"; do rm -f "$(root "/etc/systemd/system/$unit")"; done
rm -rf "$(root /opt/rill-xray-agent)" "$(root /run/rill-xray-agent)"
if ((purge)); then
    rm -rf \
      "$(root /etc/rill-xray-agent)" \
      "$(root /var/lib/rill-xray-agent-runtime)" \
      "$(root /var/lib/rill-xray-agent-root)" \
      "$(root /var/lib/rill-xray-agent-xray)"
fi
[[ -n "$DESTDIR" ]] || systemctl daemon-reload
echo 'Rill Xray Agent removed; Xray configuration was not modified'
