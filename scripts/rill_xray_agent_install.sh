#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'root required' >&2; exit 77; }
SOURCE=$(cd -- "$(dirname -- "$0")" && pwd)
DESTDIR=${DESTDIR:-}
root() { printf '%s%s' "$DESTDIR" "$1"; }

install -d -m 0750 \
  "$(root /etc/rill-xray-agent)" \
  "$(root /etc/rill-xray-agent/scripts)" \
  "$(root /var/lib/rill-xray-agent-runtime)" \
  "$(root /var/lib/rill-xray-agent-root/transactions)" \
  "$(root /var/lib/rill-xray-agent-xray/status)" \
  "$(root /var/lib/rill-xray-agent-xray/history)" \
  "$(root /run/rill-xray-agent)" \
  "$(root /opt/rill-xray-agent)" \
  "$(root /etc/systemd/system)"

for file in rill_xray_agent_manager.sh rill_xray_agent_observe.py rill_xray_agent_install.sh rill_xray_agent_verify.sh rill_xray_agent_uninstall.sh rill_xray_agent_bootstrap.sh; do
    [[ -f "$SOURCE/$file" ]] && install -m 0755 "$SOURCE/$file" "$(root /etc/rill-xray-agent/scripts/$file)"
done
cp -a "$SOURCE/../rill_payload/." "$(root /opt/rill-xray-agent/)"
find "$(root /opt/rill-xray-agent/bin)" -type f -exec chmod 0755 {} +
for unit in "$SOURCE"/../systemd/*; do
    install -m 0644 "$unit" "$(root "/etc/systemd/system/$(basename "$unit")")"
done
[[ -f "$(root /etc/rill-xray-agent/config.json)" ]] || install -m 0640 "$SOURCE/../rill_payload/config/default.json" "$(root /etc/rill-xray-agent/config.json)"

if [[ -n "$DESTDIR" ]]; then
    echo "staged Rill Xray Agent installed under $DESTDIR"
    exit 0
fi
getent group rill-xray-agent >/dev/null || groupadd --system rill-xray-agent
id rill-xray-agent >/dev/null 2>&1 || useradd --system --gid rill-xray-agent --home-dir /var/lib/rill-xray-agent-runtime --shell /usr/sbin/nologin rill-xray-agent
chown -R rill-xray-agent:rill-xray-agent /var/lib/rill-xray-agent-runtime /run/rill-xray-agent
chown -R root:rill-xray-agent /var/lib/rill-xray-agent-root
chmod 0750 /var/lib/rill-xray-agent-root /var/lib/rill-xray-agent-root/transactions
# DAC contract: the observation tree is root-writable / rill-xray-agent
# readable-and-traversable / NOT writable by the Runtime user. The setgid
# directory bit keeps every newly created member file in group
# rill-xray-agent; the root observer (User=root Group=rill-xray-agent
# UMask=0027) then writes 0640 root:rill-xray-agent, which the unprivileged
# Runtime can read but never modify.
for d in /var/lib/rill-xray-agent-xray \
         /var/lib/rill-xray-agent-xray/status \
         /var/lib/rill-xray-agent-xray/history; do
    chown root:rill-xray-agent "$d"
    chmod 2750 "$d"
done
systemctl daemon-reload
systemctl enable --now rill-xray-agent-runtime.service
source /etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh
rxa_apply_mode "$(rxa_get mode)"
# Fresh-install runtime verification: all state parties must be truly enabled,
# not merely config-matching. Any drift fails the install.
if ! rxa_mode_state_matches_target "$(rxa_get mode)"; then
    echo 'Rill Xray Agent: install verified state does not match target mode' >&2
    exit 1
fi
for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
    systemctl is-enabled --quiet "$unit" || { echo "unit not enabled: $unit" >&2; exit 1; }
    systemctl is-active --quiet "$unit" || { echo "unit not active: $unit" >&2; exit 1; }
done
if [[ "$(rxa_get routeAssistEnabled)" != false ]] || [[ "$(rxa_get boundedAutoAllowed)" != false ]]; then
    echo 'ERR Rill install: unsafe defaults overridden' >&2
    exit 1
fi
echo 'Rill Xray Agent installed; mode=observe-only; Route Assist remains OFF'
