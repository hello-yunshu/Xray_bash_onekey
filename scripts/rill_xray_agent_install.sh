#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '需要 root 权限' >&2; exit 77; }
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
  "$(root /etc/systemd/system)" \
  "$(root /var/spool/rill-xray-agent-apply)"

for file in rill_xray_agent_manager.sh rill_xray_agent_observe.py rill_xray_agent_install.sh rill_xray_agent_verify.sh rill_xray_agent_uninstall.sh rill_xray_agent_bootstrap.sh; do
    [[ -f "$SOURCE/$file" ]] && install -m 0755 "$SOURCE/$file" "$(root /etc/rill-xray-agent/scripts/$file)"
done
cp -a "$SOURCE/../rill_payload/." "$(root /opt/rill-xray-agent/)"
find "$(root /opt/rill-xray-agent/bin)" -type f -exec chmod 0755 {} +
# On upgrade the payload is copied with cp -a, which preserves the source
# mtime. A __pycache__ left by the previous install is then newer than the
# freshly copied source, so Python would keep running the OLD bytecode and the
# new payload would never actually take effect. Purge it so the deployed
# source is always recompiled from the installed version.
find "$(root /opt/rill-xray-agent)" -depth -type d -name __pycache__ -exec rm -rf {} +
for unit in "$SOURCE"/../systemd/*; do
    install -m 0644 "$unit" "$(root "/etc/systemd/system/$(basename "$unit")")"
done
[[ -f "$(root /etc/rill-xray-agent/config.json)" ]] || install -m 0640 "$SOURCE/../rill_payload/config/default.json" "$(root /etc/rill-xray-agent/config.json)"

if [[ -n "$DESTDIR" ]]; then
    echo "Rill Xray AI 运维助手已暂存安装到 $DESTDIR"
    exit 0
fi
getent group rill-xray-agent >/dev/null || groupadd --system rill-xray-agent
id rill-xray-agent >/dev/null 2>&1 || useradd --system --gid rill-xray-agent --home-dir /var/lib/rill-xray-agent-runtime --shell /usr/sbin/nologin rill-xray-agent
chown -R rill-xray-agent:rill-xray-agent /var/lib/rill-xray-agent-runtime /run/rill-xray-agent
chown -R root:rill-xray-agent /var/lib/rill-xray-agent-root
chmod 2750 /var/lib/rill-xray-agent-root
chmod 0750 /var/lib/rill-xray-agent-root/transactions
# Root-owned generation (§P0-7): a fresh install starts at generation 0. The
# file is 0640 root:rill-xray-agent so the unprivileged Runtime can read
# committed generations; only the root oneshot executor writes it.
if [[ ! -f "$(root /var/lib/rill-xray-agent-root/generation)" ]]; then
    printf '0\n' > "$(root /var/lib/rill-xray-agent-root/generation)"
    chown root:rill-xray-agent "$(root /var/lib/rill-xray-agent-root/generation)"
    chmod 0640 "$(root /var/lib/rill-xray-agent-root/generation)"
fi
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
# Apply chain (Route Assist / Bounded Auto), wired but LOCKED: the
# unprivileged Runtime may stage an ApplyRequest into the setgid spool; the
# root oneshot executor re-reads the CURRENT release manifest and never
# trusts the staged request. The manifest is locked (supported=true /
# released=false), so no route mutation is applied until a future release
# gate flips the manifest.
chown root:rill-xray-agent /var/spool/rill-xray-agent-apply
chmod 2770 /var/spool/rill-xray-agent-apply
chown root:rill-xray-agent /opt/rill-xray-agent/share/release-capabilities.json
chmod 0640 /opt/rill-xray-agent/share/release-capabilities.json
systemctl daemon-reload
systemctl enable --now rill-xray-agent-runtime.service
systemctl enable --now rill-xray-agent-apply.path
systemctl enable --now rill-xray-agent-auto-evaluate.path
# Upgrade path: enable --now never restarts an already-running unit, so a
# re-install over an existing installation would keep the OLD daemon (old
# payload) alive while the files on disk are already the new ones. Force a
# restart of every active Rill unit so the installed payload is the code
# that actually runs. Inactive units are left untouched (safe-disabled).
for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service \
            rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer \
            rill-xray-agent-apply.path rill-xray-agent-auto-evaluate.path; do
    if systemctl is-active --quiet "$unit"; then
        systemctl restart "$unit"
    fi
done
source /etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh
rxa_apply_mode "$(rxa_get mode)"
# Fresh-install runtime verification: all state parties must be truly enabled,
# not merely config-matching. Any drift fails the install.
if ! rxa_mode_state_matches_target "$(rxa_get mode)"; then
    echo 'Rill Xray AI 运维助手安装校验失败：实际状态与目标工作模式不一致' >&2
    exit 1
fi
for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer rill-xray-agent-apply.path rill-xray-agent-auto-evaluate.path; do
    systemctl is-enabled --quiet "$unit" || { echo "服务未启用: $unit" >&2; exit 1; }
    systemctl is-active --quiet "$unit" || { echo "服务未运行: $unit" >&2; exit 1; }
done
if [[ "$(rxa_get routeAssistEnabled)" != false ]] || [[ "$(rxa_get boundedAutoAllowed)" != false ]]; then
    echo 'Rill 安装失败：安全默认值被异常覆盖' >&2
    exit 1
fi
# Best-effort RillML prebuilt runtime install (§30/§61): the prebuilt native
# runtime is an enhancement, never a single point of failure for the core
# service. We resolve the signed stable index and activate a matching prebuilt;
# ANY failure (network down, index/signature/checksum/probe error, unsupported
# platform) leaves RillML Native unavailable and the agent on the Portable
# Python fallback. A RillML failure never changes the install exit code, and
# the core install result above is already final.
if [[ -x "$RILL_XRAY_AGENT_CLI" ]]; then
    if rxa_rillml install --probe lightweight >/dev/null 2>&1; then
        echo 'RillML 预编译运行时安装完成；RillML Native 已启用'
    else
        echo 'RillML 预编译运行时暂不可用；保持 Portable Python 回退'
    fi
else
    echo 'RillML 预编译运行时跳过（CLI 不可用）'
fi
echo 'Rill Xray AI 运维助手安装完成；AI 观察模式已启用；路由辅助保持关闭'
