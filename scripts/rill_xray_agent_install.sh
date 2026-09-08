#!/usr/bin/env bash
set -euo pipefail
SOURCE=$(cd -- "$(dirname -- "$0")" && pwd)
DESTDIR=${DESTDIR:-}
root() { printf '%s%s' "$DESTDIR" "$1"; }
[[ ${EUID:-$(id -u)} -eq 0 || -n "$DESTDIR" ]] || { echo '需要 root 权限' >&2; exit 77; }

UPGRADE=0
case "${1:-}" in
    --upgrade) UPGRADE=1 ;;
    '') ;;
    *) echo "用法: $0 [--upgrade]" >&2; exit 64 ;;
esac

# An upgrade is only valid for a real deployment. Residual config/state is
# deliberately insufficient: standalone uninstall may retain those paths.
if ((UPGRADE)); then
    if [[ ! -x "$(root /opt/rill-xray-agent/bin/rill-xray-agent)" ]]; then
        echo '拒绝升级：未检测到已安装的 Rill 执行组件' >&2
        exit 65
    fi
fi

SAVED_MODE=""
if ((UPGRADE)); then
    # Read the operator preference from the durable config before replacing
    # any payload. The old manager is not a compatibility boundary: it may be
    # missing, too old, or otherwise broken while the config remains valid.
    config_file="$(root /etc/rill-xray-agent/config.json)"
    if [[ ! -r "$config_file" ]]; then
        echo '拒绝升级：Rill config.json 不存在或不可读' >&2
        exit 65
    fi
    if ! SAVED_MODE=$(python3 - "$config_file" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding='utf-8') as stream:
        mode = json.load(stream).get('mode')
except (OSError, ValueError, TypeError, AttributeError):
    raise SystemExit(1)

if mode not in {'normal', 'observe-only', 'safe-disabled'}:
    raise SystemExit(1)
print(mode)
PY
    ); then
        echo '拒绝升级：config.json 无效或工作模式非法' >&2
        exit 65
    fi
fi

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

if ((UPGRADE)); then
    # Only remove directories explicitly owned by the canonical payload. User
    # config, runtime state, audit/timeline data and transaction state live
    # outside this list and must survive an upgrade.
    for owned in PROVENANCE bin config python share systemd; do
        rm -rf -- "$(root "/opt/rill-xray-agent/${owned}")"
    done
fi

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
if ((UPGRADE)); then
    # Restart only units that were already active. The new manager below owns
    # the final mode transition; this prevents safe-disabled from being
    # silently re-enabled by an upgrade.
    for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service \
                rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer \
                rill-xray-agent-apply.path rill-xray-agent-auto-evaluate.path; do
        if systemctl is-active --quiet "$unit"; then
            systemctl restart "$unit"
        fi
    done
else
    systemctl enable --now rill-xray-agent-runtime.service
    systemctl enable --now rill-xray-agent-apply.path
    systemctl enable --now rill-xray-agent-auto-evaluate.path
fi
# shellcheck disable=SC1090
source "$(root /etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh)"
if ((UPGRADE)); then
    # An upgrade is a security boundary. Always revoke the root-authoritative
    # temporary auto-execution authorization, even when the saved mode already
    # matches and rxa_apply_mode would otherwise return early.
    if ! rxa_apply_auto_revoke; then
        echo 'Rill 升级失败：无法撤销 root 自动执行授权' >&2
        exit 1
    fi
    if ! rxa_apply_mode "$SAVED_MODE"; then
        echo "Rill 升级失败：无法恢复工作模式 ${SAVED_MODE}" >&2
        exit 1
    fi
else
    rxa_apply_mode "$(rxa_get mode)"
fi
# Mode-aware verification is authoritative for both paths. A fresh install
# additionally requires its complete active unit set below.
if ! rxa_mode_state_matches_target "$(rxa_get mode)"; then
    echo 'Rill Xray AI 运维助手安装校验失败：实际状态与目标工作模式不一致' >&2
    exit 1
fi
if (( ! UPGRADE )); then
    for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer rill-xray-agent-apply.path rill-xray-agent-auto-evaluate.path; do
        systemctl is-enabled --quiet "$unit" || { echo "服务未启用: $unit" >&2; exit 1; }
        systemctl is-active --quiet "$unit" || { echo "服务未运行: $unit" >&2; exit 1; }
    done
fi
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
if (( ! UPGRADE )) && [[ -x "$RILL_XRAY_AGENT_CLI" ]]; then
    if rxa_rillml install --probe lightweight >/dev/null 2>&1; then
        echo 'RillML 预编译运行时安装完成；RillML Native 已启用'
    else
        echo 'RillML 预编译运行时暂不可用；保持 Portable Python 回退'
    fi
else
    echo 'RillML 预编译运行时跳过（CLI 不可用）'
fi
if ((UPGRADE)); then
    echo "Rill Xray AI 运维助手升级完成；工作模式保持 ${SAVED_MODE}；RillML 未变更"
else
    echo 'Rill Xray AI 运维助手安装完成；AI 观察模式已启用；路由辅助保持关闭'
fi
