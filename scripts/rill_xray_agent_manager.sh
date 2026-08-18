#!/usr/bin/env bash
set -o pipefail

RILL_XRAY_AGENT_HOME=${RILL_XRAY_AGENT_HOME:-/etc/rill-xray-agent}
RILL_XRAY_AGENT_CONFIG=${RILL_XRAY_AGENT_CONFIG:-${RILL_XRAY_AGENT_HOME}/config.json}
RILL_XRAY_AGENT_STATUS=${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}
RILL_XRAY_AGENT_CLI=${RILL_XRAY_AGENT_CLI:-/opt/rill-xray-agent/bin/rill-xray-agent}
# P0-8: root-authoritative execution-policy helper. The Xray manager (running
# as root) invokes this for EVERY authority-relevant transition: mode change,
# routeStage change, auto confirm/revoke, safe-disable, fuse acknowledge and
# policy reset. The helper bumps executionEpoch on each transition so queued
# ApplyRequests become stale; the Runtime re-reads the safe projection.
RILL_XRAY_AGENT_ROOT_POLICY_HELPER=${RILL_XRAY_AGENT_ROOT_POLICY_HELPER:-/opt/rill-xray-agent/bin/rill-xray-agent-root-policy}
RILL_XRAY_AGENT_HEADER_STATE='AI 判断: 未安装'
RILL_XRAY_AGENT_HEADER_MODE='工作模式: 不可用'
RILL_XRAY_AGENT_HEADER_RUNTIME='服务: 未运行'
RILL_XRAY_AGENT_HEADER_ROUTE='路由辅助: 关闭'
RILL_XRAY_AGENT_HEADER_AUTO='自动修改: 暂未开放'
export RILL_XRAY_AGENT_HEADER_STATE RILL_XRAY_AGENT_HEADER_MODE
export RILL_XRAY_AGENT_HEADER_RUNTIME RILL_XRAY_AGENT_HEADER_ROUTE
export RILL_XRAY_AGENT_HEADER_AUTO
# RillML prebuilt native runtime: ROOT-owned lifecycle tree (staging/current/
# rollback). The manager (root) operates it via the CLI root-only `rillml`
# subcommand; the Runtime only reflects the verified installed tree through
# the read-only rillmlStatus IPC surface (never downloads / mutates).
RILL_XRAY_AGENT_RILLML_ROOT=${RILL_XRAY_AGENT_RILLML_ROOT:-/var/lib/rill-xray-agent-rillml}
RILL_XRAY_AGENT_HEADER_RILLML='RillML 运行时: 未安装'
export RILL_XRAY_AGENT_RILLML_ROOT RILL_XRAY_AGENT_HEADER_RILLML

rxa_systemctl() {
    [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} == 1 ]] && return 0
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground --kill-after=2s 15s systemctl "$@"
    else
        systemctl "$@"
    fi
}

rxa_config_init() {
    install -d -m 0750 "$(dirname "$RILL_XRAY_AGENT_CONFIG")"
    [[ -f "$RILL_XRAY_AGENT_CONFIG" ]] || printf '%s\n' \
      '{"schemaVersion":1,"mode":"observe-only","sentinelEnabled":true,"routeStage":"observe","routeAssistEnabled":false,"boundedAutoAllowed":false,"localOnly":true,"uploadEnabled":false,"userLevelStatistics":false}' \
      > "$RILL_XRAY_AGENT_CONFIG"
}

rxa_get() {
    python3 - "$RILL_XRAY_AGENT_CONFIG" "$1" <<'PY'
import json,sys
value=json.load(open(sys.argv[1])).get(sys.argv[2],'')
if isinstance(value,bool):
    print('true' if value else 'false')
else:
    print(value)
PY
}

rxa_set() {
    python3 - "$RILL_XRAY_AGENT_CONFIG" "$1" "$2" <<'PY'
import json,os,sys,tempfile
path,key,value=sys.argv[1:]
data=json.load(open(path))
data[key]={'true':True,'false':False}.get(value,value)
fd,tmp=tempfile.mkstemp(prefix='.config.',dir=os.path.dirname(path))
with os.fdopen(fd,'w') as stream:
    json.dump(data,stream,sort_keys=True,separators=(',',':'))
    stream.write('\n');stream.flush();os.fsync(stream.fileno())
os.chmod(tmp,0o640);os.replace(tmp,path)
PY
}

rxa_runtime() {
    # One Runtime config query path. The CLI defaults to the RUNTIME socket
    # (which stays up in every mode); --socket is available for overrides.
    "$RILL_XRAY_AGENT_CLI" --json "$@"
}

# ---- RillML native runtime lifecycle (root-only, §P0-16) ----------------
# The manager is the ROOT operator entrypoint for the RillML prebuilt runtime.
# Lifecycle operations (install/upgrade/reinstall/rollback) directly operate
# the ROOT-owned tree via the CLI's root-only `rillml` subcommand and NEVER go
# through the Runtime IPC (the unprivileged Runtime is read-only for RillML).
# The read-only status surface (rillmlStatus) IS available over IPC and is what
# the header / status display uses.

rxa_rillml() {
    # Root-only RillML lifecycle via the single authoritative CLI. The CLI
    # fails closed with rootRequired when not running as euid 0.
    "$RILL_XRAY_AGENT_CLI" --json --rillml-root "$RILL_XRAY_AGENT_RILLML_ROOT" rillml "$@"
}

rxa_rillml_native_status() {
    # Read-only native-runtime status over the Runtime IPC (unprivileged).
    # Emits the nativeRuntime surface JSON on stdout; fails closed (1) when
    # the Runtime is down or the IPC does not answer.
    rxa_runtime rillml-status
}

rxa_rillml_state_label() {
    case "${1:-}" in
        active) gettext "已启用" ;;
        unavailable) gettext "未安装" ;;
        *) gettext "不可用" ;;
    esac
}

rxa_rillml_status_display() {
    # Root view: detailed lifecycle status straight from the authoritative
    # tree (current / rollback / platform). Read-only; requires root.
    local out
    out=$(rxa_rillml status 2>/dev/null) || {
        printf '%s\n' "$(gettext "RillML 运行时状态读取失败（需要 root 权限）")"
        return 1
    }
    printf '%s' "${out}" | python3 - <<'PY'
import json,sys
try:
    d=json.load(sys.stdin); d=d.get('result') or d
except Exception:
    print('RillML 运行时状态读取失败'); sys.exit(0)
cur=d.get('current') or {}
rb=d.get('rollback') or {}
plat=d.get('platform') or {}
if d.get('supported'):
    print('RillML 运行时: %s' % ('已启用' if d.get('available') else '未安装'))
    print('  目标平台: %s/%s/%s' % (plat.get('os','?'),plat.get('arch','?'),plat.get('libc','?')))
    print('  已激活版本: %s' % (cur.get('version') or '-'))
    print('  回滚可用: %s' % (rb.get('version') or '-'))
else:
    print('RillML 运行时: 不支持 (%s)' % (d.get('unavailableReason') or '?'))
PY
}

rxa_rillml_install() {
    local answer out
    printf '%s\n' "$(gettext "将下载并安装 RillML 预编译运行时（需联网获取 signed stable index）。")"
    printf '%s' "$(gettext "确认安装吗？ [y/N]: ")"
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) ;;
        *) printf '%s\n' "$(gettext "已取消。")"; return 0 ;;
    esac
    out=$(rxa_rillml install --probe lightweight 2>&1) || { printf '%s\n' "${out}"; printf '%s\n' "$(gettext "RillML 运行时安装失败。")"; return 1; }
    printf '%s\n' "${out}"
}

rxa_rillml_upgrade() {
    local answer out
    printf '%s\n' "$(gettext "将检查并升级到可用的 RillML 预编译运行时（严格拒绝降级）。")"
    printf '%s' "$(gettext "确认升级吗？ [y/N]: ")"
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) ;;
        *) printf '%s\n' "$(gettext "已取消。")"; return 0 ;;
    esac
    out=$(rxa_rillml upgrade --probe lightweight 2>&1) || { printf '%s\n' "${out}"; printf '%s\n' "$(gettext "RillML 运行时升级失败。")"; return 1; }
    printf '%s\n' "${out}"
}

rxa_rillml_reinstall() {
    local answer out
    printf '%s\n' "$(gettext "将重新安装当前版本的 RillML 预编译运行时。")"
    printf '%s' "$(gettext "确认重新安装吗？ [y/N]: ")"
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) ;;
        *) printf '%s\n' "$(gettext "已取消。")"; return 0 ;;
    esac
    out=$(rxa_rillml reinstall --probe lightweight 2>&1) || { printf '%s\n' "${out}"; printf '%s\n' "$(gettext "RillML 运行时重新安装失败。")"; return 1; }
    printf '%s\n' "${out}"
}

rxa_rillml_rollback() {
    local answer out
    printf '%s\n' "$(gettext "将回滚到上一个已验证的 RillML 运行时（无可用时失败）。")"
    printf '%s' "$(gettext "确认回滚吗？ [y/N]: ")"
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) ;;
        *) printf '%s\n' "$(gettext "已取消。")"; return 0 ;;
    esac
    out=$(rxa_rillml rollback 2>&1) || { printf '%s\n' "${out}"; printf '%s\n' "$(gettext "RillML 运行时回滚失败。")"; return 1; }
    printf '%s\n' "${out}"
}

# ---- P0-8: root execution-policy orchestration -------------------------
# The Xray manager is the ROOT operator entrypoint. Every authority-relevant
# transition (mode change, routeStage change, auto confirm/revoke, safe-disable,
# fuse acknowledge, policy reset) MUST go through the one-shot root execution
# policy helper so executionEpoch is bumped (queued ApplyRequests become stale)
# and the unprivileged Runtime projection is refreshed. The helper is root-only
# and fail-closed on corruption; a missing/unavailable helper fails the
# transition instead of allowing a half-state.

rxa_root_policy() {
    # Invoke the one-shot root execution-policy helper.
    # RILL_XRAY_AGENT_ROOT_POLICY_HELPER overrides the path (tests / sandbox).
    local helper=${RILL_XRAY_AGENT_ROOT_POLICY_HELPER:-/opt/rill-xray-agent/bin/rill-xray-agent-root-policy}
    [[ -x "$helper" ]] || return 1
    "$helper" "$@"
}

rxa_root_policy_ok() {
    # Best-effort read of the CURRENT root execution policy mode. Returns the
    # mode string on stdout, or 1 when the helper is unavailable / corrupt /
    # the projection cannot be read. Read-only: never mutates state.
    local helper=${RILL_XRAY_AGENT_ROOT_POLICY_HELPER:-/opt/rill-xray-agent/bin/rill-xray-agent-root-policy}
    if [[ -x "$helper" ]]; then
        local out
        out=$("$helper" status 2>/dev/null) || return 1
        python3 - "$out" <<'PY' || return 1
import json,sys
try:
    print(json.loads(sys.argv[1])['policy']['mode'])
except Exception:
    raise SystemExit(1)
PY
        return 0
    fi
    # No helper: fall back to the configured preference (never an authority).
    rxa_get mode 2>/dev/null
}

rxa_root_policy_route_stage() {
    # Best-effort read of the CURRENT root execution policy routeStage
    # (observe/assist/auto). Returns the stage string on stdout, or 1 when the
    # helper is unavailable / corrupt / the projection cannot be read.
    # Read-only: never mutates state.
    local helper=${RILL_XRAY_AGENT_ROOT_POLICY_HELPER:-/opt/rill-xray-agent/bin/rill-xray-agent-root-policy}
    if [[ -x "$helper" ]]; then
        local out
        out=$("$helper" status 2>/dev/null) || return 1
        python3 - "$out" <<'PY' || return 1
import json,sys
try:
    print(json.loads(sys.argv[1])['policy']['routeStage'])
except Exception:
    raise SystemExit(1)
PY
        return 0
    fi
    # No helper: fall back to the configured preference (never an authority).
    rxa_get routeStage 2>/dev/null
}

rxa_root_policy_sync_mode() {
    # Sync the ROOT execution policy mode as the FIRST step of a mode
    # transaction. safe-disabled uses the dedicated safe-disable transition
    # (revokes auto + bumps epoch -> queued requests stale). normal /
    # observe-only use the mode transition (bumps epoch; NEVER restores auto
    # confirmation). A missing helper fails closed so no half-state exists.
    local target=${1:-}
    local helper=${RILL_XRAY_AGENT_ROOT_POLICY_HELPER:-/opt/rill-xray-agent/bin/rill-xray-agent-root-policy}
    [[ -x "$helper" ]] || return 1
    if [[ "$target" == safe-disabled ]]; then
        "$helper" safe-disable >/dev/null 2>&1 || return 1
    else
        "$helper" mode "$target" >/dev/null 2>&1 || return 1
    fi
    return 0
}

rxa_apply_route_stage() {
    # P0-8: routeStage is a three-party transaction: root execution policy
    # route-stage (bumps epoch -> queued requests stale), configured
    # preference and Runtime preference. Any failure rolls the root policy
    # back to the previous stage so no half-state exists.
    local stage=${1:-} old
    case "$stage" in observe|assist|auto) ;; *) return 64 ;; esac
    rxa_config_init
    old=$(rxa_get routeStage)
    [[ -z "${old}" ]] && old=observe
    # Re-asserting the same preference is only a no-op when the root policy
    # agrees; otherwise repair the drift below.
    local rp_stage
    rp_stage=$(rxa_root_policy_route_stage) || rp_stage="$old"
    if [[ "$rp_stage" == "$stage" ]]; then
        rxa_set routeStage "$stage" || return 1
        return 0
    fi
    # 1) root execution policy route-stage (authority; bumps epoch).
    if ! rxa_root_policy route-stage "$stage" >/dev/null 2>&1; then
        # No helper / corrupt policy: fail closed, never half-apply.
        return 1
    fi
    # 2) configured preference; on failure roll the root policy back.
    if ! rxa_set routeStage "$stage"; then
        rxa_root_policy route-stage "$old" >/dev/null 2>&1 || true
        return 1
    fi
    # 3) Runtime preference (shadow only, never authority).
    rxa_runtime route-stage "$stage" >/dev/null 2>&1 || true
    return 0
}

rxa_apply_auto_confirm() {
    # P0-8: real auto execution authority comes from root-policy confirm-auto,
    # NEVER from the Runtime-local autoConfirmedAtEpochSeconds. Requires the
    # configured routeStage preference to be auto first.
    local stage
    stage=$(rxa_get routeStage 2>/dev/null) || stage=observe
    if [[ "$stage" != auto ]]; then
        return 64
    fi
    rxa_root_policy confirm-auto >/dev/null 2>&1
}

rxa_apply_auto_revoke() {
    # P0-8: explicit auto revocation through the root policy (bumps epoch).
    rxa_root_policy revoke-auto >/dev/null 2>&1
}

rxa_acknowledge_fuse() {
    # P0-8: explicit fuse acknowledgment to re-arm auto through the root policy.
    rxa_root_policy acknowledge-fuse >/dev/null 2>&1
}

# P1-2: integration capability floor. Compatibility is decided by a SCHEMA
# FLOOR (>=, never a strict equality) PLUS a REQUIRED-CAPABILITY floor. A
# candidate is compatible only when its numeric schema is at or above the
# floor AND every required capability is really present as a live off-line
# dispatch branch.
RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR=${RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR:-2}
RILL_XRAY_AGENT_REQUIRED_CAPABILITIES=${RILL_XRAY_AGENT_REQUIRED_CAPABILITIES:-"status verify mode safe-disable uninstall-v2 diagnose timeline"}

# P1-2: returns 0 only when the candidate REALLY provides ${cap} as a live
# off-line dispatch branch (a real case line routing to a real rxa_dispatch
# action). A comment line, a bare string, or a missing dispatch fails closed.
rxa_capability_present() {
    local candidate=${1:-} cap=${2:-}
    case "${cap}" in
        status)       grep -qE '^[[:space:]]*--rill-agent-status\)[[:space:]]*rxa_dispatch status' "${candidate}" ;;
        verify)       grep -qE '^[[:space:]]*--rill-agent-verify\)[[:space:]]*rxa_dispatch verify' "${candidate}" ;;
        mode)         grep -qE '^[[:space:]]*--rill-agent-safe-disable\)[[:space:]]*rxa_dispatch mode safe-disabled' "${candidate}" ;;
        safe-disable) grep -qE '^[[:space:]]*--rill-agent-safe-disable\)[[:space:]]*rxa_dispatch mode safe-disabled' "${candidate}" ;;
        uninstall-v2) grep -qE '^[[:space:]]*--rill-agent-uninstall\)[[:space:]]*rxa_dispatch uninstall' "${candidate}" ;;
        diagnose)     grep -qE '^[[:space:]]*--rill-agent-diagnose\)[[:space:]]*rxa_dispatch diagnose' "${candidate}" ;;
        timeline)     grep -qE '^[[:space:]]*--rill-agent-timeline\)[[:space:]]*rxa_dispatch timeline' "${candidate}" ;;
        *) return 1 ;;
    esac
}

rxa_candidate_guard() {
    # Validates a freshly downloaded install.sh candidate before it is ever
    # allowed to replace the running script. Returns 0 only when every
    # integration anchor and the shell syntax check succeed.
    # P1-2: schema floor (>=, never strict equality) + capability floor.
    # A candidate is compatible when its numeric schema is at or above the
    # floor AND every required capability is really dispatched. A higher
    # schema that still provides all capabilities keeps passing.
    local candidate=${1:-} block rtmp rc cand_schema cap
    [[ -f "${candidate}" ]] || return 1
    bash -n "${candidate}" 2>/dev/null || return 1
    cand_schema=$(sed -n 's/^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=\([0-9][0-9]*\)$/\1/p' "${candidate}" | head -n1)
    [[ "${cand_schema}" =~ ^[0-9]+$ ]] || return 1
    (( cand_schema >= RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR )) || return 1
    for cap in ${RILL_XRAY_AGENT_REQUIRED_CAPABILITIES}; do
        rxa_capability_present "${candidate}" "${cap}" || return 1
    done
    grep -qE '^[[:space:]]*9\)[[:space:]]*rxa_menu' "${candidate}" || return 1
    grep -qE '^[[:space:]]*--rill-agent-status\)[[:space:]]*rxa_dispatch' "${candidate}" || return 1
    block=$(sed -n '/^# [B]EGIN RILL XRAY AGENT INTEGRATION$/,/^# [E]ND RILL XRAY AGENT INTEGRATION$/p' "${candidate}")
    [[ -n "${block}" ]] || return 1
    rtmp=$(mktemp -d) || return 1
    if RILL_XRAY_AGENT_PROBE_BLOCK="${block}" RILL_XRAY_AGENT_PROBE_ROOT="${rtmp}" \
        bash -c '
set -u
rt=${RILL_XRAY_AGENT_PROBE_ROOT}
mkdir -p "${rt}/bin" "${rt}/cfgs" "${rt}/xraybin" "${rt}/nginxbin" "${rt}/logs" "${rt}/state" "${rt}/etc-rill/scripts"
# Fake host tooling: the probe must never touch the real system.
cat > "${rt}/bin/systemctl" <<EOF
#!/usr/bin/env bash
exit 0
EOF
cat > "${rt}/bin/xray" <<EOF
#!/usr/bin/env bash
[ "\${1}" = "run" ] && [ "\${2}" = "-test" ] && exit 0
exit 0
EOF
cat > "${rt}/bin/nginx" <<EOF
#!/usr/bin/env bash
[ "\${1}" = "-t" ] && exit 0
exit 0
EOF
cat > "${rt}/bin/ss" <<JEOF
#!/usr/bin/env bash
printf "LISTEN 0 4096 0.0.0.0:60000 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61000 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61001 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61002 0.0.0.0:* inet sshd\n"
JEOF
cat > "${rt}/bin/jq" <<JQEOF
#!/usr/bin/env python3
import json,sys
args=list(sys.argv[1:])
arg={}
while "--arg" in args:
    i=args.index("--arg"); arg[args[i+1]]=args[i+2]; args=args[:i]+args[i+3:]
args=[a for a in args if not a.startswith("-") and a!="--"]
flt=args[0]
if len(args)>1:
    d=json.load(open(args[1]))
else:
    d=json.load(sys.stdin)
if flt==".":
    print(json.dumps(d,separators=(",",":"))); sys.exit(0)
name=flt.split(".")[-1].split("//")[0].strip().strip(chr(34))
if name.startswith("[$"): name=arg.get(name[2:-1],"")
if isinstance(d,dict) and name in d: print(d[name])
JQEOF
chmod +x "${rt}"/bin/*
export PATH="${rt}/bin:${PATH}"
printf "%s\n" "{\"tls\":\"TLS\",\"port\":60000,\"reality_add_nginx\":\"off\",\"ws_port\":61000,\"grpc_port\":61001,\"xhttp_port\":61002}" > "${rt}/cfgs/install_config.json"
printf "%s\n" "not json" > "${rt}/cfgs/broken.json"
cp "${rt}/bin/xray" "${rt}/xraybin/xray"
cp "${rt}/bin/nginx" "${rt}/nginxbin/nginx"
printf "%s\n" "{}" > "${rt}/cfgs/xray.json"
printf "%s\n" "{}" > "${rt}/cfgs/nginx.conf"
export RILL_XRAY_AGENT_INSTALL_CONFIG="${rt}/cfgs/install_config.json"
export RILL_XRAY_AGENT_XRAY_BIN="${rt}/xraybin/xray"
export RILL_XRAY_AGENT_XRAY_CONF="${rt}/cfgs/xray.json"
export RILL_XRAY_AGENT_NGINX_BIN="${rt}/nginxbin/nginx"
export RILL_XRAY_AGENT_NGINX_CONF="${rt}/cfgs/nginx.conf"
export RILL_XRAY_AGENT_LOG_DIR="${rt}/logs"
export RILL_XRAY_AGENT_CONFIG="${rt}/cfgs/config.json"
export RILL_XRAY_AGENT_HOME="${rt}/etc-rill"
export RILL_XRAY_AGENT_STATE="${rt}/state"
export RILL_XRAY_AGENT_MANAGER="${rt}/etc-rill/scripts/rill_xray_agent_manager.sh"
export RILL_XRAY_AGENT_STATUS="${rt}/status/xray-observation.json"
export _TEST_MODE=1
menu_pause(){ return 0; }
eval "${RILL_XRAY_AGENT_PROBE_BLOCK}" || exit 1
# 1) real function definitions, not comment strings.
for f in rxa_candidate_guard rxa_uninstall_prepare rxa_uninstall_commit \
         rxa_uninstall_abort rxa_uninstall_finish rxa_reconfigure_enter \
         rxa_reconfigure_leave rxa_host_healthy rxa_dispatch rxa_menu; do
    declare -F "$f" >/dev/null 2>&1 || exit 2
done
# 2) healthy host must be real, not the old any-active shortcut.
rxa_host_healthy || exit 3
# 3) unparseable config must be refused.
RILL_XRAY_AGENT_INSTALL_CONFIG="${rt}/cfgs/broken.json" rxa_host_healthy && exit 4
# 4) missing xray binary must be refused.
RILL_XRAY_AGENT_XRAY_BIN="${rt}/nonexistent" rxa_host_healthy && exit 4
# 5) offline-safe dispatch must really run and emit the observe JSON.
out=$(rxa_dispatch status) || exit 5
case "$out" in *installed*) ;; *) exit 6 ;; esac
# 6) reconfigure hooks are non-fatal with no agent state.
rxa_reconfigure_enter || exit 7
rxa_reconfigure_leave 0 || exit 7
# 7) uninstall contract: prepare no-op without Rill; commit fails safe when
#    the purge script is absent; abort keeps the host rc and finish routes 1.
rxa_uninstall_prepare || exit 8
rxa_uninstall_commit && exit 9
rxa_uninstall_finish 1
[ $? -eq 1 ] || exit 10
# 8) menu case 9 target must be a real function.
rxa_menu >/dev/null 2>&1 || exit 11
exit 0
'; then
        rc=0
    else
        rc=$?
    fi
    rm -rf "${rtmp}"
    return "${rc}"
}

rxa_verify_runtime_mode() {
    # Fail-closed Runtime contract: WAL mode must equal the expected mode and
    # the Runtime must answer routeAssistEnabled=false and boundedAutoAllowed=
    # false in EVERY mode; a missing answer or a dead Runtime fails the check.
    local expected=${1:-} payload got expected_ra expected_ba
    payload=$(rxa_runtime config 2>/dev/null) || return 1
    read -r got expected_ra expected_ba <<<"$(printf '%s' "$payload" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    d=d.get("result") or d
    print(d.get("mode","?"),d.get("routeAssistEnabled","?"),d.get("boundedAutoAllowed","?"))
except Exception:
    print("? ? ?")')"
    [[ "$got" == "$expected" && "$expected_ra" == "False" && "$expected_ba" == "False" ]]
}

rxa_observe_valid() {
    # Read-side freshness/structure check of the persisted observation.
    # Never mutates state: used by the target-state matcher to decide whether
    # a same-mode call is a true no-op.
    local status=${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}
    python3 - "$status" <<'PY' || return 1
import json,sys,time
try:
    data=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
now=time.time()
assert data.get('capturedAtEpochSeconds',0) >= now - 3700, 'observation.stale'
assert 'xrayConfig' in data and 'services' in data, 'observation.invalid-structure'
PY
}

rxa_observe_fresh() {
    # Refresh the persisted observation from the live observer and validate it.
    local observer=${RILL_XRAY_AGENT_OBSERVER:-$RILL_XRAY_AGENT_HOME/scripts/rill_xray_agent_observe.py}
    python3 "$observer" >/dev/null 2>&1 || return 1
    rxa_observe_valid
}

rxa_mode_state_matches_target() {
    # Full target-state validation: config string, Runtime WAL mode and (when
    # systemd is present) unit states and observation freshness must ALL agree
    # with the requested mode. Same-mode is only a no-op when every party
    # matches; otherwise the caller must run the repair transaction.
    local mode=${1:-} unit want_units=0
    case "$mode" in normal|observe-only) want_units=1 ;; safe-disabled) want_units=0 ;; *) return 64 ;; esac
    [[ "$(rxa_get mode)" == "$mode" ]] || return 1
    rxa_verify_runtime_mode "$mode" || return 1
    if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
        if ((want_units)); then
            for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer rill-xray-agent-auto-evaluate.path; do
                rxa_systemctl is-active --quiet "$unit" || return 1
            done
            rxa_observe_valid || return 1
        else
            for unit in rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer rill-xray-agent-auto-evaluate.path; do
                rxa_systemctl is-active --quiet "$unit" && return 1
            done
        fi
    fi
    return 0
}

rxa_apply_mode() {
    # Mode switch is a four-party transaction: config, Runtime service,
    # systemd units and the xray observation snapshot must all agree on the
    # new mode before the config is committed; any failure rolls everything
    # back to the previous mode.
    #
    # Same-mode is NOT an implicit success: the full target state must already
    # match (config, Runtime mode, unit states, observation freshness). If the
    # config string equals the target but a unit or observation drifted, the
    # repair transaction below converges the system back to the target state.
    local mode=${1:-} old rc=0 unit want_units=0
    case "$mode" in normal|observe-only) want_units=1 ;; safe-disabled) want_units=0 ;; *) return 64 ;; esac
    rxa_config_init
    old=$(rxa_get mode)
    [[ -z "${old}" ]] && old=observe-only
    if rxa_mode_state_matches_target "$mode"; then
        return 0
    fi

    # P0-8 Phase 0: ROOT execution policy FIRST, before any Runtime/unit
    # mutation. safe-disabled uses the dedicated safe-disable transition
    # (revokes auto + bumps executionEpoch -> queued ApplyRequests become
    # stale); normal / observe-only use the mode transition (bumps epoch;
    # NEVER restores auto confirmation - the operator must re-confirm
    # explicitly). The helper is root-only and fail-closed: a missing or
    # corrupt helper aborts the transition so no half-state exists.
    if ! rxa_root_policy_sync_mode "$mode"; then
        return 1
    fi

    # Phase 1: config + Runtime committed through the Runtime WAL.
    if ! rxa_runtime mode "$mode" >/dev/null; then
        # P0-8: early rollback restores the root execution policy; no
        # half-state where authority diverges from preference.
        rxa_root_policy_sync_mode "$old" >/dev/null 2>&1 || true
        return 1
    fi
    if ! rxa_verify_runtime_mode "$mode"; then
        # Early rollback must ALSO restore the root execution policy so no
        # half-state exists (P0-8: authority and preference stay in lockstep).
        rxa_runtime mode "$old" >/dev/null 2>&1 || true
        rxa_root_policy_sync_mode "$old" >/dev/null 2>&1 || true
        return 1
    fi

    # Phase 2: systemd unit states for the target mode. The runtime unit is
    # part of the enabled set so a fresh observe-only install really starts
    # the whole stack, not just the Runtime.
    if ((want_units)); then
        rxa_systemctl enable --now rill-xray-agent-runtime.service >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-agent.service >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-auto-evaluate.path >/dev/null 2>&1 || rc=1
        if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
            for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer rill-xray-agent-auto-evaluate.path; do
                rxa_systemctl is-active --quiet "$unit" || rc=1
            done
        fi
    else
        rxa_systemctl disable --now \
          rill-xray-agent-agent.service \
          rill-xray-agent-xray-observe.path \
          rill-xray-agent-xray-observe.timer \
          rill-xray-agent-auto-evaluate.path >/dev/null 2>&1 || rc=1
        if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
            for unit in rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-auto-evaluate.path; do
                rxa_systemctl is-active --quiet "$unit" && rc=1
            done
        fi
    fi

    # Phase 3: observation must reflect the target mode.
    if ((want_units)); then
        rxa_observe_fresh || rc=1
    elif [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
        rxa_systemctl is-active --quiet rill-xray-agent-xray-observe.path && rc=1
        rxa_systemctl is-active --quiet rill-xray-agent-agent.service && rc=1
        rxa_systemctl is-active --quiet rill-xray-agent-auto-evaluate.path && rc=1
    fi

    # Phase 4: commit the persisted config only after every party verified.
    if ((rc == 0)); then
        rxa_set mode "$mode"
        [[ "$(rxa_get mode)" == "$mode" ]] || rc=1
    fi

    if ((rc != 0)); then
        # Roll back Runtime, systemd units, config AND the root execution
        # policy to the previous mode (P0-8: authority and preference must
        # stay in lockstep; a partial transition is never left behind).
        rxa_runtime mode "$old" >/dev/null 2>&1 || true
        rxa_root_policy_sync_mode "$old" >/dev/null 2>&1 || true
        if [[ "$old" == safe-disabled ]]; then
            rxa_systemctl disable --now \
              rill-xray-agent-agent.service \
              rill-xray-agent-xray-observe.path \
              rill-xray-agent-xray-observe.timer \
              rill-xray-agent-auto-evaluate.path >/dev/null 2>&1 || true
        else
            rxa_systemctl enable --now rill-xray-agent-agent.service >/dev/null 2>&1 || true
            rxa_systemctl enable --now rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || true
            rxa_systemctl enable --now rill-xray-agent-auto-evaluate.path >/dev/null 2>&1 || true
        fi
        rxa_set mode "$old" >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}

rxa_status_json() {
    rxa_config_init
    local runtime=false agent=false
    rxa_systemctl is-active --quiet rill-xray-agent-runtime.service && runtime=true
    rxa_systemctl is-active --quiet rill-xray-agent-agent.service && agent=true
    python3 - "$RILL_XRAY_AGENT_CONFIG" "$runtime" "$agent" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
print(json.dumps({
    'schemaVersion':1,
    'installed':True,
    'mode':data['mode'],
    'runtimeActive':sys.argv[2]=='true',
    'agentActive':sys.argv[3]=='true',
    'routeStage':data.get('routeStage','observe'),
    'routeAssistEnabled':False,
    'boundedAutoAllowed':False,
},sort_keys=True))
PY
}

rxa_mode_label() {
    case "${1:-}" in
        normal) gettext "智能判断" ;;
        observe-only) gettext "仅观察" ;;
        safe-disabled) gettext "安全停用" ;;
        *) printf '%s' "${1:-}" ;;
    esac
}

rxa_auto_status() {
    # P0-8: autoStatus distinguishes configured / rootAuthoritative / shadow /
    # effective. The ONLY authority that can enable auto is the ROOT execution
    # policy (autoConfirmed=true, mode=normal, routeStage=auto) AND the release
    # manifest must have boundedAuto.released=true. Runtime-local
    # autoConfirmedAtEpochSeconds is a shadow record only, never an authority.
    # Any party that is unavailable/corrupt fails closed towards not-effective
    # (never fabricates an enablement).
    rxa_config_init
    local cfg_stage cfg_ba rp_json rp_mode rp_stage rp_auto rp_epoch
    local shadow_json shadow_confirmed shadow_stage ba_released
    cfg_stage=$(rxa_get routeStage 2>/dev/null); [[ -n "${cfg_stage}" ]] || cfg_stage=observe
    cfg_ba=$(rxa_get boundedAutoAllowed 2>/dev/null)
    [[ "${cfg_ba}" == true ]] && cfg_ba=true || cfg_ba=false
    rp_mode=unknown; rp_stage=unknown; rp_auto=false; rp_epoch=0
    if rp_json=$(rxa_root_policy status 2>/dev/null); then
        read -r rp_mode rp_stage rp_auto rp_epoch <<<"$(printf '%s' "${rp_json}" | python3 -c 'import json,sys
try:
    p=json.load(sys.stdin)["policy"]
    print(p.get("mode","?"),p.get("routeStage","?"),"true" if p.get("autoConfirmed") else "false",p.get("executionEpoch","?"))
except Exception:
    print("? ? ? ?")')"
    fi
    shadow_confirmed=false; shadow_stage=unknown
    if shadow_json=$(rxa_runtime auto-status 2>/dev/null); then
        read -r shadow_confirmed shadow_stage <<<"$(printf '%s' "${shadow_json}" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); d=d.get("result") or d
    print("true" if d.get("autoConfirmed") else "false", d.get("configuredStage","?"))
except Exception:
    print("? ?")')"
    fi
    ba_released=false
    local rel=${RILL_XRAY_AGENT_RELEASE_MANIFEST:-/opt/rill-xray-agent/share/release-capabilities.json}
    if [[ -r "${rel}" ]]; then
        ba_released=$(python3 - "${rel}" <<'PY' 2>/dev/null || printf 'false'
import json,sys
try:
    print("true" if json.load(open(sys.argv[1]))["features"]["boundedAuto"]["released"] else "false")
except Exception:
    print("false")
PY
)
        [[ "${ba_released}" == true ]] && ba_released=true || ba_released=false
    fi
    local effective=false
    if [[ "${rp_mode}" == normal && "${rp_stage}" == auto && "${rp_auto}" == true && "${ba_released}" == true ]]; then
        effective=true
    fi
    python3 - "${cfg_stage}" "${cfg_ba}" "${rp_mode}" "${rp_stage}" "${rp_auto}" "${rp_epoch}" "${shadow_confirmed}" "${shadow_stage}" "${effective}" <<'PY'
import json,sys
(stage,ba,rp_mode,rp_stage,rp_auto,rp_epoch,sh_conf,sh_stage,eff)=sys.argv[1:]
print(json.dumps({
    'schemaVersion':1,
    'autoStatus':{
        'configured':{'routeStage':stage,'boundedAutoAllowed':ba=='true'},
        'rootAuthoritative':{'mode':rp_mode,'routeStage':rp_stage,
                             'autoConfirmed':rp_auto=='true',
                             'executionEpoch':int(rp_epoch)},
        'shadow':{'autoConfirmed':sh_conf=='true','configuredStage':sh_stage},
        'effective':eff=='true',
    },
},sort_keys=True))
PY
}

rxa_ai_judgment_label() {
    case "${1:-}" in
        normal) gettext "已开启" ;;
        observe-only) gettext "仅观察" ;;
        safe-disabled) gettext "已停用" ;;
        *) gettext "不可用" ;;
    esac
}

rxa_install_testing_confirm() {
    local answer
    printf '\n%s\n' "$(gettext "提示：Rill AI 判断引擎目前仍处于测试阶段。")"
    printf '%s\n' "$(gettext "可能存在兼容性、判断准确性或稳定性问题，不能保证完全无故障。")"
    printf '%s\n' "$(gettext "安装后默认仅启用 AI 观察模式，路由辅助保持关闭。")"
    if [[ ${RILL_XRAY_AGENT_ACCEPT_TEST_RISK:-0} == 1 ]]; then
        return 0
    fi
    printf '%s' "$(gettext "确认了解测试风险并继续安装吗？ [y/N]: ")"
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) return 0 ;;
        *)
            printf '%s\n' "$(gettext "已取消安装。")"
            return 1
            ;;
    esac
}

rxa_install_with_notice() {
    rxa_install_testing_confirm || return 1
    bash "${scripts_dir}/rill_xray_agent_install.sh"
}

rxa_refresh_summary() {
    local status mode
    if ! status=$(rxa_status_json 2>/dev/null); then
        RILL_XRAY_AGENT_HEADER_STATE="$(gettext "AI 判断: 未安装")"
        RILL_XRAY_AGENT_HEADER_MODE="$(gettext "工作模式: 不可用")"
        RILL_XRAY_AGENT_HEADER_RUNTIME="$(gettext "服务: 未运行")"
        RILL_XRAY_AGENT_HEADER_ROUTE="$(gettext "路由辅助: 关闭")"
        RILL_XRAY_AGENT_HEADER_RILLML="$(gettext "RillML 运行时: 不可用")"
        return 0
    fi
    mode=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["mode"])' <<<"$status")
    RILL_XRAY_AGENT_HEADER_MODE="$(gettext "工作模式"): $(rxa_mode_label "$mode")"
    if rxa_systemctl is-active --quiet rill-xray-agent-runtime.service; then
        RILL_XRAY_AGENT_HEADER_STATE="$(gettext "AI 判断"): $(rxa_ai_judgment_label "$mode")"
        RILL_XRAY_AGENT_HEADER_RUNTIME="$(gettext "服务: 运行中")"
    else
        RILL_XRAY_AGENT_HEADER_STATE="$(gettext "AI 判断: 不可用")"
        RILL_XRAY_AGENT_HEADER_RUNTIME="$(gettext "服务: 未运行")"
    fi
    RILL_XRAY_AGENT_HEADER_ROUTE="$(gettext "路由辅助: 关闭")"
    # RillML native-runtime header: read-only IPC surface (never a lifecycle op).
    local rillml_status_line rillml_state
    if rillml_status_line=$(rxa_rillml_native_status 2>/dev/null); then
        rillml_state=$(printf '%s' "${rillml_status_line}" | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin); d=d.get("result") or d
    print(d.get("nativeRuntime",{}).get("status","?"))
except Exception:
    print("?")')
        RILL_XRAY_AGENT_HEADER_RILLML="$(gettext "RillML 运行时"): $(rxa_rillml_state_label "$rillml_state")"
    else
        RILL_XRAY_AGENT_HEADER_RILLML="$(gettext "RillML 运行时: 不可用")"
    fi
}

rxa_socket_connectable() {
    # REAL connect() probe: a stale socket inode whose listener is gone must
    # fail closed - inode presence alone is never a pass.
    local sock=${1:-}
    python3 - "$sock" <<'PY' || return 1
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(sys.argv[1])
    s.close()
except Exception:
    sys.exit(1)
PY
}

rxa_verify_live_contract() {
    # Single, mode-aware live verification contract shared by the manager menu
    # (Verify), rill_xray_agent_verify.sh, the CLI (--rill-agent-verify) and CI.
    # Safe-disabled is verified per its own mode contract, NOT by forcing every
    # unit active.
    #
    # Verifies: committed config defaults (routeAssist=false, boundedAuto=false),
    # Runtime WAL mode == target config mode, per-mode systemd unit states +
    # observation freshness, and PER-MODE socket rules:
    #   normal / observe-only: runtime.sock exists and CONNECTS; agent.sock
    #                          exists and CONNECTS
    #   safe-disabled:         runtime.sock exists and CONNECTS; agent.sock must
    #                          be MISSING or must REFUSE connection (a stale
    #                          inode that still accepts is a FAIL)
    rxa_config_init
    [[ "$(rxa_get routeAssistEnabled)" == false ]] || return 1
    [[ "$(rxa_get boundedAutoAllowed)" == false ]] || return 1
    local mode
    mode=$(rxa_get mode)
    [[ -n "$mode" ]] || return 1
    rxa_mode_state_matches_target "$mode" || return 1
    # Socket rules apply on a real system (real path) and in sandbox tests
    # (RILL_XRAY_AGENT_SOCKET_DIR points at a throwaway directory).
    if [[ -n "${RILL_XRAY_AGENT_SOCKET_DIR:-}" || ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
        local sock_dir=${RILL_XRAY_AGENT_SOCKET_DIR:-/run/rill-xray-agent}
        rxa_socket_connectable "$sock_dir/runtime.sock" || return 1
        case "$mode" in
            normal|observe-only)
                rxa_socket_connectable "$sock_dir/agent.sock" || return 1
                ;;
            safe-disabled)
                if [[ -S "$sock_dir/agent.sock" ]]; then
                    rxa_socket_connectable "$sock_dir/agent.sock" && return 1
                fi
                ;;
            *) return 64 ;;
        esac
    fi
    return 0
}

rxa_verify() {
    rxa_verify_live_contract
}

rxa_diagnose() {
    # Advisory-only Doctor diagnosis. Emits the deterministic diagnosis result
    # so the operator can see facts vs inference and suggested next steps.
    # Never executes host commands; canApply is always false.
    rxa_runtime diagnose
}

rxa_status_display() {
    local state_field runtime_field
    rxa_refresh_summary
    state_field="${RILL_XRAY_AGENT_HEADER_STATE}"
    runtime_field="${RILL_XRAY_AGENT_HEADER_RUNTIME}"
    # 仅运行中的状态着绿色；关闭、未运行不加颜色（与主菜单一致）。
    if [[ -n "${Green:-}" && "${runtime_field}" == *"$(gettext "运行中")"* ]]; then
        state_field="${Green:-}${state_field}${Font:-}"
        runtime_field="${Green:-}${runtime_field}${Font:-}"
    fi
    printf '%s\n' "${state_field}"
    printf '%s\n' "${RILL_XRAY_AGENT_HEADER_MODE}"
    printf '%s\n' "${runtime_field}"
    printf '%s\n' "${RILL_XRAY_AGENT_HEADER_ROUTE}"
    printf '%s\n' "${RILL_XRAY_AGENT_HEADER_RILLML}"
}

rxa_mode_change_confirm() {
    # Explains what each work-mode switch actually changes, then asks for
    # confirmation before any unit/config mutation. RILL_XRAY_AGENT_ACCEPT_MODE_SWITCH=1
    # skips the prompt for non-interactive consumers.
    local mode="${1:-}" msg
    case "$mode" in
        normal)
            msg="$(gettext "开启 AI 智能判断后，系统将持续观测 Xray/Nginx 状态，自动诊断故障并给出处理建议。说明：自动修改功能暂不开放，当前不会自动更改系统。")"
            ;;
        observe-only)
            msg="$(gettext "切换到 AI 观察模式后，AI 仅观测和判断，不会自动修改系统，结果仅供参考。")"
            ;;
        safe-disabled)
            msg="$(gettext "安全停用后，AI 判断功能暂停，引擎保留，可随时重新开启。")"
            ;;
        *) return 64 ;;
    esac
    printf '\n%s\n' "${msg}"
    if [[ ${RILL_XRAY_AGENT_ACCEPT_MODE_SWITCH:-0} == 1 ]]; then
        return 0
    fi
    printf '%s' "$(gettext "确认切换吗？ [y/N]: ")"
    local answer
    IFS= read -r answer || answer=""
    case ${answer} in
        y|Y|yes|YES|Yes|是) return 0 ;;
        *) printf '%s\n' "$(gettext "已取消。")"; return 1 ;;
    esac
}

rxa_apply_mode_display() {
    local mode="$1" label
    label=$(rxa_mode_label "$mode")
    rxa_mode_change_confirm "$mode" || return 1
    if rxa_apply_mode "$mode"; then
        printf '%s: %s\n' "$(gettext "工作模式已切换")" "$label"
    else
        printf '%s: %s\n' "$(gettext "工作模式切换失败")" "$label" >&2
        return 1
    fi
}

rxa_verify_display() {
    if rxa_verify; then
        printf '%s\n' "$(gettext "AI 判断引擎校验通过")"
    else
        printf '%s\n' "$(gettext "AI 判断引擎校验失败，请检查后台服务和观测数据")" >&2
        return 1
    fi
}

rxa_diagnosis_summary() {
    case "${1:-}" in
        HEALTHY) gettext "Xray 相关服务运行正常，未发现近期故障" ;;
        CONFIG_CHANGED_HEALTHY) gettext "近期配置发生过变化，但当前服务与配置校验均正常" ;;
        RECOVERY_REQUIRED) gettext "Rill 内部恢复尚未完成，暂时无法进行可靠判断" ;;
        MISSING_OBSERVATION) gettext "尚无可用的观测数据，暂时无法判断" ;;
        INVALID_OBSERVATION_TIME) gettext "观测时间无效，当前证据不可用" ;;
        STALE_OBSERVATION) gettext "观测数据已过期，需要先刷新观测" ;;
        UNSAFE_PATH) gettext "检测到不安全的配置路径，需要人工检查" ;;
        BOTH_SERVICES_DOWN) gettext "Xray 与 Nginx 均未运行" ;;
        XRAY_VALIDATION_FAILED*) gettext "Xray 配置校验失败" ;;
        NGINX_VALIDATION_FAILED*) gettext "Nginx 配置校验失败" ;;
        XRAY_SERVICE_DOWN*) gettext "Xray 服务未运行" ;;
        NGINX_SERVICE_DOWN*) gettext "Nginx 服务未运行" ;;
        INSUFFICIENT_EVIDENCE) gettext "现有证据不足，暂时无法判断" ;;
        *) gettext "已生成判断结果，请结合诊断代码继续检查" ;;
    esac
}

rxa_health_label() {
    # Compact per-refresh health label for the main-menu banner. Runs the real
    # diagnosis; on failure or missing evidence it degrades to "不可用" instead
    # of fabricating a health state. Healthy states render green.
    local payload code summary
    if ! payload=$(rxa_diagnose 2>/dev/null); then
        printf '%s\n' "$(gettext "检测：不可用")"
        return 0
    fi
    code=$(printf '%s' "$payload" | python3 -c '
import json,sys
data=json.load(sys.stdin)
result=data.get("result") or data
print(result.get("diagnosisCode","UNKNOWN"))
' 2>/dev/null) || {
        printf '%s\n' "$(gettext "检测：不可用")"
        return 0
    }
    summary=$(rxa_diagnosis_summary "$code")
    case "$code" in
        HEALTHY|CONFIG_CHANGED_HEALTHY)
            printf '%s%s%s\n' "${Green:-}" "$(gettext "检测")：${summary}" "${Font:-}"
            ;;
        *)
            printf '%s\n' "$(gettext "检测")：${summary}"
            ;;
    esac
}

rxa_confidence_label() {
    case "${1:-}" in
        high) gettext "高" ;;
        medium) gettext "中" ;;
        low) gettext "低" ;;
        insufficient-evidence) gettext "证据不足" ;;
        *) gettext "未知" ;;
    esac
}

rxa_diagnose_display() {
    local payload fields code confidence can_apply
    if ! payload=$(rxa_diagnose); then
        printf '%s\n' "$(gettext "AI 故障诊断失败，后台服务没有返回有效结果")" >&2
        return 1
    fi
    fields=$(printf '%s' "$payload" | python3 -c '
import json,sys
try:
    data=json.load(sys.stdin)
    result=data.get("result") or data
    print(result.get("diagnosisCode", "UNKNOWN"))
    print(result.get("confidenceBand", "unknown"))
    print("true" if result.get("canApply") is True else "false")
except Exception:
    raise SystemExit(1)
' 2>/dev/null) || {
        printf '%s\n' "$(gettext "AI 故障诊断失败，返回内容无法解析")" >&2
        return 1
    }
    code=$(sed -n '1p' <<<"$fields")
    confidence=$(sed -n '2p' <<<"$fields")
    can_apply=$(sed -n '3p' <<<"$fields")
    printf '%s: %s\n' "$(gettext "AI 判断")" "$(rxa_diagnosis_summary "$code")"
    printf '%s: %s\n' "$(gettext "判断置信度")" "$(rxa_confidence_label "$confidence")"
    printf '%s: %s\n' "$(gettext "诊断代码")" "$code"
    if [[ "$can_apply" == true ]]; then
        printf '%s\n' "$(gettext "此结果允许自动处理")"
    else
        printf '%s\n' "$(gettext "此结果仅提供判断建议，不会自动修改系统")"
    fi
}

rxa_mode_help() {
    printf '%s\n' "$(gettext "三种工作模式说明：")"
    printf '  %s\n' "$(gettext "智能判断：AI 实时诊断故障并给出处理建议。自动修改功能暂不开放，当前不会自动更改系统。")"
    printf '  %s\n' "$(gettext "观察模式：AI 仅观察和判断，不会自动修改系统，结果仅供参考。")"
    printf '  %s\n' "$(gettext "安全停用：暂停 AI 判断功能，引擎保留，可随时重新开启。")"
}

rxa_mode_menu() {
    local choice
    while true; do
        menu_submenu_begin "$(gettext "Rill Xray AI 运维助手 / 切换工作模式")"
        menu_item 1 "$(gettext "开启 AI 智能判断")"
        menu_item 2 "$(gettext "切换到 AI 观察模式")"
        menu_item 3 "$(gettext "安全停用 AI 判断")"
        menu_blank
        menu_item 4 "$(gettext "查看工作模式说明")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read choice 4
        echo
        case $choice in
            0) return ;;
            1) rxa_apply_mode_display normal; menu_pause ;;
            2) rxa_apply_mode_display observe-only; menu_pause ;;
            3) rxa_apply_mode_display safe-disabled; menu_pause ;;
            4) rxa_mode_help; menu_pause ;;
        esac
    done
}

rxa_verify_diag_menu() {
    local choice
    while true; do
        menu_submenu_begin "$(gettext "Rill Xray AI 运维助手 / 校验与诊断")"
        menu_item 1 "$(gettext "校验 AI 判断引擎")"
        menu_item 2 "$(gettext "运行 AI 故障诊断")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read choice 2
        echo
        case $choice in
            0) return ;;
            1) rxa_verify_display; menu_pause ;;
            2) rxa_diagnose_display; menu_pause ;;
        esac
    done
}

rxa_rillml_menu() {
    local choice
    while true; do
        menu_submenu_begin "$(gettext "Rill Xray AI 运维助手 / RillML 运行时管理")"
        menu_row "$(gettext "RillML 预编译运行时：安装 / 升级 / 重装 / 回滚（root 操作，失败不阻塞主引擎）。")"
        menu_blank
        menu_item 1 "$(gettext "查看 RillML 运行时状态")"
        menu_item 2 "$(gettext "安装 RillML 运行时")"
        menu_item 3 "$(gettext "升级 RillML 运行时")"
        menu_item 4 "$(gettext "重新安装 RillML 运行时")"
        menu_item 5 "$(gettext "回滚 RillML 运行时")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read choice 5
        echo
        case $choice in
            0) return ;;
            1) rxa_rillml_status_display; menu_pause ;;
            2) rxa_rillml_install; menu_pause ;;
            3) rxa_rillml_upgrade; menu_pause ;;
            4) rxa_rillml_reinstall; menu_pause ;;
            5) rxa_rillml_rollback; menu_pause ;;
        esac
    done
}

rxa_menu() {
    local choice
    scripts_dir=${scripts_dir:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}
    while true; do
        menu_submenu_begin "$(gettext "Rill Xray AI 运维助手")"
        menu_row "$(gettext "本地 AI 运维助手：实时监控 Xray/Nginx 健康，自动诊断故障并给出处理建议。")"
        menu_row "$(gettext "• 监控：实时观测服务与配置状态")"
        menu_row "$(gettext "• 诊断：定位故障原因，附置信度建议")"
        menu_row "$(gettext "• 模式：智能判断 / 仅观察 / 安全停用")"
        menu_row "$(rxa_health_label)"
        menu_blank
        menu_item 1 "$(gettext "查看 AI 判断状态")"
        menu_item 2 "$(gettext "切换工作模式")"
        menu_item 3 "$(gettext "校验与诊断")"
        menu_blank
        menu_item 4 "$(gettext "安装或修复 AI 判断引擎")"
        menu_item 5 "$(gettext "卸载 Rill AI 引擎")"
        menu_blank
        menu_item 6 "$(gettext "RillML 运行时管理")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read choice 6
        echo
        case $choice in
            0) return ;;
            1) rxa_status_display; menu_pause ;;
            2) rxa_mode_menu ;;
            3) rxa_verify_diag_menu ;;
            4) rxa_install_with_notice; menu_pause ;;
            5) bash "${scripts_dir}/rill_xray_agent_uninstall.sh"; return ;;
            6) rxa_rillml_menu ;;
        esac
    done
}

rxa_dispatch() {
    case "${1:-status}" in
        status) rxa_status_json ;;
        install) rxa_install_with_notice ;;
        mode) rxa_apply_mode "${2:-}" ;;
        safe-disable) rxa_apply_mode safe-disabled ;;
        verify) rxa_verify ;;
        diagnose) rxa_diagnose ;;
        timeline) rxa_runtime timeline ;;
        # P0-8: authority-relevant transitions MUST go through the root policy.
        # routeStage is a three-party transaction (root policy + configured
        # preference + Runtime shadow); auto confirm/revoke and fuse ack go
        # through the root-policy helper which bumps executionEpoch.
        routeStage) rxa_apply_route_stage "${2:-}" ;;
        autoStatus) rxa_auto_status ;;
        autoConfirm) rxa_apply_auto_confirm ;;
        autoRevoke) rxa_apply_auto_revoke ;;
        fuseAck) rxa_acknowledge_fuse ;;
        uninstall) bash "${scripts_dir}/rill_xray_agent_uninstall.sh" ;;
        # RillML native runtime: read-only status over IPC; lifecycle ops are
        # root-only (never proxied through the Runtime, §P0-16).
        rillmlStatus) rxa_rillml_native_status ;;
        rillml-status) rxa_rillml_status_display ;;
        rillml-install) rxa_rillml_install ;;
        rillml-upgrade) rxa_rillml_upgrade ;;
        rillml-reinstall) rxa_rillml_reinstall ;;
        rillml-rollback) rxa_rillml_rollback ;;
        *) return 64 ;;
    esac
}
