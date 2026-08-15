#!/usr/bin/env bash
set -euo pipefail
# RILL_XRAY_AGENT_ALLOW_NONROOT is a test-only escape hatch (never set by
# production paths) so CI runners without root can exercise the full flow
# against a DESTDIR sandbox.
if [[ ${RILL_XRAY_AGENT_ALLOW_NONROOT:-0} != 1 ]] && [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo '需要 root 权限' >&2
    exit 77
fi
DESTDIR=${DESTDIR:-}
root() { printf '%s%s' "$DESTDIR" "$1"; }

RILL_XRAY_AGENT_HOME=${RILL_XRAY_AGENT_HOME:-/etc/rill-xray-agent}
RILL_XRAY_AGENT_CONFIG=${RILL_XRAY_AGENT_CONFIG:-/etc/rill-xray-agent/config.json}
RILL_XRAY_AGENT_STATE=${RILL_XRAY_AGENT_STATE:-/var/lib/rill-xray-agent-runtime}
RILL_XRAY_AGENT_XRAY=${RILL_XRAY_AGENT_XRAY:-/var/lib/rill-xray-agent-xray}
RILL_XRAY_AGENT_STATUS=${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}
RILL_XRAY_AGENT_MANAGER=${RILL_XRAY_AGENT_MANAGER:-/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh}
RILL_XRAY_AGENT_UNITS=(rill-xray-agent-runtime.service rill-xray-agent-agent.service \
    rill-xray-agent-xray-observe.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer \
    rill-xray-agent-apply.service rill-xray-agent-apply.path)

rxa_fake_systemctl() {
    # Test-only systemctl shim (only active when FAKE_SYSTEMCTL_LOG is set):
    # every invocation is logged so the CI contract test can assert the
    # systemctl calls; failure injection respects FAKE_DISABLE_FAIL /
    # FAKE_ACTIVE_UNITS. Production runs never set these variables.
    local op=$1
    shift
    printf '%s %s\n' "$op" "$*" >>"$FAKE_SYSTEMCTL_LOG"
    case "$op" in
    disable)
        [[ ${FAKE_DISABLE_FAIL:-0} == 1 ]] && return 1
        ;;
    is-active)
        for unit in "$@"; do
            case " ${FAKE_ACTIVE_UNITS:-} " in
            *" $unit "*) return 0 ;;
            esac
        done
        return 1
        ;;
    esac
    return 0
}

rxa_write_intent_atomic() {
    # Durable intent write: mkdir -> temp file -> fsync file -> atomic rename
    # -> fsync directory. Returns non-zero on ANY failure; a prepare intent
    # that is not durable must never be treated as success (fail-closed).
    local dir=${1:-} content=${2:-} dest=${3:-}
    install -d -m 0750 "$(root "$dir")" 2>/dev/null || return 1
    python3 - "$(root "$dir")" "$content" "$(root "$dest")" <<'PY' || return 1
import os,sys,tempfile
d,content,dest=sys.argv[1:]
fd,tmp=tempfile.mkstemp(prefix='.intent.',dir=d)
try:
    with os.fdopen(fd,'w') as f:
        f.write(content+'\n')
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp,0o640)
    os.replace(tmp,dest)
    dfd=os.open(d,os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    sys.exit(1)
PY
}

rxa_uninstall_prepare() {
    # Two-phase uninstall, phase 1: freeze the agent in observe-only, refresh
    # the last observation, persist a durable uninstall intent and snapshot
    # the runtime state. NOTHING is deleted here: Runtime, audit, config and
    # the observation all stay in place so a failed host uninstall can abort
    # and keep diagnostics.
    #
    # Prepare only succeeds when BOTH the mode freeze AND the durable intent
    # write succeed; a non-durable intent aborts before any host removal.
    local rc=0
    if [[ -f "$RILL_XRAY_AGENT_MANAGER" ]]; then
        # shellcheck disable=SC1090
        source "$RILL_XRAY_AGENT_MANAGER"
        rxa_apply_mode observe-only >/dev/null 2>&1 || rc=1
    fi
    if [[ -x "$RILL_XRAY_AGENT_HOME/scripts/rill_xray_agent_observe.py" ]]; then
        RILL_XRAY_AGENT_OUTPUT="$(root "$RILL_XRAY_AGENT_STATUS")" \
            python3 "$RILL_XRAY_AGENT_HOME/scripts/rill_xray_agent_observe.py" >/dev/null 2>&1 || rc=1
    fi
    rxa_write_intent_atomic \
        "$RILL_XRAY_AGENT_STATE" \
        "{\"schemaVersion\":1,\"intent\":\"uninstall\",\"phase\":\"prepared\",\"atEpochSeconds\":$(date +%s)}" \
        "$RILL_XRAY_AGENT_STATE/uninstall.intent.json" || rc=1
    return "$rc"
}

rxa_uninstall_remove_rill() {
    # Removes Rill units, binaries and runtime dirs. Every critical step
    # contributes to the accumulated return code; nothing is swallowed.
    local rc=0
    if [[ -n ${FAKE_SYSTEMCTL_LOG:-} ]]; then
        rxa_fake_systemctl disable "${RILL_XRAY_AGENT_UNITS[@]}" >>"$FAKE_SYSTEMCTL_LOG" || rc=1
        rxa_fake_systemctl daemon-reload >>"$FAKE_SYSTEMCTL_LOG" 2>/dev/null || true
    else
        systemctl disable --now "${RILL_XRAY_AGENT_UNITS[@]}" >/dev/null 2>&1 || rc=1
        [[ -n "$DESTDIR" ]] || systemctl daemon-reload >/dev/null 2>&1 || rc=1
    fi
    for unit in "${RILL_XRAY_AGENT_UNITS[@]}"; do
        rm -f "$(root "/etc/systemd/system/$unit")" || rc=1
    done
    rm -rf "$(root /opt/rill-xray-agent)" "$(root /run/rill-xray-agent)" \
           "$(root /var/spool/rill-xray-agent-apply)" || rc=1
    if [[ ${1:-0} == 1 ]]; then
        rm -rf \
          "$(root /etc/rill-xray-agent)" \
          "$(root /var/lib/rill-xray-agent-runtime)" \
          "$(root /var/lib/rill-xray-agent-root)" \
          "$(root /var/lib/rill-xray-agent-xray)" || rc=1
    fi
    return "$rc"
}

rxa_uninstall_verify_host() {
    # Post-removal verification: no Rill unit may still be active and no Rill
    # binary may still exist. Any leftover forces the abort path.
    local unit binary failed=0
    for unit in "${RILL_XRAY_AGENT_UNITS[@]}"; do
        if [[ -n ${FAKE_SYSTEMCTL_LOG:-} ]]; then
            rxa_fake_systemctl is-active "$unit" >>"$FAKE_SYSTEMCTL_LOG"
            active=$?
        else
            systemctl is-active --quiet "$unit" 2>/dev/null
            active=$?
        fi
        if [[ $active -eq 0 ]]; then
            echo "Rill 后台服务仍在运行: $unit" >&2
            failed=1
        fi
    done
    for binary in /opt/rill-xray-agent/bin/rill-xray-agent /opt/rill-xray-agent/bin/rill-xray-agent-observe; do
        if [[ -e "$(root "$binary")" ]]; then
            echo "Rill 程序文件仍然存在: $binary" >&2
            failed=1
        fi
    done
    return "$failed"
}

rxa_uninstall_mark() {
    # Append a durable phase marker to the uninstall intent ledger. Fail-closed:
    # ANY marker-write failure returns non-zero so a non-durable committed
    # marker can never be followed by a purge, and a non-durable aborted marker
    # can never turn a host failure into success.
    install -d -m 0750 "$(root "$RILL_XRAY_AGENT_STATE")" 2>/dev/null || return 1
    python3 - "$1" "$(root "$RILL_XRAY_AGENT_STATE/uninstall.intent.json")" "$(root "$RILL_XRAY_AGENT_STATE")" <<'PY' || return 1
import os,sys,tempfile,time
phase,dest,d=sys.argv[1:]
fd,tmp=tempfile.mkstemp(prefix='.mark.',dir=d)
try:
    with os.fdopen(fd,'w') as out:
        try:
            with open(dest,'rb') as existing:
                out.write(existing.read().decode('utf-8','replace'))
        except OSError:
            pass
        out.write('{"schemaVersion":1,"intent":"uninstall","phase":"%s","atEpochSeconds":%d}\n'
                  % (phase, int(time.time())))
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp,0o640)
    os.replace(tmp,dest)
    dfd=os.open(d,os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    sys.exit(1)
PY
}

rxa_uninstall_commit() {
    # Two-phase uninstall, phase 2 (host uninstall fully succeeded): append
    # the completion marker, then remove Rill. The committed marker MUST be
    # durable before any removal begins: a marker-write failure stops here
    # with non-zero and no purge (diagnostics retained).
    rxa_uninstall_mark committed || return 1
    rxa_uninstall_remove_rill 1
}

rxa_uninstall_abort() {
    # Host uninstall failed: keep Runtime, audit, config and observation;
    # record the aborted intent and return the host's real non-zero code.
    # An abort-marker write failure must not turn the host failure into
    # success: the original failure code is always returned.
    rxa_uninstall_mark aborted 2>/dev/null || true
    echo 'Xray 主程序卸载失败；已保留 Rill AI 判断记录与诊断数据' >&2
    return 1
}

# --purge: commit phase invoked by the host uninstaller after its own phase
# fully succeeded. Removal runs here; failures propagate.
if [[ ${1:-} == --purge ]]; then
    rxa_uninstall_commit
    exit $?
fi

# Standalone two-phase uninstall (manager menu / --rill-agent-uninstall):
# prepare -> remove Rill -> verify -> commit or abort. Config and state are
# kept unless --purge is passed to the host, matching the original contract.
if ! rxa_uninstall_prepare; then
    rxa_uninstall_abort
    exit 1
fi
if ! rxa_uninstall_remove_rill 0; then
    rxa_uninstall_abort
    exit 1
fi
if ! rxa_uninstall_verify_host; then
    rxa_uninstall_abort
    exit 1
fi
if ! rxa_uninstall_mark committed; then
    echo 'Rill 卸载完成标记未能可靠写入；本次卸载按失败处理' >&2
    exit 1
fi
echo 'Rill Xray AI 运维助手已卸载；Xray 配置未被修改'
exit 0
