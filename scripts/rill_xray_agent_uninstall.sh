#!/usr/bin/env bash
set -euo pipefail
# RILL_XRAY_AGENT_ALLOW_NONROOT is a test-only escape hatch (never set by
# production paths) so CI runners without root can exercise the full flow
# against a DESTDIR sandbox.
if [[ ${RILL_XRAY_AGENT_ALLOW_NONROOT:-0} != 1 ]] && [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo 'root required' >&2
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
    rill-xray-agent-xray-observe.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer)

rxa_uninstall_prepare() {
    # Two-phase uninstall, phase 1: freeze the agent in observe-only, refresh
    # the last observation, persist a durable uninstall intent and snapshot
    # the runtime state. NOTHING is deleted here: Runtime, audit, config and
    # the observation all stay in place so a failed host uninstall can abort
    # and keep diagnostics.
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
    install -d -m 0750 "$(root "$RILL_XRAY_AGENT_STATE")"
    printf '{"schemaVersion":1,"intent":"uninstall","phase":"prepared","atEpochSeconds":%s}\n' \
        "$(date +%s)" > "$(root "$RILL_XRAY_AGENT_STATE/uninstall.intent.json")" 2>/dev/null || rc=1
    return "$rc"
}

rxa_uninstall_remove_rill() {
    # Removes Rill units, binaries and runtime dirs. Every critical step
    # contributes to the accumulated return code; nothing is swallowed.
    local rc=0
    systemctl disable --now "${RILL_XRAY_AGENT_UNITS[@]}" >/dev/null 2>&1 || rc=1
    for unit in "${RILL_XRAY_AGENT_UNITS[@]}"; do
        rm -f "$(root "/etc/systemd/system/$unit")" || rc=1
    done
    rm -rf "$(root /opt/rill-xray-agent)" "$(root /run/rill-xray-agent)" || rc=1
    if [[ ${1:-0} == 1 ]]; then
        rm -rf \
          "$(root /etc/rill-xray-agent)" \
          "$(root /var/lib/rill-xray-agent-runtime)" \
          "$(root /var/lib/rill-xray-agent-root)" \
          "$(root /var/lib/rill-xray-agent-xray)" || rc=1
    fi
    [[ -n "$DESTDIR" ]] || systemctl daemon-reload >/dev/null 2>&1 || rc=1
    return "$rc"
}

rxa_uninstall_verify_host() {
    # Post-removal verification: no Rill unit may still be active and no Rill
    # binary may still exist. Any leftover forces the abort path.
    local unit binary failed=0
    for unit in "${RILL_XRAY_AGENT_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            echo "Rill Xray Agent: unit still active: $unit" >&2
            failed=1
        fi
    done
    for binary in /opt/rill-xray-agent/bin/rill-xray-agent /opt/rill-xray-agent/bin/rill-xray-agent-observe; do
        if [[ -e "$(root "$binary")" ]]; then
            echo "Rill Xray Agent: binary still present: $binary" >&2
            failed=1
        fi
    done
    return "$failed"
}

rxa_uninstall_mark() {
    # Append a durable phase marker to the uninstall intent ledger. Marker
    # writes are best-effort; they never hide a real removal failure.
    install -d -m 0750 "$(root "$RILL_XRAY_AGENT_STATE")" 2>/dev/null || true
    printf '{"schemaVersion":1,"intent":"uninstall","phase":"%s","atEpochSeconds":%s}\n' \
        "${1:-}" "$(date +%s)" >> "$(root "$RILL_XRAY_AGENT_STATE/uninstall.intent.json")" 2>/dev/null || true
}

rxa_uninstall_commit() {
    # Two-phase uninstall, phase 2 (host uninstall fully succeeded): append
    # the completion marker, then remove Rill. A failure here returns non-zero
    # and is never masked with `|| true`.
    rxa_uninstall_mark committed
    rxa_uninstall_remove_rill 1
}

rxa_uninstall_abort() {
    # Host uninstall failed: keep Runtime, audit, config and observation;
    # record the aborted intent and return the host's real non-zero code.
    rxa_uninstall_mark aborted
    echo 'Rill Xray Agent: host uninstall failed; agent diagnostics retained' >&2
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
rxa_uninstall_mark committed
echo 'Rill Xray Agent removed; Xray configuration was not modified'
exit 0
