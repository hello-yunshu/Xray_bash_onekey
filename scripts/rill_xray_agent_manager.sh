#!/usr/bin/env bash
set -o pipefail

RILL_XRAY_AGENT_HOME=${RILL_XRAY_AGENT_HOME:-/etc/rill-xray-agent}
RILL_XRAY_AGENT_CONFIG=${RILL_XRAY_AGENT_CONFIG:-${RILL_XRAY_AGENT_HOME}/config.json}
RILL_XRAY_AGENT_STATUS=${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}
RILL_XRAY_AGENT_CLI=${RILL_XRAY_AGENT_CLI:-/opt/rill-xray-agent/bin/rill-xray-agent}
RILL_XRAY_AGENT_HEADER_STATE='Agent: not installed'
RILL_XRAY_AGENT_HEADER_RUNTIME='Runtime: OFF'
RILL_XRAY_AGENT_HEADER_ROUTE='Route: OFF'
export RILL_XRAY_AGENT_HEADER_STATE RILL_XRAY_AGENT_HEADER_RUNTIME RILL_XRAY_AGENT_HEADER_ROUTE

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
print(json.load(open(sys.argv[1])).get(sys.argv[2],''))
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
    "$RILL_XRAY_AGENT_CLI" --json "$@"
}

rxa_candidate_guard() {
    # Validates a freshly downloaded install.sh candidate before it is ever
    # allowed to replace the running script. Returns 0 only when every
    # integration anchor and the shell syntax check succeed.
    local candidate=${1:-}
    [[ -f "${candidate}" ]] || return 1
    bash -n "${candidate}" 2>/dev/null || return 1
    grep -q '^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=' "${candidate}" || return 1
    grep -q 'menu_item 9 "Rill Xray Agent"' "${candidate}" || return 1
    grep -q -- '--rill-agent-status' "${candidate}" || return 1
    grep -q 'rxa_reconfigure_enter()' "${candidate}" || return 1
    grep -q 'rxa_uninstall_finish()' "${candidate}" || return 1
    grep -q 'rxa_host_healthy()' "${candidate}" || return 1
    return 0
}

rxa_verify_runtime_mode() {
    local expected=${1:-} got
    got=$(rxa_runtime config 2>/dev/null | python3 -c 'import json,sys
try:
    d=json.load(sys.stdin)
    d=d.get("result") or d
    print(d.get("mode",""))
except Exception:
    pass') || true
    [[ "$got" == "$expected" ]]
}

rxa_observe_fresh() {
    local observer=${RILL_XRAY_AGENT_OBSERVER:-$RILL_XRAY_AGENT_HOME/scripts/rill_xray_agent_observe.py}
    local status=${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}
    python3 "$observer" >/dev/null 2>&1 || return 1
    python3 - "$status" <<'PY' || return 1
import json,sys,time
try:
    data=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
now=time.time()
assert data.get('capturedAtEpochSeconds',0) >= now - 3600, 'observation.stale'
assert 'xrayConfig' in data and 'services' in data
PY
}

rxa_apply_mode() {
    # Mode switch is a four-party transaction: config, Runtime service,
    # systemd units and the xray observation snapshot must all agree on the
    # new mode before the config is committed; any failure rolls everything
    # back to the previous mode.
    local mode=${1:-} old rc=0 unit want_units=0
    case "$mode" in normal|observe-only) want_units=1 ;; safe-disabled) want_units=0 ;; *) return 64 ;; esac
    rxa_config_init
    old=$(rxa_get mode)
    [[ -z "${old}" ]] && old=observe-only
    [[ "${old}" == "${mode}" ]] && return 0

    # Phase 1: config + Runtime committed through the Runtime WAL.
    rxa_runtime mode "$mode" >/dev/null || return 1
    if ! rxa_verify_runtime_mode "$mode"; then
        rxa_runtime mode "$old" >/dev/null 2>&1 || true
        return 1
    fi

    # Phase 2: systemd unit states for the target mode.
    if ((want_units)); then
        rxa_systemctl enable --now rill-xray-agent-agent.service >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || rc=1
        if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
            for unit in rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
                rxa_systemctl is-active --quiet "$unit" || rc=1
            done
        fi
    else
        rxa_systemctl disable --now \
          rill-xray-agent-agent.service \
          rill-xray-agent-xray-observe.path \
          rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || rc=1
        if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
            for unit in rill-xray-agent-agent.service rill-xray-agent-xray-observe.path; do
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
    fi

    # Phase 4: commit the persisted config only after every party verified.
    if ((rc == 0)); then
        rxa_set mode "$mode"
        [[ "$(rxa_get mode)" == "$mode" ]] || rc=1
    fi

    if ((rc != 0)); then
        # Roll back Runtime, systemd units and config to the previous mode.
        rxa_runtime mode "$old" >/dev/null 2>&1 || true
        if [[ "$old" == safe-disabled ]]; then
            rxa_systemctl disable --now \
              rill-xray-agent-agent.service \
              rill-xray-agent-xray-observe.path \
              rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || true
        else
            rxa_systemctl enable --now rill-xray-agent-agent.service >/dev/null 2>&1 || true
            rxa_systemctl enable --now rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || true
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

rxa_refresh_summary() {
    local status mode
    status=$(rxa_status_json 2>/dev/null) || return 0
    mode=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["mode"])' <<<"$status")
    RILL_XRAY_AGENT_HEADER_STATE="Agent: $mode"
    RILL_XRAY_AGENT_HEADER_RUNTIME="Runtime: $(rxa_systemctl is-active --quiet rill-xray-agent-runtime.service && echo ON || echo OFF)"
    RILL_XRAY_AGENT_HEADER_ROUTE="Route: $(rxa_get routeStage) · Assist OFF"
}

rxa_verify() {
    rxa_config_init
    [[ "$(rxa_get routeAssistEnabled)" == false ]]
    [[ "$(rxa_get boundedAutoAllowed)" == false ]]
    local mode runtime_mode
    mode=$(rxa_get mode)
    runtime_mode=$(rxa_runtime config 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("result") or d).get("mode",""))') || return 1
    [[ "$mode" == "$runtime_mode" ]]
}

rxa_menu() {
    local choice
    scripts_dir=${scripts_dir:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}
    while true; do
        menu_submenu_begin "Rill Xray Agent"
        menu_item 1 "Status"
        menu_item 2 "Install or repair"
        menu_item 3 "Mode: normal"
        menu_item 4 "Mode: observe-only"
        menu_item 5 "Safe disable"
        menu_item 6 "Verify"
        menu_item 7 "Uninstall"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read choice 7
        case $choice in
            0) return ;;
            1) rxa_status_json; menu_pause ;;
            2) bash "${scripts_dir}/rill_xray_agent_install.sh"; menu_pause ;;
            3) rxa_apply_mode normal; menu_pause ;;
            4) rxa_apply_mode observe-only; menu_pause ;;
            5) rxa_apply_mode safe-disabled; menu_pause ;;
            6) rxa_verify; menu_pause ;;
            7) bash "${scripts_dir}/rill_xray_agent_uninstall.sh"; return ;;
        esac
    done
}

rxa_dispatch() {
    case "${1:-status}" in
        status) rxa_status_json ;;
        install) bash "${scripts_dir}/rill_xray_agent_install.sh" ;;
        mode) rxa_apply_mode "${2:-}" ;;
        safe-disable) rxa_apply_mode safe-disabled ;;
        verify) rxa_verify ;;
        uninstall) bash "${scripts_dir}/rill_xray_agent_uninstall.sh" ;;
        *) return 64 ;;
    esac
}
