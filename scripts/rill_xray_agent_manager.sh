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

rxa_candidate_guard() {
    # Validates a freshly downloaded install.sh candidate before it is ever
    # allowed to replace the running script. Returns 0 only when every
    # integration anchor and the shell syntax check succeed.
    local candidate=${1:-} block rtmp rc
    [[ -f "${candidate}" ]] || return 1
    bash -n "${candidate}" 2>/dev/null || return 1
    grep -qx '^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=1$' "${candidate}" || return 1
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
            for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
                rxa_systemctl is-active --quiet "$unit" || return 1
            done
            rxa_observe_valid || return 1
        else
            for unit in rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
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

    # Phase 1: config + Runtime committed through the Runtime WAL.
    rxa_runtime mode "$mode" >/dev/null || return 1
    if ! rxa_verify_runtime_mode "$mode"; then
        rxa_runtime mode "$old" >/dev/null 2>&1 || true
        return 1
    fi

    # Phase 2: systemd unit states for the target mode. The runtime unit is
    # part of the enabled set so a fresh observe-only install really starts
    # the whole stack, not just the Runtime.
    if ((want_units)); then
        rxa_systemctl enable --now rill-xray-agent-runtime.service >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-agent.service >/dev/null 2>&1 || rc=1
        rxa_systemctl enable --now rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer >/dev/null 2>&1 || rc=1
        if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
            for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service rill-xray-agent-xray-observe.path rill-xray-agent-xray-observe.timer; do
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

rxa_verify_live_contract() {
    # Single, mode-aware live verification contract shared by the manager menu
    # (Verify), the CLI (--rill-agent-verify), rill_xray_agent_verify.sh and CI.
    # Safe-disabled is verified per its own mode contract (Runtime stays down,
    # dependent units inactive), NOT by forcing every unit active.
    #
    # Verifies: committed config defaults (routeAssist=false, boundedAuto=false),
    # Runtime WAL mode == config mode, Runtime + Agent sockets present, and full
    # target-state convergence for the configured mode (config string, Runtime
    # mode, systemd unit states, observation freshness).
    rxa_config_init
    [[ "$(rxa_get routeAssistEnabled)" == false ]] || return 1
    [[ "$(rxa_get boundedAutoAllowed)" == false ]] || return 1
    local mode
    mode=$(rxa_get mode)
    [[ -n "$mode" ]] || return 1
    rxa_mode_state_matches_target "$mode" || return 1
    # Sockets must be present and owned sanely for live systems.
    if [[ ${RILL_XRAY_AGENT_NO_SYSTEMD:-0} != 1 ]]; then
        local sock
        for sock in /run/rill-xray-agent/runtime.sock /run/rill-xray-agent/agent.sock; do
            [[ -S "$sock" ]] || return 1
        done
    fi
    return 0
}

rxa_verify() {
    rxa_verify_live_contract
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
