#!/usr/bin/env bash
# Two-phase uninstall contract tests.
#
# Coverage:
#   - prepare writes a durable 'prepared' intent and never deletes anything
#   - standalone success path: remove Rill -> verify -> 'committed' marker,
#     Xray config and runtime state are retained
#   - host failure (unit still active) routes to abort: 'aborted' marker,
#     diagnostics retained, non-zero exit
#   - removal failure (systemctl disable fails) aborts with non-zero exit
#   - --purge removes config and state and fails loudly (never `|| true`)
#   - prepare failure aborts before any removal
#
# Run: bash .github/test/test_rill_xray_agent_uninstall.sh

set -u
UNINSTALL="$(cd "$(dirname "$0")/../.." && pwd)/scripts/rill_xray_agent_uninstall.sh"

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

DESTDIR="${TMP_ROOT}/dest"
HOME_DIR="${DESTDIR}/etc/rill-xray-agent"
STATE_DIR="${DESTDIR}/var/lib/rill-xray-agent-runtime"
XRAY_DIR="${DESTDIR}/var/lib/rill-xray-agent-xray"
mkdir -p "${HOME_DIR}/scripts" "${STATE_DIR}" "${XRAY_DIR}" "${DESTDIR}/etc/systemd/system"

for unit in rill-xray-agent-runtime.service rill-xray-agent-agent.service \
    rill-xray-agent-xray-observe.service rill-xray-agent-xray-observe.path \
    rill-xray-agent-xray-observe.timer; do
    printf '[Unit]\n' > "${DESTDIR}/etc/systemd/system/${unit}"
done

cat > "${HOME_DIR}/scripts/rill_xray_agent_observe.py" <<'PYEOF'
#!/usr/bin/env python3
import json, os
os.makedirs(os.path.dirname(os.environ["RILL_XRAY_AGENT_OUTPUT"]), exist_ok=True)
with open(os.environ["RILL_XRAY_AGENT_OUTPUT"], "w") as f:
    json.dump({"ok": True, "mode": "observe-only"}, f)
PYEOF
chmod +x "${HOME_DIR}/scripts/rill_xray_agent_observe.py"

cat > "${HOME_DIR}/scripts/rill_xray_agent_manager.sh" <<'SHEOF'
rxa_apply_mode() {
    [[ "${RXA_STUB_APPLY_MODE_FAIL:-0}" == 1 ]] && return 1
    return 0
}
SHEOF

SYSTEMCTL_LOG="${TMP_ROOT}/systemctl.log"
cat > "${TMP_ROOT}/systemctl" <<'SHEOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${FAKE_SYSTEMCTL_LOG:-/dev/null}"
case "$1" in
    disable)
        [[ "${FAKE_DISABLE_FAIL:-0}" != 1 ]]
        ;;
    is-active)
        local unit=""
        for arg in "$@"; do
            case "$arg" in
                rill-xray-agent-*) unit="$arg" ;;
            esac
        done
        [[ -n "$unit" && "${FAKE_ACTIVE_UNITS:-}" == *"$unit"* ]]
        ;;
    *) exit 0 ;;
esac
SHEOF
chmod +x "${TMP_ROOT}/systemctl"
export PATH="${TMP_ROOT}:${PATH}"

export RILL_XRAY_AGENT_ALLOW_NONROOT=1
export DESTDIR
export FAKE_SYSTEMCTL_LOG="${SYSTEMCTL_LOG}"

# RILL_XRAY_AGENT_STATE/RILL_XRAY_AGENT_STATUS defaults are already correct
# (the script prefixes them with DESTDIR via root()); only the manager and
# home paths that are used verbatim need sandbox overrides.
run_uninstall() {
    env RILL_XRAY_AGENT_MANAGER="${HOME_DIR}/scripts/rill_xray_agent_manager.sh" \
        RILL_XRAY_AGENT_HOME="${HOME_DIR}" \
        bash "${UNINSTALL}" "$@" 2> "${TMP_ROOT}/stderr.txt"
    return $?
}

intent() { grep -o '"phase":"[a-z]*"' "${STATE_DIR}/uninstall.intent.json" | tail -1; }

# --- 1: standalone success ---
printf '' > "${SYSTEMCTL_LOG}"
rm -f "${STATE_DIR}/uninstall.intent.json"
if run_uninstall; then
    ok "standalone uninstall exits 0"
else
    bad "standalone uninstall exits $? (want 0)"
fi
[[ "$(intent)" == '"phase":"committed"' ]] && ok "intent ends committed" || bad "intent ends $(intent)"
[[ -d "${HOME_DIR}" ]] && ok "agent config retained" || bad "agent config removed"
[[ -d "${STATE_DIR}" ]] && ok "runtime state retained" || bad "runtime state removed"
[[ -d "${DESTDIR}/etc/systemd/system" ]] && \
    [[ -z "$(ls "${DESTDIR}/etc/systemd/system")" ]] && ok "all unit files removed" || bad "unit files remain"
grep -q '^disable ' "${SYSTEMCTL_LOG}" && ok "systemctl disable called" || bad "systemctl disable missing"

# --- 2: host failure (unit still active) aborts ---
rm -f "${STATE_DIR}/uninstall.intent.json"
if FAKE_ACTIVE_UNITS="rill-xray-agent-runtime.service" run_uninstall; then
    bad "verify-host failure must exit non-zero"
else
    ok "verify-host failure exits non-zero"
fi
[[ "$(intent)" == '"phase":"aborted"' ]] && ok "intent ends aborted" || bad "intent ends $(intent)"
grep -q 'diagnostics retained' "${TMP_ROOT}/stderr.txt" && ok "abort message on stderr" || bad "abort message missing"

# --- 3: removal failure aborts ---
rm -f "${STATE_DIR}/uninstall.intent.json"
if FAKE_DISABLE_FAIL=1 run_uninstall; then
    bad "removal failure must exit non-zero"
else
    ok "removal failure exits non-zero"
fi
[[ "$(intent)" == '"phase":"aborted"' ]] && ok "intent ends aborted after removal failure" || bad "intent ends $(intent)"

# --- 4: prepare failure aborts before any removal ---
rm -f "${STATE_DIR}/uninstall.intent.json"
if RXA_STUB_APPLY_MODE_FAIL=1 run_uninstall; then
    bad "prepare failure must exit non-zero"
else
    ok "prepare failure exits non-zero"
fi
[[ -d "${DESTDIR}/etc/systemd/system" ]] && ok "no removal before prepare success" || bad "units removed despite prepare failure"

# --- 5: --purge removes config and state, fails loudly ---
rm -f "${STATE_DIR}/uninstall.intent.json"
if run_uninstall --purge; then
    ok "--purge exits 0"
else
    bad "--purge exits $? (want 0)"
fi
[[ -d "${HOME_DIR}" ]] && bad "--purge kept agent config" || ok "--purge removed agent config"
[[ -d "${STATE_DIR}" ]] && bad "--purge kept runtime state" || ok "--purge removed runtime state"

# --- 6: --purge removal failure propagates (never `|| true`) ---
rm -f "${STATE_DIR}/uninstall.intent.json"
if FAKE_DISABLE_FAIL=1 run_uninstall --purge; then
    bad "--purge failure must exit non-zero"
else
    ok "--purge failure exits non-zero"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]
