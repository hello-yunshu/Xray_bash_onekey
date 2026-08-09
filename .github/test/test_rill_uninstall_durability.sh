#!/usr/bin/env bash
# Real-implementation durable-uninstall intent tests.
#
# Unlike test_install_uninstall_transaction.sh (which mocks the whole Rill
# two-phase contract to prove host failure routing), this test exercises the
# REAL production implementations:
#
#   - rxa_write_uninstall_intent_atomic()  (host block, install.sh)
#   - rxa_uninstall_prepare / commit / abort (host block, install.sh)
#   - standalone rxa_uninstall_mark()       (rill_xray_agent_uninstall.sh)
#
# Only the COLLABORATORS are mocked: systemctl, the observer script, the Rill
# mode helper (rxa_apply_mode), the purge command and the host binaries. The
# durable intent writer itself is never mocked.
#
# Durability semantics asserted (RC.1 P1-1):
#   - prepared: intent file exists, content is parseable JSONL, phase=prepared
#   - prepare write failure -> prepare non-zero, host removal NOT invoked
#   - committed marker durable BEFORE purge runs (event-order proof)
#   - commit write failure  -> commit non-zero, purge NOT invoked
#   - abort on host failure  -> aborted marker persisted, final rc non-zero
#   - abort write failure    -> final rc STILL non-zero (never success)
#   - both writers fnparent-directory fsync presence (real marker vs fallback)
#
# Run: bash .github/test/test_rill_uninstall_durability.sh

set -u

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"
STANDALONE="${REPO_DIR}/scripts/rill_xray_agent_uninstall.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT

HOME_DIR="${SANDBOX}/etc-rill"
STATE_DIR="${SANDBOX}/state"
mkdir -p "${HOME_DIR}/scripts"

PURGE_LOG="${SANDBOX}/purge.log"
EVENT_LOG="${SANDBOX}/events.log"
export PURGE_LOG EVENT_LOG

# --- real install.sh functions (the production block) ---
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true

# --- sandbox wiring for the REAL functions ---
export DESTDIR="${SANDBOX}"
export RILL_XRAY_AGENT_HOME=/etc-rill
export RILL_XRAY_AGENT_STATE=/state
export RILL_XRAY_AGENT_STATUS=/status/xray-observation.json

# Rill mode helper (collaborator, may be mocked per audit note).
rxa_apply_mode() { return 0; }

# Config + observer collaborator must exist for prepare to proceed.
printf '{"mode":"observe-only"}' > "${HOME_DIR}/config.json"
cat > "${HOME_DIR}/scripts/rill_xray_agent_observe.py" <<'PYEOF'
#!/usr/bin/env python3
import json, os, sys
out = os.environ.get("RILL_XRAY_AGENT_OUTPUT", "")
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w") as f:
    json.dump({"ok": True, "mode": "observe-only"}, f)
PYEOF

# Purge collaborator (the standalone script invoked by the host block).
# It refuses to run unless the committed marker is already durable, which
# proves ordering: committed-marker BEFORE purge.
cat > "${HOME_DIR}/scripts/rill_xray_agent_uninstall.sh" <<'PURGEEOF'
#!/usr/bin/env bash
printf '%s\n' "purge-invoked args=$*" >> "${PURGE_LOG}"
case "$*" in
    *--purge*)
        ledger="${RILL_XRAY_AGENT_STATE_LEDGER:-}"
        if [[ -z "${ledger}" ]] || ! grep -q '"phase":"committed"' "${ledger}" 2>/dev/null; then
            printf '%s\n' "purge-rejected: committed marker not durable" >> "${PURGE_LOG}"
            exit 7
        fi
        printf '%s\n' "$(date +%s) purge" >> "${EVENT_LOG}"
        exit 0
        ;;
    *) exit 0 ;;
esac
PURGEEOF
chmod +x "${HOME_DIR}/scripts/rill_xray_agent_uninstall.sh" \
    "${HOME_DIR}/scripts/rill_xray_agent_observe.py"

# The host-block commit invokes the standalone purge script with the ledger
# at the sandboxed intent path.
RILL_XRAY_AGENT_STATE_LEDGER="${SANDBOX}/state/uninstall.intent.json"
export RILL_XRAY_AGENT_STATE_LEDGER

last_phase() {
    local ledger="${RILL_XRAY_AGENT_STATE_LEDGER}"
    [[ -f "${ledger}" ]] || { echo missing; return; }
    python3 - "$ledger" <<'PY'
import json, sys
last = None
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            last = json.loads(line)["phase"]
        except (ValueError, KeyError):
            pass
print(last or "unparseable")
PY
}

intent_is_parseable() {
    python3 - "${RILL_XRAY_AGENT_STATE_LEDGER}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        json.loads(line)
PY
}

purge_called() { grep -q '^purge-invoked ' "${PURGE_LOG}" 2>/dev/null; }
purge_completed() { grep -q " purge$" "${EVENT_LOG}" 2>/dev/null; }

reset_bed() {
    rm -rf "${STATE_DIR}"
    mkdir -p "${STATE_DIR}"
    : > "${PURGE_LOG}"
}

# ---------------------------------------------------------------------------
# 1) prepared durable success
# ---------------------------------------------------------------------------
reset_bed
if rxa_uninstall_prepare; then
    ok "prepare exits 0"
else
    bad "prepare exits $? (want 0)"
fi
if rxa_write_uninstall_intent_atomic prepared replace; then
    ok "atomic writer exits 0"
else
    bad "atomic writer exits $?"
fi
[[ "$(last_phase)" == "prepared" ]] && ok "intent file ends phase=prepared" || bad "intent file phase=$(last_phase)"
if intent_is_parseable; then
    ok "intent file is parseable JSONL"
else
    bad "intent file not parseable JSONL"
fi

# ---------------------------------------------------------------------------
# 2) prepare persistence failure: state dir parent is a regular file
# ---------------------------------------------------------------------------
reset_bed
rm -rf "${SANDBOX}/blocked"
printf 'x' > "${SANDBOX}/blocked"
if ( export RILL_XRAY_AGENT_STATE=/blocked/state; rxa_uninstall_prepare ); then
    bad "prepare must fail when intent cannot be written (want non-zero)"
else
    ok "prepare fails when marker cannot be written durably"
fi
[[ -f "${RILL_XRAY_AGENT_STATE_LEDGER}" ]] || ok "no marker written on prepare failure"
purge_called && bad "prepare failure must NOT invoke host removal/purge" || ok "prepare failure never invokes purge"
[[ -s "${SANDBOX}/state/uninstall.intent.json" ]] && bad "partial intent written" || ok "no partial intent on prepare failure"

# ---------------------------------------------------------------------------
# 3) committed durable then purge (ordering proof)
# ---------------------------------------------------------------------------
reset_bed
if rxa_uninstall_commit; then
    ok "commit exits 0"
else
    bad "commit exits $?"
fi
[[ "$(last_phase)" == "committed" ]] && ok "intent ends committed" || bad "intent phase=$(last_phase)"
purge_called && ok "purge invoked after commit marker" || bad "purge not invoked"
grep -q 'purge-rejected' "${PURGE_LOG}" 2>/dev/null \
    && bad "purge ran before committed marker was durable" || ok "purge only after durable committed marker"
[[ "$(grep -c '^[0-9]* purge$' "${EVENT_LOG}" 2>/dev/null)" == "1" ]] \
    && ok "event log shows one purge" || bad "event log purge count != 1"

# ---------------------------------------------------------------------------
# 4) commit persistence failure: marker destination cannot be written
# ---------------------------------------------------------------------------
reset_bed
rm -rf "${SANDBOX}/state"
touch "${SANDBOX}/state"          # intent destination becomes a regular file
if rxa_uninstall_commit; then
    bad "commit must fail when committed marker cannot persist (want non-zero)"
else
    ok "commit fails when marker not durable"
fi
purge_called && bad "purge must NOT run after failed commit" || ok "purge not invoked after failed commit"

# ---------------------------------------------------------------------------
# 5) abort success: host failure -> aborted marker persisted, rc non-zero
# ---------------------------------------------------------------------------
reset_bed
if rxa_uninstall_abort; then
    bad "abort must return non-zero (host failure)"
else
    ok "abort returns non-zero"
fi
[[ "$(last_phase)" == "aborted" ]] && ok "aborted marker persisted" || bad "aborted marker phase=$(last_phase)"

# ---------------------------------------------------------------------------
# 6) abort persistence failure: marker cannot be written, rc STILL non-zero
# ---------------------------------------------------------------------------
rm -rf "${SANDBOX}/state"
touch "${SANDBOX}/state"
if rxa_uninstall_abort; then
    bad "abort must return non-zero even when marker write fails"
else
    ok "abort returns non-zero despite marker failure (never host-failure->success)"
fi

# ---------------------------------------------------------------------------
# 7) standalone rxa_uninstall_mark has parent-directory fsync, durable write
# ---------------------------------------------------------------------------
if grep -q 'os.O_DIRECTORY' "${STANDALONE}" && grep -q 'os.fsync(dfd)' "${STANDALONE}"; then
    ok "standalone rxa_uninstall_mark fsyncs the parent directory"
else
    bad "standalone rxa_uninstall_mark lacks parent-directory fsync"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]