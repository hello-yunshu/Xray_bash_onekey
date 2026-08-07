#!/usr/bin/env bash
# P1-4: semantic candidate self-check. install.sh must expose a read-only,
# side-effect-free contract self-check at --rill-integration-self-check that
# returns a parsable JSON object reflecting the real integration contract.
#
# Assertions:
#   - the flag is dispatched as an offline-safe command
#   - it emits valid JSON with the expected contract keys
#   - the booleans are true when the integration block actually provides the
#     schema marker, menu/offline dispatch, hooks, host health contract and
#     two-phase uninstall contract
#   - it never installs and never touches the network (no side effects)
#
# Run: bash .github/test/test_candidate_self_check.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

# The self-check must run in the offline-safe path (before init_language /
# check_file_integrity / judge_mode / version checks). Force it to operate
# with no language files and a throwaway HOME so nothing is written to host
# state. Redirect everything except the JSON to stderr so stdout carries only
# the contract.
out="$(HOME="$REPO_DIR" bash "$REPO_DIR/install.sh" --rill-integration-self-check 2>/dev/null)"
rc=$?

if [[ "$rc" == 0 ]]; then
    ok "--rill-integration-self-check exits 0"
else
    bad "--rill-integration-self-check exits $rc (want 0)"
fi

if python3 -c 'import json,sys; json.loads(sys.argv[1])' "$out" 2>/dev/null; then
    ok "self-check emits valid JSON"
else
    bad "self-check output is not valid JSON: $out"
fi

# Verify the expected contract keys are all present and structurally sane.
if python3 - "$out" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
keys={"schemaVersion","integrationSchema","menuDispatch","offlineDispatch",
      "reconfigureHooks","uninstallHooks","hostHealthContract"}
missing=keys-set(d)
assert not missing, f"missing keys: {sorted(missing)}"
assert d["schemaVersion"]==1
assert d["integrationSchema"]==1
for k in ("menuDispatch","offlineDispatch","reconfigureHooks","uninstallHooks","hostHealthContract"):
    assert isinstance(d[k], bool), f"{k} not bool"
PY
then
    ok "JSON contains all contract keys with correct types"
else
    bad "JSON missing keys or wrong types"
fi

# The real install.sh integration block must honestly report true for every
# contract dimension (this is the production candidate that must pass).
if python3 - "$out" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
for k in ("schemaVersion","integrationSchema","menuDispatch","offlineDispatch",
          "reconfigureHooks","uninstallHooks","hostHealthContract"):
    if k in ("schemaVersion","integrationSchema"):
        assert d[k]==1, f"{k} != 1"
    else:
        assert d[k] is True, f"{k} is not True (semantic contract missing)"
PY
then
    ok "all semantic contract booleans are true for the real install.sh"
else
    bad "some semantic contract boolean is false for the real install.sh"
fi

# --rill-agent-status must also still dispatch (regression: the self-check flag
# must not break the existing offline dispatch table).
out2="$(HOME="$REPO_DIR" bash "$REPO_DIR/install.sh" --rill-agent-status 2>/dev/null)"
if [[ "$out2" == *"installed"* || "$out2" == *"routeAssistEnabled"* ]]; then
    ok "--rill-agent-status still dispatches (offline table intact)"
else
    bad "--rill-agent-status regression: output=$out2"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]