#!/usr/bin/env bash
# Stage 04: auto-update retry policy and metadata source fallback.
#
# The updater is exercised as a real subprocess with stubbed curl/install.sh so
# the assertions are about its behaviour, not about string matching in a file.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
suite() { printf '\n-- %s --\n' "$1"; }

STUB_BIN="${TMP_ROOT}/bin"
mkdir -p "${STUB_BIN}"

# --- stubs -----------------------------------------------------------------
cat >"${STUB_BIN}/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"${STUB_BIN}/curl" <<'EOF'
#!/usr/bin/env bash
url=""
for arg in "$@"; do
    case "${arg}" in
        http://*|https://*) url="${arg}" ;;
    esac
done
printf '%s\n' "${url}" >>"${CURL_LOG}"
case "${url}" in
    *cdn.jsdelivr.net*)
        [[ "${FAIL_CDN:-0}" == "1" ]] && exit 22
        printf '%s' "${CDN_JSON}"
        ;;
    *raw.githubusercontent.com*)
        [[ "${FAIL_RAW:-0}" == "1" ]] && exit 22
        printf '%s' "${RAW_JSON}"
        ;;
    *) exit 22 ;;
esac
EOF
chmod +x "${STUB_BIN}/curl" "${STUB_BIN}/flock"

export IDLELEO_TEST_MODE=1
export IDLELEO_TEST_PATH="${STUB_BIN}:${PATH}"
export IDLELEO_UPDATE_LOCK_FILE="${TMP_ROOT}/run/update.lock"

versions_json='{"shell_online_version":"3.2.11","xray_online_version":"26.10.31","nginx_build_online_version":"2026.10.15.7679"}'

# Fresh, isolated installation root for one scenario.
new_root() {
    root="${TMP_ROOT}/case$((++CASE_ID))"
    mkdir -p "${root}/conf/xray" "${root}/logs" "${root}/scripts" "${root}/bin"
    cp "${REPO_DIR}/scripts/auto_update.sh" "${root}/scripts/auto_update.sh"
    cat >"${root}/install.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${INSTALL_LOG}"
if [[ "$*" == "-x"* && -n "${FAIL_XRAY:-}" ]]; then
    exit "${FAIL_XRAY}"
fi
exit 0
EOF
    chmod +x "${root}/install.sh"
    printf '#!/bin/sh\nexit 0\n' >"${root}/bin/xray"
    chmod +x "${root}/bin/xray"
    mkdir -p "${root}/nginx/sbin"
    printf '#!/bin/sh\nexit 0\n' >"${root}/nginx/sbin/nginx"
    chmod +x "${root}/nginx/sbin/nginx"
    printf '{}' >"${root}/conf/xray/config.json"
    printf '3.2.11' >"${root}/release-managed.version"
    cat >"${root}/conf/install_config.json" <<'EOF'
{"shell_version":"3.2.11","xray_version":"26.1.1","nginx_build_version":"2026.01.01.1"}
EOF
    export IDLELEO_DIR="${root}"
    export IDLELEO_LOG_DIR="${root}/logs"
    export IDLELEO_XRAY_BIN="${root}/bin/xray"
    export IDLELEO_NGINX_DIR="${root}/nginx"
    export INSTALL_LOG="${root}/calls.log"
    export CURL_LOG="${root}/curl.log"
    : >"${INSTALL_LOG}"
    : >"${CURL_LOG}"
}

run_update() {
    bash "${IDLELEO_DIR}/scripts/auto_update.sh"
}

log_has() { grep -Fq "$1" "${IDLELEO_LOG_DIR}/auto_update.log"; }

CASE_ID=0

# ---------------------------------------------------------------------------
suite "A. legacy .xray/.nginx markers no longer block"
new_root
touch "${root}/logs/update_failed.mark.xray" "${root}/logs/update_failed.mark.nginx"
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}" FAIL_CDN=0 FAIL_RAW=0
run_update
rc=$?
if [[ ${rc} -eq 0 ]]; then ok "a run with legacy markers succeeds"; else bad "legacy markers aborted the run (rc=${rc})"; fi
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}" && grep -Fq -- "-n auto_update" "${INSTALL_LOG}"; then
    ok "legacy markers do not stop the Xray/Nginx updates"
else
    bad "legacy markers still stopped an update: $(tr '\n' ' ' <"${INSTALL_LOG}")"
fi
if [[ ! -f "${root}/logs/update_failed.mark.xray" && ! -f "${root}/logs/update_failed.mark.nginx" ]]; then
    ok "legacy markers are removed after migration"
else
    bad "legacy markers were left behind"
fi
if log_has "Removed legacy xray failure marker"; then ok "migration is logged"; else bad "migration was not logged"; fi

# ---------------------------------------------------------------------------
suite "B. the same failed target version is not retried"
new_root
cat >"${root}/logs/update_failed.json" <<'EOF'
{"xray":{"version":"26.10.31","failed_at":"2026-11-01T10:00:00Z"}}
EOF
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}"
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then
    bad "the same failed Xray target was retried"
else
    ok "the same failed Xray target is skipped"
fi
if log_has "xray v26.10.31 already failed"; then ok "the skip names the failed version"; else bad "the skip reason is not actionable"; fi
if log_has "Manual retry: jq 'del(.xray)'"; then ok "manual retry instructions are logged"; else bad "no manual retry instructions"; fi
if grep -Fq -- "-n auto_update" "${INSTALL_LOG}"; then
    ok "an unrelated component (Nginx) still updates"
else
    bad "the Xray failure blocked the Nginx update"
fi

# ---------------------------------------------------------------------------
suite "C. a new target version retries"
new_root
cat >"${root}/logs/update_failed.json" <<'EOF'
{"xray":{"version":"26.10.30","failed_at":"2026-11-01T10:00:00Z"}}
EOF
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}"
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then ok "a new Xray target is retried"; else bad "a new target was blocked by an older failure"; fi
if log_has "Recorded xray failure was for v26.10.30"; then ok "the retry explains itself"; else bad "the retry is not logged"; fi

# ---------------------------------------------------------------------------
suite "D. failure is recorded for the failed target and cleared on success"
new_root
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}" FAIL_XRAY=1
run_update
recorded=$(jq -r '.xray.version // empty' "${root}/logs/update_failed.json" 2>/dev/null)
if [[ "${recorded}" == "26.10.31" ]]; then ok "a failed update records component and target version"; else bad "failure not recorded (got '${recorded}')"; fi
if [[ -n "$(jq -r '.xray.failed_at // empty' "${root}/logs/update_failed.json" 2>/dev/null)" ]]; then
    ok "the record carries a timestamp"
else
    bad "the record has no timestamp"
fi
: >"${INSTALL_LOG}"
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then bad "second run retried the recorded target"; else ok "second run respects the record"; fi
unset FAIL_XRAY
: >"${INSTALL_LOG}"
rm -f "${root}/logs/update_failed.json"
run_update
if [[ ! -s "${root}/logs/update_failed.json" ]] || [[ "$(jq -r '.xray // empty' "${root}/logs/update_failed.json" 2>/dev/null)" == "" ]]; then
    ok "a successful update clears the record"
else
    bad "a successful update left a stale record"
fi

# ---------------------------------------------------------------------------
suite "E. CDN failure falls back to GitHub Raw"
new_root
export CDN_JSON="garbage" RAW_JSON="${versions_json}" FAIL_CDN=1 FAIL_RAW=0
run_update
if [[ "$(wc -l <"${CURL_LOG}" | tr -d ' ')" -ge 2 ]] &&
    grep -Fq "cdn.jsdelivr.net" "${CURL_LOG}" && grep -Fq "raw.githubusercontent.com" "${CURL_LOG}"; then
    ok "the CDN failure triggers exactly one Raw fallback"
else
    bad "fallback sequence unexpected: $(tr '\n' ' ' <"${CURL_LOG}")"
fi
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then ok "the update proceeds on fallback metadata"; else bad "fallback metadata was not used"; fi
if log_has "using GitHub Raw fallback"; then ok "the fallback is logged"; else bad "the fallback is silent"; fi

# ---------------------------------------------------------------------------
suite "F. untrusted or incomplete metadata is rejected"
new_root
export FAIL_CDN=0 FAIL_RAW=0
export CDN_JSON='{"shell_online_version":"3.2.11"}' RAW_JSON='not-json-at-all'
run_update
rc=$?
if [[ ${rc} -eq 0 ]]; then ok "a fully invalid metadata run exits cleanly"; else bad "invalid metadata produced rc=${rc}"; fi
if [[ -s "${INSTALL_LOG}" ]]; then bad "an update ran on rejected metadata"; else ok "no update ran on rejected metadata"; fi
if log_has "jsDelivr and GitHub Raw both failed or returned an untrusted payload"; then ok "the rejection is logged"; else bad "the rejection reason is missing"; fi

new_root
export CDN_JSON='{"shell_online_version":"3.2.11"}' RAW_JSON="${versions_json}"
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then ok "an incomplete CDN payload falls through to Raw"; else bad "incomplete payload stopped the fallback"; fi

new_root
export CDN_JSON='{"shell_online_version":"3.2.11","xray_online_version":"26.10.31","nginx_build_online_version":"latest"}'
export RAW_JSON='{"shell_online_version":"3.2.11","xray_online_version":"26.10.31","nginx_build_online_version":"latest"}'
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then bad "a non-version Nginx target was accepted"; else ok "a malformed version field is rejected"; fi
if log_has "jsDelivr unavailable or invalid"; then ok "the malformed field is explained"; else bad "no explanation for the malformed field"; fi

# ---------------------------------------------------------------------------
suite "G. relay node updates the script and Nginx only"
new_root
cat >"${root}/conf/install_config.json" <<'EOF'
{"shell_version":"3.2.11","role":"relay","relay_target":"127.0.0.1:443","nginx_build_version":"2026.01.01.1"}
EOF
rm -f "${root}/bin/xray" "${root}/conf/xray/config.json"
export CDN_JSON='{"shell_online_version":"3.2.11","nginx_build_online_version":"2026.10.15.7679"}' RAW_JSON="${CDN_JSON}"
export FAIL_CDN=0 FAIL_RAW=0
run_update
rc=$?
if [[ ${rc} -eq 0 ]]; then ok "relay run exits successfully"; else bad "relay run failed with rc=${rc}"; fi
if grep -Fq -- "-n auto_update" "${INSTALL_LOG}"; then ok "relay still updates Nginx"; else bad "relay did not update Nginx"; fi
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then bad "relay attempted an Xray update"; else ok "relay never attempts an Xray update"; fi
if log_has "Relay node: Xray is not installed by design"; then ok "missing Xray is reported as not applicable"; else bad "relay Xray handling is not explicit"; fi
if [[ -f "${root}/logs/update_failed.json" ]] && jq -e '.xray' "${root}/logs/update_failed.json" >/dev/null 2>&1; then
    bad "relay recorded a phantom Xray failure"
else
    ok "relay records no Xray failure"
fi

# ---------------------------------------------------------------------------
suite "H. an older metadata target never downgrades the host"
new_root
cat >"${root}/conf/install_config.json" <<'EOF'
{"shell_version":"3.2.11","xray_version":"26.10.31","nginx_build_version":"2026.10.15.7679"}
EOF
export CDN_JSON='{"shell_online_version":"3.2.11","xray_online_version":"26.9.30","nginx_build_online_version":"2026.10.15.7679"}'
export RAW_JSON="${CDN_JSON}" FAIL_CDN=0 FAIL_RAW=0
run_update
rc=$?
if [[ ${rc} -eq 0 ]]; then ok "a regressed target exits cleanly"; else bad "a regressed target failed the run (rc=${rc})"; fi
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then
    bad "26.10.31 was replaced by the older 26.9.30"
else
    ok "26.9.30 is not installed over 26.10.31"
fi
if log_has "newer than the metadata target 26.9.30; refusing to downgrade"; then
    ok "the refusal states both versions"
else
    bad "the downgrade refusal is not logged"
fi
if [[ -f "${root}/logs/update_failed.json" ]] && jq -e '.xray' "${root}/logs/update_failed.json" >/dev/null 2>&1; then
    bad "a refused downgrade was recorded as an update failure"
else
    ok "a refused downgrade is not recorded as a failure"
fi

# 26.10.4 -> 26.10.31 is an upgrade; a string comparison would call it a
# downgrade because "4" sorts after "3".
new_root
cat >"${root}/conf/install_config.json" <<'EOF'
{"shell_version":"3.2.11","xray_version":"26.10.4","nginx_build_version":"2026.10.15.7679"}
EOF
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}"
run_update
if grep -Fq -- "-x auto_update" "${INSTALL_LOG}"; then
    ok "26.10.4 -> 26.10.31 is treated as an upgrade"
else
    bad "a numerically newer target was skipped as a downgrade"
fi
if log_has "refusing to downgrade"; then bad "26.10.4 -> 26.10.31 was misread as a downgrade"; else ok "no false downgrade for 26.10.4"; fi

# The same guard covers Nginx builds (2026.01.01.1 -> 2026.10.15.7679 is newer).
new_root
cat >"${root}/conf/install_config.json" <<'EOF'
{"shell_version":"3.2.11","xray_version":"26.10.31","nginx_build_version":"2026.11.01.9000"}
EOF
export CDN_JSON="${versions_json}" RAW_JSON="${versions_json}"
run_update
if grep -Fq -- "-n auto_update" "${INSTALL_LOG}"; then
    bad "an older Nginx build replaced a newer one"
else
    ok "an older Nginx target is refused"
fi
if log_has "newer than the metadata target 2026.10.15.7679; refusing to downgrade"; then
    ok "the Nginx refusal is logged"
else
    bad "the Nginx downgrade refusal is not logged"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
