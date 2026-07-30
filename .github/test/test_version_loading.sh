#!/usr/bin/env bash
# Regression tests for resilient, non-contaminating online version loading.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { printf '%s\n' "$*"; }
gettext() { printf '%s' "$1"; }

versions_json='{
  "shell_online_version": "2026.7.29",
  "xray_online_version": "26.3.27",
  "nginx_build_online_version": "2026.06.17.6717",
  "shell_tested_version": "2026.7.28",
  "xray_tested_version": "26.3.27",
  "nginx_build_tested_version": "2026.06.17.6717"
}'

printf '%s\n' '--- CDN fallback and single-fetch cache ---'
curl_log="${TMP_ROOT}/curl.log"
curl() {
    local arg
    local url=""
    for arg in "$@"; do
        case "${arg}" in
            http://*|https://*) url="${arg}" ;;
        esac
    done
    printf '%s\n' "${url}" >>"${curl_log}"
    case "${url}" in
        *cdn.jsdelivr.net*) return 22 ;;
        *raw.githubusercontent.com*)
            printf '%s' "${versions_json}"
            return 0
            ;;
        *) return 22 ;;
    esac
}

get_versions_all=""
_get_versions_loaded=0
if read_version &&
    [[ "${shell_online_version:-}" == "2026.7.29" ]] &&
    [[ "${xray_online_version:-}" == "26.3.27" ]] &&
    [[ "${nginx_build_version:-}" == "2026.06.17.6717" ]]; then
    ok "origin fallback supplies every mandatory version"
else
    bad "origin fallback did not supply mandatory versions"
fi

if [[ "$(wc -l <"${curl_log}" | tr -d ' ')" == "2" ]] &&
    grep -Fq "cdn.jsdelivr.net" "${curl_log}" &&
    grep -Fq "raw.githubusercontent.com" "${curl_log}"; then
    ok "CDN failure performs exactly one origin fallback"
else
    bad "version loading did not use the expected two-source sequence"
fi

if read_version && [[ "$(wc -l <"${curl_log}" | tr -d ' ')" == "2" ]]; then
    ok "subsequent field reads reuse the in-shell version cache"
else
    bad "cached version data triggered additional network requests"
fi

printf '%s\n' '--- fail-closed output separation ---'
curl() { return 22; }
get_versions_all=""
_get_versions_loaded=0
shell_online_version="preserve-shell"
xray_online_version="preserve-xray"
nginx_build_version="preserve-nginx"
failure_stdout="${TMP_ROOT}/failure.stdout"
failure_stderr="${TMP_ROOT}/failure.stderr"

if read_version >"${failure_stdout}" 2>"${failure_stderr}"; then
    bad "complete source failure returned success"
else
    ok "complete source failure returns nonzero"
fi

if [[ ! -s "${failure_stdout}" ]] && grep -Fq "在线版本检测失败" "${failure_stderr}"; then
    ok "failure diagnostics stay off version-data stdout"
else
    bad "failure diagnostics contaminated version-data stdout"
fi

if [[ "${shell_online_version}" == "preserve-shell" ]] &&
    [[ "${xray_online_version}" == "preserve-xray" ]] &&
    [[ "${nginx_build_version}" == "preserve-nginx" ]]; then
    ok "failed reads do not partially overwrite prior versions"
else
    bad "failed reads partially overwrote prior versions"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
