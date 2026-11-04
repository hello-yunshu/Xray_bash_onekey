#!/usr/bin/env bash
# color-test-fixture: this file intentionally asserts on literal ESC bytes to
# verify the stats renderer's TTY/NO_COLOR policy.
# P3 readout/regression matrix for the stats CLI.
# Requires root, bash, jq, curl, gettext, an Xray binary (XRAY_BIN or PATH),
# and a supported distro (Debian 12 / Ubuntu 24.04 / CentOS Stream 10).
set -uo pipefail

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRIPT="${REPO_DIR}/scripts/xray_stats.sh"
XRAY_BIN="${XRAY_BIN:-$(command -v xray 2>/dev/null || true)}"
if [[ -z "${XRAY_BIN}" || ! -x "${XRAY_BIN}" ]]; then
    echo "xray binary not found; set XRAY_BIN" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "jq not found" >&2
    exit 1
fi
if [[ "$(id -u)" != "0" ]]; then
    echo "run as root" >&2
    exit 1
fi

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/xray-stats-p3.XXXXXX") || exit 1
trap 'rm -rf "${TMP_ROOT}"' EXIT
CONF_DIR="${TMP_ROOT}/conf"
SCRIPTS_DIR="${TMP_ROOT}/scripts"
mkdir -p "${CONF_DIR}" "${SCRIPTS_DIR}" /var/log/xray
CONF="${CONF_DIR}/config.json"
STATUS_CONF="${CONF_DIR}/status_config.json"
BASE_CONF="${TMP_ROOT}/base.json"
PID_FILE="${TMP_ROOT}/xray.pid"
LOG_FILE="${TMP_ROOT}/xray.log"

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1
unset _TEST_MODE

idleleo_dir="${TMP_ROOT}/idleleo"
log_dir="${TMP_ROOT}/logs"
LOG_FILE="${log_dir}/install.log"
mkdir -p "${log_dir}"
xray_conf_dir="${CONF_DIR}"
xray_conf="${CONF}"
xray_status_conf="${STATUS_CONF}"
xray_install_config_file="${TMP_ROOT}/install_config.json"
xray_default_conf="${TMP_ROOT}/default-config.json"
xray_bin_dir=$(dirname "${XRAY_BIN}")
scripts_dir="${SCRIPTS_DIR}"
xray_stats_script="${SCRIPTS_DIR}/xray_stats.sh"
log_echo() { :; }
service_stop() { return 0; }
service_start() { return 0; }
# Keep the real downloader for the checksum-failure case; setup/toggle uses
# a local fixture so no network is required.
eval "$(declare -f download_json_file | sed 's/^download_json_file/real_download_json_file/')"
download_json_file() { cp "${REPO_DIR}/config/status_config.json" "$2"; }

# A syntactically valid Reality config with fixed test-only credentials.
make_base() {
    jq --arg uuid "d2369645-0738-4270-a5eb-ed4fd73f0a48" \
        --arg key "UMu_MWbFB6Dbe_k3i1N3nbfFusN7IQ13TNhYvI3QRH4" \
        '.inbounds[0].settings.clients[0].id = $uuid
         | .inbounds[0].streamSettings.realitySettings.privateKey = $key
         | .inbounds[0].streamSettings.realitySettings.shortIds = ["0123456789abcdef"]' \
        "${REPO_DIR}/config/vless_reality.json" >"${BASE_CONF}"
    cp "${BASE_CONF}" "${CONF}"
    chmod 600 "${CONF}"
    rm -f "${STATUS_CONF}"
}

stop_xray() {
    if [[ -f "${PID_FILE}" ]]; then
        kill "$(cat "${PID_FILE}")" 2>/dev/null || true
        rm -f "${PID_FILE}"
    fi
    sleep 1
}

start_xray() {
    stop_xray
    nohup "${XRAY_BIN}" run -config "${CONF}" >"${LOG_FILE}" 2>&1 &
    echo $! >"${PID_FILE}"
    sleep 1
    if ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        tail -3 "${LOG_FILE}" >&2 || true
        return 1
    fi
}

port_listener() {
    awk '$2 ~ /:2765$/ {print $2}' /proc/net/tcp 2>/dev/null
}

run_script() {
    local out="$1" err="$2"
    shift 2
    XRAY_STATS_BIN="${XRAY_BIN}" bash "${SCRIPT}" --config "${CONF}" "$@" >"${out}" 2>"${err}"
}

stdout_zero() {
    [[ $(wc -l <"$1") -eq 0 ]]
}

echo "== enable and query =="
make_base
printf 'y\n' | xray_status_add >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "enable rc=0" || bad "enable failed"
[[ "$(jq -r '.api.listen // empty' "${CONF}")" == "127.0.0.1:10085" ]] && \
    ok "api.listen is loopback 10085" || bad "api.listen wrong"
"${XRAY_BIN}" run -test -config "${CONF}" >/dev/null 2>&1 && \
    ok "xray -test after enable" || bad "xray -test after enable"
start_xray || bad "xray did not start after enable"
[[ -n "$(port_listener)" ]] && ok "10085 listener present" || bad "10085 listener absent"

run_script "${TMP_ROOT}/q.out" "${TMP_ROOT}/q.err"
[[ $? -eq 0 ]] && ok "query rc=0" || bad "query rc!=0"
grep -qE "运行时长|Uptime:" "${TMP_ROOT}/q.out" && grep -q "VLESS-Reality-in" "${TMP_ROOT}/q.out" && \
    ok "table has uptime and inbound" || bad "table missing fields"
grep -q "暂无流量" "${TMP_ROOT}/q.out" && \
    ok "zero-traffic table explains there is no traffic" || bad "zero-traffic empty-state missing"
width=$(LC_ALL=C.UTF-8 bash -c '
    max=0
    while IFS= read -r line; do
        n=${#line}
        (( n > max )) && max=$n
    done < "$1"
    printf "%s" "${max}"
' _ "${TMP_ROOT}/q.out")
[[ "${width}" -le 80 ]] && ok "table width ${width} <= 80 characters" || bad "table width ${width}"

for requested_width in 100 120; do
    XRAY_STATS_WIDTH="${requested_width}" XRAY_STATS_BIN="${XRAY_BIN}" \
        bash "${SCRIPT}" --config "${CONF}" >"${TMP_ROOT}/w${requested_width}.out" 2>"${TMP_ROOT}/w${requested_width}.err"
    [[ $? -eq 0 ]] && ok "width ${requested_width} query rc=0" || bad "width ${requested_width} query rc!=0"
    measured=$(LC_ALL=C.UTF-8 bash -c '
        max=0
        while IFS= read -r line; do
            n=${#line}
            (( n > max )) && max=$n
        done < "$1"
        printf "%s" "${max}"
    ' _ "${TMP_ROOT}/w${requested_width}.out")
    expected=$((requested_width - 1))
    [[ "${measured}" -le "${expected}" ]] && \
        ok "width ${requested_width} stays within ${expected} characters" || \
        bad "width ${requested_width} rendered ${measured} characters"
done

run_script "${TMP_ROOT}/j.out" "${TMP_ROOT}/j.err" --json
[[ $? -eq 0 ]] && jq -e '.schemaVersion == 1 and .server == "127.0.0.1:10085" and (.inbounds | type == "array") and (.uptimeSeconds | numbers) and (.reset == false)' "${TMP_ROOT}/j.out" >/dev/null && \
    ok "--json contract valid" || bad "--json contract invalid"

if command -v gettext >/dev/null 2>&1; then
    TEXTDOMAINDIR="${REPO_DIR}/i18n/languages" XRAY_STATS_LANG=en XRAY_STATS_BIN="${XRAY_BIN}" \
        bash "${SCRIPT}" --config "${CONF}" >"${TMP_ROOT}/en.out" 2>"${TMP_ROOT}/en.err"
    [[ $? -eq 0 ]] && grep -q "Overview" "${TMP_ROOT}/en.out" && \
        ok "English catalog renders English headings" || bad "English catalog missing"
    TEXTDOMAINDIR="${REPO_DIR}/i18n/languages" XRAY_STATS_LANG=zh XRAY_STATS_BIN="${XRAY_BIN}" \
        bash "${SCRIPT}" --config "${CONF}" >"${TMP_ROOT}/zh.out" 2>"${TMP_ROOT}/zh.err"
    [[ $? -eq 0 ]] && grep -q "总览" "${TMP_ROOT}/zh.out" && \
        ok "Chinese catalog renders Chinese headings" || bad "Chinese catalog missing"
else
    echo "  SKIP: gettext unavailable for the catalog checks"
fi

if command -v script >/dev/null 2>&1; then
    TERM=xterm-256color script -q -c \
        "XRAY_STATS_BIN='${XRAY_BIN}' bash '${SCRIPT}' --config '${CONF}'" /dev/null \
        >"${TMP_ROOT}/color.out" 2>"${TMP_ROOT}/color.err"
    grep -q $'\033' "${TMP_ROOT}/color.out" && \
        ok "pseudo-TTY table contains ANSI colours" || bad "pseudo-TTY table has no ANSI colours"
    NO_COLOR=1 TERM=xterm-256color script -q -c \
        "NO_COLOR=1 XRAY_STATS_BIN='${XRAY_BIN}' bash '${SCRIPT}' --config '${CONF}'" /dev/null \
        >"${TMP_ROOT}/nocolor.out" 2>"${TMP_ROOT}/nocolor.err"
    grep -q $'\033' "${TMP_ROOT}/nocolor.out" && \
        bad "NO_COLOR table still contains ANSI" || ok "NO_COLOR table contains no ANSI"
    TERM=dumb script -q -c \
        "TERM=dumb XRAY_STATS_BIN='${XRAY_BIN}' bash '${SCRIPT}' --config '${CONF}'" /dev/null \
        >"${TMP_ROOT}/dumb.out" 2>"${TMP_ROOT}/dumb.err"
    grep -q $'\033' "${TMP_ROOT}/dumb.out" && \
        bad "TERM=dumb table still contains ANSI" || ok "TERM=dumb table contains no ANSI"
    grep -q $'\033' "${TMP_ROOT}/q.out" && \
        bad "non-TTY table contains ANSI" || ok "non-TTY table contains no ANSI"
else
    echo "  SKIP: script(1) unavailable for the colour matrix"
fi

run_script "${TMP_ROOT}/q2.out" "${TMP_ROOT}/q2.err"
sed -E '/运行时长|Uptime:/d' "${TMP_ROOT}/q.out" >"${TMP_ROOT}/q.norm"
sed -E '/运行时长|Uptime:/d' "${TMP_ROOT}/q2.out" >"${TMP_ROOT}/q2.norm"
cmp -s "${TMP_ROOT}/q.norm" "${TMP_ROOT}/q2.norm" && ok "repeat query identical (uptime excluded)" || bad "repeat query differs"

echo "== reset =="
printf 'n\n' | XRAY_STATS_BIN="${XRAY_BIN}" bash "${SCRIPT}" --config "${CONF}" --reset >"${TMP_ROOT}/rc.out" 2>"${TMP_ROOT}/rc.err"
[[ $? -eq 1 ]] && stdout_zero "${TMP_ROOT}/rc.out" && ok "reset cancel rc=1, stdout empty" || bad "reset cancel contract"
printf 'y\n' | XRAY_STATS_BIN="${XRAY_BIN}" bash "${SCRIPT}" --config "${CONF}" --reset --json >"${TMP_ROOT}/ry.out" 2>"${TMP_ROOT}/ry.err"
[[ $? -eq 0 ]] && jq -e '.reset == true and (.inbounds | type == "array")' "${TMP_ROOT}/ry.out" >/dev/null && \
    ok "reset confirm rc=0, reset=true" || bad "reset confirm contract"
run_script "${TMP_ROOT}/qa.out" "${TMP_ROOT}/qa.err" --json
jq -e '.reset == false and (.inbounds[]?.uplinkBytes == 0) and (.inbounds[]?.downlinkBytes == 0)' "${TMP_ROOT}/qa.out" >/dev/null && \
    ok "post-reset re-query zero" || bad "post-reset counters"

echo "== watch =="
timeout --preserve-status -s INT 1 bash "${SCRIPT}" --config "${CONF}" --watch 1 >"${TMP_ROOT}/watch.out" 2>"${TMP_ROOT}/watch.err"
[[ $? -eq 130 ]] && ok "watch SIGINT rc=130" || bad "watch rc != 130"

echo "== failure states: stdout must be empty =="
stop_xray
run_script "${TMP_ROOT}/down.out" "${TMP_ROOT}/down.err"
[[ $? -eq 2 ]] && stdout_zero "${TMP_ROOT}/down.out" && ok "API down rc=2, stdout empty" || bad "API down rc/empty"

jq 'del(.api.listen)' "${CONF}" >"${TMP_ROOT}/no-listen.json"
cp "${TMP_ROOT}/no-listen.json" "${CONF}"
chmod 600 "${CONF}"
run_script "${TMP_ROOT}/nl.out" "${TMP_ROOT}/nl.err"
[[ $? -eq 2 ]] && stdout_zero "${TMP_ROOT}/nl.out" && ok "no api.listen rc=2, stdout empty" || bad "no api.listen rc/empty"

make_base
printf 'y\n' | xray_status_add >/dev/null 2>&1
printf 'y\n' | xray_status_add >/dev/null 2>&1
run_script "${TMP_ROOT}/off.out" "${TMP_ROOT}/off.err"
[[ $? -eq 2 ]] && stdout_zero "${TMP_ROOT}/off.out" && ok "stats disabled rc=2, stdout empty" || bad "stats disabled rc/empty"

make_base
printf 'y\n' | xray_status_add >/dev/null 2>&1
start_xray || bad "xray restart failed"
cat >"${TMP_ROOT}/fake-xray" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '{"bad":1}'
EOF
chmod +x "${TMP_ROOT}/fake-xray"
XRAY_STATS_BIN="${TMP_ROOT}/fake-xray" bash "${SCRIPT}" --config "${CONF}" >"${TMP_ROOT}/bad.out" 2>"${TMP_ROOT}/bad.err"
[[ $? -eq 3 ]] && stdout_zero "${TMP_ROOT}/bad.out" && ok "bad JSON rc=3, stdout empty" || bad "bad JSON rc/empty"

echo "== migration =="
stop_xray
make_base
printf 'y\n' | xray_status_add >/dev/null 2>&1
cp "${CONF}" "${TMP_ROOT}/enabled.json"
jq 'del(.api.listen)' "${TMP_ROOT}/enabled.json" >"${CONF}"
chmod 600 "${CONF}"
old_sha=$(sha256sum "${CONF}" | awk '{print $1}')
xray_stats_listen_ensure >/dev/null 2>&1
[[ $? -eq 0 ]] && [[ "$(jq -r '.api.listen // empty' "${CONF}")" == "127.0.0.1:10085" ]] && \
    ok "legacy migration added listen" || bad "legacy migration"
"${XRAY_BIN}" run -test -config "${CONF}" >/dev/null 2>&1 && \
    ok "xray -test after migration" || bad "xray -test after migration"
start_xray || bad "xray after migration"
run_script "${TMP_ROOT}/m.out" "${TMP_ROOT}/m.err"
[[ $? -eq 0 ]] && grep -q "VLESS-Reality-in" "${TMP_ROOT}/m.out" && \
    ok "query after migration" || bad "query after migration"

echo "== port occupied and rollback =="
stop_xray
jq 'del(.api.listen)' "${TMP_ROOT}/enabled.json" >"${CONF}"
chmod 600 "${CONF}"
port_sha=$(sha256sum "${CONF}" | awk '{print $1}')
cat >"${TMP_ROOT}/occupier.json" <<'EOF'
{"inbounds":[{"listen":"127.0.0.1","port":10085,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"freedom"}]}
EOF
nohup "${XRAY_BIN}" run -config "${TMP_ROOT}/occupier.json" >/dev/null 2>&1 &
occ_pid=$!
sleep 1
xray_stats_listen_ensure >/dev/null 2>&1
[[ $? -ne 0 ]] && [[ "$(sha256sum "${CONF}" | awk '{print $1}')" == "${port_sha}" ]] && \
    ok "occupied port rejected, bytes unchanged" || bad "occupied port"
kill "${occ_pid}" 2>/dev/null || true
sleep 1

jq 'del(.api.listen) | .inbounds[0].streamSettings.realitySettings.privateKey = "bad"' \
    "${TMP_ROOT}/enabled.json" >"${CONF}"
chmod 600 "${CONF}"
bad_sha=$(sha256sum "${CONF}" | awk '{print $1}')
xray_stats_listen_ensure >/dev/null 2>&1
[[ $? -ne 0 ]] && [[ "$(sha256sum "${CONF}" | awk '{print $1}')" == "${bad_sha}" ]] && \
    ok "failed migration restored bytes" || bad "failed migration rollback"

echo "== non-root =="
if command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid=65534 --regid=65534 --clear-groups env XRAY_STATS_BIN="${XRAY_BIN}" \
        bash "${SCRIPT}" --config "${CONF}" >"${TMP_ROOT}/nr.out" 2>"${TMP_ROOT}/nr.err"
    [[ $? -eq 5 ]] && stdout_zero "${TMP_ROOT}/nr.out" && ok "non-root rc=5, stdout empty" || bad "non-root contract"
else
    bad "setpriv unavailable for non-root check"
fi

echo "== helper checksum failure, toggle unaffected =="
make_base
printf 'y\n' | xray_status_add >/dev/null 2>&1
printf 'y\n' | xray_status_add >/dev/null 2>&1
release="${TMP_ROOT}/release/releases/download/v${shell_version}"
mkdir -p "${release}" "${SCRIPTS_DIR}"
cp "${SCRIPT}" "${release}/xray_stats.sh"
printf '{"schemaVersion":1,"version":"%s","statsScriptSha256":"%064d"}\n' "${shell_version}" 0 >"${release}/release-manifest.json"
rm -f "${xray_stats_script}"
command -v curl >/dev/null 2>&1 || bad "curl missing for checksum case"
# Restore the real downloader for this one case.
download_json_file() { real_download_json_file "$@"; }
XRAY_QUALIFICATION_MODE=1 SHELL_RELEASE_BASE_OVERRIDE="file://${TMP_ROOT}/release" \
    xray_stats_cli stats >"${TMP_ROOT}/cs.out" 2>"${TMP_ROOT}/cs.err"
[[ $? -eq 2 ]] && stdout_zero "${TMP_ROOT}/cs.out" && ok "checksum failure rc=2, stdout empty" || bad "checksum failure"
download_json_file() { cp "${REPO_DIR}/config/status_config.json" "$2"; }
printf 'y\n' | xray_status_add >/dev/null 2>&1
printf 'y\n' | xray_status_add >/dev/null 2>&1
[[ "$(jq -r '.stats // "null"' "${CONF}")" == "null" ]] && \
    ok "toggle still works after checksum failure" || bad "toggle after checksum failure"

echo "Summary: PASS=${PASS} FAIL=${FAIL}"
[[ ${FAIL} -eq 0 ]]
