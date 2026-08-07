#!/usr/bin/env bash
# P0-3: production Nginx health default-path regression tests.
#
# rxa_host_healthy() must derive the Nginx main config from the real host
# variable nginx_main_conf (the compile-prefix main config), NEVER by guessing
# "${nginx_conf_dir}/nginx.conf" (that dir holds only managed fragments like
# 00-xray.conf). This test runs WITHOUT the RILL_XRAY_AGENT_NGINX_CONF and
# RILL_XRAY_AGENT_NGINX_BIN overrides so the production default path is what
# actually gets exercised.
#
# Scenarios:
#   * TLS + Nginx      -> nginx required, healthy when the derived main-cfg
#                          path exists and nginx passes -t
#   * Reality + Nginx  -> nginx required, healthy
#   * Reality-only     -> nginx NOT required, healthy without nginx present
#   * XTLS-only        -> nginx NOT required, healthy without nginx present
#   * Wrong-path guard -> a fragment dir that contains nginx.conf is NOT used;
#                          the derived nginx_main_conf path is authoritative.
#
# Run: bash .github/test/test_nginx_health_production_defaults.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT
ok()  { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# Canonical block from install.sh (the shipped integration).
INTEGRATION="${TMP_ROOT}/integration.sh"
awk '/^# BEGIN RILL XRAY AGENT INTEGRATION/,/^# END RILL XRAY AGENT INTEGRATION/' \
    "${REPO_DIR}/install.sh" > "${INTEGRATION}"
grep -q 'rxa_host_healthy()' "${INTEGRATION}" || { echo "integration extraction failed"; exit 99; }

# --- sandbox filesystem (production layout) ---
# nginx maintained at compile-prefix /usr/local/nginx (nginx_dir); main config
# lives directly under conf/nginx.conf (nginx_main_conf). The fragment dir
# (nginx_conf_dir) is a separate managed-fragment location.
FAKE_BIN="${TMP_ROOT}/bin"
TARGET="${TMP_ROOT}/usr/local"
NGINX_BIN="${TARGET}/nginx/sbin/nginx"
NGINX_MAIN_CONF="${TARGET}/nginx/conf/nginx.conf"   # == nginx_main_conf
FRAG_DIR="${TMP_ROOT}/etc/idleleo/conf/nginx"       # == nginx_conf_dir (fragments)
XCONF="${TMP_ROOT}/xray/config.json"
CFG="${TMP_ROOT}/install_config.json"
LOGS="${TMP_ROOT}/logs"
mkdir -p "${FAKE_BIN}" "${TARGET}/nginx/sbin" "$(dirname "${NGINX_MAIN_CONF}")" \
         "${FRAG_DIR}" "$(dirname "${XCONF}")" "${LOGS}"
touch "${NGINX_MAIN_CONF}" "${XCONF}"

# nginx binary: -t FAILS if RXA_NGINX_FAIL set or the -c config file is absent,
# so the production default path is genuinely validated.
cat > "${FAKE_BIN}/nginx" <<'XEOF'
#!/usr/bin/env bash
[[ "${RXA_NGINX_FAIL:-0}" == 1 ]] && exit 1
cfg=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c) cfg="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -n "${cfg}" && ! -f "${cfg}" ]]; then
    echo "nginx: config file test failed" >&2
    exit 1
fi
exit 0
XEOF
chmod +x "${FAKE_BIN}/nginx"
# Real nginx binary at the production path.
cp "${FAKE_BIN}/nginx" "${NGINX_BIN}"
chmod +x "${NGINX_BIN}"

# xray binary: -test honours RXA_XRAY_FAIL.
cat > "${FAKE_BIN}/xray" <<'XEOF'
#!/usr/bin/env bash
[[ "${RXA_XRAY_FAIL:-0}" == 1 ]] && exit 1
exit 0
XEOF
chmod +x "${FAKE_BIN}/xray"

# systemctl: is-active true only for units in FAKE_ACTIVE.
cat > "${FAKE_BIN}/systemctl" <<'XEOF'
#!/usr/bin/env bash
unit=""
for arg in "$@"; do
    case "$arg" in
        -q|--quiet|is-active) continue ;;
        *) unit="$arg" ;;
    esac
done
[[ " ${FAKE_ACTIVE:-} " == *" ${unit} "* ]]
XEOF
chmod +x "${FAKE_BIN}/systemctl"

# ss: -ltnH lists ports from FAKE_LISTEN.
cat > "${FAKE_BIN}/ss" <<'XEOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-ltnH" ]]; then
    for p in ${FAKE_LISTEN:-}; do
        printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:*\n' "$p"
    done
fi
exit 0
XEOF
chmod +x "${FAKE_BIN}/ss"

write_cfg() {
    # $1 tls value, $2 reality, $3 port, $4.. extra key=val
    local tls="$1" reality="${2:-off}" port="${3:-60000}"
    local extra=""
    shift 3 2>/dev/null || set --
    for kv in "$@"; do extra="${extra},\"${kv%%=*}\":${kv#*=}"; done
    printf '{"schemaVersion":1,"tls":"%s","reality_add_nginx":"%s","port":%s,"ws_port":18080,"grpc_port":8443,"xhttp_port":8444%s}\n' \
        "$tls" "$reality" "$port" "$extra" > "${CFG}"
}

# health(): run rxa_host_healthy WITHOUT nginx cfg/bin overrides so the
# production default path in nginx_main_conf is exercised. Host globals
# (nginx_dir, nginx_main_conf, xray_bin_dir, xray_install_config_file) are
# exported so the block falls back on them exactly as in production.
health() {
    (
        export FAKE_ACTIVE="${FAKE_ACTIVE:-}"
        export FAKE_LISTEN="${FAKE_LISTEN:-}"
        export PATH="${FAKE_BIN}:${PATH}"
        export INTEGRATION="${INTEGRATION}"
        export RILL_XRAY_AGENT_INSTALL_CONFIG="${CFG}"
        export RILL_XRAY_AGENT_XRAY_BIN="${FAKE_BIN}/xray"
        export RILL_XRAY_AGENT_XRAY_CONF="${XCONF}"
        export RILL_XRAY_AGENT_LOG_DIR="${LOGS}"
        # production host globals (no RILL_XRAY_AGENT_NGINX_* overrides)
        export xray_install_config_file="${CFG}"
        export xray_bin_dir="${FAKE_BIN}"
        export xray_conf="${XCONF}"
        export nginx_dir="${TARGET}/nginx"
        export nginx_main_conf="${NGINX_MAIN_CONF}"
        export nginx_conf_dir="${FRAG_DIR}"
        for e in "$@"; do export "$e"; done
        bash -c 'set -u; source "${INTEGRATION}"; rxa_host_healthy'
    ) 2>/dev/null
    return $?
}

rm_marks() { rm -rf "${LOGS}"; mkdir -p "${LOGS}"; }
FAKE_ACTIVE= FAKE_LISTEN= rm_marks

# ---------- 1: TLS + Nginx, production default path -> healthy ----------
write_cfg "TLS" "on"
if FAKE_ACTIVE="xray nginx" FAKE_LISTEN="60000 18080 8443 8444" health; then
    ok "TLS+Nginx production default path => 0"
else
    bad "TLS+Nginx production default path => $? (want 0)"
fi

# ---------- 2: Reality + Nginx, production default path -> healthy ----------
write_cfg "Reality" "on"
if FAKE_ACTIVE="xray nginx" FAKE_LISTEN="60000 18080 8443 8444" health; then
    ok "Reality+Nginx production default path => 0"
else
    bad "Reality+Nginx production default path => $? (want 0)"
fi

# ---------- 3: Reality-only does NOT require Nginx ----------
write_cfg "Reality" "off"
if FAKE_ACTIVE="xray" FAKE_LISTEN="60000" health; then
    ok "Reality-only ignores Nginx => 0"
else
    bad "Reality-only without Nginx => $? (want 0)"
fi

# ---------- 4: XTLS-only does NOT require Nginx ----------
write_cfg "none" "off"
if FAKE_ACTIVE="xray" FAKE_LISTEN="60000" health; then
    ok "XTLS/none-only ignores Nginx => 0"
else
    bad "XTLS/none-only without Nginx => $? (want 0)"
fi

# ---------- 5: wrong-path guard: fragment dir is NOT the main config ----------
# The fragment dir (nginx_conf_dir) contains a nginx.conf; the real main-cfg
# path (nginx_main_conf) is removed. Health must FAIL because the block uses
# nginx_main_conf, not "${nginx_conf_dir}/nginx.conf".
write_cfg "TLS" "on"
printf 'bad-fragment\n' > "${FRAG_DIR}/nginx.conf"     # decoy, must be ignored
cp "${NGINX_MAIN_CONF}" "${NGINX_MAIN_CONF}.bak"
rm -f "${NGINX_MAIN_CONF}"
if FAKE_ACTIVE="xray nginx" FAKE_LISTEN="60000 18080 8443 8444" health; then
    bad "nginx_main_conf missing but fragment-decoys present => 0 (must fail)"
else
    ok "nginx_main_conf missing => non-zero (fragment dir decoy ignored)"
fi
mv "${NGINX_MAIN_CONF}.bak" "${NGINX_MAIN_CONF}"
rm -f "${FRAG_DIR}/nginx.conf"

# ---------- 6: nginx -t failure at production default path => 1 ----------
write_cfg "TLS" "on"
if FAKE_ACTIVE="xray nginx" FAKE_LISTEN="18080 8443 8444" RXA_NGINX_FAIL=1 health; then
    bad "nginx -t failure at production path => 0 (must be 1)"
else
    ok "nginx -t failure at production path => non-zero"
fi

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]