#!/usr/bin/env bash
# Phase 4 / P0-6: mode-aware host health check regression tests.
#
# rxa_host_healthy() must return 0 ONLY when every component the active
# install mode requires is verifiably healthy. Untestable states (no
# systemctl / no xray binary / missing or unparseable install_config) are
# NEVER healthy. Modes without NGINX must not require it. Markers and port
# checks gate the result, and rxa_reconfigure_leave restores the prior mode
# only after a full health pass.
#
# The body under test is the canonical integration block, extracted verbatim
# from install.sh (byte-identical to the Rill mirror).
#
# Run: bash .github/test/test_rill_xray_agent_healthy.sh

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

# --- sandbox filesystem ---
FAKE_BIN="${TMP_ROOT}/bin"
CFG="${TMP_ROOT}/install_config.json"
XCONF="${TMP_ROOT}/xray/config.json"
NGFX_CONF="${TMP_ROOT}/nginx/conf/nginx.conf"
NGINX_DIR="${TMP_ROOT}/nginx"
LOGS="${TMP_ROOT}/logs"
mkdir -p "${FAKE_BIN}" "${TMP_ROOT}/xray" "$(dirname "${NGFX_CONF}")" "${LOGS}"
touch "${XCONF}" "${NGFX_CONF}"

# xray binary: run -test honours RXA_X_TFAIL.
cat > "${FAKE_BIN}/xray" <<'XEOF'
#!/usr/bin/env bash
[[ "${RXA_XRAY_FAIL:-0}" == 1 ]] && exit 1
exit 0
XEOF
chmod +x "${FAKE_BIN}/xray"

# nginx binary: -t honours RXA_NGINX_FAIL.
cat > "${FAKE_BIN}/nginx" <<'XEOF'
#!/usr/bin/env bash
[[ "${RXA_NGINX_FAIL:-0}" == 1 ]] && exit 1
exit 0
XEOF
chmod +x "${FAKE_BIN}/nginx"

# systemctl: fake; is-active returns ok only if the unit is in FAKE_ACTIVE.
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

# ss: -ltnH lists listening ports from FAKE_LISTEN (space separated).
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

# health(): run rxa_host_healthy in a clean env; extra envs passed as args.
health() {
    (
        # Prefix assignments (FAKE_ACTIVE=... FAKE_LISTEN=...) are shell
        # locals of the caller; re-export them so the inner bash sees them.
        export FAKE_ACTIVE="${FAKE_ACTIVE:-}"
        export FAKE_LISTEN="${FAKE_LISTEN:-}"
        export PATH="${FAKE_BIN}:${PATH}"
        export INTEGRATION="${INTEGRATION}"
        export RILL_XRAY_AGENT_INSTALL_CONFIG="${CFG}"
        export RILL_XRAY_AGENT_XRAY_BIN="${FAKE_BIN}/xray"
        export RILL_XRAY_AGENT_XRAY_CONF="${XCONF}"
        export RILL_XRAY_AGENT_NGINX_BIN="${FAKE_BIN}/nginx"
        export RILL_XRAY_AGENT_NGINX_CONF="${NGFX_CONF}"
        export RILL_XRAY_AGENT_LOG_DIR="${LOGS}"
        # install.sh globals the block falls back on (kept benign).
        export xray_install_config_file="${CFG}"
        export xray_bin_dir="${FAKE_BIN}"
        export xray_conf="${XCONF}"
        export nginx_dir="${NGINX_DIR}"
        export nginx_conf_dir="$(dirname "${NGFX_CONF}")"
        # honour env overrides passed in
        for e in "$@"; do export "$e"; done
        bash -c 'set -u; source "${INTEGRATION}"; rxa_host_healthy'
    ) 2>/dev/null
    return $?
}

rm_marks() { rm -rf "${LOGS}"; mkdir -p "${LOGS}"; }
FAKE_ACTIVE= FAKE_LISTEN= rm_marks

# ---------- 1: healthy Reality install (no NGINX required) ----------
write_cfg "Reality" "off"
if FAKE_ACTIVE="xray" FAKE_LISTEN="60000" health; then
    ok "Reality-only healthy => 0"
else
    bad "Reality-only healthy => $? (want 0)"
fi

# ---------- 2: healthy TLS+NGINX install (NGINX present) ----------
write_cfg "TLS" "on"
if FAKE_ACTIVE="xray nginx" FAKE_LISTEN="60000 18080 8443 8444" health; then
    ok "TLS+NGINX healthy => 0"
else
    bad "TLS+NGINX healthy => $? (want 0)"
fi

# ---------- 3: NGINX-required mode but NGINX down => 1 ----------
write_cfg "TLS" "on"
if FAKE_ACTIVE="xray" FAKE_LISTEN="18080 8443 8444" health; then
    bad "NGINX-required mode with NGINX down must fail"
else
    ok "NGINX-required mode with NGINX down => non-zero"
fi

# ---------- 4: non-NGINX mode must NOT require NGINX ----------
write_cfg "Reality" "off"
if FAKE_ACTIVE="xray" FAKE_LISTEN="60000" health; then
    ok "Reality-only mode ignores NGINX state => 0"
else
    bad "non-NGINX mode without NGINX => $? (want 0)"
fi

# ---------- 5: systemctl missing (untestable) => 1 ----------
write_cfg "Reality" "off"
NORUN="${TMP_ROOT}/norun"
mkdir -p "${NORUN}"
if env PATH="${NORUN}" INTEGRATION="${INTEGRATION}" \
    RILL_XRAY_AGENT_INSTALL_CONFIG="${CFG}" \
    RILL_XRAY_AGENT_XRAY_BIN="${FAKE_BIN}/xray" \
    RILL_XRAY_AGENT_XRAY_CONF="${XCONF}" \
    RILL_XRAY_AGENT_NGINX_BIN="${FAKE_BIN}/nginx" \
    RILL_XRAY_AGENT_NGINX_CONF="${NGFX_CONF}" \
    RILL_XRAY_AGENT_LOG_DIR="${LOGS}" \
    xray_install_config_file="${CFG}" xray_bin_dir="${FAKE_BIN}" xray_conf="${XCONF}" \
    nginx_dir="${NGINX_DIR}" nginx_conf_dir="$(dirname "${NGFX_CONF}")" \
    FAKE_ACTIVE="xray" FAKE_LISTEN="18080" \
    /bin/bash -c 'set -u; source "${INTEGRATION}"; rxa_host_healthy' _; then
    bad "systemctl missing => 0 (must be untestable => 1)"
else
    ok "systemctl missing => non-zero (never healthy)"
fi

# ---------- 6: xray binary missing => 1 ----------
write_cfg "Reality" "off"
if env PATH="${FAKE_BIN}:${PATH}" INTEGRATION="${INTEGRATION}" \
    RILL_XRAY_AGENT_INSTALL_CONFIG="${CFG}" \
    RILL_XRAY_AGENT_XRAY_BIN="${TMP_ROOT}/missing-xray" \
    RILL_XRAY_AGENT_XRAY_CONF="${XCONF}" \
    RILL_XRAY_AGENT_NGINX_BIN="${FAKE_BIN}/nginx" \
    RILL_XRAY_AGENT_NGINX_CONF="${NGFX_CONF}" \
    RILL_XRAY_AGENT_LOG_DIR="${LOGS}" \
    xray_install_config_file="${CFG}" xray_bin_dir="${FAKE_BIN}" xray_conf="${XCONF}" \
    nginx_dir="${NGINX_DIR}" nginx_conf_dir="$(dirname "${NGFX_CONF}")" \
    FAKE_ACTIVE="xray" FAKE_LISTEN="18080" \
    bash -c 'set -u; source "${INTEGRATION}"; rxa_host_healthy' _; then
    bad "xray binary missing => 0 (must be untestable => 1)"
else
    ok "xray binary missing => non-zero"
fi

# ---------- 7: install_config missing / unparseable => 1 ----------
rm -f "${CFG}"
if FAKE_ACTIVE="xray" FAKE_LISTEN="18080" health; then
    bad "missing install_config => 0 (must be 1)"
else
    ok "missing install_config => non-zero"
fi
printf 'not-json{{{\n' > "${CFG}"
if FAKE_ACTIVE="xray" FAKE_LISTEN="18080" health; then
    bad "unparseable install_config => 0 (must be 1)"
else
    ok "unparseable install_config => non-zero"
fi
write_cfg "Reality" "off"

# ---------- 8: marker file blocks health ----------
for mark in update_failed.mark restore_failed.mark rollback_unverified.mark; do
    touch "${LOGS}/${mark}"
    if FAKE_ACTIVE="xray" FAKE_LISTEN="18080" health; then
        bad "${mark} present => 0 (must be 1)"
    else
        ok "${mark} present => non-zero"
    fi
    rm -f "${LOGS}/${mark}"
done

# ---------- 9: xray -test failure => 1 ----------
if FAKE_ACTIVE="xray" FAKE_LISTEN="18080" RXA_XRAY_FAIL=1 health; then
    bad "xray -test failure => 0 (must be 1)"
else
    ok "xray -test failure => non-zero"
fi

# ---------- 10: port not listening => 1 ----------
if FAKE_ACTIVE="xray" FAKE_LISTEN="99999" health; then
    bad "xray port not listening => 0 (must be 1)"
else
    ok "xray port not listening => non-zero"
fi

# ---------- 11: rxa_reconfigure_leave: restores only after full pass ----------
# leave_case: body uses RC, HHRC, PRIOR_MODE from env; apply_mode recorded.
cat > "${TMP_ROOT}/leave_case.sh" <<'EOF'
#!/usr/bin/env bash
set -u
RJCF="${RILL_XRAY_AGENT_CONFIG}"
PRIOR_FILE="${RJCF}.prior-mode"
printf '%s' "${PRIOR_MODE:-}" > "${PRIOR_FILE}" 2>/dev/null || true
source "${INTEGRATION}"
APPLY=0
rxa_apply_mode() { APPLY=$((APPLY+1)); APPLIED="$1"; }
rxa_host_healthy() { return "${HHRC:-0}"; }
rxa_reconfigure_leave "${RC:-0}" "${PRIOR_FILE}" 2>/dev/null
printf 'rc=%d apply=%d applied=%s\n' "$?" "${APPLY}" "${APPLIED:-none}"
rm -f "${PRIOR_FILE}"
EOF

LAUNCH_L() {
    env PATH="${FAKE_BIN}:${PATH}" INTEGRATION="${INTEGRATION}" \
        RILL_XRAY_AGENT_CONFIG="${TMP_ROOT}/$1-config.json" \
        RC="${2:-0}" HHRC="${3:-0}" PRIOR_MODE="${4:-normal}" \
        bash "${TMP_ROOT}/leave_case.sh" 2>/dev/null
}

# A) rc=0 and healthy -> apply restored prior mode, return 0.
for mode in normal observe-only; do
    out=$(LAUNCH_L "a-${mode}" 0 0 "$mode")
    echo "$out" | grep -q "rc=0 apply=1 applied=${mode}" \
        && ok "leave(rc=0, healthy) restores ${mode}" \
        || bad "leave(rc=0, healthy) not rest ${mode}: '${out}'"
done

# B) rc=0, unhealthy -> non-zero while staying observe-only (apply not called).
out=$(LAUNCH_L b 0 1 normal)
echo "$out" | grep -q 'rc=1 apply=0' \
    && ok "leave(rc=0, unhealthy) => rc=1, no restore" \
    || bad "leave(rc=0, unhealthy): '${out}' want rc=1 apply=0"

# C) rc!=0 (host tx failed) -> by contract the non-fatal hook returns 0 and
#    must NOT restore the prior mode.
out=$(LAUNCH_L c 3 0 normal)
echo "$out" | grep -q 'rc=0 apply=0' \
    && ok "rc!=0 leave: no restore, leave non-fatal (rc=0)" \
    || bad "rc!=0 leave: '${out}' want rc=0 apply=0"

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" == 0 ]]