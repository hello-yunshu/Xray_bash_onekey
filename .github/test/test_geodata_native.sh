#!/usr/bin/env bash
#
# Stage 03 regression tests: native GeoData download + hot reload.
#
# The installer no longer schedules `geo_update.sh` for normal nodes. Xray owns
# the schedule through a root-level `geodata` block, so this suite covers:
#
#   A. the generated block itself (cron shape, HTTPS assets, Loyalsoldier
#      source, idempotent merge, custom blocks preserved)
#   B. asset layout: both .dat files must be real regular files inside the
#      directory the running Xray actually resolves
#   C. permissions: only the asset directory/files are opened up, config and
#      keys keep their mode
#   D. cron de-duplication: only the entry this project created is removed
#   E. role scoping and install-chain wiring (relay never gets GeoData; the
#      official installer's `install -m 644` is answered by a re-apply)
#   F. traffic_blocker reporting: the native path never presents the legacy
#      geo_version.json as proof that a scheduled run succeeded
#
# No root, no Xray binary and no network access are required: the Xray CLI is a
# controllable stub, `chown` is recorded instead of applied, and crontab is a
# file-backed shim. Root-only probes are skipped with an explicit message.
#
# Usage: bash .github/test/test_geodata_native.sh

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"
TRAFFIC_SH="${REPO_DIR}/scripts/traffic_blocker.sh"
GEO_UPDATE_SH="${REPO_DIR}/scripts/geo_update.sh"

PASS=0
FAIL=0
SKIP=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP: %s\n' "$1"; }
check() {
    local desc="$1"
    shift
    if "$@"; then ok "${desc}"; else bad "${desc}"; fi
}
check_not() {
    local desc="$1"
    shift
    if "$@"; then bad "${desc}"; else ok "${desc}"; fi
}
fn_has() { declare -f "$1" 2>/dev/null | grep -qF -- "$2"; }
fn_lacks() { ! fn_has "$1" "$2"; }

[[ -f "${INSTALL_SH}" ]] || {
    echo "FATAL: ${INSTALL_SH} not found"
    exit 1
}

# ---- macOS portability: GNU `stat -c` is what update_json_config uses --------
if ! stat -c '%a' / >/dev/null 2>&1; then
    stat() {
        case "${1:-}" in
            -c)
                case "${2:-}" in
                    '%a') shift 2 && command stat -f '%Lp' "$@" ;;
                    '%u') shift 2 && command stat -f '%u' "$@" ;;
                    '%g') shift 2 && command stat -f '%g' "$@" ;;
                    '%Y') shift 2 && command stat -f '%m' "$@" ;;
                    '%s') shift 2 && command stat -f '%z' "$@" ;;
                    *) command stat "$@" ;;
                esac
                ;;
            *) command stat "$@" ;;
        esac
    }
fi

# ---- environment stubs (must exist before sourcing) -------------------------
log_echo() { :; }
gettext() { printf '%s' "$1"; }
judge() { return 0; }
systemctl() { return 0; }
Error=""
RedBG=""
OK=""
GreenBG=""
Font=""
Warning=""
YellowBG=""
Green=""
Red=""
Info=""

export _TEST_MODE=1
# shellcheck source=/dev/null
source "${INSTALL_SH}" >/dev/null 2>&1 || true
unset _TEST_MODE

echo "============================================================"
echo "  Stage 03: native GeoData download + hot reload"
echo "============================================================"

# ---- redirect every managed path into the temp root ------------------------
idleleo_dir="${TMP_ROOT}/idleleo"
local_bin="${TMP_ROOT}/usr/local"
xray_bin_dir="${TMP_ROOT}/bin"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
xray_default_conf="${local_bin}/etc/xray/config.json"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
xray_systemd_file="${TMP_ROOT}/systemd/xray.service"
geo_update_file="${idleleo_dir}/scripts/geo_update.sh"
geodata_dir="${idleleo_dir}/share/xray"
mkdir -p "${xray_conf_dir}" "${xray_bin_dir}" "$(dirname "${xray_systemd_file}")" \
    "${geodata_dir}" "${idleleo_dir}/scripts" "${local_bin}/share" \
    "${xray_default_conf%/*}"

# `info_extraction` needs associative arrays (bash 4+); the dev host runs 3.2.
info_extraction() {
    jq -r --arg k "$1" '.[$k] // empty' "${xray_install_config_file}" 2>/dev/null
}
_info_cache_invalidate() { :; }

# ---- Xray CLI stub: records XRAY_LOCATION_ASSET, returns a chosen rc --------
cat >"${xray_bin_dir}/xray" <<'STUB'
#!/bin/sh
if [ "$1" = "run" ]; then
    [ -n "${GEO_TEST_ASSET_FILE:-}" ] && printf '%s' "${XRAY_LOCATION_ASSET:-}" >"${GEO_TEST_ASSET_FILE}"
    n=$(( $(cat "${GEO_TEST_COUNT_FILE:-/dev/null}" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "${n}" >"${GEO_TEST_COUNT_FILE:-/dev/null}" 2>/dev/null
    rc="${GEO_TEST_RC:-0}"
    # GEO_TEST_PLAN="0,1" makes the first call pass and the second fail, which
    # is how the rollback path (ours broke the config) gets exercised.
    if [ -n "${GEO_TEST_PLAN:-}" ]; then
        rc=$(printf '%s' "${GEO_TEST_PLAN}" | cut -d, -f"${n}")
        [ -n "${rc}" ] || rc=0
    fi
    exit "${rc}"
fi
echo "Xray 26.10.31 (stub)"
STUB
chmod +x "${xray_bin_dir}/xray"
export GEO_TEST_ASSET_FILE="${TMP_ROOT}/asset-arg.txt"
export GEO_TEST_COUNT_FILE="${TMP_ROOT}/test-calls.txt"
GEO_TEST_RC=0
export GEO_TEST_RC

set_geo_plan() {
    GEO_TEST_PLAN="$1"
    export GEO_TEST_PLAN
    : >"${GEO_TEST_COUNT_FILE}"
}


# ---- chown is recorded, never applied (tests run unprivileged) --------------
GEO_CHOWN_LOG="${TMP_ROOT}/chown.log"
chown() {
    printf '%s %s\n' "$1" "$2" >>"${GEO_CHOWN_LOG}"
    return 0
}

# ---- crontab shim with on-disk state ---------------------------------------
GEO_CRONTAB="${TMP_ROOT}/crontab.txt"
# Real crontab writes a temp spool file and replaces it, so a
# `crontab -l | ... | crontab -` pipeline never truncates its own input. The
# shim must do the same or it manufactures a race the product does not have.
crontab() {
    local incoming
    case "${1:-}" in
        -l) cat "${GEO_CRONTAB}" 2>/dev/null ;;
        -)
            incoming="${GEO_CRONTAB}.incoming.$$"
            cat >"${incoming}" && mv -f "${incoming}" "${GEO_CRONTAB}"
            ;;
        *) return 1 ;;
    esac
}
: >"${GEO_CRONTAB}"

reset_geo() {
    rm -rf "${geodata_dir}" "${TMP_ROOT}/usr/local/share/xray"
    mkdir -p "${geodata_dir}" "${local_bin}/share"
    printf 'DAT-IP\n' >"${geodata_dir}/geoip.dat"
    printf 'DAT-SITE\n' >"${geodata_dir}/geosite.dat"
    ln -sfn "${geodata_dir}" "${local_bin}/share/xray"
    cat >"${xray_systemd_file}" <<'UNIT'
[Service]
User=nobody
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
UNIT
    printf '{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}\n' >"${xray_conf}"
    chmod 600 "${xray_conf}"
    : >"${GEO_CHOWN_LOG}"
    : >"${GEO_CRONTAB}"
    GEO_TEST_RC=0
    unset GEO_TEST_PLAN
    : >"${GEO_TEST_COUNT_FILE}"
    node_role="node"
    rm -f "${GEO_TEST_ASSET_FILE}"
}

echo ""
echo "-- A. generated geodata block --"
reset_geo

_geo_json=$(geodata_managed_json)
check "managed block is valid JSON" jq -e . >/dev/null 2>&1 <<<"${_geo_json}"
check "cron uses the standard five fields" \
    test "$(jq -r '.cron' <<<"${_geo_json}" | awk '{print NF}')" = "5"
check "cron keeps the legacy weekly cadence" \
    test "$(jq -r '.cron' <<<"${_geo_json}")" = "0 3 * * 1"
check "both assets are declared" test "$(jq -r '.assets | length' <<<"${_geo_json}")" = "2"
check "geoip.dat asset is present" \
    jq -e '.assets[] | select(.file == "geoip.dat")' >/dev/null 2>&1 <<<"${_geo_json}"
check "geosite.dat asset is present" \
    jq -e '.assets[] | select(.file == "geosite.dat")' >/dev/null 2>&1 <<<"${_geo_json}"
check "every asset URL is HTTPS" \
    test "$(jq -r '[.assets[].url | startswith("https://")] | all' <<<"${_geo_json}")" = "true"
check "assets keep the Loyalsoldier source (routing semantics unchanged)" \
    test "$(jq -r '[.assets[].url | contains("Loyalsoldier/v2ray-rules-dat")] | all' <<<"${_geo_json}")" = "true"
check "asset entries use the documented 'file' field" \
    test "$(jq -r '[.assets[] | has("file")] | all' <<<"${_geo_json}")" = "true"
check_not "no undocumented 'destination' field is emitted" \
    jq -e '.assets[] | has("destination")' >/dev/null 2>&1 <<<"${_geo_json}"

check "state starts as absent" test "$(geodata_state)" = "absent"
check "apply succeeds" geodata_apply_config
check "state becomes managed" test "$(geodata_state)" = "managed"
check "block is stored at the config root" \
    jq -e '.geodata.cron and (.geodata.assets | length == 2)' "${xray_conf}"
check "existing config keys survive" jq -e '.outbounds[0].tag == "direct"' "${xray_conf}"
check "config stays private (600)" test "$(stat -c '%a' "${xray_conf}")" = "600"

check "second apply is idempotent" geodata_apply_config
check "assets are not duplicated" test "$(jq -r '.geodata.assets | length' "${xray_conf}")" = "2"

jq '.geodata.cron = "0 5 * * *"' "${xray_conf}" >"${TMP_ROOT}/custom.json"
cp "${TMP_ROOT}/custom.json" "${xray_conf}"
check "custom geodata is treated as custom" test "$(geodata_state)" = "custom"
check "custom geodata is not rejected" geodata_apply_config
check "custom cron is preserved" test "$(jq -r '.geodata.cron' "${xray_conf}")" = "0 5 * * *"

printf '{not json\n' >"${xray_conf}"
check "unparsable config reports invalid" test "$(geodata_state)" = "invalid"
check_not "unparsable config is not rewritten" geodata_apply_config
check "unparsable config is left byte-identical" test "$(cat "${xray_conf}")" = "{not json"

echo ""
echo "-- B. asset layout and systemd sandbox --"
reset_geo
check "layout passes when both .dat files exist" geodata_prepare_layout
check "asset directory resolves to the managed directory" test "$(geodata_asset_root)" = "${local_bin}/share/xray"

rm -f "${geodata_dir}/geosite.dat"
check_not "a missing .dat is refused" geodata_prepare_layout
printf 'DAT-SITE\n' >"${geodata_dir}/geosite.dat"

rm -f "${geodata_dir}/geoip.dat"
ln -s "${TMP_ROOT}/outside.dat" "${geodata_dir}/geoip.dat"
printf 'DAT\n' >"${TMP_ROOT}/outside.dat"
check_not "a symlinked .dat is refused" geodata_prepare_layout
rm -f "${geodata_dir}/geoip.dat"
printf 'DAT-IP\n' >"${geodata_dir}/geoip.dat"

rm -f "${local_bin}/share/xray"
mkdir -p "${local_bin}/share/xray"
check_not "an asset directory Xray does not read is refused" geodata_prepare_layout
rm -rf "${local_bin}/share/xray"
ln -sfn "${geodata_dir}" "${local_bin}/share/xray"

cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
ProtectSystem=strict
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
UNIT
check_not "ProtectSystem=strict without ReadWritePaths is refused" geodata_sandbox_allows_write
cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
ProtectSystem=strict
ReadWritePaths=${geodata_dir}
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
UNIT
check "an explicit ReadWritePaths for the asset directory is accepted" geodata_sandbox_allows_write
cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
ProtectSystem=strict
ReadWritePaths=/var/log/xray
ReadWritePaths=${geodata_dir}
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
UNIT
check "multiple ReadWritePaths lines are additive" geodata_sandbox_allows_write
cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
UNIT
check "the pinned unit (no sandbox directives) is accepted" geodata_sandbox_allows_write

mkdir -p "${xray_systemd_file}.d"
cat >"${xray_systemd_file}.d/10-geodata.conf" <<UNIT
[Service]
ReadWritePaths=${geodata_dir}
UNIT
cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
ProtectSystem=strict
UNIT
check "a drop-in can grant the write path" geodata_sandbox_allows_write
rm -rf "${xray_systemd_file}.d"

cat >"${xray_systemd_file}" <<UNIT
[Service]
User=nobody
Environment="XRAY_LOCATION_ASSET=${geodata_dir}"
UNIT
check "XRAY_LOCATION_ASSET overrides the resolved directory" \
    test "$(geodata_asset_root)" = "${geodata_dir}"
check "an overridden asset directory can still match" geodata_prepare_layout

echo ""
echo "-- C. permissions stay scoped to the asset directory --"
reset_geo
xray_service_user() { printf '%s\n' "${GEO_TEST_USER:-nobody}"; }
xray_service_group() { printf '%s\n' "${GEO_TEST_GROUP:-nogroup}"; }
chmod 0755 "${geodata_dir}"
chmod 0644 "${geodata_dir}/geoip.dat" "${geodata_dir}/geosite.dat"
printf 'PRIVATE-KEY\n' >"${idleleo_dir}/cert.key"
chmod 600 "${idleleo_dir}/cert.key"

check "permissions are applied for a non-root service account" geodata_apply_permissions
check "the asset directory becomes group-writable (0770)" \
    test "$(stat -c '%a' "${geodata_dir}")" = "770"
check "geoip.dat becomes group-writable only (0660)" \
    test "$(stat -c '%a' "${geodata_dir}/geoip.dat")" = "660"
check "geosite.dat becomes group-writable only (0660)" \
    test "$(stat -c '%a' "${geodata_dir}/geosite.dat")" = "660"
check "the directory stays owned by root, group is the service group" \
    grep -qx "root:nogroup ${geodata_dir}" "${GEO_CHOWN_LOG}"
check "the data files are handed to the service account" \
    grep -qx "nobody:nogroup ${geodata_dir}/geoip.dat" "${GEO_CHOWN_LOG}"
check "both data files are handed over" \
    test "$(grep -c "^nobody:nogroup ${geodata_dir}/" "${GEO_CHOWN_LOG}")" = "2"
check "the config file is not chowned by the geodata step" \
    test "$(grep -c "${xray_conf}" "${GEO_CHOWN_LOG}")" = "0"
check "private keys are not chowned by the geodata step" \
    test "$(grep -c "cert.key" "${GEO_CHOWN_LOG}")" = "0"
check "the private key mode is untouched" test "$(stat -c '%a' "${idleleo_dir}/cert.key")" = "600"
check "the config mode is untouched" test "$(stat -c '%a' "${xray_conf}")" = "600"

GEO_TEST_USER=root GEO_TEST_GROUP=root geodata_apply_permissions
check "root service account needs no ownership change" \
    test "$(stat -c '%a' "${geodata_dir}")" = "755"
check "root service account keeps the data files world-readable" \
    test "$(stat -c '%a' "${geodata_dir}/geoip.dat")" = "644"

check "native_configured is false without a geodata block" \
    test "$(geodata_native_configured; echo $?)" = "1"
geodata_apply_config
check "native_configured is true with the managed block" geodata_native_configured

echo ""
echo "-- D. cron de-duplication --"
reset_geo
cat >"${GEO_CRONTAB}" <<CRON
0 3 * * 1 bash "${geo_update_file}"
15 4 * * * /usr/local/bin/user-task --keep
CRON
check "the managed entry is recognised" test -n "$(geodata_legacy_cron_lines)"
check "only one managed entry is matched" \
    test "$(geodata_legacy_cron_lines | wc -l | tr -d ' ')" = "1"

_cron_before=$(cat "${GEO_CRONTAB}")
geodata_legacy_cron_disable >/dev/null 2>&1
check "removal is skipped while the config is not native" \
    test "$(cat "${GEO_CRONTAB}")" = "${_cron_before}"

geodata_apply_config
check "removal succeeds once the native schedule is managed" geodata_legacy_cron_disable
check "the managed entry is gone" \
    bash -c "! grep -qF 'geo_update.sh' '${GEO_CRONTAB}'"
check "the user's own schedule is preserved" grep -qF 'user-task --keep' "${GEO_CRONTAB}"

cat >"${GEO_CRONTAB}" <<CRON
0 3 * * 1 bash "${geo_update_file}"
0 6 * * * bash /opt/custom/geo_update.sh
CRON
geodata_legacy_cron_disable >/dev/null
check "a hand-written updater at another path is preserved" \
    grep -qF '/opt/custom/geo_update.sh' "${GEO_CRONTAB}"
check "the project's own updater is still removed" \
    bash -c "! grep -qF '${geo_update_file}' '${GEO_CRONTAB}'"

check "the legacy updater is kept as a manual rescue tool" test -f "${GEO_UPDATE_SH}"
check "the legacy updater still performs a transactional update" \
    grep -qF 'rollback_and_fail' "${GEO_UPDATE_SH}"

echo ""
echo "-- E. role scoping and install-chain wiring --"
reset_geo
jq 'del(.geodata)' "${xray_conf}" >"${TMP_ROOT}/nogeo.json"
cp "${TMP_ROOT}/nogeo.json" "${xray_conf}"
node_role="relay"
geodata_native_enable
check "relay never gets a geodata block" \
    test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
cat >"${GEO_CRONTAB}" <<CRON
0 3 * * 1 bash "${geo_update_file}"
CRON
geodata_legacy_cron_disable
check "relay never touches the cron table" grep -qF 'geo_update.sh' "${GEO_CRONTAB}"
check "relay install does not call the geodata step" fn_lacks install_nginx_relay geodata_native_enable
node_role="node"

check "native enable is wired into the ws+tls chain" \
    bash -c "awk '/^install_xray_ws_tls\(\)/,/^}/' '${INSTALL_SH}' | grep -qF 'geodata_native_enable'"
check "native enable is wired into the reality chain" \
    bash -c "awk '/^install_xray_reality\(\)/,/^}/' '${INSTALL_SH}' | grep -qF 'geodata_native_enable'"
check "native enable is wired into the ws-only chain" \
    bash -c "awk '/^install_xray_ws_only\(\)/,/^}/' '${INSTALL_SH}' | grep -qF 'geodata_native_enable'"
check "cron cleanup runs only after a successful restart" \
    bash -c "awk '/^install_xray_ws_tls\(\)/,/^}/' '${INSTALL_SH}' | sed -n '/service_restart || return 1/,+5p' | grep -qF 'geodata_legacy_cron_disable'"
check "the official installer's 644 reset is answered by a re-apply" \
    fn_has xray_privilege_escalation geodata_apply_permissions
check "the re-apply is guarded by the managed state" \
    fn_has xray_privilege_escalation geodata_native_configured

reset_geo
geodata_native_enable >/dev/null 2>&1
check "xray run -test is executed against the resolved asset directory" \
    test "$(cat "${GEO_TEST_ASSET_FILE}" 2>/dev/null)" = "${geodata_dir}"
check "the block is written after a passing test" \
    test "$(jq -r '.geodata.cron' "${xray_conf}" 2>/dev/null)" = "0 3 * * 1"

reset_geo
_geo_before=$(cat "${xray_conf}")
set_geo_plan "0,1"
check_not "a config test that fails after the write aborts the step" geodata_native_enable
check "the config is restored byte-identically on failure" \
    test "$(cat "${xray_conf}")" = "${_geo_before}"
check "no geodata block leaks into a failed deploy" \
    test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
set_geo_plan "0"

reset_geo
set_geo_plan "1"
check "a config that was already invalid is skipped, not fatal" geodata_native_enable
check "an already-invalid config is left untouched" \
    test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
set_geo_plan "0"

if [[ "${EUID}" -eq 0 ]]; then
    reset_geo
    # mktemp -d is 0700: let the unprivileged account traverse to the asset
    # directory, otherwise the probe fails for a reason unrelated to the mode.
    chmod 0711 "${TMP_ROOT}" "${idleleo_dir}" "${idleleo_dir}/share" 2>/dev/null || true
    chmod 0600 "${geodata_dir}/geoip.dat"
    # The recorded-chown shim must go: this block asserts real DAC access, so
    # ownership has to be applied for real.
    unset -f chown
    xray_service_user() { printf 'nobody\n'; }
    xray_service_group() { printf '%s\n' "$(id -gn nobody 2>/dev/null || printf 'nogroup')"; }
    check_not "the write probe fails when the account cannot write" geodata_service_can_write
    geodata_apply_permissions >/dev/null 2>&1
    check "the write probe passes after the permission step" geodata_service_can_write
else
    skip "service-account write probe needs root (container/CI covers it)"
fi
xray_service_user() { printf 'nobody\n'; }
xray_service_group() { printf '%s\n' "$(id -gn nobody 2>/dev/null || printf 'nogroup')"; }

echo ""
echo "-- F. traffic_blocker reporting --"
check "traffic_blocker defines the native cron reader" \
    grep -qF 'tb_geo_native_cron()' "${TRAFFIC_SH}"
check "the native reader reads .geodata.cron" \
    bash -c "awk '/^tb_geo_native_cron\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '.geodata.cron'"
check "the assets validator requires HTTPS" \
    bash -c "awk '/^tb_geo_native_assets_ok\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF 'https://'"
check "the legacy cron reader only targets the project updater" \
    bash -c "awk '/^tb_geo_legacy_cron_lines\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF 'tb_geo_updater_path'"
check "the GeoData menu no longer offers a migration choice" \
    bash -c "! grep -qF 'tb_geo_rescue_menu' '${TRAFFIC_SH}' && ! grep -qF '立即启用' '${TRAFFIC_SH}' && ! grep -qF '移除旧的 geo_update.sh 周期任务' '${TRAFFIC_SH}'"
check "the GeoData menu never calls the migration function" \
    bash -c "! grep -qF 'tb_geo_try_migrate_from_menu' '${TRAFFIC_SH}' && ! grep -qF 'geodata_migrate_legacy' '${TRAFFIC_SH}'"
check "the summary distinguishes a remaining legacy task" \
    grep -qF '旧 geo_update.sh 任务仍在' "${TRAFFIC_SH}"
check "the summary shows a failed migration marker" \
    grep -qF 'tb_geo_show_migration_failure' "${TRAFFIC_SH}"
check "the native summary is honest about the missing success record" \
    bash -c "awk '/^tb_display_geo_native_summary\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '不代表某次自动刷新已成功'"
check "the native summary does not read geo_version.json" \
    bash -c "awk '/^tb_display_geo_native_summary\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF 'tb_get_geo_local_version' && exit 1 || exit 0"
check "the native summary reports the real schedule" \
    bash -c "awk '/^tb_display_geo_native_summary\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '自动刷新计划'"
check "the summary does not re-describe custom config as native" \
    bash -c "awk '/^tb_display_geo_summary\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF 'custom)'"
check "the state header names the automatic-refresh state" \
    bash -c "awk '/^tb_geo_state_header\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '[自动刷新已开启]'"
check "the state header names the not-enabled state" \
    bash -c "awk '/^tb_geo_state_header\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '[自动刷新未开启]'"
check "the state header names the custom-config state" \
    bash -c "awk '/^tb_geo_state_header\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '[自定义 geodata]'"
check "the state header names the invalid-config state" \
    bash -c "awk '/^tb_geo_state_header\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '[配置不可解析]'"
check "the state header names the migration-failure state" \
    bash -c "awk '/^tb_geo_state_header\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '[上次自动迁移未完成]'"
check "the menu prints the state header before the summary" \
    bash -c "awk '/^tb_geo_menu\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF 'tb_geo_state_header'"
check "manual refresh announces the current automatic-refresh state" \
    bash -c "awk '/^tb_geo_manual_refresh_intro\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '当前为自动刷新状态'"
check "manual refresh reports its write location and restart status" \
    bash -c "awk '/^tb_geo_manual_refresh_finish\(\)/,/^}/' '${TRAFFIC_SH}' | grep -qF '写入位置'"
check "no user-visible '救援' wording remains in GeoData paths" \
    bash -c "! grep -qF '救援' '${TRAFFIC_SH}' && ! grep -qF '救援' '${INSTALL_SH}'"

# The sub-script expects the installer's globals; stub the few it needs.
scripts_dir="${idleleo_dir}/scripts"
xray_error_log="${TMP_ROOT}/error.log"
# shellcheck source=/dev/null
source "${TRAFFIC_SH}" >/dev/null 2>&1 || true
tb_geo_dir="${geodata_dir}"
tb_config_file="${TMP_ROOT}/traffic_blocker.json"
check "CJK table width counts wide chars once" \
    test "$(tb_display_width "国家/地区阻断 (未配置)")" = "22"
check "Cyrillic text stays single-cell" \
    test "$(tb_display_width "Привет")" = "6"
check "box-drawing characters stay single-cell" \
    test "$(tb_display_width "─│")" = "2"

printf 'status=failed\nreason=restart\ntime=2026-11-05 10:00:00\n' \
    >"${idleleo_dir}/geodata_migration.failed"
_marker_text=$(tb_geo_migration_failure_text)
check "the menu maps a failed restart marker" \
    test "${_marker_text%%|*}" = "Xray 重启失败，已回滚"
check "the menu keeps the marker timestamp" \
    test "${_marker_text#*|}" = "2026-11-05 10:00:00"
rm -f "${idleleo_dir}/geodata_migration.failed"

reset_geo
check "no native cron before the block exists" \
    bash -c "tb_geo_native_cron >/dev/null 2>&1 && exit 1 || exit 0"
geodata_apply_config
check "the native cron is reported once configured" \
    test "$(tb_geo_native_cron)" = "0 3 * * 1"
check "a valid managed block passes the asset check" tb_geo_native_assets_ok
jq '.geodata.assets[0].url |= sub("https://"; "http://")' "${xray_conf}" >"${TMP_ROOT}/plain.json"
cp "${TMP_ROOT}/plain.json" "${xray_conf}"
check_not "a plain-HTTP asset is rejected" tb_geo_native_assets_ok
jq 'del(.geodata.assets)' "${xray_conf}" >"${TMP_ROOT}/noassets.json"
cp "${TMP_ROOT}/noassets.json" "${xray_conf}"
check_not "an empty asset list is rejected" tb_geo_native_assets_ok
geodata_apply_config >/dev/null 2>&1 || cp "${TMP_ROOT}/custom.json" "${xray_conf}"

reset_geo
touch -t 203001010000 "${geodata_dir}/geoip.dat" 2>/dev/null || true
if [[ "$(uname -s)" == "Darwin" ]]; then
    touch -t "$(date -v-1d '+%Y%m%d%H%M')" "${geodata_dir}/geoip.dat" "${geodata_dir}/geosite.dat"
    check "a recent file reports recent" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "recent"
    touch -t "$(date -v-10d '+%Y%m%d%H%M')" "${geodata_dir}/geoip.dat"
    check "a file older than a week reports pending" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "pending"
    touch -t "$(date -v-40d '+%Y%m%d%H%M')" "${geodata_dir}/geoip.dat"
    check "a file older than a month reports stale" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "stale"
else
    touch -d '1 day ago' "${geodata_dir}/geoip.dat" "${geodata_dir}/geosite.dat"
    check "a recent file reports recent" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "recent"
    touch -d '10 days ago' "${geodata_dir}/geoip.dat"
    check "a file older than a week reports pending" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "pending"
    touch -d '40 days ago' "${geodata_dir}/geoip.dat"
    check "a file older than a month reports stale" test "$(tb_geo_native_file_state "${geodata_dir}/geoip.dat")" = "stale"
fi
rm -f "${geodata_dir}/geosite.dat"
check "a missing file reports missing" test "$(tb_geo_native_file_state "${geodata_dir}/geosite.dat")" = "missing"

echo ""
echo "-- G. legacy install -> native geodata migration --"
legacy_setup() {
    rm -rf "${geodata_dir}" "${local_bin}/share/xray" "${local_bin}"/share/xray.legacy-migrate.*
    mkdir -p "${geodata_dir}" "${local_bin}/share/xray"
    printf 'LEGACY-IP\n' >"${local_bin}/share/xray/geoip.dat"
    printf 'LEGACY-SITE\n' >"${local_bin}/share/xray/geosite.dat"
    jq 'del(.geodata)' "${xray_conf}" >"${TMP_ROOT}/legacy.json"
    cp "${TMP_ROOT}/legacy.json" "${xray_conf}"
    printf '0 3 * * 1 bash "%s"\n' "${geo_update_file}" >"${GEO_CRONTAB}"
    printf '0 4 * * * /usr/local/bin/hand-written-geo-job\n' >>"${GEO_CRONTAB}"
    xray_service_user() { printf 'root\n'; }
    xray_service_group() { printf 'root\n'; }
    GEO_TEST_RC=0
    unset GEO_TEST_PLAN
    : >"${GEO_TEST_COUNT_FILE}"
    : >"${GEO_CHOWN_LOG}"
    node_role="node"
}

# The migration restarts an active Xray so the new geodata block is read by the
# running process. Allow the failure path to be exercised without touching the
# test host's service manager.
GEO_RESTART_FAIL=0
GEO_RESTART_FAIL_ONCE=0
systemctl() {
    if [[ "${1:-}" == "restart" && "${GEO_RESTART_FAIL}" == "1" ]]; then
        [[ "${GEO_RESTART_FAIL_ONCE}" == "1" ]] && GEO_RESTART_FAIL=0
        return 1
    fi
    return 0
}

legacy_setup
_legacy_cfg=$(cat "${xray_conf}")
check "legacy migration sees the old cron entry" \
    test -n "$(grep -F "${geo_update_file}" "${GEO_CRONTAB}")"
check "legacy real directory is migrated and linked" geodata_migrate_legacy
check "the old real directory is replaced by a symlink" \
    test -L "${local_bin}/share/xray"
check "the symlink points at the managed directory" \
    test "$(_geodata_realpath "${local_bin}/share/xray")" = "$(_geodata_realpath "${geodata_dir}")"
check "legacy data is present in the managed directory" \
    test "$(cat "${geodata_dir}/geoip.dat")" = "LEGACY-IP"
check "native geodata block is written" \
    jq -e '.geodata.cron == "0 3 * * 1" and (.geodata.assets | length == 2)' "${xray_conf}"
check "xray run -test was executed during migration" \
    test "$(cat "${GEO_TEST_COUNT_FILE}" 2>/dev/null || echo 0)" -ge 1
check "the project's old cron entry is removed after success" \
    bash -c "! grep -qF '${geo_update_file}' '${GEO_CRONTAB}'"
check "a hand-written cron entry is preserved" \
    grep -qF 'hand-written-geo-job' "${GEO_CRONTAB}"
check "successful migration clears the failure marker" \
    test ! -f "${idleleo_dir}/geodata_migration.failed"
_legacy_cfg=$(cat "${xray_conf}")
check "migration is idempotent on a second run" geodata_migrate_legacy
check "the second run does not rewrite the config" \
    test "$(cat "${xray_conf}")" = "$_legacy_cfg"
check "the second run leaves no duplicate cron" \
    bash -c "! grep -qF '${geo_update_file}' '${GEO_CRONTAB}'"
_managed_log=$(geodata_migrate_legacy 2>&1)
check_not "a managed re-run does not claim a migration" \
    grep -qF '已从脚本模式切换' <<<"${_managed_log}"

rm -f "${local_bin}/share/xray"
check "a missing asset symlink is recreated" geodata_migrate_legacy
check "the recreated symlink points at the managed directory" \
    test "$(_geodata_realpath "${local_bin}/share/xray")" = "$(_geodata_realpath "${geodata_dir}")"

# Non-regular entries must never be deleted by a "successful" migration.
legacy_setup
mkdir -p "${local_bin}/share/xray/custom"
printf 'keep-me\n' >"${local_bin}/share/xray/custom/keep.txt"
ln -s geoip.dat "${local_bin}/share/xray/link.dat"
check_not "migration fails closed on a legacy subdirectory/symlink" geodata_migrate_legacy
check "the legacy directory is still a real directory" \
    test -d "${local_bin}/share/xray" && test ! -L "${local_bin}/share/xray"
check "the legacy subdirectory content survives" \
    test "$(cat "${local_bin}/share/xray/custom/keep.txt")" = "keep-me"
check "the legacy symlink survives" test -L "${local_bin}/share/xray/link.dat"
check "the failed migration keeps the old cron" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "the failed migration leaves no .geodata block" \
    test "$(jq -c '.geodata // null' "${xray_conf}")" = "null"

# A failed copy must not leave half of the assets in the managed directory.
legacy_setup
rm -f "${local_bin}/share/xray/geosite.dat"
rm -rf "${geodata_dir}"
mkdir -p "${geodata_dir}"
check_not "migration fails when only one .dat exists" geodata_migrate_legacy
check "the partial copy is removed from the managed directory" \
    test ! -e "${geodata_dir}/geoip.dat"

# A same-named file with different content is preserved as a backup.
legacy_setup
printf 'MANAGED-IP\n' >"${geodata_dir}/geoip.dat"
check "migration succeeds with a same-named managed file" geodata_migrate_legacy
check "the differing legacy file is kept in a backup" \
    bash -c "ls -d '${local_bin}/share/xray.legacy-migrate.'* >/dev/null 2>&1"
check "the backup keeps the legacy content" \
    bash -c "grep -rqF 'LEGACY-IP' '${local_bin}'/share/xray.legacy-migrate.*/geoip.dat"

legacy_setup
jq '.geodata = {"cron":"0 5 * * *","assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}' \
    "${xray_conf}" >"${TMP_ROOT}/custom-migrate.json"
cp "${TMP_ROOT}/custom-migrate.json" "${xray_conf}"
_legacy_cfg=$(cat "${xray_conf}")
check "custom geodata migration is skipped" geodata_migrate_legacy
check "custom geodata config is unchanged" \
    test "$(cat "${xray_conf}")" = "${_legacy_cfg}"
check "custom geodata keeps the old cron" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "custom geodata keeps the real asset directory" \
    test -d "${local_bin}/share/xray"
check "custom geodata clears a stale failure marker" \
    test ! -f "${idleleo_dir}/geodata_migration.failed"

legacy_setup
_legacy_cfg=$(cat "${xray_conf}")
set_geo_plan "0,1"
check_not "a post-write config test failure aborts migration" geodata_migrate_legacy
check "the original config is restored on failure" \
    test "$(cat "${xray_conf}")" = "$_legacy_cfg"
check "the old cron remains when native migration fails" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "no native block leaks into the failed migration" \
    test "$(jq -c 'has("geodata")' "${xray_conf}")" = "false"
check "a failed config test records the migration failure marker" \
    grep -q '^reason=native_enable$' "${idleleo_dir}/geodata_migration.failed"
set_geo_plan "0"

legacy_setup
rm -rf "${geodata_dir}"
printf 'not-a-directory\n' >"${geodata_dir}"
check_not "a blocked asset directory aborts migration" geodata_migrate_legacy
check "the old cron remains when the managed path is blocked" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "a blocked layout records the failure marker" \
    grep -q '^reason=layout$' "${idleleo_dir}/geodata_migration.failed"

legacy_setup
cp() {
    case "$*" in
        *"/share/xray/"*) return 1 ;;
        *) command cp "$@" ;;
    esac
}
check_not "a failed copy (unwritable target) aborts migration" geodata_migrate_legacy
unset -f cp
check "the old cron remains when the copy fails" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "the old real asset directory is kept when the copy fails" \
    test -d "${local_bin}/share/xray"
check "a copy failure records the failure marker" \
    grep -q '^reason=layout$' "${idleleo_dir}/geodata_migration.failed"

legacy_setup
_legacy_cfg=$(cat "${xray_conf}")
GEO_RESTART_FAIL=1
check_not "an Xray restart failure aborts migration" geodata_migrate_legacy
check "the original config is restored after a restart failure" \
    test "$(cat "${xray_conf}")" = "${_legacy_cfg}"
check "the old cron remains after a restart failure" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
check "a failed recovery records the recovery marker" \
    grep -q '^reason=recovery_required$' "${idleleo_dir}/geodata_migration.failed"
GEO_RESTART_FAIL=0
rm -f "${xray_conf}".legacy-migrate.*

legacy_setup
_legacy_cfg=$(cat "${xray_conf}")
GEO_RESTART_FAIL=1
GEO_RESTART_FAIL_ONCE=1
check_not "a restart failure still aborts migration" geodata_migrate_legacy
check "the original config is restored before the rollback restart" \
    test "$(cat "${xray_conf}")" = "${_legacy_cfg}"
check "the rollback restart removes the recovery backup" \
    bash -c "! compgen -G '${xray_conf}.legacy-migrate.*' >/dev/null"
check "a rolled-back restart records the restart marker" \
    grep -q '^reason=restart$' "${idleleo_dir}/geodata_migration.failed"
check "the old cron remains after the rollback restart" \
    grep -qF "${geo_update_file}" "${GEO_CRONTAB}"
GEO_RESTART_FAIL=0
GEO_RESTART_FAIL_ONCE=0

# Hidden regular files are ordinary data: they must be migrated, compared and
# never deleted by the post-migration backup cleanup.
legacy_setup
printf 'LEGACY-HIDDEN-A\n' >"${local_bin}/share/xray/.hidden"
check "migration succeeds with a hidden regular file" geodata_migrate_legacy
check "the hidden regular file is migrated" \
    test "$(cat "${geodata_dir}/.hidden")" = "LEGACY-HIDDEN-A"
check "the old tree is replaced by a symlink after the hidden migration" \
    test -L "${local_bin}/share/xray"

legacy_setup
printf 'LEGACY-HIDDEN-B\n' >"${local_bin}/share/xray/.hidden"
printf 'MANAGED-HIDDEN\n' >"${geodata_dir}/.hidden"
check "a conflicting hidden file keeps the legacy backup" geodata_migrate_legacy
check "the managed hidden file wins" \
    test "$(cat "${geodata_dir}/.hidden")" = "MANAGED-HIDDEN"
check "the legacy hidden content survives in the backup" \
    bash -c "grep -rqF 'LEGACY-HIDDEN-B' '${local_bin}'/share/xray.legacy-migrate.*/.hidden"

# The real install/update entry point must reuse the same transactional
# migration; an inline move/overwrite is exactly what the recheck flagged.
legacy_setup
rm -f "${xray_default_conf}"
rm -f "${local_bin}/share/xray/geosite.dat"
check_not "set_xray_config_path rejects a single .dat" set_xray_config_path
check "the rejected entry point keeps the old directory" \
    test -d "${local_bin}/share/xray" && test ! -L "${local_bin}/share/xray"
check "the rejected entry point leaves no partial .dat" \
    test ! -e "${geodata_dir}/geoip.dat"
check "the rejected entry point does not touch the config symlink" \
    test ! -e "${xray_default_conf}"

legacy_setup
rm -f "${xray_default_conf}"
printf 'MANAGED-IP\n' >"${geodata_dir}/geoip.dat"
check "set_xray_config_path succeeds with a same-name conflict" set_xray_config_path
check "the managed content still wins" \
    test "$(cat "${geodata_dir}/geoip.dat")" = "MANAGED-IP"
check "the legacy conflict is backed up" \
    bash -c "grep -rqF 'LEGACY-IP' '${local_bin}'/share/xray.legacy-migrate.*/geoip.dat"
check "the entry point links the config path" test -L "${xray_default_conf}"
check "the entry point leaves the asset symlink in place" \
    test -L "${local_bin}/share/xray"

legacy_setup
rm -f "${xray_default_conf}"
printf 'LEGACY-HIDDEN-C\n' >"${local_bin}/share/xray/.hidden"
check "set_xray_config_path migrates hidden files" set_xray_config_path
check "the hidden file reached the managed directory" \
    test "$(cat "${geodata_dir}/.hidden")" = "LEGACY-HIDDEN-C"
check "the entry point replaced the old tree with a symlink" \
    test -L "${local_bin}/share/xray"

legacy_setup
rm -f "${xray_default_conf}"
mkdir -p "${local_bin}/share/xray/custom"
check_not "set_xray_config_path fails closed on non-regular entries" set_xray_config_path
check "a non-regular entry keeps the legacy tree" \
    test -d "${local_bin}/share/xray" && test ! -L "${local_bin}/share/xray"
check "a rejected entry point leaves no config symlink" \
    test ! -e "${xray_default_conf}"

check "xray_install checks the layout migration result" \
    fn_has xray_install 'if ! set_xray_config_path'
check "xray_update checks the layout migration result" \
    fn_has xray_update 'if ! set_xray_config_path'

echo ""
echo "-- H. legacy cron PATH resolution --"
GEO_RESOLVE_ROOT="${TMP_ROOT}/geo-resolve"
mkdir -p "${GEO_RESOLVE_ROOT}/logs" "${GEO_RESOLVE_ROOT}/conf/xray"
printf '{}\n' >"${GEO_RESOLVE_ROOT}/conf/xray/config.json"
env -i PATH=/usr/bin:/bin \
    XRAY_BIN_DIR="${xray_bin_dir}" \
    XRAY_GEO_ROOT="${GEO_RESOLVE_ROOT}" \
    XRAY_GEO_CONFIG="${GEO_RESOLVE_ROOT}/conf/xray/config.json" \
    XRAY_UPDATE_LOCK_FILE="${GEO_RESOLVE_ROOT}/update.lock" \
    XRAY_GEO_RESOLVE_ONLY=1 \
    bash "${GEO_UPDATE_SH}" >/dev/null 2>&1
_geo_resolve_rc=$?
check "cron PATH resolves the pinned Xray binary" test "${_geo_resolve_rc}" -eq 0
check "the resolved path is the configured bin directory" \
    grep -qF "Resolved Xray binary: ${xray_bin_dir}/xray" "${GEO_RESOLVE_ROOT}/logs/geo_update.log"
rm -rf "${GEO_RESOLVE_ROOT}/logs"
env -i PATH=/usr/bin:/bin \
    XRAY_BIN_DIR=/nonexistent \
    XRAY_GEO_ROOT="${GEO_RESOLVE_ROOT}" \
    XRAY_GEO_CONFIG="${GEO_RESOLVE_ROOT}/conf/xray/config.json" \
    XRAY_UPDATE_LOCK_FILE="${GEO_RESOLVE_ROOT}/update.lock" \
    XRAY_GEO_RESOLVE_ONLY=1 \
    bash "${GEO_UPDATE_SH}" >/dev/null 2>&1
_geo_missing_rc=$?
check "a missing binary returns non-zero" test "${_geo_missing_rc}" -eq 1
check "an explicit XRAY_BIN_DIR is authoritative (no system fallback)" \
    grep -qF "tried: <unset> /nonexistent/xray" \
    "${GEO_RESOLVE_ROOT}/logs/geo_update.log"

check "legacy migration never runs for relay" \
    bash -c "awk '/^geodata_migrate_legacy\(\)/,/^}/' '${INSTALL_SH}' | grep -qF 'is_relay_role &&'"

echo ""
echo "-- I. no legacy evidence is left untouched --"
reset_geo
_no_evidence_cfg=$(cat "${xray_conf}")
_no_evidence_cron=$(cat "${GEO_CRONTAB}")
GEO_IE_RESTARTS=0
systemctl() {
    if [[ "${1:-}" == "restart" ]]; then
        GEO_IE_RESTARTS=$((GEO_IE_RESTARTS + 1))
    fi
    return 0
}
check "an absent .geodata with no legacy marker is not re-enabled" geodata_migrate_legacy
check "the no-evidence config is unchanged" \
    test "$(cat "${xray_conf}")" = "${_no_evidence_cfg}"
check "the no-evidence crontab is unchanged" \
    test "$(cat "${GEO_CRONTAB}")" = "${_no_evidence_cron}"
check "the no-evidence run does not restart Xray" \
    test "${GEO_IE_RESTARTS}" -eq 0
check "the no-evidence run does not run xray -test" \
    test ! -s "${GEO_TEST_COUNT_FILE}"

echo "-- I-b. automatic migration wiring --"
check "the startup hook still runs the migration" \
    grep -qF 'geodata_migrate_legacy || true' "${INSTALL_SH}"
check "the startup hook is gated by legacy evidence" \
    bash -c "awk '/^geodata_migrate_legacy\(\)/,/^}/' '${INSTALL_SH}' | grep -qF 'geodata_legacy_evidence'"
check "-u runs the newly installed script's migration in the same run" \
    bash -c "awk '/^_update_sh_impl\(\)/,/^}/' '${INSTALL_SH}' | grep -qF -- '--internal-geodata-migrate-legacy'"
check "the internal migration command is a root-only offline mutation" \
    bash -c "awk '/^is_offline_root_mutation_command\(\)/,/^}/' '${INSTALL_SH}' | grep -qF -- '--internal-geodata-migrate-legacy'"
check "the internal migration command is dispatched" \
    bash -c "awk '/^dispatch_offline_root_mutation_command\(\)/,/^}/' '${INSTALL_SH}' | grep -qF -- '--internal-geodata-migrate-legacy) geodata_migrate_legacy'"

echo ""
echo "-- J. automatic-refresh status header and manual refresh --"
reset_geo
geodata_apply_config >/dev/null
_out=$(tb_geo_state_header 2>&1)
check "native state header says automatic refresh is on" \
    bash -c "[[ '${_out}' == *'[自动刷新已开启]'* ]]"
check "native state header shows the schedule and its meaning" \
    bash -c "[[ '${_out}' == *'0 3 * * 1'* && '${_out}' == *'每周一 03:00'* ]]"
check "native state header says no manual action is needed" \
    bash -c "[[ '${_out}' == *'无需手动操作'* ]]"
check "native state header contains no legacy wording" \
    bash -c "[[ '${_out}' != *'救援'* && '${_out}' != *'自动更新'* ]]"

reset_geo
_out=$(tb_geo_state_header 2>&1)
check "no-cron header says automatic refresh is off" \
    bash -c "[[ '${_out}' == *'[自动刷新未开启]'* ]]"
check "no-cron header says this run will not refresh automatically" \
    bash -c "[[ '${_out}' == *'当前不会自动刷新'* ]]"

reset_geo
printf '0 3 * * 1 bash "%s"\n' "${geo_update_file}" >"${GEO_CRONTAB}"
_out=$(tb_geo_state_header 2>&1)
check "legacy-cron header names the remaining task and automatic retry" \
    bash -c "[[ '${_out}' == *'旧的 geo_update.sh 任务仍在'* && '${_out}' == *'重启脚本会自动重试迁移'* ]]"

reset_geo
jq '.geodata = {"cron":"0 5 * * *","assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}' \
    "${xray_conf}" >"${TMP_ROOT}/header-custom.json"
cp "${TMP_ROOT}/header-custom.json" "${xray_conf}"
_out=$(tb_geo_state_header 2>&1)
check "custom-config header says this project will not take over" \
    bash -c "[[ '${_out}' == *'[自定义 geodata]'* && '${_out}' == *'本项目不接管'* ]]"

printf 'not-json\n' >"${xray_conf}"
_out=$(tb_geo_state_header 2>&1)
check "invalid-config header names the parse failure and asks for a fix" \
    bash -c "[[ '${_out}' == *'[配置不可解析]'* && '${_out}' == *'修复 config.json'* ]]"

reset_geo
geodata_apply_config >/dev/null
printf 'status=failed\nreason=restart\ntime=2026-11-05 10:00:00\n' \
    >"${idleleo_dir}/geodata_migration.failed"
_out=$(tb_geo_state_header 2>&1)
check "failure header includes the recorded reason and automatic retry" \
    bash -c "[[ '${_out}' == *'[上次自动迁移未完成]'* && '${_out}' == *'Xray 重启失败，已回滚'* && '${_out}' == *'重启脚本会自动重试'* ]]"
rm -f "${idleleo_dir}/geodata_migration.failed"

# Fake updater: records that it ran, never touches config/cron, and can fail.
mkdir -p "${scripts_dir}"
cat >"${geo_update_file}" <<'FAKE_UPDATER'
#!/bin/sh
printf 'ran\n' >>"${GEO_MANUAL_MARKER:-/tmp/geo-manual-ran}"
[[ "${GEO_MANUAL_FAIL:-0}" == "1" ]] && exit 1
exit 0
FAKE_UPDATER
chmod +x "${geo_update_file}"
GEO_MANUAL_MARKER="${TMP_ROOT}/manual-ran"
export GEO_MANUAL_MARKER
GEO_SYSTEMCTL_LOG="${TMP_ROOT}/manual-systemctl.log"
GEO_ACTIVE=0
systemctl() {
    printf '%s\n' "$*" >>"${GEO_SYSTEMCTL_LOG}"
    case "${1:-}" in
        is-active) [[ "${GEO_ACTIVE}" == "1" ]] && return 0 || return 1 ;;
        restart) return 0 ;;
        *) return 0 ;;
    esac
}

check "the menu refresh path never writes a cron entry" \
    bash -c "awk '/^tb_download_geo_file\(\)/,/^}/' '${TRAFFIC_SH}' | grep -q 'crontab' && exit 1 || exit 0"

echo ""
echo "============================================================"
printf 'Result: %d passed, %d failed, %d skipped\n' "${PASS}" "${FAIL}" "${SKIP}"
echo "============================================================"
[[ "${FAIL}" -eq 0 ]] || exit 1
exit 0
