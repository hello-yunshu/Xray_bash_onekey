#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.0.6"
idleleo_dir="${XRAY_GEO_ROOT:-/etc/idleleo}"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${XRAY_GEO_CONFIG:-${xray_conf_dir}/config.json}"
log_dir="${idleleo_dir}/logs"
log_file="${log_dir}/geo_update.log"
geo_dir="${idleleo_dir}/share/xray"
geo_version_file="${xray_conf_dir}/geo_version.json"
lock_file="${XRAY_UPDATE_LOCK_FILE:-/run/lock/idleleo-update.lock}"
release_latest="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest"
release_base="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download"
xray_binary="${XRAY_BINARY:-$(command -v xray || true)}"
deadline=$((SECONDS + 600))
stage_dir=""
keep_stage=false
log() { printf '%s\n' "$*" >>"${log_file}"; }
cleanup() { [[ "${keep_stage}" == true || -z "${stage_dir}" || ! -d "${stage_dir}" ]] || rm -rf -- "${stage_dir}"; }
trap cleanup EXIT

run_bounded() {
    local limit="$1" remaining
    shift
    remaining=$((deadline - SECONDS))
    ((remaining > 0)) || return 124
    ((limit < remaining)) && remaining="$limit"
    timeout "${remaining}" "$@"
}

mkdir -p "${log_dir}" "${geo_dir}" "$(dirname "${lock_file}")"
if [[ "${IDLELEO_UPDATE_LOCK_HELD:-0}" != 1 ]]; then
    exec 9>"${lock_file}"
    if ! flock -n 9; then
        log "Another Xray update is holding ${lock_file}"
        exit 1
    fi
fi

get_remote_version() {
    local effective
    effective=$(run_bounded 30 curl -fsSL --connect-timeout 10 --max-time 25 --retry 1 -o /dev/null \
        -w '%{url_effective}' "${release_latest}" 2>/dev/null) || return 1
    effective=${effective%%\?*}
    [[ "${effective}" == */releases/tag/* ]] || return 1
    effective=${effective##*/releases/tag/}
    [[ "${effective}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || return 1
    printf '%s' "${effective}"
}

download() {
    local url="$1" output="$2"
    run_bounded 120 curl -fsSL --connect-timeout 15 --max-time 90 --max-filesize 104857600 \
        --retry 1 --retry-delay 1 -o "${output}" "${url}"
}

verify_checksum_file() {
    local file="$1" checksum="$2" expected listed
    [[ -s "${file}" && -s "${checksum}" ]] || return 1
    read -r expected listed <"${checksum}" || return 1
    expected=${expected,,}
    listed=${listed#\*}
    [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "${listed}" == "${file##*/}" ]] || return 1
    [[ "$(sha256sum "${file}" | awk '{print tolower($1)}')" == "${expected}" ]]
}

prepare_metadata() {
    local version="$1" output="$2"
    if [[ -e "${geo_version_file}" ]]; then
        [[ -f "${geo_version_file}" && ! -L "${geo_version_file}" ]] || return 1
        jq -e '.geo_versions | objects' "${geo_version_file}" >/dev/null 2>&1 || return 1
        jq --arg ip "geoip.dat" --arg site "geosite.dat" --arg v "${version}" \
            '.geo_versions[$ip] = $v | .geo_versions[$site] = $v' \
            "${geo_version_file}" >"${output}" || return 1
    else
        jq -n --arg ip "geoip.dat" --arg site "geosite.dat" --arg v "${version}" \
            '{geo_versions:{($ip):$v,($site):$v}}' >"${output}" || return 1
    fi
    [[ -s "${output}" ]] || return 1
    jq -e '.geo_versions["geoip.dat"] and .geo_versions["geosite.dat"]' \
        "${output}" >/dev/null 2>&1
}

restore_previous() {
    local name src dst temp
    for name in geoip.dat geosite.dat geo_version.json; do
        if [[ -f "${stage_dir}/previous/${name}.present" ]]; then
            src="${stage_dir}/previous/${name}"
            if [[ "${name}" == geo_version.json ]]; then dst="${geo_version_file}"; else dst="${geo_dir}/${name}"; fi
            temp="${dst}.restore.$$"
            cp -p -- "${src}" "${temp}" && mv -f -- "${temp}" "${dst}" || return 1
        else
            if [[ "${name}" == geo_version.json ]]; then dst="${geo_version_file}"; else dst="${geo_dir}/${name}"; fi
            rm -f -- "${dst}" || return 1
        fi
    done
}

restore_service() {
    local was_active="$1"
    [[ "${was_active}" == true ]] || return 0
    run_bounded 60 systemctl restart xray || return 1
    run_bounded 15 systemctl is-active --quiet xray
}

remote_version=$(get_remote_version) || { log 'Failed to resolve immutable GeoData release tag'; exit 1; }
log "Pinned GeoData release tag: ${remote_version}"

[[ -x "${xray_binary}" ]] || { log 'Xray executable is unavailable; refusing to install unparsed GeoData'; exit 1; }
[[ -f "${xray_conf}" && ! -L "${xray_conf}" ]] || { log 'Xray config is unavailable; refusing to install unparsed GeoData'; exit 1; }
stage_dir=$(mktemp -d "${geo_dir}/.geo-update.XXXXXX")
mkdir -m 0700 "${stage_dir}/previous"
for file_name in geoip.dat geosite.dat; do
    if ! download "${release_base}/${remote_version}/${file_name}" "${stage_dir}/${file_name}"; then
        log "Failed to download ${file_name} for release ${remote_version}"
        exit 1
    fi
    if ! download "${release_base}/${remote_version}/${file_name}.sha256sum" "${stage_dir}/${file_name}.sha256sum"; then
        log "Failed to download checksum for ${file_name}"
        exit 1
    fi
    if ! verify_checksum_file "${stage_dir}/${file_name}" "${stage_dir}/${file_name}.sha256sum"; then
        log "GeoData checksum verification failed for ${file_name}"
        exit 1
    fi
done

current_ip_version=$(jq -r --arg name geoip.dat '.geo_versions[$name] // ""' "${geo_version_file}" 2>/dev/null || true)
current_site_version=$(jq -r --arg name geosite.dat '.geo_versions[$name] // ""' "${geo_version_file}" 2>/dev/null || true)
if [[ "${current_ip_version}" == "${remote_version}" && "${current_site_version}" == "${remote_version}" ]] \
   && verify_checksum_file "${geo_dir}/geoip.dat" "${stage_dir}/geoip.dat.sha256sum" \
   && verify_checksum_file "${geo_dir}/geosite.dat" "${stage_dir}/geosite.dat.sha256sum"; then
    log "All GeoData files are current and match release ${remote_version} checksums"
    exit 0
fi

# The upstream .sha256sum assets are fetched over HTTPS from the same immutable
# GitHub release. They are not signed; the integrity guarantee is the HTTPS
# trust boundary plus exact tag binding, not an independent publisher signature.
outbound_tag=$(jq -r '.outbounds[0].tag // empty' "${xray_conf}" 2>/dev/null) || {
    log 'Failed to read the first configured Xray outbound tag'
    exit 1
}
[[ -n "${outbound_tag}" ]] || { log 'Xray config has no tagged outbound for GeoData validation'; exit 1; }
if ! jq --arg tag "${outbound_tag}" \
    '.routing //= {} | .routing.rules //= [] | .routing.rules += [{"type":"field","ip":["geoip:private"],"domain":["geosite:cn"],"outboundTag":$tag}]' \
    "${xray_conf}" >"${stage_dir}/validation-config.json"; then
    log 'Failed to stage Xray validation config'
    exit 1
fi
if ! XRAY_LOCATION_ASSET="${stage_dir}" run_bounded 60 "${xray_binary}" run -test -config "${stage_dir}/validation-config.json" >/dev/null 2>&1; then
    log 'Xray rejected staged GeoData with the installed configuration'
    exit 1
fi

for name in geoip.dat geosite.dat; do
    if [[ -e "${geo_dir}/${name}" ]]; then
        [[ -f "${geo_dir}/${name}" && ! -L "${geo_dir}/${name}" ]] || { log "Unsafe existing asset: ${name}"; exit 1; }
        cp -p -- "${geo_dir}/${name}" "${stage_dir}/previous/${name}"
        : >"${stage_dir}/previous/${name}.present"
    fi
done
if [[ -e "${geo_version_file}" ]]; then
    [[ -f "${geo_version_file}" && ! -L "${geo_version_file}" ]] || { log 'Unsafe GeoData version metadata'; exit 1; }
    cp -p -- "${geo_version_file}" "${stage_dir}/previous/geo_version.json"
    : >"${stage_dir}/previous/geo_version.json.present"
fi
if ! prepare_metadata "${remote_version}" "${stage_dir}/geo_version.json"; then
    log 'Failed to stage valid GeoData version metadata'
    exit 1
fi
chmod 0644 "${stage_dir}/geo_version.json"

was_active=false
if run_bounded 15 systemctl is-active --quiet xray 2>/dev/null; then was_active=true; fi
commit_started=false
rollback_and_fail() {
    local reason="$1"
    log "GeoData update failed: ${reason}; restoring previous generation"
    if [[ "${commit_started}" == true ]]; then
        if restore_previous && restore_service "${was_active}"; then
            log 'Previous GeoData generation restored and service state verified'
        else
            keep_stage=true
            log 'RECOVERY REQUIRED: previous GeoData restoration or service verification failed'
            log "Recovery materials retained at ${stage_dir}"
        fi
    fi
    exit 1
}

commit_started=true
mv -f -- "${stage_dir}/geoip.dat" "${geo_dir}/geoip.dat" || rollback_and_fail 'geoip.dat rename failed'
mv -f -- "${stage_dir}/geosite.dat" "${geo_dir}/geosite.dat" || rollback_and_fail 'geosite.dat rename failed'
mv -f -- "${stage_dir}/geo_version.json" "${geo_version_file}" || rollback_and_fail 'version metadata rename failed'
if [[ "${was_active}" == true ]]; then
    if ! run_bounded 60 systemctl restart xray || ! run_bounded 15 systemctl is-active --quiet xray; then
        rollback_and_fail 'Xray restart or health check failed'
    fi
fi
log "GeoData update completed successfully for ${remote_version}"
exit 0
