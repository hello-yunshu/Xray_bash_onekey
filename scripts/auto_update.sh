#!/usr/bin/env bash
# Production uses a hardened PATH. Tests set IDLELEO_TEST_MODE=1 and inject
# stub commands through IDLELEO_TEST_PATH; nothing else changes behaviour.
if [[ "${IDLELEO_TEST_MODE:-0}" == "1" ]]; then
    PATH="${IDLELEO_TEST_PATH:-$PATH}"
else
    PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
fi
export PATH

VERSION="1.2.1"

_script_args=("$@")

# Paths are overridable for tests only; the defaults are the production ones.
idleleo_dir="${IDLELEO_DIR:-/etc/idleleo}"
scripts_dir="${idleleo_dir}/scripts"
local_bin="/usr/local"
nginx_dir="${IDLELEO_NGINX_DIR:-${local_bin}/nginx}"
xray_bin="${IDLELEO_XRAY_BIN:-/usr/local/bin/xray}"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
log_dir="${IDLELEO_LOG_DIR:-${idleleo_dir}/logs}"
log_file="${log_dir}/auto_update.log"
running_file="${log_dir}/auto_update.running"
update_lock_file="${IDLELEO_UPDATE_LOCK_FILE:-/run/lock/idleleo-update.lock}"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
# Structured failure record. One object per component, e.g.
#   {"xray":{"version":"26.10.31","failed_at":"2026-11-02T01:00:00Z"}}
# A component is only skipped while the failed target version is still the
# current target; a new target version always gets a fresh attempt.
failure_record_file="${log_dir}/update_failed.json"
# Legacy per-component markers (<=1.1.6). They blocked every future version
# forever; they are migrated into the record file and removed.
failed_update_marker="${log_dir}/update_failed.mark"
# Version metadata: CDN first, then GitHub Raw. Both must pass the same
# field validation, and neither may bypass the Release/SHA checks performed
# by install.sh itself.
versions_cdn_url="https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json"
versions_origin_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/xray_shell_versions.json"

log() {
    echo "$*" >>"${log_file}"
}

# Safely update install_config.json preserving owner/group/mode.
# Implements same semantics as install.sh:update_json_config but standalone
# (auto_update.sh runs as cron and must not source install.sh which has side effects).
# Args: jq_filter_and_args... (passed to jq as-is, e.g. --arg sv "1.0" '. += {"shell_version":$sv}')
# Returns: 0 on success, 1 on failure. Original file is never touched on failure.
safe_update_install_config() {
    local config_file="${xray_install_config_file}"
    [[ -f "${config_file}" ]] || return 1

    local original_mode original_uid original_gid tmp_file _old_umask
    original_mode=$(stat -c '%a' "${config_file}" 2>/dev/null) || return 1
    original_uid=$(stat -c '%u' "${config_file}" 2>/dev/null) || return 1
    original_gid=$(stat -c '%g' "${config_file}" 2>/dev/null) || return 1
    # Same directory = same filesystem for atomic mv; mktemp avoids symlink attacks
    tmp_file=$(mktemp "${config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${config_file}.tmp.$$"

    _old_umask=$(umask)
    umask 077

    if ! jq "$@" "${config_file}" > "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        echo "Failed to generate updated JSON for ${config_file##*/}" >>"${log_file}"
        return 1
    fi
    # Validate generated JSON before replacing original (fail closed)
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        echo "Generated JSON invalid, kept original ${config_file##*/}" >>"${log_file}"
        return 1
    fi
    # Restore original owner/group/mode (do not let auto-update widen sensitive file perms)
    if ! chmod "${original_mode}" "${tmp_file}" 2>/dev/null || ! chown "${original_uid}:${original_gid}" "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        echo "Failed to restore permissions on ${config_file##*/}" >>"${log_file}"
        return 1
    fi
    umask "${_old_umask}"

    if ! mv "${tmp_file}" "${config_file}"; then
        rm -f "${tmp_file}"
        echo "Failed to atomically replace ${config_file##*/}" >>"${log_file}"
        return 1
    fi

    # Refresh in-memory cache so subsequent reads in this run see the new content
    info_extraction_all=$(jq -rc . "${config_file}" 2>/dev/null)
    return 0
}

check_update() {
    # auto_update.sh is a Release-owned helper. It is replaced together with
    # install.sh and must never fetch or execute mutable main/scripts content.
    return 0
}

# ---- Failure record -------------------------------------------------------
# component -> failed target version, so the retry decision is about the
# version that actually failed, not about "has this component ever failed".

failure_record_get() {
    local component="$1" value
    [[ -f "${failure_record_file}" ]] || return 1
    value=$(jq -r --arg c "${component}" '(.[$c].version // "") | select(length > 0)' "${failure_record_file}" 2>/dev/null) || return 1
    [[ -n "${value}" ]] || return 1
    printf '%s\n' "${value}"
}

failure_record_failed_at() {
    local component="$1"
    [[ -f "${failure_record_file}" ]] || return 1
    jq -er --arg c "${component}" '.[$c].failed_at // empty' "${failure_record_file}" 2>/dev/null
}

failure_record_write() {
    local component="$1" version="$2" tmp_file
    [[ -n "${version}" ]] || return 1
    mkdir -p "${log_dir}" 2>/dev/null || true
    tmp_file=$(mktemp "${failure_record_file}.XXXXXX" 2>/dev/null) || return 1
    if [[ -f "${failure_record_file}" ]] && jq -e 'type == "object"' "${failure_record_file}" >/dev/null 2>&1; then
        if ! jq --arg c "${component}" --arg v "${version}" --arg at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            '.[$c] = {version: $v, failed_at: $at}' "${failure_record_file}" >"${tmp_file}" 2>/dev/null; then
            rm -f "${tmp_file}"
            return 1
        fi
    else
        if ! jq -n --arg c "${component}" --arg v "${version}" --arg at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            '{($c): {version: $v, failed_at: $at}}' >"${tmp_file}" 2>/dev/null; then
            rm -f "${tmp_file}"
            return 1
        fi
    fi
    chmod 0640 "${tmp_file}" 2>/dev/null || true
    mv "${tmp_file}" "${failure_record_file}"
}

failure_record_clear() {
    local component="$1" tmp_file
    [[ -f "${failure_record_file}" ]] || return 0
    tmp_file=$(mktemp "${failure_record_file}.XXXXXX" 2>/dev/null) || return 1
    if ! jq --arg c "${component}" 'del(.[$c])' "${failure_record_file}" >"${tmp_file}" 2>/dev/null; then
        rm -f "${tmp_file}"
        return 1
    fi
    chmod 0640 "${tmp_file}" 2>/dev/null || true
    mv "${tmp_file}" "${failure_record_file}"
}

# How to get out of a suppressed retry, printed whenever a skip happens so the
# log is self-sufficient.
failure_retry_hint() {
    local component="$1"
    log "  Manual retry: jq 'del(.${component})' '${failure_record_file}' (or delete that file), then run: bash ${idleleo_dir}/scripts/auto_update.sh"
    log "  Automatic retry: the next run retries as soon as the metadata advertises a different target version."
}

# A legacy marker carries no version, so it cannot suppress anything: it is
# removed and the decision is re-made from the current metadata. Leaving it in
# place is what made every future version unreachable.
legacy_marker_migrate() {
    local component marker
    for component in xray nginx; do
        marker="${failed_update_marker}.${component}"
        [[ -f "${marker}" ]] || continue
        rm -f "${marker}" 2>/dev/null || continue
        log "Removed legacy ${component} failure marker (${marker}): legacy markers blocked all future versions and are no longer consulted."
    done
    [[ -f "${failed_update_marker}" ]] && rm -f "${failed_update_marker}" 2>/dev/null
    return 0
}

# 0 = attempt this target, 1 = skip, the failed target version is unchanged.
component_should_attempt() {
    local component="$1" target="$2" failed_version failed_at
    failed_version=$(failure_record_get "${component}") || return 0
    if [[ "${failed_version}" == "${target}" ]]; then
        failed_at=$(failure_record_failed_at "${component}" 2>/dev/null || echo "unknown")
        log "${component} v${target} already failed on ${failed_at}; skipping this target version."
        failure_retry_hint "${component}"
        return 1
    fi
    log "Recorded ${component} failure was for v${failed_version}; the current target is v${target}, retrying."
    return 0
}

# ---- Version ordering -----------------------------------------------------

version_is_numeric() {
    [[ "${1:-}" =~ ^[0-9]+(\.[0-9]+)*$ ]]
}

# 1 / 0 / -1 for newer / equal / older; 2 when either side is not a dotted
# numeric version. Components compare numerically, so 26.9.30 < 26.10.31.
version_compare() {
    local a="${1#v}" b="${2#v}"
    local i n x y
    local -a av bv
    version_is_numeric "${a}" && version_is_numeric "${b}" || return 2
    IFS='.' read -r -a av <<<"${a}"
    IFS='.' read -r -a bv <<<"${b}"
    n=${#av[@]}
    [[ ${#bv[@]} -gt ${n} ]] && n=${#bv[@]}
    for ((i = 0; i < n; i++)); do
        x=$((10#${av[i]:-0}))
        y=$((10#${bv[i]:-0}))
        if [[ ${x} -gt ${y} ]]; then
            printf '1\n'
            return 0
        fi
        if [[ ${x} -lt ${y} ]]; then
            printf -- '-1\n'
            return 0
        fi
    done
    printf '0\n'
}

version_gt() {
    [[ "$(version_compare "$1" "$2")" == "1" ]]
}

# ---- Version metadata -----------------------------------------------------

fetch_versions() {
    local url="$1" response
    response=$(curl -fsSL --connect-timeout 10 --max-time 30 --retry 2 --retry-delay 1 "${url}" 2>/dev/null) || return 1
    [[ -n "${response}" ]] || return 1
    # A response that is not a single JSON object is untrusted input.
    printf '%s' "${response}" | jq -e 'type == "object"' >/dev/null 2>&1 || return 1
    printf '%s' "${response}"
}

# Every field this run consumes must exist and look like a version. A response
# with a missing/garbage field is rejected as a whole instead of being used
# partially (a partial read is how a downgrade or a bogus target happens).
versions_fields_ok() {
    local json="$1" key value
    shift
    for key in "$@"; do
        value=$(printf '%s' "${json}" | jq -r --arg k "${key}" '.[$k] // empty' 2>/dev/null)
        [[ -n "${value}" ]] || return 1
        [[ "${value}" =~ ^[0-9]+(\.[0-9]+)*$ ]] || return 1
    done
    return 0
}

load_versions() {
    local response required url
    required=("shell_online_version" "nginx_build_online_version")
    [[ ${is_relay} -eq 1 ]] || required+=("xray_online_version")

    if [[ -n "${XRAY_VERSIONS_FILE:-}" && -f "${XRAY_VERSIONS_FILE}" ]]; then
        response=$(cat "${XRAY_VERSIONS_FILE}")
        if ! versions_fields_ok "${response}" "${required[@]}"; then
            log "Injected version metadata is missing required fields, skipping update checks."
            return 1
        fi
        get_versions_all="${response}"
        return 0
    fi

    # CDN first, GitHub Raw second. A source counts as usable only when it
    # answers with a JSON object that carries every field this run needs; a
    # partial payload is a rejected source, not a partial update.
    for url in "${versions_cdn_url}" "${versions_origin_url}"; do
        if response=$(fetch_versions "${url}") && versions_fields_ok "${response}" "${required[@]}"; then
            get_versions_all="${response}"
            [[ "${url}" == "${versions_origin_url}" ]] && log "Version metadata: using GitHub Raw fallback."
            return 0
        fi
        if [[ "${url}" == "${versions_cdn_url}" ]]; then
            log "Version metadata: jsDelivr unavailable or invalid, falling back to GitHub Raw."
        fi
    done
    log "Version metadata: jsDelivr and GitHub Raw both failed or returned an untrusted payload, skipping update checks."
    return 1
}

check_online_version() {
    local result
    result=$(echo "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null)
    if [[ $? -ne 0 ]] || [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        log "Online version check failed for ${1}, please try again later!"
        return 1
    fi
    echo "${result}"
}

# Same read without the failure log: used where a missing field is expected
# (e.g. the Xray target on a relay-only node).
check_online_version_silent() {
    local result
    result=$(echo "${get_versions_all}" | jq -rc --arg key "$1" '.[$key] // empty' 2>/dev/null) || return 1
    [[ -n "${result}" ]] || return 1
    echo "${result}"
}

info_extraction() {
    echo "${info_extraction_all}" | jq -r --arg key "$1" '.[$key]' 2>/dev/null
}

node_role() {
    local role
    role=$(info_extraction role 2>/dev/null)
    [[ -z "${role}" || "${role}" == "null" ]] && role="node"
    printf '%s\n' "${role}"
}

[[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}"
mkdir -p "$(dirname "${update_lock_file}")" 2>/dev/null || true
exec 9>"${update_lock_file}" 2>/dev/null || exec 9>"${log_dir}/update.lock"
if command -v flock >/dev/null 2>&1; then
    if ! flock -n 9; then
        echo "Another update process already holds the shared update lock." >>"${log_file}"
        exit 1
    fi
else
    # macOS dev hosts have no util-linux flock; production always does.
    echo "flock unavailable, running without the shared file lock." >>"${log_file}"
fi
export IDLELEO_UPDATE_LOCK_HELD=1
if ! mkdir "${running_file}" 2>/dev/null; then
    echo "Previous auto update process is still running! Checked at: $(date '+%Y-%m-%d %H:%M') Manual troubleshooting recommended!" >>"${log_file}"
    exit 1
fi
trap 'rm -rf "${running_file}"; flock -u 9 2>/dev/null || true; exec 9>&-' EXIT
[[ -f "${log_file}" ]] && rm -f "${log_file}"

echo "Update time: $(date '+%Y-%m-%d %H:%M')" >"${log_file}"

check_update
legacy_marker_migrate

if [[ ! -f "${xray_install_config_file}" ]]; then
    log "Config file not found, skipping update checks."
    exit 0
fi

info_extraction_all=$(jq -rc . "${xray_install_config_file}" 2>/dev/null)
is_relay=0
[[ "$(node_role)" == "relay" ]] && is_relay=1

get_versions_all=""
if ! load_versions; then
    exit 0
fi

if ! shell_online_version="$(check_online_version shell_online_version)"; then
    log "Failed to check shell online version, skipping update checks."
    exit 1
fi
nginx_online_version="$(check_online_version_silent nginx_build_online_version || true)"
if [[ -z "${nginx_online_version}" ]]; then
    log "Failed to check Nginx online version, skipping the Nginx update."
fi
if [[ ${is_relay} -eq 1 ]]; then
    # A relay node installs no Xray; a missing Xray target is not a failure.
    xray_online_version="$(check_online_version_silent xray_online_version || true)"
else
    if ! xray_online_version="$(check_online_version xray_online_version)"; then
        log "Failed to check Xray online version, skipping update checks."
        exit 1
    fi
fi

if [[ $(info_extraction shell_version) == null ]] || [[ $(info_extraction shell_version) != "${shell_online_version}" ]] ||
   [[ ! -f "${idleleo_dir}/release-managed.version" ]] || [[ $(cat "${idleleo_dir}/release-managed.version" 2>/dev/null) != "${shell_online_version}" ]]; then
    IDLELEO_UPDATE_LOCK_HELD=1 bash "${idleleo_dir}/install.sh" -u auto_update
    [[ 0 -ne $? ]] && log "Script update failed!" && exit 1
    log "Script updated successfully!"
    # Persist shell_version preserving owner/group/mode (avoids permission regression)
    if ! safe_update_install_config --arg sv "${shell_online_version}" '. += {"shell_version": $sv}'; then
        log "Failed to persist shell_version in config (original preserved)"
    fi
else
    log "Script is up to date!"
fi

# ---- Nginx ---------------------------------------------------------------
installed_nginx_version="$(info_extraction nginx_build_version)"
if [[ -z "${nginx_online_version}" ]]; then
    log "Nginx target version unknown, skipping the Nginx update."
elif [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
    log "Nginx not installed, skipping the Nginx update."
elif [[ "${installed_nginx_version}" == null ]]; then
    log "Nginx build version unknown in install_config.json, skipping the Nginx update."
elif [[ "${nginx_online_version}" == "${installed_nginx_version}" ]]; then
    log "Nginx is up to date!"
elif version_gt "${installed_nginx_version}" "${nginx_online_version}"; then
    log "Installed Nginx build ${installed_nginx_version} is newer than the metadata target ${nginx_online_version}; refusing to downgrade."
elif ! component_should_attempt "nginx" "${nginx_online_version}"; then
    log "Nginx ${nginx_online_version} stays blocked until the metadata moves to another version."
else
    log "Updating Nginx..."
    auto_update=YES bash "${idleleo_dir}/install.sh" -n auto_update
    if [[ $? -ne 0 ]]; then
        log "Nginx update to ${nginx_online_version} failed!"
        failure_record_write "nginx" "${nginx_online_version}" || log "Failed to record the Nginx failure."
    else
        log "Nginx updated successfully!"
        failure_record_clear "nginx" || true
    fi
fi

# ---- Xray ---------------------------------------------------------------
installed_xray_version="$(info_extraction xray_version)"
if [[ ${is_relay} -eq 1 ]]; then
    # Relay-only role: Nginx forwards TCP; Xray is not part of this server.
    log "Relay node: Xray is not installed by design, skipping the Xray update."
elif [[ -z "${xray_online_version}" ]]; then
    log "Xray target version unknown, skipping the Xray update."
elif [[ ! -f "${xray_conf}" ]] || [[ ! -f "${xray_bin}" ]]; then
    log "Xray not installed, skipping the Xray update."
elif [[ "${installed_xray_version}" == null ]]; then
    log "Xray version unknown, cannot auto update"
elif [[ "${xray_online_version}" == "${installed_xray_version}" ]]; then
    log "Xray is up to date!"
elif version_gt "${installed_xray_version}" "${xray_online_version}"; then
    # Metadata can regress (reverted release, stale CDN copy). Moving a working
    # host backwards is never an automatic action; a human decides that.
    log "Installed Xray ${installed_xray_version} is newer than the metadata target ${xray_online_version}; refusing to downgrade."
elif ! component_should_attempt "xray" "${xray_online_version}"; then
    log "Xray ${xray_online_version} stays blocked until the metadata moves to another version."
else
    log "Updating Xray to ${xray_online_version}..."
    auto_update=YES bash "${idleleo_dir}/install.sh" -x auto_update
    if [[ $? -ne 0 ]]; then
        log "Xray update to ${xray_online_version} failed!"
        failure_record_write "xray" "${xray_online_version}" || log "Failed to record the Xray failure."
    else
        log "Xray updated successfully!"
        failure_record_clear "xray" || true
    fi
fi
