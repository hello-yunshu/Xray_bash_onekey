#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#stty erase ^?

if [[ "${_TEST_MODE:-0}" != "1" ]]; then
    cd "$(
        cd "$(dirname "$0")" || exit
        pwd
    )" || exit
fi

#=================================================================
#	System Request: Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+
#	Author:	yunyunshu
#	Dscription: Xray Onekey Management
#	Version: 3.0
#	Official document: hey.run
#=================================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
GreenW="\033[1;32m"
RedW="\033[1;31m"
Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
YellowBG="\033[43;30m"
Font="\033[0m"

# Minimal gettext fallback: returns the input string as-is when the real
# gettext binary/function is not yet available (e.g. before init_language).
# init_language sources the real gettext.sh which overrides this function.
if ! command -v gettext >/dev/null 2>&1; then
    gettext() { printf '%s' "$1"; }
fi

#notification information
Info="${Green}[$(gettext "信息")]${Font}"
OK="${Green}[OK]${Font}"
Error="${RedW}[$(gettext "错误")]${Font}"
Warning="${Yellow}[$(gettext "警告")]${Font}"

shell_version="3.0.1"
shell_mode="$(gettext "未安装")"
tls_mode="None"
transport_mode="None"
local_bin="/usr/local"
idleleo_dir="/etc/idleleo"
idleleo="${idleleo_dir}/install.sh"
idleleo_conf_dir="${idleleo_dir}/conf"
scripts_dir="${idleleo_dir}/scripts"
log_dir="${idleleo_dir}/logs"
xray_bin_dir="${local_bin}/bin"
xray_conf_dir="${idleleo_conf_dir}/xray"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
xray_conf="${xray_conf_dir}/config.json"
xray_status_conf="${xray_conf_dir}/status_config.json"
xray_default_conf="${local_bin}/etc/xray/config.json" # COMPAT: 旧版使用符号链接指向此路径，仅用于清理旧链接和 sed 匹配，未来可删除
nginx_conf="${nginx_conf_dir}/00-xray.conf"
nginx_ssl_conf="${nginx_conf_dir}/01-xray-80.conf"
nginx_upstream_conf="${nginx_conf_dir}/02-xray-server.conf"
# Files this script owns inside ${nginx_conf_dir}. Only these are removed
# during reinstall; user-added .conf files (custom sites, stream blocks,
# reverse proxies, security rules) are preserved.
managed_nginx_files=(
    "00-xray.conf"
    "01-xray-80.conf"
    "02-xray-server.conf"
    "03-isolate.conf"
    "03-decoy.conf"
)
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
nginx_dir="${local_bin}/nginx"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
auto_update_file="${scripts_dir}/auto_update.sh"
ssl_update_file="${scripts_dir}/ssl_update.sh"
geo_update_file="${scripts_dir}/geo_update.sh"
mf_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/scripts/fail2ban_manager.sh"
tb_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/scripts/traffic_blocker.sh"
fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/scripts/file_manager.sh"
au_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/scripts/auto_update.sh"
main_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh"
shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
get_versions_all=""
_get_versions_loaded=0

fetch_versions_json() {
    local url="$1"
    local response

    if ! response=$(curl -fsSL --connect-timeout 10 --max-time 30 \
        --retry 3 --retry-delay 1 "${url}" 2>/dev/null); then
        return 1
    fi
    if [[ -z "${response}" ]] || ! printf '%s' "${response}" | jq -e 'type == "object"' >/dev/null 2>&1; then
        return 1
    fi
    printf '%s' "${response}"
}

load_versions() {
    if [[ ${_get_versions_loaded} -eq 0 ]]; then
        local versions_cdn_url="https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json"
        local versions_origin_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/xray_shell_versions.json"
        local response

        if ! response=$(fetch_versions_json "${versions_cdn_url}"); then
            response=$(fetch_versions_json "${versions_origin_url}") || {
                get_versions_all=""
                return 1
            }
        fi
        get_versions_all="${response}"
        _get_versions_loaded=1
    fi
    [[ -n "${get_versions_all}" ]]
}
read_config_status=1
reality_add_more="off"
reality_add_nginx="off"
reality_add_balance="off"
# Reality 负载均衡角色：primary=主服务器(安装 Nginx)，secondary=二级服务器(仅 Reality 后端)，空=未启用
reality_balance_role=""
# SNI Guard 默认值：Reality+Nginx 模式下默认启用，未知 SNI 不转发到 Xray
reality_nginx_sni_guard="on"
unknown_sni_policy="isolate"
decoy_domain=""
spiderx_path=""
old_config_status="off"
old_tls_mode="NULL"
# Distinguishes "read old config" from "locked, cannot modify".
# old_config_loaded="on" means we read the old config into memory;
# it does NOT by itself prevent parameter editing.
old_config_loaded="off"
# When "on", xray_conf_add preserves the existing Xray JSON for
# single-user configs too (保留配置重新安装 path), instead of rebuilding
# from the standard template.
reinstall_keep_config="off"
# Single state variable distinguishing the four reconfigure operations.
# Values: none | keep_config | standard_rebuild | mode_switch | clean_install
reinstall_operation="none"
# Per-field edit flags. Set to "yes" by reinstall_edit_menu when the
# user explicitly chooses to modify that field during a keep-config reinstall.
# Param functions check these to decide whether to re-prompt even when
# old_config_status="on".
change_port="no"
change_user="no"
change_transport="no"
change_inner_ports="no"
change_reality="no"
change_nginx_sni="no"
change_ws_path="no"
change_grpc_path="no"
change_xhttp_path="no"
# When "yes", email_set and UUID_set skip prompting and reuse the
# values already loaded from the old config during a mode switch.
mode_switch_reuse="off"
# Install wizard profile state. When install_wizard_preset="on", interactive
# choose functions (transport_choose, xray_reality_add_more_choose,
# reality_nginx_add_fq, reality_balance_add_fq) skip prompting and use the
# values set by apply_install_profile. This decouples menu selection from
# install-function-side prompting so the wizard never asks the same question twice.
install_profile=""
install_wizard_preset="off"
random_num=$((RANDOM % 12 + 4))
[[ -f "${xray_install_config_file}" ]] && info_extraction_all=$(jq -rc . "${xray_install_config_file}")

is_ws_mode() {
    [[ ${transport_mode} == *ws* ]]
}

is_grpc_mode() {
    [[ ${transport_mode} == *gRPC* ]]
}

is_xhttp_mode() {
    [[ ${transport_mode} == *xhttp* ]]
}

[[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}"
[[ ! -f "${log_dir}/install.log" ]] && touch "${log_dir}"/install.log
LOG_FILE="${log_dir}/install.log"
log_file="${LOG_FILE}"
LOG_MAX_SIZE=$((3 * 1024 * 1024))
MAX_ARCHIVES=5
_log_check_counter=0

log() {
    _log_check_counter=$((_log_check_counter + 1))
    if [[ $((_log_check_counter % 100)) -eq 1 ]]; then
        if [ $(stat -c%s "$LOG_FILE" 2>/dev/null) -gt $LOG_MAX_SIZE ]; then
            log_rotate
        fi
    fi

    local message=$(echo -e "$1" | sed 's/\x1B\[\([0-9]\(;[0-9]\)*\)*m//g' | tr -d '\n')
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE" >/dev/null
}

log_rotate() {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local archived_log="${LOG_FILE}.${timestamp}.gz"

    if ! gzip -c "$LOG_FILE" > "$archived_log"; then
        log_echo "${Error} ${RedBG} $(gettext "日志文件归档失败") ${Font}"
        return 1
    fi

    if ! :> "$LOG_FILE"; then
        log_echo "${Error} ${RedBG} $(gettext "日志文件清空失败") ${Font}"
        return 1
    fi

    log "$(gettext "日志文件已轮转并归档为") $archived_log"

    rotate_archives
}

rotate_archives() {
    local archives
    mapfile -t archives < <(ls "${LOG_FILE}".*.gz 2>/dev/null)
    while [ ${#archives[@]} -gt $MAX_ARCHIVES ]; do
        oldest_archive=${archives[0]}
        rm "$oldest_archive"
        mapfile -t archives < <(ls "${LOG_FILE}".*.gz 2>/dev/null)
    done
}

log_echo() {
    local message=$(printf "%b" "$@")
    echo -e "$message"
    log "$message"
}

log_echo_secure() {
    local message=$(printf "%b" "$@")
    echo -e "$message"
}

# Redact secrets before diagnostic text reaches stdout or the persistent log.
# Keep this helper in the production script: CI-only redaction cannot protect
# interactive update/rollback diagnostics on real hosts.
redact_diagnostic_text() {
    sed -E \
        -e 's#vless://[^[:space:]]+#<vless link redacted>#g' \
        -e 's/((privateKey|publicKey|password|shortIds?|UUID|uuid|token)[":=[:space:]]+)[A-Za-z0-9._:@\/+-]+/\1<redacted>/gI' \
        -e 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/<uuid redacted>/g' \
        -e 's/(Authorization:[[:space:]]*)[^[:space:]]+([[:space:]]+[^[:space:]]+)?/\1<redacted>/gI' \
        -e 's/ghp_[A-Za-z0-9]{20,}/<github token redacted>/g' \
        -e 's/github_pat_[A-Za-z0-9_]{20,}/<github token redacted>/g' |
        awk '
            /-----BEGIN [^-]*PRIVATE KEY-----/ {
                print "<private key block redacted>"
                in_private_key = 1
                next
            }
            /-----END [^-]*PRIVATE KEY-----/ {
                in_private_key = 0
                next
            }
            !in_private_key { print }
        '
}

safe_rm() {
    local target="$1"
    if [[ -z "${target}" || "${target}" == "/" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "拒绝删除空路径或根目录"): ${target} ${Font}"
        return 1
    fi
    rm -rf "${target}"
}

sed_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//&/\\&}"
    str="${str//\//\\/}"
    printf '%s' "$str"
}

update_json_config() {
    local config_file="$1"
    shift
    if [[ -z "${config_file}" ]] || [[ $# -eq 0 ]]; then
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "参数不能为空") ${Font}"
        return 1
    fi
    if [[ ! -f "${config_file}" ]]; then
        log_echo "${Error} ${RedBG} update_json_config: ${config_file} $(gettext "文件不存在") ${Font}"
        return 1
    fi

    local original_mode original_uid original_gid tmp_file _old_umask
    original_mode=$(stat -c '%a' "${config_file}" 2>/dev/null) || return 1
    original_uid=$(stat -c '%u' "${config_file}" 2>/dev/null) || return 1
    original_gid=$(stat -c '%g' "${config_file}" 2>/dev/null) || return 1
    # Use mktemp for unpredictable temp file name (same directory = same filesystem for atomic mv)
    tmp_file=$(mktemp "${config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${config_file}.tmp.$$"

    # Restrictive umask before writing sensitive content (UUID/privateKey/shortIds etc.)
    _old_umask=$(umask)
    umask 077

    if ! jq "$@" "${config_file}" > "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        return 1
    fi
    # Validate generated JSON before replacing original (fail closed on corruption)
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "生成的 JSON 无效，已保留原文件"): ${config_file} ${Font}"
        return 1
    fi
    if ! chmod "${original_mode}" "${tmp_file}" || ! chown "${original_uid}:${original_gid}" "${tmp_file}"; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${config_file} ${Font}"
        return 1
    fi
    umask "${_old_umask}"
    if ! mv "${tmp_file}" "${config_file}"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ "${config_file}" == "${xray_install_config_file}" ]]; then
        info_extraction_all=$(jq -rc . "${config_file}" 2>/dev/null) || return 1
        declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    fi
    return 0
}

# BEGIN RILL XRAY AGENT INTEGRATION
RILL_XRAY_AGENT_INTEGRATION_SCHEMA=1
rill_xray_agent_manager=/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh
# P0-5: candidate validation for script self-updates. Defined here (not only
# in the manager) so it is available even when the agent files are absent.
rxa_candidate_guard() {
    local candidate=${1:-}
    [[ -f "${candidate}" ]] || return 1
    bash -n "${candidate}" 2>/dev/null || return 1
    grep -q '^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=' "${candidate}" || return 1
    grep -q 'menu_item 9 "Rill Xray Agent"' "${candidate}" || return 1
    grep -q -- '--rill-agent-status' "${candidate}" || return 1
    grep -q 'rxa_reconfigure_enter()' "${candidate}" || return 1
    grep -q 'rxa_uninstall_finish()' "${candidate}" || return 1
    grep -q 'rxa_host_healthy()' "${candidate}" || return 1
    return 0
}
if [[ -f "$rill_xray_agent_manager" ]]; then
    source "$rill_xray_agent_manager"
else
    rxa_refresh_summary(){ RILL_XRAY_AGENT_HEADER_STATE='Agent: not installed'; RILL_XRAY_AGENT_HEADER_RUNTIME='Runtime: OFF'; RILL_XRAY_AGENT_HEADER_ROUTE='Route: OFF'; }
    rxa_menu(){ echo 'Rill Xray Agent is not installed. Run the included bootstrap script.'; menu_pause; }
    rxa_dispatch(){ case "${1:-}" in status) printf '%s\n' '{"installed":false,"routeAssistEnabled":false,"boundedAutoAllowed":false}' ;; install) bash "${scripts_dir}/rill_xray_agent_bootstrap.sh" ;; *) return 66 ;; esac; }
fi
# Lifecycle coordination used by the host install/update/uninstall paths.
# Every hook is non-fatal: it never changes the host transaction return code.
rxa_reconfigure_enter() {
    local cfg mode
    cfg=${RILL_XRAY_AGENT_CONFIG:-/etc/rill-xray-agent/config.json}
    command -v rxa_get >/dev/null 2>&1 || return 0
    [[ -f "$cfg" ]] || return 0
    mode=$(rxa_get mode 2>/dev/null || printf 'observe-only')
    printf '%s' "$mode" >"${cfg}.prior-mode" 2>/dev/null || true
    rxa_apply_mode observe-only >/dev/null 2>&1 || true
}
rxa_reconfigure_leave() {
    local rc=${1:-1} cfg mode
    cfg=${RILL_XRAY_AGENT_CONFIG:-/etc/rill-xray-agent/config.json}
    mode=$(cat "${cfg}.prior-mode" 2>/dev/null || printf 'observe-only')
    rm -f "${cfg}.prior-mode"
    if [[ "$rc" == 0 ]] && rxa_host_healthy; then
        rxa_apply_mode "$mode" >/dev/null 2>&1 || true
        RILL_XRAY_AGENT_OUTPUT=/var/lib/rill-xray-agent-xray/status/xray-observation.json \
            bash /etc/rill-xray-agent/scripts/rill_xray_agent_observe.py >/dev/null 2>&1 || true
    fi
    return 0
}
rxa_host_healthy() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl is-active --quiet xray 2>/dev/null && return 0
    systemctl is-active --quiet nginx 2>/dev/null && return 0
    return 1
}
rxa_uninstall_enter() {
    command -v rxa_apply_mode >/dev/null 2>&1 || return 0
    [[ -f /etc/rill-xray-agent/config.json ]] || return 0
    rxa_apply_mode observe-only >/dev/null 2>&1 || true
}
rxa_uninstall_finish() {
    local rc=${1:-1}
    if [[ "$rc" != 0 ]]; then
        echo 'Rill Xray Agent: host uninstall failed; agent diagnostics retained' >&2
        return 0
    fi
    bash /etc/rill-xray-agent/scripts/rill_xray_agent_uninstall.sh --purge || true
}
# END RILL XRAY AGENT INTEGRATION

download_file() {
    local url="$1"
    local dest_file="$2"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]]; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
}

download_script_file() {
    local url="$1"
    local dest_file="$2"
    local syntax_shell="${3:-bash}"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]] || ! "${syntax_shell}" -n "${tmp_file}" 2>/dev/null; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
    chmod +x "${dest_file}"
}

download_json_file() {
    local url="$1"
    local dest_file="$2"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]] || ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
}

xray_install_release() {
    local installer="${idleleo_dir}/tmp/xray-install-release.sh"
    local installer_url="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"
    local ret

    if ! download_script_file "$installer_url" "$installer"; then
        return 1
    fi
    bash "$installer" "$@"
    ret=$?
    rm -f "$installer"
    return "$ret"
}

get_public_ip() {
    local ip_version="$1"
    if [[ "${ip_version}" == "IPv6" ]]; then
        curl -6 -fsSL --max-time 10 ip.me 2>/dev/null || curl -6 -fsSL --max-time 10 ip.im 2>/dev/null
    else
        curl -4 -fsSL --max-time 10 ip.me 2>/dev/null || curl -4 -fsSL --max-time 10 ip.im 2>/dev/null
    fi
}

generate_random_port() {
    local min="$1"
    local max="$2"
    local exclude_ports="${3:-}"
    local port
    while true; do
        port=$((RANDOM % (max - min + 1) + min))
        local is_excluded=0
        for ep in ${exclude_ports}; do
            [[ "${port}" == "${ep}" ]] && is_excluded=1 && break
        done
        [[ ${is_excluded} -eq 0 ]] && echo "${port}" && return
    done
}

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

# Wait for apt/dpkg locks to be released instead of deleting them.
# Waits up to $1 seconds (default 60) for the dpkg lock to become available.
# Shows the process holding the lock if it remains held.
# Returns 0 if the lock is available (or was acquired), 1 on timeout.
# NEVER deletes lock files that are held by a running process — that corrupts
# the package database.
wait_for_apt_lock() {
    local timeout="${1:-60}"
    local elapsed=0
    local lock_files=(
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )
    if [[ -n "${APT_LOCK_FILES:-}" ]]; then
        read -r -a lock_files <<< "${APT_LOCK_FILES}"
    fi

    # apt/dpkg use POSIX/fcntl locks; flock(1) uses a different lock class and
    # can incorrectly report those files as free. Inspect actual holders with
    # fuser/lsof instead.
    while [[ ${elapsed} -lt ${timeout} ]]; do
        local locked=0
        for lock_file in "${lock_files[@]}"; do
            [[ ! -e "${lock_file}" ]] && continue
            if command -v fuser >/dev/null 2>&1; then
                if fuser "${lock_file}" >/dev/null 2>&1; then
                    locked=1
                    break
                fi
            elif command -v lsof >/dev/null 2>&1; then
                if lsof "${lock_file}" >/dev/null 2>&1; then
                    locked=1
                    break
                fi
            else
                log_echo "${Error} ${RedBG} $(gettext "无法检查 apt/dpkg 锁: 缺少 fuser 或 lsof") ${Font}"
                return 1
            fi
        done

        if [[ ${locked} -eq 0 ]]; then
            return 0
        fi

        if [[ $((elapsed % 10)) -eq 0 && ${elapsed} -gt 0 ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "等待 apt/dpkg 锁释放") (${elapsed}/${timeout}s) ${Font}"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    # Timeout reached — show holders and fail.
    log_echo "${Error} ${RedBG} $(gettext "等待 apt/dpkg 锁超时") ${Font}"
    for lock_file in "${lock_files[@]}"; do
        [[ ! -e "${lock_file}" ]] && continue
        local holders
        holders=$(fuser "${lock_file}" 2>&1 || lsof "${lock_file}" 2>/dev/null || true)
        if [[ -n "${holders}" ]]; then
            log_echo "${Error} ${lock_file}: ${holders} ${Font}"
        fi
    done
    return 1
}

check_system() {
    if [[ "${ID}" == "centos" || "${ID}" == "rocky" || "${ID}" == "almalinux" ]] && [[ ${VERSION_ID%%.*} -ge 10 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        [[ ! -f "${xray_install_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 12 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_install_config_file}" ]]; then
            wait_for_apt_lock 60 || exit 1
            dpkg --configure -a || exit 1
            $INS update || exit 1
        fi
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 24 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_install_config_file}" ]]; then
            # Wait for apt/dpkg locks instead of deleting them.
            # Deleting locks that are held by a running process corrupts the
            # package database and can leave the system in an unrecoverable state.
            if ! wait_for_apt_lock 60; then
                log_echo "${Error} ${RedBG} $(gettext "apt/dpkg 锁等待超时, 请稍后重试或手动检查占用进程") ${Font}"
                exit 1
            fi
            # Configure any interrupted packages — safe now that we hold the lock.
            dpkg --configure -a || exit 1
            $INS update || exit 1
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} $(gettext "不在支持的系统列表内, 安装中断")! ${Font}"
        exit 1
    fi
}

is_root() {
    if [[ 0 == $UID ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前用户是 root 用户, 开始安装") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "当前用户不是 root 用户, 请切换到 root 用户后重新运行脚本")! ${Font}"
        exit 1
    fi
}

check_and_create_user_group() {
    if ! getent group nogroup > /dev/null; then
        groupadd nogroup
    fi

    if ! id nobody > /dev/null 2>&1; then
        useradd -r -g nogroup -s /sbin/nologin -c "Unprivileged User" nobody
    fi
}

check_language_update() {
    local lang_code="$1"
    local local_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/xray_install.mo"
    local version_file_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/i18n/languages/${lang_code}/LC_MESSAGES/version"

    [[ ! -f "${local_file}" ]] && return 0

    local remote_version
    remote_version=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "${version_file_url}" 2>/dev/null || echo "")

    if [ -z "$remote_version" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "无法获取远程语言文件信息") ${Font}"
        return 1
    fi

    local local_version
    local_version=$(cat "${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/version" 2>/dev/null || echo "")

    [ "$remote_version" != "$local_version" ]
}

update_language_file() {
    local lang_code="$1"
    local mo_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/xray_install.mo"
    local version_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/version"
    local github_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/i18n/languages"

    mkdir -p "${idleleo_dir}/languages/${lang_code}/LC_MESSAGES"

    log_echo "${Info} ${Green} $(gettext "正在更新语言文件")... ${Font}"

    if ! download_file "${github_url}/${lang_code}/LC_MESSAGES/xray_install.mo" "${mo_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件更新失败") ${Font}"
        return 1
    fi

    if [ ! -s "${mo_file}" ]; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件无效") ${Font}"
        rm -f "${mo_file}"
        return 1
    fi

    if ! download_file "${github_url}/${lang_code}/LC_MESSAGES/version" "${version_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "版本文件更新失败") ${Font}"
        return 1
    fi

    find "${idleleo_dir}/languages" -type d -exec chmod 755 {} \;
    find "${idleleo_dir}/languages" -type f -exec chmod 644 {} \;

    log_echo "${OK} ${Green} $(gettext "语言文件更新") $(gettext "完成") ${Font}"
}

# Safely read language.conf without sourcing it as a shell script.
# Only LANG= and LC_MESSAGES= assignments are parsed. The function rejects:
#   - command substitution ($(...), `...`)
#   - shell metacharacters (;, &&, ||, |, <, >, &)
#   - unknown keys (anything other than LANG or LC_MESSAGES)
#   - values that don't match the locale name pattern ([a-zA-Z0-9_.@-]+)
# Returns 0 if the file was parsed (even partially), 1 on fatal error.
safe_source_language_conf() {
    local conf_file="$1"

    if [[ -z "${conf_file}" || ! -f "${conf_file}" ]]; then
        return 1
    fi

    # Read the file line by line. This avoids any shell interpretation.
    local line key value
    local parsed_lang=""
    local parsed_lc_messages=""
    local invalid=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Skip empty lines and comments.
        line="${line#"${line%%[![:space:]]*}"}"  # trim leading whitespace
        [[ -z "${line}" || "${line}" == \#* ]] && continue

        # Reject lines that contain shell metacharacters or command substitution.
        if [[ "${line}" == *'$('* || "${line}" == *'`'* || "${line}" == *';'* || \
              "${line}" == *'&&'* || "${line}" == *'||'* || "${line}" == *'|'* || \
              "${line}" == *'<'* || "${line}" == *'>'* || "${line}" == *'&'* ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 包含可疑字符, 跳过该行"): ${line} ${Font}"
            invalid=1
            continue
        fi

        # Parse KEY=value without evaluating shell syntax. Bash's ERE engine
        # does not portably support the back-reference previously used here.
        if [[ "${line}" != *=* ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 行格式无效, 跳过"): ${line} ${Font}"
            invalid=1
            continue
        fi
        key="${line%%=*}"
        value="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        case "${value}" in
            \"*\")
                value="${value#\"}"
                value="${value%\"}"
                ;;
            \'*\')
                value="${value#\'}"
                value="${value%\'}"
                ;;
        esac
        if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 键格式无效, 跳过"): ${key} ${Font}"
            invalid=1
            continue
        fi

        # Allowlist: only LANG and LC_MESSAGES are permitted.
        case "${key}" in
            LANG|LC_MESSAGES)
                # Validate value: only locale characters (letters, digits, _ . @ -).
                if [[ ! "${value}" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
                    log_echo "${Warning} ${YellowBG} $(gettext "language.conf 值包含非法字符, 跳过"): ${key}=${value} ${Font}"
                    invalid=1
                    continue
                fi
                if [[ "${key}" == "LANG" ]]; then
                    parsed_lang="${value}"
                else
                    parsed_lc_messages="${value}"
                fi
                ;;
            *)
                log_echo "${Warning} ${YellowBG} $(gettext "language.conf 未知键, 跳过"): ${key} ${Font}"
                invalid=1
                continue
                ;;
        esac
    done < "${conf_file}"

    # Reject the complete file rather than partially applying a mixed
    # valid/malicious payload.
    [[ ${invalid} -eq 0 ]] || return 1
    [[ -n "${parsed_lang}" ]] && export LANG="${parsed_lang}"
    [[ -n "${parsed_lc_messages}" ]] && export LC_MESSAGES="${parsed_lc_messages}"
    return 0
}

init_language() {
    if ! command -v gettext >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "正在安装") gettext... ${Font}"
        pkg_install "gettext"
        if [ $? -ne 0 ]; then
            log_echo "${Error} ${RedBG} gettext $(gettext "安装") $(gettext "失败"), $(gettext "将使用默认语言") ${Font}"
            unset LANG
            unset LC_MESSAGES
            return 1
        fi
    fi

    local gettext_paths=(
        "/usr/share/gettext/gettext.sh"
        "/usr/local/share/gettext/gettext.sh"
        "/usr/bin/gettext.sh"
        "/usr/local/bin/gettext.sh"
        "/usr/share/gettext-"*/gettext.sh
    )

    local gettext_sh=""
    for path in "${gettext_paths[@]}"; do
        if [ -f "$path" ]; then
            gettext_sh="$path"
            break
        fi
    done

    if [ -z "$gettext_sh" ]; then
        log_echo "${Error} ${RedBG} $(gettext "未找到") gettext.sh, $(gettext "将使用默认语言") ${Font}"
        unset LANG
        unset LC_MESSAGES
        return 1
    fi

    [ -d "${idleleo_dir}/languages" ] || mkdir "${idleleo_dir}/languages"
    export TEXTDOMAIN="xray_install"
    export TEXTDOMAINDIR="${idleleo_dir}/languages"
    . "$gettext_sh"

    if [ -f "${idleleo_dir}/language.conf" ]; then
        # Safe-read language.conf instead of sourcing it directly.
        # Only LANG= and LC_MESSAGES= assignments are allowed. Command
        # substitution, extra shell statements, and unknown keys are rejected.
        if ! safe_source_language_conf "${idleleo_dir}/language.conf"; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 校验失败, 将使用默认语言") ${Font}"
            unset LANG
            unset LC_MESSAGES
            return 0
        fi

        if [[ "${LANG%.*}" != "zh_CN" ]]; then
            local lang_code
            case "${LANG%.*}" in
                "en_US") lang_code="en" ;;
                "fa_IR") lang_code="fa" ;;
                "ru_RU") lang_code="ru" ;;
                "ko_KR") lang_code="ko" ;;
                "fr_FR") lang_code="fr" ;;
                *)
                    log_echo "${Warning} ${YellowBG} $(gettext "不支持的语言"):${LANG%.*}, $(gettext "将使用默认语言") ${Font}"
                    unset LANG
                    unset LC_MESSAGES
                    return 0
                    ;;
            esac

            local lang_file="${TEXTDOMAINDIR}/${lang_code}/LC_MESSAGES/${TEXTDOMAIN}.mo"
            if [ ! -f "$lang_file" ]; then
                if ! update_language_file "$lang_code"; then
                    log_echo "${Warning} ${YellowBG} $(gettext "语言文件更新失败"), $(gettext "将使用默认语言") ${Font}"
                    unset LANG
                    unset LC_MESSAGES
                    return 0
                fi
            elif check_language_update "$lang_code"; then
                log_echo "${Info} ${Green} $(gettext "发现语言文件更新") ${Font}"
                if update_language_file "$lang_code"; then
                    . "$gettext_sh"
                fi
            fi
        fi
    # else
        # log_echo "${Info} ${Green} $(gettext "未找到") language.conf, $(gettext "将使用默认语言") ${Font}"
        # unset LANG
        # unset LC_MESSAGES
    fi
}

judge() {
    local ret=$?
    local judge_mode="exit"
    if [[ "$1" == "-r" || "$1" == "--return" ]]; then
        judge_mode="return"
        shift
    fi
    local desc="$1"
    if [[ $# -gt 1 ]]; then
        "${@:2}"
        ret=$?
    fi

    if [[ $ret -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} ${desc} $(gettext "完成") ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} ${desc} $(gettext "失败") ${Font}"
        if [[ "${judge_mode}" == "return" ]]; then
            return 1
        else
            exit 1
        fi
    fi
    return $ret
}

check_version() {
    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi
    local result
    if ! result=$(printf '%s' "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null) ||
        [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi
    printf '%s\n' "${result}"
}

# Silent version reader for optional API fields (e.g. *_tested_version).
# Returns empty string on missing/null fields without printing error messages,
# so read_version can probe for tested_version without spamming users on
# older API payloads that don't yet carry the field.
check_version_silent() {
    load_versions || return 1
    local result
    if ! result=$(printf '%s' "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null) ||
        [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        return 1
    fi
    printf '%s\n' "${result}"
}

pkg_install_judge() {
    if [[ "${ID}" == "centos" ]]; then
        yum list installed | grep -iw "^$1"
    else
        dpkg --get-selections | grep -iw "^$1" | grep -ivw "deinstall"
    fi
}

pkg_install() {
    install_array=(${1//,/ })
    install_status=1
    if [[ ${#install_array[@]} -gt 1 ]]; then
        for install_var in "${install_array[@]}"; do
            if [[ -z $(pkg_install_judge "${install_var}") ]]; then
                ${INS} -y install "${install_var}"
                install_status=0
            fi
        done
        if [[ ${install_status} == 0 ]]; then
            judge "$(gettext "安装") ${1//,/ }"
        else
            log_echo "${OK} ${GreenBG} $(gettext "已安装") ${1//,/ } ${Font}"
            sleep 0.5
        fi
    else
        if [[ -z $(pkg_install_judge "$1") ]]; then
            ${INS} -y install $1
            judge "$(gettext "安装") $1"
        else
            log_echo "${OK} ${GreenBG} $(gettext "已安装") $1 ${Font}"
            sleep 0.5
        fi
    fi
}

dependency_install() {
    pkg_install "bc,curl,dbus,git,jq,lsof,python3,qrencode"
    if [[ "${ID}" == "centos" ]]; then
        pkg_install "crontabs"
    else
        pkg_install "cron"
    fi
    if [[ ! -f "/var/spool/cron/root" ]] && [[ ! -f "/var/spool/cron/crontabs/root" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
            systemctl start crond && systemctl enable crond >/dev/null 2>&1
            judge "crontab $(gettext "自启动配置")"
        else
            touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
            systemctl start cron && systemctl enable cron >/dev/null 2>&1
            judge "crontab $(gettext "自启动配置")"
        fi
    fi
    if [[ ${tls_mode} != "None" ]] && [[ ${tls_mode} != "XTLS" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "epel-release,iputils,pcre,pcre-devel,zlib-devel,perl-IPC-Cmd"
        else
            pkg_install "iputils-ping,libpcre3,libpcre3-dev,zlib1g-dev"
        fi
        judge "Nginx $(gettext "链接库安装")"
    fi
}

read_optimize() {
    local prompt="$1"
    local var_name="$2"
    local default_value="${3:-NULL}"
    local min_value="${4:-}"
    local max_value="${5:-}"
    local error_msg="${6:-$(gettext "值为空或超出范围, 请重新输入")!}"
    local user_input

    while true; do
        if ! IFS= read -r -p "${prompt}" user_input; then
            log_echo "${Error} ${RedBG} $(gettext "输入已结束, 操作取消") ${Font}"
            return 1
        fi

        if [[ -z "${user_input}" ]]; then
            if [[ "${default_value}" != "NULL" ]]; then
                user_input="${default_value}"
            else
                log_echo "${Error} ${RedBG} $(gettext "值为空, 请重新输入")! ${Font}"
                continue
            fi
        fi

        if [[ -n "${min_value}" || -n "${max_value}" ]]; then
            if [[ ! "${user_input}" =~ ^[0-9]+$ ]]; then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
            if [[ -n "${min_value}" ]] && (( user_input < min_value )); then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
            if [[ -n "${max_value}" ]] && (( user_input > max_value )); then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
        fi

        printf -v "${var_name}" '%s' "${user_input}"
        return 0
    done
}

basic_optimization() {
    # Fail-closed: every system write must propagate failure so a caller's
    # `basic_optimization || return 1` aborts the install chain instead of
    # continuing after a half-applied limits tuning.
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf || return 1
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf || return 1
    printf '%s\n' '* soft nofile 65536' >>/etc/security/limits.conf || return 1
    printf '%s\n' '* hard nofile 65536' >>/etc/security/limits.conf || return 1

    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config || return 1
        setenforce 0 || return 1
    fi

    return 0
}

create_directory() {
    # Fail-closed: any mkdir that cannot create a target terminates the
    # function so the caller can abort the deploy before further steps run.
    # Each existing directory short-circuits to 0 (no mkdir, no error).
    if [[ ${tls_mode} != "None" ]] && [[ ${tls_mode} != "XTLS" ]]; then
        [[ -d "${nginx_conf_dir}" ]] || mkdir -p "${nginx_conf_dir}" || return 1
    fi
    [[ -d "${ssl_chainpath}" ]] || mkdir -p "${ssl_chainpath}" || return 1
    [[ -d "${xray_conf_dir}" ]] || mkdir -p "${xray_conf_dir}" || return 1
    [[ -d "${idleleo_dir}/info" ]] || mkdir -p "${idleleo_dir}"/info || return 1
    [[ -d "${idleleo_conf_dir}" ]] || mkdir -p "${idleleo_conf_dir}" || return 1

    return 0
}

is_reality_reserved_port() {
    case "$1" in
        9403|9404|9443|9444) return 0 ;;
        *) return 1 ;;
    esac
}

reality_reserved_port_conflict() {
    local configured_port
    for configured_port in "${port:-}" "${xport:-}" "${gport:-}" "${xhttpport:-}"; do
        if [[ -n "${configured_port}" ]] && is_reality_reserved_port "${configured_port}"; then
            echo "${configured_port}"
            return 0
        fi
    done
    return 1
}

validate_reality_reserved_ports() {
    local conflicting_port
    if conflicting_port=$(reality_reserved_port_conflict); then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${conflicting_port} ${Font}"
        return 1
    fi
    return 0
}

validate_port_number() {
    local port="$1"
    [[ "${port}" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

validate_active_ports() {
    local -a names=()
    local -a values=()
    local i j

    if [[ -n "${port:-}" && "${port}" != "None" ]]; then
        names+=("port")
        values+=("${port}")
    fi
    if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
        names+=("ws")
        values+=("${xport}")
    fi
    if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
        names+=("gRPC")
        values+=("${gport}")
    fi
    if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
        names+=("xHTTP")
        values+=("${xhttpport}")
    fi

    for i in "${!values[@]}"; do
        validate_port_number "${values[$i]}" || return 1
        if [[ "${tls_mode:-}" == "Reality" ]] && is_reality_reserved_port "${values[$i]}"; then
            return 1
        fi
        for ((j = i + 1; j < ${#values[@]}; j++)); do
            if [[ "${values[$i]}" == "${values[$j]}" ]]; then
                log_echo "${Error} ${RedBG} $(gettext "端口重复"): ${names[$i]}=${values[$i]}, ${names[$j]}=${values[$j]} ${Font}"
                return 1
            fi
        done
    done
    return 0
}

port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_port} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "确定端口") ${Font}"
        read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
        while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${port}"; do
            echo -e "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
            read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
        done
    fi
}

# Reset install wizard profile state before each wizard entry.
# Must NOT clear old_config_status (preserves "retain old config" mode).
reset_install_wizard_state() {
    install_profile=""
    install_wizard_preset="off"
    reality_add_more="off"
    reality_add_nginx="off"
    reality_add_balance="off"
    reality_balance_role=""
    transport_mode="None"
}

# Apply install profile: sets tls_mode / reality_* / transport_mode / shell_mode
# based on the profile selected by the hierarchical install wizard.
#
# For profiles that include an extra transport (reality_transport,
# reality_transport_nginx, transport_nginx_tls, transport_only), transport_mode
# is NOT overwritten here — it is set beforehand by menu_choose_transport, and
# shell_mode is derived later by _transport_set_shell_mode.
#
# For profiles without extra transport (reality_nginx, reality_standard,
# xtls_only), transport_mode is forced to "None" and shell_mode is set directly.
apply_install_profile() {
    case "${install_profile}" in
        reality_nginx)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="on"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Nginx+Reality"
            ;;
        reality_standard)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Reality"
            ;;
        reality_transport)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_transport_nginx)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="on"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_balance_primary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="on"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="primary"
            shell_mode="Nginx+Reality+Balance"
            ;;
        reality_balance_secondary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="off"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="secondary"
            shell_mode="Reality+Balance"
            ;;
        transport_nginx_tls)
            tls_mode="TLS"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        transport_only)
            tls_mode="None"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        xtls_only)
            tls_mode="XTLS"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="XTLS ONLY"
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "未知的安装配置") ${Font}"
            return 1
            ;;
    esac
    return 0
}

transport_choose() {
    # Install wizard preset: transport_mode already set by menu_choose_transport.
    if [[ ${install_wizard_preset:-off} == "on" ]] &&
       [[ -n ${transport_mode:-} ]] &&
       [[ ${transport_mode} != "None" ]]; then
        _transport_set_shell_mode
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_transport} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "请选择传输协议") ${Font}"
        echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
        echo "2: gRPC"
        echo "3: xHTTP"
        echo "4: ws+xHTTP"
        echo "5: ws+gRPC+xHTTP"
        local choose_network
        read_optimize "$(gettext "请输入"): " "choose_network" 1 1 5 "$(gettext "请输入有效的数字")!" || return 1
        case ${choose_network} in
        2)
            transport_mode="onlygRPC"
            ;;
        3)
            transport_mode="onlyxhttp"
            ;;
        4)
            transport_mode="wsxhttp"
            ;;
        5)
            transport_mode="wsgRPCxhttp"
            ;;
        *)
            transport_mode="onlyws"
            ;;
        esac
        _transport_set_shell_mode
    fi
}

_transport_set_shell_mode() {
    local transport_label=""

    # Non-transport installs (standard Reality, Reality+Nginx, Reality balance
    # primary/secondary, XTLS ONLY, and the not-installed state) persist
    # transport_mode="None" in the config. On script restart judge_mode reads
    # the config and calls this function; without this branch shell_mode would
    # stay at the initial "未安装" placeholder. Derive shell_mode from tls_mode
    # and the reality_* flags so the menu reflects the real installed mode.
    if [[ -z ${transport_mode:-} ||
          ${transport_mode} == "None" ||
          ${transport_mode} == "null" ]]; then
        case ${tls_mode} in
        Reality)
            if [[ ${reality_add_balance} == "on" ]]; then
                if [[ ${reality_add_nginx} == "on" ]]; then
                    shell_mode="Nginx+Reality+Balance"
                else
                    shell_mode="Reality+Balance"
                fi
            elif [[ ${reality_add_nginx} == "on" ]]; then
                shell_mode="Nginx+Reality"
            else
                shell_mode="Reality"
            fi
            ;;
        XTLS)
            shell_mode="XTLS ONLY"
            ;;
        None)
            shell_mode="$(gettext "未安装")"
            ;;
        esac
        return 0
    fi

    case ${transport_mode} in
    onlyws) transport_label="ws";;
    onlygRPC) transport_label="gRPC";;
    onlyxhttp) transport_label="xHTTP";;
    wsxhttp) transport_label="ws+xHTTP";;
    wsgRPCxhttp) transport_label="ws+gRPC+xHTTP";;
    *) return;;
    esac
    case ${tls_mode} in
    TLS)
        shell_mode="Nginx+${transport_label}+TLS"
        ;;
    Reality)
        if [[ ${reality_add_more} == "on" && ${reality_add_nginx} == "off" ]]; then
            shell_mode="Reality+${transport_label}"
        elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "on" ]]; then
            shell_mode="Nginx+Reality+${transport_label}"
        elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "off" ]]; then
            shell_mode="Nginx+Reality"
        else
            shell_mode="Reality"
        fi
        if [[ ${reality_add_balance} == "on" ]]; then
            shell_mode="${shell_mode}+Balance"
        fi
        ;;
    None)
        shell_mode="${transport_label} ONLY"
        ;;
    XTLS)
        shell_mode="XTLS ONLY"
        ;;
    esac
}

xray_reality_add_more_choose() {
    # Install wizard preset: reality_add_more and transport_mode already set
    # by apply_install_profile + menu_choose_transport.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_more} == "on" ]]; then
            # transport_mode already set; derive shell_mode and init ports/paths
            _transport_set_shell_mode
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
            if is_ws_mode; then
                port_exist_check "${xport}" || return 1
            fi
            if is_grpc_mode; then
                port_exist_check "${gport}" || return 1
            fi
            if is_xhttp_mode; then
                port_exist_check "${xhttpport}" || return 1
            fi
        else
            transport_mode="None"
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
        fi
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_transport} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否添加用于负载均衡的 ws/gRPC 协议") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择")! ${Font}"
        read -r reality_add_more_fq
        case $reality_add_more_fq in
        [yY][eE][sS] | [yY])
            reality_add_more="on"
            transport_choose || return 1
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
            if is_ws_mode; then
                port_exist_check "${xport}" || return 1
            fi
            if is_grpc_mode; then
                port_exist_check "${gport}" || return 1
            fi
            if is_xhttp_mode; then
                port_exist_check "${xhttpport}" || return 1
            fi
            ;;
        *)
            reality_add_more="off"
            transport_mode="None"
            ws_inbound_port_set
            grpc_inbound_port_set
            xhttp_inbound_port_set
            ws_path_set
            grpc_path_set
            xhttp_path_set
            log_echo "${OK} ${GreenBG} $(gettext "已跳过添加简单 ws/gRPC/xHTTP 协议") ${Font}"
            ;;
        esac
    fi
}

transport_qr() {
    artpath="None"
    artxport="None"
    artserviceName="None"
    artgport="None"
    artxhttppath="None"
    artxhttpport="None"
    artnet="ws/gRPC"
    if is_ws_mode; then
        artxport=${xport}
        artpath=${path}
    fi
    if is_grpc_mode; then
        artgport=${gport}
        artserviceName=${serviceName}
    fi
    if is_xhttp_mode; then
        artxhttpport=${xhttpport}
        artxhttppath=${xhttppath}
        artnet="xHTTP"
    fi
    if [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
        artnet="ws/gRPC/xHTTP"
    elif [[ ${transport_mode} == "wsxhttp" ]]; then
        artnet="ws/xHTTP"
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_ws_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") ws inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") ws inbound_port ($(gettext "请勿与其他端口相同")!): " "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${xport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") ws inbound_port ($(gettext "请勿与其他端口相同")!): " "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            *)
                xport=$(generate_random_port 10000 10999)
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            esac
        fi
    fi
}

grpc_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_grpc_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") gRPC inbound_port ($(gettext "请勿与其他端口相同")!): " "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${gport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") gRPC inbound_port ($(gettext "请勿与其他端口相同")!): " "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            *)
                gport=$(generate_random_port 10000 10999)
                while [[ ${gport} == ${xport} ]]; do gport=$(generate_random_port 10000 10999); done
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            esac
        fi
    fi
}

xhttp_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_xhttp_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") xHTTP inbound_port ($(gettext "请勿与其他端口相同")!): " "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${xhttpport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") xHTTP inbound_port ($(gettext "请勿与其他端口相同")!): " "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
                ;;
            *)
                xhttpport=$(generate_random_port 11000 11999)
                while [[ ${xhttpport} == ${xport} || ${xhttpport} == ${gport} ]]; do xhttpport=$(generate_random_port 11000 11999); done
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
                ;;
            esac
        fi
    fi
}

managed_ports_file="${idleleo_conf_dir}/managed_ports.json"

# Managed-firewall compatibility layer.
# The project historically only manages iptables directly; if firewalld or
# nftables frontends are introduced later, route through these helpers so
# rule idempotency and managed-port tracking remain single-sourced.
firewall_rule_exists() {
    local proto="$1"
    local port="$2"
    iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1
}

firewall_add_managed_port() {
    local proto="$1"
    local port="$2"
    firewall_rule_exists "${proto}" "${port}" ||
        iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT
}

firewall_remove_managed_port() {
    local proto="$1"
    local port="$2"
    while firewall_rule_exists "${proto}" "${port}"; do
        iptables -D INPUT -p "${proto}" --dport "${port}" -j ACCEPT || return 1
    done
}

# Idempotent helper: add OUTPUT accept rule for a sport. Fails closed.
firewall_add_output_port() {
    local proto="$1"
    local port="$2"
    iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1 ||
        iptables -I OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT
}

# Check whether an OUTPUT sport accept rule exists.
firewall_output_rule_exists() {
    local proto="$1"
    local port="$2"
    iptables -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1
}

# Idempotent helper: remove OUTPUT accept rule for a sport. Fails closed.
firewall_remove_output_port() {
    local proto="$1"
    local port="$2"
    while firewall_output_rule_exists "${proto}" "${port}"; do
        iptables -D OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT || return 1
    done
}

# Idempotent helper: add loopback accept rules. Fails closed.
firewall_add_loopback_rules() {
    iptables -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 ||
        iptables -A INPUT -i lo -j ACCEPT
    iptables -C OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 ||
        iptables -A OUTPUT -o lo -j ACCEPT
}

# Idempotent helper: add UDP high-port range accept for INPUT. Fails closed.
firewall_add_udp_high_port_range() {
    iptables -C INPUT -p udp --dport 1024:65535 -j ACCEPT >/dev/null 2>&1 ||
        iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
}

atomic_write_managed_ports() {
    local json="$1"
    mkdir -p "$(dirname "${managed_ports_file}")"
    local tmp_file="${managed_ports_file}.tmp.$$"
    printf '%s' "${json}" > "${tmp_file}" || return 1
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${managed_ports_file}"
}

collect_new_managed_ports() {
    local -a tcp=()
    local -a udp=()
    if [[ -n "${port:-}" && "${port}" != "None" ]]; then
        tcp+=("${port}")
        udp+=("${port}")
    fi
    if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
        tcp+=("${xport}")
        udp+=("${xport}")
    fi
    if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
        tcp+=("${gport}")
        udp+=("${gport}")
    fi
    if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
        tcp+=("${xhttpport}")
        udp+=("${xhttpport}")
    fi
    new_ports_json=$(jq -nc \
        --argjson tcp "$(printf '%s\n' "${tcp[@]:-}" | jq -R . | jq -s 'unique')" \
        --argjson udp "$(printf '%s\n' "${udp[@]:-}" | jq -R . | jq -s 'unique')" \
        '{tcp:$tcp, udp:$udp}')
}

reconcile_managed_firewall() {
    local old_json="$1"
    local new_json="$2"
    local old_tcp new_tcp old_udp new_udp port

    old_tcp=$(printf '%s' "${old_json}" | jq -r '.tcp[]? // empty')
    new_tcp=$(printf '%s' "${new_json}" | jq -r '.tcp[]? // empty')
    old_udp=$(printf '%s' "${old_json}" | jq -r '.udp[]? // empty')
    new_udp=$(printf '%s' "${new_json}" | jq -r '.udp[]? // empty')

    # Remove script-managed old TCP INPUT ports no longer in the new set.
    # Fail closed: if removal fails, abort so we don't leave stale rules.
    while IFS= read -r port; do
        [[ -n "${port}" ]] || continue
        printf '%s\n' "${new_tcp}" | grep -qxF "${port}" ||
            firewall_remove_managed_port tcp "${port}" || return 1
    done <<< "${old_tcp}"

    # Remove script-managed old UDP INPUT ports no longer in the new set.
    while IFS= read -r port; do
        [[ -n "${port}" ]] || continue
        printf '%s\n' "${new_udp}" | grep -qxF "${port}" ||
            firewall_remove_managed_port udp "${port}" || return 1
    done <<< "${old_udp}"

    # Remove script-managed old TCP OUTPUT sport rules no longer in the new set.
    while IFS= read -r port; do
        [[ -n "${port}" ]] || continue
        printf '%s\n' "${new_tcp}" | grep -qxF "${port}" ||
            firewall_remove_output_port tcp "${port}" || return 1
    done <<< "${old_tcp}"

    # Remove script-managed old UDP OUTPUT sport rules no longer in the new set.
    while IFS= read -r port; do
        [[ -n "${port}" ]] || continue
        printf '%s\n' "${new_udp}" | grep -qxF "${port}" ||
            firewall_remove_output_port udp "${port}" || return 1
    done <<< "${old_udp}"

    # Add new managed TCP INPUT ports (idempotent).
    # Fail closed: if add fails, abort so caller can rollback.
    for port in ${new_tcp}; do
        [[ -n "${port}" ]] || continue
        firewall_add_managed_port tcp "${port}" || return 1
    done

    # Add new managed UDP INPUT ports.
    for port in ${new_udp}; do
        [[ -n "${port}" ]] || continue
        firewall_add_managed_port udp "${port}" || return 1
    done

    # Add new managed TCP OUTPUT sport rules.
    for port in ${new_tcp}; do
        [[ -n "${port}" ]] || continue
        firewall_add_output_port tcp "${port}" || return 1
    done

    # Add new managed UDP OUTPUT sport rules.
    for port in ${new_udp}; do
        [[ -n "${port}" ]] || continue
        firewall_add_output_port udp "${port}" || return 1
    done
    return 0
}

# Apply a managed-firewall port-set change transactionally (old → new).
#   - Reconciles rules old→new; on any partial failure reverses new→old so
#     no half-applied rules remain.
#   - On success persists the new set to managed_ports.json. If the write
#     fails, reverses new→old so no stale rules remain.
#   - Tracks the transaction state in _reinstall_firewall_changed so the global
#     rollback knows exactly what must still be reversed:
#       no      — not modified, or already fully reversed
#       pending — forward changes started but reverse not confirmed; the global
#                 rollback MUST retry the reverse
#       yes     — forward change succeeded; the global rollback must reverse it
#   - A failed forward change or state-file write always tries new→old
#     immediately. The reverse error is NEVER swallowed with `|| true` — on
#     reverse failure the state stays "pending" so reinstall_backup_restore
#     retries instead of silently leaving half-applied rules.
# Returns 0 on success, 1 on failure.
apply_managed_firewall_transaction() {
    local old_json="$1" new_json="$2"
    _reinstall_firewall_old_ports="${old_json}"
    _reinstall_firewall_new_ports="${new_json}"
    _reinstall_firewall_changed="pending"
    if ! reconcile_managed_firewall "${old_json}" "${new_json}"; then
        if reconcile_managed_firewall "${new_json}" "${old_json}" 2>/dev/null; then
            _reinstall_firewall_changed="no"
        else
            log_echo "${Error} ${RedBG} $(gettext "防火墙规则前向修改失败且反向恢复未完成, 全局回滚时将再次尝试") ${Font}"
        fi
        return 1
    fi
    _reinstall_firewall_changed="yes"
    if ! atomic_write_managed_ports "${new_json}"; then
        if reconcile_managed_firewall "${new_json}" "${old_json}" 2>/dev/null; then
            _reinstall_firewall_changed="no"
        else
            log_echo "${Error} ${RedBG} $(gettext "防火墙状态写入失败且反向恢复未完成, 全局回滚时将再次尝试") ${Font}"
        fi
        return 1
    fi
    return 0
}

firewall_set() {
    echo
    log_echo "${GreenBG} $(gettext "是否需要设置防火墙") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r firewall_set_fq
    case $firewall_set_fq in
    [yY][eE][sS] | [yY])
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "iptables-services"
        else
            pkg_install "iptables-persistent"
        fi

        # Always-on infrastructure rules (idempotent, never auto-removed):
        # loopback, DNS (53), and the FullCone UDP high-port range. These are
        # required in every mode and are tracked as separate always-on state.
        firewall_add_loopback_rules || return 1
        firewall_add_managed_port tcp 53 || return 1
        firewall_add_managed_port udp 53 || return 1
        firewall_add_output_port tcp 53 || return 1
        firewall_add_output_port udp 53 || return 1
        firewall_add_udp_high_port_range || return 1

        # Capture the pre-deploy managed set once (loaded at reconfig start).
        # Fall back to reading managed_ports.json for a standalone firewall_set.
        if [[ -z "${_reinstall_firewall_old_ports:-}" || \
              "${_reinstall_firewall_old_ports:-}" == '{"tcp":[],"udp":[]}' ]]; then
            _reinstall_firewall_old_ports=$(cat "${managed_ports_file}" 2>/dev/null ||
                echo '{"tcp":[],"udp":[]}')
        fi

        # Build the full new managed set: main + transport ports, plus port 80
        # when TLS mode (ACME / HTTP redirect). Including 80 in the managed set
        # lets a TLS → Reality switch remove the now-unneeded 80 rule.
        collect_new_managed_ports
        if [[ ${tls_mode} == "TLS" ]]; then
            new_ports_json=$(printf '%s' "${new_ports_json}" |
                jq '.tcp = ((.tcp + [80]) | unique) | .udp = ((.udp + [80]) | unique)')
        fi
        _reinstall_firewall_new_ports="${new_ports_json}"

        # Apply the managed rules as a transaction (old → new). Any partial
        # failure or managed_ports.json write failure reverses the rules.
        apply_managed_firewall_transaction \
            "${_reinstall_firewall_old_ports}" \
            "${_reinstall_firewall_new_ports}" || {
                log_echo "${Error} ${RedBG} $(gettext "防火墙规则更新失败") ${Font}"
                return 1
            }

        # Persist rules. Failures here are non-fatal (rules are already active).
        if [[ "${ID}" == "centos" || "${ID}" == "rocky" || "${ID}" == "almalinux" ]]; then
            service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            service iptables restart 2>/dev/null || true
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") ${Font}"
        else
            netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") ${Font}"
        fi

        log_echo "${OK} ${GreenBG} $(gettext "开放防火墙相关端口") ${Font}"
        log_echo "${Warning} ${GreenBG} $(gettext "若修改配置, 请注意关闭防火墙相关端口") ${Font}"
        log_echo "${OK} ${GreenBG} $(gettext "配置") Xray FullCone ${Font}"
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "跳过防火墙设置") ${Font}"
        ;;
    esac
}

ws_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_ws_path} == "yes" ]]; then
            if is_ws_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") ws $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") ws $(gettext "伪装路径") ($(gettext "不需要")"/":)" "path" "NULL" || return 1
                    path="${path#/}"
                    log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                    ;;
                *)
                    path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_ws_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") ws $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_ws_path_fq
            case $change_ws_path_fq in
            [yY][eE][sS] | [yY])
                change_ws_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

grpc_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_grpc_path} == "yes" ]]; then
            if is_grpc_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") gRPC $(gettext "伪装路径") ($(gettext "不需要")"/":)" "serviceName" "NULL" || return 1
                    serviceName="${serviceName#/}"
                    log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                    ;;
                *)
                    serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_grpc_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_grpc_path_fq
            case $change_grpc_path_fq in
            [yY][eE][sS] | [yY])
                change_grpc_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

xhttp_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_xhttp_path} == "yes" ]]; then
            if is_xhttp_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") xHTTP $(gettext "伪装路径") ($(gettext "不需要")"/":)" "xhttppath" "NULL" || return 1
                    xhttppath="${xhttppath#/}"
                    log_echo "${Green} xHTTP $(gettext "伪装路径"): ${xhttppath} ${Font}"
                    ;;
                *)
                    xhttppath="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} xHTTP $(gettext "伪装路径"): ${xhttppath} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_xhttp_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_xhttp_path_fq
            case $change_xhttp_path_fq in
            [yY][eE][sS] | [yY])
                change_xhttp_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

email_set() {
    # Reuse old UUID/email during mode switch without re-prompting.
    if [[ ${mode_switch_reuse} == "yes" && -n "${custom_email:-}" ]]; then
        log_echo "${Green} Xray $(gettext "用户名") (email): ${custom_email} ${Font}"
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_user} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") Xray $(gettext "用户名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_email_fq
        case $custom_email_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入正确的 email") (e.g. me@hey.run): " "custom_email" "NULL" || return 1
            ;;
        *)
            custom_email="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})@hey.run"
            ;;
        esac
        log_echo "${Green} Xray $(gettext "用户名") (email): ${custom_email} ${Font}"
    fi
}

UUID_set() {
    # Reuse old UUID during mode switch without re-prompting.
    if [[ ${mode_switch_reuse} == "yes" && -n "${UUID:-}" ]]; then
        log_echo "${Green} UUID: ${UUID} ${Font}"
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_user} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义字符串映射") (UUIDv5) [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入自定义字符串") ($(gettext "最多30字符")):" "UUID5_char" "NULL" || return 1
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} $(gettext "自定义字符串"): ${UUID5_char} ${Font}"
            log_echo_secure "${Green} UUIDv5: ${UUID} ${Font}"
            echo
            ;;
        *)
            UUID5_char="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} UUID $(gettext "映射字符串"): ${UUID5_char} ${Font}"
            log_echo_secure "${Green} UUID: ${UUID} ${Font}"
            echo
            ;;
        esac
    fi
}

target_set() {
    if [[ "on" == ${old_config_status} ]] && [[ -n $(info_extraction target) ]]; then
        echo
        log_echo "${GreenBG} $(gettext "检测到 target 域名已配置, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq
            case $old_host_fq in
            [nN][oO] | [nN])
                target_reset=1
                nginx_reality_serverNames_del
                ;;
            *)
                target_reset=0
                ;;
            esac
    fi
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local domain
        local output
        local curl_output
        pkg_install "nmap"

        while true; do
            echo
            log_echo "${GreenBG} $(gettext "请输入一个域名") (e.g. bing.com)${Font}"
            log_echo "${Green}$(gettext "域名必须支持 TLSv1.3、X25519、H2, 且不能跳转")${Font}"
            read_optimize "$(gettext "确认域名符合要求后请输入"): " "domain" "NULL" || return 1
            log_echo "${Green}$(gettext "正在检测域名请等待")...${Font}"

            output=$(nmap --script ssl-enum-ciphers -p 443 "${domain}")
            curl_output=$(curl -I -k -m 5 "https://${domain}" 2>&1)

            # 检测TLSv1.3支持
            if ! echo "$output" | grep -q "TLSv1.3"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") TLSv1.3 ${YellowBG}${Font}"
            fi

            # 检测X25519支持
            if ! echo "$output" | grep -q "x25519"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") X25519 ${YellowBG}${Font}"
            fi

            # 检测HTTP/2支持
            if ! echo "$curl_output" | grep -q "HTTP/2"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") HTTP/2 ${YellowBG}${Font}"
            fi

            # 检测是否跳转
            if echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名发生了跳转") ${YellowBG}${Font}"
            fi

            if ! echo "$output" | grep -q "TLSv1.3" || \
               ! echo "$output" | grep -q "x25519" || \
               ! echo "$curl_output" | grep -q "HTTP/2" || \
               echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名可能不满足所有要求") ${YellowBG}${Font}"
                log_echo "${GreenBG} $(gettext "是否仍要设置此域名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r force_set_fq
                case $force_set_fq in
                    [yY][eE][sS] | [yY])
                        target=$domain
                        break
                        ;;
                    *)
                        continue
                        ;;
                esac
            else
                log_echo "${OK} ${GreenBG} $(gettext "域名") ${domain} $(gettext "满足所有要求") ${Font}"
                target=$domain
                break
            fi
        done
        log_echo "${Green} target $(gettext "域名"): ${target} ${Font}"
    fi
}

serverNames_set() {
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_serverNames_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") ${target} $(gettext "域名的") serverNames [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Green} $(gettext "默认为") ${target} $(gettext "域名本身")${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
        read -r custom_serverNames_fq
        case $custom_serverNames_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个域名"): " "serverNames" "NULL" || return 1
            ;;
        *)
            serverNames=$target
            ;;
        esac
        log_echo "${Green} serverNames: ${serverNames} ${Font}"
        echo
    fi
}

keys_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_keys_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") privateKey [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_keys_fq
        case $custom_keys_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入") privateKey:" "privateKey" "NULL" || return 1
            local keys
            keys=$(${xray_bin_dir}/xray x25519 -i "${privateKey}")
            password=$(parse_reality_public_key "${keys}")
            ;;
        *)
            local keys
            keys=$(${xray_bin_dir}/xray x25519)
            privateKey=$(echo "${keys}" | awk -F"PrivateKey: " '{print $2}' | awk '{print $1}')
            password=$(parse_reality_public_key "${keys}")
            ;;
        esac
        if [[ -z "${privateKey}" || -z "${password}" ]]; then
            log_echo "${Error} ${RedBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        log_echo_secure "${Green} privateKey: ${privateKey} ${Font}"
        log_echo_secure "${Green} publicKey (Password): ${password} ${Font}"
        echo
    fi
}

# 兼容 Xray 不同版本的 x25519 输出名称：Password、Password (PublicKey)、PublicKey
parse_reality_public_key() {
    local keys="$1"
    keys=$(printf '%s\n' "${keys}" | tr '\n' ' ')
    if echo "${keys}" | grep -q "Password (PublicKey): "; then
        echo "${keys}" | sed 's/.*Password (PublicKey): //' | awk '{print $1}'
    elif echo "${keys}" | grep -q "Password: "; then
        echo "${keys}" | awk -F"Password: " '{print $2}' | awk '{print $1}'
    elif echo "${keys}" | grep -q "PublicKey: "; then
        echo "${keys}" | awk -F"PublicKey: " '{print $2}' | awk '{print $1}'
    fi
}


shortIds_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_shortids_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") shortIds [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_shortids_fq
        case $custom_shortids_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个 shortId"): " "shortIds" "NULL" || return 1
            while [[ ! "${shortIds}" =~ ^[0-9a-fA-F]{16}$ ]]; do
                log_echo "${Error} ${RedBG} shortIds $(gettext "值为空或超出范围, 请重新输入")! ${Font}"
                read_optimize "$(gettext "请输入单个 shortId"): " "shortIds" "NULL" || return 1
            done
            ;;
        *)
            pkg_install "openssl"
            shortIds=$(generate_reality_short_id)
            ;;
        esac
        log_echo_secure "${Green} shortIds: ${shortIds} ${Font}"
        echo
    fi
}

ensure_sub_script() {
    local script_name="$1"
    local remote_url="$2"
    local local_file="${scripts_dir}/${script_name}"

    mkdir -p "${scripts_dir}"
    if [ ! -f "$local_file" ]; then
        log_echo "${Info} ${Green} $(gettext "本地文件") ${script_name} $(gettext "不存在, 正在下载")... ${Font}"
        if ! download_script_file "$remote_url" "$local_file"; then
            log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
            return 1
        fi
    else
        local required_version
        required_version=$(grep '^MIN_MAIN_VERSION=' "$local_file" | head -1 | sed 's/MIN_MAIN_VERSION="//; s/"//')
        if [ -z "$required_version" ]; then
            log_echo "${Warning} ${YellowBG} ${script_name} $(gettext "版本过旧, 建议更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            local update_choice
            read -r update_choice
            case $update_choice in
                [yY][eE][sS] | [yY])
                    if ! download_script_file "$remote_url" "$local_file"; then
                        log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
                        return 1
                    fi
                    ;;
                *)
                    log_echo "${Warning} ${YellowBG} ${script_name} $(gettext "版本过旧, 可能存在兼容性问题") ${Font}"
                    ;;
            esac
        else
            local oldest
            oldest=$(printf '%s\n%s\n' "$required_version" "$shell_version" | sort -V | head -1)
            if [ "$oldest" != "$required_version" ]; then
                log_echo "${Error} ${RedBG} ${script_name} $(gettext "需要主脚本版本") >= ${required_version}, $(gettext "当前版本"): ${shell_version}, $(gettext "请先更新主脚本") ${Font}"
                return 1
            fi
        fi
    fi
    return 0
}


nginx_upstream_server_set() {
    echo
    log_echo "${GreenBG} $(gettext "是否变更") Nginx $(gettext "负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
    read -r nginx_upstream_server_fq
    case $nginx_upstream_server_fq in
    [yY][eE][sS] | [yY])
        if [[ ${tls_mode} == "TLS" ]]; then
            echo -e "\n${GreenBG} $(gettext "请选择协议为 ws 或 gRPC 或 xHTTP") ${Font}"
            echo "1: ws"
            echo "2: gRPC"
            echo "3: xHTTP"
            echo "4: $(gettext "返回")"
            local upstream_choose
            read_optimize "$(gettext "请输入"): " "upstream_choose" "NULL" 1 4 "$(gettext "请输入有效的数字")!"

            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                case $upstream_choose in
                1) source "${scripts_dir}/file_manager.sh" wsServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                2) source "${scripts_dir}/file_manager.sh" grpcServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                3) source "${scripts_dir}/file_manager.sh" xhttpServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                4) ;;
                *)
                    log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试")! ${Font}"
                    nginx_upstream_server_set
                    ;;
                esac
            fi
        elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_balance} == "on" ]] && [[ ${reality_add_nginx} == "on" ]]; then
            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                source "${scripts_dir}/file_manager.sh" realityServers ${nginx_conf_dir}
                fm_check_for_updates
                fm_main_menu
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
            return 1
        fi
        ;;
    *) ;;
    esac
}

nginx_servernames_server_set() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否变更") Nginx serverNames [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
        echo -e "${Info} ${GreenBG} $(gettext "配置用途可以参考文章"): https://hey.run/posts/use-reality ${Font}"
        read -r nginx_servernames_server_fq
        case $nginx_servernames_server_fq in
        [yY][eE][sS] | [yY])
            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                source "${scripts_dir}/file_manager.sh" serverNames ${nginx_conf_dir}
                fm_check_for_updates
                fm_main_menu
            fi
        ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    python3 -c "import uuid,sys;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,sys.argv[1]))" "$1"
}

modify_listen_address() {
    if [[ ${tls_mode} == "XTLS" ]]; then
        update_json_config "${xray_conf}" '(.inbounds[] | select(.tag == "VLESS-XTLS-in")).listen = "0.0.0.0"'
        judge "Xray listen address $(gettext "修改")"
        return
    fi

    local listen_addr="0.0.0.0"
    if [[ ${tls_mode} == "TLS" ]]; then
        listen_addr="127.0.0.1"
    fi

    if is_ws_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-ws-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_grpc_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_xhttp_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
}

modify_inbound_port() {
    local _port_failed=0
    if [[ ${tls_mode} == "Reality" ]]; then
        if [[ ${reality_add_nginx} == "off" ]]; then
            update_json_config "${xray_conf}" --argjson port "${port:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-Reality-in")).port = $port' || _port_failed=1
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        else
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
        update_json_config "${xray_conf}" --argjson port "${port:-0}" \
           '(.inbounds[] | select(.tag == "VLESS-XTLS-in")).port = $port' || _port_failed=1
    else
        if is_ws_mode; then
            update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
        fi
        if is_grpc_mode; then
            update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
        fi
        if is_xhttp_mode; then
            update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
        fi
    fi
    if [[ ${_port_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray inbound port $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Xray inbound port $(gettext "修改") $(gettext "完成") ${Font}"
}

add_ws_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local ws_port="${2:-10086}"
    local ws_path="${3:-/ray/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${ws_port:-0}" \
       --arg path "${ws_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-ws-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "ws@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "ws",
               "security": "none",
               "wsSettings": {"path": $path}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-ws-in"]'
}

add_grpc_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local grpc_port="${2:-10087}"
    local grpc_service="${3:-grpc}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${grpc_port:-0}" \
       --arg serviceName "${grpc_service}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-gRPC-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "me@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "grpc",
               "security": "none",
               "grpcSettings": {"serviceName": $serviceName, "multiMode": true, "idle_timeout": 20}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-gRPC-in"]'
}

add_xhttp_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local xhttp_port="${2:-10088}"
    local xhttp_path="${3:-xhttp}"
    xhttp_path="/${xhttp_path#/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${xhttp_port:-0}" \
       --arg xhttp_path "${xhttp_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-xhttp-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "xhttp@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "xhttp",
               "security": "none",
               "xhttpSettings": {"path": $xhttp_path, "mode": "auto"}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-xhttp-in"]'
}

modify_nginx_origin_conf() {
    # Use dedicated idleleo-nginx user for worker process,
    # instead of shared `nobody`. The user/group is created by ensure_idleleo_nginx_user.
    local nginx_worker_user="idleleo-nginx"
    local nginx_worker_group="idleleo-nginx"
    if ! id -u "${nginx_worker_user}" >/dev/null 2>&1; then
        # Fallback to nobody only if user creation failed (defensive, should not happen
        # because ensure_idleleo_nginx_user is called before this function).
        nginx_worker_user="nobody"
        nginx_worker_group="$(id -gn nobody 2>/dev/null || echo nogroup)"
    fi
    if grep -qE '^[[:space:]]*#?[[:space:]]*user[[:space:]]+' "${nginx_dir}"/conf/nginx.conf; then
        sed -i "/^[[:space:]]*#*[[:space:]]*user[[:space:]]/c\\user ${nginx_worker_user} ${nginx_worker_group};" "${nginx_dir}"/conf/nginx.conf
    else
        sed -i "1i user ${nginx_worker_user} ${nginx_worker_group};" "${nginx_dir}"/conf/nginx.conf
    fi
    sed -i "s/worker_processes  1;/worker_processes  auto;/" "${nginx_dir}"/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" "${nginx_dir}"/conf/nginx.conf
    sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf};#d" "${nginx_dir}"/conf/nginx.conf
    sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/\*\.conf;#d" "${nginx_dir}"/conf/nginx.conf
    if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "Reality" && ${reality_add_nginx} == "on" ]]; then
        if [[ ${tls_mode} == "Reality" ]]; then
            printf '\ninclude %s;\n' "${nginx_conf}" >> "${nginx_dir}"/conf/nginx.conf
            # Create empty placeholder so nginx -t passes during nginx_install.
            # The actual stream{} block is written later by nginx_reality_conf_add.
            [[ -f "${nginx_conf}" ]] || touch "${nginx_conf}"
        else
            sed -i "\$i include ${nginx_conf_dir}/*.conf;" "${nginx_dir}"/conf/nginx.conf
        fi
    fi
    sed -i "/http\( *\){/a \\\tserver_tokens off;" "${nginx_dir}"/conf/nginx.conf
    sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 403;\\n\\t\\t}" "${nginx_dir}"/conf/nginx.conf
}

# Idempotently create a dedicated idleleo-nginx system user/group.
# - system user (no home, no login shell)
# - reuses existing user if already present
# - does NOT use shared `nobody` identity

# Returns the nginx worker user (idleleo-nginx if exists, else nobody fallback).
# Used for SSL cert ownership and other shared resources that nginx worker must read.
get_nginx_worker_user() {
    if id -u "idleleo-nginx" >/dev/null 2>&1; then
        echo "idleleo-nginx"
    else
        echo "nobody"
    fi
}

# Returns the nginx worker group (idleleo-nginx if exists, else nobody's group).
get_nginx_worker_group() {
    if id -g "idleleo-nginx" >/dev/null 2>&1; then
        echo "idleleo-nginx"
    else
        id -gn nobody 2>/dev/null || echo "nogroup"
    fi
}

ensure_idleleo_nginx_user() {
    local user_name="idleleo-nginx"
    local group_name="idleleo-nginx"
    # Create group first (some systems need group before user)
    if ! getent group "${group_name}" >/dev/null 2>&1; then
        groupadd --system "${group_name}" 2>/dev/null || \
            addgroup --system "${group_name}" 2>/dev/null || true
    fi
    if ! id -u "${user_name}" >/dev/null 2>&1; then
        # Create system user with no login shell and no home
        useradd --system --gid "${group_name}" --shell /usr/sbin/nologin --no-create-home "${user_name}" 2>/dev/null || \
            adduser --system --ingroup "${group_name}" --shell /usr/sbin/nologin --no-create-home "${user_name}" 2>/dev/null || true
    fi
    # Verify
    if ! id -u "${user_name}" >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} idleleo-nginx $(gettext "用户创建失败, 将回退到 nobody") ${Font}"
        return 1
    fi
    return 0
}

# Apply layered permission model to Nginx directory tree.
# Layered model:
#   - Binary and modules: root:root, 755 (only root can modify program)
#   - Config dir/files:   root:idleleo-nginx, dir 750, files 640 (worker can read, not write)
#   - HTML/static:        root:idleleo-nginx, dir 750, files 640 (worker read-only)
#   - Logs/temp dirs:     idleleo-nginx:idleleo-nginx, 750 (worker writes here)
#   - pid file: handled by systemd (root master creates it)
apply_nginx_layered_permissions() {
    local worker_user="idleleo-nginx"
    local worker_group="idleleo-nginx"
    local failed=0
    if ! id -u "${worker_user}" >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} idleleo-nginx $(gettext "用户不存在, 跳过分层权限") ${Font}"
        return 1
    fi

    local nginx_root="${nginx_dir}"
    [[ ! -d "${nginx_root}" ]] && return 0

    # 0) Parent directory: root:root 755 (worker user must traverse to reach subdirs)
    chown root:root "${nginx_root}" 2>/dev/null || failed=1
    chmod 755 "${nginx_root}" 2>/dev/null || failed=1

    # 1) Binary and modules: root:root 755 (only root can modify program)
    if [[ -f "${nginx_root}/sbin/nginx" ]]; then
        chown root:root "${nginx_root}/sbin/nginx" 2>/dev/null || failed=1
        chmod 755 "${nginx_root}/sbin/nginx" 2>/dev/null || failed=1
    fi
    if [[ -d "${nginx_root}/modules" ]]; then
        chown -R root:root "${nginx_root}/modules" 2>/dev/null || failed=1
        find "${nginx_root}/modules" -type d -exec chmod 755 {} + 2>/dev/null || failed=1
        find "${nginx_root}/modules" -type f -exec chmod 644 {} + 2>/dev/null || failed=1
    fi

    # 2) Built-in conf dir: root:idleleo-nginx dir 750, files 640
    if [[ -d "${nginx_root}/conf" ]]; then
        chown root:"${worker_group}" "${nginx_root}/conf" 2>/dev/null || failed=1
        chmod 750 "${nginx_root}/conf" 2>/dev/null || failed=1
        while IFS= read -r -d '' conf_file; do
            chown root:"${worker_group}" "$conf_file" 2>/dev/null || failed=1
            chmod 640 "$conf_file" 2>/dev/null || failed=1
        done < <(find "${nginx_root}/conf" -type f -print0 2>/dev/null)
    fi

    # 3) Project conf dir (/etc/idleleo/conf/nginx/): root:idleleo-nginx dir 750, files 640
    if [[ -d "${nginx_conf_dir}" ]]; then
        chown root:"${worker_group}" "${nginx_conf_dir}" 2>/dev/null || failed=1
        chmod 750 "${nginx_conf_dir}" 2>/dev/null || failed=1
        while IFS= read -r -d '' conf_file; do
            chown root:"${worker_group}" "$conf_file" 2>/dev/null || failed=1
            chmod 640 "$conf_file" 2>/dev/null || failed=1
        done < <(find "${nginx_conf_dir}" -type f -print0 2>/dev/null)
    fi

    # 4) HTML/static content: root:idleleo-nginx dir 750, files 640 (worker read-only)
    if [[ -d "${nginx_root}/html" ]]; then
        chown root:"${worker_group}" "${nginx_root}/html" 2>/dev/null || failed=1
        chmod 750 "${nginx_root}/html" 2>/dev/null || failed=1
        while IFS= read -r -d '' static_file; do
            chown root:"${worker_group}" "$static_file" 2>/dev/null || failed=1
            chmod 640 "$static_file" 2>/dev/null || failed=1
        done < <(find "${nginx_root}/html" -type f -print0 2>/dev/null)
        find "${nginx_root}/html" -type d -exec chmod 750 {} + 2>/dev/null || failed=1
    fi

    # 5) Logs/temp dirs: idleleo-nginx:idleleo-nginx 750 (worker must write here)
    local writable_dir
    for writable_dir in logs client_body_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
        if [[ -d "${nginx_root}/${writable_dir}" ]]; then
            chown -R "${worker_user}:${worker_group}" "${nginx_root}/${writable_dir}" 2>/dev/null || failed=1
            find "${nginx_root}/${writable_dir}" -type d -exec chmod 750 {} + 2>/dev/null || failed=1
            find "${nginx_root}/${writable_dir}" -type f -exec chmod 640 {} + 2>/dev/null || failed=1
        fi
    done

    # 6) SSL certificate directory (/etc/idleleo/cert/): root:idleleo-nginx dir 750, files 640
    # Certs and private keys must be readable by worker, not writable.
    if [[ -d "${ssl_chainpath}" ]]; then
        chown root:"${worker_group}" "${ssl_chainpath}" 2>/dev/null || failed=1
        chmod 750 "${ssl_chainpath}" 2>/dev/null || failed=1
        while IFS= read -r -d '' cert_file; do
            chown root:"${worker_group}" "$cert_file" 2>/dev/null || failed=1
            # Root owns, worker group can read but NOT write.
            # Private key: 640 (root rw, idleleo-nginx r, others none)
            # Public cert: 640 (root rw, idleleo-nginx r, others none)
            chmod 640 "$cert_file" 2>/dev/null || failed=1
        done < <(find "${ssl_chainpath}" -type f -print0 2>/dev/null)
    fi

    if [[ ${failed} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限应用不完整") ${Font}"
        return 1
    fi
    return 0
}

verify_nginx_layered_permissions() {
    local worker_user="idleleo-nginx"
    local worker_group="idleleo-nginx"
    local nginx_root="${nginx_dir}"
    local path actual

    id -u "${worker_user}" >/dev/null 2>&1 || return 1
    [[ -d "${nginx_root}" ]] || return 1

    if [[ -f "${nginx_root}/sbin/nginx" ]]; then
        actual=$(stat -c '%U:%G %a' "${nginx_root}/sbin/nginx" 2>/dev/null) || return 1
        [[ "${actual}" == "root:root 755" ]] || return 1
    else
        return 1
    fi

    for path in "${nginx_root}/conf" "${nginx_conf_dir}" "${nginx_root}/html" "${ssl_chainpath}"; do
        [[ -d "${path}" ]] || continue
        actual=$(stat -c '%U:%G %a' "${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "root:${worker_group} 750" ]] || return 1
    done

    while IFS= read -r -d '' path; do
        actual=$(stat -c '%U:%G %a' "${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "root:${worker_group} 640" ]] || return 1
    done < <(
        {
            [[ -d "${nginx_root}/conf" ]] && find "${nginx_root}/conf" -type f -print0 2>/dev/null
            [[ -d "${nginx_conf_dir}" ]] && find "${nginx_conf_dir}" -type f -print0 2>/dev/null
            [[ -d "${nginx_root}/html" ]] && find "${nginx_root}/html" -type f -print0 2>/dev/null
            [[ -d "${ssl_chainpath}" ]] && find "${ssl_chainpath}" -type f -print0 2>/dev/null
        }
    )

    for path in logs client_body_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
        [[ -d "${nginx_root}/${path}" ]] || continue
        actual=$(stat -c '%U:%G %a' "${nginx_root}/${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "${worker_user}:${worker_group} 750" ]] || return 1
    done

    # Prove the worker can read but not write TLS private keys when one exists.
    if [[ -f "${ssl_chainpath}/xray.key" ]]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "${worker_user}" -- test -r "${ssl_chainpath}/xray.key" || return 1
            if runuser -u "${worker_user}" -- test -w "${ssl_chainpath}/xray.key"; then
                return 1
            fi
        elif command -v su >/dev/null 2>&1; then
            su -s /bin/sh "${worker_user}" -c "test -r '${ssl_chainpath}/xray.key'" || return 1
            if su -s /bin/sh "${worker_user}" -c "test -w '${ssl_chainpath}/xray.key'"; then
                return 1
            fi
        else
            return 1
        fi
    fi

    return 0
}

modify_nginx_port() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "s/^\( *\)listen.*so_keepalive=on.*/\1listen ${port} reuseport so_keepalive=on backlog=65535;/" "${nginx_conf}"
        judge "Nginx port $(gettext "修改")"
    elif [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)listen [^[]*ssl reuseport;$/\1listen ${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*ssl reuseport;$/\1listen [::]:${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen [^[]*quic reuseport;$/\1listen ${port} quic reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*quic reuseport;$/\1listen [::]:${port} quic reuseport;/" "${nginx_conf}"
        judge "Xray port $(gettext "修改")"
    fi
    [[ "on" != ${old_config_status} ]] && log_echo "${OK} ${GreenBG} $(gettext "端口"): ${port} ${Font}"
}

modify_nginx_ssl_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" "${nginx_dir}"/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    local escaped_domain
    escaped_domain=$(sed_escape "${domain}")
    sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${escaped_domain};/g" "${nginx_ssl_conf}"
    sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${escaped_domain}\$request_uri;/" "${nginx_ssl_conf}"
}

modify_nginx_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" "${nginx_dir}"/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    if [[ ${tls_mode} == "TLS" ]]; then
        local escaped_domain escaped_path escaped_serviceName escaped_xhttppath
        escaped_domain=$(sed_escape "${domain}")
        escaped_path=$(sed_escape "${path}")
        escaped_serviceName=$(sed_escape "${serviceName}")
        escaped_xhttppath=$(sed_escape "${xhttppath}")
        sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${escaped_domain};/g" "${nginx_conf}"
        if is_ws_mode; then
            sed -i "s/^\( *\)location ws$/\1location \/${escaped_path}/" "${nginx_conf}"
            sed -i "s/^\( *\)#proxy_pass http:\/\/xray-ws-server;/\1proxy_pass http:\/\/xray-ws-server;/" "${nginx_conf}"
        else
            sed -i "/^\s*location ws$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_grpc_mode; then
            sed -i "s/^\( *\)location grpc$/\1location \/${escaped_serviceName}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location grpc$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_xhttp_mode; then
            sed -i "s/^\( *\)location xhttp$/\1location \/${escaped_xhttppath}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*xray-xhttp-server\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location xhttp$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
    fi
}

nginx_servers_add() {
    if is_ws_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.wsServers
        cat >"${nginx_conf_dir}"/127.0.0.1.wsServers <<EOF
server 127.0.0.1:${xport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
    if is_grpc_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.grpcServers
        cat >"${nginx_conf_dir}"/127.0.0.1.grpcServers <<EOF
server 127.0.0.1:${gport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
    if is_xhttp_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.xhttpServers
        cat >"${nginx_conf_dir}"/127.0.0.1.xhttpServers <<EOF
server 127.0.0.1:${xhttpport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
}


modify_path() {
    local _path_failed=0
    is_ws_mode && { update_json_config "${xray_conf}" --arg ws_path "/${path}" \
       '(.inbounds[] | select(.tag == "VLESS-ws-in")).streamSettings.wsSettings.path = $ws_path' || _path_failed=1; }
    is_grpc_mode && { update_json_config "${xray_conf}" --arg serviceName "${serviceName}" \
       '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).streamSettings.grpcSettings.serviceName = $serviceName' || _path_failed=1; }
    is_xhttp_mode && { update_json_config "${xray_conf}" --arg xhttp_path "/${xhttppath#/}" \
       '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).streamSettings.xhttpSettings.path = $xhttp_path' || _path_failed=1; }
    if [[ ${_path_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    if [[ ${tls_mode} == "Reality" ]] && [[ "$reality_add_more" == "off" ]]; then
        log_echo "${Warning} ${YellowBG} Reality $(gettext "不支持") path ${Font}"
    else
        log_echo "${OK} ${GreenBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "完成") ${Font}"
    fi
}

modify_email_address() {
    local multi_user
    multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}")
    if [[ "${multi_user}" == "true" ]]; then
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除多余的用户") ${Font}"
    else
        update_json_config "${xray_conf}" --arg custom_email "${custom_email}" \
           '(.inbounds[].settings.clients[].email) = $custom_email'
        judge "Xray $(gettext "用户名修改")"
    fi
}

modify_UUID() {
    local multi_user
    multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}")
    if [[ "${multi_user}" == "true" ]]; then
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除多余的用户") ${Font}"
    else
        update_json_config "${xray_conf}" --arg UUID "${UUID}" \
           '(.inbounds[].settings.clients[].id) = $UUID'
        judge "Xray UUID $(gettext "修改")"
    fi
}

modify_target_serverNames() {
  update_json_config "${xray_conf}" --arg target "${target}:443" --arg serverName "${serverNames}" '
     .inbounds[0].streamSettings.realitySettings.target = $target |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$serverName]'
  judge "target serverNames $(gettext "配置修改")"
}

modify_privateKey_shortIds() {
  update_json_config "${xray_conf}" --arg privateKey "${privateKey}" --arg shortId "${shortIds}" '
     .inbounds[0].streamSettings.realitySettings.privateKey = $privateKey |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId]'
  judge "privateKey shortIds $(gettext "配置修改")"
}

# 生成 16 位 hex shortId，openssl 优先，/dev/urandom 兜底
generate_reality_short_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8 2>/dev/null || tr -dc 'a-f0-9' </dev/urandom | head -c 16
    else
        tr -dc 'a-f0-9' </dev/urandom | head -c 16
    fi
}

# 从少量普通路径模板中随机生成 spiderX，结果以 / 开头，仅含 a-z0-9/. 字符
generate_spiderx() {
    local r
    r=$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 8)
    [[ -z "${r}" ]] && r="default$(date +%s | tail -c 5)"
    case $((RANDOM % 4)) in
        0) echo "/assets/${r}.css" ;;
        1) echo "/static/${r}.js" ;;
        2) echo "/docs/${r}/index.html" ;;
        *) echo "/api/status/${r}" ;;
    esac
}

# spiderX 设置：仅新安装或新增客户端时生成，不改动老用户已有配置
spiderx_set() {
    if [[ "${old_config_status}" != "on" ]] || [[ ${change_reality} == "yes" ]]; then
        spiderx_path=$(generate_spiderx)
        log_echo "${Green} spiderX: ${spiderx_path} ${Font}"
    fi
}

# 收紧敏感配置文件权限：不影响 Xray(nobody) 读取 config.json 与证书
# install_config/分享文件仅 root 可读；config.json 与私钥由 nobody 持有以兼容 Xray
# SSL certs/keys must be root-owned with worker group read (640).
apply_sensitive_file_permissions() {
    local file="$1"
    local owner="$2"
    local mode="${3:-600}"
    [[ -f "${file}" ]] || return 0
    if ! chown "${owner}" "${file}" 2>/dev/null || ! chmod "${mode}" "${file}" 2>/dev/null; then
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${file} ${Font}"
        return 1
    fi
    return 0
}

harden_config_permissions() {
    local failed=0
    local _nginx_worker_group

    # An existing Nginx tree can predate the dedicated worker account (for
    # example, upgrades and Docker images shared by non-Nginx install modes).
    # Create the account before resolving the group or applying the layered
    # model; otherwise an unrelated XTLS/Reality-only install fails merely
    # because Nginx happens to be present on disk.
    if [[ -d "${nginx_dir}" ]] && ! ensure_idleleo_nginx_user; then
        failed=1
    fi
    _nginx_worker_group=$(get_nginx_worker_group)

    apply_sensitive_file_permissions "${xray_install_config_file}" "root:root" || failed=1
    apply_sensitive_file_permissions "${xray_conf}" "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" || failed=1
    # Root owns certs/keys, worker group can read but NOT write.
    # Private key: 640 (root rw, idleleo-nginx r, others none)
    # Public cert: 640 (root rw, idleleo-nginx r, others none)
    apply_sensitive_file_permissions "${ssl_chainpath}/xray.key" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/xray.crt" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.key" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.crt" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${xray_info_file}" "root:root" || failed=1
    apply_sensitive_file_permissions "${xray_info_file%.*}_clash.yaml" "root:root" || failed=1
    if [[ -d "${nginx_dir}" ]]; then
        apply_nginx_layered_permissions || failed=1
        verify_nginx_layered_permissions || failed=1
    fi
    return "${failed}"
}

modify_reality_listen_address () {
    update_json_config "${xray_conf}" '.inbounds[0].listen = "127.0.0.1"'
    judge "Xray reality listen address $(gettext "配置修改")"
}

xray_privilege_escalation() {
    local _systemd_files=("${xray_systemd_file}")
    local _override_dir="${xray_systemd_file}.d"
    if [[ -d "${_override_dir}" ]]; then
        local _conf_file
        for _conf_file in "${_override_dir}"/*.conf; do
            [[ -f "$_conf_file" ]] && _systemd_files+=("$_conf_file")
        done
    fi
    local _has_nobody_user=false
    local _svc_file
    for _svc_file in "${_systemd_files[@]}"; do
        if grep -q "User=nobody" "$_svc_file"; then
            _has_nobody_user=true
            break
        fi
    done
    if [[ "${_has_nobody_user}" == "true" ]]; then
        local _nobody_group
        _nobody_group=$(id -gn nobody 2>/dev/null || echo "nogroup")
        log_echo "${OK} ${GreenBG} $(gettext "检测到 Xray 的权限控制, 启动修改程序") ${Font}"
        mkdir -p /var/log/xray/
        chown -fR "nobody:${_nobody_group}" /var/log/xray/
        chmod -f 755 /var/log/xray/
        find /var/log/xray/ -type f -exec chmod -f 644 {} \;
        # SSL cert files must be owned by root, not worker.
        # xray_privilege_escalation() must NOT change cert ownership to worker user.
        # Only apply_nginx_layered_permissions() and harden_config_permissions()
        # are authoritative for cert permission model (root:idleleo-nginx 640).
        if [[ -d "${nginx_dir}" ]]; then
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
        fi
    fi
    log_echo "${OK} ${GreenBG} Xray $(gettext "修改") $(gettext "完成") ${Font}"
}

set_xray_config_path() {
    [[ -L "${xray_default_conf}" || -e "${xray_default_conf}" ]] && rm -f "${xray_default_conf}"
    ln -s "${xray_conf}" "${xray_default_conf}"
    local _default_geo_dir="${local_bin}/share/xray"
    if [[ -d "${_default_geo_dir}" ]] && [[ ! -L "${_default_geo_dir}" ]]; then
        local _new_geo_dir="${idleleo_dir}/share/xray"
        mkdir -p "${_new_geo_dir}"
        for _f in "${_default_geo_dir}"/*; do
            [[ -f "$_f" ]] && mv "$_f" "${_new_geo_dir}/"
        done
        rmdir "${_default_geo_dir}" 2>/dev/null || rm -rf "${_default_geo_dir}"
    fi
    if [[ ! -L "${_default_geo_dir}" ]]; then
        ln -s "${idleleo_dir}/share/xray" "${_default_geo_dir}"
    fi
}

xray_install() {
    if [[ $(xray version) == "" ]] || [[ ! -f "${xray_conf}" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "即将安装") Xray v${xray_online_version} ${Font}"
        xray_install_release install -f --version v${xray_online_version}
        judge "$(gettext "安装") Xray"
        xray_privilege_escalation || return 1
        set_xray_config_path
        systemctl daemon-reload
        xray_version=${xray_online_version}
    else
        log_echo "${OK} ${GreenBG} $(gettext "已安装") Xray ${Font}"
        xray_version=$(info_extraction xray_version)
        if [[ -z "${xray_version}" ]]; then
            xray_version=$(${xray_bin_dir}/xray version | head -1 | awk '{print $2}')
        fi
    fi
}

xray_update() {
    local current_xray_version
    local update_rolled_back=0
    rxa_reconfigure_enter
    trap 'rxa_reconfigure_leave $?' RETURN
    current_xray_version=$(info_extraction xray_version)
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    # COMPAT: 旧版依赖 /usr/local/etc/xray 目录存放默认配置，新版不再使用，未来可删除
    [[ ! -d "${local_bin}/etc/xray" ]] && log_echo "${GreenBG} $(gettext "若更新无效, 建议直接卸载再安装")! ${Font}"
    log_echo "${Warning} ${GreenBG} $(gettext "部分新功能需要重新安装才可生效") ${Font}"
    if [[ ${current_xray_version} != ${xray_online_version} ]]; then
        log_echo "${Info} ${GreenBG} Xray $(gettext "更新"): v${current_xray_version} → v${xray_online_version} ${Font}"
        if [[ ${auto_update} != "YES" ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "检测到存在最新版") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "脚本可能未兼容此版本") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_test_fq
            case $xray_test_fq in
            [yY][eE][sS] | [yY])
                log_echo "${OK} ${GreenBG} $(gettext "更新") Xray ! ${Font}"
                # Backup current binary as Layer 1 rollback source
                # Backup must succeed before proceeding — refuse to overwrite without backup
                if ! backup_xray_binary; then
                    log_echo "${Error} ${RedBG} $(gettext "本机备份失败, 拒绝继续更新")! ${Font}"
                    return 1
                fi
                systemctl stop xray
                # Install + comprehensive health check
                # (binary exec / version match / config parse / service active / port listening)
                if xray_install_release install -f --version "v${xray_online_version}" && health_check_xray_update "${xray_online_version}"; then
                    xray_version=${xray_online_version}
                    judge "Xray $(gettext "更新")" true
                else
                    log_echo "${Error} ${RedBG} Xray $(gettext "更新") $(gettext "失败")! ${Font}"
                    xray_diagnose
                    log_echo "${Warning} ${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                    case $rollback_fq in
                    [nN][oO] | [nN])
                        log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                        log_echo "${Error} ${RedBG} Xray $(gettext "更新失败且未回滚, 当前服务可能不可用, 请手动检查")! ${Font}"
                        if ! systemctl is-active xray >/dev/null 2>&1; then
                            log_echo "${Error} ${RedBG} $(gettext "高优先级错误: Xray 服务已停止")! ${Font}"
                        fi
                        return 1
                        ;;
                    *)
                        log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                        # Layer 1 = local pre-update backup restore
                        if restore_xray_binary_backup; then
                            log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Xray $(gettext "版本")! ${Font}"
                            xray_version=${current_xray_version}
                            update_rolled_back=1
                        else
                            # Layer 2 = tested_version known-good fallback
                            log_echo "${Info} ${YellowBG} $(gettext "Layer 1 失败, 尝试 Layer 2 tested_version 恢复") ${Font}"
                            if fallback_xray_to_tested_version; then
                                xray_version=${xray_tested_version}
                                update_rolled_back=1
                            else
                                # Layer 3 = stop + diagnostics (already printed above)
                                log_echo "${Error} ${RedBG} Xray $(gettext "回滚失败")! ${Font}"
                                return 1
                            fi
                        fi
                        ;;
                    esac
                fi
                ;;
            *)
                return 0
                ;;
            esac
        else
            # Auto-update mode — non-interactive, automated layered rollback
            # Backup must succeed before proceeding — refuse to overwrite without backup
            if ! backup_xray_binary; then
                echo "$(gettext "本机备份失败, 拒绝继续更新")!" >>"${log_file}"
                return 1
            fi
            systemctl stop xray
            if xray_install_release install -f --version "v${xray_online_version}" && health_check_xray_update "${xray_online_version}"; then
                xray_version=${xray_online_version}
            else
                xray_diagnose
                # Layer 1 = local backup restore
                if restore_xray_binary_backup; then
                    xray_version=${current_xray_version}
                    update_rolled_back=1
                elif fallback_xray_to_tested_version; then
                    # Layer 2 = tested_version
                    xray_version=${xray_tested_version}
                    update_rolled_back=1
                else
                    # Layer 3 = stop + diagnostics (already printed above)
                    echo "Xray $(gettext "回滚失败")!" >>"${log_file}"
                    return 1
                fi
            fi
        fi
    else
        countdown "$(gettext "重装") Xray !"
        # Backup before reinstall too (reinstall may corrupt the binary)
        # Backup must succeed — refuse to overwrite without backup
        if ! backup_xray_binary; then
            log_echo "${Error} ${RedBG} $(gettext "本机备份失败, 拒绝继续重装")! ${Font}"
            return 1
        fi
        systemctl stop xray
        xray_version=${xray_online_version}
        # Same-version reinstall must have layered rollback
        if xray_install_release install -f --version v${xray_online_version} && health_check_xray_update "${xray_online_version}"; then
            judge "Xray $(gettext "重装")" true
        else
            log_echo "${Error} ${RedBG} Xray $(gettext "重装") $(gettext "失败")! ${Font}"
            xray_diagnose
            # Layer 1: local backup restore
            if [[ ${auto_update} != "YES" ]]; then
                log_echo "${Warning} ${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r rollback_fq
                case $rollback_fq in
                [nN][oO] | [nN])
                    log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                    return 1
                    ;;
                esac
            fi
            log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
            if restore_xray_binary_backup; then
                log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Xray $(gettext "版本")! ${Font}"
                xray_version=${current_xray_version}
                update_rolled_back=1
            elif fallback_xray_to_tested_version; then
                # Layer 2: tested_version fallback
                xray_version=${xray_tested_version}
                update_rolled_back=1
            else
                # Layer 3: stop + diagnostics (already printed above)
                log_echo "${Error} ${RedBG} Xray $(gettext "回滚失败")! ${Font}"
                return 1
            fi
        fi
    fi
    xray_privilege_escalation || return 1
    set_xray_config_path
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version' || return 1
    systemctl daemon-reload
    systemctl start xray
    # Final health gate — must pass before declaring success
    if ! health_check_xray_update "${xray_version}"; then
        [[ ${auto_update} == "YES" ]] && echo "Xray $(gettext "更新") $(gettext "失败")!" >>"${log_file}"
        [[ ${auto_update} != "YES" ]] && log_echo "${Error} ${RedBG} Xray $(gettext "更新") $(gettext "失败")! ${Font}"
        xray_diagnose
        return 1
    fi
    # 服务恢复成功 ≠ 本次更新成功
    # 无论手动还是自动模式，只要发生过回滚（update_rolled_back=1），
    # 本次更新即为失败，必须返回非零。不得用 auto_update 决定失败操作的返回码。
    if [[ ${update_rolled_back} -eq 1 ]]; then
        return 1
    fi
    return 0
}

reality_balance_add_fq() {
    # Install wizard preset: reality_add_balance already set by apply_install_profile.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_balance} == "on" ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "已启用") ${Font}"
        else
            log_echo "${OK} ${GreenBG} $(gettext "已跳过") ${Font}"
        fi
        return 0
    fi
    echo
    log_echo "${GreenBG} $(gettext "是否添加 Reality 负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    echo -e "${Warning} ${Green} $(gettext "使用此功能前，建议先阅读作者教程")! ${Font}"
    echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择")! ${Font}"
    read -r reality_balance_add_fq
    case $reality_balance_add_fq in
        [yY][eE][sS] | [yY])
            reality_add_balance="on"
            log_echo "${OK} ${GreenBG} $(gettext "已启用") ${Font}"
        ;;
        *)
            reality_add_balance="off"
            log_echo "${OK} ${GreenBG} $(gettext "已跳过") ${Font}"
        ;;

    esac
}


# 通过公网 DNS 解析域名的 A/AAAA 记录，逐行返回 IP 或空字符串
resolve_domain_ips() {
    local domain="$1" result
    if command -v dig >/dev/null 2>&1; then
        result=$({ dig +short +time=3 +tries=1 A "${domain}" @8.8.8.8 2>/dev/null; \
                   dig +short +time=3 +tries=1 AAAA "${domain}" @2001:4860:4860::8888 2>/dev/null; } |
            grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$' | awk '!seen[$0]++')
    elif command -v nslookup >/dev/null 2>&1; then
        result=$({ nslookup -type=A "${domain}" 8.8.8.8 2>/dev/null; nslookup -type=AAAA "${domain}" 8.8.8.8 2>/dev/null; } |
            awk '/^Address:/ && $2 !~ /8\.8\.[0-9.]+|8\.8\.4\.4/ {print $2}' | awk '!seen[$0]++')
    elif command -v host >/dev/null 2>&1; then
        result=$({ host -t A "${domain}" 8.8.8.8 2>/dev/null; host -t AAAA "${domain}" 8.8.8.8 2>/dev/null; } |
            awk '/has address/ {print $4} /has IPv6 address/ {print $5}' | awk '!seen[$0]++')
    else
        result=$({ curl -fsSL --connect-timeout 5 "https://dns.google/resolve?name=${domain}&type=A" 2>/dev/null; \
                   curl -fsSL --connect-timeout 5 "https://dns.google/resolve?name=${domain}&type=AAAA" 2>/dev/null; } |
            jq -r '.Answer[]? | select(.type==1 or .type==28) | .data' 2>/dev/null | awk '!seen[$0]++')
    fi
    echo "${result}"
}

ip_in_list() {
    local needle="$1"
    local candidate
    while IFS= read -r candidate; do
        [[ -n "${candidate}" && "${candidate}" == "${needle}" ]] && return 0
    done
    return 1
}

ip_lists_overlap() {
    local local_ips="$1"
    local remote_ips="$2"
    local remote_ip
    while IFS= read -r remote_ip; do
        ip_in_list "${remote_ip}" <<<"${local_ips}" && return 0
    done <<<"${remote_ips}"
    return 1
}

# SNI Guard 策略选择：仅新安装时交互，默认 isolate
sni_guard_policy_choose() {
    local force_choose="${1:-}"
    [[ ${reality_add_nginx} != "on" ]] && return 0
    # 老用户升级：不强行改配置，按已有/默认值处理
    [[ "${force_choose}" != "force" && "${old_config_status}" == "on" ]] && return 0

    echo
    log_echo "${GreenBG} $(gettext "异常 SNI 处理方式") ${Font}"
    echo -e "${Green}1${Font}: $(gettext "隔离异常流量, 不转发到 Xray") ($(gettext "推荐"))"
    echo -e "${Green}2${Font}: $(gettext "使用指向本机 IP 的自建 HTTPS 站点作为回落") ($(gettext "高级"))"
    echo -e "${Green}3${Font}: $(gettext "直接拒绝异常 TLS 连接") ($(gettext "高级"))"
    echo -e "${Warning} $(gettext "第 2 项需要你已有自己的域名, 并且该域名的 A/AAAA 记录指向本机公网 IP。若不了解含义, 请使用默认隔离策略。") ${Font}"
    local sni_policy_choice
    read_optimize "$(gettext "请输入选项") ($(gettext "默认值"):1):" "sni_policy_choice" 1 1 3 "$(gettext "请输入有效的数字")!" || return 1
    # 切换策略前先清理旧的 isolate/decoy http 块配置（03-isolate.conf / 03-decoy.conf + include）
    decoy_conf_remove
    case ${sni_policy_choice} in
        2)
            if decoy_site_setup; then
                unknown_sni_policy="decoy"
            else
                log_echo "${Warning} ${YellowBG} $(gettext "decoy 站点设置失败, 回退到默认隔离策略") ${Font}"
                unknown_sni_policy="isolate"
            fi
            ;;
        3)
            unknown_sni_policy="reject"
            log_echo "${OK} ${GreenBG} $(gettext "已选择直接拒绝异常 TLS 连接") ${Font}"
            ;;
        *)
            unknown_sni_policy="isolate"
            log_echo "${OK} ${GreenBG} $(gettext "已选择隔离异常流量") ${Font}"
            ;;
    esac
    reality_nginx_sni_guard="on"
}

add_sni_guard_http_include() {
    local config_name="$1"
    local include_line="include ${nginx_conf_dir}/${config_name};"
    [[ -f "${nginx_dir}/conf/nginx.conf" ]] || return 1
    if ! grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null; then
        sed -i "/^http[[:space:]]*{/a \\    ${include_line}" "${nginx_dir}/conf/nginx.conf" || return 1
    fi
    grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null
}

write_isolate_site_config() {
    mkdir -p "${nginx_conf_dir}"
    cat >"${nginx_conf_dir}/03-isolate.conf" <<'HTTPCONF'
# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
    access_log off;
    error_log /dev/null;
}
HTTPCONF
    add_sni_guard_http_include "03-isolate.conf"
}

decoy_site_artifacts_ready() {
    local decoy_webroot="${idleleo_dir}/decoy"
    [[ -n "${decoy_domain}" ]] || return 1
    [[ -f "${ssl_chainpath}/decoy.key" && -f "${ssl_chainpath}/decoy.crt" && -f "${decoy_webroot}/index.html" ]]
}

write_decoy_site_config() {
    local decoy_webroot="${idleleo_dir}/decoy"
    decoy_site_artifacts_ready || return 1

    mkdir -p "${nginx_conf_dir}"
    cat >"${nginx_conf_dir}/03-decoy.conf" <<EOF
# decoy 回落站点 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 HTTPS 站点
server {
    listen 127.0.0.1:9444 ssl;
    server_name ${decoy_domain};
    ssl_certificate ${ssl_chainpath}/decoy.crt;
    ssl_certificate_key ${ssl_chainpath}/decoy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    root ${decoy_webroot};
    index index.html;
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    add_sni_guard_http_include "03-decoy.conf"
}

sni_guard_port_conflicts() {
    local guard_port="$1"
    local configured_port
    for configured_port in "${port:-}" "${xport:-}" "${gport:-}" "${xhttpport:-}"; do
        [[ -n "${configured_port}" && "${configured_port}" == "${guard_port}" ]] && return 0
    done
    return 1
}

# decoy 站点设置：校验域名指向本机、生成自签证书、生成 Nginx HTTPS 站点
decoy_site_setup() {
    echo
    log_echo "${GreenBG} $(gettext "decoy 站点设置") ${Font}"
    log_echo "${Warning} $(gettext "请输入你自己的域名, 该域名的 A/AAAA 记录必须指向本机公网 IP") ${Font}"
    local decoy_input decoy_resolved local_ips
    read_optimize "$(gettext "请输入 decoy 域名"): " "decoy_input" "NULL" || return 1
    if [[ ! "${decoy_input}" =~ ^[A-Za-z0-9.-]+$ || "${decoy_input}" != *.* ]]; then
        log_echo "${Error} ${RedBG} $(gettext "请输入 decoy 域名") ${Font}"
        return 1
    fi

    # 解析域名 A/AAAA 记录并与本机公网 IP 比对
    decoy_resolved=$(resolve_domain_ips "${decoy_input}")
    local_ips=$(printf "%s\n%s\n%s\n" "${local_ip}" "$(get_public_ip "IPv4" 2>/dev/null)" "$(get_public_ip "IPv6" 2>/dev/null)" |
        awk 'NF && !seen[$0]++')
    if [[ -z "${decoy_resolved}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法解析该域名的 A/AAAA 记录, 请检查 DNS 是否已生效") ${Font}"
        return 1
    fi
    if ! ip_lists_overlap "${local_ips}" "${decoy_resolved}"; then
        log_echo "${Warning} ${YellowBG} $(gettext "该域名 A/AAAA 记录") $(echo "${decoy_resolved}" | tr '\n' ' ') $(gettext "未指向本机公网 IP") $(echo "${local_ips}" | tr '\n' ' ') ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请先将域名 A/AAAA 记录指向本机, 或使用默认隔离策略") ${Font}"
        return 1
    fi

    decoy_domain="${decoy_input}"
    log_echo "${OK} ${GreenBG} $(gettext "域名校验通过") ${Font}"

    # 生成自签证书（高级用户可自行替换为 acme.sh 签发的正式证书）
    pkg_install "openssl"
    mkdir -p "${ssl_chainpath}"
    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "${ssl_chainpath}/decoy.key" \
        -out "${ssl_chainpath}/decoy.crt" \
        -subj "/CN=${decoy_domain}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "自签证书生成失败") ${Font}"
        return 1
    fi
    # Root owns certs/keys, worker group can read but NOT write.
    # Private key: 640 (root rw, idleleo-nginx r, others none)
    # Public cert: 640 (root rw, idleleo-nginx r, others none)
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.key" "root:$(get_nginx_worker_group)" 640 || true
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.crt" "root:$(get_nginx_worker_group)" 640 || true

    # 生成不统一的极简站点页面（含域名与随机标识，避免统一指纹）
    local decoy_webroot="${idleleo_dir}/decoy"
    mkdir -p "${decoy_webroot}"
    local decoy_token
    decoy_token=$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 6)
    [[ -z "${decoy_token}" ]] && decoy_token="ok$(date +%s | tail -c 5)"
    cat >"${decoy_webroot}/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${decoy_domain}</title>
</head>
<body>
<h1>It works</h1>
<p>Service status: OK (${decoy_token})</p>
</body>
</html>
EOF

    # 生成 Nginx HTTPS 站点配置（监听 127.0.0.1:9444，供 stream deny upstream 回落）
    write_decoy_site_config || return 1

    log_echo "${OK} ${GreenBG} $(gettext "decoy 站点配置完成") ${Font}"
    log_echo "${Warning} $(gettext "当前使用自签证书, 浏览器访问会有证书提示。高级用户可自行替换") ${ssl_chainpath}/decoy.crt $(gettext "与") decoy.key ${Font}"
    return 0
}

# 清理 decoy 配置（切换策略或卸载时调用）
decoy_conf_remove() {
    [[ -f "${nginx_conf_dir}/03-decoy.conf" ]] && rm -f "${nginx_conf_dir}/03-decoy.conf"
    [[ -f "${nginx_conf_dir}/03-isolate.conf" ]] && rm -f "${nginx_conf_dir}/03-isolate.conf"
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]]; then
        sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/03-decoy.conf;#d" "${nginx_dir}/conf/nginx.conf"
        sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/03-isolate.conf;#d" "${nginx_dir}/conf/nginx.conf"
    fi
    return 0
}

ensure_reality_sni_guard_defaults() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    [[ "$(info_extraction tls)" != "Reality" ]] && return 0

    local current_guard current_policy current_decoy defaults_present
    current_guard=$(info_extraction reality_nginx_sni_guard)
    current_policy=$(info_extraction unknown_sni_policy)
    current_decoy=$(info_extraction decoy_domain)
    [[ -z "${current_guard}" ]] && current_guard="on"
    [[ -z "${current_policy}" ]] && current_policy="isolate"

    defaults_present=$(jq -r '
       has("reality_nginx_sni_guard") and
       has("unknown_sni_policy") and
       has("decoy_domain") and
       ((.reality_nginx_sni_guard // "") != "") and
       ((.unknown_sni_policy // "") != "")' "${xray_install_config_file}" 2>/dev/null) || return 1
    if [[ "${defaults_present}" != "true" ]]; then
        update_json_config "${xray_install_config_file}" \
           --arg guard "${current_guard}" \
           --arg policy "${current_policy}" \
           --arg decoy "${current_decoy}" '
           .reality_nginx_sni_guard = (if ((.reality_nginx_sni_guard // "") == "") then $guard else .reality_nginx_sni_guard end) |
           .unknown_sni_policy = (if ((.unknown_sni_policy // "") == "") then $policy else .unknown_sni_policy end) |
           .decoy_domain = (if has("decoy_domain") then .decoy_domain else $decoy end)' || return 1
    fi
    reality_nginx_sni_guard=$(info_extraction reality_nginx_sni_guard)
    unknown_sni_policy=$(info_extraction unknown_sni_policy)
    decoy_domain=$(info_extraction decoy_domain)
}

reset_sni_guard_policy() {
    if [[ ! -f "${xray_install_config_file}" ]] || [[ ! -f "${nginx_conf}" ]] || [[ ${tls_mode} != "Reality" ]] || [[ ${reality_add_nginx} != "on" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "当前模式不支持此操作")! ${Font}"
        return 1
    fi
    sni_guard_policy_choose force || return 1
    nginx_reality_conf_add || return 1
    update_json_config "${xray_install_config_file}" \
       --arg guard "${reality_nginx_sni_guard}" \
       --arg policy "${unknown_sni_policy}" \
       --arg decoy "${decoy_domain}" '
       .reality_nginx_sni_guard = $guard |
       .unknown_sni_policy = $policy |
       .decoy_domain = $decoy' || return 1
    service_restart || return 1
    reset_install_config
}


# Apply Reality+Nginx installation steps (shared by preset and interactive paths).
# Returns 0 on success, 1 on failure (propagated to caller).
_apply_reality_nginx_install() {
    validate_reality_reserved_ports || return 1
    nginx_exist_check || return 1
    nginx_systemd || return 1
    sni_guard_policy_choose || return 1
    nginx_reality_conf_add || return 1
    nginx_reality_servers_add || return 1
    nginx_reality_serverNames_add || return 1
}

# Skip Reality+Nginx installation. Does NOT uninstall existing Nginx.
# P0 safety: choosing "no Nginx" must not auto-remove an existing Nginx
# installation. Users who want to remove Nginx must do so explicitly.
_skip_reality_nginx_install() {
    if [[ -d "${nginx_dir}" ]]; then
        echo
        log_echo "${Warning} ${Green} $(gettext "检测到已安装") nginx ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "已跳过安装 nginx, 保留现有 nginx 不卸载") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "已跳过安装") nginx ${Font}"
    fi
}

reality_nginx_add_fq() {
    # Install wizard preset: reality_add_nginx already set by apply_install_profile.
    # Preset mode MUST NOT uninstall existing Nginx when reality_add_nginx=off.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_nginx} == "on" ]]; then
            _apply_reality_nginx_install || return 1
        else
            _skip_reality_nginx_install
        fi
        return 0
    fi

    echo
    log_echo "${Warning} ${Green} $(gettext "Reality 协议可能存在流量绕过风险") ${Font}"
    if [[ ${reality_add_balance} == "off" ]]; then
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护")($(gettext "推荐")) [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [nN][oO] | [nN])
                reality_add_nginx="off"
                _skip_reality_nginx_install
            ;;
            *)
                reality_add_nginx="on"
                _apply_reality_nginx_install || return 1
            ;;
        esac
    else
        log_echo "${Warning} ${Green} $(gettext "检测到已开启 Reality 负载均衡") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "作为 Reality 负载均衡主服务器时必须安装") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "作为 Reality 负载均衡二级服务器时无需安装") ${Font}"
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [yY][eE][sS] | [yY])
                reality_add_nginx="on"
                _apply_reality_nginx_install || return 1
            ;;
            *)
                reality_add_nginx="off"
                _skip_reality_nginx_install
            ;;
        esac
    fi
}

nginx_exist_check() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]] && [[ -n "$(info_extraction nginx_build_version)" ]]; then
        # Older custom Nginx installations may predate the dedicated worker
        # account. Create it before changing config or provisioning TLS files.
        if ! ensure_idleleo_nginx_user; then
            return 1
        fi
        if [[ -d "${nginx_conf_dir}" ]]; then
            # Only remove files this script owns; preserve user-added .conf
            # (custom sites, stream blocks, reverse proxies, security rules).
            local _managed_file
            for _managed_file in "${managed_nginx_files[@]}"; do
                rm -f "${nginx_conf_dir}/${_managed_file}"
            done
            if [[ -f "${nginx_conf_dir}/nginx.default" ]]; then
                cp -fp "${nginx_conf_dir}"/nginx.default "${nginx_dir}"/conf/nginx.conf
            elif [[ -f "${nginx_dir}/conf/nginx.conf.default" ]]; then
                cp -fp "${nginx_dir}"/conf/nginx.conf.default "${nginx_dir}"/conf/nginx.conf
            else
                sed -i "/if \(.*\) {$/,+2d" "${nginx_dir}"/conf/nginx.conf
                sed -i "/^include.*\*\.conf;$/d" "${nginx_dir}"/conf/nginx.conf
            fi
        else
            sed -i "/if \(.*\) {$/,+2d" "${nginx_dir}"/conf/nginx.conf
            sed -i "/^include.*\*\.conf;$/d" "${nginx_dir}"/conf/nginx.conf
        fi
        modify_nginx_origin_conf || return 1
        nginx_build_version=$(info_extraction nginx_build_version)
        log_echo "${OK} ${GreenBG} Nginx $(gettext "已存在, 跳过编译安装过程") ${Font}"
    elif [[ -d "/etc/nginx" ]] && [[ -n "$(info_extraction nginx_version)" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "检测到其他套件安装的 Nginx, 继续安装会造成冲突, 请处理后安装")! ${Font}"
        exit 1
    else
        nginx_install || exit 1
    fi
}

# Strict tar safety check for Nginx release archives.
# Validates every tar entry BEFORE extraction and refuses dangerous archives.
# Returns 0 if the archive is safe, 1 otherwise.
# Safety rules:
#   1. All entries MUST live under the single top-level "nginx/" prefix.
#   2. Reject absolute paths (leading /).
#   3. Reject parent traversal (.. anywhere in the path).
#   4. Reject symlinks/hardlinks whose target points outside "nginx/".
#   5. Reject device files, FIFOs, sockets and other non-regular non-dir entries.
#   6. Reject file names containing control characters or NUL bytes.
#   7. Extraction uses --no-same-permissions --no-same-owner to drop tainted metadata.
# Uses Python3 tarfile for robust, cross-platform parsing (avoids tar -tvf
# output format differences between GNU tar and bsdtar).
nginx_tar_safe_check() {
    local tar_file="$1"
    local target_dir="$2"

    if [[ -z "${tar_file}" || ! -f "${tar_file}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 文件不存在") ${Font}"
        return 1
    fi
    if [[ -z "${target_dir}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 目标目录未指定") ${Font}"
        return 1
    fi

    # Use Python3 tarfile to inspect every entry. This avoids differences
    # between GNU tar and bsdtar output formats and gives us structured access
    # to entry type, link target, and path.
    local py_result
    py_result=$(python3 - "$tar_file" <<'PYEOF' 2>&1
import sys
import tarfile
import os
import re

tar_path = sys.argv[1]
bad = False
reason = ""

try:
    tf = tarfile.open(tar_path, "r:gz")
except Exception as e:
    print("ERROR: cannot open tar: %s" % e)
    sys.exit(1)

def normalize(path):
    """Collapse . and .. components, strip leading ./"""
    parts = []
    for p in path.split("/"):
        if p == "" or p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts)

CTRL_RE = re.compile(r'[\x00-\x1f\x7f]')

for member in tf.getmembers():
    name = member.name
    # Reject control characters in the path.
    if CTRL_RE.search(name):
        bad = True
        reason = "control char in path: %r" % name
        break
    # Reject absolute paths.
    if name.startswith("/"):
        bad = True
        reason = "absolute path: %s" % name
        break
    # Reject parent traversal as a full path component.
    if ".." in name.split("/"):
        bad = True
        reason = "parent traversal: %s" % name
        break
    # Require every entry to live under "nginx/" top-level prefix.
    normalized = normalize(name)
    if normalized != "nginx" and not normalized.startswith("nginx/"):
        bad = True
        reason = "non-nginx/ top-level entry: %s" % name
        break

    # Inspect entry type.
    if member.issym() or member.islnk():
        # Symlink or hardlink. Verify target stays inside nginx/.
        target = member.linkname
        if target.startswith("/"):
            bad = True
            reason = "link absolute target: %s -> %s" % (name, target)
            break
        if ".." in target.split("/"):
            # For symlinks, resolve relative to the entry's directory.
            # For hardlinks, the target is relative to archive root.
            if member.issym():
                entry_dir = os.path.dirname(name)
                resolved = normalize(entry_dir + "/" + target)
            else:
                resolved = normalize(target)
            if resolved != "nginx" and not resolved.startswith("nginx/"):
                bad = True
                reason = "link target escapes nginx/: %s -> %s" % (name, target)
                break
        else:
            # No ".." — still verify target is inside nginx/.
            if member.issym():
                entry_dir = os.path.dirname(name)
                resolved = normalize(entry_dir + "/" + target)
            else:
                resolved = normalize(target)
            if resolved != "nginx" and not resolved.startswith("nginx/"):
                bad = True
                reason = "link target outside nginx/: %s -> %s" % (name, target)
                break
    elif member.isdev():
        bad = True
        reason = "device file: %s" % name
        break
    elif member.isfifo():
        bad = True
        reason = "FIFO: %s" % name
        break
    # Regular files and directories are allowed.

tf.close()

if bad:
    print("REJECT: %s" % reason)
    sys.exit(1)
else:
    print("OK")
    sys.exit(0)
PYEOF
    )
    local py_exit=$?

    if [[ ${py_exit} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查") ${py_result} ${Font}"
        return 1
    fi

    # Extract into staging with safe tar options: drop original owner/perms.
    if ! tar -xzf "${tar_file}" \
        -C "${target_dir}" \
        --no-same-permissions \
        --no-same-owner \
        --no-overwrite-dir \
        2>/dev/null; then
        # Fallback: some tar implementations (BusyBox) don't support all flags.
        # Retry with --no-same-owner only, which is the most critical safety flag.
        if ! tar -xzf "${tar_file}" -C "${target_dir}" --no-same-owner 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 解压失败") ${Font}"
            return 1
        fi
    fi

    return 0
}

restore_nginx_preinstall_backup() {
    local backup_dir="$1"
    [[ -n "${backup_dir}" && -d "${backup_dir}" ]] || return 0
    safe_rm "${nginx_dir}" || return 1
    mv "${backup_dir}" "${nginx_dir}"
}

nginx_download_release_asset() {
    local url="$1"
    local output="$2"
    curl -fL -# --connect-timeout 10 --retry 2 --retry-delay 1 -o "${output}" "${url}"
}

nginx_verify_release_sha256() {
    local expected_sha="$1"
    local filename="$2"
    printf '%s  %s\n' "${expected_sha}" "${filename}" | sha256sum -c - >/dev/null 2>&1
}

nginx_validate_binary_file() {
    local binary="$1"
    local magic
    magic=$(head -c 4 "${binary}" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    [[ "${magic}" == "7f454c46" && -x "${binary}" ]]
}

nginx_run_config_test() {
    "${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf"
}

nginx_install() {
    # Staging-based install with mandatory manifest and SHA256.
    # Uses dedicated idleleo-nginx user with layered permissions.
    # Uses nginx_tar_safe_check() for strict archive safety validation.
    local temp_dir
    temp_dir=$(mktemp -d)
    local current_dir
    current_dir=$(pwd)

    cd "$temp_dir" || return 1

    local nginx_arch
    local nginx_filename
    local expected_nginx_filename
    case $(uname -m) in
        x86_64)
            nginx_arch="x86"
            nginx_filename="xray-nginx-custom-x86.tar.gz"
            ;;
        aarch64|arm64)
            nginx_arch="arm"
            nginx_filename="xray-nginx-custom-arm.tar.gz"
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "不支持的系统架构"): $(uname -m) ${Font}"
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
            ;;
    esac
    expected_nginx_filename="${nginx_filename}"

    log_echo "${OK} ${GreenBG} $(gettext "即将下载已编译的") Nginx v${nginx_build_version} (${nginx_arch}) ${Font}"

    local base_url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${nginx_build_version}"
    local manifest_file="${temp_dir}/release-manifest.json"

    # Manifest is mandatory (fail-closed). Missing/invalid manifest = abort.
    if ! download_json_file "${base_url}/release-manifest.json" "${manifest_file}"; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "release-manifest.json 下载失败或无效, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Validate manifest structure: must have assets array with matching arch entry.
    local manifest_filename
    local manifest_sha256
    local manifest_build_version
    local manifest_tag
    manifest_filename=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .filename // empty' "${manifest_file}" | head -n 1)
    manifest_sha256=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .sha256 // empty' "${manifest_file}" | head -n 1)
    manifest_build_version=$(jq -r '.versions.nginx_build // empty' "${manifest_file}")
    manifest_tag=$(jq -r '.tag // empty' "${manifest_file}")
    if [[ -z "${manifest_filename}" || "${manifest_filename}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 中未找到架构"): ${nginx_arch} $(gettext "的产物记录, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ -z "${manifest_sha256}" || "${manifest_sha256}" == "null" ]]; then
        # SHA256 is mandatory when manifest exists. Fail-closed.
        log_echo "${Error} ${RedBG} $(gettext "manifest 中未提供 SHA256, 拒绝未校验安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ "${manifest_filename}" != "${expected_nginx_filename}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 产物文件名与架构契约不匹配, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ ! "${manifest_sha256}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest SHA256 格式无效, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ "${manifest_build_version}" != "${nginx_build_version}" ||
          "${manifest_tag}" != "v${nginx_build_version}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 版本或 tag 不匹配, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    nginx_filename="${manifest_filename}"
    local nginx_sha256="${manifest_sha256}"

    local url="${base_url}/${nginx_filename}"

    if ! nginx_download_release_asset "$url" "$nginx_filename"; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "下载") $(gettext "失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx $(gettext "下载") $(gettext "完成") ${Font}"

    # Mandatory SHA256 verification (fail-closed).
    if ! nginx_verify_release_sha256 "${nginx_sha256}" "${nginx_filename}"; then
        log_echo "${Error} ${RedBG} Nginx SHA256 $(gettext "校验") $(gettext "失败") $(gettext ", 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx SHA256 $(gettext "校验") $(gettext "通过") ${Font}"

    # Strict tar safety check (replaces previous simple grep-based check).
    # Validates every entry before extraction and extracts into a staging
    # directory with --no-same-permissions --no-same-owner.
    local staging_dir="${temp_dir}/staging"
    mkdir -p "${staging_dir}"
    if ! nginx_tar_safe_check "${nginx_filename}" "${staging_dir}"; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 压缩包安全检查失败, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "Nginx 压缩包安全检查通过") ${Font}"

    # Verify extracted structure (sbin/nginx must be a regular file).
    if [[ ! -f "${staging_dir}/nginx/sbin/nginx" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "解压后未找到 sbin/nginx 或不是常规文件, 结构校验失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Verify sbin/nginx is a valid ELF binary.
    # ELF magic: 0x7f 'E' 'L' 'F'. file(1) may be unavailable on minimal systems.
    if ! nginx_validate_binary_file "${staging_dir}/nginx/sbin/nginx"; then
        log_echo "${Error} ${RedBG} $(gettext "sbin/nginx 不是可执行 ELF 二进制, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Move the validated staging tree into temp_dir root so subsequent code
    # that expects "./nginx" continues to work.
    if ! mv "${staging_dir}/nginx" "./nginx"; then
        log_echo "${Error} ${RedBG} $(gettext "staging 目录移动失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Backup current nginx_dir before replacement (for rollback).
    local nginx_backup_dir=""
    if [[ -d "${nginx_dir}" ]]; then
        nginx_backup_dir="${nginx_dir}.pre-install.$$"
        if ! mv "${nginx_dir}" "${nginx_backup_dir}" 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 现有目录备份失败, 拒绝替换") ${Font}"
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
        fi
    fi

    # Atomic swap: move staged nginx to final location.
    if ! mv ./nginx "${nginx_dir}"; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 替换失败") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p "${nginx_conf_dir}"
    if ! cp -fp "${nginx_dir}"/conf/nginx.conf "${nginx_conf_dir}"/nginx.default; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Create dedicated idleleo-nginx user before modifying config.
    if ! ensure_idleleo_nginx_user; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    if ! modify_nginx_origin_conf; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Apply layered permission model (replaces chown -fR nobody / chmod -fR 755).
    # Propagate permission failure so callers (nginx_update) can trigger rollback.
    if ! apply_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限应用失败, 可能影响服务运行") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if ! verify_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限验证失败") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Post-install config validation.
    if ! nginx_run_config_test >/dev/null 2>&1; then
        local _nginx_t_output
        _nginx_t_output=$(nginx_run_config_test 2>&1)
        _nginx_t_output=$(printf '%s' "${_nginx_t_output}" | redact_diagnostic_text)
        log_echo "${Error} ${RedBG} $(gettext "Nginx 配置校验失败"): ${_nginx_t_output} ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Only discard an internal pre-install backup after replacement, permission
    # verification, and nginx -t all succeed. nginx_update keeps its separate
    # outer backup until service/port health also succeeds.
    if [[ -n "${nginx_backup_dir}" && -d "${nginx_backup_dir}" ]]; then
        safe_rm "${nginx_backup_dir}" || {
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
        }
    fi

    # 删除临时文件
    cd "$current_dir" && rm -rf "$temp_dir"
    return 0
}

nginx_diagnose() {
    if [[ -x "${nginx_dir}/sbin/nginx" ]]; then
        local nginx_test_output
        nginx_test_output=$("${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf" 2>&1)
        nginx_test_output=$(printf '%s' "${nginx_test_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "配置检测"): ${nginx_test_output} ${Font}"
    fi
    local nginx_journal_output
    nginx_journal_output=$(journalctl -u nginx --no-pager -n 10 2>/dev/null)
    if [[ -n "${nginx_journal_output}" ]]; then
        nginx_journal_output=$(printf '%s' "${nginx_journal_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "服务日志"): ${Font}"
        echo "${nginx_journal_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
    fi
}

xray_diagnose() {
    if [[ -x "${xray_bin_dir}/xray" ]]; then
        local xray_version_output
        xray_version_output=$("${xray_bin_dir}/xray" version 2>&1 | head -3)
        xray_version_output=$(printf '%s' "${xray_version_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "版本检测"): ${xray_version_output} ${Font}"
    fi
    local xray_journal_output
    xray_journal_output=$(journalctl -u xray --no-pager -n 10 2>/dev/null)
    if [[ -n "${xray_journal_output}" ]]; then
        xray_journal_output=$(printf '%s' "${xray_journal_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "服务日志"): ${Font}"
        echo "${xray_journal_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
    fi
    if [[ -f "${xray_error_log}" ]]; then
        local xray_error_output
        xray_error_output=$(tail -10 "${xray_error_log}" 2>/dev/null)
        if [[ -n "${xray_error_output}" ]]; then
            xray_error_output=$(printf '%s' "${xray_error_output}" | redact_diagnostic_text)
            log_echo "${Error} $(gettext "错误日志"): ${Font}"
            echo "${xray_error_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
        fi
    fi
}

restore_nginx_backup() {
    local backup_dir="$1"

    service_stop || return 1
    safe_rm "${nginx_dir}" || return 1
    if ! mv "${backup_dir}" "${nginx_dir}"; then
        return 1
    fi
    apply_nginx_layered_permissions || return 1
    verify_nginx_layered_permissions || return 1
    service_start || return 1
    sleep 1
    if ! health_check_nginx_update "${port:-}"; then
        nginx_diagnose
        return 1
    fi
    return 0
}

# Layered rollback & health check helpers
# Layering order on update failure:
#   Layer 1: restore local pre-update backup (binary/script)
#   Layer 2: install known-good tested_version from API
#   Layer 3: stop service + print redacted diagnostics, no infinite retry
# Each layer is attempted at most once.

# Backup current Xray binary to ${idleleo_dir}/tmp/xray.prev with metadata.
# Same directory as the binary's parent ensures same-filesystem mv; ${idleleo_dir}/tmp
# is also created by compat_migrate, so it exists on every supported install.
backup_xray_binary() {
    local xray_binary="${xray_bin_dir}/xray"
    local backup_dir="${idleleo_dir}/tmp"
    [[ ! -f "${xray_binary}" ]] && return 1
    mkdir -p "${backup_dir}"
    # cp -p preserves owner/group/mode; the .prev file must not be world-readable
    if ! cp -p "${xray_binary}" "${backup_dir}/xray.prev"; then
        log_echo "${Warning} ${YellowBG} Xray $(gettext "二进制备份失败") ${Font}"
        return 1
    fi
    chmod 600 "${backup_dir}/xray.prev" 2>/dev/null
    {
        printf 'backup_time=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'backup_version=%s\n' "$(info_extraction xray_version 2>/dev/null)"
        printf 'backup_sha256=%s\n' "$(sha256sum "${xray_binary}" 2>/dev/null | awk '{print $1}')"
    } > "${backup_dir}/xray.prev.meta"
    chmod 600 "${backup_dir}/xray.prev.meta" 2>/dev/null
    return 0
}

# Restore Xray binary from local backup (Layer 1 rollback).
# Verifies sha256 against recorded metadata before restoring.
restore_xray_binary_backup() {
    local backup_file="${idleleo_dir}/tmp/xray.prev"
    local backup_meta="${idleleo_dir}/tmp/xray.prev.meta"
    local target="${xray_bin_dir}/xray"

    if [[ ! -f "${backup_file}" ]]; then
        log_echo "${Warning} ${YellowBG} Xray $(gettext "本机备份不存在, 跳过 Layer 1 恢复") ${Font}"
        return 1
    fi
    if [[ -f "${backup_meta}" ]]; then
        local expected_sha actual_sha
        expected_sha=$(grep '^backup_sha256=' "${backup_meta}" | cut -d= -f2-)
        actual_sha=$(sha256sum "${backup_file}" 2>/dev/null | awk '{print $1}')
        if [[ -n "${expected_sha}" && "${expected_sha}" != "${actual_sha}" ]]; then
            log_echo "${Error} ${RedBG} Xray $(gettext "备份校验失败, 拒绝恢复") ${Font}"
            return 1
        fi
    fi
    systemctl stop xray >/dev/null 2>&1
    if ! mv -f "${backup_file}" "${target}"; then
        log_echo "${Error} ${RedBG} Xray $(gettext "二进制恢复失败") ${Font}"
        return 1
    fi
    chmod 755 "${target}" 2>/dev/null
    systemctl start xray >/dev/null 2>&1
    sleep 1
    if ! systemctl -q is-active xray; then
        xray_diagnose
        return 1
    fi
    return 0
}

# Layer 2 fallback: install Xray from API tested_version (known-good baseline).
# Returns 0 on success, 1 if tested_version is missing or installation fails.
fallback_xray_to_tested_version() {
    local tested_ver
    tested_ver=$(check_version_silent xray_tested_version)
    if [[ -z "${tested_ver}" || "${tested_ver}" == "null" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "tested_version 不可用, 跳过 Layer 2 恢复") ${Font}"
        return 1
    fi
    log_echo "${Info} ${GreenBG} $(gettext "尝试使用 tested_version 恢复"): v${tested_ver} ${Font}"
    systemctl stop xray >/dev/null 2>&1
    if ! xray_install_release install -f --version "v${tested_ver}"; then
        log_echo "${Error} ${RedBG} Xray tested_version $(gettext "安装失败") ${Font}"
        return 1
    fi
    if ! "${xray_bin_dir}/xray" -version &>/dev/null; then
        log_echo "${Error} ${RedBG} Xray tested_version $(gettext "二进制不可执行") ${Font}"
        return 1
    fi
    systemctl start xray >/dev/null 2>&1
    sleep 1
    if ! systemctl -q is-active xray; then
        xray_diagnose
        return 1
    fi
    update_json_config "${xray_install_config_file}" --arg xray_version "${tested_ver}" '.xray_version = $xray_version' >/dev/null 2>&1
    log_echo "${OK} ${GreenBG} Xray $(gettext "已恢复到 tested_version"): v${tested_ver} ${Font}"
    return 0
}

# Layer 2 fallback: install Nginx from API tested_version (known-good baseline).
fallback_nginx_to_tested_version() {
    local tested_ver
    tested_ver=$(check_version_silent nginx_build_tested_version)
    if [[ -z "${tested_ver}" || "${tested_ver}" == "null" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "tested_version 不可用, 跳过 Layer 2 恢复") ${Font}"
        return 1
    fi
    log_echo "${Info} ${GreenBG} $(gettext "尝试使用 tested_version 恢复"): v${tested_ver} ${Font}"
    systemctl stop nginx >/dev/null 2>&1
    # Save and override global version used by nginx_install
    local _saved_version="${nginx_build_version}"
    nginx_build_version="${tested_ver}"
    if ! nginx_install; then
        nginx_build_version="${_saved_version}"
        log_echo "${Error} ${RedBG} Nginx tested_version $(gettext "安装失败") ${Font}"
        return 1
    fi
    systemctl start nginx >/dev/null 2>&1
    sleep 1
    if ! health_check_nginx_update "${port:-}"; then
        nginx_build_version="${_saved_version}"
        nginx_diagnose
        return 1
    fi
    if ! update_json_config "${xray_install_config_file}" --arg nginx_build_version "${tested_ver}" \
        '.nginx_build_version = $nginx_build_version' >/dev/null 2>&1; then
        nginx_build_version="${_saved_version}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx $(gettext "已恢复到 tested_version"): v${tested_ver} ${Font}"
    return 0
}

rollback_nginx_update() {
    local backup_dir="$1"
    local previous_version="$2"
    nginx_rollback_layer=0

    # Layer 1: the exact pre-update directory.
    if restore_nginx_backup "${backup_dir}"; then
        if update_json_config "${xray_install_config_file}" \
            --arg nginx_build_version "${previous_version}" \
            '.nginx_build_version = $nginx_build_version'; then
            nginx_rollback_layer=1
            return 0
        fi
        log_echo "${Error} ${RedBG} Nginx $(gettext "旧版本记录恢复失败, 继续 tested_version 恢复") ${Font}"
    fi

    # Layer 2: one known-good API fallback attempt. Keep any still-existing
    # local backup until the fallback has passed its own health check.
    log_echo "${Info} ${YellowBG} $(gettext "Layer 1 失败, 尝试 Layer 2 tested_version 恢复") ${Font}"
    if fallback_nginx_to_tested_version; then
        [[ -e "${backup_dir}" || -L "${backup_dir}" ]] && safe_rm "${backup_dir}"
        nginx_rollback_layer=2
        return 0
    fi

    # Layer 3: fail closed, keep remaining evidence/backups, stop and redact.
    log_echo "${Error} ${RedBG} Nginx $(gettext "所有回滚层均失败")! ${Font}"
    systemctl stop nginx >/dev/null 2>&1
    nginx_diagnose
    log_echo "${Error} ${RedBG} Nginx $(gettext "更新失败且所有回滚层均失败, 请手动检查") ${Font}"
    return 1
}

recover_failed_nginx_update() {
    local backup_dir="$1"
    local previous_version="$2"
    if rollback_nginx_update "${backup_dir}" "${previous_version}"; then
        if [[ ${nginx_rollback_layer} -eq 1 ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Nginx $(gettext "版本")! ${Font}"
        else
            log_echo "${OK} ${GreenBG} Nginx $(gettext "已恢复到 tested_version")! ${Font}"
        fi
    fi
    # The attempted update failed even when service recovery succeeded.
    return 1
}

# Health check: Xray after update. Verifies binary, version, config, service, port.
health_check_xray_update() {
    local expected_version="$1"
    local xray_binary="${xray_bin_dir}/xray"

    [[ ! -x "${xray_binary}" ]] && { log_echo "${Error} ${RedBG} Xray $(gettext "二进制不可执行") ${Font}"; return 1; }
    if ! "${xray_binary}" -version &>/dev/null; then
        log_echo "${Error} ${RedBG} Xray $(gettext "二进制执行失败") ${Font}"
        return 1
    fi
    if [[ -n "${expected_version}" ]]; then
        local actual_version
        actual_version=$("${xray_binary}" version 2>/dev/null | head -1 | awk '{print $2}')
        # Xray prints "vX.Y.Z" or "X.Y.Z"; accept either form
        if [[ "${actual_version}" != "v${expected_version}" && "${actual_version}" != "${expected_version}" ]]; then
            log_echo "${Error} ${RedBG} Xray $(gettext "版本不匹配"): expected=${expected_version}, actual=${actual_version} ${Font}"
            return 1
        fi
    fi
    # Config syntax check (does not require running service)
    if [[ -f "${xray_conf}" ]]; then
        if ! "${xray_binary}" run -test -config "${xray_conf}" &>/dev/null; then
            log_echo "${Error} ${RedBG} Xray $(gettext "配置解析失败") ${Font}"
            return 1
        fi
    fi
    if ! systemctl -q is-active xray; then
        log_echo "${Error} ${RedBG} Xray $(gettext "服务未运行") ${Font}"
        return 1
    fi
    # Port listening check (only when port is known from config)
    local listen_port
    listen_port=$(info_extraction port 2>/dev/null)
    if [[ -n "${listen_port}" && "${listen_port}" != "null" ]]; then
        if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${listen_port}\$"; then
            log_echo "${Warning} ${YellowBG} Xray $(gettext "端口未监听"): ${listen_port} ${Font}"
            return 1
        fi
    fi
    return 0
}

# Health check: Nginx after update. Verifies nginx -t, service, port.
health_check_nginx_update() {
    local listen_port="$1"
    local nginx_binary="${nginx_dir}/sbin/nginx"

    [[ ! -x "${nginx_binary}" ]] && { log_echo "${Error} ${RedBG} Nginx $(gettext "二进制不可执行") ${Font}"; return 1; }
    if ! "${nginx_binary}" -t -c "${nginx_dir}/conf/nginx.conf" &>/dev/null; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "配置检测失败") ${Font}"
        nginx_diagnose
        return 1
    fi
    if ! systemctl -q is-active nginx; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "服务未运行") ${Font}"
        return 1
    fi
    if ! verify_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "分层权限验证失败") ${Font}"
        return 1
    fi
    if [[ -n "${listen_port}" && "${listen_port}" != "null" ]]; then
        if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${listen_port}\$"; then
            log_echo "${Warning} ${YellowBG} Nginx $(gettext "端口未监听"): ${listen_port} ${Font}"
            return 1
        fi
    fi
    return 0
}

activate_nginx_update() {
    local listen_port="${1:-}"
    apply_nginx_layered_permissions || return 1
    verify_nginx_layered_permissions || return 1
    service_start || return 1
    sleep 1
    health_check_nginx_update "${listen_port}"
}

# Health check: install.sh after update. Verifies bash -n and shell_version marker.
health_check_shell_update() {
    local script_file="$1"
    local expected_version="$2"

    [[ -z "${script_file}" ]] && script_file="${idleleo_dir}/install.sh"
    if [[ ! -f "${script_file}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "脚本不存在"): ${script_file} ${Font}"
        return 1
    fi
    if ! bash -n "${script_file}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "脚本语法检查失败") ${Font}"
        return 1
    fi
    if [[ -n "${expected_version}" ]]; then
        local actual_version
        actual_version=$(grep -E '^shell_version=' "${script_file}" | head -1 | awk -F'=|"' '{print $3}')
        if [[ "${actual_version}" != "${expected_version}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "脚本版本不匹配"): expected=${expected_version}, actual=${actual_version} ${Font}"
            return 1
        fi
    fi
    return 0
}

nginx_update() {
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    local save_originconf=""
    if [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        current_nginx_build_version=$(info_extraction nginx_build_version)
        if [[ ${nginx_build_version} != ${current_nginx_build_version} ]]; then
            log_echo "${Info} ${GreenBG} Nginx $(gettext "更新"): v${current_nginx_build_version} → v${nginx_build_version} ${Font}"
            ip_check
            if [[ -f "${xray_install_config_file}" ]]; then
                domain=$(info_extraction host)
                if [[ ${tls_mode} == "TLS" ]]; then
                    port=$(info_extraction port)
                    if [[ ${transport_mode} == "onlyws" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(generate_random_port 30000 30999)
                        while [[ ${gport} == ${xport} ]]; do gport=$(generate_random_port 30000 30999); done
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "onlygRPC" ]]; then
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xport=$(generate_random_port 20000 20999)
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                        xport=$(generate_random_port 20000 20999)
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                        gport=$(generate_random_port 30000 30999)
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "wsxhttp" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                        gport=$(generate_random_port 30000 30999)
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                    fi
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不完整, 退出更新")!" >>"${log_file}" && return 1
                        log_echo "${Error} ${RedBG} $(gettext "配置不完整, 退出更新")! ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
                    port=$(info_extraction port)
                    serverNames=$(info_extraction serverNames)
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不完整, 退出更新")!" >>"${log_file}" && return 1
                        log_echo "${Error} ${RedBG} $(gettext "配置不完整, 退出更新")! ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "None" ]]; then
                    [[ ${auto_update} == "YES" ]] && echo "$(gettext "当前安装模式不需要") Nginx !" >>"${log_file}" && return 1
                    log_echo "${Error} ${RedBG} $(gettext "当前安装模式不需要") Nginx ! ${Font}"
                    return 1
                elif [[ ${tls_mode} == "XTLS" ]]; then
                    [[ ${auto_update} == "YES" ]] && echo "$(gettext "当前安装模式不需要") Nginx !" >>"${log_file}" && return 1
                    log_echo "${Error} ${RedBG} $(gettext "当前安装模式不需要") Nginx ! ${Font}"
                    return 1
                fi
            else
                [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不存在, 退出更新")!" >>"${log_file}" && return 1
                log_echo "${Error} ${RedBG} $(gettext "配置不存在, 退出更新")! ${Font}"
                return 1
            fi
            service_stop || return 1
            backup_nginx_dir="${nginx_dir}_backup_${current_nginx_build_version}"
            if [[ -e "${backup_nginx_dir}" || -L "${backup_nginx_dir}" ]]; then
                safe_rm "${backup_nginx_dir}" || return 1
            fi
            if ! cp -a "${nginx_dir}" "${backup_nginx_dir}"; then
                log_echo "${Error} ${RedBG} $(gettext "备份旧版") Nginx $(gettext "失败") ${Font}"
                return 1
            fi
            log_echo "${OK} ${GreenBG} $(gettext "备份旧版") Nginx $(gettext "完成") ${Font}"
            countdown "$(gettext "删除旧版") Nginx !"
            safe_rm "${nginx_dir}" || return 1
            if [[ ${auto_update} != "YES" ]]; then
                echo
                log_echo "${GreenBG} $(gettext "是否保留原 Nginx 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r save_originconf_fq
            else
                save_originconf_fq=1
            fi
            case $save_originconf_fq in
            [nN][oO] | [nN])
                rm -rf "${nginx_conf_dir}"/*.conf
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除")! ${Font}"
                ;;
            *)
                save_originconf="Yes"
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已保留")! ${Font}"
                ;;
            esac
            if ! nginx_install; then
                # nginx_install returns 1 on hard failure (not exit).
                # Enter rollback path directly — same as startup failure.
                local nginx_start_failed=1
                local service_start_failed=1
            else
                # nginx_install succeeded, proceed with config and startup
                local nginx_start_failed=0
                local service_start_failed=0
                if [[ ${tls_mode} == "TLS" ]] && [[ ${save_originconf} != "Yes" ]]; then
                    if ! (nginx_ssl_conf_add && nginx_conf_add && nginx_servers_conf_add); then
                        nginx_start_failed=1
                        service_start_failed=1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]] && [[ ${save_originconf} != "Yes" ]]; then
                    if ! (nginx_reality_conf_add && nginx_reality_servers_add && nginx_reality_serverNames_add); then
                        nginx_start_failed=1
                        service_start_failed=1
                    fi
                fi
                if [[ ${nginx_start_failed} -eq 0 ]] && ! activate_nginx_update "${port}"; then
                    nginx_start_failed=1
                    service_start_failed=1
                fi
            fi
            if [[ ${nginx_start_failed} -eq 0 ]] && ! update_json_config "${xray_install_config_file}" \
                --arg nginx_build_version "${nginx_build_version}" \
                '.nginx_build_version = $nginx_build_version'; then
                log_echo "${Error} ${RedBG} Nginx $(gettext "版本记录更新失败, 执行回滚") ${Font}"
                nginx_start_failed=1
            fi
            if [[ ${nginx_start_failed} -eq 1 ]]; then
                log_echo "${Error} ${RedBG} Nginx $(gettext "启动") $(gettext "失败")! ${Font}"
                if [[ ${service_start_failed} -eq 0 ]]; then
                    nginx_diagnose
                fi
                # Layered rollback — Layer 1 (local backup) → Layer 2 (tested_version) → Layer 3 (stop + diagnostics).
                # Each layer is attempted at most once. No infinite retry, no recursive update.
                if [[ ${auto_update} != "YES" ]]; then
                    echo
                    log_echo "${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                else
                    rollback_fq="y"
                fi
                case $rollback_fq in
                [nN][oO] | [nN])
                    log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                    return 1
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                    recover_failed_nginx_update "${backup_nginx_dir}" "${current_nginx_build_version}"
                    return $?
                    ;;
                esac
            elif [[ ${service_start_failed} -eq 1 ]]; then
                return 1
            else
                judge "Nginx $(gettext "更新")"
                safe_rm "${backup_nginx_dir}" || return 1
                judge "$(gettext "删除") Nginx $(gettext "备份")"
            fi
        else
            log_echo "${OK} ${GreenBG} Nginx $(gettext "已为最新版") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} Nginx $(gettext "未安装") ${Font}"
    fi
    return 0
}

auto_update() {
    if [[ "${ID}" == "centos" ]]; then
        crontab_file="/var/spool/cron/root"
    else
        crontab_file="/var/spool/cron/crontabs/root"
    fi
    if [[ ! -f "${auto_update_file}" ]] || [[ $(crontab -l | grep -c "auto_update.sh") -lt 1 ]]; then
        echo
        log_echo "${GreenBG} $(gettext "设置后台定时自动更新程序 (包含: 脚本/Xray/Nginx)") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "可能自动更新后有兼容问题, 谨慎启用") ${Font}"
        log_echo "${GreenBG} $(gettext "是否启用") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            download_script_file "${au_remote_url}" "${auto_update_file}"
            judge -r "$(gettext "下载自动更新脚本")" || return 1
            echo "0 1 15 * * bash \"${auto_update_file}\"" >>"${crontab_file}"
            judge -r "$(gettext "设置自动更新")"
            ;;
        *) ;;
        esac
    else
        log_echo "${OK} ${GreenBG} $(gettext "已设置自动更新") ${Font}"
        log_echo "${GreenBG} $(gettext "是否关闭") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_close_fq
        case $auto_update_close_fq in
        [yY][eE][sS] | [yY])
            sed -i "/auto_update.sh/d" "${crontab_file}"
            rm -rf "${auto_update_file}"
            judge -r "$(gettext "删除自动更新")"
            ;;
        *) ;;
        esac
    fi
}

ssl_install() {
    pkg_install "socat"
    judge -r "$(gettext "安装 SSL 证书生成脚本依赖")" || return 1
    local acme_install_file="${idleleo_dir}/tmp/acme-install.sh"
    if ! download_script_file "https://get.acme.sh" "$acme_install_file" sh; then
        log_echo "${Error} ${RedBG} $(gettext "下载 SSL 证书生成脚本失败") ${Font}"
        exit 1
    fi
    sh "$acme_install_file" email=${custom_email}
    local acme_install_ret=$?
    rm -f "$acme_install_file"
    if [[ $acme_install_ret -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "安装 SSL 证书生成脚本") $(gettext "完成") ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} $(gettext "安装 SSL 证书生成脚本") $(gettext "失败") ${Font}"
        exit 1
    fi
}

domain_check() {
    local ip_version_fq install
    while true; do
        if [[ "on" == ${old_config_status} ]] && [[ -n $(info_extraction host) ]] && [[ -n $(info_extraction ip_version) ]]; then
            echo
            log_echo "${GreenBG} $(gettext "检测到原域名配置存在, 是否跳过域名设置") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq || return 1
            case $old_host_fq in
            [nN][oO] | [nN]) ;;
            *)
                domain=$(info_extraction host)
                ip_version=$(info_extraction ip_version)
                if [[ ${ip_version} == "IPv4" ]]; then
                    local_ip=$(get_public_ip "IPv4")
                elif [[ ${ip_version} == "IPv6" ]]; then
                    local_ip=$(get_public_ip "IPv6")
                else
                    local_ip=${ip_version}
                fi
                if [[ -z ${local_ip} ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
                    return 1
                fi
                log_echo "${OK} ${GreenBG} $(gettext "已跳过域名设置") ${Font}"
                return 0
                ;;
            esac
        fi
        echo
        log_echo "${GreenBG} $(gettext "确定域名信息") ${Font}"
        read_optimize "$(gettext "请输入你的域名信息") (e.g. www.hey.run):" "domain" "NULL" || return 1
        echo -e "\n${GreenBG} $(gettext "请选择公网IP(IPv4/IPv6)或手动输入域名") ${Font}"
        echo -e "${Red}1${Font}: IPv4 ($(gettext "默认"))"
        echo "2: IPv6"
        echo "3: $(gettext "域名")"
        read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")!" || return 1
        log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
        if [[ ${ip_version_fq} == 1 ]]; then
            local_ip=$(get_public_ip "IPv4")
            domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
            ip_version="IPv4"
        elif [[ ${ip_version_fq} == 2 ]]; then
            local_ip=$(get_public_ip "IPv6")
            domain_ip=$(ping -6 "${domain}" -c 1 | sed '2{s/[^(]*(//;s/).*//;q}' | tail -n +2)
            ip_version="IPv6"
        elif [[ ${ip_version_fq} == 3 ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "此选项用于服务器商仅提供域名访问服务器") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "请为服务器商提供的域名添加 CNAME 记录") ${Font}"
            read_optimize "$(gettext "请输入"): " "local_ip" "NULL" || return 1
            ip_version=${local_ip}
        else
            local_ip=$(get_public_ip "IPv4")
            domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
            ip_version="IPv4"
        fi
        if [[ -z ${local_ip} ]]; then
            log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
            return 1
        fi
        log_echo "$(gettext "域名 DNS 解析 IP"): ${domain_ip}"
        log_echo "$(gettext "公网IP/域名"): ${local_ip}"
        if [[ ${ip_version_fq} != 3 ]] && [[ ${local_ip} == ${domain_ip} ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "域名 DNS 解析 IP 与公网 IP 匹配") ${Font}"
            break
        else
            log_echo "${Warning} ${YellowBG} $(gettext "请确保域名添加了正确的 A/AAAA 记录, 否则将无法正常使用 Xray") ${Font}"
            log_echo "${Error} ${RedBG} $(gettext "域名 DNS 解析 IP 与公网 IP 不匹配, 请选择"): ${Font}"
            echo "1: $(gettext "继续安装")"
            echo "2: $(gettext "重新输入")"
            log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
            read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!" || return 1
            case $install in
            1)
                log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
                break
                ;;
            2)
                continue
                ;;
            *)
                log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"
                exit 2
                ;;
            esac
        fi
    done
}

ip_check() {
    if [[ "on" == ${old_config_status} || ${auto_update} == "YES" ]] && [[ -n $(info_extraction host) ]] && [[ -n $(info_extraction ip_version) ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "检测到原IP配置存在, 是否跳过IP设置") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq || return 1
        else
            old_host_fq=1
        fi
        case $old_host_fq in
        [nN][oO] | [nN]) ;;
        *)
            ip_version=$(info_extraction ip_version)
            if [[ ${ip_version} == "IPv4" ]]; then
                local_ip=$(get_public_ip "IPv4")
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(get_public_ip "IPv6")
            else
                local_ip=${ip_version}
            fi
            if [[ -z ${local_ip} ]]; then
                log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
                return 1
            fi
            echo
            log_echo "${OK} ${GreenBG} $(gettext "已跳过IP设置") ${Font}"
            return 0
            ;;
        esac
    fi
    echo
    log_echo "${GreenBG} $(gettext "确定公网IP信息") ${Font}"
    log_echo "${GreenBG} $(gettext "请选择公网IP为IPv4或IPv6") ${Font}"
    echo -e "${Red}1${Font}: IPv4 ($(gettext "默认"))"
    echo "2: IPv6"
    echo "3: $(gettext "手动输入")"
    local ip_version_fq
    read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")!" || return 1
    [[ -z ${ip_version_fq} ]] && ip_version=1
    log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(get_public_ip "IPv4")
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(get_public_ip "IPv6")
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        read_optimize "$(gettext "请输入"): " "local_ip" "NULL" || return 1
        ip_version=${local_ip}
    else
        local_ip=$(get_public_ip "IPv4")
        ip_version="IPv4"
    fi
    if [[ -z ${local_ip} ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
        return 1
    fi
    log_echo "$(gettext "公网IP/域名"): ${local_ip}"
}

port_listener_info() {
    local port="$1"
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null ||
        ss -H -ltnp "sport = :${port}" 2>/dev/null
}

# Check whether a PID belongs to a project-managed service.
# Returns 0 (project service) only when the executable path can be
# positively identified as the project's xray or nginx. The systemd unit
# name alone is NOT sufficient (a third-party nginx also has nginx.service).
# If the PID cannot be positively confirmed, returns 1 (treat as third-party).
is_project_service_pid() {
    local pid="$1"
    [[ -z "${pid}" || "${pid}" == "-" ]] && return 1

    # Check 1: executable path via /proc/<pid>/exe — the primary check.
    local exe_path
    exe_path=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
    if [[ -n "${exe_path}" ]]; then
        case "${exe_path}" in
            "${xray_bin_dir}/xray") return 0 ;;
            "${nginx_dir}/sbin/nginx") return 0 ;;
            *) return 1 ;;  # Non-project path → third-party
        esac
    fi

    # Check 2: comm (process name) + cgroup fallback — only when exe path
    # is unavailable (e.g. permission denied). Require BOTH a matching
    # process name AND a matching systemd unit to avoid false positives.
    local comm cgroup
    comm=$(cat "/proc/${pid}/comm" 2>/dev/null || true)
    cgroup=$(cat "/proc/${pid}/cgroup" 2>/dev/null || true)
    if [[ "${comm}" == "xray" ]] && echo "${cgroup}" | grep -qE 'xray\.service|/xray\b'; then
        return 0
    fi
    if [[ "${comm}" == "nginx" ]] && echo "${cgroup}" | grep -qE 'nginx\.service|/nginx\b'; then
        return 0
    fi

    return 1
}

port_exist_check() {
    local port="${1:-}"

    [[ -z "${port}" ]] && return 0

    [[ "${port}" =~ ^[0-9]+$ ]] || {
        log_echo "${Error} ${RedBG} $(gettext "端口格式无效"): ${port} ${Font}"
        return 1
    }

    if ! port_listener_info "${port}" | grep -q .; then
        log_echo "${OK} ${GreenBG} ${port} $(gettext "端口未被占用") ${Font}"
        return 0
    fi

    # Port is occupied. Precisely identify whether the occupant is a
    # project-managed service (xray.service / nginx.service with project
    # binary path). A name-only match (e.g. third-party "nginx" from apt)
    # is NOT sufficient and must be treated as third-party.
    local listener_output pids pid all_project=1
    listener_output=$(port_listener_info "${port}")

    # Extract PIDs from ss/lsof output. Format varies:
    #   ss:   users:(("xray",pid=1234,fd=5))
    #   lsof: COMMAND PID USER FD TYPE SIZE/OFF NODE NAME
    pids=$(echo "${listener_output}" | grep -oE 'pid=[0-9]+' | sed 's/pid=//')
    if [[ -z "${pids}" ]]; then
        # lsof format: second column is PID
        pids=$(echo "${listener_output}" | awk 'NR>1{print $2}')
    fi

    if [[ -z "${pids}" ]]; then
        # Cannot extract any PID — cannot positively confirm project service.
        all_project=0
    else
        for pid in ${pids}; do
            if ! is_project_service_pid "${pid}"; then
                all_project=0
                break
            fi
        done
    fi

    if [[ ${all_project} -eq 1 ]]; then
        log_echo "${OK} ${GreenBG} ${port} $(gettext "端口由本项目服务占用, 将在安装前停止") ${Font}"
        return 0
    fi

    log_echo "${Error} ${RedBG} $(gettext "检测到端口被占用"): ${port} ${Font}"
    echo "${listener_output}"
    log_echo "${Warning} ${YellowBG} $(gettext "脚本不会自动终止占用该端口的进程") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "请更换端口或自行停止对应服务后重试") ${Font}"
    return 1
}

acme() {
    systemctl restart nginx
    #暂时解决ca问题
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --server letsencrypt --keylength ec-256 --force --test; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --keylength ec-256 --force --test; then
        log_echo "${OK} ${GreenBG} SSL $(gettext "证书测试签发成功, 开始正式签发") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
    else
        log_echo "${Error} ${RedBG} SSL $(gettext "证书测试签发失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --server letsencrypt --keylength ec-256 --force; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --keylength ec-256 --force; then
        log_echo "${OK} ${GreenBG} SSL $(gettext "证书生成") $(gettext "成功") ${Font}"
        mkdir -p "${ssl_chainpath}"
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --force --reloadcmd "chown -f root:idleleo-nginx ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && systemctl restart nginx && systemctl restart xray"; then
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            log_echo "${OK} ${GreenBG} SSL $(gettext "证书配置") $(gettext "成功") ${Font}"
            systemctl stop nginx
        else
            log_echo "${Error} ${RedBG} SSL $(gettext "证书配置") $(gettext "失败") ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} SSL $(gettext "证书生成") $(gettext "失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    # Source of truth for multi-user is the actual Xray config, not
    # install_config.json — install_config_* may have already overwritten
    # the metadata before this function runs.
    local _multi_user_detected
    _multi_user_detected=$(detect_multi_user_from_xray_conf)

    # standard_rebuild and mode_switch must always rebuild from template —
    # never preserve the old mode's Xray JSON, even if multi-user is detected.
    case "${reinstall_operation}" in
        standard_rebuild|mode_switch|clean_install)
            _multi_user_detected="no"
            # Remove old multi-user metadata so it doesn't interfere.
            if [[ -f "${xray_install_config_file}" ]]; then
                update_json_config "${xray_install_config_file}" 'del(.multi_user)' 2>/dev/null || true
            fi
            ;;
    esac

    if [[ "${_multi_user_detected}" == "yes" ]]; then
        # Ensure metadata reflects reality so subsequent reads are consistent.
        if [[ -f "${xray_install_config_file}" ]]; then
            local _cur_multi_user
            _cur_multi_user=$(info_extraction multi_user 2>/dev/null)
            [[ "${_cur_multi_user}" != "yes" ]] && \
                update_json_config "${xray_install_config_file}" --arg mu "yes" '.multi_user = $mu' 2>/dev/null || true
        fi
    fi

    # keep-config path — preserve the existing Xray JSON and apply only the
    # user-selected changes. This protects custom routing/outbounds/DNS and
    # multi-user configs. Allowed for both single-user and multi-user: multi-user
    # may modify non-user fields (port, path, Reality params) but NOT UUID/email.
    # Falls back to template rebuild when there is no existing config file.
    if [[ "${reinstall_keep_config}" == "on" && -f "${xray_conf}" ]]; then
        # Apply selected changes to the existing config in-place.
        # Only modify fields the user explicitly chose to change.
        # All modify_* calls must propagate errors (|| return 1).
        if [[ "${change_port}" == "yes" ]]; then
            modify_inbound_port || return 1
        fi
        if [[ "${change_inner_ports}" == "yes" ]]; then
            modify_inbound_port || return 1
        fi
        if [[ "${change_ws_path}" == "yes" || "${change_grpc_path}" == "yes" || "${change_xhttp_path}" == "yes" ]]; then
            modify_path || return 1
        fi
        # UUID/email changes are NOT allowed in keep-config — use user management.
        # change_user is intentionally not handled here; the edit menu no longer
        # offers it and directs users to the user-management entry point.
        if [[ "${change_reality}" == "yes" ]] && [[ ${tls_mode} == "Reality" ]]; then
            modify_target_serverNames || return 1
            modify_privateKey_shortIds || return 1
        fi
        # Transport structure changes are NOT supported in keep-config.
        # change_transport is intentionally not handled here — the edit menu
        # redirects transport changes to standard template rebuild.
        return 0
    fi

    # Template rebuild path (fresh install, standard_rebuild, or mode_switch)
    if [[ "${_multi_user_detected}" != "yes" ]] && \
       [[ "${reinstall_keep_config}" != "on" || ! -f "${xray_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            judge "$(gettext "下载 Xray TLS 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/config/vless_tls.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "Reality" ]]; then
            judge "$(gettext "下载 Xray Reality 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/config/vless_reality.json" "${xray_conf}"
            modify_target_serverNames
            modify_privateKey_shortIds
            xray_reality_add_more
        elif [[ ${tls_mode} == "None" ]]; then
            judge "$(gettext "下载 Xray 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/config/vless_tls.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "XTLS" ]]; then
            judge "$(gettext "下载 Xray XTLS 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/config/vless_xtls.json" "${xray_conf}"
            modify_listen_address
            modify_inbound_port
        fi
        modify_email_address
        modify_UUID
    else
        echo
        log_echo "${Warning} ${GreenBG} $(gettext "检测到 Xray 配置过多用户") ${Font}"
        log_echo "${GreenBG} $(gettext "是否保留原 Xray 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r save_originxray_fq
        case $save_originxray_fq in
        [nN][oO] | [nN])
            rm -rf "${xray_conf}"
            update_json_config "${xray_install_config_file}" 'del(.multi_user)'
            log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除")! ${Font}"
            xray_conf_add
            ;;
        *) ;;
        esac
    fi
}

xray_reality_add_more() {
    if [[ ${reality_add_more} == "on" ]]; then
        if is_ws_mode; then
            add_ws_inbound "0.0.0.0" "${xport}" "${path}"
        fi
        if is_grpc_mode; then
            add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
        fi
        if is_xhttp_mode; then
            add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
        fi
        modify_path
        modify_listen_address
        modify_inbound_port
        judge "$(gettext "添加简单 ws/gRPC/xHTTP 协议")"
    else
        if is_ws_mode; then
            add_ws_inbound "0.0.0.0" "${xport}" "${path}"
        fi
        if is_grpc_mode; then
            add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
        fi
        if is_xhttp_mode; then
            add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
        fi
        modify_path
        modify_inbound_port
    fi

    if [[ ${reality_add_nginx} == "on" ]] && [[ ${reality_add_balance} == "off" ]]; then
        modify_reality_listen_address
    fi
}

old_config_exist_check() {
    # Reset reinstall flags — only set to "on" inside this function when the
    # user explicitly chooses 保留配置重新安装 / mode switch. Ensures a
    # previous reinstall does not leak into a subsequent fresh install.
    reinstall_keep_config="off"
    reinstall_operation="none"
    mode_switch_reuse="off"
    # Reset all change_* flags to prevent leakage from prior reinstall.
    change_port="no"
    change_user="no"
    change_transport="no"
    change_inner_ports="no"
    change_reality="no"
    change_nginx_sni="no"
    change_ws_path="no"
    change_grpc_path="no"
    change_xhttp_path="no"
    # Capture the pre-deploy managed port set for the firewall transaction.
    # managed_ports.json still holds the old value at this point (before any
    # deploy changes), so it is the correct source for rollback.
    _reinstall_firewall_old_ports=$(cat "${managed_ports_file}" 2>/dev/null ||
        echo '{"tcp":[],"udp":[]}')
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"
    if [[ -f "${xray_install_config_file}" ]]; then
        # Snapshot the running config before any reinstall or mode switch
        # So a failed deploy can be rolled back. Skip in test mode
        # where systemctl/xray binaries may not exist.
        if [[ -z "${_TEST_MODE:-}" ]]; then
            if ! _reinstall_backup_dir=$(reinstall_backup_create 2>/dev/null); then
                log_echo "${Error} ${RedBG} $(gettext "无法完成安全备份, 已取消重新配置") ${Font}"
                _reinstall_backup_dir=""
                return 1
            fi
        fi
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            # Split into two explicit paths — keep-config reinstall
            # vs. standard-template rebuild — instead of a single Y/N that
            # conflates "read old config" with "lock all parameters".
            echo
            log_echo "${GreenBG} $(gettext "检测到已有安装配置") ${Font}"
            log_echo "  ${Green}1)${Font} $(gettext "保留配置重新安装")"
            log_echo "  ${Green}2)${Font} $(gettext "使用标准模板重建")"
            log_echo "  ${Green}3)${Font} $(gettext "返回")"
            echo
            log_echo "${GreenBG} $(gettext "请选择") [1/2/3]: ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            1)
                # 保留配置重新安装: read old params, preserve the existing
                # Xray JSON (custom routing/outbounds/DNS are kept).
                log_echo "${OK} ${GreenBG} $(gettext "已选择保留配置重新安装") ${Font}"
                old_config_status="on"
                old_config_loaded="on"
                reinstall_keep_config="on"
                reinstall_operation="keep_config"
                old_config_input
                # Let the user pick which params to modify; unselected
                # fields keep their old values during the reinstall.
                reinstall_edit_menu
                ;;
            2)
                # 使用标准模板重建: warn that custom fields may be removed,
                # then drop the old config and proceed with fresh input.
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "自定义 routing、outbounds、DNS 和其他非标准字段可能被移除") ${Font}"
                log_echo "${Warning} ${YellowBG} $(gettext "原配置已备份") ${Font}"
                log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r _rebuild_confirm
                case $_rebuild_confirm in
                [yY][eE][sS] | [yY])
                    rm -rf "${xray_install_config_file}"
                    old_config_status="off"
                    reinstall_keep_config="off"
                    reinstall_operation="standard_rebuild"
                    log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件, 将使用标准模板重建") ${Font}"
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                    menu
                    ;;
                esac
                ;;
            3|*)
                log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                menu
                ;;
            esac
        else
            # Dedicated mode-switch entry. Show what can be reused,
            # what cannot, and what is backed up. Only proceed after
            # explicit confirmation. The backup was already created at the
            # top of this function, so reinstall_finalize will restore on
            # deploy failure.
            echo
            log_echo "${Warning} ${YellowBG} $(gettext "检测到当前安装模式与配置文件的安装模式不一致") ${Font}"
            log_echo "  $(gettext "当前模式"): ${old_tls_mode}"
            log_echo "  $(gettext "目标模式"): ${tls_mode}"
            echo
            log_echo "${GreenBG} $(gettext "可以复用") ${Font}"
            log_echo "  - UUID"
            log_echo "  - $(gettext "用户名 (email)")"
            echo
            log_echo "${YellowBG} $(gettext "不能直接复用") ${Font}"
            log_echo "  - $(gettext "模式相关参数 (target/privateKey/shortIds/路径等)")"
            echo
            log_echo "${GreenBG} $(gettext "将保留") ${Font}"
            log_echo "  - $(gettext "原 Xray 配置备份")"
            log_echo "  - $(gettext "原 Nginx 配置备份")"
            log_echo "  - $(gettext "原证书")"
            echo
            log_echo "${GreenBG} $(gettext "是否继续切换模式") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                # Reuse mode-independent params from the old config.
                custom_email=$(info_extraction email 2>/dev/null)
                UUID5_char=$(info_extraction idc 2>/dev/null)
                UUID=$(info_extraction id 2>/dev/null)
                mode_switch_reuse="yes"
                reinstall_operation="mode_switch"
                rm -rf "${xray_install_config_file}"
                old_config_status="off"
                reinstall_keep_config="off"
                log_echo "${OK} ${GreenBG} $(gettext "已删除旧配置文件, 将使用目标模式标准模板生成新配置") ${Font}"
                ;;
            *)
                log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                menu
                ;;
            esac
        fi
    fi
}

old_config_input() {
    info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    _info_cache_invalidate
    custom_email=$(info_extraction email)
    UUID5_char=$(info_extraction idc)
    UUID=$(info_extraction id)
    if [[ ${tls_mode} == "TLS" ]]; then
        port=$(info_extraction port)
        if is_ws_mode; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
        fi
        if is_grpc_mode; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
        if is_xhttp_mode; then
            xhttpport=$(info_extraction xhttp_port)
            xhttppath=$(info_extraction xhttp_path)
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        port=$(info_extraction port)
        target=$(info_extraction target)
        serverNames=$(info_extraction serverNames)
        privateKey=$(info_extraction privateKey)
        password=$(info_reality_public_key)
        shortIds=$(info_extraction shortIds)
        # SNI Guard / spiderX 升级兼容：缺失字段补默认值，不覆盖老用户已有配置
        spiderx_path=$(info_extraction spiderx_path)
        reality_nginx_sni_guard=$(info_extraction reality_nginx_sni_guard)
        [[ -z "${reality_nginx_sni_guard}" ]] && reality_nginx_sni_guard="on"
        unknown_sni_policy=$(info_extraction unknown_sni_policy)
        [[ -z "${unknown_sni_policy}" ]] && unknown_sni_policy="isolate"
        decoy_domain=$(info_extraction decoy_domain)
        ensure_reality_sni_guard_defaults
        if [[ ${reality_add_more} == "on" ]]; then
            if is_ws_mode; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
            fi
            if is_grpc_mode; then
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
            fi
            if is_xhttp_mode; then
                xhttpport=$(info_extraction xhttp_port)
                xhttppath=$(info_extraction xhttp_path)
            fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if is_ws_mode; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
        fi
        if is_grpc_mode; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
        if is_xhttp_mode; then
            xhttpport=$(info_extraction xhttp_port)
            xhttppath=$(info_extraction xhttp_path)
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
        port=$(info_extraction port)
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        # The old prompt said "已保留配置文件" while setting
        # old_config_status="off", which meant the install flow would
        # re-prompt and overwrite. Provide clear, behavior-matching options.
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "检测到配置文件不完整") ${Font}"
        log_echo "  ${Green}1)${Font} $(gettext "尝试从实际 Xray 配置补全安装信息")"
        log_echo "  ${Green}2)${Font} $(gettext "备份旧配置后使用标准模板重建")"
        log_echo "  ${Green}3)${Font} $(gettext "返回")"
        echo
        log_echo "${GreenBG} $(gettext "请选择") [1/2/3]: ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        1)
            # Keep what was read; the install flow will use available
            # values and fall back to defaults for missing fields.
            old_config_status="on"
            reinstall_keep_config="on"
            log_echo "${OK} ${GreenBG} $(gettext "将尝试使用已读取的配置继续") ${Font}"
            ;;
        2)
            rm -rf "${xray_install_config_file}"
            old_config_status="off"
            reinstall_keep_config="off"
            log_echo "${OK} ${GreenBG} $(gettext "已删除不完整配置文件, 将使用标准模板重建") ${Font}"
            ;;
        3|*)
            log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
            menu
            ;;
        esac
    fi
}

# Reinstall parameter edit menu.
# Called after old_config_input reads the old config. Lets the user pick
# which fields to modify; unselected fields keep their old values.
# Sets the per-field change_* flags that param functions check.
reinstall_edit_menu() {
    echo
    log_echo "${GreenBG} $(gettext "当前配置摘要") ${Font}"
    log_echo "  $(gettext "安装模式"): ${tls_mode}"
    [[ -n "${transport_mode:-}" ]] && log_echo "  $(gettext "传输组合"): ${transport_mode}"
    [[ -n "${port:-}" ]] && log_echo "  $(gettext "主端口"): ${port}"
    if [[ ${tls_mode} == "Reality" ]]; then
        [[ -n "${target:-}" ]] && log_echo "  target: ${target}"
        [[ -n "${serverNames:-}" ]] && log_echo "  serverNames: ${serverNames}"
    fi
    if is_ws_mode; then
        [[ -n "${xport:-}" ]] && log_echo "  ws $(gettext "端口"): ${xport}"
        [[ -n "${path:-}" ]] && log_echo "  ws $(gettext "路径"): ${path}"
    fi
    if is_grpc_mode; then
        [[ -n "${gport:-}" ]] && log_echo "  gRPC $(gettext "端口"): ${gport}"
        [[ -n "${serviceName:-}" ]] && log_echo "  gRPC serviceName: ${serviceName}"
    fi
    if is_xhttp_mode; then
        [[ -n "${xhttpport:-}" ]] && log_echo "  xHTTP $(gettext "端口"): ${xhttpport}"
        [[ -n "${xhttppath:-}" ]] && log_echo "  xHTTP $(gettext "路径"): ${xhttppath}"
    fi
    echo
    log_echo "${GreenBG} $(gettext "可选择需要修改的项目 (未选择的保持原值)") ${Font}"
    log_echo "  ${Green}1)${Font} $(gettext "修改主端口")"
    log_echo "  ${Green}2)${Font} $(gettext "修改内部端口")"
    log_echo "  ${Green}3)${Font} $(gettext "修改传输路径")"
    log_echo "  ${Green}4)${Font} $(gettext "修改 Reality 参数")"
    log_echo "  ${Green}5)${Font} $(gettext "不再修改, 开始重新部署")"
    echo
    log_echo "${Warning} ${YellowBG} $(gettext "UUID 和多用户信息请使用现有用户管理或 UUID 变更功能") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "传输组合变更请使用标准模板重建") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "Nginx/SNI 修改请使用标准模板重建") ${Font}"
    echo
    local _edit_choice
    while true; do
        log_echo "${GreenBG} $(gettext "请选择") [1-5]: ${Font}"
        read -r _edit_choice
        case $_edit_choice in
        1) change_port="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改主端口") ${Font}" ;;
        2) change_inner_ports="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改内部端口") ${Font}" ;;
        3) change_ws_path="yes"; change_grpc_path="yes"; change_xhttp_path="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改传输路径") ${Font}" ;;
        4) change_reality="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改 Reality 参数") ${Font}" ;;
        5) break ;;
        *) log_echo "${Error} ${RedBG} $(gettext "值为空或超出范围, 请重新输入") ${Font}" ;;
        esac
    done
}

nginx_ssl_conf_add() {
    touch "${nginx_ssl_conf}"
    cat >"${nginx_ssl_conf}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name serveraddr.com;

    location ^~ /.well-known/acme-challenge/ {
        root ${idleleo_dir}/conf;
        default_type "text/plain";
        allow all;
    }
    location = /.well-known/acme-challenge/ {
        return 404;
    }

    location / {
        return 301 https://www.hey.run\$request_uri;
    }
}
EOF
    modify_nginx_ssl_other
    judge "Nginx SSL $(gettext "配置修改")"
}

nginx_conf_add() {
    touch "${nginx_conf}"
    cat >"${nginx_conf}" <<EOF
server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl reuseport;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    http2 on;
    set_real_ip_from      127.0.0.1;
    real_ip_header        X-Forwarded-For;
    real_ip_recursive     on;
    ssl_certificate       ${idleleo_dir}/cert/xray.crt;
    ssl_certificate_key   ${idleleo_dir}/cert/xray.key;
    ssl_protocols         TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_ecdh_curve        X25519:prime256v1:secp384r1;
    server_name           serveraddr.com;
    root /var/www/html;
    error_page 403 https://hey.run/helloworld;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_early_data on;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000";

    location grpc
    {
        #grpc_pass grpc://xray-grpc-server;
        #proxy_pass http://xray-grpc-server;
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$http_host;
    }

    location ws
    {
        #proxy_pass http://xray-ws-server;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location xhttp
    {
        #grpc_pass grpc://xray-xhttp-server;
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
        grpc_set_header Host \$host;
        #proxy_pass http://xray-xhttp-server;
        #proxy_redirect off;
        #proxy_http_version 1.1;
        #proxy_connect_timeout 60s;
        #proxy_send_timeout 720m;
        #proxy_read_timeout 720m;
        #proxy_buffering off;
        #client_max_body_size 0;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        #proxy_set_header Host \$http_host;
    }

    location /
    {
        return 403;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx $(gettext "配置修改")"
}

nginx_reality_conf_add() {
    validate_reality_reserved_ports || return 1
    touch "${nginx_conf}"
    # SNI Guard 策略分支：isolate 默认(ssl_reject_handshake)/reject 死端口/decoy 回落站点
    # 注意：ssl_reject_handshake 属于 ngx_http_ssl_module，必须在 http{} 块内生效，
    #       不能放在 stream{} 块里。isolate 策略下单独写入 03-isolate.conf 由 http 块 include。
    local _deny_port
    case "${unknown_sni_policy}" in
        reject)
            # 直接拒绝：指向无监听的死端口，TCP 连接被拒绝
            _deny_port="9404"
            ;;
        decoy)
            # decoy 回落：指向本地 9444 的 HTTPS 站点（由 03-decoy.conf 提供）
            if decoy_site_artifacts_ready; then
                _deny_port="9444"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_decoy_site_config || return 1
            else
                log_echo "${Warning} ${YellowBG} $(gettext "decoy 站点设置失败, 回退到默认隔离策略") ${Font}"
                unknown_sni_policy="isolate"
                decoy_domain=""
                _deny_port="9403"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_isolate_site_config || return 1
            fi
            ;;
        isolate|*)
            # 隔离：ssl_reject_handshake 发送 TLS alert，不转发到 Xray
            # deny upstream 指向 127.0.0.1:9403，由 http 块内的 03-isolate.conf server 提供 TLS 拒绝
            _deny_port="9403"
            if sni_guard_port_conflicts "${_deny_port}"; then
                log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                return 1
            fi
            write_isolate_site_config || return 1
            ;;
    esac
    if [[ "${unknown_sni_policy}" == "reject" ]] && sni_guard_port_conflicts "${_deny_port}"; then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
        return 1
    fi
    cat >"${nginx_conf}" <<EOF

stream {
    map \$ssl_preread_protocol \$is_valid_protocol {
        #TLSv1.2    1;
        TLSv1.3    1;
        default    0;
    }

    map \$ssl_preread_server_name \$sni_upstream {
        include ${nginx_conf_dir}/*.serverNames;
        default deny;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$final_upstream {
        # 格式：上游名称:协议标记 => 最终上游
        ~^reality:1\$     reality;
        default          deny;
    }

    map \$final_upstream \$is_abnormal {
        deny    1;
        default 0;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$error_type {
        ~^reality:0\$     "tls_error";
        ~^deny:1\$        "sni_error";
        ~^deny:0\$        "tls_sni_error";
        default          "other_error";
    }

    map \$error_type \$is_tls_error {
        "tls_error"      1;
        #"tls_sni_error"  1;
        default          0;
    }

    map \$error_type \$is_sni_error {
        "sni_error"      1;
        "tls_sni_error"  1;
        default          0;
    }

    upstream reality {
        include ${nginx_conf_dir}/*.realityServers;
    }

    upstream deny {
        server 127.0.0.1:${_deny_port};
    }

    log_format tls_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    log_format sni_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    server {
        listen 443 reuseport so_keepalive=on backlog=65535;
        proxy_pass \$final_upstream;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
        access_log ${nginx_dir}/logs/tls_error.log tls_error_log buffer=8k flush=3s if=\$is_tls_error;
        access_log ${nginx_dir}/logs/sni_error.log sni_error_log buffer=8k flush=3s if=\$is_sni_error;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx $(gettext "配置修改")"
}

nginx_reality_servers_add () {
    touch "${nginx_conf_dir}"/127.0.0.1.realityServers
    cat >"${nginx_conf_dir}"/127.0.0.1.realityServers <<EOF
server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;
EOF
    judge "Nginx servers $(gettext "配置修改")"

}

nginx_reality_serverNames_add () {
    touch "${nginx_conf_dir}"/${serverNames}.serverNames
    cat >"${nginx_conf_dir}"/${serverNames}.serverNames <<EOF
${serverNames} reality;
EOF
    judge "Nginx serverNames $(gettext "配置修改")"

}

nginx_reality_serverNames_del () {
    [[ -f "${nginx_conf_dir}/${serverNames}.serverNames" ]] && rm -f "${nginx_conf_dir}/${serverNames}.serverNames"
    judge "Nginx serverNames $(gettext "配置删除")"

}

nginx_servers_conf_add() {
    touch "${nginx_upstream_conf}"
    > "${nginx_upstream_conf}"
    if is_ws_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-ws-server {
    include ${nginx_conf_dir}/*.wsServers;
}

EOF
    fi
    if is_grpc_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-grpc-server {
    include ${nginx_conf_dir}/*.grpcServers;
}

EOF
    fi
    if is_xhttp_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-xhttp-server {
    include ${nginx_conf_dir}/*.xhttpServers;
}

EOF
    fi
    nginx_servers_add
    judge "Nginx servers $(gettext "配置修改")"
}

enable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl enable nginx
            judge -r "$(gettext "设置 Nginx 开机自启")" || return 1
        fi
    fi
    systemctl enable xray
    judge -r "$(gettext "设置") Xray $(gettext "开机自启")" || return 1
}

disable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl stop nginx && systemctl disable nginx
            judge -r "$(gettext "关闭 Nginx 开机自启")" || return 1
        fi
    fi
    systemctl disable xray
    judge -r "$(gettext "关闭") Xray $(gettext "开机自启")" || return 1
}

stop_service_all() {
    [[ -f "${nginx_systemd_file}" ]] && { systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; }
    systemctl stop xray 2>/dev/null
    systemctl disable xray 2>/dev/null
    if [[ ${tls_mode} != "TLS" ]] && [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
        log_echo "${OK} ${GreenBG} $(gettext "已清理残留的证书自动更新定时任务") ${Font}"
    fi
    log_echo "${OK} ${GreenBG} $(gettext "停止") ${Font}"
}

acme_cron_cleanup() {
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
        log_echo "${OK} ${GreenBG} $(gettext "已清理证书自动更新定时任务") ${Font}"
    fi
}

service_restart() {
    systemctl daemon-reload
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl restart nginx
            if ! judge -r "Nginx $(gettext "重启")"; then
                nginx_diagnose
                return 1
            fi
        fi
    fi
    systemctl restart xray
    if ! judge -r "Xray $(gettext "重启")"; then
        xray_diagnose
        return 1
    fi
}

service_start() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl start nginx
            if ! judge -r "Nginx $(gettext "启动")"; then
                nginx_diagnose
                return 1
            fi
        fi
    fi
    systemctl start xray
    if ! judge -r "Xray $(gettext "启动")"; then
        xray_diagnose
        return 1
    fi
}

service_stop() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl stop nginx
            judge -r "Nginx $(gettext "停止")" || return 1
        fi
    fi
    systemctl stop xray
    judge -r "Xray $(gettext "停止")" || return 1
}

acme_cron_update() {
    if [[ ${tls_mode} == "TLS" ]]; then
        local crontab_file
        if [[ "${ID}" == "centos" ]]; then
            crontab_file="/var/spool/cron/root"
        else
            crontab_file="/var/spool/cron/crontabs/root"
        fi
        if [[ -f "${ssl_update_file}" ]] && [[ $(crontab -l | grep -Fc -- "${ssl_update_file}") == "1" ]]; then
            echo
            log_echo "${Warning} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "老版本请及时删除 废弃的 改版证书自动更新")! ${Font}"
            log_echo "${GreenBG} $(gettext "已设置改版证书自动更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除改版证书自动更新 (请删除)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r remove_acme_cron_update_fq
            case $remove_acme_cron_update_fq in
            [nN][oO] | [nN]) ;;
            *)
                sed -i "\|${ssl_update_file}|d" "${crontab_file}"
                rm -rf "${ssl_update_file}"
                judge -r "$(gettext "删除改版证书自动更新")"
                ;;
            esac
        else
            echo
            log_echo "${OK} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

check_cert_status() {
    if [[ ${tls_mode} == "TLS" ]]; then
        host="$(info_extraction host)"
        if [[ -d "$HOME/.acme.sh/${host}_ecc" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.key" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.cer" ]]; then
            modifyTime=$(stat -c %Y "$HOME/.acme.sh/${host}_ecc/${host}.cer" 2>/dev/null)
            currentTime=$(date +%s)
            ((stampDiff = currentTime - modifyTime))
            ((days = stampDiff / 86400))
            ((remainingDays = 90 - days))
            tlsStatus=${remainingDays}
            [[ ${remainingDays} -le 0 ]] && tlsStatus="${Yellow}$(gettext "已过期")${Font}"
            echo
            log_echo "${Green}$(gettext "证书生成日期"): $(date -d "@${modifyTime}" +"%F %H:%M:%S")${Font}"
            log_echo "${Green}$(gettext "证书生成天数"): ${days}${Font}"
            log_echo "${Green}$(gettext "证书剩余天数"): ${tlsStatus}${Font}"
            echo
            if [[ ${remainingDays} -le 0 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "是否立即更新证书") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r cert_update_manuel_fq
                case $cert_update_manuel_fq in
                [yY][eE][sS] | [yY])
                    systemctl stop xray
                    judge -r "Xray $(gettext "停止")" || return 1
                    cert_update_manuel
                    ;;
                *) ;;
                esac
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发")! ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

cert_update_manuel() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ -f "${amce_sh_file}" ]]; then
            "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
            host="$(info_extraction host)"
            "$HOME"/.acme.sh/acme.sh --installcert -d "${host}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "chown -f root:idleleo-nginx ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && systemctl restart nginx && systemctl restart xray"
            judge -r "$(gettext "证书更新")" || return 1
            # Reuse authoritative layered permission model after cert renewal.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            service_restart || return 1
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发")! ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

set_fail2ban() {
    if ! ensure_sub_script "fail2ban_manager.sh" "${mf_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/fail2ban_manager.sh"
    mf_check_for_updates
    mf_main_menu
}

# CLI entry point for Fail2ban management.
# Reuses the same mf_cli() implementation as the menu — no duplicated logic.
set_fail2ban_cli() {
    if ! ensure_sub_script "fail2ban_manager.sh" "${mf_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/fail2ban_manager.sh"
    mf_cli "$@"
}

set_traffic_blocker() {
    if [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "未安装"), $(gettext "请先安装") Xray ${Font}"
        return 1
    fi
    if ! ensure_sub_script "traffic_blocker.sh" "${tb_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/traffic_blocker.sh"
    tb_check_for_updates
    tb_main_menu
}

setup_auto_clean_logs() {
    local logrotate_config
    echo

    log_echo "${GreenBG} $(gettext "是否需要设置自动清理日志") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r auto_clean_logs_fq
    case $auto_clean_logs_fq in
    [nN][oO] | [nN])
        log_echo "${OK} ${Green} $(gettext "已跳过设置自动清理日志") ${Font}"
        ;;
    *)
        log_echo "${OK} ${Green} $(gettext "将在 每周三 04:00 自动清空日志") ${Font}"

        logrotate_config="/etc/logrotate.d/xray_log_cleanup"

        if [[ -f "$logrotate_config" ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "已设置自动清理日志任务") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除现有自动清理日志任务") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r delete_task
            case $delete_task in
            [yY][eE][sS] | [yY])
                rm -f "$logrotate_config"
                judge -r "$(gettext "删除自动清理日志任务")"
                ;;
            *)
                log_echo "${OK} ${Green} $(gettext "保留现有自动清理日志任务") ${Font}"
                return
                ;;
            esac
        fi

        echo "/var/log/xray/*.log ${nginx_dir}/logs/*.log {" > "$logrotate_config"
        echo "    weekly" >> "$logrotate_config"
        echo "    rotate 3" >> "$logrotate_config"
        echo "    compress" >> "$logrotate_config"
        echo "    missingok" >> "$logrotate_config"
        echo "    notifempty" >> "$logrotate_config"
        local _logrotate_group
        _logrotate_group=$(id -gn nobody 2>/dev/null || echo "nogroup")
        echo "    create 640 nobody ${_logrotate_group}" >> "$logrotate_config"
        echo "}" >> "$logrotate_config"

        judge -r "$(gettext "设置自动清理日志")"
        ;;
    esac
}

clean_logs() {
    echo
    log_echo "${Green} $(gettext "检测到日志文件大小如下:") ${Font}"
    log_echo "${Green}$(du -sh /var/log/xray "${nginx_dir}"/logs 2>/dev/null)${Font}"
    countdown "$(gettext "即将清除")!"
    for i in $(find /var/log/xray/ "${nginx_dir}"/logs -name "*.log" 2>/dev/null); do cat /dev/null >"$i" 2>/dev/null; done
    judge -r "$(gettext "日志清理")" || return 1
    setup_auto_clean_logs
}

# Detect multi-user setup by inspecting the actual Xray config.
# Returns "yes" if any inbound has more than one client, "no" otherwise.
# This is the source of truth for reinstall decisions — install_config.json's
# multi_user field may already have been overwritten by a prior install_config_*.
detect_multi_user_from_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        echo "no"
        return
    fi
    local result
    result=$(jq -r '[.inbounds[].settings.clients | length] | any(. > 1) // false' "${xray_conf}" 2>/dev/null || echo "false")
    if [[ "${result}" == "true" ]]; then
        echo "yes"
    else
        echo "no"
    fi
}

# Count total Reality clients across all inbounds in the actual Xray config.
count_reality_clients_in_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        echo 0
        return
    fi
    jq -r '[.inbounds[] | select(.protocol == "vless") | .settings.clients | length] | add // 0' "${xray_conf}" 2>/dev/null || echo 0
}

# Extract the deduplicated UUID set from all VLESS inbounds in the actual
# Xray config. Returns a sorted, newline-separated list of UUIDs. Used for
# Stable user-identity comparison across reconfigures.
extract_uuid_set_from_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        return
    fi
    jq -r '[.inbounds[] | select(.protocol == "vless") | .settings.clients[]?.id // empty] | unique | sort | .[]' "${xray_conf}" 2>/dev/null
}

# Merge new install_config fields onto the existing file, preserving
# multi_user, reality_clients, and any other top-level extension fields
# the script does not manage (custom routing metadata, third-party tool
# markers, etc.).
# Usage: _install_config_merge_write <new_fields_file>
#   <new_fields_file>: path to a file containing the new-field JSON object.
_install_config_merge_write() {
    local new_fields_file="$1"
    local tmp_file _old_umask original_mode original_uid original_gid

    if [[ -z "${new_fields_file}" || ! -f "${new_fields_file}" ]]; then
        log_echo "${Error} ${RedBG} _install_config_merge_write: $(gettext "参数不能为空") ${Font}"
        return 1
    fi
    if ! jq empty "${new_fields_file}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} _install_config_merge_write: $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
        return 1
    fi

    _old_umask=$(umask)
    umask 077
    tmp_file=$(mktemp "${xray_install_config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${xray_install_config_file}.tmp.$$"

    # Only merge if the existing file contains a valid JSON object. An empty
    # or corrupt file (e.g. left by a failed prior write) is treated as
    # "no existing config" so the new fields become the baseline.
    if [[ -s "${xray_install_config_file}" ]] && jq -e 'type == "object"' "${xray_install_config_file}" >/dev/null 2>&1; then
        original_mode=$(stat -c '%a' "${xray_install_config_file}" 2>/dev/null) || original_mode="600"
        original_uid=$(stat -c '%u' "${xray_install_config_file}" 2>/dev/null) || original_uid="$(id -u)"
        original_gid=$(stat -c '%g' "${xray_install_config_file}" 2>/dev/null) || original_gid="$(id -g)"
        # jq merge: right operand (new fields) wins for overlapping keys;
        # left operand's (old file) unique top-level keys are preserved.
        if ! jq -s '.[0] * .[1]' "${xray_install_config_file}" "${new_fields_file}" > "${tmp_file}" 2>/dev/null; then
            umask "${_old_umask}"
            rm -f "${tmp_file}"
            log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
            return 1
        fi
    else
        original_mode="600"
        original_uid="$(id -u)"
        original_gid="$(id -g)"
        if ! jq -c . "${new_fields_file}" > "${tmp_file}" 2>/dev/null; then
            umask "${_old_umask}"
            rm -f "${tmp_file}"
            log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
            return 1
        fi
    fi

    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
        return 1
    fi
    if ! chmod "${original_mode}" "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${xray_install_config_file} ${Font}"
        return 1
    fi
    chown "${original_uid}:${original_gid}" "${tmp_file}" 2>/dev/null || true
    umask "${_old_umask}"
    if ! mv "${tmp_file}" "${xray_install_config_file}"; then
        rm -f "${tmp_file}"
        return 1
    fi
    info_extraction_all=$(jq -rc . "${xray_install_config_file}" 2>/dev/null) || return 1
    declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    return 0
}

install_config_tls_ws() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${domain}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "tls": "TLS",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "${artnet}",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}",
    "nginx_build_version": "${nginx_build_version:-}"
}
EOF
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

install_config_reality() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "raw",
    "tls": "Reality",
    "target": "${target}",
    "serverNames":"${serverNames}",
    "privateKey":"${privateKey}",
    "publicKey":"${password}",
    "password":"${password}",
    "shortIds":"${shortIds}",
    "spiderx_path":"${spiderx_path}",
    "reality_add_nginx": "${reality_add_nginx}",
    "reality_add_balance": "${reality_add_balance}",
    "reality_balance_role": "${reality_balance_role}",
    "reality_add_more": "${reality_add_more}",
    "reality_nginx_sni_guard": "${reality_nginx_sni_guard}",
    "unknown_sni_policy": "${unknown_sni_policy}",
    "decoy_domain": "${decoy_domain}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "ws_path": "${artpath}",
    "grpc_serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}"
}
EOF
    if [[ ${reality_add_nginx} == "on" ]]; then
        # nginx_build_version is only meaningful when Reality fronted by Nginx.
        jq --arg nginx_build_version "${nginx_build_version}" \
            '. + {"nginx_build_version": $nginx_build_version}' "${_new_fields}" > "${_new_fields}.tmp" 2>/dev/null \
            && mv "${_new_fields}.tmp" "${_new_fields}"
    fi
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

install_config_xtls_only() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "None",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "tls": "XTLS",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "raw",
    "security": "none",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}"
}
EOF
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

install_config_ws_only() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "tls": "None",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "${artnet}",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}"
}
EOF
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

vless_urlquote() {
    [[ $# = 0 ]] && return 1
    python3 -c "import urllib.request,sys;print(urllib.request.quote(sys.argv[1]))" "$1"
}

info_ws_path() {
    local value
    value=$(info_extraction path)
    if [[ -z ${value} || ${value} == "None" ]]; then
        value=$(info_extraction ws_path)
    fi
    echo "${value}"
}

info_grpc_serviceName() {
    local value
    value=$(info_extraction serviceName)
    if [[ -z ${value} || ${value} == "None" ]]; then
        value=$(info_extraction grpc_serviceName)
    fi
    echo "${value}"
}

format_xhttp_path() {
    local raw_path="$1"
    echo "/${raw_path#/}"
}

info_xhttp_path() {
    local value
    value=$(info_extraction xhttp_path)
    echo "${value}"
}

# publicKey 是当前规范名称；password 是 Xray 历史名称，保留以兼容旧配置。
info_reality_public_key() {
    local value
    value=$(info_extraction publicKey)
    [[ -z "${value}" ]] && value=$(info_extraction password)
    echo "${value}"
}

# 修复旧配置缺少公钥的情况：优先迁移旧 password，否则由 privateKey 重新推导。
ensure_reality_public_key() {
    [[ $(info_extraction tls) != "Reality" ]] && return 0
    [[ ! -f "${xray_install_config_file}" ]] && return 1

    local public_key private_key keys
    public_key=$(info_reality_public_key)
    if [[ -z "${public_key}" ]]; then
        private_key=$(info_extraction privateKey)
        if [[ -z "${private_key}" || ! -x "${xray_bin_dir}/xray" ]]; then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        if ! keys=$(${xray_bin_dir}/xray x25519 -i "${private_key}" 2>/dev/null); then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        public_key=$(parse_reality_public_key "${keys}")
        if [[ -z "${public_key}" ]]; then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
    fi

    if [[ $(info_extraction publicKey) != "${public_key}" || $(info_extraction password) != "${public_key}" ]]; then
        update_json_config "${xray_install_config_file}" --arg publicKey "${public_key}" \
           '.publicKey = $publicKey | .password = $publicKey' || return 1
        chmod -f 600 "${xray_install_config_file}" 2>/dev/null
    fi
    return 0
}

reality_client_meta() {
    local user_id="$1"
    local field="$2"
    [[ -z "${user_id}" || -z "${field}" || ! -f "${xray_install_config_file}" ]] && return 0
    jq -r --arg user_id "${user_id}" --arg field "${field}" \
       '.reality_clients[$user_id][$field] // empty' "${xray_install_config_file}" 2>/dev/null
}

generate_vless_link() {
    local user_id="$1"
    local mode="$2"
    local host port quoted_host result

    quoted_host=$(vless_urlquote "$(info_extraction host)")

    case "$mode" in
        ws_tls)
            port=$(info_extraction port)
            local path
            path=$(info_ws_path)
            path=$(vless_urlquote "${path}")
            result="vless://${user_id}@${quoted_host}:${port}?path=%2f${path}%3Fed%3D2048&security=tls&encryption=none&host=${quoted_host}&type=ws&fp=chrome#${quoted_host}+ws%E5%8D%8F%E8%AE%AE"
            ;;
        grpc_tls)
            port=$(info_extraction port)
            local service_name
            service_name=$(info_grpc_serviceName)
            service_name=$(vless_urlquote "${service_name}")
            result="vless://${user_id}@${quoted_host}:${port}?serviceName=${service_name}&security=tls&encryption=none&host=${quoted_host}&type=grpc&fp=chrome#${quoted_host}+gRPC%E5%8D%8F%E8%AE%AE"
            ;;
        xhttp_tls)
            port=$(info_extraction port)
            local xhttp_path
            xhttp_path=$(info_xhttp_path)
            xhttp_path=$(vless_urlquote "$(format_xhttp_path "${xhttp_path}")")
            result="vless://${user_id}@${quoted_host}:${port}?path=${xhttp_path}&mode=auto&security=tls&encryption=none&host=${quoted_host}&type=xhttp&fp=chrome#${quoted_host}+xHTTP%E5%8D%8F%E8%AE%AE"
            ;;
        ws)
            port=$(info_extraction ws_port)
            local path
            path=$(info_ws_path)
            path=$(vless_urlquote "${path}")
            result="vless://${user_id}@${quoted_host}:${port}?path=%2f${path}%3Fed%3D2048&encryption=none&type=ws#${quoted_host}+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
            ;;
        grpc)
            port=$(info_extraction grpc_port)
            local service_name
            service_name=$(info_grpc_serviceName)
            service_name=$(vless_urlquote "${service_name}")
            result="vless://${user_id}@${quoted_host}:${port}?serviceName=${service_name}&encryption=none&type=grpc#${quoted_host}+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
            ;;
        xhttp)
            port=$(info_extraction xhttp_port)
            local xhttp_path
            xhttp_path=$(info_xhttp_path)
            xhttp_path=$(vless_urlquote "$(format_xhttp_path "${xhttp_path}")")
            result="vless://${user_id}@${quoted_host}:${port}?path=${xhttp_path}&mode=auto&security=none&encryption=none&host=${quoted_host}&type=xhttp#${quoted_host}+%E5%8D%95%E7%8B%ADxHTTP%E5%8D%8F%E8%AE%AE"
            ;;
        reality)
            port=$(info_extraction port)
            local pbk sni target sid spx spx_param
            pbk=$(info_reality_public_key)
            sni=$(info_extraction serverNames)
            target=$(info_extraction target)
            sid=$(reality_client_meta "${user_id}" shortIds)
            [[ -z "${sid}" ]] && sid=$(info_extraction shortIds)
            spx=$(reality_client_meta "${user_id}" spiderx_path)
            [[ -z "${spx}" ]] && spx=$(info_extraction spiderx_path)
            # 仅当存在 spiderX 时拼接 spx= 参数，老配置无 spiderX 保持兼容
            if [[ -n "${spx}" ]]; then
                spx_param="&spx=$(vless_urlquote "${spx}")"
            else
                spx_param=""
            fi
            result="vless://${user_id}@${quoted_host}:${port}?security=reality&flow=xtls-rprx-vision&fp=chrome&pbk=${pbk}&sni=${sni}&target=${target}&sid=${sid}${spx_param}#${quoted_host}+Reality%E5%8D%8F%E8%AE%AE"
            ;;
        xtls)
            port=$(info_extraction port)
            result="vless://${user_id}@${quoted_host}:${port}?security=none&encryption=none&headerType=none&type=raw#${quoted_host}+XTLS%E5%8D%8F%E8%AE%AE"
            ;;
        *)
            return 1
            ;;
    esac

    echo "$result"
}

generate_clash_config() {
    local type=$1
    local port=$2
    local path=$3
    local service_name=$4
    local security=$5
    local flow=$6
    local pbk=$7
    local sni=$8
    local target=$9
    local sid=${10}
    local tls=${11}
    local transport_label=${12:-$type}
    local spx=${13:-}

    local clash_name
    clash_name="VLESS-$(info_extraction host)-${transport_label}"
    local clash_config=""
    local flow_line=""
    [[ -n "${flow}" ]] && flow_line="
    flow: ${flow}"

    if [[ ${type} == "ws" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: $(info_extraction host)
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: ws
    ws-opts:
      path: ${path}
      headers:
        Host: $(info_extraction host)
    skip-cert-verify: false"

    elif [[ ${type} == "grpc" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: $(info_extraction host)
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: grpc
    grpc-opts:
      grpc-service-name: ${service_name}
    skip-cert-verify: false"

    elif [[ ${type} == "tcp" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: $(info_extraction host)
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: tcp
    skip-cert-verify: false"

    elif [[ ${type} == "xhttp" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: $(info_extraction host)
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: xhttp
    xhttp-opts:
      path: ${path}
      mode: auto
    skip-cert-verify: false"
    fi

    if [[ ${tls} == "true" && -n "${sni}" ]]; then
        clash_config="${clash_config}
    servername: ${sni}"
    fi

    if [[ ${security} == "reality" ]]; then
        clash_config="${clash_config}
    reality-opts:
      public-key: ${pbk}
      short-id: ${sid}"
        if [[ -n "${spx}" ]]; then
            clash_config="${clash_config}
      spider-x: ${spx}"
        fi
    fi

    echo ""
    echo "${clash_config}"
}

install_link_image() {
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_public_key || return 1
    fi
    local main_id
    main_id=$(info_extraction id)

    if [[ ${tls_mode} == "TLS" ]]; then
        is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws_tls")
        is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc_tls")
        is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp_tls")
    elif [[ ${tls_mode} == "Reality" ]]; then
        vless_link=$(generate_vless_link "$main_id" "reality")
        if [[ ${reality_add_more} == "on" ]]; then
            is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws")
            is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc")
            is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp")
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws")
        is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc")
        is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp")
    elif [[ ${tls_mode} == "XTLS" ]]; then
        vless_link=$(generate_vless_link "$main_id" "xtls")
    fi

    clash_config_content="proxies:"

    if [[ ${tls_mode} == "TLS" ]]; then
        if is_ws_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction port)" "/$(info_ws_path)" "" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
        if is_grpc_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction port)" "" "$(info_grpc_serviceName)" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
        if is_xhttp_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "reality" "xtls-rprx-vision" "$(info_reality_public_key)" "$(info_extraction serverNames)" "$(info_extraction target)" "$(info_extraction shortIds)" "true" "tcp" "$(info_extraction spiderx_path)")"

        if [[ ${reality_add_more} == "on" ]]; then
            if is_ws_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false")"
            fi
            if is_grpc_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false")"
            fi
            if is_xhttp_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false")"
            fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if is_ws_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false")"
        fi
        if is_grpc_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false")"
        fi
        if is_xhttp_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false")"
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
        clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "none" "" "" "" "" "" "false")"
    fi
    
    {
        echo
        log_echo "${Red} —————————————— Xray $(gettext "链接分享") —————————————— ${Font}"
        if [[ ${tls_mode} == "Reality" ]] || [[ ${tls_mode} == "XTLS" ]]; then
            log_echo_secure "${Red} URL $(gettext "分享链接"):${Font} ${vless_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_ws_mode && [[ -n "${vless_ws_link}" ]]; then
            log_echo_secure "${Red} ws URL $(gettext "分享链接"):${Font} ${vless_ws_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_grpc_mode && [[ -n "${vless_grpc_link}" ]]; then
            log_echo_secure "${Red} gRPC URL $(gettext "分享链接"):${Font} ${vless_grpc_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_xhttp_mode && [[ -n "${vless_xhttp_link}" ]]; then
            log_echo_secure "${Red} xHTTP URL $(gettext "分享链接"):${Font} ${vless_xhttp_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_xhttp_link}" | qrencode -o - -t utf8
            echo
        fi
        
        # 输出Clash配置
        log_echo "${Red} —————————————— Clash $(gettext "配置分享") —————————————— ${Font}"
        log_echo "${Red} Clash $(gettext "配置分享"): ${Font}"
        echo "${clash_config_content}"
        echo
        # 添加结束线
        log_echo "${Red} ——————————————————  END  —————————————————— ${Font}"
        echo
    } >>"${xray_info_file}"
    
    # 保存Clash配置到文件
    echo "${clash_config_content}" > "${xray_info_file%.*}_clash.yaml"
    apply_sensitive_file_permissions "${xray_info_file%.*}_clash.yaml" "root:root" || true
}

vless_link_image_choice() {
    echo
    log_echo "${GreenBG} $(gettext "生成分享链接"): ${Font}"
    install_link_image
}

declare -A _info_cache=()
_info_cache_loaded=0

_info_cache_invalidate() {
    declare -gA _info_cache=()
    _info_cache_loaded=0
}

_info_cache_load() {
    if [[ ${_info_cache_loaded} -eq 0 ]] && [[ -n "${info_extraction_all:-}" ]]; then
        while IFS=$'\t' read -r key value; do
            _info_cache["$key"]="$value"
        done < <(echo "${info_extraction_all}" | jq -r 'to_entries | .[] | [.key, .value // ""] | @tsv' 2>/dev/null)
        _info_cache_loaded=1
    fi
}

info_extraction() {
    if [[ ${_info_cache_loaded} -eq 0 ]]; then
        _info_cache_load
    fi
    if [[ -n "${_info_cache[$1]+x}" ]]; then
        echo "${_info_cache[$1]}"
    else
        local result
        result=$(echo "${info_extraction_all:-}" | jq -r ".$1 // empty" 2>/dev/null)
        local jq_exit_code=$?
        echo "$result"
        if [[ $jq_exit_code -ne 0 ]]; then
            read_config_status=0
        fi
    fi
}

install_iftop() {
    if ! command -v iftop &>/dev/null; then
        log_echo "${Info} ${Green} $(gettext "正在安装") iftop... ${Font}"
        check_system
        pkg_install "iftop"
    else
        log_echo "${OK} ${GreenBG} $(gettext "已安装") iftop ${Font}"
    fi
}

monitor_traffic_with_iftop() {
    if [[ ! -f "${xray_install_config_file}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        exit 1
    fi

    install_iftop

    local port
    local interface

    port=$(info_extraction port)
    if [[ -z "${port}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        exit 1
    fi

    interface=$(ip route show | awk '/default/ {print $5; exit}')
    if [[ -z "${interface}" ]]; then
        interface="any"
        log_echo "${Warning} ${YellowBG} $(gettext "无法获取网卡, 将监控所有网卡") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "监控网卡"): ${interface} ${Font}"
    fi

    log_echo "${OK} ${GreenBG} $(gettext "监控端口"): ${port} ${Font}"
    echo
    log_echo "${Info} ${Green} $(gettext "按 q 键退出 iftop") ${Font}"
    countdown "$(gettext "启动") iftop"
    sleep 3

    if [[ "${interface}" == "any" ]]; then
        iftop -i any -n -f "port ${port}"
    else
        iftop -i "${interface}" -n -f "port ${port}"
    fi
}

basic_information() {
    ensure_reality_public_key || true
    {
        echo
        log_echo "${OK} ${GreenBG} Xray+${shell_mode} $(gettext "安装") $(gettext "完成") ${Font}"
        echo
        log_echo "${Warning} ${YellowBG} VLESS $(gettext "目前分享链接规范为实验阶段, 请自行判断是否适用") ${Font}"
        if is_xhttp_mode; then
            log_echo "${Warning} ${YellowBG} $(gettext "当前 xHTTP 仅支持 stream-one 和 stream-up 模式") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "xHTTP 需要 mihomo (Meta) 内核, 原版 Clash 不支持") ${Font}"
        fi
        echo
        log_echo "${Red} —————————————— Xray $(gettext "配置信息") —————————————— ${Font}"
        log_echo "${Red} $(gettext "主机") (host):${Font} $(info_extraction host) "
        if [[ ${tls_mode} == "None" ]]; then
            if is_ws_mode; then
                log_echo "${Red} ws $(gettext "端口") (port):${Font} $(info_extraction ws_port) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} gRPC $(gettext "端口") (port):${Font} $(info_extraction grpc_port) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} xHTTP $(gettext "端口") (port):${Font} $(info_extraction xhttp_port) "
            fi
        else
            log_echo "${Red} $(gettext "端口") (port):${Font} $(info_extraction port) "
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if is_ws_mode; then
                log_echo "${Red} Xray ws $(gettext "端口") (inbound_port):${Font} $(info_extraction ws_port) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} Xray gRPC $(gettext "端口") (inbound_port):${Font} $(info_extraction grpc_port) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} Xray xHTTP $(gettext "端口") (inbound_port):${Font} $(info_extraction xhttp_port) "
            fi
        fi
        log_echo "${Red} UUIDv5 $(gettext "映射字符串"):${Font} $(info_extraction idc)"
        log_echo_secure "${Red} $(gettext "用户id") (UUID):${Font} $(info_extraction id)"

        log_echo "${Red} $(gettext "加密") (encryption):${Font} None "
        log_echo "${Red} $(gettext "传输协议") (network):${Font} $(info_extraction net) "
        log_echo "${Red} $(gettext "底层传输安全") (tls):${Font} $(info_extraction tls) "
        if [[ ${tls_mode} != "Reality" && ${tls_mode} != "XTLS" ]]; then
            if is_ws_mode; then
                log_echo "${Red} $(gettext "路径") (path $(gettext "不要落下")/):${Font} /$(info_ws_path) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} serviceName ($(gettext "不需要加")/):${Font} $(info_grpc_serviceName) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} xHTTP $(gettext "路径") (path $(gettext "不要落下")/):${Font} $(format_xhttp_path "$(info_xhttp_path)") "
            fi
        else
            if [[ ${tls_mode} == "Reality" ]]; then
                log_echo "${Red} $(gettext "流控") (flow):${Font} xtls-rprx-vision "
                log_echo "${Red} target:${Font} $(info_extraction target) "
                log_echo "${Red} serverNames:${Font} $(info_extraction serverNames) "
                log_echo_secure "${Red} privateKey:${Font} $(info_extraction privateKey) "
                log_echo_secure "${Red} publicKey (Password):${Font} $(info_reality_public_key) "
                log_echo_secure "${Red} shortIds:${Font} $(info_extraction shortIds) "
                if [[ -n "$(info_extraction spiderx_path)" ]]; then
                    log_echo "${Red} spiderX:${Font} $(info_extraction spiderx_path) "
                fi
                if [[ "$reality_add_more" == "on" ]]; then
                    if is_ws_mode; then
                        log_echo "${Red} ws $(gettext "端口") (port):${Font} $(info_extraction ws_port) "
                        log_echo "${Red} ws $(gettext "路径") ($(gettext "不要落下")/):${Font} /$(info_ws_path) "
                    fi
                    if is_grpc_mode; then
                        log_echo "${Red} gRPC $(gettext "端口") (port):${Font} $(info_extraction grpc_port) "
                        log_echo "${Red} gRPC serviceName ($(gettext "不需要加")/):${Font} $(info_grpc_serviceName) "
                    fi
                    if is_xhttp_mode; then
                        log_echo "${Red} xHTTP $(gettext "端口") (port):${Font} $(info_extraction xhttp_port) "
                        log_echo "${Red} xHTTP $(gettext "路径") (path $(gettext "不要落下")/):${Font} $(format_xhttp_path "$(info_xhttp_path)") "
                    fi
                fi
            fi
        fi
    } >"${xray_info_file}"
        chmod -f 600 "${xray_info_file}" 2>/dev/null
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    cd $HOME
    echo
    local has_cert_files="false"
    local has_acme_files="false"

    [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] && has_cert_files="true"
    [[ -f "$HOME/.acme.sh/acme.sh" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] && has_acme_files="true"

    if [[ ${has_cert_files} != "true" && ${has_acme_files} != "true" ]]; then
        log_echo "${GreenBG} $(gettext "即将申请证书, 支持使用自定义证书") ${Font}"
        log_echo "${Green} $(gettext "如需使用自定义证书, 请按如下步骤:") ${Font}"
        log_echo " $(gettext "1. 将证书文件重命名: 私钥(xray.key)、证书(xray.crt)")"
        log_echo " $(gettext "2. 将重命名后的证书文件放入") ${ssl_chainpath} $(gettext "目录后再运行脚本")"
        log_echo " $(gettext "3. 重新运行脚本")"
        log_echo "${GreenBG} $(gettext "是否继续") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r ssl_continue
        case $ssl_continue in
        [nN][oO] | [nN])
            return 1
            ;;
        esac
    fi

    if [[ ${has_cert_files} == "true" ]]; then
        if [[ ${has_acme_files} == "true" ]]; then
            log_echo "${GreenBG} $(gettext "所有证书文件均已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        else
            log_echo "${GreenBG} $(gettext "证书文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        fi
        read -r ssl_delete_choice
        case $ssl_delete_choice in
        [nN][oO] | [nN])
            [[ ${has_acme_files} == "true" ]] && delete_tls_key_and_crt
            rm -rf "${ssl_chainpath}"/*
            log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
            ssl_install
            acme
            ;;
        *)
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            judge "$(gettext "证书应用")"
            ;;
        esac
    elif [[ ${has_acme_files} == "true" ]]; then
        log_echo "${GreenBG} $(gettext "证书签发残留文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r ssl_delete_3
        case $ssl_delete_3 in
        [nN][oO] | [nN])
            delete_tls_key_and_crt
            log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
            ssl_install
            acme
            ;;
        *)
            "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "chown -f root:idleleo-nginx ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && systemctl restart nginx && systemctl restart xray"
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            judge "$(gettext "证书应用")"
            ;;
        esac
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >"${nginx_systemd_file}" <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=${nginx_dir}/logs/nginx.pid
ExecStartPre=${nginx_dir}/sbin/nginx -t
ExecStart=${nginx_dir}/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=${nginx_dir}/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge -r "Nginx systemd ServerFile $(gettext "添加")" || return 1
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "${nginx_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            while true; do
                echo
                log_echo "${GreenBG} $(gettext "请选择支持的 TLS 版本") (default:2): ${Font}"
                log_echo "${GreenBG} $(gettext "建议选择 TLSv1.3 only (安全模式)") ${Font}"
                echo -e "1: TLSv1.2 and TLSv1.3 ($(gettext "兼容模式"))"
                echo -e "${Red}2${Font}: TLSv1.3 only ($(gettext "安全模式"))"
                local choose_tls
                read_optimize "$(gettext "请输入"): " "choose_tls" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                if [[ ${choose_tls} == 1 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "由于 h3 仅支持 TLSv1.3, 此处只支持 TLSv1.3 only (安全模式)")! ${Font}"
                else
                    sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
                    log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.3 only ${Font}"
                    break
                fi
            done
        elif [[ ${tls_mode} == "Reality" && ${reality_add_nginx} == "on" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "请选择 TLS 版本") (default:1): ${Font}"
            log_echo "${GreenBG} $(gettext "建议选择 TLSv1.3 (安全模式)") ${Font}"
            echo -e "${Red}1${Font}: TLSv1.3 ($(gettext "默认"))"
            echo -e "2: TLSv1.2+ ($(gettext "兼容模式"))"
            local tls_version_choice
            read_optimize "$(gettext "请输入"): " "tls_version_choice" 1 1 2 "$(gettext "请输入有效的数字")!" || return 1
            if [[ ${tls_version_choice} == 2 ]]; then
                sed -i "s/^\( *\)#TLSv1.2\( *\)1;\( *\)$/\1TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.2+ ${Font}"
            else
                sed -i "s/^\( *\)TLSv1.2\( *\)1;\( *\)$/\1#TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.3 ${Font}"
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作") ${Font}"
            return 1
        fi
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl restart nginx
            judge -r "Nginx $(gettext "重启")" || return 1
        fi
        systemctl restart xray
        judge -r "Xray $(gettext "重启")" || return 1
        return 0
    else
        log_echo "${Error} ${RedBG} $(gettext "Nginx 配置文件不存在或当前模式不支持") ${Font}"
        return 1
    fi
}

reset_install_config() {
    [[ -f "${xray_install_config_file}" ]] && info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    _info_cache_invalidate
    basic_information
    install_link_image
    show_information
}

reset_UUID() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        old_config_status="off"
        UUID_set
        old_config_status="${_saved_old_config_status}"
        modify_UUID
        update_json_config "${xray_install_config_file}" --arg uuid "${UUID}" \
           --arg uuid5_char "${UUID5_char}" \
           '.id = $uuid | .idc = $uuid5_char'
        service_restart || return 1
        reset_install_config
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

reset_port() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        local old_ports_json new_ports_json
        # Snapshot current port values so we can restore them on any failure.
        local _old_port="${port:-}"
        local _old_xport="${xport:-}"
        local _old_gport="${gport:-}"
        local _old_xhttpport="${xhttpport:-}"
        local _rollback_config_file=""
        local _rollback_xray_conf=""
        old_config_status="off"
        old_ports_json=$(cat "${managed_ports_file}" 2>/dev/null || echo '{"tcp":[],"udp":[]}')

        # ----- Phase 1: collect input only (no config writes) -----
        if [[ ${tls_mode} == "TLS" ]]; then
            port_set || { _reset_port_restore; return 1; }
        elif [[ ${tls_mode} == "Reality" ]]; then
            port_set || { _reset_port_restore; return 1; }
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
        elif [[ ${tls_mode} == "None" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
        elif [[ ${tls_mode} == "XTLS" ]]; then
            port_set || { _reset_port_restore; return 1; }
            log_echo "${Green} $(gettext "端口"): ${port} ${Font}"
        fi

        # ----- Phase 2: validate (no config writes yet) -----
        collect_new_managed_ports
        validate_active_ports || { _reset_port_restore; return 1; }
        if [[ -n "${port:-}" && "${port}" != "None" ]]; then
            port_exist_check "${port}" || { _reset_port_restore; return 1; }
        fi
        if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
            port_exist_check "${xport}" || { _reset_port_restore; return 1; }
        fi
        if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
            port_exist_check "${gport}" || { _reset_port_restore; return 1; }
        fi
        if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
            port_exist_check "${xhttpport}" || { _reset_port_restore; return 1; }
        fi

        # ----- Phase 3: snapshot configs for rollback, then write -----
        _rollback_config_file=$(mktemp)
        _rollback_xray_conf=$(mktemp)
        _rollback_managed_ports=$(mktemp)
        cp "${xray_install_config_file}" "${_rollback_config_file}" 2>/dev/null || true
        cp "${xray_conf}" "${_rollback_xray_conf}" 2>/dev/null || true
        cp "${managed_ports_file}" "${_rollback_managed_ports}" 2>/dev/null || true

        if [[ ${tls_mode} == "TLS" ]]; then
            modify_nginx_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            update_json_config "${xray_install_config_file}" --argjson port "${port:-0}" '.port = $port' || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        elif [[ ${tls_mode} == "Reality" ]]; then
            local port_update_expr='.port = $port'
            if is_ws_mode; then
                port_update_expr="${port_update_expr} | .ws_port = \$ws_port"
            fi
            if is_grpc_mode; then
                port_update_expr="${port_update_expr} | .grpc_port = \$grpc_port"
            fi
            if is_xhttp_mode; then
                port_update_expr="${port_update_expr} | .xhttp_port = \$xhttp_port"
            fi
            update_json_config "${xray_install_config_file}" --argjson port "${port:-0}" \
               --argjson ws_port "${xport:-0}" \
               --argjson grpc_port "${gport:-0}" \
               --argjson xhttp_port "${xhttpport:-0}" \
               "${port_update_expr}" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            modify_inbound_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            if [[ ${reality_add_nginx} == "on" ]]; then
                modify_nginx_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            fi
        elif [[ ${tls_mode} == "None" ]]; then
            local none_port_update=""
            if is_ws_mode; then
                none_port_update="${none_port_update} | .ws_port = \$ws_port"
            fi
            if is_grpc_mode; then
                none_port_update="${none_port_update} | .grpc_port = \$grpc_port"
            fi
            if is_xhttp_mode; then
                none_port_update="${none_port_update} | .xhttp_port = \$xhttp_port"
            fi
            if [[ -n "${none_port_update}" ]]; then
                update_json_config "${xray_install_config_file}" --argjson ws_port "${xport:-0}" \
                   --argjson grpc_port "${gport:-0}" \
                   --argjson xhttp_port "${xhttpport:-0}" \
                   "${none_port_update# | }" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            fi
            modify_inbound_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        elif [[ ${tls_mode} == "XTLS" ]]; then
            update_json_config "${xray_install_config_file}" --argjson port "${port:-0}" '.port = $port' || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            modify_inbound_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        fi

        # ----- Phase 4: apply runtime + firewall -----
        if ! service_restart; then
            _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
            return 1
        fi
        if ! reconcile_managed_firewall "${old_ports_json}" "${new_ports_json}"; then
            _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
            service_restart >/dev/null 2>&1 || true
            return 1
        fi
        atomic_write_managed_ports "${new_ports_json}" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        rm -f "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
        reset_install_config
        old_config_status="${_saved_old_config_status}"
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

# Helper: restore port variables on validation failure (no config was written).
_reset_port_restore() {
    port="${_old_port:-}"
    xport="${_old_xport:-}"
    gport="${_old_gport:-}"
    xhttpport="${_old_xhttpport:-}"
    old_config_status="${_saved_old_config_status:-}"
}

# Helper: restore config files, firewall rules, managed_ports.json, AND port
# variables on write/apply failure. This treats config + firewall as one
# transaction: if any step fails, both are rolled back.
_reset_port_rollback() {
    local rb_config="$1"
    local rb_xray="$2"
    local rb_managed_ports="${3:-}"
    # Restore config files
    [[ -f "${rb_config}" ]] && cp "${rb_config}" "${xray_install_config_file}" 2>/dev/null || true
    [[ -f "${rb_xray}" ]] && cp "${rb_xray}" "${xray_conf}" 2>/dev/null || true
    # Restore managed_ports.json from snapshot
    if [[ -n "${rb_managed_ports}" && -f "${rb_managed_ports}" ]]; then
        cp "${rb_managed_ports}" "${managed_ports_file}" 2>/dev/null || true
    fi
    # Best-effort firewall rollback: reverse the reconciliation to undo any
    # partial firewall changes. Best-effort means we log but don't fail if
    # rollback itself encounters errors (the config is already restored).
    if [[ -n "${new_ports_json:-}" && -n "${old_ports_json:-}" ]]; then
        reconcile_managed_firewall "${new_ports_json}" "${old_ports_json}" 2>/dev/null || true
    fi
    rm -f "${rb_config}" "${rb_xray}" "${rb_managed_ports}"
    port="${_old_port:-}"
    xport="${_old_xport:-}"
    gport="${_old_gport:-}"
    xhttpport="${_old_xhttpport:-}"
    old_config_status="${_saved_old_config_status:-}"
}

reset_target() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} == "Reality" ]]; then
        target_reset=1
        serverNames=$(info_extraction serverNames)
        nginx_reality_serverNames_del
        target_set
        serverNames_set
        modify_target_serverNames
        if [[ ${reality_add_nginx} == "on" ]]; then
            nginx_reality_serverNames_add
        fi
        update_json_config "${xray_install_config_file}" --arg target "${target}" \
           --arg serverNames "${serverNames}" \
           '.target = $target | .serverNames = $serverNames'
        service_restart || return 1
        reset_install_config
        return 0
    elif [[ ${tls_mode} != "Reality" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持修改") target ! ${Font}"
        return 1
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

show_user() {
    if [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持查看用户")! ${Font}"
        return
    fi
    if [[ ! -f "${xray_install_config_file}" ]] || [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return
    fi
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_public_key || return 1
    fi

    local choose_user_prot show_user_index user_email user_id user_vless_link show_user_continue

    while true; do
        user_email=""
        user_id=""
        echo
        log_echo "${GreenBG} $(gettext "即将显示用户, 一次仅能显示一个") ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                choose_user_tag="VLESS-ws-in"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                choose_user_tag="VLESS-gRPC-in"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                choose_user_tag="VLESS-xhttp-in"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                log_echo "${GreenBG} $(gettext "请选择显示用户使用的协议") ws/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                else
                    choose_user_tag="VLESS-ws-in"
                fi
            else
                log_echo "${GreenBG} $(gettext "请选择显示用户使用的协议") ws/gRPC/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: gRPC"
                echo "3: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 1 ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                else
                    choose_user_tag="VLESS-xhttp-in"
                fi
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_tag="VLESS-Reality-in"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            choose_user_tag="VLESS-XTLS-in"
        fi
        echo
        log_echo "${GreenBG} $(gettext "请选择要显示的用户编号"): ${Font}"
        jq -r -c --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients[].email' "${xray_conf}" | awk '{print NR""": "$0}'
        read_optimize "$(gettext "请输入"): " "show_user_index" "NULL"
        if [[ ${show_user_index} == 1 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "请直接在主菜单选择 [查看 Xray 配置信息] 显示主用户") ${Font}"
            echo
        elif [[ ${show_user_index} -gt 1 ]] && [[ $(jq -r --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients|length' "${xray_conf}") -ge ${show_user_index} ]]; then
            local idx=$((show_user_index - 1))
            user_email=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${idx}" '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].email' "${xray_conf}")
            user_id=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${idx}" '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].id' "${xray_conf}")
        else
            log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
            continue
        fi
        if [[ -n ${user_email} ]] && [[ -n ${user_id} ]]; then
            log_echo "${Green} $(gettext "用户名"): ${user_email} ${Font}"
            log_echo_secure "${Green} UUID: ${user_id} ${Font}"
            if [[ ${tls_mode} == "TLS" ]]; then
                if [[ ${choose_user_tag} == "VLESS-ws-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "ws_tls")
                elif [[ ${choose_user_tag} == "VLESS-gRPC-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "grpc_tls")
                elif [[ ${choose_user_tag} == "VLESS-xhttp-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "xhttp_tls")
                fi
            elif [[ ${tls_mode} == "Reality" ]]; then
                user_vless_link=$(generate_vless_link "$user_id" "reality")
            elif [[ ${tls_mode} == "XTLS" ]]; then
                user_vless_link=$(generate_vless_link "$user_id" "xtls")
            fi
            log_echo_secure "${Red} URL $(gettext "分享链接"):${Font} ${user_vless_link}"
            echo -n "${user_vless_link}" | qrencode -o - -t utf8
        fi
        echo
        log_echo "${GreenBG} $(gettext "是否继续显示用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r show_user_continue
        case $show_user_continue in
        [yY][eE][sS] | [yY])
            ;;
        *)
            break
            ;;
        esac
    done
}

add_user() {
    local choose_user_prot reality_user_more
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local add_user_continue
        while true; do
            echo
            log_echo "${GreenBG} $(gettext "即将添加用户, 一次仅能添加一个") ${Font}"
            local new_reality_short_id="" new_reality_spiderx=""
            if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "None" ]]; then
                if [[ ${transport_mode} == "onlyws" ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${transport_mode} == "onlygRPC" ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                elif [[ ${transport_mode} == "wsxhttp" ]]; then
                    log_echo "${GreenBG} $(gettext "请选择添加用户使用的协议") ws/xHTTP ${Font}"
                    echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                    echo "2: xHTTP"
                    read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                    if [[ ${choose_user_prot} -eq 2 ]]; then
                        choose_user_tag="VLESS-xhttp-in"
                    else
                        choose_user_tag="VLESS-ws-in"
                    fi
                else
                    log_echo "${GreenBG} $(gettext "请选择添加用户使用的协议") ws/gRPC/xHTTP ${Font}"
                    echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                    echo "2: gRPC"
                    echo "3: xHTTP"
                    read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                    if [[ ${choose_user_prot} -eq 1 ]]; then
                        choose_user_tag="VLESS-ws-in"
                    elif [[ ${choose_user_prot} -eq 2 ]]; then
                        choose_user_tag="VLESS-gRPC-in"
                    else
                        choose_user_tag="VLESS-xhttp-in"
                    fi
                fi
                reality_user_more="{}"
            elif [[ ${tls_mode} == "Reality" ]]; then
                choose_user_tag="VLESS-Reality-in"
                reality_user_more='{"flow":"xtls-rprx-vision"}'
                new_reality_short_id=$(generate_reality_short_id)
                new_reality_spiderx=$(generate_spiderx)
            elif [[ ${tls_mode} == "XTLS" ]]; then
                choose_user_tag="VLESS-XTLS-in"
                reality_user_more='{}'
            fi
            email_set
            local existing_emails
            existing_emails=$(jq -r --arg tag "${choose_user_tag}" \
                '.inbounds[] | select(.tag == $tag) | .settings.clients[].email' \
                "${xray_conf}" 2>/dev/null)
            if echo "${existing_emails}" | grep -qFx "${custom_email}"; then
                log_echo "${Error} ${RedBG} $(gettext "该用户名已存在, 请使用不同的用户名")! ${Font}"
                continue
            fi
            UUID_set
            update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" \
               --arg UUID "${UUID}" \
               --argjson reality_user_more "${reality_user_more}" \
               --arg custom_email "${custom_email}" \
               '(.inbounds[] | select(.tag == $choose_user_tag)).settings.clients += [
                   {"id": $UUID} +
                   ($reality_user_more // {}) +
                   {"level": 0, "email": $custom_email}
               ]'
            judge -r "$(gettext "添加用户")" || return 1
            if [[ ${tls_mode} == "Reality" ]]; then
                update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --arg shortId "${new_reality_short_id}" \
                   '(.inbounds[] | select(.tag == $choose_user_tag) | .streamSettings.realitySettings.shortIds) |= (((. // []) + [$shortId]) | unique)' || return 1
                update_json_config "${xray_install_config_file}" --arg uuid "${UUID}" \
                   --arg shortId "${new_reality_short_id}" \
                   --arg spx "${new_reality_spiderx}" \
                   '.multi_user = "yes" |
                    .reality_clients = (.reality_clients // {}) |
                    .reality_clients[$uuid] = {"shortIds": $shortId, "spiderx_path": $spx}' || return 1
                log_echo_secure "${Green} $(gettext "已为当前客户端生成独立 shortId。") ${Font}"
                log_echo "${Green} spiderX: ${new_reality_spiderx} ${Font}"
            else
                update_json_config "${xray_install_config_file}" ". += {\"multi_user\": \"yes\"}"
            fi
            echo
            log_echo "${GreenBG} $(gettext "是否继续添加用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r add_user_continue
            case $add_user_continue in
            [yY][eE][sS] | [yY])
                continue
                ;;
            *)
                break
                ;;
            esac
        done
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

remove_user() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local choose_user_prot
        if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "None" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                choose_user_tag="VLESS-ws-in"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                choose_user_tag="VLESS-gRPC-in"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                choose_user_tag="VLESS-xhttp-in"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                log_echo "${GreenBG} $(gettext "请选择删除用户使用的协议") ws/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                else
                    choose_user_tag="VLESS-ws-in"
                fi
            else
                log_echo "${GreenBG} $(gettext "请选择删除用户使用的协议") ws/gRPC/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: gRPC"
                echo "3: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 1 ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                else
                    choose_user_tag="VLESS-xhttp-in"
                fi
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_tag="VLESS-Reality-in"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            choose_user_tag="VLESS-XTLS-in"
        fi
        local del_user_index
        local remove_user_continue
        while true; do
            echo
            log_echo "${GreenBG} $(gettext "即将删除用户, 一次仅能删除一个") ${Font}"
            log_echo "${GreenBG} $(gettext "请选择要删除的用户编号") ${Font}"
            jq -r -c --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients[].email' "${xray_conf}" | awk '{print NR""": "$0}'
            read_optimize "$(gettext "请输入"): " "del_user_index" "NULL"
            if [[ -z "${del_user_index}" ]] || [[ -n $(echo "${del_user_index}" | sed 's/[0-9]//g') ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ ${del_user_index} == 0 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ $(jq -r --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients|length' "${xray_conf}") -lt ${del_user_index} ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ ${del_user_index} == 1 ]]; then
                echo
                log_echo "${Error} ${RedBG} $(gettext "主用户无法删除")! ${Font}"
                echo
                continue
            elif [[ ${del_user_index} -gt 1 ]]; then
                del_user_index=$((del_user_index - 1))
                local removed_user_id="" removed_short_id=""
                if [[ ${tls_mode} == "Reality" ]]; then
                    removed_user_id=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${del_user_index}" \
                        '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].id // empty' "${xray_conf}")
                    removed_short_id=$(reality_client_meta "${removed_user_id}" shortIds)
                fi
                update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --argjson del_user_index "${del_user_index}" \
                   'del((.inbounds[] | select(.tag == $choose_user_tag)).settings.clients[$del_user_index])'
                judge -r "$(gettext "删除用户")" || return 1
                if [[ ${tls_mode} == "Reality" ]]; then
                    if [[ -n "${removed_short_id}" ]]; then
                        update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --arg shortId "${removed_short_id}" \
                           '(.inbounds[] | select(.tag == $choose_user_tag) | .streamSettings.realitySettings.shortIds) |= map(select(. != $shortId))' || return 1
                    fi
                    if [[ -n "${removed_user_id}" ]]; then
                        update_json_config "${xray_install_config_file}" --arg uuid "${removed_user_id}" 'del(.reality_clients[$uuid])' || return 1
                    fi
                fi
                local remaining_multi_user
                remaining_multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}" 2>/dev/null)
                if [[ "${remaining_multi_user}" != "true" ]]; then
                    update_json_config "${xray_install_config_file}" 'del(.multi_user) | del(.reality_clients)'
                fi
            fi
            echo
            log_echo "${GreenBG} $(gettext "是否继续删除用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r remove_user_continue
            case $remove_user_continue in
            [yY][eE][sS] | [yY])
                continue
                ;;
            *)
                break
                ;;
            esac
        done
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

show_access_log() {
    [[ -f "${xray_access_log}" ]] && tail -f ${xray_access_log} || log_echo "${Error} ${RedBG} log $(gettext "文件不存在")! ${Font}"
}

show_error_log() {
    [[ -f "${xray_error_log}" ]] && tail -f ${xray_error_log} || log_echo "${Error} ${RedBG} log $(gettext "文件不存在")! ${Font}"
}

xray_status_add() {
    if [[ -f "${xray_conf}" ]]; then
        if [[ $(jq -r .stats "${xray_conf}") != "null" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "已配置 Xray 流量统计") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要关闭此功能") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop || return 1
                update_json_config "${xray_conf}" "del(.api)|del(.stats)|del(.policy)"
                if ! judge -r "$(gettext "关闭 Xray 流量统计")"; then
                    service_start
                    return 1
                fi
                service_start || return 1
                [[ -f "${xray_status_conf}" ]] && rm -rf "${xray_status_conf}"
                ;;
            *) ;;
            esac
        else
            echo
            log_echo "${GreenBG} Xray $(gettext "流量统计需要使用") api ${Font}"
            log_echo "${GreenBG} $(gettext "可能会影响 Xray 性能") ${Font}"
            log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop || return 1
                if ! judge -r "$(gettext "下载流量统计配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/config/status_config.json" "${xray_status_conf}"; then
                    service_start
                    return 1
                fi
                local status_config
                if ! status_config=$(jq -c . "${xray_status_conf}"); then
                    log_echo "${Error} ${RedBG} $(gettext "流量统计配置解析失败") ${Font}"
                    service_start
                    return 1
                fi
                update_json_config "${xray_conf}" --argjson status_config "${status_config}" \
                    '. += $status_config'
                if ! judge -r "$(gettext "设置 Xray 流量统计")"; then
                    service_start
                    return 1
                fi
                service_start || return 1
                ;;
            *) ;;
            esac
        fi
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

bbr_boost_sh() {
    read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
    if [[ -f "${scripts_dir}/tcp.sh" ]]; then
        cd "${scripts_dir}" && chmod +x ./tcp.sh && ./tcp.sh
    else
        if download_script_file "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" "${scripts_dir}/tcp.sh"; then
            "${scripts_dir}/tcp.sh"
        else
            log_echo "${Error} ${RedBG} TCP $(gettext "加速脚本下载失败") ${Font}"
            return 1
        fi
    fi
    read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
}

uninstall_xray() {
    systemctl disable xray
    xray_install_release remove --purge
    [[ -d "${xray_conf_dir}" ]] && safe_rm "${xray_conf_dir}"
    if [[ -f "${xray_install_config_file}" ]]; then
        update_json_config "${xray_install_config_file}" -r 'del(.xray_version)'
    fi
    log_echo "${OK} ${GreenBG} $(gettext "已卸载") Xray ${Font}"
}

uninstall_nginx() { 
    if [[ "${1}" != "--force" ]]; then
        log_echo "${GreenBG} $(gettext "是否卸载") Nginx [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [nN][oO] | [nN]) 
            log_echo "${OK} ${GreenBG} $(gettext "已取消卸载") Nginx ${Font}"        
            return
            ;;
        esac
    fi
    systemctl disable nginx
    safe_rm "${nginx_dir}"
    safe_rm "${nginx_conf_dir}"
    [[ -f "${nginx_systemd_file}" ]] && safe_rm "${nginx_systemd_file}"
    if [[ -f "${xray_install_config_file}" ]]; then
        update_json_config "${xray_install_config_file}" 'del(.nginx_build_version)'
    fi
    log_echo "${OK} ${GreenBG} $(gettext "已卸载") Nginx ${Font}"
}

uninstall_all() {
    rxa_uninstall_enter
    stop_service_all
    acme_cron_cleanup
    local crontab_file
    if [[ "${ID}" == "centos" ]]; then
        crontab_file="/var/spool/cron/root"
    else
        crontab_file="/var/spool/cron/crontabs/root"
    fi
    if [[ -f "${crontab_file}" ]]; then
        sed -i "/auto_update.sh/d" "${crontab_file}"
        sed -i "/geo_update.sh/d" "${crontab_file}"
        sed -i "\|${ssl_update_file}|d" "${crontab_file}"
    fi
    [[ -f "/etc/logrotate.d/xray_log_cleanup" ]] && rm -f "/etc/logrotate.d/xray_log_cleanup"
    [[ -L "/usr/local/etc/xray/config.json" ]] && rm -f "/usr/local/etc/xray/config.json"
    [[ -L "/usr/local/share/xray" ]] && rm -f "/usr/local/share/xray"
    [[ -f "${xray_bin_dir}/xray" ]] && uninstall_xray
    echo
    [[ -d "${nginx_dir}" ]] && uninstall_nginx --force
    echo
    local keep_config=true
    if [[ -f "${xray_install_config_file}" ]]; then
        log_echo "${GreenBG} $(gettext "是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r remove_config_fq
        case $remove_config_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
            ;;
        *)
            keep_config=false
            log_echo "${OK} ${GreenBG} $(gettext "将删除配置文件") ${Font}"
            ;;
        esac
    fi
    log_echo "${GreenBG} $(gettext "是否删除所有脚本文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r remove_all_idleleo_file_fq
    case $remove_all_idleleo_file_fq in
    [yY][eE][sS] | [yY])
        if [[ "${keep_config}" == "true" && -f "${xray_install_config_file}" ]]; then
            local _tmp_config
            _tmp_config=$(mktemp)
            cp -f "${xray_install_config_file}" "${_tmp_config}"
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
            mkdir -p "${idleleo_conf_dir}"
            mv -f "${_tmp_config}" "${xray_install_config_file}"
        else
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
        fi
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已删除所有文件") ${Font}"
        log_echo "${GreenBG} $(gettext "ヾ(￣▽￣) 拜拜~") ${Font}"
        rxa_uninstall_finish 0
        exit 0
        ;;
    *)
        if [[ "${keep_config}" == "false" && -f "${xray_install_config_file}" ]]; then
            rm -rf "${xray_install_config_file}"
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
        fi
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已保留脚本文件 (包含 SSL 证书等)") ${Font}"
        ;;
    esac
    rxa_uninstall_finish 0
}

delete_tls_key_and_crt() {
    [[ -f "$HOME/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d "$HOME/.acme.sh" ]] && rm -rf "$HOME/.acme.sh"
    log_echo "${OK} ${GreenBG} $(gettext "已清空证书遗留文件") ${Font}"
}

countdown() {
    countdown_cnt=0
    countdown_str=""
    while [[ ${countdown_cnt} -le 30 ]]; do
        let countdown_cnt++
        countdown_str+="#"
    done
    let countdown_cnt=countdown_cnt+5
    while [[ ${countdown_cnt} -gt 0 ]]; do
        let countdown_cnt--
        if [[ ${countdown_cnt} -gt 25 ]]; then
            let countdown_color=32
            let countdown_bg=42
            countdown_index="3"
        elif [[ ${countdown_cnt} -gt 15 ]]; then
            let countdown_color=33
            let countdown_bg=43
            countdown_index="2"
        elif [[ ${countdown_cnt} -gt 5 ]]; then
            let countdown_color=31
            let countdown_bg=41
            countdown_index="1"
        else
            countdown_index="0"
        fi
        printf "${Warning} ${GreenBG} %d%s%s ${Font} \033[%d;%dm%-s\033[0m \033[%dm%d\033[0m \r" \
            "$countdown_index" \
            " $(gettext "秒后") " \
            "$1" \
            "$countdown_color" \
            "$countdown_bg" \
            "$countdown_str" \
            "$countdown_color" \
            "$countdown_index"
        sleep 0.1
        countdown_str=${countdown_str%?}
        [[ ${countdown_cnt} -eq 0 ]] && printf "\n"
    done
}

judge_mode() {
    if [[ -f "${xray_install_config_file}" ]]; then
        transport_mode=$(info_extraction transport_mode)
        [[ -z ${transport_mode} || ${transport_mode} == "null" ]] && transport_mode="None"
        tls_mode=$(info_extraction tls)
        if [[ ${tls_mode} == "Reality" ]]; then
            reality_add_more=$(info_extraction reality_add_more)
            reality_add_nginx=$(info_extraction reality_add_nginx)
            reality_add_balance=$(info_extraction reality_add_balance)
            reality_balance_role=$(info_extraction reality_balance_role)
            [[ -z ${reality_balance_role} || ${reality_balance_role} == "null" ]] && reality_balance_role=""
        fi
        _transport_set_shell_mode
        old_tls_mode=${tls_mode}
    fi
}

install_xray_ws_tls() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path. Creating nginx_conf_dir/ssl_chainpath/xray_conf_dir/
    # idleleo info + conf dirs first would pollute the manifest recorded file
    # existence and break rollback to the true source state.
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return below triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    domain_check || return 1
    transport_choose || return 1
    port_set || return 1
    ws_inbound_port_set || return 1
    grpc_inbound_port_set || return 1
    xhttp_inbound_port_set || return 1
    validate_active_ports || return 1
    port_exist_check 80 || return 1
    port_exist_check "${port}" || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    firewall_set || return 1
    ws_path_set || return 1
    grpc_path_set || return 1
    xhttp_path_set || return 1
    email_set || return 1
    UUID_set || return 1
    transport_qr
    install_config_tls_ws || return 1
    stop_service_all
    xray_install || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    nginx_exist_check || return 1
    nginx_systemd || return 1
    nginx_ssl_conf_add || return 1
    ssl_judge_and_install || return 1
    nginx_conf_add || return 1
    nginx_servers_conf_add || return 1
    xray_conf_add || return 1
    harden_config_permissions || return 1
    if [[ ${reality_add_nginx} == "on" ]]; then
        tls_type || return 1
    fi
    enable_process_systemd || return 1
    acme_cron_update
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    # Clear trap before finalize — finalize handles its own restore.
    trap - RETURN
    # Propagate reinstall_finalize's exact return code to the caller:
    #   1 = deploy failed but restore succeeded
    #   2 = deploy failed and restore failed (backup retained)
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    # Success info only after final safety gate passes.
    basic_information
    vless_link_image_choice
    show_information
}

install_xray_reality() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path (see install_xray_ws_tls).
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return below triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    ip_check || return 1
    port_set || return 1
    email_set || return 1
    UUID_set || return 1
    target_set || return 1
    serverNames_set || return 1
    shortIds_set || return 1
    spiderx_set || return 1
    xray_reality_add_more_choose || return 1
    validate_active_ports || return 1
    port_exist_check "${port}" || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    xray_install || return 1
    keys_set || return 1
    transport_qr
    firewall_set || return 1
    stop_service_all
    reality_balance_add_fq
    reality_nginx_add_fq || return 1
    xray_conf_add || return 1
    install_config_reality || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    harden_config_permissions || return 1
    if [[ ${reality_add_nginx} == "on" ]]; then
        tls_type || return 1
    fi
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    trap - RETURN
    # Propagate reinstall_finalize's exact return code (1 restore-ok / 2 restore-failed).
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    basic_information
    vless_link_image_choice
    show_information
}

install_xray_xtls_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path (see install_xray_ws_tls).
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    ip_check || return 1
    shell_mode="XTLS ONLY"
    tls_mode="XTLS"
    port_set || return 1
    validate_active_ports || return 1
    port_exist_check "${port}" || return 1
    firewall_set || return 1
    email_set || return 1
    UUID_set || return 1
    install_config_xtls_only || return 1
    stop_service_all
    xray_install || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    xray_conf_add || return 1
    harden_config_permissions || return 1
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    trap - RETURN
    # Propagate reinstall_finalize's exact return code (1 restore-ok / 2 restore-failed).
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    basic_information
    vless_link_image_choice
    show_information
}

install_xray_ws_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path (see install_xray_ws_tls).
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    ip_check || return 1
    transport_choose || return 1
    ws_inbound_port_set || return 1
    grpc_inbound_port_set || return 1
    xhttp_inbound_port_set || return 1
    validate_active_ports || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    firewall_set || return 1
    ws_path_set || return 1
    grpc_path_set || return 1
    xhttp_path_set || return 1
    email_set || return 1
    UUID_set || return 1
    transport_qr
    install_config_ws_only || return 1
    stop_service_all
    xray_install || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    xray_conf_add || return 1
    harden_config_permissions || return 1
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    trap - RETURN
    # Propagate reinstall_finalize's exact return code (1 restore-ok / 2 restore-failed).
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    basic_information
    vless_link_image_choice
    show_information
}

update_sh() {
    local downloaded_shell_version _backup_script
    ol_version=${shell_online_version}
    echo "${ol_version}" >"${shell_version_tmp}"
    [[ -z ${ol_version} ]] && log_echo "${Error} ${RedBG} $(gettext "检测最新版本失败")! ${Font}" && return 1
    echo "${shell_version}" >>"${shell_version_tmp}"
    newest_version=$(sort -rV "${shell_version_tmp}" | head -1)
    oldest_version=$(sort -V "${shell_version_tmp}" | head -1)
    version_difference=$(echo "(${newest_version:0:3}-${oldest_version:0:3})>0" | bc)
    if [[ ${shell_version} != ${newest_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "新版本")(${newest_version}) $(gettext "更新内容"): ${Font}"
            log_echo "${Green} $(check_version shell_upgrade_details) ${Font}"
            if [[ ${version_difference} == 1 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "存在新版本, 但版本变化较大, 可能存在不兼容情况, 是否更新") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
            else
                echo
                log_echo "${GreenBG} $(gettext "存在新版本, 是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            fi
            read -r update_confirm
        else
            [[ -z ${ol_version} ]] && echo "$(gettext "检测最新版本失败")!" >>"${log_file}" && return 1
            [[ ${version_difference} == 1 ]] && echo "$(gettext "脚本版本差别过大, 跳过更新")!" >>"${log_file}" && return 1
            update_confirm="YES"
        fi
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L "${idleleo_commend_file}" ]] && rm -f ${idleleo_commend_file}
            _backup_script=""
            if [[ -f "${idleleo}" ]]; then
                _backup_script="${idleleo}.bak.$$"
                cp -a "${idleleo}" "${_backup_script}" || _backup_script=""
            fi
            _candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
            if ! download_script_file "${main_remote_url}" "${_candidate}"; then
                rm -f "${_candidate}"
                [[ -n "${_backup_script}" && -f "${_backup_script}" ]] && mv -f "${_backup_script}" "${idleleo}"
                ln -sf "${idleleo}" "${idleleo_commend_file}"
                [[ ${auto_update} == "YES" ]] && echo "$(gettext "脚本更新失败")!" >>"${log_file}"
                [[ ${auto_update} != "YES" ]] && log_echo "${Error} ${RedBG} $(gettext "脚本更新失败")! ${Font}"
                return 1
            fi
            # Rill Xray Agent: validate the candidate before it can replace
            # the running script; on any failure keep the old version.
            if ! command -v rxa_candidate_guard >/dev/null 2>&1 || ! rxa_candidate_guard "${_candidate}"; then
                rm -f "${_candidate}"
                [[ -n "${_backup_script}" && -f "${_backup_script}" ]] && mv -f "${_backup_script}" "${idleleo}"
                ln -sf "${idleleo}" "${idleleo_commend_file}"
                log_echo "${Error} ${RedBG} Rill Xray Agent $(gettext "集成校验失败, 已阻止脚本更新") ${Font}"
                return 1
            fi
            downloaded_shell_version=$(
                grep -E '^shell_version=' "${_candidate}" |
                head -n 1 |
                awk -F'=|"' '{print $3}'
            )
            if [[ -z "${downloaded_shell_version}" ||
                  "${downloaded_shell_version}" != "${newest_version}" ]]; then
                rm -f "${_candidate}"
                log_echo "${Error} ${RedBG} $(gettext "下载脚本版本校验失败") ${Font}"
                [[ -n "${_backup_script}" && -f "${_backup_script}" ]] && mv -f "${_backup_script}" "${idleleo}"
                ln -sf "${idleleo}" "${idleleo_commend_file}"
                rm -f "${_backup_script}"
                return 1
            fi
            mv -f "${_candidate}" "${idleleo}"
            rm -f "${_backup_script}"
            ln -s "${idleleo}" "${idleleo_commend_file}"
            if [[ -f "${xray_install_config_file}" ]]; then
                update_json_config "${xray_install_config_file}" \
                    --arg shell_version "${downloaded_shell_version}" \
                    '.shell_version = $shell_version' || return 1
            fi
            shell_version="${downloaded_shell_version}"
            clear
            log_echo "${OK} ${GreenBG} $(gettext "更新") $(gettext "完成") ${Font}"
            [[ ${version_difference} == 1 ]] && log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 若服务无法正常运行请卸载后重装")! ${Font}"
            return 0
            ;;
        *)
            return 0
            ;;
        esac
    else
        clear
        log_echo "${OK} ${GreenBG} $(gettext "当前已经是最新版本") ${Font}"
    fi
    return 0

}

check_file_integrity() {
    if [[ ! -L "${idleleo_commend_file}" ]] && [[ ! -f "${idleleo}" ]]; then
        check_system
        pkg_install "bc,jq"
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p "${idleleo_dir}"
        [[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p "${idleleo_dir}"/tmp
        [[ ! -d "${scripts_dir}" ]] && mkdir -p "${scripts_dir}"
        download_script_file "${main_remote_url}" "${idleleo_dir}/install.sh"
        judge "$(gettext "下载最新脚本")"
        ln -s "${idleleo}" "${idleleo_commend_file}"
        clear
        exec "${BASH:-bash}" "${idleleo}"
    fi
}

compat_migrate() {
    local _marker_file="${idleleo_dir}/.compat_migrate_v1"
    [[ -f "${_marker_file}" ]] && return 0

    # COMPAT: vless_qr.json → install_config.json，v2.15 后删除
    local _old_install_config="${idleleo_dir}/info/vless_qr.json"
    if [[ -f "${_old_install_config}" && ! -f "${xray_install_config_file}" ]]; then
        mkdir -p "${idleleo_conf_dir}"
        mv "${_old_install_config}" "${xray_install_config_file}"
        info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    fi
    # COMPAT_END
    # COMPAT: info/install_config.json → conf/install_config.json，v2.15 后删除
    local _old_install_config_path="${idleleo_dir}/info/install_config.json"
    if [[ -f "${_old_install_config_path}" && ! -f "${xray_install_config_file}" ]]; then
        mkdir -p "${idleleo_conf_dir}"
        mv "${_old_install_config_path}" "${xray_install_config_file}"
        info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    fi
    # COMPAT_END
    # COMPAT: 删除低于仓库版本的旧子脚本(自更新下载路径错误)，v2.15 后删除
    local _subscripts="file_manager.sh:fm_SCRIPT_VERSION:1.5.8 traffic_blocker.sh:tb_SCRIPT_VERSION:1.5.12 fail2ban_manager.sh:mf_SCRIPT_VERSION:1.5.7"
    local _entry _script_name _ver_var _required_ver _loc _local_ver _oldest_ver
    for _entry in $_subscripts; do
        IFS=':' read -r _script_name _ver_var _required_ver <<< "$_entry"
        [[ -f "${idleleo_dir}/${_script_name}" ]] && rm -f "${idleleo_dir}/${_script_name}"
        _loc="${scripts_dir}/${_script_name}"
        if [[ -f "$_loc" ]]; then
            _local_ver=$(grep "^${_ver_var}=" "$_loc" | head -1 | sed 's/.*="//; s/"//')
            if [[ -z "$_local_ver" ]]; then
                rm -f "$_loc"
            else
                _oldest_ver=$(printf '%s\n%s\n' "$_required_ver" "$_local_ver" | sort -V | head -1)
                [[ "$_oldest_ver" != "$_required_ver" ]] && rm -f "$_loc"
            fi
        fi
    done
    # COMPAT_END
    # COMPAT: 清理非交互式子脚本根目录残留 + crontab 路径修正，v2.15 后删除
    mkdir -p "${scripts_dir}"
    for _script_name in auto_update.sh ssl_update.sh geo_update.sh tcp.sh; do
        if [[ -f "${idleleo_dir}/${_script_name}" ]]; then
            if [[ -f "${scripts_dir}/${_script_name}" ]]; then
                rm -f "${idleleo_dir}/${_script_name}"
            else
                mv -f "${idleleo_dir}/${_script_name}" "${scripts_dir}/${_script_name}"
            fi
        fi
    done
    local _crontab_file
    if [[ "${ID}" == "centos" ]]; then
        _crontab_file="/var/spool/cron/root"
    else
        _crontab_file="/var/spool/cron/crontabs/root"
    fi
    if [[ -f "${_crontab_file}" ]]; then
        sed -i "s|${idleleo_dir}/auto_update\.sh|${scripts_dir}/auto_update.sh|g" "${_crontab_file}"
        sed -i "s|${idleleo_dir}/geo_update\.sh|${scripts_dir}/geo_update.sh|g" "${_crontab_file}"
        sed -i "s|${idleleo_dir}/ssl_update\.sh|${scripts_dir}/ssl_update.sh|g" "${_crontab_file}"
    fi
    # COMPAT_END

    touch "${_marker_file}"
}

read_version() {
    # Load once in the current shell. Calling check_version only through command
    # substitutions would otherwise perform one network request per field because
    # each substitution runs in a subshell and cannot preserve the cache state.
    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi

    local new_shell_online_version
    local new_xray_online_version
    local new_nginx_build_version
    local new_shell_tested_version
    local new_xray_tested_version
    local new_nginx_build_tested_version

    new_shell_online_version="$(check_version shell_online_version)" || return 1
    new_xray_online_version="$(check_version xray_online_version)" || return 1
    new_nginx_build_version="$(check_version nginx_build_online_version)" || return 1
    # Read tested_version (known-good fallback baseline) from API.
    # These fields are optional in the API JSON; missing fields are treated as
    # "no Layer 2 fallback available" and silently become empty strings.
    new_shell_tested_version="$(check_version_silent shell_tested_version || echo "")"
    new_xray_tested_version="$(check_version_silent xray_tested_version || echo "")"
    new_nginx_build_tested_version="$(check_version_silent nginx_build_tested_version || echo "")"

    shell_online_version="${new_shell_online_version}"
    xray_online_version="${new_xray_online_version}"
    nginx_build_version="${new_nginx_build_version}"
    shell_tested_version="${new_shell_tested_version}"
    xray_tested_version="${new_xray_tested_version}"
    nginx_build_tested_version="${new_nginx_build_tested_version}"
}

maintain() {
    log_echo "${Error} ${RedBG} $(gettext "该选项暂时无法使用")! ${Font}"
    log_echo "${Error} ${RedBG} $(gettext "$1") ${Font}"
    exit 0
}

list() {
    case $1 in
    '-1' | '--install-tls')
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        ;;
    '-2' | '--install-reality')
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        ;;
    '-3' | '--install-none')
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        ;;
    '-4' | '--install-xtls')
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式仅用于流量中转, 不建议在其他情况下使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r xtlsonly_fq
        case $xtlsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="XTLS ONLY"
            tls_mode="XTLS"
            install_xray_xtls_only
            ;;
        *) ;;
        esac
        ;;
    '-5' | '--add-upstream')
        nginx_upstream_server_set
        ;;
    '-6' | '--add-servernames')
        nginx_servernames_server_set
        ;;
    '-sg' | '--sni-guard')
        reset_sni_guard_policy
        ;;
    '-au' | '--auto-update')
        auto_update
        ;;
    '-c' | '--clean-logs')
        clean_logs
        ;;
    '-cs' | '--cert-status')
        check_cert_status
        ;;
    '-cu' | '--cert-update')
        cert_update_manuel
        ;;
    '-cau' | '--cert-auto-update')
        acme_cron_update
        ;;
    '-f' | '--set-fail2ban')
        set_fail2ban
        ;;
    '--fail2ban-list')
        set_fail2ban_cli --list
        ;;
    '--fail2ban-unban')
        set_fail2ban_cli --unban "$2" "$3"
        ;;
    '--fail2ban-trust-add')
        set_fail2ban_cli --trust-add "$2" "$3"
        ;;
    '--fail2ban-trust-del')
        set_fail2ban_cli --trust-del "$2" "$3"
        ;;
    '-tb' | '--traffic-blocker')
        set_traffic_blocker
        ;;
    '-h' | '--help')
        show_help
        ;;
    '-l' | '--language')
        set_language
        ;;
    '-n' | '--nginx-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        nginx_update
        ;;
    '-p' | '--port-reset')
        reset_port
        ;;
    '-pt' | '--port-traffic')
        clear
        monitor_traffic_with_iftop
        ;;
    '--purge' | '--uninstall')
        uninstall_all
        ;;
    '-s' | '--show')
        clear
        basic_information
        install_link_image
        show_information
        ;;
    '-t' | '--target-reset')
        reset_target
        ;;
    '-tcp' | '--tcp')
        bbr_boost_sh
        ;;
    '-tls' | '--tls')
        tls_type
        ;;
    '-u' | '--update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        update_sh
        ;;
    '-uu' | '--uuid-reset')
        reset_UUID
        ;;
    '-xa' | '--xray-access')
        clear
        show_access_log
        ;;
    '-xe' | '--xray-error')
        clear
        show_error_log
        ;;
    '-x' | '--xray-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        xray_update
        ;;
    *)
        menu
        ;;
    esac
}

show_help() {
    echo "usage: idleleo [OPTION]"
    echo
    echo "OPTION:"
    echo "  -1, --install-tls           $(gettext "安装") Xray (Nginx+ws/gRPC/xHTTP+TLS)"
    echo "  -2, --install-reality       $(gettext "安装") Xray (Nginx+Reality+ws/gRPC/xHTTP)"
    echo "  -3, --install-none          $(gettext "安装") Xray (ws/gRPC/xHTTP ONLY)"
    echo "  -4, --install-xtls          $(gettext "安装") Xray (XTLS ONLY)"
    echo "  -5, --add-upstream          $(gettext "变更") Nginx $(gettext "负载均衡配置")"
    echo "  -6, --add-servernames       $(gettext "变更") Nginx serverNames $(gettext "配置")"
    echo "  -sg, --sni-guard            $(gettext "变更") SNI Guard"
    echo "  -au, --auto-update          $(gettext "设置自动更新")"
    echo "  -c, --clean-logs            $(gettext "清除日志文件")"
    echo "  -cs, --cert-status          $(gettext "查看证书状态")"
    echo "  -cu, --cert-update          $(gettext "更新证书有效期")"
    echo "  -cau, --cert-auto-update    $(gettext "设置证书自动更新")"
    echo "  -f, --set-fail2ban          $(gettext "设置 Fail2ban 防暴力破解")"
    echo "      --fail2ban-list         $(gettext "查看 Fail2ban 状态")"
    echo "      --fail2ban-unban <jail> <ip>                $(gettext "快速解封 IP")"
    echo "      --fail2ban-trust-add <jail> <ip-or-cidr>   $(gettext "添加可信 IP/CIDR")"
    echo "      --fail2ban-trust-del <jail> <ip-or-cidr>   $(gettext "移除可信 IP/CIDR")"
    echo "  -tb, --traffic-blocker      $(gettext "设置 Xray 流量阻断")"
    echo "  -h, --help                  $(gettext "显示帮助")"
    echo "  -l, --language              $(gettext "修改语言")"
    echo "  -n, --nginx-update          $(gettext "更新") Nginx"
    echo "  -p, --port-reset            $(gettext "变更") port"
    echo "  -pt, --port-traffic         $(gettext "查看") port $(gettext "实时流量")"
    echo "  --purge, --uninstall        $(gettext "脚本卸载")"
    echo "  -s, --show                  $(gettext "显示安装信息")"
    echo "  -t, --target-reset          $(gettext "变更") target"
    echo "  -tcp, --tcp                 $(gettext "配置") TCP $(gettext "加速")"
    echo "  -tls, --tls                 $(gettext "修改") TLS $(gettext "配置")"
    echo "  -u, --update                $(gettext "更新脚本")"
    echo "  -uu, --uuid-reset           $(gettext "变更") UUIDv5/$(gettext "映射字符串")"
    echo "  -xa, --xray-access          $(gettext "显示") Xray $(gettext "访问信息")"
    echo "  -xe, --xray-error           $(gettext "显示") Xray $(gettext "错误信息")"
    echo "  -x, --xray-update           $(gettext "更新") Xray"
    exit 0
}

idleleo_commend() {
    if [[ -L "${idleleo_commend_file}" ]] || [[ -f "${idleleo}" ]]; then
        [[ ! -L "${idleleo_commend_file}" ]] && chmod +x "${idleleo}" && ln -s "${idleleo}" "${idleleo_commend_file}"
        old_version=$(grep "shell_version=" "${idleleo}" | head -1 | awk -F '=|"' '{print $3}')
        echo "${old_version}" >"${shell_version_tmp}"
        echo "${shell_version}" >>"${shell_version_tmp}"
        oldest_version=$(sort -V "${shell_version_tmp}" | head -1)
        version_difference=$(echo "(${shell_version:0:3}-${oldest_version:0:3})>0" | bc)
        if [[ -z ${old_version} ]]; then
            _candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
            if ! download_script_file "${main_remote_url}" "${_candidate}"; then
                rm -f "${_candidate}"
                return 1
            fi
            if ! command -v rxa_candidate_guard >/dev/null 2>&1 || ! rxa_candidate_guard "${_candidate}"; then
                rm -f "${_candidate}"
                echo "Rill Xray Agent $(gettext "集成校验失败, 已阻止脚本更新")" >&2
                return 1
            fi
            mv -f "${_candidate}" "${idleleo}"

            judge "$(gettext "下载最新脚本")"
            clear
            exec "${BASH:-bash}" "${idleleo}"
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            echo
            log_echo "${GreenBG} $(gettext "新版本")(${shell_version}) $(gettext "更新内容"): ${Font}"
            log_echo "${Green} $(check_version shell_upgrade_details) ${Font}"
            if [[ ${version_difference} == 1 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 可能存在不兼容情况, 是否继续使用") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r update_sh_fq
                case $update_sh_fq in
                [yY][eE][sS] | [yY])
                    _candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
            if ! download_script_file "${main_remote_url}" "${_candidate}"; then
                rm -f "${_candidate}"
                return 1
            fi
            if ! command -v rxa_candidate_guard >/dev/null 2>&1 || ! rxa_candidate_guard "${_candidate}"; then
                rm -f "${_candidate}"
                echo "Rill Xray Agent $(gettext "集成校验失败, 已阻止脚本更新")" >&2
                return 1
            fi
            mv -f "${_candidate}" "${idleleo}"

                    judge "$(gettext "下载最新脚本")"
                    clear
                    log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 若服务无法正常运行请卸载后重装")! ${Font}"
                    echo
                    ;;
                *)
                    exec "${BASH:-bash}" "${idleleo}"
                    ;;
                esac
            else
                _candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
            if ! download_script_file "${main_remote_url}" "${_candidate}"; then
                rm -f "${_candidate}"
                return 1
            fi
            if ! command -v rxa_candidate_guard >/dev/null 2>&1 || ! rxa_candidate_guard "${_candidate}"; then
                rm -f "${_candidate}"
                echo "Rill Xray Agent $(gettext "集成校验失败, 已阻止脚本更新")" >&2
                return 1
            fi
            mv -f "${_candidate}" "${idleleo}"

                echo
                judge "$(gettext "下载最新脚本")"
                clear
                echo
            fi
            exec "${BASH:-bash}" "${idleleo}"
        else
            ol_version=${shell_online_version}
            echo "${ol_version}" >"${shell_version_tmp}"
            [[ -z ${ol_version} ]] && shell_need_update="${Yellow}[$(gettext "检测失败")]!${Font}"
            echo "${shell_version}" >>"${shell_version_tmp}"
            newest_version=$(sort -rV "${shell_version_tmp}" | head -1)
            if [[ ${shell_version} != ${newest_version} ]]; then
                shell_need_update="${Yellow}[$(gettext "有新版")!]${Font}"
                shell_emoji="${Yellow}>_<${Font}"
            else
                shell_need_update="${Green}[$(gettext "最新版")]${Font}"
                shell_emoji="${Green}^O^${Font}"
            fi
            if [[ -f "${xray_install_config_file}" ]]; then
                if [[ -z "$(info_extraction nginx_build_version)" ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
                    nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                elif [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
                    nginx_need_update="${Green}[$(gettext "有新版")!]${Font}"
                else
                    nginx_need_update="${Green}[$(gettext "最新版")]${Font}"
                fi
                if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f "${xray_bin_dir}/xray" ]]; then
                    ##xray_online_version=$(check_version xray_online_pre_version)
                    if [[ -z "$(info_extraction xray_version)" ]]; then
                        xray_need_update="${Green}[$(gettext "已安装")] ($(gettext "版本未知"))${Font}"
                    elif [[ ${xray_online_version} != $(info_extraction xray_version) ]]; then
                        xray_need_update="${Green}[$(gettext "有新版")!]${Font}"
                        ### xray_need_update="${Red}[$(gettext "请务必更新")]!${Font}"
                    else
                        xray_need_update="${Green}[$(gettext "最新版")]${Font}"
                    fi
                else
                    xray_need_update="${Yellow}[$(gettext "未安装")]${Font}"
                fi
            else
                nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                xray_need_update="${Yellow}[$(gettext "未安装")]${Font}"
            fi
        fi
    fi
}

check_program() {
    if [[ -n $(pgrep nginx) ]]; then
        nginx_status="${Green}$(gettext "运行中")..${Font}"
    elif [[ ${tls_mode} == "None" ]] || [[ ${tls_mode} == "XTLS" ]] || [[ ${tls_mode} == "Reality" && ${reality_add_nginx} != "on" ]]; then
        nginx_status="${Green}$(gettext "无需测试")${Font}"
    else
        nginx_status="${Red}$(gettext "未运行")${Font}"
    fi
    if [[ -n $(pgrep xray) ]]; then
        xray_status="${Green}$(gettext "运行中")..${Font}"
    else
        xray_status="${Red}$(gettext "未运行")${Font}"
    fi
}

curl_local_connect() {
    curl -Is -o /dev/null -w '%{http_code}' --max-time 10 "https://$1/$2"
}

curl_local_connect_xhttp() {
    local host="$1"
    local raw_path="$2"
    local probe_path
    local curl_args=(-s -o /dev/null -w '%{http_code}' --max-time 10)

    probe_path="$(format_xhttp_path "${raw_path}")"
    probe_path="${probe_path%/}/xhttp-probe-${RANDOM}"
    if curl --version 2>/dev/null | grep -q 'HTTP2'; then
        curl_args+=(--http2)
    fi
    curl "${curl_args[@]}" "https://${host}${probe_path}"
}

tcp_local_connect() {
    local port="$1"

    [[ ${port} =~ ^[0-9]+$ ]] || return 1
    timeout 3 bash -c ':</dev/tcp/127.0.0.1/$1' _ "${port}" >/dev/null 2>&1
}

xray_inbound_port() {
    local inbound_tag="$1"

    [[ -f "${xray_conf}" ]] || return 1
    jq -r --arg tag "${inbound_tag}" 'first(.inbounds[]? | select(.tag == $tag) | .port) // empty' "${xray_conf}" 2>/dev/null
}

check_transport_tcp_ports() {
    if is_ws_mode && ! tcp_local_connect "$(info_extraction ws_port)"; then
        return 1
    fi
    if is_grpc_mode && ! tcp_local_connect "$(info_extraction grpc_port)"; then
        return 1
    fi
    if is_xhttp_mode && ! tcp_local_connect "$(info_extraction xhttp_port)"; then
        return 1
    fi
    is_ws_mode || is_grpc_mode || is_xhttp_mode
}

check_reality_tcp_ports() {
    local reality_port

    if [[ ${reality_add_nginx} == "on" ]]; then
        reality_port=$(xray_inbound_port "VLESS-Reality-in")
        tcp_local_connect "$(info_extraction port)" && tcp_local_connect "${reality_port}" || return 1
    else
        tcp_local_connect "$(info_extraction port)" || return 1
    fi
    if [[ ${reality_add_more} == "on" ]]; then
        check_transport_tcp_ports || return 1
    fi
}

check_xray_local_connect() {
    if [[ -f "${xray_install_config_file}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            xray_local_connect_status="${Yellow}$(gettext "无法连通")${Font}"
        else
            xray_local_connect_status="${Red}$(gettext "无法连通")${Font}"
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyxhttp" ]]; then
                [[ $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "onlyws" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" && $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" && $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" && $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            check_reality_tcp_ports && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        elif [[ ${tls_mode} == "None" ]]; then
            check_transport_tcp_ports && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            tcp_local_connect "$(info_extraction port)" && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        fi
    else
        xray_local_connect_status="${Red}$(gettext "未安装")${Font}"
    fi
}

check_online_version_connect() {
    maintain_file_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/maintain")

    if [[ ${maintain_file_status} == "200" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "脚本维护中.. 请稍后再试")! ${Font}"
        sleep 0.5
        exit 0
    fi

    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "无法检测所需依赖的在线版本, 请稍后再试")! ${Font}"
        sleep 0.5
        exit 1
    fi
}

set_language() {
    echo
    log_echo "${GreenBG} 选择语言 / Select Language / انتخاب زبان / Выберите язык ${Font}"
    echo -e "${Green}1.${Font} 中文 (默认)"
    echo -e "${Green}2.${Font} English"
    echo -e "${Green}3.${Font} Français"
    echo -e "${Green}4.${Font} فارسی"
    echo -e "${Green}5.${Font} Русский"
    echo -e "${Green}6.${Font} 한국어"

    local lang_choice
    read_optimize "$(gettext "请输入数字"): " "lang_choice" "NULL" 1 6 "$(gettext "请输入 1 到 6 之间的有效数字")" || return 1

    case $lang_choice in
        1)
            unset LANG
            unset LC_MESSAGES
            rm -f "${idleleo_dir}/language.conf"
            rm -rf "${idleleo_dir}/languages"
            ;;
        2)
            export LANG=en_US.UTF-8
            export LC_MESSAGES=en_US.UTF-8
            ;;
        3)
            export LANG=fr_FR.UTF-8
            export LC_MESSAGES=fr_FR.UTF-8
            ;;
        4)
            export LANG=fa_IR.UTF-8
            export LC_MESSAGES=fa_IR.UTF-8
            ;;
        5)
            export LANG=ru_RU.UTF-8
            export LC_MESSAGES=ru_RU.UTF-8
            ;;
        6)
            export LANG=ko_KR.UTF-8
            export LC_MESSAGES=ko_KR.UTF-8
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
            return 1
            ;;
    esac

    if [ "$lang_choice" -ne 1 ]; then

        check_system

        echo "LANG=$LANG" > "${idleleo_dir}/language.conf"
        echo "LC_MESSAGES=$LC_MESSAGES" >> "${idleleo_dir}/language.conf"

        case $ID in
            debian|ubuntu)
                if ! dpkg -s locales-all >/dev/null 2>&1; then
                    pkg_install "locales-all"
                fi

                if command -v locale-gen >/dev/null 2>&1; then
                     locale-gen "$LANG" 2>/dev/null || true # 忽略可能的错误
                fi
                ;;
            centos)
                local ins_lang_code="${LANG%%_*}"
                if ! rpm -q "glibc-langpack-$ins_lang_code" >/dev/null 2>&1; then
                    pkg_install "glibc-langpack-$ins_lang_code"
                fi
                # 尝试生成 locale (非必需，但可能有帮助)
                if command -v localedef >/dev/null 2>&1 && [ -f "/usr/share/i18n/locales/${LANG%.*}" ]; then
                    localedef -c -i "${LANG%.*}" -f UTF-8 "$LANG" 2>/dev/null || true # 忽略可能的错误
                fi
                ;;
        esac
    fi

    exec "${BASH:-bash}" "${idleleo}"
}

function backup_directories() {
    local timestamp=$(date +"%Y%m%d%H%M%S")
    local backup_name=""
    read_optimize "$(gettext "请输入备份名称") ($(gettext "不需要后缀")): " "backup_name" ""
    local backup_filename="xray_bash_${backup_name}_${timestamp}.tar.gz"
    local backup_path="/etc/idleleo/${backup_filename}"

    local tar_output
    tar_output=''
    tar_output=$(tar --exclude='/etc/idleleo/xray_bash_*.tar.gz' -czf "${backup_path}" /etc/idleleo /usr/local/nginx 2>&1)

    if [[ $? -ne 0 ]]; then
        log_echo "${Green} tar $(gettext "报错信息"): ${Font}"
        echo "${tar_output}"
        log_echo "${Warning} ${YellowBG} $(gettext "备份完整性可能受到影响, 请检查上述错误信息") ${Font}"
    fi

    if [[ ! -f "${backup_path}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "备份") $(gettext "成功"): ${backup_path} ${Font}"
    fi
}

function restore_directories() {
    log_echo "${Warning} ${YellowBG} $(gettext "请确保备份文件在目录"): /etc/idleleo ${Font}"
    local backup_files=($(ls /etc/idleleo/xray_bash_*.tar.gz 2>/dev/null))
    
    if [[ ${#backup_files[@]} -eq 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "没有找到备份文件") ${Font}"
        return 1
    fi

    if [[ ${#backup_files[@]} -gt 1 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "发现多个备份文件"), $(gettext "将使用最新的文件进行恢复") ${Font}"
    fi

    local latest_backup_file=${backup_files[-1]}
    log_echo "${Green} $(gettext "找到最新备份文件"): ${latest_backup_file} ${Font}"

    countdown "$(gettext "恢复备份")!"
    tar -xzf "${latest_backup_file}" -C / &> /dev/null

    if [[ $? -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "恢复") $(gettext "成功") ${Font}"
        log_echo "${Info} ${Green} $(gettext "记得安装") xray ${Font}"
        if [[ -d "/usr/local/nginx" ]]; then
            log_echo "${Info} ${Green} $(gettext "记得安装") nginx ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "恢复") $(gettext "失败") ${Font}"
    fi
}

# ============================================================
# Reinstall backup / restore
# Simple, reliable directory snapshot taken before any reinstall
# or mode switch. On deploy failure the snapshot is restored.
# ============================================================

# Path to the backup directory created for the current reinstall attempt.
# Empty when there is nothing to restore (fresh install, or test mode where
# old_config_exist_check is mocked out).
_reinstall_backup_dir=""
# Firewall transaction state (see apply_managed_firewall_transaction). Captured
# at reconfig start (old) and after parameters are determined (new), so a
# partial firewall change can be reversed even if managed_ports.json was not
# yet written with the new set.
_reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_changed="no"

# RETURN-trap wrapper: restores the backup exactly once on deploy failure.
# Args: <exit_code> <backup_dir>
# - rc == 0 (success): clear backup dir reference, no restore.
# - rc != 0 (failure): restore once; on restore failure return 2 and retain
#   backup dir so the operator can inspect it. Clears the trap first to
#   avoid recursion.
reinstall_rollback_on_return() {
    local rc="$1"
    local backup_dir="$2"
    trap - RETURN
    if [[ "${rc}" -ne 0 && -n "${backup_dir}" ]]; then
        if ! reinstall_backup_restore "${backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "部署失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
    else
        _reinstall_backup_dir=""
    fi
    return "${rc}"
}

# Canonical cron marker for the project-managed ACME cert-renewal task.
# Detection, backup, restore, dedup and deletion must ALL match this exact
# script path (fixed-string grep) so a user's own ssl_update.sh or another
# project's ACME job is never detected, backed up, restored or deleted.
acme_cron_match_pattern() {
    printf '%s' "${ssl_update_file}"
}

# Create a timestamped backup of the running config before reinstall
# or mode switch. Echoes the backup directory path on stdout.
# Returns 1 if the backup could not be created.
reinstall_backup_create() {
    local backup_dir
    local _backup_root="${idleleo_dir}/backup"
    # Ensure parent directory exists (fail-closed if it cannot be created).
    if ! mkdir -p "${_backup_root}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "备份父目录创建失败, 中止重配置") ${Font}"
        return 1
    fi
    # Use mktemp -d for a unique directory (prevents same-second collisions).
    backup_dir=$(mktemp -d "${_backup_root}/reinstall-$(date +%Y%m%d-%H%M%S)-XXXXXX" 2>/dev/null)
    if [[ -z "${backup_dir}" || ! -d "${backup_dir}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份目录创建失败, 中止重配置") ${Font}"
        return 1
    fi

    local _cp_err=0
    # Fail-closed metadata error flag. Set anywhere below (cron line backup,
    # manifest validation, checksum generation) to abort the whole backup.
    local _meta_err=0

    # Critical files — fail closed if they exist but cannot be copied.
    if [[ -f "${xray_install_config_file}" ]]; then
        cp -a "${xray_install_config_file}" "${backup_dir}/install_config.json" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${xray_conf_dir}" ]]; then
        cp -a "${xray_conf_dir}" "${backup_dir}/xray" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${nginx_conf_dir}" ]]; then
        cp -a "${nginx_conf_dir}" "${backup_dir}/nginx" 2>/dev/null || _cp_err=1
    fi
    # Main nginx.conf (outside the project conf dir).
    local _nginx_main_conf="/usr/local/nginx/conf/nginx.conf"
    if [[ -f "${_nginx_main_conf}" ]]; then
        cp -a "${_nginx_main_conf}" "${backup_dir}/nginx.conf" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${ssl_chainpath}" ]]; then
        cp -a "${ssl_chainpath}" "${backup_dir}/cert" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${managed_ports_file}" ]]; then
        cp -a "${managed_ports_file}" "${backup_dir}/managed_ports.json" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${xray_systemd_file}" ]]; then
        cp -a "${xray_systemd_file}" "${backup_dir}/xray.service" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${nginx_systemd_file}" ]]; then
        cp -a "${nginx_systemd_file}" "${backup_dir}/nginx.service" 2>/dev/null || _cp_err=1
    fi
    # Share info files — use the canonical xray_info_file path and Clash YAML.
    if [[ -f "${xray_info_file}" ]]; then
        cp -a "${xray_info_file}" "${backup_dir}/xray_info.inf" 2>/dev/null || _cp_err=1
    fi
    local _clash_yaml="${xray_info_file%.*}_clash.yaml"
    if [[ -f "${_clash_yaml}" ]]; then
        cp -a "${_clash_yaml}" "${backup_dir}/xray_info_clash.yaml" 2>/dev/null || _cp_err=1
    fi

    if [[ ${_cp_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "关键文件备份失败, 中止重配置") ${Font}"
        rm -rf "${backup_dir}"
        return 1
    fi

    # Record pre-reinstall state. Use old_tls_mode (source mode) not tls_mode
    # (target mode) so mode-switch backups record the correct source.
    local _source_mode="${old_tls_mode:-${tls_mode:-}}"
    local _xray_active="no" _nginx_active="no" _xray_enabled="no" _nginx_enabled="no"
    systemctl is-active --quiet xray 2>/dev/null && _xray_active="yes"
    systemctl is-active --quiet nginx 2>/dev/null && _nginx_active="yes"
    systemctl is-enabled --quiet xray 2>/dev/null && _xray_enabled="yes"
    systemctl is-enabled --quiet nginx 2>/dev/null && _nginx_enabled="yes"

    # Snapshot actual managed firewall rules.
    local _fw_snapshot=""
    if command -v iptables >/dev/null 2>&1; then
        _fw_snapshot=$(iptables -S 2>/dev/null | grep -i idleleo || true)
    fi

    # Snapshot ACME/cron state for TLS mode. Detection AND the saved task line
    # must match ONLY the project-managed script path. Whether the project cron
    # exists is decided solely by the user crontab containing the exact project
    # script path — never by the presence of $HOME/.acme.sh/acme.sh (which may
    # be missing or relocated while the project cron still exists). The line
    # backup is fail-closed: a failed or empty write invalidates the whole
    # backup, so an "acme_cron=yes" manifest can never point at a missing/empty
    # cron file.
    local _acme_cron="no"
    local _acme_marker
    _acme_marker=$(acme_cron_match_pattern)
    if [[ ${_source_mode} == "TLS" ]]; then
        if crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
            _acme_cron="yes"
            _meta_err=0
            if ! crontab -l 2>/dev/null | grep -F -- "${_acme_marker}" > "${backup_dir}/acme_cron_line.txt" 2>/dev/null; then
                _meta_err=1
            fi
            [[ -s "${backup_dir}/acme_cron_line.txt" ]] || _meta_err=1
        fi
    fi

    # Record file existence manifest. Use a brace group redirected to file
    # (NOT var=$(...)>file, which writes an empty file — the command
    # substitution captures stdout into the var, leaving the redirection
    # target empty).
    {
        echo "{"
        # NOTE: the $(...) command substitutions must NOT escape the inner
        # quotes (\"...\"). GNU bash 3.2 treats `\"` inside a command
        # substitution as a literal backslash+quote, so the path becomes
        # `\"/path\"` and the -f/-d test always fails. Use plain quotes so the
        # manifest records file existence correctly on all bash versions.
        echo "  \"files\": {"
        echo "    \"install_config.json\": $( [[ -f "${xray_install_config_file}" ]] && echo true || echo false),"
        echo "    \"xray_conf_dir\": $( [[ -d "${xray_conf_dir}" ]] && echo true || echo false),"
        echo "    \"nginx_conf_dir\": $( [[ -d "${nginx_conf_dir}" ]] && echo true || echo false),"
        echo "    \"nginx_main_conf\": $( [[ -f "${_nginx_main_conf}" ]] && echo true || echo false),"
        echo "    \"cert_dir\": $( [[ -d "${ssl_chainpath}" ]] && echo true || echo false),"
        echo "    \"info_dir\": $( [[ -d "${idleleo_dir}/info" ]] && echo true || echo false),"
        echo "    \"conf_dir\": $( [[ -d "${idleleo_conf_dir}" ]] && echo true || echo false),"
        echo "    \"managed_ports.json\": $( [[ -f "${managed_ports_file}" ]] && echo true || echo false),"
        echo "    \"xray.service\": $( [[ -f "${xray_systemd_file}" ]] && echo true || echo false),"
        echo "    \"nginx.service\": $( [[ -f "${nginx_systemd_file}" ]] && echo true || echo false),"
        echo "    \"xray_info.inf\": $( [[ -f "${xray_info_file}" ]] && echo true || echo false),"
        echo "    \"xray_info_clash.yaml\": $( [[ -f "${_clash_yaml}" ]] && echo true || echo false)"
        echo "  },"
        echo "  \"source_tls_mode\": \"${_source_mode}\","
        echo "  \"source_transport_mode\": \"${transport_mode:-}\","
        echo "  \"multi_user\": \"$(detect_multi_user_from_xray_conf)\","
        echo "  \"reality_clients\": $(count_reality_clients_in_xray_conf),"
        echo "  \"uuid_set\": $(extract_uuid_set_from_xray_conf | jq -R . | jq -s .),"
        echo "  \"xray_active\": \"${_xray_active}\","
        echo "  \"nginx_active\": \"${_nginx_active}\","
        echo "  \"xray_enabled\": \"${_xray_enabled}\","
        echo "  \"nginx_enabled\": \"${_nginx_enabled}\","
        echo "  \"acme_cron\": \"${_acme_cron}\","
        echo "  \"fw_snapshot\": $(jq -Rn --arg v "${_fw_snapshot}" '$v' 2>/dev/null || echo '""')"
        echo "}"
    } > "${backup_dir}/pre_reinstall_state.json"

    # Generate SHA256 manifest for integrity verification.
    # Use relative paths so verification does not depend on the original
    # absolute backup_dir path (which may differ if the snapshot is moved).
    #
    # Fail-closed metadata validation: a backup whose state manifest is
    # missing/corrupt, or whose checksum list is missing/empty/incomplete, is
    # useless for restore. Any such failure deletes this incomplete backup and
    # returns 1 so the upper layer stops reconfiguration before any change.
    if ! jq empty "${backup_dir}/pre_reinstall_state.json" >/dev/null 2>&1; then
        _meta_err=1
    fi
    ( cd "${backup_dir}" && find . -type f ! -name "sha256sums.txt" -exec sha256sum {} \; 2>/dev/null ) > "${backup_dir}/sha256sums.txt" || _meta_err=1
    [[ -s "${backup_dir}/sha256sums.txt" ]] || _meta_err=1
    grep -q "pre_reinstall_state.json" "${backup_dir}/sha256sums.txt" 2>/dev/null || _meta_err=1
    if [[ ${_meta_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份元数据校验失败, 中止重配置") ${Font}"
        rm -rf "${backup_dir}"
        return 1
    fi

    echo "${backup_dir}"
}

# Restore a previously created reinstall backup.
# Args: <backup_dir>
# Returns 1 on any critical restore failure. Does NOT output "已恢复" on failure.
reinstall_backup_restore() {
    local backup_dir="$1"
    [[ -z "${backup_dir}" || ! -d "${backup_dir}" ]] && return 1

    log_echo "${Warning} ${YellowBG} $(gettext "部署失败, 正在恢复原配置") ${Font}"

    local _restore_err=0

    # Verify backup integrity via SHA256 before restoring (strict fail-closed).
    # Refuses to restore on: missing manifest, missing file, hash mismatch,
    # sha256sum failure, or unparseable manifest line (--strict).
    if [[ ! -f "${backup_dir}/sha256sums.txt" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性清单缺失, 拒绝恢复") ${Font}"
        return 1
    fi
    if ! ( cd "${backup_dir}" && sha256sum --strict -c sha256sums.txt >/dev/null 2>&1 ); then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性校验失败, 拒绝恢复") ${Font}"
        return 1
    fi

    # Stop all services to avoid races during restoration.
    service_stop 2>/dev/null || true

    # Read the pre-reinstall manifest once. It records which managed paths
    # existed before the deploy, so restore can delete anything the failed
    # deploy created that was not there before (P2 manifest-driven cleanup).
    local _pre_state="${backup_dir}/pre_reinstall_state.json"

    # Whether a managed path existed before the reinstall.
    # Returns "true"/"false". Defaults to "true" (restore, not delete) so an
    # unknown path is never wrongly deleted.
    # NOTE: must NOT use `// true` on the value — jq treats an explicit `false`
    # as falsy, so `false // true` yields `true` and a file recorded as absent
    # would be wrongly restored. Only an ABSENT field/-missing manifest should
    # default to "true".
    _manifest_existed() {
        local key="$1"
        if [[ -f "${_pre_state}" ]]; then
            jq -r --arg k "${key}" \
                'if (has("files") and (.files[$k] == false)) then "false" else "true" end' \
                "${_pre_state}" 2>/dev/null || echo true
        else
            echo true
        fi
    }

    # Restore critical files according to the manifest: paths that existed
    # before are restored from backup; paths that did NOT exist before (created
    # by the failed deploy) are removed. Only script-managed paths are touched.
    if [[ "$(_manifest_existed install_config.json)" == "true" ]]; then
        cp -a "${backup_dir}/install_config.json" "${xray_install_config_file}" 2>/dev/null || _restore_err=1
    else
        # Deleting a path that did not exist before must NOT fail the restore
        # when it (or its parent dir) does not exist — e.g. the failed deploy
        # never created it, or the parent was also removed. Only a real error
        # that leaves the path present should count as a failure.
        rm -f "${xray_install_config_file}" 2>/dev/null || [[ ! -e "${xray_install_config_file}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed xray_conf_dir)" == "true" ]]; then
        rm -rf "${xray_conf_dir}" 2>/dev/null
        cp -a "${backup_dir}/xray" "${xray_conf_dir}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${xray_conf_dir}" 2>/dev/null || [[ ! -e "${xray_conf_dir}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed nginx_conf_dir)" == "true" ]]; then
        rm -rf "${nginx_conf_dir}" 2>/dev/null
        cp -a "${backup_dir}/nginx" "${nginx_conf_dir}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${nginx_conf_dir}" 2>/dev/null || [[ ! -e "${nginx_conf_dir}" ]] || _restore_err=1
    fi
    # Restore/delete main nginx.conf (outside the project conf dir).
    local _nginx_main_conf="/usr/local/nginx/conf/nginx.conf"
    if [[ "$(_manifest_existed nginx_main_conf)" == "true" ]]; then
        cp -a "${backup_dir}/nginx.conf" "${_nginx_main_conf}" 2>/dev/null || _restore_err=1
    else
        rm -f "${_nginx_main_conf}" 2>/dev/null || [[ ! -e "${_nginx_main_conf}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed cert_dir)" == "true" ]]; then
        rm -rf "${ssl_chainpath}" 2>/dev/null
        cp -a "${backup_dir}/cert" "${ssl_chainpath}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${ssl_chainpath}" 2>/dev/null || [[ ! -e "${ssl_chainpath}" ]] || _restore_err=1
    fi
    # Project-owned directory tree created by create_directory that is not
    # separately backed up: idleleo_conf_dir (parent of xray/nginx conf dirs)
    # and idleleo_dir/info (share-info files). Restore the true source state:
    # a dir that did not exist before the failed deploy must be removed.
    if [[ "$(_manifest_existed conf_dir)" != "true" ]]; then
        rm -rf "${idleleo_conf_dir}" 2>/dev/null || [[ ! -e "${idleleo_conf_dir}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed info_dir)" != "true" ]]; then
        rm -rf "${idleleo_dir}/info" 2>/dev/null || [[ ! -e "${idleleo_dir}/info" ]] || _restore_err=1
    fi

    # Firewall transaction rollback: reverse the exact rules this deploy
    # changed, even if managed_ports.json was not yet written with the new set.
    # Both "yes" (forward succeeded) and "pending" (forward started but the
    # immediate reverse was not confirmed) must be reversed here; "no" means
    # nothing was modified or it was already fully reversed.
    if [[ "${_reinstall_firewall_changed:-}" == "yes" || "${_reinstall_firewall_changed:-}" == "pending" ]]; then
        if ! reconcile_managed_firewall \
            "${_reinstall_firewall_new_ports}" \
            "${_reinstall_firewall_old_ports}"; then
            log_echo "${Error} ${RedBG} $(gettext "防火墙规则回滚失败") ${Font}"
            _restore_err=1
        else
            _reinstall_firewall_changed="no"
        fi
    fi
    # Restore or delete managed_ports.json per the manifest.
    if [[ "$(_manifest_existed managed_ports.json)" == "true" ]]; then
        cp -a "${backup_dir}/managed_ports.json" "${managed_ports_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${managed_ports_file}" 2>/dev/null || [[ ! -e "${managed_ports_file}" ]] || _restore_err=1
    fi

    # Restore/delete per-unit systemd files per the manifest. A unit that did
    # NOT exist on the source system must be removed (the failed deploy created
    # it), and must never be enable/disable/start/stop'd afterwards — systemd
    # fails those commands for a missing unit, which would wrongly turn a
    # correct restore into a reported failure.
    local _xray_unit_existed _nginx_unit_existed
    _xray_unit_existed=$(_manifest_existed xray.service)
    _nginx_unit_existed=$(_manifest_existed nginx.service)
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        cp -a "${backup_dir}/xray.service" "${xray_systemd_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_systemd_file}" 2>/dev/null || [[ ! -e "${xray_systemd_file}" ]] || _restore_err=1
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        cp -a "${backup_dir}/nginx.service" "${nginx_systemd_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${nginx_systemd_file}" 2>/dev/null || [[ ! -e "${nginx_systemd_file}" ]] || _restore_err=1
    fi
    # Restore/delete share info — use canonical xray_info_file path and Clash YAML.
    if [[ "$(_manifest_existed xray_info.inf)" == "true" ]]; then
        cp -a "${backup_dir}/xray_info.inf" "${xray_info_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_info_file}" 2>/dev/null || [[ ! -e "${xray_info_file}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed xray_info_clash.yaml)" == "true" ]]; then
        cp -a "${backup_dir}/xray_info_clash.yaml" "${xray_info_file%.*}_clash.yaml" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_info_file%.*}_clash.yaml" 2>/dev/null || [[ ! -e "${xray_info_file%.*}_clash.yaml" ]] || _restore_err=1
    fi

    systemctl daemon-reload 2>/dev/null || _restore_err=1

    # Reload config state from restored file.
    info_extraction_all=$(jq -rc . "${xray_install_config_file}" 2>/dev/null || echo "{}")
    declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate 2>/dev/null || true

    # Restore source mode variables from backup state so service_start/stop
    # below uses the SOURCE mode (not the failed target mode).
    if [[ -f "${_pre_state}" ]]; then
        local _src_mode
        _src_mode=$(jq -r '.source_tls_mode // empty' "${_pre_state}" 2>/dev/null)
        [[ -n "${_src_mode}" ]] && old_tls_mode="${_src_mode}" && tls_mode="${_src_mode}"
        local _src_transport
        _src_transport=$(jq -r '.source_transport_mode // empty' "${_pre_state}" 2>/dev/null)
        [[ -n "${_src_transport}" ]] && transport_mode="${_src_transport}"
    fi

    # Restore service active/enabled state per the pre-reinstall snapshot.
    # Units that did NOT exist on the source system are NEVER
    # enable/disable/start/stop'd — systemd fails those commands for a missing
    # unit, which would wrongly turn a correct restore into a reported failure.
    local _pre_xray_active="no" _pre_nginx_active="no"
    local _pre_xray_enabled="no" _pre_nginx_enabled="no"
    if [[ -f "${_pre_state}" ]]; then
        _pre_xray_active=$(jq -r '.xray_active // "no"' "${_pre_state}" 2>/dev/null)
        _pre_nginx_active=$(jq -r '.nginx_active // "no"' "${_pre_state}" 2>/dev/null)
        _pre_xray_enabled=$(jq -r '.xray_enabled // "no"' "${_pre_state}" 2>/dev/null)
        _pre_nginx_enabled=$(jq -r '.nginx_enabled // "no"' "${_pre_state}" 2>/dev/null)
    fi
    # Enabled state — propagate failures instead of swallowing with || true.
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        if [[ "${_pre_xray_enabled}" == "yes" ]]; then
            systemctl enable xray 2>/dev/null || _restore_err=1
        else
            systemctl disable xray 2>/dev/null || _restore_err=1
        fi
        if [[ "${_pre_xray_active}" == "yes" ]]; then
            systemctl start xray 2>/dev/null || _restore_err=1
        else
            systemctl stop xray 2>/dev/null || _restore_err=1
        fi
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        if [[ "${_pre_nginx_enabled}" == "yes" ]]; then
            systemctl enable nginx 2>/dev/null || _restore_err=1
        else
            systemctl disable nginx 2>/dev/null || _restore_err=1
        fi
        if [[ "${_pre_nginx_active}" == "yes" ]]; then
            systemctl start nginx 2>/dev/null || _restore_err=1
        else
            systemctl stop nginx 2>/dev/null || _restore_err=1
        fi
    fi

    if [[ ${_restore_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "恢复未完全成功, 请手动检查") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
        return 1
    fi

    # Bidirectional verification: active AND enabled states must match the
    # snapshot for units that existed before. Units that did NOT exist before
    # must be gone from systemd entirely — if systemd still sees them as
    # loaded/active/enabled, the restore must fail and report it clearly.
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        if [[ "${_pre_xray_active}" == "yes" ]] && ! systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后未运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_active}" == "no" ]] && systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍在运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_enabled}" == "yes" ]] && ! systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后未启用") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_enabled}" == "no" ]] && systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍启用") ${Font}"
            _restore_err=1
        fi
    else
        if systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍被 systemd 加载为 active, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
        if systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍为 enabled, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        if [[ "${_pre_nginx_active}" == "yes" ]] && ! systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后未运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_active}" == "no" ]] && systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍在运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_enabled}" == "yes" ]] && ! systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后未启用") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_enabled}" == "no" ]] && systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍启用") ${Font}"
            _restore_err=1
        fi
    else
        if systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍被 systemd 加载为 active, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
        if systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍为 enabled, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
    fi

    # Restore ACME/cron state if it was recorded as active before reinstall.
    # All detection, dedup and verification below matches the project's exact
    # managed script path so user-owned ssl_update.sh tasks are never touched.
    local _pre_acme_cron="no"
    local _acme_marker
    _acme_marker=$(acme_cron_match_pattern)
    if [[ -f "${_pre_state}" ]]; then
        _pre_acme_cron=$(jq -r '.acme_cron // "no"' "${_pre_state}" 2>/dev/null)
    fi
    if [[ "${_pre_acme_cron}" == "yes" ]]; then
        # Restore via the standard crontab interface (works on Debian, CentOS,
        # Rocky, AlmaLinux alike — no spool path assumptions). Only append if
        # the managed ssl_update.sh line is missing, to avoid duplicates.
        if ! crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
            if [[ -s "${backup_dir}/acme_cron_line.txt" ]]; then
                {
                    crontab -l 2>/dev/null || true
                    cat "${backup_dir}/acme_cron_line.txt" 2>/dev/null
                } | crontab - || _restore_err=1
                # Verify the restore actually took effect.
                if ! crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
                    log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务未能恢复, 请手动检查") ${Font}"
                    _restore_err=1
                fi
            else
                log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务未能恢复, 请手动检查") ${Font}"
                _restore_err=1
            fi
        fi
    elif [[ "${_pre_acme_cron}" == "no" ]]; then
        # The source system had NO script-managed ssl_update.sh cron. A failed
        # deploy may have added one — remove only the line matching the exact
        # project path while preserving every other user crontab line, using
        # the standard `crontab -l` / filter / `crontab -` interface (never the
        # spool files). A failed write or a leftover line fails the restore.
        local _cron_before="" _cron_filtered=""
        _cron_before=$(crontab -l 2>/dev/null || true)
        if printf '%s\n' "${_cron_before}" | grep -Fq -- "${_acme_marker}"; then
            # grep -v exits 1 when it drops the LAST line (crontab becomes
            # empty) — that is a successful removal, not a failure.
            _cron_filtered=$(printf '%s\n' "${_cron_before}" | grep -Fv -- "${_acme_marker}" || true)
            if [[ -n "${_cron_filtered}" ]]; then
                printf '%s\n' "${_cron_filtered}" | crontab - 2>/dev/null || _restore_err=1
            else
                # Nothing left: install an empty crontab.
                : | crontab - 2>/dev/null || _restore_err=1
            fi
            if printf '%s\n' "$(crontab -l 2>/dev/null)" | grep -Fq -- "${_acme_marker}"; then
                log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务删除后仍存在, 请手动检查") ${Font}"
                _restore_err=1
            fi
        fi
    fi

    if [[ ${_restore_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "恢复后验证失败, 请手动检查") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
        return 1
    fi

    # Rollback succeeded — reset the firewall transaction for the next attempt.
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"

    log_echo "${OK} ${GreenBG} $(gettext "已恢复原配置") ${Font}"
    return 0
}

# Validate the newly deployed config. Returns non-zero if any check fails.
reinstall_validate_deploy() {
    if [[ -f "${xray_conf}" ]] && ! ${xray_bin_dir}/xray run -test -config "${xray_conf}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置测试失败") ${Font}"
        return 1
    fi
    if [[ -x "${nginx_dir}/sbin/nginx" ]] && [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if ! "${nginx_dir}/sbin/nginx" -t >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 配置测试失败") ${Font}"
            return 1
        fi
    fi
    if ! systemctl is-active --quiet xray 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 服务未运行") ${Font}"
        return 1
    fi
    if [[ -x "${nginx_dir}/sbin/nginx" ]] && [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if ! systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务未运行") ${Font}"
            return 1
        fi
    fi
    return 0
}

# Verify user identity set was preserved across a keep-config reinstall.
# Args: <backup_dir>
# Returns 1 if UUID set changed. Skipped for mode_switch and standard_rebuild
# since those operations legitimately change the user set.
reinstall_verify_preservation() {
    local backup_dir="$1"
    [[ -z "${backup_dir}" || ! -f "${backup_dir}/pre_reinstall_state.json" ]] && return 0

    # Skip preservation check for mode_switch and standard_rebuild — these
    # Operations legitimately change the user set.
    case "${reinstall_operation}" in
        mode_switch|standard_rebuild|clean_install)
            return 0
            ;;
    esac

    # For keep_config: verify UUID set is unchanged.
    local pre_uuids post_uuids
    pre_uuids=$(jq -r '.uuid_set[]?' "${backup_dir}/pre_reinstall_state.json" 2>/dev/null | sort)
    post_uuids=$(extract_uuid_set_from_xray_conf | sort)

    if [[ "${pre_uuids}" != "${post_uuids}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "用户 UUID 集合发生变化, 将恢复原配置") ${Font}"
        return 1
    fi
    return 0
}

# Final safety gate called at the end of every install_xray_* path.
# Validates the freshly deployed config and verifies user counts were
# preserved across the reinstall. On any failure, restores the backup
# and returns non-zero so the caller can surface the error.
# No-op when no backup was created (fresh install or test mode).
reinstall_finalize() {
    [[ -z "${_reinstall_backup_dir}" ]] && return 0
    if ! reinstall_validate_deploy; then
        if ! reinstall_backup_restore "${_reinstall_backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "最终验证失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${_reinstall_backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
        return 1
    fi
    if ! reinstall_verify_preservation "${_reinstall_backup_dir}"; then
        if ! reinstall_backup_restore "${_reinstall_backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "最终验证失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${_reinstall_backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
        return 1
    fi
    _reinstall_backup_dir=""
    return 0
}

menu_clear() {
    if [[ -t 1 && -n ${TERM:-} && ${TERM} != "dumb" ]]; then
        clear
    else
        echo
    fi
}

menu_prepare_width() {
    local terminal_columns="" max_box_width=60

    if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        terminal_columns=$(tput cols 2>/dev/null || true)
    fi
    if ! [[ ${terminal_columns} =~ ^[0-9]+$ ]]; then
        terminal_columns="${COLUMNS:-}"
    fi
    if ! [[ ${terminal_columns} =~ ^[0-9]+$ ]] && [[ -t 1 ]]; then
        terminal_columns=$(stty size 2>/dev/null | awk '{print $2}')
    fi
    [[ ${terminal_columns} =~ ^[0-9]+$ ]] || terminal_columns=80

    MENU_BOX_WIDTH=$((terminal_columns - 4))
    ((MENU_BOX_WIDTH > max_box_width)) && MENU_BOX_WIDTH=${max_box_width}
    if ((MENU_BOX_WIDTH < 52)); then
        MENU_BOX_WIDTH=$((terminal_columns - 2))
    fi
    ((MENU_BOX_WIDTH < 20)) && MENU_BOX_WIDTH=20
}

menu_ensure_width() {
    [[ ${MENU_BOX_WIDTH:-} =~ ^[0-9]+$ ]] || menu_prepare_width
}

menu_visible_width() {
    local plain_text visible_width
    plain_text=$(printf '%b' "$1" | sed $'s/\033\\[[0-9;]*m//g')
    if ! visible_width=$(printf '%s' "${plain_text}" | LC_ALL=C.UTF-8 wc -L 2>/dev/null); then
        visible_width=$(printf '%s' "${plain_text}" | wc -L 2>/dev/null)
    fi
    visible_width=${visible_width//[[:space:]]/}
    if [[ ${visible_width} =~ ^[0-9]+$ ]]; then
        printf '%s' "${visible_width}"
    else
        printf '%s' "${#plain_text}"
    fi
}

menu_repeat() {
    local character="$1" count="$2" index
    for ((index = 0; index < count; index++)); do
        printf '%s' "${character}"
    done
}

menu_title() {
    local title="$1" title_width line_count
    menu_prepare_width
    title_width=$(menu_visible_width "${title}")
    line_count=$((MENU_BOX_WIDTH - title_width - 5))
    ((line_count < 1)) && line_count=1

    printf '%b╭─ %b%b %b' "${GreenW}" "${Font}" "${title}" "${GreenW}"
    menu_repeat '─' "${line_count}"
    printf '╮%b\n' "${Font}"
}

menu_footer() {
    menu_ensure_width
    printf '%b╰' "${GreenW}"
    menu_repeat '─' "$((MENU_BOX_WIDTH - 2))"
    printf '╯%b\n' "${Font}"
}

menu_divider() {
    local title="$1" title_width line_count
    menu_ensure_width
    title_width=$(menu_visible_width "${title}")
    line_count=$((MENU_BOX_WIDTH - title_width - 5))
    ((line_count < 1)) && line_count=1

    printf '%b├─ %b%b %b' "${GreenW}" "${Font}" "${title}" "${GreenW}"
    menu_repeat '─' "${line_count}"
    printf '┤%b\n' "${Font}"
}

menu_row() {
    local content="$1" content_width padding
    menu_ensure_width
    content_width=$(menu_visible_width "${content}")
    padding=$((MENU_BOX_WIDTH - content_width - 4))
    ((padding < 0)) && padding=0

    printf '%b│%b %b' "${GreenW}" "${Font}" "${content}"
    printf '%*s' "${padding}" ''
    printf '%b │%b\n' "${GreenW}" "${Font}"
}

menu_fields() {
    local field current="" candidate candidate_width max_width
    menu_ensure_width
    max_width=$((MENU_BOX_WIDTH - 4))

    for field in "$@"; do
        if [[ -z ${current} ]]; then
            current="${field}"
            continue
        fi
        candidate="${current}  ·  ${field}"
        candidate_width=$(menu_visible_width "${candidate}")
        if ((candidate_width <= max_width)); then
            current="${candidate}"
        else
            menu_row "${current}"
            current="${field}"
        fi
    done
    [[ -n ${current} ]] && menu_row "${current}"
}

menu_blank() {
    menu_row ""
}

menu_item() {
    local item
    printf -v item '%b%2s.%b %s' "${Green}" "$1" "${Font}" "$2"
    menu_row "${item}"
}

menu_pause() {
    echo
    read -rp "$(gettext "回到菜单") [Enter] " _ || true
}

menu_read() {
    local target_var="$1"
    local max_value="$2"
    read_optimize "$(gettext "请输入选项"): " "${target_var}" "NULL" 0 "${max_value}" "$(gettext "请输入有效的数字")!"
}

menu_submenu_begin() {
    menu_clear
    menu_title "$1"
    menu_blank
}

menu_action() {
    case $1 in
    0)
        update_sh
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    1)
        xray_update
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    2)
        echo
        log_echo "${Red}[$(gettext "不建议")]${Font} $(gettext "频繁更新 Nginx, 请确认 Nginx 有更新的必要")!"
        countdown "$(gettext "开始更新")!"
        nginx_update
        exec "${BASH:-bash}" "${idleleo}"
        ;;
     3)
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        local install_rc=$?
        if [[ ${install_rc} -eq 0 ]]; then
            exec "${BASH:-bash}" "${idleleo}"
        fi
        if [[ ${install_rc} -eq 2 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
        fi
        return "${install_rc}"
        ;;
     4)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        local install_rc=$?
        if [[ ${install_rc} -eq 0 ]]; then
            exec "${BASH:-bash}" "${idleleo}"
        fi
        if [[ ${install_rc} -eq 2 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
        fi
        return "${install_rc}"
        ;;
     5)
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            local install_rc=$?
            if [[ ${install_rc} -eq 0 ]]; then
                exec "${BASH:-bash}" "${idleleo}"
            fi
            if [[ ${install_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
            else
                log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
            fi
            return "${install_rc}"
            ;;
        *) ;;
        esac
        ;;
     6)
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式仅用于流量中转, 不建议在其他情况下使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r xtlsonly_fq
        case $xtlsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="XTLS ONLY"
            tls_mode="XTLS"
            install_xray_xtls_only
            local install_rc=$?
            if [[ ${install_rc} -eq 0 ]]; then
                exec "${BASH:-bash}" "${idleleo}"
            fi
            if [[ ${install_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
            else
                log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
            fi
            return "${install_rc}"
            ;;
        *) ;;
        esac
        ;;
    7)
        reset_UUID
        judge -r "$(gettext "变更") UUIDv5/$(gettext "映射字符串")"
        menu_pause
        ;;
    8)
        reset_port
        judge -r "$(gettext "变更") port"
        menu_pause
        ;;
    9)
        reset_target
        judge -r "$(gettext "变更") target"
        menu_pause
        ;;
    10)
        tls_type
        judge -r "$(gettext "变更") TLS $(gettext "版本")"
        menu_pause
        ;;
    11)
        nginx_upstream_server_set
        menu_pause
        ;;
    12)
        nginx_servernames_server_set
        menu_pause
        ;;
    39)
        reset_sni_guard_policy
        judge -r "$(gettext "变更") SNI Guard"
        menu_pause
        ;;
    13)
        show_user
        menu_pause
        ;;
    14)
        if service_stop; then
            add_user && service_start
        fi
        menu_pause
        ;;
    15)
        if service_stop; then
            remove_user && service_start
        fi
        menu_pause
        ;;
    16)
        clear
        show_access_log
        menu_pause
        ;;
    17)
        clear
        show_error_log
        menu_pause
        ;;
    18)
        clear
        basic_information
        install_link_image
        show_information
        menu_pause
        ;;
    19)
        clear
        monitor_traffic_with_iftop
        menu_pause
        ;;
    20)
        service_restart
        check_program
        check_xray_local_connect
        menu_pause
        ;;
    21)
        if service_start; then
            check_program
            check_xray_local_connect
        else
            log_echo "${Error} ${RedBG} $(gettext "所有服务") $(gettext "启动") $(gettext "失败") ${Font}"
        fi
        menu_pause
        ;;
    22)
        if service_stop; then
            check_program
            check_xray_local_connect
        else
            log_echo "${Error} ${RedBG} $(gettext "所有服务") $(gettext "停止") $(gettext "失败") ${Font}"
        fi
        menu_pause
        ;;
    23)
        if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        menu_pause
        ;;
    24)
        check_cert_status
        menu_pause
        ;;
    25)
        cert_update_manuel
        menu_pause
        ;;
    26)
        acme_cron_update
        menu_pause
        ;;
    27)
        auto_update
        menu_pause
        ;;
    28)
        clear
        bbr_boost_sh
        menu_pause
        ;;
    29)
        set_fail2ban
        ;;
    30)
        xray_status_add
        menu_pause
        ;;
    31)
        set_traffic_blocker
        ;;
    32)
        clean_logs
        menu_pause
        ;;
    33)
        clear
        read -r -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        local superspeed_script="${idleleo_dir}/tmp/superspeed.sh"
        if download_script_file "https://cdn.jsdelivr.net/gh/hello-yunshu/superspeed@master/superspeed.sh" "$superspeed_script"; then
            bash "$superspeed_script"
            rm -f "$superspeed_script"
        else
            log_echo "${Error} ${RedBG} $(gettext "网速测试脚本下载失败") ${Font}"
        fi
        read -r -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        menu_pause
        ;;
    34)
        backup_directories
        menu_pause
        ;;
    35)
        restore_directories
        menu_pause
        ;;
    36)
        uninstall_all
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    37)
        delete_tls_key_and_crt
        rm -rf "${ssl_chainpath:?}"/*
        menu_pause
        ;;
    38)
        exit 0
        ;;
    99)
        set_language
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    esac
}

# Fourth-level menu: choose transport protocol (ws/gRPC/xHTTP).
# Sets transport_mode and returns 0 on success, 1 on "0. return".
menu_choose_transport() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "选择传输协议")"
        menu_item 1 "ws"
        menu_item 2 "gRPC"
        menu_item 3 "xHTTP"
        menu_item 4 "ws+xHTTP"
        menu_item 5 "ws+gRPC+xHTTP"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return 1 ;;
            1) transport_mode="onlyws"; return 0 ;;
            2) transport_mode="onlygRPC"; return 0 ;;
            3) transport_mode="onlyxhttp"; return 0 ;;
            4) transport_mode="wsxhttp"; return 0 ;;
            5) transport_mode="wsgRPCxhttp"; return 0 ;;
        esac
    done
}

# Third-level menu: Reality deployment methods.
menu_install_reality() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "Reality 部署方式")"
        menu_item 1 "Reality + Nginx $(gettext "前置保护")($(gettext "推荐"))"
        menu_item 2 "$(gettext "标准") Reality"
        menu_item 3 "Reality + ws/gRPC/xHTTP"
        menu_item 4 "Reality + ws/gRPC/xHTTP + Nginx"
        menu_item 5 "Reality $(gettext "负载均衡")($(gettext "高级"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return ;;
            1)
                reset_install_wizard_state
                install_profile="reality_nginx"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="reality_standard"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            3)
                reset_install_wizard_state
                install_profile="reality_transport"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            4)
                reset_install_wizard_state
                install_profile="reality_transport_nginx"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            5)
                menu_install_reality_balance_role || continue
                ;;
        esac
    done
}

# Fourth-level menu: Reality load-balancing role selection.
# Primary installs Nginx front-end + upstream; secondary only provides Reality backend.
menu_install_reality_balance_role() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "Reality 负载均衡角色")"
        menu_item 1 "$(gettext "主服务器")($(gettext "安装 Nginx"))"
        menu_item 2 "$(gettext "二级服务器")($(gettext "仅提供 Reality 后端"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return 1 ;;
            1)
                reset_install_wizard_state
                install_profile="reality_balance_primary"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="reality_balance_secondary"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
        esac
    done
}

# Third-level menu: ws/gRPC/xHTTP deployment methods.
menu_install_transport() {
    local menu_num
    while true; do
        menu_submenu_begin "ws/gRPC/xHTTP $(gettext "部署方式")"
        menu_item 1 "Nginx + TLS ($(gettext "推荐"))"
        menu_item 2 "ONLY ($(gettext "无 Nginx、无 TLS")，$(gettext "高级"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1)
                reset_install_wizard_state
                install_profile="transport_nginx_tls"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_ws_tls
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="transport_only"
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "ONLY 模式主要用于中转、负载均衡后端或已有上层代理的环境") ${Font}"
                log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r wsonly_fq
                case ${wsonly_fq:-} in
                    [yY][eE][sS] | [yY]) ;;
                    *) continue ;;
                esac
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_ws_only
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
        esac
    done
}

# Second-level menu: install wizard main (protocol category selection).
menu_install() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "安装向导")"
        menu_item 1 "Reality"
        menu_item 2 "ws/gRPC/xHTTP"
        menu_item 3 "XTLS ONLY ($(gettext "高级"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_install_reality ;;
            2) menu_install_transport ;;
            3)
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "此模式主要用于流量中转或特殊部署，不建议普通用户使用") ${Font}"
                log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r xtlsonly_fq
                case ${xtlsonly_fq:-} in
                    [yY][eE][sS] | [yY]) ;;
                    *) continue ;;
                esac
                reset_install_wizard_state
                install_profile="xtls_only"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_xtls_only
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
        esac
    done
}

menu_user_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "用户管理")"
        menu_item 1 "$(gettext "查看") Xray $(gettext "用户")"
        menu_item 2 "$(gettext "添加") Xray $(gettext "用户")"
        menu_item 3 "$(gettext "删除") Xray $(gettext "用户")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_action 13 ;;
            2) menu_action 14 ;;
            3) menu_action 15 ;;
        esac
    done
}

menu_connection_config() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "配置变更")"
        menu_item 1 "$(gettext "变更") UUIDv5/$(gettext "映射字符串")"
        menu_item 2 "$(gettext "变更") port"
        menu_item 3 "$(gettext "变更") target"
        menu_item 4 "$(gettext "变更") TLS $(gettext "版本")"
        menu_item 5 "$(gettext "变更") SNI Guard"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return ;;
            1) menu_action 7 ;;
            2) menu_action 8 ;;
            3) menu_action 9 ;;
            4) menu_action 10 ;;
            5) menu_action 39 ;;
        esac
    done
}

menu_nginx_config() {
    local menu_num
    while true; do
        menu_submenu_begin "Nginx $(gettext "配置")"
        menu_item 1 "$(gettext "负载均衡")"
        menu_item 2 "serverNames"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1) menu_action 11 ;;
            2) menu_action 12 ;;
        esac
    done
}

menu_config() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "配置变更")"
        menu_item 1 "$(gettext "用户管理")"
        menu_item 2 "$(gettext "配置变更")"
        menu_item 3 "Nginx $(gettext "配置")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_user_management ;;
            2) menu_connection_config ;;
            3) menu_nginx_config ;;
        esac
    done
}

menu_information() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "查看信息")"
        menu_item 1 "Xray $(gettext "配置信息")"
        menu_item 2 "Xray $(gettext "实时访问日志")"
        menu_item 3 "Xray $(gettext "实时错误日志")"
        menu_item 4 "port $(gettext "实时流量")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 18 ;;
            2) menu_action 16 ;;
            3) menu_action 17 ;;
            4) menu_action 19 ;;
        esac
    done
}

menu_service_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "服务相关")"
        menu_item 1 "$(gettext "重启") $(gettext "所有服务")"
        menu_item 2 "$(gettext "启动") $(gettext "所有服务")"
        menu_item 3 "$(gettext "停止") $(gettext "所有服务")"
        menu_item 4 "$(gettext "查看") $(gettext "所有服务")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 20 ;;
            2) menu_action 21 ;;
            3) menu_action 22 ;;
            4) menu_action 23 ;;
        esac
    done
}

menu_certificate_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "证书相关")"
        menu_item 1 "$(gettext "证书状态")"
        menu_item 2 "$(gettext "证书有效期")"
        menu_item 3 "$(gettext "证书自动更新")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_action 24 ;;
            2) menu_action 25 ;;
            3) menu_action 26 ;;
        esac
    done
}

menu_service_and_certificate() {
    local menu_num
    while true; do
        menu_submenu_begin "Xray / TLS"
        menu_item 1 "$(gettext "服务相关")"
        menu_item 2 "$(gettext "证书相关")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1) menu_service_management ;;
            2) menu_certificate_management ;;
        esac
    done
}

menu_update() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "更新向导")"
        menu_item 1 "$(gettext "更新") $(gettext "脚本")"
        menu_item 2 "$(gettext "更新") Xray"
        menu_item 3 "$(gettext "更新") Nginx"
        menu_item 4 "$(gettext "配置") $(gettext "自动更新")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 0 ;;
            2) menu_action 1 ;;
            3) menu_action 2 ;;
            4) menu_action 27 ;;
        esac
    done
}

menu_tools() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "其他选项")"
        menu_item 1 "TCP $(gettext "加速")"
        menu_item 2 "Fail2ban"
        menu_item 3 "Xray $(gettext "流量统计")"
        menu_item 4 "Xray $(gettext "流量阻断")"
        menu_item 5 "$(gettext "清除") $(gettext "日志文件")"
        menu_item 6 "$(gettext "服务器网速")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 6
        case $menu_num in
            0) return ;;
            1) menu_action 28 ;;
            2) menu_action 29 ;;
            3) menu_action 30 ;;
            4) menu_action 31 ;;
            5) menu_action 32 ;;
            6) menu_action 33 ;;
        esac
    done
}

menu_backup_and_uninstall() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "备份恢复")"
        menu_item 1 "$(gettext "备份") $(gettext "全部文件")"
        menu_item 2 "$(gettext "恢复") $(gettext "全部文件")"
        menu_item 3 "$(gettext "清空") $(gettext "证书文件")"
        menu_item 4 "$(gettext "卸载") $(gettext "脚本")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 34 ;;
            2) menu_action 35 ;;
            3) menu_action 37 ;;
            4) menu_action 36 ;;
        esac
    done
}

menu_main_header() {
    menu_clear
    menu_title "$(gettext "Xray 管理脚本") ${Red}[${shell_version}]${Font} ${shell_emoji}"
    local mode_field="$(gettext "当前模式"): ${shell_mode}"
    local language_field="$(gettext "当前语言"): ${LANG%.*}"
    local shell_version_field="$(gettext "脚本"): ${shell_need_update}"
    local xray_version_field="Xray: ${xray_need_update}"
    local nginx_version_field="Nginx: ${nginx_need_update}"
    local xray_status_field="Xray: ${xray_status}"
    local nginx_status_field="Nginx: ${nginx_status}"
    local connect_status_field="$(gettext "连通性"): ${xray_local_connect_status}"
    menu_fields "${mode_field}" "${language_field}"
    menu_divider "$(gettext "版本检测")"
    menu_fields "${shell_version_field}" "${xray_version_field}" "${nginx_version_field}"
    menu_divider "$(gettext "运行状态")"
    menu_fields "${xray_status_field}" "${nginx_status_field}" "${connect_status_field}"
    rxa_refresh_summary
    menu_divider "Rill Xray Agent"
    menu_fields "${RILL_XRAY_AGENT_HEADER_STATE}" "${RILL_XRAY_AGENT_HEADER_RUNTIME}" "${RILL_XRAY_AGENT_HEADER_ROUTE}"
    menu_footer
    log "${mode_field}  ·  ${language_field}"
    log "${shell_version_field}  ·  ${xray_version_field}  ·  ${nginx_version_field}"
    log "${xray_status_field}  ·  ${nginx_status_field}  ·  ${connect_status_field}"
    echo
    menu_title "$(gettext "Xray 管理菜单")"
    menu_blank
}

menu() {
    local menu_num
    while true; do
        menu_main_header
        menu_item 1 "$(gettext "安装向导")"
        menu_item 2 "$(gettext "配置变更")"
        menu_item 3 "$(gettext "查看信息")"
        menu_item 4 "Xray / TLS"
        menu_item 5 "$(gettext "更新向导")"
        menu_item 6 "$(gettext "其他选项")"
        menu_item 7 "$(gettext "备份恢复")"
        menu_item 8 "$(gettext "修改语言") / Language"
        menu_item 9 "Rill Xray Agent"
        menu_blank
        menu_item 0 "$(gettext "退出")"
        menu_footer
        menu_read menu_num 9
        case $menu_num in
            0) exit 0 ;;
            1) menu_install ;;
            2) menu_config ;;
            3) menu_information ;;
            4) menu_service_and_certificate ;;
            5) menu_update ;;
            6) menu_tools ;;
            7) menu_backup_and_uninstall ;;
            8) menu_action 99 ;;
            9) rxa_menu ;;
        esac
    done
}

is_offline_safe_command() {
    case "${1:-}" in
        -h|--help|--purge|--uninstall|-s|--show|\
        --service-start|--service-stop|--service-restart|\
        --access-log|--error-log|--backup|\
        --rill-agent|--rill-agent-status|--rill-agent-safe-disable|--rill-agent-verify|--rill-agent-uninstall)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

dispatch_offline_safe_command() {
    case "${1:-}" in
        -h|--help) show_help ;;
        --purge|--uninstall) uninstall_all ;;
        -s|--show)
            judge_mode
            basic_information
            install_link_image
            show_information
            ;;
        --service-start) service_start ;;
        --service-stop) service_stop ;;
        --service-restart) service_restart ;;
        --access-log) show_access_log ;;
        --error-log) show_error_log ;;
        --backup) backup_directories ;;
        --rill-agent) rxa_menu ;;
        --rill-agent-status) rxa_dispatch status ;;
        --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;
        --rill-agent-verify) rxa_dispatch verify ;;
        --rill-agent-uninstall) rxa_dispatch uninstall ;;
        *) return 1 ;;
    esac
}

harden_config_permissions_if_needed() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_sni_guard_defaults || log_echo "${Warning} ${YellowBG} Reality SNI Guard $(gettext "配置修改") $(gettext "失败") ${Font}"
    fi
    harden_config_permissions
}

[[ "${_TEST_MODE:-0}" == "1" ]] && return 0

# -h/--help MUST be dispatched before init_language, check_file_integrity,
# version checks, network requests, and dependency installation. This ensures
# `bash install.sh --help` works with zero network access, zero package
# manager calls, and zero language file downloads — even when gettext is not
# installed, GitHub is unreachable, or the script is not yet installed.
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
esac

# Initialize language first so remaining offline commands get localized
# messages without requiring any network access.
init_language

# Offline-safe commands (--uninstall, service control, logs, backup)
# MUST be dispatched before check_file_integrity, which may attempt network
# downloads. This ensures these commands work even when GitHub is
# unreachable or the script is not yet installed locally.
if is_offline_safe_command "${1:-}"; then
    dispatch_offline_safe_command "$@"
    exit $?
fi

check_file_integrity
compat_migrate
judge_mode
check_online_version_connect
read_version || exit 1

harden_config_permissions_if_needed || exit 1
idleleo_commend
check_program
if [[ ${tls_mode} == "Reality" ]]; then
    ensure_reality_public_key || true
fi
check_xray_local_connect
list "$@"
