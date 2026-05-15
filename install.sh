#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#=================================================================
#	System Request: Debian 12+ / Ubuntu 24.04+ / Centos Stream 8+
#	Author:	yunyunshu
#	Dscription: Xray Onekey Management
#	Version: 2.8
#	Official document: hey.run
#=================================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
GreenW="\033[1;32m"
RedW="\033[1;31m"
#Yellow="\033[33m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
YellowBG="\033[43;30m"
Font="\033[0m"

#notification information
Info="${Green}[$(gettext "信息")]${Font}"
OK="${Green}[OK]${Font}"
Error="${RedW}[$(gettext "错误")]${Font}"
Warning="${RedW}[$(gettext "警告")]${Font}"

shell_version="2.12.2"
shell_mode="$(gettext "未安装")"
tls_mode="None"
transport_mode="None"
local_bin="/usr/local"
idleleo_dir="/etc/idleleo"
idleleo="${idleleo_dir}/install.sh"
idleleo_conf_dir="${idleleo_dir}/conf"
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
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
nginx_dir="${local_bin}/nginx"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
auto_update_file="${idleleo_dir}/auto_update.sh"
ssl_update_file="${idleleo_dir}/ssl_update.sh"
geo_update_file="${idleleo_dir}/geo_update.sh"
mf_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/fail2ban_manager.sh"
tb_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/traffic_blocker.sh"
fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"
shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
get_versions_all=""
_get_versions_loaded=0
load_versions() {
    if [[ ${_get_versions_loaded} -eq 0 ]]; then
        get_versions_all=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json 2>/dev/null)
        _get_versions_loaded=1
    fi
}
read_config_status=1
reality_add_more="off"
reality_add_nginx="off"
reality_add_balance="off"
old_config_status="off"
old_tls_mode="NULL"
random_num=$((RANDOM % 12 + 4))
[[ -f "${xray_qr_config_file}" ]] && info_extraction_all=$(jq -rc . "${xray_qr_config_file}")

is_ws_mode() {
    [[ ${transport_mode} == *ws* || ${transport_mode} == "all" ]]
}

is_grpc_mode() {
    [[ ${transport_mode} == *gRPC* || ${transport_mode} == "all" ]]
}

is_xhttp_mode() {
    [[ ${transport_mode} == *xhttp* || ${transport_mode} == "all" ]]
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
    jq "$@" "${config_file}" > "${config_file}.tmp"
    if [[ $? -ne 0 ]]; then
        rm -f "${config_file}.tmp"
        return 1
    fi
    if ! mv "${config_file}.tmp" "${config_file}"; then
        return 1
    fi
    if [[ "${config_file}" == "${xray_qr_config_file}" ]]; then
        info_extraction_all=$(jq -rc . "${config_file}" 2>/dev/null) || return 1
        declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    fi
    return 0
}

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

check_system() {
    if [[ "${ID}" == "centos" || "${ID}" == "rocky" || "${ID}" == "almalinux" ]] && [[ ${VERSION_ID%%.*} -ge 8 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 12 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 24 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_qr_config_file}" ]]; then
            rm /var/lib/dpkg/lock || true
            dpkg --configure -a || true
            rm /var/lib/apt/lists/lock || true
            rm /var/cache/apt/archives/lock || true
            $INS update || true
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
    local version_file_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/languages/${lang_code}/LC_MESSAGES/version"

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
    local github_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/languages"

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

    log_echo "${OK} ${Green} $(gettext "语言文件更新完成") ${Font}"
}

init_language() {
    if ! command -v gettext >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "正在安装") gettext... ${Font}"
        pkg_install "gettext"
        if [ $? -ne 0 ]; then
            log_echo "${Error} ${RedBG} gettext $(gettext "安装失败"), $(gettext "将使用默认语言") ${Font}"
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
        source "${idleleo_dir}/language.conf"

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
    load_versions
    local result
    result=$(echo "${get_versions_all}" | jq -rc ".$1" 2>/dev/null)
    if [[ $? -ne 0 ]] || [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}"
        return 1
    fi
    echo "${result}"
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
    local prompt="$1" var_name="$2" default_value="${3:-NULL}" min_value="${4:-}" max_value="${5:-}" error_msg="${6:-$(gettext "值为空或超出范围, 请重新输入")!}"
    local user_input

    while true; do
        read -rp "$prompt" user_input

        if [[ -z $user_input ]]; then
            if [[ $default_value != "NULL" ]]; then
                user_input=$default_value
                break
            else
                log_echo "${Error} ${RedBG} $(gettext "值为空, 请重新输入")! ${Font}"
                continue
            fi
        fi

        if [[ -n $min_value ]] && [[ -n $max_value ]]; then
            if (( user_input < min_value )) || (( user_input > max_value )); then
                log_echo "${Error} ${RedBG} $error_msg ${Font}"
                continue
            fi
        fi
        break
    done

    printf -v "$var_name" "%s" "$user_input"
}

basic_optimization() {
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

create_directory() {
    if [[ ${tls_mode} != "None" ]] && [[ ${tls_mode} != "XTLS" ]]; then
        [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p "${nginx_conf_dir}"
    fi
    [[ ! -d "${ssl_chainpath}" ]] && mkdir -p "${ssl_chainpath}"
    [[ ! -d "${xray_conf_dir}" ]] && mkdir -p "${xray_conf_dir}"
    [[ ! -d "${idleleo_dir}/info" ]] && mkdir -p "${idleleo_dir}"/info
}

port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo
        log_echo "${GreenBG} $(gettext "确定端口") ${Font}"
        read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
        while [[ ${port} -eq 9443 || ${port} -eq 9403 ]] && [[ ${tls_mode} == "Reality" ]]; do
            echo -e "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
            read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
        done
    fi
}

transport_choose() {
    if [[ "on" != ${old_config_status} ]]; then
        echo
        log_echo "${GreenBG} $(gettext "请选择传输协议") ${Font}"
        echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
        echo "2: gRPC"
        echo "3: xHTTP"
        echo "4: ws+gRPC+xHTTP"
        local choose_network
        read_optimize "$(gettext "请输入"): " "choose_network" 1 1 4 "$(gettext "请输入有效的数字")!"
        case ${choose_network} in
        2)
            transport_mode="onlygRPC"
            ;;
        3)
            transport_mode="onlyxhttp"
            ;;
        4)
            transport_mode="all"
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
    case ${transport_mode} in
    onlyws) transport_label="ws";;
    onlygRPC) transport_label="gRPC";;
    onlyxhttp) transport_label="xHTTP";;
    all) transport_label="ws+gRPC+xHTTP";;
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
    if [[ "on" != ${old_config_status} ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否添加简单 ws/gRPC 协议 用于负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择")! ${Font}"
        read -r reality_add_more_fq
        case $reality_add_more_fq in
        [yY][eE][sS] | [yY])
            reality_add_more="on"
            transport_choose
            ws_inbound_port_set
            grpc_inbound_port_set
            xhttp_inbound_port_set
            ws_path_set
            grpc_path_set
            xhttp_path_set
            is_ws_mode && port_exist_check "${xport}"
            is_grpc_mode && port_exist_check "${gport}"
            is_xhttp_mode && port_exist_check "${xhttpport}"
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
    if [[ ${transport_mode} == "all" ]]; then
        artnet="ws/gRPC/xHTTP"
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if is_ws_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") ws inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") ws inbound_port ($(gettext "请勿与其他端口相同")!): " "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
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
    if [[ "on" != ${old_config_status} ]]; then
        if is_grpc_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") gRPC inbound_port ($(gettext "请勿与其他端口相同")!): " "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
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
    if [[ "on" != ${old_config_status} ]]; then
        if is_xhttp_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") xHTTP inbound_port ($(gettext "请勿与其他端口相同")!): " "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
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
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        if [[ ${tls_mode} == "TLS" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,80,${port} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,80,${port} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,80,${port} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,80,${port} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${tls_mode} == "XTLS" || ${tls_mode} == "Reality" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${port} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${port} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${port} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${port} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        fi
        if [[ ${transport_mode} == "onlyws" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${transport_mode} == "onlygRPC" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${transport_mode} == "onlyxhttp" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xhttpport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xhttpport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xhttpport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xhttpport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${transport_mode} == "all" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport},${gport},${xhttpport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport},${gport},${xhttpport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport},${gport},${xhttpport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport},${gport},${xhttpport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        fi
        if [[ "${ID}" == "centos" || "${ID}" == "rocky" || "${ID}" == "almalinux" ]]; then
            service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            service iptables restart 2>/dev/null || true
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") ${Font}"
        else
            netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") ${Font}"
        fi
        log_echo "${OK} ${GreenBG} $(gettext "开放防火墙相关端口") ${Font}"
        log_echo "${GreenBG} $(gettext "若修改配置, 请注意关闭防火墙相关端口") ${Font}"
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
                    read_optimize "$(gettext "请输入") ws $(gettext "伪装路径") ($(gettext "不需要")"/":)" "path" "NULL"
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
                    read_optimize "$(gettext "请输入") gRPC $(gettext "伪装路径") ($(gettext "不需要")"/":)" "serviceName" "NULL"
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
                    read_optimize "$(gettext "请输入") xHTTP $(gettext "伪装路径") ($(gettext "不需要")"/":)" "xhttppath" "NULL"
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
    if [[ "on" != ${old_config_status} ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") Xray $(gettext "用户名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_email_fq
        case $custom_email_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入正确的 email") (e.g. me@hey.run): " "custom_email" "NULL"
            ;;
        *)
            custom_email="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})@hey.run"
            ;;
        esac
        log_echo "${Green} Xray $(gettext "用户名") (email): ${custom_email} ${Font}"
    fi
}

UUID_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义字符串映射") (UUIDv5) [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入自定义字符串") ($(gettext "最多30字符")):" "UUID5_char" "NULL"
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
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]]; then
        local domain
        local output
        local curl_output
        pkg_install "nmap"

        while true; do
            echo
            log_echo "${GreenBG} $(gettext "请输入一个域名") (e.g. bing.com)${Font}"
            log_echo "${Green}$(gettext "域名要求支持 TLSv1.3、X25519 与 H2 以及域名非跳转用")${Font}"
            read_optimize "$(gettext "确认域名符合要求后请输入"): " "domain" "NULL"
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
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]]; then
        local custom_serverNames_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") ${target} $(gettext "域名的") serverNames [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Green} $(gettext "默认为") ${target} $(gettext "域名本身")${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
        read -r custom_serverNames_fq
        case $custom_serverNames_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个域名"): " "serverNames" "NULL"
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
    if [[ "on" != ${old_config_status} ]]; then
        local custom_keys_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") privateKey [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_keys_fq
        case $custom_keys_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入") privateKey:" "privateKey" "NULL"
            local keys=$(${xray_bin_dir}/xray x25519 -i "${privateKey}" | tr '\n' ' ')
            if echo "${keys}" | grep -q "Password (PublicKey): "; then
                password=$(echo "${keys}" | sed 's/.*Password (PublicKey): //' | awk '{print $1}')
            elif echo "${keys}" | grep -q "Password: "; then
                password=$(echo "${keys}" | awk -F"Password: " '{print $2}' | awk '{print $1}')
            elif echo "${keys}" | grep -q "PublicKey: "; then
                password=$(echo "${keys}" | awk -F"PublicKey: " '{print $2}' | awk '{print $1}')
            fi
            ;;
        *)
            local keys=$(${xray_bin_dir}/xray x25519 | tr '\n' ' ')
            privateKey=$(echo "${keys}" | awk -F"PrivateKey: " '{print $2}' | awk '{print $1}')
            if echo "${keys}" | grep -q "Password (PublicKey): "; then
                password=$(echo "${keys}" | sed 's/.*Password (PublicKey): //' | awk '{print $1}')
            elif echo "${keys}" | grep -q "Password: "; then
                password=$(echo "${keys}" | awk -F"Password: " '{print $2}' | awk '{print $1}')
            elif echo "${keys}" | grep -q "PublicKey: "; then
                password=$(echo "${keys}" | awk -F"PublicKey: " '{print $2}' | awk '{print $1}')
            fi
            ;;
        esac
        log_echo_secure "${Green} privateKey: ${privateKey} ${Font}"
        log_echo_secure "${Green} Password: ${password} ${Font}"
        echo
    fi
}


shortIds_set() {
    if [[ "on" != ${old_config_status} ]]; then
        local custom_shortids_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") shortIds [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_shortids_fq
        case $custom_shortids_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个 shortId"): " "shortIds" "NULL"
            ;;
        *)
            pkg_install "openssl"
            shortIds=$(openssl rand -hex 8)
            ;;
        esac
        log_echo "${Green} shortIds: ${shortIds} ${Font}"
        echo
    fi
}

ensure_sub_script() {
    local script_name="$1"
    local remote_url="$2"
    local local_file="${idleleo_dir}/${script_name}"

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
                log_echo "${Error} ${RedBG} ${script_name} $(gettext "需要主脚本版本") >= ${required_version}，$(gettext "当前版本"): ${shell_version}，$(gettext "请先更新主脚本") ${Font}"
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

            if ensure_sub_script "file_manager.sh" "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"; then
                case $upstream_choose in
                1) source "${idleleo_dir}/file_manager.sh" wsServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                2) source "${idleleo_dir}/file_manager.sh" grpcServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                3) source "${idleleo_dir}/file_manager.sh" xhttpServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                4) ;;
                *)
                    log_echo "${Error} ${RedBG} $(gettext "无效选项, 请重试")! ${Font}"
                    nginx_upstream_server_set
                    ;;
                esac
            fi
        elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_balance} == "on" ]] && [[ ${reality_add_nginx} == "on" ]]; then
            if ensure_sub_script "file_manager.sh" "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"; then
                source "${idleleo_dir}/file_manager.sh" realityServers ${nginx_conf_dir}
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
        echo -e "${Info} ${GreenBG} $(gettext "配置用途可以参考文章"): https://hey.run/archives/use-reality ${Font}"
        read -r nginx_servernames_server_fq
        case $nginx_servernames_server_fq in
        [yY][eE][sS] | [yY])
            if ensure_sub_script "file_manager.sh" "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"; then
                source "${idleleo_dir}/file_manager.sh" serverNames ${nginx_conf_dir}
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
    sed -i "s/worker_processes  1;/worker_processes  auto;/" "${nginx_dir}"/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" "${nginx_dir}"/conf/nginx.conf
    if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "Reality" && ${reality_add_nginx} == "on" ]]; then
        sed -i "\$i include ${nginx_conf_dir}/*.conf;" "${nginx_dir}"/conf/nginx.conf
    fi
    sed -i "/http\( *\){/a \\\tserver_tokens off;" "${nginx_dir}"/conf/nginx.conf
    sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 403;\\n\\t\\t}" "${nginx_dir}"/conf/nginx.conf
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
    [[ "on" != ${old_config_status} ]] && log_echo "${Green} $(gettext "端口"): ${port} ${Font}"
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
        [[ -f "${ssl_chainpath}/xray.key" ]] && chown -fR "nobody:${_nobody_group}" "${ssl_chainpath}"/*
    fi
    log_echo "${OK} ${GreenBG} Xray $(gettext "修改完成") ${Font}"
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
        xray_install_release install -f --version v${xray_online_version}
        judge "$(gettext "安装") Xray"
        xray_privilege_escalation
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
    current_xray_version=$(info_extraction xray_version)
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    # COMPAT: 旧版依赖 /usr/local/etc/xray 目录存放默认配置，新版不再使用，未来可删除
    [[ ! -d "${local_bin}/etc/xray" ]] && log_echo "${GreenBG} $(gettext "若更新无效, 建议直接卸载再安装")! ${Font}"
    log_echo "${Warning} ${GreenBG} $(gettext "部分新功能需要重新安装才可生效") ${Font}"
    ## xray_online_version=$(check_version xray_online_pre_version)
    ## if [[ $(info_extraction xray_version) != ${xray_online_version} ]] && [[ ${xray_version} != ${xray_online_version} ]]; then
    if [[ ${current_xray_version} != ${xray_online_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "检测到存在最新版") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "脚本可能未兼容此版本") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_test_fq
            case $xray_test_fq in
            [yY][eE][sS] | [yY])
                log_echo "${OK} ${GreenBG} $(gettext "更新") Xray ! ${Font}"
                systemctl stop xray
                if ! xray_install_release install -f --version "v${xray_online_version}" || ! "${xray_bin_dir}/xray" -version &> /dev/null; then
                    log_echo "${Error} ${RedBG} Xray $(gettext "启动失败")! ${Font}"
                    log_echo "${Warning} ${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                    case $rollback_fq in
                    [nN][oO] | [nN])
                        log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                        return 0
                        ;;
                    *)
                        log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                        if [[ -z "${current_xray_version}" || "${current_xray_version}" == "null" ]]; then
                            log_echo "${Error} ${RedBG} Xray $(gettext "版本未知"), $(gettext "回滚失败")! ${Font}"
                            return 1
                        fi
                        xray_version=${current_xray_version}
                        if xray_install_release install -f --version "v${xray_version}" && "${xray_bin_dir}/xray" -version &> /dev/null; then
                            log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Xray $(gettext "版本")! ${Font}"
                            update_rolled_back=1
                        else
                            log_echo "${Error} ${RedBG} Xray $(gettext "回滚失败")! ${Font}"
                            return 1
                        fi
                        ;;
                    esac
                else
                    xray_version=${xray_online_version}
                    judge "Xray $(gettext "更新")" true
                fi
                ;;
            *)
                return 0
                ;;
            esac
        else
            systemctl stop xray
            if ! xray_install_release install -f --version "v${xray_online_version}" || ! "${xray_bin_dir}/xray" -version &> /dev/null; then
                if [[ -z "${current_xray_version}" || "${current_xray_version}" == "null" ]]; then
                    echo "Xray $(gettext "回滚失败")!" >>"${log_file}"
                    return 1
                fi
                xray_version=${current_xray_version}
                if ! xray_install_release install -f --version "v${xray_version}" || ! "${xray_bin_dir}/xray" -version &> /dev/null; then
                    echo "Xray $(gettext "回滚失败")!" >>"${log_file}"
                    return 1
                fi
                update_rolled_back=1
            else
                xray_version=${xray_online_version}
            fi
        fi
    else
        countdown "$(gettext "重装") Xray !"
        systemctl stop xray
        xray_version=${xray_online_version}
        xray_install_release install -f --version v${xray_online_version}
        judge "Xray $(gettext "重装")"
    fi
    xray_privilege_escalation
    set_xray_config_path
    update_json_config "${xray_qr_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version' || return 1
    systemctl daemon-reload
    systemctl start xray
    if ! ${xray_bin_dir}/xray -version &> /dev/null; then
        [[ ${auto_update} == "YES" ]] && echo "Xray $(gettext "更新失败")!" >>"${log_file}"
        [[ ${auto_update} != "YES" ]] && log_echo "${Error} ${RedBG} Xray $(gettext "更新失败")! ${Font}"
        return 1
    fi
    [[ ${auto_update} == "YES" && ${update_rolled_back} -eq 1 ]] && return 1
    return 0
}

reality_balance_add_fq() {
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


reality_nginx_add_fq() {
    echo
    log_echo "${Warning} ${Green} $(gettext "Reality 协议有流量偷跑的风险") ${Font}"
    if [[ ${reality_add_balance} == "off" ]]; then
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护")($(gettext "推荐")) [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [nN][oO] | [nN])
                reality_add_nginx="off"
                if [[ -d "${nginx_dir}" ]]; then
                    echo
                    log_echo "${Warning} ${Green} $(gettext "检测到已安装") nginx ${Font}"
                    uninstall_nginx
                else
                    log_echo "${OK} ${GreenBG} $(gettext "已跳过安装") nginx ${Font}"
                fi
            ;;
            *)
                reality_add_nginx="on"
                nginx_exist_check
                nginx_systemd
                nginx_reality_conf_add
                nginx_reality_servers_add
                nginx_reality_serverNames_add
            ;;

        esac
    else
        log_echo "${Warning} ${Green} $(gettext "检测到已开启 Reality 负载均衡") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "如用作 Reality 负载均衡主服务器必须安装") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "如用作 Reality 负载均衡二级服务器则无需安装") ${Font}"
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [yY][eE][sS] | [yY])
                reality_add_nginx="on"
                nginx_exist_check
                nginx_systemd
                nginx_reality_conf_add
                nginx_reality_servers_add
                nginx_reality_serverNames_add
            ;;
            *)
                reality_add_nginx="off"
                if [[ -d "${nginx_dir}" ]]; then
                    echo
                    log_echo "${Warning} ${Green} $(gettext "检测到已安装") nginx ${Font}"
                    uninstall_nginx
                else
                    log_echo "${OK} ${GreenBG} $(gettext "已跳过安装") nginx ${Font}"
                fi
            ;;
        esac
    fi    
}

nginx_exist_check() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]] && [[ -n "$(info_extraction nginx_build_version)" ]]; then
        if [[ -d "${nginx_conf_dir}" ]]; then
            rm -rf "${nginx_conf_dir}"/*.conf
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
        modify_nginx_origin_conf
        nginx_build_version=$(info_extraction nginx_build_version)
        log_echo "${OK} ${GreenBG} Nginx $(gettext "已存在, 跳过编译安装过程") ${Font}"
    elif [[ -d "/etc/nginx" ]] && [[ -n "$(info_extraction nginx_version)" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "检测到其他套件安装的 Nginx, 继续安装会造成冲突, 请处理后安装")! ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    local temp_dir=$(mktemp -d)
    local current_dir=$(pwd)

    cd "$temp_dir" || exit

    log_echo "${OK} ${GreenBG} $(gettext "即将下载已编译的") Nginx ${Font}"
    local nginx_arch
    local nginx_filename
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
            exit 1
            ;;
    esac

    local base_url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${nginx_build_version}"
    local manifest_file="${temp_dir}/release-manifest.json"
    local nginx_sha256=""

    if download_json_file "${base_url}/release-manifest.json" "${manifest_file}"; then
        local manifest_filename
        local manifest_sha256
        manifest_filename=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .filename // empty' "${manifest_file}" | head -n 1)
        manifest_sha256=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .sha256 // empty' "${manifest_file}" | head -n 1)
        if [[ -n "${manifest_filename}" ]]; then
            nginx_filename="${manifest_filename}"
            nginx_sha256="${manifest_sha256}"
        fi
    fi

    local url="${base_url}/${nginx_filename}"

    if ! curl -fL -# --connect-timeout 10 --retry 2 --retry-delay 1 -o "$nginx_filename" "$url"; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "下载失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        exit 1
    fi
    log_echo "${OK} ${GreenBG} Nginx $(gettext "下载成功") ${Font}"

    if [[ -n "${nginx_sha256}" ]] && [[ "${nginx_sha256}" != "null" ]]; then
        if ! echo "${nginx_sha256}  ${nginx_filename}" | sha256sum -c - >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} Nginx SHA256 校验失败 ${Font}"
            cd "$current_dir" && rm -rf "$temp_dir"
            exit 1
        fi
    fi

    if ! tar -xzf "$nginx_filename" -C ./; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "解压失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        exit 1
    fi

    [[ -d "${nginx_dir}" ]] && safe_rm "${nginx_dir}"
    mv ./nginx "${nginx_dir}"

    [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p "${nginx_conf_dir}"
    cp -fp "${nginx_dir}"/conf/nginx.conf "${nginx_conf_dir}"/nginx.default

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    modify_nginx_origin_conf

    # 删除临时文件
    cd "$current_dir" && rm -rf "$temp_dir"
    chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${nginx_dir}"
    chmod -fR 755 "${nginx_dir}"
}

restore_nginx_backup() {
    local backup_dir="$1"

    service_stop || return 1
    safe_rm "${nginx_dir}"
    if ! mv "${backup_dir}" "${nginx_dir}"; then
        return 1
    fi
    service_start || return 1
    sleep 1
    systemctl -q is-active nginx
}

nginx_update() {
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    if [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        current_nginx_build_version=$(info_extraction nginx_build_version)
        if [[ ${nginx_build_version} != ${current_nginx_build_version} ]]; then
            ip_check
            if [[ -f "${xray_qr_config_file}" ]]; then
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
                    elif [[ ${transport_mode} == "all" ]]; then
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
            cp -r "${nginx_dir}" "${backup_nginx_dir}"
            judge "$(gettext "备份旧版") Nginx"
            countdown "$(gettext "删除旧版") Nginx !"
            safe_rm "${nginx_dir}"
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
            nginx_install
            if [[ ${tls_mode} == "TLS" ]] && [[ ${save_originconf} != "Yes" ]]; then
                nginx_ssl_conf_add
                nginx_conf_add
                nginx_servers_conf_add
            elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]] && [[ ${save_originconf} != "Yes" ]]; then
                nginx_reality_conf_add
            fi
            service_start || return 1
            sleep 1
            if ! systemctl -q is-active nginx; then
                log_echo "${Error} ${RedBG} Nginx $(gettext "启动失败")! ${Font}"
                if [[ ${auto_update} != "YES" ]]; then
                    echo
                    log_echo "${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                else
                    log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                    if restore_nginx_backup "${backup_nginx_dir}"; then
                        log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Nginx $(gettext "版本")! ${Font}"
                        update_json_config "${xray_qr_config_file}" --arg nginx_build_version "${current_nginx_build_version}" '.nginx_build_version = $nginx_build_version' || return 1
                    else
                        log_echo "${Error} ${RedBG} $(gettext "回滚失败")! ${Font}"
                    fi
                    return 1
                fi
                case $rollback_fq in
                [nN][oO] | [nN])
                    log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                    return 1
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                    if restore_nginx_backup "${backup_nginx_dir}"; then
                        log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Nginx $(gettext "版本")! ${Font}"
                        update_json_config "${xray_qr_config_file}" --arg nginx_build_version "${current_nginx_build_version}" '.nginx_build_version = $nginx_build_version' || return 1
                        safe_rm "${backup_nginx_dir}"
                        return 1
                    else
                        log_echo "${Error} ${RedBG} $(gettext "回滚失败")! ${Font}"
                        return 1
                    fi
                    ;;
                esac
            else
                update_json_config "${xray_qr_config_file}" --arg nginx_build_version "${nginx_build_version}" '.nginx_build_version = $nginx_build_version'
                judge "Nginx $(gettext "更新")"
                safe_rm "${backup_nginx_dir}"
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
            download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/auto_update.sh" "${auto_update_file}"
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
            read -r old_host_fq
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
        read_optimize "$(gettext "请输入你的域名信息") (e.g. www.hey.run):" "domain" "NULL"
        echo -e "\n${GreenBG} $(gettext "请选择公网IP(IPv4/IPv6)或手动输入域名") ${Font}"
        echo -e "${Red}1${Font}: IPv4 ($(gettext "默认"))"
        echo "2: IPv6"
        echo "3: $(gettext "域名")"
        read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")!"
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
            log_echo "${Warning} ${GreenBG} $(gettext "注意服务器商域名添加 CNAME 记录") ${Font}"
            read_optimize "$(gettext "请输入"): " "local_ip" "NULL"
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
        log_echo "$(gettext "域名DNS解析IP"): ${domain_ip}"
        log_echo "$(gettext "公网IP/域名"): ${local_ip}"
        if [[ ${ip_version_fq} != 3 ]] && [[ ${local_ip} == ${domain_ip} ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "域名DNS解析IP与公网IP匹配") ${Font}"
            break
        else
            log_echo "${Warning} ${YellowBG} $(gettext "请确保域名添加了正确的 A/AAAA 记录, 否则将无法正常使用 Xray") ${Font}"
            log_echo "${Error} ${RedBG} $(gettext "域名DNS解析IP与公网IP不匹配, 请选择"): ${Font}"
            echo "1: $(gettext "继续安装")"
            echo "2: $(gettext "重新输入")"
            log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
            read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!"
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
            read -r old_host_fq
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
    read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")!"
    [[ -z ${ip_version_fq} ]] && ip_version=1
    log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(get_public_ip "IPv4")
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(get_public_ip "IPv6")
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        read_optimize "$(gettext "请输入"): " "local_ip" "NULL"
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

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        log_echo "${OK} ${GreenBG} $1 $(gettext "端口未被占用") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "检测到") $1 $(gettext "端口被占用"), $(gettext "以下为") $1 $(gettext "端口占用信息") ${Font}"
        lsof -i:"$1"
        countdown "$(gettext "尝试终止占用的进程")!"
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        log_echo "${OK} ${GreenBG} kill $(gettext "完成") ${Font}"
    fi
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
        log_echo "${OK} ${GreenBG} SSL $(gettext "证书生成成功") ${Font}"
        mkdir -p "${ssl_chainpath}"
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --force --reloadcmd "chmod -f 644 ${ssl_chainpath}/xray.crt; chmod -f 600 ${ssl_chainpath}/xray.key; chown -fR nobody:\$(id -gn nobody 2>/dev/null || echo nogroup) ${ssl_chainpath}/*; systemctl restart nginx; systemctl restart xray"; then
            chmod -f 644 "${ssl_chainpath}"/xray.crt
            chmod -f 600 "${ssl_chainpath}"/xray.key
            chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${ssl_chainpath}"/*
            log_echo "${OK} ${GreenBG} SSL $(gettext "证书配置成功") ${Font}"
            systemctl stop nginx
        fi
    else
        log_echo "${Error} ${RedBG} SSL $(gettext "证书生成失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    if [[ $(info_extraction multi_user) != "yes" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            judge "$(gettext "下载 Xray TLS 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "all" ]]; then
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "Reality" ]]; then
            judge "$(gettext "下载 Xray Reality 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_reality/config.json" "${xray_conf}"
            modify_target_serverNames
            modify_privateKey_shortIds
            xray_reality_add_more
        elif [[ ${tls_mode} == "None" ]]; then
            judge "$(gettext "下载 Xray 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "all" ]]; then
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "XTLS" ]]; then
            judge "$(gettext "下载 Xray XTLS 配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_xtls/config.json" "${xray_conf}"
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
            update_json_config "${xray_qr_config_file}" 'del(.multi_user)'
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
    if [[ -f "${xray_qr_config_file}" ]]; then
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            echo
            log_echo "${GreenBG} $(gettext "检测到配置文件, 是否读取配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [nN][oO] | [nN])
                rm -rf "${xray_qr_config_file}"
                log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
                ;;
            *)
                log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
                old_config_status="on"
                old_config_input
                ;;
            esac
        else
            echo
            log_echo "${Warning} ${GreenBG} $(gettext "检测到当前安装模式与配置文件的安装模式不一致") ${Font}"
            log_echo "${GreenBG} $(gettext "是否保留配置文件 (强烈不建议)") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                log_echo "${Warning} ${GreenBG} $(gettext "请务必确保配置文件正确") ${Font}"
                log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
                menu
                ;;
            *)
                rm -rf "${xray_qr_config_file}"
                log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
                ;;
            esac
        fi
    fi
}

old_config_input() {
    info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
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
        password=$(info_extraction password)
        shortIds=$(info_extraction shortIds)
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
        echo
        log_echo "${GreenBG} $(gettext "检测到配置文件不完整, 是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        [yY][eE][sS] | [yY])
            old_config_status="off"
            log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
            ;;
        *)
            rm -rf "${xray_qr_config_file}"
            old_config_status="off"
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
            ;;
        esac
    fi
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
        #proxy_pass http://xray-xhttp-server;
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
    touch "${nginx_conf}"
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
        server 127.0.0.1:9403;
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

    server {
        listen 127.0.0.1:9403 reuseport;
        #ssl_preread on;
        ssl_reject_handshake on;
        return 444;
        access_log off;
        error_log /dev/null;
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
    cat >"${nginx_upstream_conf}" <<EOF
upstream xray-ws-server {
    include ${nginx_conf_dir}/*.wsServers;
}

upstream xray-grpc-server {
    include ${nginx_conf_dir}/*.grpcServers;
}

upstream xray-xhttp-server {
    include ${nginx_conf_dir}/*.xhttpServers;
}
EOF
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
            judge -r "Nginx $(gettext "重启")" || return 1
        fi
    fi
    systemctl restart xray
    judge -r "Xray $(gettext "重启")" || return 1
}

service_start() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl start nginx
            judge -r "Nginx $(gettext "启动")" || return 1
        fi
    fi
    systemctl start xray
    judge -r "Xray $(gettext "启动")" || return 1
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
        if [[ -f "${ssl_update_file}" ]] && [[ $(crontab -l | grep -c "ssl_update.sh") == "1" ]]; then
            echo
            log_echo "${Warning} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "老版本请及时删除 废弃的 改版证书自动更新")! ${Font}"
            log_echo "${GreenBG} $(gettext "已设置改版证书自动更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除改版证书自动更新 (请删除)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r remove_acme_cron_update_fq
            case $remove_acme_cron_update_fq in
            [nN][oO] | [nN]) ;;
            *)
                sed -i "/ssl_update.sh/d" "${crontab_file}"
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
            modifyTime=$(stat -c %Y "$HOME/.acme.sh/${host}_ecc/${host}.cer" 2>/dev/null || stat -f %m "$HOME/.acme.sh/${host}_ecc/${host}.cer" 2>/dev/null)
            currentTime=$(date +%s)
            ((stampDiff = currentTime - modifyTime))
            ((days = stampDiff / 86400))
            ((remainingDays = 90 - days))
            tlsStatus=${remainingDays}
            [[ ${remainingDays} -le 0 ]] && tlsStatus="${Red}$(gettext "已过期")${Font}"
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
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发")! ${Font}"
        fi
        host="$(info_extraction host)"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${host}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "chmod -f 644 ${ssl_chainpath}/xray.crt; chmod -f 600 ${ssl_chainpath}/xray.key; chown -fR nobody:\$(id -gn nobody 2>/dev/null || echo nogroup) ${ssl_chainpath}/*; systemctl restart nginx; systemctl restart xray"
        judge -r "$(gettext "证书更新")" || return 1
        service_restart || return 1
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

set_fail2ban() {
    if ! ensure_sub_script "fail2ban_manager.sh" "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/fail2ban_manager.sh"; then
        return 1
    fi
    source "${idleleo_dir}/fail2ban_manager.sh"
    mf_check_for_updates
    mf_main_menu
}

set_traffic_blocker() {
    if [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 未安装, 请先安装") Xray ${Font}"
        return 1
    fi
    if ! ensure_sub_script "traffic_blocker.sh" "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/traffic_blocker.sh"; then
        return 1
    fi
    source "${idleleo_dir}/traffic_blocker.sh"
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

vless_qr_config_tls_ws() {
    cat >"${xray_qr_config_file}" <<-EOF
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
    "xray_version": "${xray_version}",
    "nginx_build_version": "${nginx_build_version}"
}
EOF
    info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
    _info_cache_invalidate
}

vless_qr_config_reality() {
    cat >"${xray_qr_config_file}" <<-EOF
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
    "password":"${password}",
    "shortIds":"${shortIds}",
    "reality_add_nginx": "${reality_add_nginx}",
    "reality_add_balance": "${reality_add_balance}",
    "reality_add_more": "${reality_add_more}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "ws_path": "${artpath}",
    "grpc_serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    if [[ ${reality_add_nginx} == "on" ]]; then
        update_json_config "${xray_qr_config_file}" --arg nginx_build_version "${nginx_build_version}" '. + {"nginx_build_version": $nginx_build_version}'
    fi
    info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
    _info_cache_invalidate
}

vless_qr_config_xtls_only() {
    cat >"${xray_qr_config_file}" <<-EOF
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
    "flow": "xtls-rprx-vision",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
    _info_cache_invalidate
}

vless_qr_config_ws_only() {
    cat >"${xray_qr_config_file}" <<-EOF
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
    "xray_version": "${xray_version}"
}
EOF
    info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
    _info_cache_invalidate
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
            local pbk sni target sid
            pbk=$(info_extraction password)
            sni=$(info_extraction serverNames)
            target=$(info_extraction target)
            sid=$(info_extraction shortIds)
            result="vless://${user_id}@${quoted_host}:${port}?security=reality&flow=xtls-rprx-vision&fp=chrome&pbk=${pbk}&sni=${sni}&target=${target}&sid=${sid}#${quoted_host}+Reality%E5%8D%8F%E8%AE%AE"
            ;;
        xtls)
            port=$(info_extraction port)
            result="vless://${user_id}@${quoted_host}:${port}?security=none&encryption=none&headerType=none&type=raw&flow=xtls-rprx-vision#${quoted_host}+XTLS%E5%8D%8F%E8%AE%AE"
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

    local clash_name="VLESS-$(info_extraction host)-${transport_label}"
    local clash_config=""

    if [[ ${type} == "ws" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: $(info_extraction host)
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}
    flow: ${flow}
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
    tls: ${tls}
    flow: ${flow}
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
    tls: ${tls}
    flow: ${flow}
    network: tcp
    skip-cert-verify: false"
    fi

    if [[ ${security} == "reality" ]]; then
        clash_config="${clash_config}
    servername: ${sni}
    reality-opts:
      public-key: ${pbk}
      short-id: ${sid}"
    fi

    echo "${clash_config}"
}

vless_qr_link_image() {
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
$(generate_clash_config "ws" "$(info_extraction port)" "/$(info_ws_path)" "" "tls" "" "" "" "" "" "true")"
        fi
        if is_grpc_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction port)" "" "$(info_grpc_serviceName)" "tls" "" "" "" "" "" "true")"
        fi
        if is_xhttp_mode; then
            clash_config_content="${clash_config_content}
# Clash $(gettext "不支持 xHTTP 传输协议")"
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "reality" "xtls-rprx-vision" "$(info_extraction password)" "$(info_extraction serverNames)" "$(info_extraction target)" "$(info_extraction shortIds)" "true")"

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
# Clash $(gettext "不支持 xHTTP 传输协议")"
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
# Clash $(gettext "不支持 xHTTP 传输协议")"
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
        clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "none" "xtls-rprx-vision" "" "" "" "" "false")"
    fi
    
    {
        echo
        log_echo "${Red} —————————————— Xray $(gettext "链接分享") —————————————— ${Font}"
        if [[ ${tls_mode} == "Reality" ]] || [[ ${tls_mode} == "XTLS" ]]; then
            log_echo "${Red} URL $(gettext "分享链接"):${Font} ${vless_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_ws_mode && [[ -n "${vless_ws_link}" ]]; then
            log_echo "${Red} ws URL $(gettext "分享链接"):${Font} ${vless_ws_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_grpc_mode && [[ -n "${vless_grpc_link}" ]]; then
            log_echo "${Red} gRPC URL $(gettext "分享链接"):${Font} ${vless_grpc_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo
        fi
        if is_xhttp_mode && [[ -n "${vless_xhttp_link}" ]]; then
            log_echo "${Red} xHTTP URL $(gettext "分享链接"):${Font} ${vless_xhttp_link}"
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
}

vless_link_image_choice() {
    echo
    log_echo "${GreenBG} $(gettext "生成分享链接"): ${Font}"
    vless_qr_link_image
}

declare -A _info_cache=()
_info_cache_loaded=0

_info_cache_invalidate() {
    _info_cache=()
    _info_cache_loaded=0
}

_info_cache_load() {
    if [[ ${_info_cache_loaded} -eq 0 ]] && [[ -n "${info_extraction_all}" ]]; then
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
        result=$(echo "${info_extraction_all}" | jq -r ".$1 // empty" 2>/dev/null)
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
    if [[ ! -f "${xray_qr_config_file}" ]]; then
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
    {
        echo
        log_echo "${OK} ${GreenBG} Xray+${shell_mode} $(gettext "安装成功") ${Font}"
        echo
        log_echo "${Warning} ${YellowBG} VLESS $(gettext "目前分享链接规范为实验阶段, 请自行判断是否适用") ${Font}"
        if is_xhttp_mode; then
            log_echo "${Warning} ${YellowBG} $(gettext "xHTTP 不支持 Clash 客户端") ${Font}"
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
            log_echo "${Red} $(gettext "流控") (flow):${Font} xtls-rprx-vision "
            if [[ ${tls_mode} == "Reality" ]]; then
                log_echo "${Red} target:${Font} $(info_extraction target) "
                log_echo "${Red} serverNames:${Font} $(info_extraction serverNames) "
                log_echo_secure "${Red} privateKey:${Font} $(info_extraction privateKey) "
                log_echo_secure "${Red} Password:${Font} $(info_extraction password) "
                log_echo "${Red} shortIds:${Font} $(info_extraction shortIds) "
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
    log_echo "${GreenBG} $(gettext "即将申请证书, 支持使用自定义证书") ${Font}"
    log_echo "${Green} $(gettext "如需使用自定义证书, 请按如下步骤:") ${Font}"
    log_echo " $(gettext "1. 将证书文件重命名: 私钥(xray.key)、证书(xray.crt)")"
    log_echo " $(gettext "2. 将重命名后的证书文件放入") ${ssl_chainpath} $(gettext "目录后再运行脚本")"
    log_echo " $(gettext "3. 重新运行脚本")"
    log_echo "${GreenBG} $(gettext "是否继续") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r ssl_continue
    case $ssl_continue in
    [nN][oO] | [nN])
        exit 0
        ;;
    *)
        if [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            log_echo "${GreenBG} $(gettext "所有证书文件均已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_1
            case $ssl_delete_1 in
            [nN][oO] | [nN])
                delete_tls_key_and_crt
                rm -rf "${ssl_chainpath}"/*
                log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${ssl_chainpath}"/*
                judge "$(gettext "证书应用")"
                ;;
            esac
        elif [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] && [[ ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            log_echo "${GreenBG} $(gettext "证书文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_2
            case $ssl_delete_2 in
            [nN][oO] | [nN])
                rm -rf "${ssl_chainpath}"/*
                log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${ssl_chainpath}"/*
                judge "$(gettext "证书应用")"
                ;;
            esac
        elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] && [[ ! -f "${ssl_chainpath}/xray.key" || ! -f "${ssl_chainpath}/xray.crt" ]]; then
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
                "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "chmod -f 644 ${ssl_chainpath}/xray.crt; chmod -f 600 ${ssl_chainpath}/xray.key; chown -fR nobody:\$(id -gn nobody 2>/dev/null || echo nogroup) ${ssl_chainpath}/*; systemctl restart nginx; systemctl restart xray"
                chown -fR "nobody:$(id -gn nobody 2>/dev/null || echo nogroup)" "${ssl_chainpath}"/*
                judge "$(gettext "证书应用")"
                ;;
            esac
        else
            ssl_install
            acme
        fi
        ;;
    esac
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
                read_optimize "$(gettext "请输入"): " "choose_tls" 2 1 2 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_tls} == 1 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "由于 h3 仅支持 TLSv1.3, 只支持 TLSv1.3 only (安全模式)")! ${Font}"
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
            read_optimize "$(gettext "请输入"): " "tls_version_choice" 1 1 2 "$(gettext "请输入有效的数字")!"
            if [[ ${tls_version_choice} == 2 ]]; then
                sed -i "s/^\( *\)#TLSv1.2\( *\)1;\( *\)$/\1TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.2+ ${Font}"
            else
                sed -i "s/^\( *\)TLSv1.2\( *\)1;\( *\)$/\1#TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.3 ${Font}"
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "当前模式不支持") ${Font}"
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
        log_echo "${Error} ${RedBG} $(gettext "Nginx配置文件不存在 或 当前模式不支持") ${Font}"
        return 1
    fi
}

reset_vless_qr_config() {
    [[ -f "${xray_qr_config_file}" ]] && info_extraction_all=$(jq -rc . "${xray_qr_config_file}")
    _info_cache_invalidate
    basic_information
    vless_qr_link_image
    show_information
}

reset_UUID() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        old_config_status="off"
        UUID_set
        old_config_status="${_saved_old_config_status}"
        modify_UUID
        update_json_config "${xray_qr_config_file}" --arg uuid "${UUID}" \
           --arg uuid5_char "${UUID5_char}" \
           '.id = $uuid | .idc = $uuid5_char'
        service_restart || return 1
        reset_vless_qr_config
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

reset_port() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        old_config_status="off"
        if [[ ${tls_mode} == "TLS" ]]; then
            port_set
            modify_nginx_port
            update_json_config "${xray_qr_config_file}" --argjson port "${port:-0}" '.port = $port'
            log_echo "${Green} $(gettext "端口"): ${port} ${Font}"
        elif [[ ${tls_mode} == "Reality" ]]; then
            port_set
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${gport}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xhttpport}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "all" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                port_exist_check "${xhttpport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
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
            update_json_config "${xray_qr_config_file}" --argjson port "${port:-0}" \
               --argjson ws_port "${xport:-0}" \
               --argjson grpc_port "${gport:-0}" \
               --argjson xhttp_port "${xhttpport:-0}" \
               "${port_update_expr}"
            modify_inbound_port
            [[ ${reality_add_nginx} == "on" ]] && modify_nginx_port
        elif [[ ${tls_mode} == "None" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${gport}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xhttpport}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "all" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                port_exist_check "${xhttpport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
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
                update_json_config "${xray_qr_config_file}" --argjson ws_port "${xport:-0}" \
                   --argjson grpc_port "${gport:-0}" \
                   --argjson xhttp_port "${xhttpport:-0}" \
                   "${none_port_update# | }"
            fi
            modify_inbound_port
        elif [[ ${tls_mode} == "XTLS" ]]; then
            port_set
            update_json_config "${xray_qr_config_file}" --argjson port "${port:-0}" '.port = $port'
            modify_inbound_port
            log_echo "${Green} $(gettext "端口"): ${port} ${Font}"
        fi
        firewall_set
        if ! service_restart; then
            old_config_status="${_saved_old_config_status}"
            return 1
        fi
        reset_vless_qr_config
        old_config_status="${_saved_old_config_status}"
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

reset_target() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} == "Reality" ]]; then
        target_reset=1
        serverNames=$(info_extraction serverNames)
        nginx_reality_serverNames_del
        target_set
        serverNames_set
        modify_target_serverNames
        if [[ ${reality_add_nginx} == "on" ]]; then
            nginx_reality_serverNames_add
        fi
        update_json_config "${xray_qr_config_file}" --arg target "${target}" \
           --arg serverNames "${serverNames}" \
           '.target = $target | .serverNames = $serverNames'
        service_restart || return 1
        reset_vless_qr_config
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
    if [[ ! -f "${xray_qr_config_file}" ]] || [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return
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
            log_echo "${Green} UUID: ${user_id} ${Font}"
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
            log_echo "${Red} URL $(gettext "分享链接"):${Font} ${user_vless_link}"
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
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        local add_user_continue
        while true; do
            echo
            log_echo "${GreenBG} $(gettext "即将添加用户, 一次仅能添加一个") ${Font}"
            if [[ ${tls_mode} == "TLS" ]]; then
                if [[ ${transport_mode} == "onlyws" ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${transport_mode} == "onlygRPC" ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                    choose_user_tag="VLESS-xhttp-in"
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
            elif [[ ${tls_mode} == "XTLS" ]]; then
                choose_user_tag="VLESS-XTLS-in"
                reality_user_more='{"flow":"xtls-rprx-vision"}'
            fi
            email_set
            local existing_emails=$(jq -r --arg tag "${choose_user_tag}" \
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
            update_json_config "${xray_qr_config_file}" ". += {\"multi_user\": \"yes\"}"
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
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持添加用户")! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

remove_user() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        local choose_user_prot
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                choose_user_tag="VLESS-ws-in"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                choose_user_tag="VLESS-gRPC-in"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                choose_user_tag="VLESS-xhttp-in"
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
                update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --argjson del_user_index "${del_user_index}" \
                   'del((.inbounds[] | select(.tag == $choose_user_tag)).settings.clients[$del_user_index])'
                judge -r "$(gettext "删除用户")" || return 1
                local remaining_multi_user
                remaining_multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}" 2>/dev/null)
                if [[ "${remaining_multi_user}" != "true" ]]; then
                    update_json_config "${xray_qr_config_file}" 'del(.multi_user)'
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
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持删除用户")! ${Font}"
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
                if ! judge -r "$(gettext "下载流量统计配置")" download_json_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/status_config.json" "${xray_status_conf}"; then
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
    if [[ -f "${idleleo_dir}/tcp.sh" ]]; then
        cd ${idleleo_dir} && chmod +x ./tcp.sh && ./tcp.sh
    else
        if download_script_file "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" "${idleleo_dir}/tcp.sh"; then
            "${idleleo_dir}/tcp.sh"
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
    if [[ -f "${xray_qr_config_file}" ]]; then
        update_json_config "${xray_qr_config_file}" -r 'del(.xray_version)'
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
    if [[ -f "${xray_qr_config_file}" ]]; then
        update_json_config "${xray_qr_config_file}" 'del(.nginx_build_version)'
    fi
    log_echo "${OK} ${GreenBG} $(gettext "已卸载") Nginx ${Font}"
}

uninstall_all() {
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
        sed -i "/ssl_update.sh/d" "${crontab_file}"
    fi
    [[ -f "/etc/logrotate.d/xray_log_cleanup" ]] && rm -f "/etc/logrotate.d/xray_log_cleanup"
    [[ -L "/usr/local/etc/xray/config.json" ]] && rm -f "/usr/local/etc/xray/config.json"
    [[ -L "/usr/local/share/xray" ]] && rm -f "/usr/local/share/xray"
    [[ -f "${xray_bin_dir}/xray" ]] && uninstall_xray
    echo
    [[ -d "${nginx_dir}" ]] && uninstall_nginx --force
    echo
    local keep_config=true
    if [[ -f "${xray_qr_config_file}" ]]; then
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
        if [[ "${keep_config}" == "true" && -f "${xray_qr_config_file}" ]]; then
            local _tmp_config
            _tmp_config=$(mktemp)
            cp -f "${xray_qr_config_file}" "${_tmp_config}"
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
            mkdir -p "${idleleo_dir}/info"
            mv -f "${_tmp_config}" "${xray_qr_config_file}"
        else
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
        fi
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已删除所有文件") ${Font}"
        log_echo "${GreenBG} $(gettext "ヾ(￣▽￣) 拜拜~") ${Font}"
        exit 0
        ;;
    *)
        if [[ "${keep_config}" == "false" && -f "${xray_qr_config_file}" ]]; then
            rm -rf "${xray_qr_config_file}"
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
        fi
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已保留脚本文件 (包含 SSL 证书等)") ${Font}"
        ;;
    esac
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
    if [[ -f "${xray_qr_config_file}" ]]; then
        transport_mode=$(info_extraction transport_mode)
        [[ -z ${transport_mode} || ${transport_mode} == "null" ]] && transport_mode="None"
        tls_mode=$(info_extraction tls)
        if [[ ${tls_mode} == "Reality" ]]; then
            reality_add_more=$(info_extraction reality_add_more)
            reality_add_nginx=$(info_extraction reality_add_nginx)
            reality_add_balance=$(info_extraction reality_add_balance)
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
    basic_optimization
    create_directory
    old_config_exist_check
    domain_check
    transport_choose
    port_set
    ws_inbound_port_set
    grpc_inbound_port_set
    xhttp_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    xhttp_path_set
    email_set
    UUID_set
    transport_qr
    vless_qr_config_tls_ws
    stop_service_all
    xray_install
    update_json_config "${xray_qr_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_systemd
    nginx_ssl_conf_add
    ssl_judge_and_install
    nginx_conf_add
    nginx_servers_conf_add
    xray_conf_add
    tls_type || return 1
    basic_information
    enable_process_systemd || return 1
    acme_cron_update
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    vless_link_image_choice
    show_information
}

install_xray_reality() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    ip_check
    xray_install
    port_set
    email_set
    UUID_set
    target_set
    serverNames_set
    keys_set
    shortIds_set
    xray_reality_add_more_choose
    transport_qr
    firewall_set
    stop_service_all
    port_exist_check "${port}"
    reality_balance_add_fq
    reality_nginx_add_fq
    xray_conf_add
    vless_qr_config_reality
    update_json_config "${xray_qr_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    tls_type || return 1
    basic_information
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    vless_link_image_choice
    show_information
}

install_xray_xtls_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    ip_check
    shell_mode="XTLS ONLY"
    tls_mode="XTLS"
    port_set
    firewall_set
    email_set
    UUID_set
    vless_qr_config_xtls_only
    stop_service_all
    xray_install
    update_json_config "${xray_qr_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    port_exist_check "${port}"
    xray_conf_add
    basic_information
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    vless_link_image_choice
    show_information
}

install_xray_ws_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install
    basic_optimization
    create_directory
    old_config_exist_check
    ip_check
    transport_choose
    ws_inbound_port_set
    grpc_inbound_port_set
    xhttp_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    xhttp_path_set
    email_set
    UUID_set
    transport_qr
    vless_qr_config_ws_only
    stop_service_all
    xray_install
    update_json_config "${xray_qr_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    port_exist_check "${xport}"
    port_exist_check "${gport}"
    port_exist_check "${xhttpport}"
    xray_conf_add
    basic_information
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    setup_auto_clean_logs || return 1
    vless_link_image_choice
    show_information
}

update_sh() {
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
            [[ -z ${ol_version} ]] && echo "$(gettext "检测 脚本 最新版本失败")!" >>"${log_file}" && return 1
            [[ ${version_difference} == 1 ]] && echo "$(gettext "脚本 版本差别过大, 跳过更新")!" >>"${log_file}" && return 1
            update_confirm="YES"
        fi
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L "${idleleo_commend_file}" ]] && rm -f ${idleleo_commend_file}
            download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh" "${idleleo_dir}/install.sh"
            if [[ $? -ne 0 ]]; then
                [[ ${auto_update} == "YES" ]] && echo "$(gettext "脚本更新失败")!" >>"${log_file}"
                [[ ${auto_update} != "YES" ]] && log_echo "${Error} ${RedBG} $(gettext "脚本更新失败")! ${Font}"
                return 1
            fi
            ln -s "${idleleo}" "${idleleo_commend_file}"
            [[ -f "${xray_qr_config_file}" ]] && update_json_config "${xray_qr_config_file}" --arg shell_version "${shell_version}" '.shell_version = $shell_version'
            clear
            log_echo "${OK} ${GreenBG} $(gettext "更新完成") ${Font}"
            [[ ${version_difference} == 1 ]] && log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 若服务无法正常运行请卸载后重装")! ${Font}"
            return 0
            ;;
        *)
            return 0
            ;;
        esac
    else
        clear
        log_echo "${OK} ${GreenBG} $(gettext "当前版本为最新版本") ${Font}"
    fi
    return 0

}

check_file_integrity() {
    if [[ ! -L "${idleleo_commend_file}" ]] && [[ ! -f "${idleleo}" ]]; then
        check_system
        pkg_install "bc,jq"
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p "${idleleo_dir}"
        [[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p "${idleleo_dir}"/tmp
        download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh" "${idleleo_dir}/install.sh"
        judge "$(gettext "下载最新脚本")"
        ln -s "${idleleo}" "${idleleo_commend_file}"
        clear
        exec "${BASH:-bash}" "${idleleo}"
    fi
}

read_version() {
    shell_online_version="$(check_version shell_online_version)"
    xray_online_version="$(check_version xray_online_version)"
    nginx_build_version="$(check_version nginx_build_online_version)"
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
        vless_qr_link_image
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
    echo "  -au, --auto-update          $(gettext "设置自动更新")"
    echo "  -c, --clean-logs            $(gettext "清除日志文件")"
    echo "  -cs, --cert-status          $(gettext "查看证书状态")"
    echo "  -cu, --cert-update          $(gettext "更新证书有效期")"
    echo "  -cau, --cert-auto-update    $(gettext "设置证书自动更新")"
    echo "  -f, --set-fail2ban          $(gettext "设置 Fail2ban 防暴力破解")"
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
            download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh" "${idleleo_dir}/install.sh"
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
                    download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh" "${idleleo_dir}/install.sh"
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
                download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh" "${idleleo_dir}/install.sh"
                echo
                judge "$(gettext "下载最新脚本")"
                clear
                echo
            fi
            exec "${BASH:-bash}" "${idleleo}"
        else
            ol_version=${shell_online_version}
            echo "${ol_version}" >"${shell_version_tmp}"
            [[ -z ${ol_version} ]] && shell_need_update="${Red}[$(gettext "检测失败")]!${Font}"
            echo "${shell_version}" >>"${shell_version_tmp}"
            newest_version=$(sort -rV "${shell_version_tmp}" | head -1)
            if [[ ${shell_version} != ${newest_version} ]]; then
                shell_need_update="${Red}[$(gettext "有新版")!]${Font}"
                shell_emoji="${Red}>_<${Font}"
            else
                shell_need_update="${Green}[$(gettext "最新版")]${Font}"
                shell_emoji="${Green}^O^${Font}"
            fi
            if [[ -f "${xray_qr_config_file}" ]]; then
                if [[ -z "$(info_extraction nginx_build_version)" ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
                    nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                elif [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
                    nginx_need_update="${Green}[$(gettext "有新版")!]${Font}"
                else
                    nginx_need_update="${Green}[$(gettext "最新版")]${Font}"
                fi
                if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f "${xray_bin_dir}/xray" ]]; then
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
                    xray_need_update="${Red}[$(gettext "未安装")]${Font}"
                fi
            else
                nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                xray_need_update="${Red}[$(gettext "未安装")]${Font}"
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

check_xray_local_connect() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        xray_local_connect_status="${Red}$(gettext "无法连通")${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyxhttp" ]]; then
                xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
            elif [[ ${transport_mode} == "onlyws" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "all" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" && $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
        elif [[ ${tls_mode} == "None" ]]; then
            xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
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

    xray_online_version_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json")
    if [[ ${xray_online_version_status} != "200" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法检测所需依赖的在线版本, 请稍后再试")! ${Font}"
        sleep 0.5
        exit 0
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
    read_optimize "$(gettext "请输入数字"): " "lang_choice" "NULL" 1 6 "$(gettext "请输入 1 到 6 之间的有效数字")"

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
            log_echo "${Error} ${RedBG} $(gettext "无效的选择") ${Font}"
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
        log_echo "${Error} ${RedBG} $(gettext "备份失败") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "备份成功"): ${backup_path} ${Font}"
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
        log_echo "${OK} ${GreenBG} $(gettext "恢复成功") ${Font}"
        log_echo "${Info} ${Green} $(gettext "记得安装") xray ${Font}"
        if [[ -d "/usr/local/nginx" ]]; then
            log_echo "${Info} ${Green} $(gettext "记得安装") nginx ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "恢复失败") ${Font}"
    fi
}

menu() {
    echo
    log_echo "Xray $(gettext "安装管理脚本") ${Red}[${shell_version}]${Font} ${shell_emoji}"
    log_echo "--- $(gettext "作者"): hello-yunshu ---"
    log_echo "--- $(gettext "修改"): hey.run ---"
    log_echo "--- https://github.com/hello-yunshu ---"
    echo
    log_echo "$(gettext "当前模式"): ${shell_mode}"
    log_echo "$(gettext "当前语言"): ${LANG%.*}"
    echo

    echo -e "$(gettext "可以使用")${RedW} idleleo ${Font}$(gettext "命令管理脚本")${Font}\n"

    log_echo "—————————————— ${GreenW}$(gettext "版本检测")${Font} ——————————————"
    log_echo "$(gettext "脚本"):  ${shell_need_update}"
    log_echo "Xray:  ${xray_need_update}"
    log_echo "Nginx: ${nginx_need_update}"
    log_echo "—————————————— ${GreenW}$(gettext "运行状态")${Font} ——————————————"
    log_echo "Xray:   ${xray_status}"
    log_echo "Nginx:  ${nginx_status}"
    log_echo "$(gettext "连通性"): ${xray_local_connect_status}"
    echo -e "—————————————— ${GreenW}$(gettext "更新向导")${Font} ——————————————"
    echo -e "${Green}0.${Font}  $(gettext "更新") $(gettext "脚本")"
    echo -e "${Green}1.${Font}  $(gettext "更新") Xray"
    echo -e "${Green}2.${Font}  $(gettext "更新") Nginx"
    echo -e "—————————————— ${GreenW}语言 / Language${Font} ———————"
    echo -e "${Green}99.${Font} 中文 (默认)"
    echo -e "    English"
    echo -e "    Français" 
    echo -e "    فارسی    "
    echo -e "    Русский"
    echo -e "    한국어"
    echo -e "—————————————— ${GreenW}$(gettext "安装向导")${Font} ——————————————"
    echo -e "${Green}3.${Font}  $(gettext "安装") Xray (Reality+ws/gRPC/xHTTP+Nginx)"
    echo -e "${Green}4.${Font}  $(gettext "安装") Xray (Nginx+ws/gRPC/xHTTP+TLS)"
    echo -e "${Green}5.${Font}  $(gettext "安装") Xray (ws/gRPC/xHTTP ONLY)"
    echo -e "${Green}6.${Font}  $(gettext "安装") Xray (XTLS ONLY)"
    echo -e "—————————————— ${GreenW}$(gettext "配置变更")${Font} ——————————————"
    echo -e "${Green}7.${Font}  $(gettext "变更") UUIDv5/$(gettext "映射字符串")"
    echo -e "${Green}8.${Font}  $(gettext "变更") port"
    echo -e "${Green}9.${Font}  $(gettext "变更") target"
    echo -e "${Green}10.${Font} $(gettext "变更") TLS $(gettext "版本")"
    echo -e "${Green}11.${Font} $(gettext "变更") Nginx $(gettext "负载均衡配置")"
    echo -e "${Green}12.${Font} $(gettext "变更") Nginx serverNames $(gettext "配置")"
    echo -e "—————————————— ${GreenW}$(gettext "用户管理")${Font} ——————————————"
    echo -e "${Green}13.${Font} $(gettext "查看") Xray $(gettext "用户")"
    echo -e "${Green}14.${Font} $(gettext "添加") Xray $(gettext "用户")"
    echo -e "${Green}15.${Font} $(gettext "删除") Xray $(gettext "用户")"
    echo -e "—————————————— ${GreenW}$(gettext "查看信息")${Font} ——————————————"
    echo -e "${Green}16.${Font} $(gettext "查看") Xray $(gettext "实时访问日志")"
    echo -e "${Green}17.${Font} $(gettext "查看") Xray $(gettext "实时错误日志")"
    echo -e "${Green}18.${Font} $(gettext "查看") Xray $(gettext "配置信息")"
    echo -e "${Green}19.${Font} $(gettext "查看") port $(gettext "实时流量")"
    echo -e "—————————————— ${GreenW}$(gettext "服务相关")${Font} ——————————————"
    echo -e "${Green}20.${Font} $(gettext "重启") $(gettext "所有服务")"
    echo -e "${Green}21.${Font} $(gettext "启动") $(gettext "所有服务")"
    echo -e "${Green}22.${Font} $(gettext "停止") $(gettext "所有服务")"
    echo -e "${Green}23.${Font} $(gettext "查看") $(gettext "所有服务")"
    echo -e "—————————————— ${GreenW}$(gettext "证书相关")${Font} ——————————————"
    echo -e "${Green}24.${Font} $(gettext "查看") $(gettext "证书状态")"
    echo -e "${Green}25.${Font} $(gettext "更新") $(gettext "证书有效期")"
    echo -e "${Green}26.${Font} $(gettext "设置") $(gettext "证书自动更新")"
    echo -e "—————————————— ${GreenW}$(gettext "其他选项")${Font} ——————————————"
    echo -e "${Green}27.${Font} $(gettext "配置") $(gettext "自动更新")"
    echo -e "${Green}28.${Font} $(gettext "设置") TCP $(gettext "加速")"
    echo -e "${Green}29.${Font} $(gettext "设置") Fail2ban $(gettext "防暴力破解")"
    echo -e "${Green}30.${Font} $(gettext "设置") Xray $(gettext "流量统计")"
    echo -e "${Green}31.${Font} $(gettext "设置") Xray $(gettext "流量阻断")"
    echo -e "${Green}32.${Font} $(gettext "清除") $(gettext "日志文件")"
    echo -e "${Green}33.${Font} $(gettext "测试") $(gettext "服务器网速")"
    echo -e "—————————————— ${GreenW}$(gettext "备份恢复")${Font} ——————————————"
    echo -e "${Green}34.${Font} $(gettext "备份") $(gettext "全部文件")"
    echo -e "${Green}35.${Font} $(gettext "恢复") $(gettext "全部文件")"
    echo -e "—————————————— ${GreenW}$(gettext "卸载向导")${Font} ——————————————"
    echo -e "${Green}36.${Font} $(gettext "卸载") $(gettext "脚本")"
    echo -e "${Green}37.${Font} $(gettext "清空") $(gettext "证书文件")"
    echo -e "${Green}38.${Font} $(gettext "退出") \n"

    local menu_num
    read_optimize "$(gettext "请输入选项"): " "menu_num" "NULL" 0 99 "$(gettext "请输入有效的数字")!"
    case $menu_num in
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
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    4)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        exec "${BASH:-bash}" "${idleleo}"
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
            ;;
        *) ;;
        esac
        exec "${BASH:-bash}" "${idleleo}"
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
            ;;
        *) ;;
        esac
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    7)
        reset_UUID
        judge -r "$(gettext "变更") UUIDv5/$(gettext "映射字符串")"
        menu
        ;;
    8)
        reset_port
        judge -r "$(gettext "变更") port"
        menu
        ;;
    9)
        reset_target
        judge -r "$(gettext "变更") target"
        menu
        ;;
    10)
        tls_type
        judge -r "$(gettext "变更") TLS $(gettext "版本")"
        menu
        ;;
    11)
        nginx_upstream_server_set
        menu
        ;;
    12)
        nginx_servernames_server_set
        menu
        ;;
    13)
        show_user
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    14)
        if service_stop; then
            add_user && service_start
        fi
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    15)
        if service_stop; then
            remove_user && service_start
        fi
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    16)
        clear
        show_access_log
        ;;
    17)
        clear
        show_error_log
        ;;
    18)
        clear
        basic_information
        vless_qr_link_image
        show_information
        menu
        ;;
    19)
        clear
        monitor_traffic_with_iftop
        menu
        ;;
    20)
        service_restart
        menu
        ;;
    21)
        if service_start; then
            exec "${BASH:-bash}" "${idleleo}"
        else
            log_echo "${Error} ${RedBG} $(gettext "服务启动失败") ${Font}"
        fi
        menu
        ;;
    22)
        if service_stop; then
            exec "${BASH:-bash}" "${idleleo}"
        else
            log_echo "${Error} ${RedBG} $(gettext "服务停止失败") ${Font}"
        fi
        menu
        ;;
    23)
        if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        menu
        ;;
    24)
        check_cert_status
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    25)
        cert_update_manuel
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    26)
        acme_cron_update
        menu
        ;;
    27)
        auto_update
        menu
        ;;
    28)
        clear
        bbr_boost_sh
        echo
        menu
        ;;
    29)
        set_fail2ban
        menu
        ;;
    30)
        xray_status_add
        countdown "$(gettext "回到菜单")!"
        menu
        ;;
    31)
        set_traffic_blocker
        menu
        ;;
    32)
        clean_logs
        menu
        ;;
    33)
        clear
        read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        local superspeed_script="${idleleo_dir}/tmp/superspeed.sh"
        if download_script_file "https://cdn.jsdelivr.net/gh/hello-yunshu/superspeed@master/superspeed.sh" "$superspeed_script"; then
            bash "$superspeed_script"
            rm -f "$superspeed_script"
        else
            log_echo "${Error} ${RedBG} $(gettext "网速测试脚本下载失败") ${Font}"
        fi
        read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        echo
        menu
        ;;
    34)
        backup_directories
        menu
        ;;
    35)
        restore_directories
        menu
        ;;
    36)
        uninstall_all
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    37)
        delete_tls_key_and_crt
        rm -rf "${ssl_chainpath}"/*
        menu
        ;;
    38)
        exit 0
        ;;
    99)
        set_language
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    *)
        log_echo "${Error} ${RedBG} $(gettext "请输入有效的数字")! ${Font}"
        menu
        ;;
    esac
}

check_file_integrity
check_online_version_connect
init_language
read_version
judge_mode
idleleo_commend
check_program
check_xray_local_connect
list "$@"
