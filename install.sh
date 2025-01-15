#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

idleleo=$(readlink -f "${BASH_SOURCE[0]}")

#=====================================================
#	System Request: Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	hello-yunshu
#	Dscription: Xray Onekey Management
#	Version: 2.0
#	email: admin@idleleo.com
#	Official document: hey.run
#=====================================================

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
Info="${Green}[$(gettext "提醒")]${Font}"
OK="${Green}[OK]${Font}"
Error="${RedW}[$(gettext "错误")]${Font}"
Warning="${RedW}[$(gettext "警告")]${Font}"

shell_version="2.2.10"
shell_mode="$(gettext "未安装")"
tls_mode="None"
ws_grpc_mode="None"
local_bin="/usr/local"
idleleo_dir="/etc/idleleo"
idleleo_conf_dir="${idleleo_dir}/conf"
log_dir="${idleleo_dir}/logs"
xray_bin_dir="${local_bin}/bin"
xray_conf_dir="${idleleo_conf_dir}/xray"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
xray_conf="${xray_conf_dir}/config.json"
xray_status_conf="${xray_conf_dir}/status_config.json"
xray_default_conf="${local_bin}/etc/xray/config.json"
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
myemali="my@example.com"
shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
get_versions_all=$(curl -s https://www.idleleo.com/api/xray_shell_versions)
read_config_status=1
reality_add_more="off"
reality_add_nginx="off"
old_config_status="off"
old_tls_mode="NULL"
random_num=$((RANDOM % 12 + 4))
[[ -f "${xray_qr_config_file}" ]] && info_extraction_all=$(jq -rc . ${xray_qr_config_file})

[[ ! -d ${log_dir} ]] && mkdir -p ${log_dir}
[[ ! -f "${log_dir}/install.log" ]] && touch ${log_dir}/install.log
LOG_FILE="${log_dir}/install.log"
LOG_MAX_SIZE=$((3 * 1024 * 1024))  # 3 MB
MAX_ARCHIVES=5

log() {
    if [ $(stat -c%s "$LOG_FILE" 2>/dev/null) -gt $LOG_MAX_SIZE ]; then
        log_rotate
    fi
    
    local message=$(echo -e "$1" | sed 's/\x1B\[\([0-9]\(;[0-9]\)*\)*m//g' | tr -d '\n')
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a $LOG_FILE >/dev/null
}

log_rotate() {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local archived_log="${LOG_FILE}.${timestamp}.gz"
    
    # 添加 gzip 错误处理
    if ! gzip -c "$LOG_FILE" > "$archived_log"; then
        log_echo "${Error} ${RedBG} $(gettext "日志文件归档失败") ${Font}"
        return 1
    fi
    
    # 添加清空日志文件的错误处理
    if ! :> "$LOG_FILE"; then
        log_echo "${Error} ${RedBG} $(gettext "清空日志文件失败") ${Font}" 
        return 1
    fi
    
    log "$(gettext "日志文件已轮转并归档为") $archived_log"
    
    rotate_archives
}

rotate_archives() {
    local archives=($(ls ${LOG_FILE}.*.gz 2>/dev/null))
    while [ ${#archives[@]} -gt $MAX_ARCHIVES ]; do
        oldest_archive=${archives[0]}
        rm "$oldest_archive"
        archives=($(ls ${LOG_FILE}.*.gz 2>/dev/null))
    done
}

log_echo() {
    local message=$(printf "%b" "$@")
    echo -e "$message"
    log "$message"
}

##兼容代码，未来删除
[[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p ${idleleo_dir}/tmp

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        [[ ! -f "${xray_qr_config_file}" ]] && $INS update || true
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
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
        log_echo "${Error} ${RedBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} $(gettext "不在支持的系统列表内, 安装中断!") ${Font}"
        exit 1
    fi
}

is_root() {
    if [[ 0 == $UID ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前用户是 root用户, 进入安装流程") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "当前用户不是 root用户, 请切换到 root用户 后重新执行脚本!") ${Font}"
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
    local version_file_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/refs/heads/main/languages/${lang_code}/LC_MESSAGES/version"
    
    [[ ! -f "${local_file}" ]] && return 0
    
    local remote_version
    remote_version=$(curl -s "${version_file_url}" || echo "")
    
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
    
    log_echo "${Info} ${Blue} $(gettext "正在更新语言文件...") ${Font}"
    
    if ! curl -s -o "${mo_file}" "${github_url}/${lang_code}/LC_MESSAGES/xray_install.mo"; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件更新失败") ${Font}"
        return 1
    fi
    
    if [ ! -s "${mo_file}" ]; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件无效") ${Font}"
        rm -f "${mo_file}"
        return 1
    fi

    # 更新version文件
    if ! curl -s -o "${version_file}" "${github_url}/${lang_code}/LC_MESSAGES/version"; then
        log_echo "${Error} ${RedBG} $(gettext "版本文件更新失败") ${Font}"
        return 1
    fi
    
    chmod -R 755 "${idleleo_dir}/languages"

    log_echo "${OK} ${Green} $(gettext "语言文件更新完成") ${Font}"
}

init_language() {
    if ! command -v gettext >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "正在安装 gettext...") ${Font}"
        ${INS} gettext
        if [ $? -ne 0 ]; then
            log_echo "${Error} ${RedBG} $(gettext "gettext 安装失败，将使用默认语言") ${Font}"
            export LANG=zh_CN.UTF-8
            return 1
        fi
    fi
    
    local gettext_paths=(
        "/usr/share/gettext/gettext.sh"
        "/usr/bin/gettext.sh"
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
        log_echo "${Error} ${RedBG} $(gettext "未找到 gettext.sh，将使用默认语言") ${Font}"
        export LANG=zh_CN.UTF-8
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
                *) 
                    log_echo "${Warning} ${YellowBG} $(gettext "不支持的语言:")${LANG%.*}$(gettext "，将使用默认语言") ${Font}"
                    export LANG=zh_CN.UTF-8
                    return 0
                    ;;
            esac
            
            local lang_file="${TEXTDOMAINDIR}/${lang_code}/LC_MESSAGES/${TEXTDOMAIN}.mo"
            if [ ! -f "$lang_file" ]; then
                if ! update_language_file "$lang_code"; then
                    log_echo "${Warning} ${YellowBG} $(gettext "语言文件更新失败，将使用默认语言") ${Font}"
                    export LANG=zh_CN.UTF-8
                    return 0
                fi
            elif check_language_update "$lang_code"; then
                log_echo "${Info} ${Blue} $(gettext "发现语言文件更新") ${Font}"
                if update_language_file "$lang_code"; then
                    . "$gettext_sh"
                fi
            fi
        fi
    else
        export LANG=zh_CN.UTF-8
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        log_echo "${OK} ${GreenBG} $1 $(gettext "完成") ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} $1 $(gettext "失败") ${Font}"
        exit 1
    fi
}

check_version() {
    echo ${get_versions_all} | jq -rc ".$1"
    [[ 0 -ne $? ]] && log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试!") ${Font}" && exit 1
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
        for install_var in ${install_array[@]}; do
            if [[ -z $(pkg_install_judge "${install_var}") ]]; then
                ${INS} -y install ${install_var}
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
    pkg_install "bc,curl,dbus,git,jq,lsof,python3,qrencode,wget"
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
    if [[ ${tls_mode} != "None" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            pkg_install "epel-release,iputils,pcre,pcre-devel,zlib-devel,perl-IPC-Cmd"
        else
            pkg_install "iputils-ping,libpcre3,libpcre3-dev,zlib1g-dev"
        fi
        judge "Nginx $(gettext "链接库安装")"
    fi
}

read_optimize() {
    local prompt="$1" var_name="$2" default_value="${3:-NULL}" min_value="${4:-}" max_value="${5:-}" error_msg="${6:-$(gettext "值为空或超出范围, 请重新输入!")}"
    local user_input

    read -rp "$prompt" user_input

    if [[ -z $user_input ]]; then
        if [[ $default_value != "NULL" ]]; then
            user_input=$default_value
        else
            log_echo "${Error} ${RedBG} $(gettext "值为空, 请重新输入!") ${Font}"
            read_optimize "$prompt" "$var_name" "$default_value" "$min_value" "$max_value" "$error_msg"
            return
        fi
    fi

    printf -v "$var_name" "%s" "$user_input"

    if [[ -n $min_value ]] && [[ -n $max_value ]]; then
        if (( user_input < min_value )) || (( user_input > max_value )); then
            log_echo "${Error} ${RedBG} $error_msg ${Font}"
            read_optimize "$prompt" "$var_name" "$default_value" "$min_value" "$max_value" "$error_msg"
            return
        fi
    fi
}

basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

create_directory() {
    if [[ ${tls_mode} != "None" ]]; then
        [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p ${nginx_conf_dir}
    fi
    [[ ! -d "${ssl_chainpath}" ]] && mkdir -p ${ssl_chainpath}
    [[ ! -d "${xray_conf_dir}" ]] && mkdir -p ${xray_conf_dir}
    [[ ! -d "${idleleo_dir}/info" ]] && mkdir -p ${idleleo_dir}/info
}

port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "确定 连接端口") ${Font}"
        read_optimize "$(gettext "请输入连接端口") ($(gettext "默认值"):443):" "port" 443 0 65535 "$(gettext "请输入 0-65535 之间的值!")"
        if [[ ${port} -eq 9443 ]] && [[ ${tls_mode} == "Reality" ]]; then
            echo -e "${Error} ${RedBG} $(gettext "端口 9443 不允许使用, 请重新输入!") ${Font}"
            read_optimize "$(gettext "请输入连接端口") ($(gettext "默认值"):443):" "port" 443 0 65535 "$(gettext "请输入 0-65535 之间的值!")"
        fi
    fi
}

ws_grpc_choose() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "请选择 安装协议 ws/gRPC") ${Font}"
        echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
        echo "2: gRPC"
        echo "3: ws+gRPC"
        local choose_network
        read_optimize "$(gettext "请输入"): " "choose_network" 1 1 3 "$(gettext "请输入有效的数字")"
        if [[ $choose_network == 2 ]]; then
            [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+gRPC+TLS"
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+gRPC"
            [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="gRPC ONLY"
            ws_grpc_mode="onlygRPC"
        elif [[ $choose_network == 3 ]]; then
            [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+ws+gRPC+TLS"
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+ws+gRPC"
            [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="ws+gRPC ONLY"
            ws_grpc_mode="all"
        else
            [[ ${shell_mode} == "Reality" ]] && shell_mode="Reality+ws"
            ws_grpc_mode="onlyws"
        fi
    fi
}

xray_reality_add_more_choose() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否添加简单 ws/gRPC 协议 用于负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择!") ${Font}"
        read -r reality_add_more_fq
        case $reality_add_more_fq in
        [yY][eE][sS] | [yY])
            reality_add_more="on"
            ws_grpc_choose
            ws_inbound_port_set
            grpc_inbound_port_set
            ws_path_set
            grpc_path_set
            port_exist_check "${xport}"
            port_exist_check "${gport}"
            ;;
        *)
            reality_add_more="off"
            ws_inbound_port_set
            grpc_inbound_port_set
            ws_path_set
            grpc_path_set
            log_echo "${OK} ${GreenBG} $(gettext "已跳过添加简单 ws/gRPC 协议") ${Font}"
            ;;
        esac
    fi
}

ws_grpc_qr() {
    artpath="None"
    artxport="None"
    artserviceName="None"
    artgport="None"
    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
        artxport=${xport}
        artpath=${path}
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
        artgport=${gport}
        artserviceName=${serviceName}
    elif [[ ${ws_grpc_mode} == "all" ]]; then
        artxport=${xport}
        artpath=${path}
        artgport=${gport}
        artserviceName=${serviceName}
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "是否需要自定义 ws inbound_port") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入自定义 ws inbound_port") ($(gettext "请勿与其他端口相同!")): " "xport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值!")"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            *)
                xport=$((RANDOM % 1000 + 10000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            esac
        else
            xport=$((RANDOM % 1000 + 20000))
        fi
    fi
}

grpc_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "是否需要自定义 gRPC inbound_port") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入自定义 gRPC inbound_port") ($(gettext "请勿与其他端口相同!")): " "gport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值!")"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            *)
                gport=$((RANDOM % 1000 + 10000))
                [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 10000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            esac
        else
            gport=$((RANDOM % 1000 + 30000))
        fi
    fi
}

firewall_set() {
    echo -e "\n"
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
        fi
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${gport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            iptables -I INPUT -p tcp -m multiport --dport 53,${xport},${gport} -j ACCEPT
            iptables -I INPUT -p udp -m multiport --dport 53,${xport},${gport} -j ACCEPT
            iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport},${gport} -j ACCEPT
            iptables -I OUTPUT -p udp -m multiport --sport 53,${xport},${gport} -j ACCEPT
            iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
        fi
        if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
            service iptables save
            service iptables restart
            log_echo "${OK} ${GreenBG} $(gettext "防火墙 重启 完成") ${Font}"
        else
            netfilter-persistent save
            systemctl restart iptables
            log_echo "${OK} ${GreenBG} $(gettext "防火墙 重启 完成") ${Font}"
        fi
        log_echo "${OK} ${GreenBG} $(gettext "开放防火墙相关端口") ${Font}"
        log_echo "${GreenBG} $(gettext "若修改配置, 请注意关闭防火墙相关端口") ${Font}"
        log_echo "${OK} ${GreenBG} $(gettext "配置 Xray FullCone") ${Font}"
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "跳过防火墙设置") ${Font}"
        ;;
    esac
}

ws_path_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_ws_path} == "yes" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "是否需要自定义 ws 伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入自定义 ws 伪装路径") ($(gettext "不需要")"/"):" "path" "NULL"
                log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                ;;
            *)
                path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                ;;
            esac
        else
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        fi
    elif [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否需要修改 ws 伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r change_ws_path_fq
        case $change_ws_path_fq in
        [yY][eE][sS] | [yY])
            change_ws_path="yes"
            ws_path_set
            ;;
        *) ;;
        esac
    fi
}

grpc_path_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_grpc_path} == "yes" ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "是否需要自定义 gRPC 伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入自定义 gRPC 伪装路径") ($(gettext "不需要")"/"):" "serviceName" "NULL"
                log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                ;;
            *)
                serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                ;;
            esac
        else
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        fi
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否需要修改 gRPC 伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r change_grpc_path_fq
        case $change_grpc_path_fq in
        [yY][eE][sS] | [yY])
            change_grpc_path="yes"
            grpc_path_set
            ;;
        *) ;;
        esac
    fi
}

email_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否需要自定义 Xray 用户名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_email_fq
        case $custom_email_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入合法的email") (e.g. me@idleleo.com): " "custom_email" "NULL"
            ;;
        *)
            custom_email="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})@idleleo.com"
            ;;
        esac
        log_echo "${Green} $(gettext "Xray 用户名") (email): ${custom_email} ${Font}"
    fi
}

UUID_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否需要自定义字符串映射为 UUIDv5") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入自定义字符串") ($(gettext "最多30字符")):" "UUID5_char" "NULL"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} $(gettext "自定义字符串"): ${UUID5_char} ${Font}"
            log_echo "${Green} UUIDv5: ${UUID} ${Font}"
            echo -e "\n"
            ;;
        *)
            UUID5_char="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo "${Green} $(gettext "UUID 映射字符串"): ${UUID5_char} ${Font}"
            log_echo "${Green} UUID: ${UUID} ${Font}"
            echo -e "\n"
            #[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
            ;;
        esac
    fi
}

target_set() {
    if [[ "on" == ${old_config_status} ]] && [[ $(info_extraction target) != null ]]; then
        echo -e "\n"
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
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "请输入一个域名") (e.g. bing.com)${Font}"
            log_echo "${Green}$(gettext "域名要求支持 TLSv1.3、X25519 与 H2 以及域名非跳转用")${Font}"
            read_optimize "$(gettext "确认域名符合要求后请输入"): " "domain" "NULL"
            log_echo "${Green}$(gettext "正在检测域名请等待")…${Font}"

            output=$(nmap --script ssl-enum-ciphers -p 443 "${domain}")
            curl_output=$(curl -I -k -m 5 "https://${domain}" 2>&1)
        
            # 检测TLSv1.3支持
            if ! echo "$output" | grep -q "TLSv1.3"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持 TLSv1.3") ${YellowBG}${Font}"
            fi

            # 检测X25519支持
            if ! echo "$output" | grep -q "x25519"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持 X25519") ${YellowBG}${Font}"
            fi

            # 检测HTTP/2支持
            if ! echo "$curl_output" | grep -q "HTTP/2"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持 HTTP/2") ${YellowBG}${Font}"
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
        log_echo "${Green} $(gettext "target 域名"): ${target} ${Font}"
    fi
}

serverNames_set() {
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]]; then
        local custom_serverNames_fq
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否需要修改") ${target} $(gettext "域名的 serverNames 用户名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Green} $(gettext "默认为") ${target} $(gettext "域名的本身")${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续!") ${Font}"
        read -r custom_serverNames_fq
        case $custom_serverNames_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入"): " "serverNames" "NULL"
            ;;
        *)
            serverNames=$target
            ;;
        esac
        log_echo "${Green} serverNames: ${serverNames} ${Font}"
        echo -e "\n"
    fi
}

keys_set() {
    if [[ "on" != ${old_config_status} ]]; then
        local keys
        keys=$(${xray_bin_dir}/xray x25519 | tr '\n' ' ')
        privateKey=$(echo "${keys}" | awk -F"Private key: " '{print $2}' | awk '{print $1}')
        publicKey=$(echo "${keys}" | awk -F"Public key: " '{print $2}' | awk '{print $1}')
        log_echo "${Green} privateKey: ${privateKey} ${Font}"
        log_echo "${Green} publicKey: ${publicKey} ${Font}"
    fi
}

shortIds_set() {
    if [[ "on" != ${old_config_status} ]]; then
        pkg_install "openssl"
        shortIds=$(openssl rand -hex 4)
        log_echo "${Green} shortIds: ${shortIds} ${Font}"
    fi
}

nginx_upstream_server_set() {
    if [[ ${tls_mode} == "TLS" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否变更 Nginx 负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续!") ${Font}"
        read -r nginx_upstream_server_fq
        case $nginx_upstream_server_fq in
        [yY][eE][sS] | [yY])
            echo -e "\n${GreenBG} $(gettext "请选择协议为 ws 或 gRPC") ${Font}"
            echo "1: ws"
            echo "2: gRPC"
            echo "3: $(gettext "返回")"
            local upstream_choose
            read_optimize "$(gettext "请输入"): " "upstream_choose" "NULL" 1 3 "$(gettext "请重新输入正确的数字")"
            
            fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"
            fm_file_path=${nginx_conf_dir}
            if [ ! -f "${idleleo_dir}/file_manager.sh" ]; then
                log_echo "${Info} ${Green} $(gettext "本地文件 file_manager.sh 不存在，正在下载...") ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"
                if [ $? -ne 0 ]; then
                    log_echo "${Error} ${RedBG} $(gettext "下载失败，请手动下载并安装新版本") ${Font}"
                    return 1
                fi
                chmod +x "${idleleo_dir}/file_manager.sh"
            fi
            case $upstream_choose in
            1) source "${idleleo_dir}/file_manager.sh" wsServers ${fm_file_path} ;;
            2) source "${idleleo_dir}/file_manager.sh" grpcServers ${fm_file_path} ;;
            3) ;;
            *) 
                log_echo "${Error} ${RedBG} $(gettext "无效选项 请重试") ${Font}" 
                nginx_upstream_server_set
                ;;
            esac
            ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作!") ${Font}"
    fi
}

nginx_servernames_server_set() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否变更 Nginx serverNames 配置") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续!") ${Font}"
        echo -e "${Info} ${GreenBG} $(gettext "配置用途可以参考文章"): ($(gettext "敬请期待")) ${Font}"
        read -r nginx_servernames_server_fq
        case $nginx_servernames_server_fq in
        [yY][eE][sS] | [yY])
            fm_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/file_manager.sh"
            fm_file_path=${nginx_conf_dir}
            if [ ! -f "${idleleo_dir}/file_manager.sh" ]; then
                log_echo "${Info} ${Green} $(gettext "本地文件 file_manager.sh 不存在，正在下载...") ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"
                if [ $? -ne 0 ]; then
                    log_echo "${Error} ${RedBG} $(gettext "下载失败，请手动下载并安装新版本") ${Font}"
                    return 1
                fi
                chmod +x "${idleleo_dir}/file_manager.sh"
            fi
            source "${idleleo_dir}/file_manager.sh" serverNames ${fm_file_path}
        ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作!") ${Font}"
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    echo "import uuid;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,'$1'));" | python3
}

modify_listen_address() {
    local modifynum modifynum2
    if [[ ${tls_mode} == "Reality" ]]; then
        modifynum=1
        modifynum2=2
    else
        modifynum=0
        modifynum2=1
    fi

    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
        jq --argjson modifynum "$modifynum" \
           '.inbounds[$modifynum].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "$(gettext "Xray listen address 修改")"
    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
        jq --argjson modifynum2 "$modifynum2" \
           '.inbounds[$modifynum2].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "$(gettext "Xray listen address 修改")"
    elif [[ ${ws_grpc_mode} == "all" ]]; then
        jq --argjson modifynum "$modifynum" --argjson modifynum2 "$modifynum2" \
           '.inbounds[$modifynum].listen = "0.0.0.0" | .inbounds[$modifynum2].listen = "0.0.0.0"' "${xray_conf}" > "${xray_conf}.tmp"
        judge "$(gettext "Xray listen address 修改")"
    fi
    mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_inbound_port() {
    if [[ ${tls_mode} == "Reality" ]]; then
        if [[ ${reality_add_nginx} == "off" ]]; then
            jq --argjson port "${port}" --argjson xport "${xport}" --argjson gport "${gport}" \
               '.inbounds[0].port = $port |
                .inbounds[1].port = $xport |
                .inbounds[2].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
            judge "$(gettext "Xray inbound port 修改")"
        else
            jq --argjson xport "${xport}" --argjson gport "${gport}" \
               '.inbounds[1].port = $xport |
                .inbounds[2].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
            judge "$(gettext "Xray inbound port 修改")"
        fi
    else
        jq --argjson xport "${xport}" --argjson gport "${gport}" \
           '.inbounds[0].port = $xport |
            .inbounds[1].port = $gport' "${xray_conf}" > "${xray_conf}.tmp"
        judge "$(gettext "Xray inbound port 修改")"
    fi
    mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_nginx_origin_conf() {
    sed -i "s/worker_processes  1;/worker_processes  auto;/" ${nginx_dir}/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" ${nginx_dir}/conf/nginx.conf
    if [[ ${tls_mode} == "TLS" ]]; then
        sed -i "\$i include ${nginx_conf_dir}/*.conf;" ${nginx_dir}/conf/nginx.conf
    elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "\$a include ${nginx_conf_dir}/*.conf;" ${nginx_dir}/conf/nginx.conf
    fi
    sed -i "/http\( *\){/a \\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 403;\\n\\t\\t}" ${nginx_dir}/conf/nginx.conf
}

modify_nginx_port() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "s/^\( *\)listen.*/\1listen ${port} reuseport so_keepalive=on backlog=65535;/" ${nginx_conf}
        judge "$(gettext "Nginx port 修改")"
    elif [[ ${tls_mode} == "TLS" ]]; then
        sed -i "2s/^\( *\).*ssl reuseport;$/\1listen ${port} ssl reuseport;/" ${nginx_conf}
        sed -i "3s/^\( *\).*ssl reuseport;$/\1listen [::]:${port} ssl reuseport;/" ${nginx_conf}
        sed -i "4s/^\( *\).*quic reuseport;$/\1listen ${port} quic reuseport;/" ${nginx_conf}
        sed -i "5s/^\( *\).*quic reuseport;$/\1listen [::]:${port} quic reuseport;/" ${nginx_conf}
        judge "$(gettext "Xray port 修改")"
    fi
    log_echo "${Green} $(gettext "端口号"): ${port} ${Font}"
}

modify_nginx_ssl_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" ${nginx_dir}/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${domain};/g" ${nginx_ssl_conf}
    sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${domain}\$request_uri;/" ${nginx_ssl_conf}
}

modify_nginx_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" ${nginx_dir}/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    if [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${domain};/g" ${nginx_conf}
        sed -i "s/^\( *\)location ws$/\1location \/${path}/" ${nginx_conf}
        sed -i "s/^\( *\)location grpc$/\1location \/${serviceName}/" ${nginx_conf}
        sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${domain}\$request_uri;/" ${nginx_conf}
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        fi
    fi
}

nginx_servers_add() {
    touch ${nginx_conf_dir}/127.0.0.1.wsServers
    cat >${nginx_conf_dir}/127.0.0.1.wsServers <<EOF
server 127.0.0.1:${xport} weight=50 max_fails=2 fail_timeout=10;
EOF
    touch ${nginx_conf_dir}/127.0.0.1.grpcServers
    cat >${nginx_conf_dir}/127.0.0.1.grpcServers<<EOF
server 127.0.0.1:${gport} weight=50 max_fails=2 fail_timeout=10;
EOF
}

modify_path() {
    sed -i "s/^\( *\)\"path\".*/\1\"path\": \"\/${path}\"/" ${xray_conf}
    sed -i "s/^\( *\)\"serviceName\".*/\1\"serviceName\": \"${serviceName}\",/" ${xray_conf}
    if [[ ${tls_mode} != "Reality" ]] || [[ "$reality_add_more" == "off" ]]; then
        judge "$(gettext "Xray 伪装路径 修改")"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "Reality 不支持 path") ${Font}"
    fi
}

modify_email_address() {
    if [[ $(jq -r '.inbounds[0].settings.clients|length' ${xray_conf}) == 1 ]] && [[ $(jq -r '.inbounds[1].settings.clients|length' ${xray_conf}) == 1 ]]; then
        sed -i "s/^\( *\)\"email\".*/\1\"email\": \"${custom_email}\"/g" ${xray_conf}
        judge "$(gettext "Xray 用户名 修改")"
    else
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除 多余的用户") ${Font}"
    fi
}

modify_UUID() {
    if [[ $(jq -r '.inbounds[0].settings.clients|length' ${xray_conf}) == 1 ]] && [[ $(jq -r '.inbounds[1].settings.clients|length' ${xray_conf}) == 1 ]]; then
        sed -i "s/^\( *\)\"id\".*/\1\"id\": \"${UUID}\",/g" ${xray_conf}
        judge "$(gettext "Xray UUID 修改")"
    else
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除 多余的用户") ${Font}"
    fi
}

modify_target_serverNames() {
  jq --arg target "${target}:443" --arg serverNames "${serverNames}" '
     .inbounds[0].streamSettings.realitySettings.target = $target |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$serverNames]' "${xray_conf}" > "${xray_conf}.tmp"
  judge "$(gettext "target serverNames 配置修改")"
  mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_privateKey_shortIds() {
  jq --arg privateKey "${privateKey}" --arg shortIds "${shortIds}" '
     .inbounds[0].streamSettings.realitySettings.privateKey = $privateKey |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortIds]' "${xray_conf}" > "${xray_conf}.tmp"
  judge "$(gettext "privateKey 和 shortIds 配置修改")"
  mv "${xray_conf}.tmp" "${xray_conf}"
}

modify_reality_listen_address () {
    jq '.inbounds[0].listen = "127.0.0.1"' "${xray_conf}" > "${xray_conf}.tmp"
    mv "${xray_conf}.tmp" "${xray_conf}"
    judge "$(gettext "Xray reality listen address 修改")"
}

xray_privilege_escalation() {
    if [[ -n "$(grep "User=nobody" ${xray_systemd_file})" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "检测到 Xray 的权限控制, 启动擦屁股程序") ${Font}"
        chmod -fR a+rw /var/log/xray/
        chown -fR nobody:nogroup /var/log/xray/
        [[ -f "${ssl_chainpath}/xray.key" ]] && chown -fR nobody:nogroup ${ssl_chainpath}/*
    fi
    log_echo "${OK} ${GreenBG} $(gettext "Xray 擦屁股 完成") ${Font}"
}

xray_install() {
    if [[ $(xray version) == "" ]] || [[ ! -f "${xray_conf}" ]]; then
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
        judge "$(gettext "安装 Xray")"
        systemctl daemon-reload
        xray_privilege_escalation
        [[ -f "${xray_default_conf}" ]] && rm -rf ${xray_default_conf}
        ln -s ${xray_conf} ${xray_default_conf}
    else
        log_echo "${OK} ${GreenBG} $(gettext "已安装 Xray") ${Font}"
    fi
}

xray_update() {
    [[ ! -d "${local_bin}/etc/xray" ]] && log_echo "${GreenBG} $(gettext "若更新无效, 建议直接卸载再安装!") ${Font}"
    log_echo "${Warning} ${GreenBG} $(gettext "部分新功能需要重新安装才可生效") ${Font}"
    xray_online_version=$(check_version xray_online_version)
    ## xray_online_version=$(check_version xray_online_pre_version)
    ## if [[ $(info_extraction xray_version) != ${xray_online_version} ]] && [[ ${xray_version} != ${xray_online_version} ]]; then
    if [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "检测到存在最新版") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "脚本可能未兼容此版本") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_test_fq
        else
            xray_test_fq=1
        fi
        case $xray_test_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} $(gettext "即将升级") Xray ! ${Font}"
            systemctl stop xray
            ## xray_version=${xray_online_version}
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
            judge "Xray $(gettext "升级")"
            ;;
        *)
            log_echo "${OK} ${GreenBG} $(gettext "即将升级/重装") Xray ! ${Font}"
            systemctl stop xray
            xray_version=$(info_extraction xray_version)
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
            judge "Xray $(gettext "升级")"
            ;;
        esac
    else
        timeout "$(gettext "升级/重装") Xray !"
        systemctl stop xray
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -f --version v${xray_version}
        judge "Xray $(gettext "升级")"
    fi
    xray_privilege_escalation
    [[ -f "${xray_default_conf}" ]] && rm -rf ${xray_default_conf}
    ln -s ${xray_conf} ${xray_default_conf}
    jq --arg xray_version "${xray_version}" '.xray_version = $xray_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
    mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
    systemctl daemon-reload
    systemctl start xray
}

reality_nginx_add_fq() {
    echo -e "\n"
    log_echo "${Warning} ${Green} $(gettext "Reality 协议有流量偷跑的风险") ${Font}"
    log_echo "${Warning} ${Green} $(gettext "该风险在 target 网址被 cdn 加速时存在") ${Font}"
    log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护(推荐)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r reality_nginx_add_fq
    case $reality_nginx_add_fq in
        [nN][oO] | [nN])
            log_echo "${OK} ${GreenBG} $(gettext "已跳过安装") nginx ${Font}"
        ;;
        *)
            reality_add_nginx="on"
            nginx_exist_check
            nginx_systemd
            nginx_reality_conf_add
            nginx_reality_serverNames_add
        ;;

    esac
}

nginx_exist_check() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]] && [[ "$(info_extraction nginx_build_version)" == "null" ]]; then
        if [[ -d "${nginx_conf_dir}" ]]; then
            rm -rf ${nginx_conf_dir}/*.conf
            if [[ -f "${nginx_conf_dir}/nginx.default" ]]; then
                cp -fp ${nginx_conf_dir}/nginx.default ${nginx_dir}/conf/nginx.conf
            elif [[ -f "${nginx_dir}/conf/nginx.conf.default" ]]; then
                cp -fp ${nginx_dir}/conf/nginx.conf.default ${nginx_dir}/conf/nginx.conf
            else
                sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
                sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
            fi
        else
            sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
            sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
        fi
        modify_nginx_origin_conf
        log_echo "${OK} ${GreenBG} $(gettext "Nginx 已存在, 跳过编译安装过程") ${Font}"
    #兼容代码，下个大版本删除
    elif [[ -d "/etc/nginx" ]] && [[ "$(info_extraction nginx_version)" == "null" ]]; then
        log_echo "${Error} ${GreenBG} $(gettext "检测到旧版本安装的") nginx ! ${Font}"
        log_echo "${Warning} ${GreenBG} $(gettext "请先做好备份") ${Font}"
        log_echo "${GreenBG} $(gettext "是否需要删除 (请删除)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r remove_nginx_fq
        case $remove_nginx_fq in
        [nN][oO] | [nN])
        log_echo "${OK} ${GreenBG} $(gettext "已跳过删除") nginx ${Font}"
        source "$idleleo"
            ;;
        *)
            rm -rf /etc/nginx/
            [[ -f "${nginx_systemd_file}" ]] && rm -rf ${nginx_systemd_file}
            [[ -d "${nginx_conf_dir}" ]] && rm -rf ${nginx_conf_dir}/*.conf
            log_echo "${Warning} ${GreenBG} $(gettext "日志目录已更改, 日志清除需要重新设置") ! ${Font}"
            nginx_install
            ;;
        esac
    #兼容代码结束
    elif [[ -d "/etc/nginx" ]] && [[ "$(info_extraction nginx_version)" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "检测到其他套件安装的 Nginx, 继续安装会造成冲突, 请处理后安装!") ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    local latest_version=$(check_version nginx_build_online_version)
    local temp_dir=$(mktemp -d)
    local current_dir=$(pwd)

    cd "$temp_dir" || exit

    log_echo "${OK} ${GreenBG} $(gettext "即将下载已编译的") Nginx ${Font}"
    local url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${latest_version}/xray-nginx-custom.tar.gz"
    wget -q --show-progress --progress=bar:force:noscroll "$url" -O xray-nginx-custom.tar.gz
    tar -xzvf xray-nginx-custom.tar.gz -C ./
    [[ -d ${nginx_dir} ]] && rm -rf "${nginx_dir}"
    mv ./nginx "${nginx_dir}"
    
    cp -fp ${nginx_dir}/conf/nginx.conf ${nginx_conf_dir}/nginx.default

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    modify_nginx_origin_conf

    # 删除临时文件
    cd "$current_dir" && rm -rf "$temp_dir"
    chown -fR nobody:nogroup "${nginx_dir}"
    chmod -fR 755 "${nginx_dir}"
}

nginx_update() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        if [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
            ip_check
            if [[ -f "${xray_qr_config_file}" ]]; then
                domain=$(info_extraction host)
                if [[ ${tls_mode} == "TLS" ]]; then
                    port=$(info_extraction port)
                    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$((RANDOM % 1000 + 30000))
                        [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xport=$((RANDOM % 1000 + 20000))
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "all" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                    fi
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "$(gettext "Nginx 配置文件不完整, 退出升级!")" && exit 1
                        log_echo "${Error} ${RedBG} $(gettext "配置文件不完整, 退出升级") ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
                    port=$(info_extraction port)
                    serverNames=$(info_extraction serverNames)
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "$(gettext "Nginx 配置文件不完整, 退出升级!")" && exit 1
                        log_echo "${Error} ${RedBG} $(gettext "配置文件不完整, 退出升级") ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "None" ]]; then
                    [[ ${auto_update} == "YES" ]] && echo "$(gettext "当前安装模式不需要") Nginx !" && exit 1
                    log_echo "${Error} ${RedBG} $(gettext "当前安装模式不需要") Nginx ! ${Font}"
                    return 1
                fi
            else
                [[ ${auto_update} == "YES" ]] && echo "$(gettext "Nginx 配置文件不存在, 退出升级!")" && exit 1
                log_echo "${Error} ${RedBG} $(gettext "配置文件不存在, 退出升级") ${Font}"
                return 1
            fi
            service_stop
            timeout "$(gettext "删除旧版") Nginx !"
            rm -rf ${nginx_dir}
            if [[ ${auto_update} != "YES" ]]; then
                echo -e "\n"
                log_echo "${GreenBG} $(gettext "是否保留原 Nginx 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r save_originconf_fq
            else
                save_originconf_fq=1
            fi
            case $save_originconf_fq in
            [nN][oO] | [nN])
                rm -rf ${nginx_conf_dir}/*.conf
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除!") ${Font}"
                ;;
            *)
                save_originconf="Yes"
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已保留!") ${Font}"
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
            service_start
            jq --arg nginx_build_version "${nginx_build_version}" '.nginx_build_version = $nginx_build_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            judge "Nginx $(gettext "升级")"
        else
            log_echo "${OK} ${GreenBG} Nginx $(gettext "已为最新版") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} Nginx $(gettext "未安装") ${Font}"
    fi
}

auto_update() {
    if [[ "${ID}" == "centos" ]]; then
        crontab_file="/var/spool/cron/root"
    else
        crontab_file="/var/spool/cron/crontabs/root"
    fi
    if [[ ! -f "${auto_update_file}" ]] || [[ $(crontab -l | grep -c "auto_update.sh") -lt 1 ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "设置后台定时自动更新程序 (包含: 脚本/Xray/Nginx)") ${Font}"
        log_echo "${GreenBG} $(gettext "可能自动更新后有兼容问题, 谨慎开启") ${Font}"
        log_echo "${GreenBG} $(gettext "是否开启") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            wget -N -P ${idleleo_dir} --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/auto_update.sh && chmod +x ${auto_update_file}
            echo "0 1 15 * * bash ${auto_update_file}" >>${crontab_file}
            judge "$(gettext "设置自动更新")"
            ;;
        *) ;;
        esac
    else
        log_echo "${OK} ${GreenBG} $(gettext "已设置自动更新") ${Font}"
        log_echo "${GreenBG} $(gettext "是否关闭") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_close_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            sed -i "/auto_update.sh/d" ${crontab_file}
            rm -rf ${auto_update_file}
            judge "$(gettext "删除自动更新")"
            ;;
        *) ;;
        esac
    fi
}

ssl_install() {
    pkg_install "socat"
    judge "$(gettext "安装 SSL 证书生成脚本依赖")"
    curl https://get.acme.sh | sh -s email=${custom_email}
    judge "$(gettext "安装 SSL 证书生成脚本")"
}

domain_check() {
    if [[ "on" == ${old_config_status} ]] && [[ $(info_extraction host) != null ]] && [[ $(info_extraction ip_version) != null ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "检测到原域名配置存在, 是否跳过域名设置") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r old_host_fq
        case $old_host_fq in
        [nN][oO] | [nN]) ;;
        *)
            domain=$(info_extraction host)
            ip_version=$(info_extraction ip_version)
            if [[ ${ip_version} == "IPv4" ]]; then
                local_ip=$(curl -4 ip.sb)
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(curl -6 ip.sb)
            else
                local_ip=${ip_version}
            fi
            log_echo "${OK} ${GreenBG} $(gettext "已跳过域名设置") ${Font}"
            return 0
            ;;
        esac
    fi
    echo -e "\n"
    log_echo "${GreenBG} $(gettext "确定域名信息") ${Font}"
    read_optimize "$(gettext "请输入你的域名信息") (e.g. www.idleleo.com):" "domain" "NULL"
    echo -e "\n${GreenBG} $(gettext "请选择公网IP(IPv4/IPv6)或手动输入域名") ${Font}"
    echo -e "${Red}1${Font}: IPv4 ($(gettext "默认"))"
    echo "2: IPv6 ($(gettext "不推荐"))"
    echo "3: $(gettext "域名")"
    local ip_version_fq
    read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")"
    log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
        domain_ip=$(ping -6 "${domain}" -c 1 | sed '2{s/[^(]*(//;s/).*//;q}' | tail -n +2)
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        log_echo "${Warning} ${GreenBG} $(gettext "此选项用于服务器商仅提供域名访问服务器") ${Font}"
        log_echo "${Warning} ${GreenBG} $(gettext "注意服务器商域名添加 CNAME 记录") ${Font}"
        read_optimize "$(gettext "请输入"): " "local_ip" "NULL"
        ip_version=${local_ip}
    else
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
        ip_version="IPv4"
    fi
    log_echo "$(gettext "域名DNS解析IP"): ${domain_ip}"
    log_echo "$(gettext "公网IP/域名"): ${local_ip}"
    if [[ ${ip_version_fq} != 3 ]] && [[ ${local_ip} == ${domain_ip} ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "域名DNS解析IP与公网IP匹配") ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请确保域名添加了正确的 A/AAAA 记录, 否则将无法正常使用 Xray") ${Font}"
        log_echo "${Error} ${RedBG} $(gettext "域名DNS解析IP与公网IP不匹配, 请选择"): ${Font}"
        echo "1: $(gettext "继续安装")"
        echo "2: $(gettext "重新输入")"
        log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
        local install
        read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")"
        case $install in
        1)
            log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
            ;;
        2)
            domain_check
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"
            exit 2
            ;;
        esac
    fi
}

ip_check() {
    if [[ "on" == ${old_config_status} || ${auto_update} == "YES" ]] && [[ $(info_extraction host) != null ]] && [[ $(info_extraction ip_version) != null ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            echo -e "\n"
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
                local_ip=$(curl -4 ip.sb)
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(curl -6 ip.sb)
            else
                local_ip=${ip_version}
            fi
            echo -e "\n"
            log_echo "${OK} ${GreenBG} $(gettext "已跳过IP设置") ${Font}"
            return 0
            ;;
        esac
    fi
    echo -e "\n"
    log_echo "${GreenBG} $(gettext "确定公网IP信息") ${Font}"
    log_echo "${GreenBG} $(gettext "请选择公网IP为IPv4或IPv6") ${Font}"
    echo -e "${Red}1${Font}: IPv4 ($(gettext "默认"))"
    echo "2: IPv6 ($(gettext "不推荐"))"
    echo "3: $(gettext "手动输入")"
    local ip_version_fq
    read_optimize "$(gettext "请输入"): " "ip_version_fq" 1 1 3 "$(gettext "请输入有效的数字")"
    [[ -z ${ip_version_fq} ]] && ip_version=1
    log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
        ip_version="IPv4"
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
        ip_version="IPv6"
    elif [[ ${ip_version_fq} == 3 ]]; then
        read_optimize "$(gettext "请输入"): " "local_ip" "NULL"
        ip_version=${local_ip}
    else
        local_ip=$(curl -4 ip.sb)
        ip_version="IPv4"
    fi
    log_echo "$(gettext "公网IP/域名"): ${local_ip}"
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "$1 端口未被占用") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "检测到 $1 端口被占用, 以下为 $1 端口占用信息") ${Font}"
        lsof -i:"$1"
        timeout "$(gettext "尝试自动 kill 占用进程")!"
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        log_echo "${OK} ${GreenBG} $(gettext "kill 完成") ${Font}"
    fi
}

acme() {
    systemctl restart nginx
    #暂时解决ca问题
    if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --server letsencrypt --keylength ec-256 --force --test; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --keylength ec-256 --force --test; then
        log_echo "${OK} ${GreenBG} $(gettext "SSL 证书测试签发成功, 开始正式签发") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
    else
        log_echo "${Error} ${RedBG} $(gettext "SSL 证书测试签发失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --server letsencrypt --keylength ec-256 --force; then
    #if "$HOME"/.acme.sh/acme.sh --issue -d ${domain} -w ${idleleo_conf_dir} --keylength ec-256 --force; then
        log_echo "${OK} ${GreenBG} $(gettext "SSL 证书生成成功") ${Font}"
        mkdir -p ${ssl_chainpath}
        if "$HOME"/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc --force; then
            chmod -f a+rw ${ssl_chainpath}/xray.crt
            chmod -f a+rw ${ssl_chainpath}/xray.key
            chown -fR nobody:nogroup ${ssl_chainpath}/*
            log_echo "${OK} ${GreenBG} $(gettext "证书配置成功") ${Font}"
            systemctl stop nginx
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "SSL 证书生成失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    if [[ $(info_extraction multi_user) != "yes" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json -O ${xray_conf}
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "Reality" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_reality/config.json -O ${xray_conf}
            modify_target_serverNames
            modify_privateKey_shortIds
            xray_reality_add_more
        elif [[ ${tls_mode} == "None" ]]; then
            wget --no-check-certificate https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/VLESS_tls/config.json -O ${xray_conf}
            modify_listen_address
            modify_path
            modify_inbound_port
        fi
        modify_email_address
        modify_UUID
    else
        echo -e "\n"
        log_echo "${Warning} ${GreenBG} $(gettext "检测到 Xray 配置过多用户") ${Font}"
        log_echo "${GreenBG} $(gettext "是否保留原 Xray 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r save_originxray_fq
        case $save_originxray_fq in
        [nN][oO] | [nN])
            rm -rf ${xray_conf}
            log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除!") ${Font}"
            xray_conf_add
            ;;
        *) ;;
        esac
    fi
}

xray_reality_add_more() {
    if [[ ${reality_add_more} == "on" ]]; then
        modify_path
        modify_listen_address
        modify_inbound_port
        judge "$(gettext "添加简单 ws/gRPC 协议")"
    else
        modify_path
        modify_inbound_port
    fi

    if [[ ${reality_add_nginx} == "on" ]]; then
        modify_reality_listen_address
    fi
}

old_config_exist_check() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "检测到配置文件, 是否读取配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [nN][oO] | [nN])
                rm -rf ${xray_qr_config_file}
                log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
                ;;
            *)
                log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
                old_config_status="on"
                old_config_input
                ;;
            esac
        else
            echo -e "\n"
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
                rm -rf ${xray_qr_config_file}
                log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
                ;;
            esac
        fi
    fi
}

old_config_input() {
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
    custom_email=$(info_extraction email)
    UUID5_char=$(info_extraction idc)
    UUID=$(info_extraction id)
    if [[ ${tls_mode} == "TLS" ]]; then
        port=$(info_extraction port)
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$((RANDOM % 1000 + 30000))
            [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
            xport=$((RANDOM % 1000 + 20000))
            [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        port=$(info_extraction port)
        target=$(info_extraction target)
        serverNames=$(info_extraction serverNames)
        privateKey=$(info_extraction privateKey)
        publicKey=$(info_extraction publicKey)
        shortIds=$(info_extraction shortIds)
        if [[ ${reality_add_more} == "on" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
                gport=$((RANDOM % 1000 + 30000))
                [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
                serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
                xport=$((RANDOM % 1000 + 20000))
                [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
                path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
            fi
        else
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            xport=$((RANDOM % 1000 + 20000))
            gport=$((RANDOM % 1000 + 30000))
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$((RANDOM % 1000 + 30000))
            [[ ${gport} == ${xport} ]] && gport=$((RANDOM % 1000 + 30000))
            serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
            xport=$((RANDOM % 1000 + 20000))
            [[ ${gport} == ${xport} ]] && xport=$((RANDOM % 1000 + 20000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "检测到配置文件不完整, 是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        [yY][eE][sS] | [yY])
            old_config_status="off"
            log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
            ;;
        *)
            rm -rf ${xray_qr_config_file}
            old_config_status="off"
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
            ;;
        esac
    fi
}

nginx_ssl_conf_add() {
    touch ${nginx_ssl_conf}
    cat >${nginx_ssl_conf} <<EOF
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
        return 301 https://www.idleleo.com\$request_uri;
    }
}
EOF
    modify_nginx_ssl_other
    judge "$(gettext "Nginx SSL 配置修改")"
}

nginx_conf_add() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF
server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl reuseport;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    http2 on;
    set_real_ip_from    127.0.0.1;
    real_ip_header      X-Forwarded-For;
    real_ip_recursive   on;
    ssl_certificate       ${idleleo_dir}/cert/xray.crt;
    ssl_certificate_key   ${idleleo_dir}/cert/xray.key;
    ssl_protocols         TLSv1.3;
    ssl_ciphers           TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA;
    server_name           serveraddr.com;
    index index.html index.htm;
    root /403.html;
    error_page 403 https://www.idleleo.com/helloworld;
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
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        client_max_body_size 0;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
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

    location /
    {
        return 403;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "$(gettext "Nginx 配置修改")"
}

nginx_reality_conf_add() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF

stream {
    map \$ssl_preread_server_name \$stream_map {
        include ${nginx_conf_dir}/*.serverNames;
    }
 
    upstream reality {
        server 127.0.0.1:9443;
    }

    server {
        listen 443 reuseport so_keepalive=on backlog=65535;
        proxy_pass \$stream_map;
        ssl_preread on;
        #proxy_protocol on;
        
        # 超时设置
        proxy_connect_timeout 20s;       # 连接超时时间
        proxy_timeout 300s;            # 数据传输超时时间
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "$(gettext "Nginx 配置修改")"
}

nginx_reality_serverNames_add () {
    touch ${nginx_conf_dir}/${serverNames}.serverNames
    cat >${nginx_conf_dir}/${serverNames}.serverNames <<EOF
${serverNames} reality;
EOF
    # modify_nginx_reality_serverNames
    judge "$(gettext "Nginx serverNames 配置修改")"

}

nginx_reality_serverNames_del () {
    [[ -f "${nginx_conf_dir}/${serverNames}.serverNames" ]] && rm -f "${nginx_conf_dir}/${serverNames}.serverNames"
    # modify_nginx_reality_serverNames
    judge "$(gettext "Nginx serverNames 配置删除")"

}

nginx_servers_conf_add() {
    touch ${nginx_upstream_conf}
    cat >${nginx_upstream_conf} <<EOF
upstream xray-ws-server {
    include ${nginx_conf_dir}/*.wsServers;
}

upstream xray-grpc-server {
    include ${nginx_conf_dir}/*.grpcServers;
}
EOF
    nginx_servers_add
    judge "$(gettext "Nginx servers 配置修改")"
}

enable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl enable nginx && judge "$(gettext "设置 Nginx 开机自启")"
    fi
    systemctl enable xray
    judge "$(gettext "设置 Xray 开机自启")"
}

disable_process_systemd() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && systemctl disable nginx && judge "$(gettext "关闭 Nginx 开机自启")"
    fi
    systemctl disable xray
    judge "$(gettext "关闭 Xray 开机自启")"
}

stop_service_all() {
    [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && systemctl disable nginx
    systemctl stop xray
    systemctl disable xray
    log_echo "${OK} ${GreenBG} $(gettext "停止已有服务") ${Font}"
}

service_restart() {
    systemctl daemon-reload
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl restart nginx && judge "$(gettext "Nginx 重启")"
    fi
    systemctl restart xray
    judge "$(gettext "Xray 重启")"
}

service_start() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl start nginx && judge "$(gettext "Nginx 启动")"
    fi
    systemctl start xray
    judge "$(gettext "Xray 启动")"
}

service_stop() {
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        [[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx && judge "$(gettext "Nginx 停止")"
    fi
    systemctl stop xray
    judge "$(gettext "Xray 停止")"
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
            echo -e "\n"
            log_echo "${Warning} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "老版本请及时删除 废弃的 改版证书自动更新!") ${Font}"
            log_echo "${GreenBG} $(gettext "已设置改版证书自动更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除改版证书自动更新 (请删除)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r remove_acme_cron_update_fq
            case $remove_acme_cron_update_fq in
            [nN][oO] | [nN]) ;;
            *)
                sed -i "/ssl_update.sh/d" ${crontab_file}
                rm -rf ${ssl_update_file}
                judge "$(gettext "删除改版证书自动更新")"
                ;;

            esac
        else
            echo -e "\n"
            log_echo "${OK} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作!") ${Font}"
    fi
}

check_cert_status() {
    if [[ ${tls_mode} == "TLS" ]]; then
        host="$(info_extraction host)"
        if [[ -d "$HOME/.acme.sh/${host}_ecc" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.key" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.cer" ]]; then
            modifyTime=$(stat "$HOME/.acme.sh/${host}_ecc/${host}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')
            modifyTime=$(date +%s -d "${modifyTime}")
            currentTime=$(date +%s)
            ((stampDiff = currentTime - modifyTime))
            ((days = stampDiff / 86400))
            ((remainingDays = 90 - days))
            tlsStatus=${remainingDays}
            [[ ${remainingDays} -le 0 ]] && tlsStatus="${Red}$(gettext "已过期")${Font}"
            echo -e "\n"
            log_echo "${Green}$(gettext "证书生成日期"): $(date -d "@${modifyTime}" +"%F %H:%M:%S")${Font}"
            log_echo "${Green}$(gettext "证书生成天数"): ${days}${Font}"
            log_echo "${Green}$(gettext "证书剩余天数"): ${tlsStatus}${Font}"
            echo -e "\n"
            if [[ ${remainingDays} -le 0 ]]; then
                echo -e "\n"
                log_echo "${Warning} ${YellowBG} $(gettext "是否立即更新证书") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r cert_update_manuel_fq
                case $cert_update_manuel_fq in
                [yY][eE][sS] | [yY])
                    systemctl stop xray
                    judge "$(gettext "Xray 停止")"
                    cert_update_manuel
                    ;;
                *) ;;
                esac
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发!") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作!") ${Font}"
    fi
}

cert_update_manuel() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ -f "${amce_sh_file}" ]]; then
            "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh"
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发!") ${Font}"
        fi
        host="$(info_extraction host)"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${host}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
        judge "$(gettext "证书更新")"
        service_restart
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作!") ${Font}"
    fi
}

set_fail2ban() {
    mf_remote_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/fail2ban_manager.sh"
    if [ ! -f "${idleleo_dir}/fail2ban_manager.sh" ]; then
        log_echo "${Info} ${Green} $(gettext "本地文件 fail2ban_manager.sh 不存在，正在下载...") ${Font}"
        curl -sL "$mf_remote_url" -o "${idleleo_dir}/fail2ban_manager.sh"
        if [ $? -ne 0 ]; then
            log_echo "${Error} ${RedBG} $(gettext "下载失败，请手动下载并安装新版本") ${Font}"
            return 1
        fi
        chmod +x "${idleleo_dir}/fail2ban_manager.sh"
    fi
    source "${idleleo_dir}/fail2ban_manager.sh"
}

clean_logs() {
    local cron_file logrotate_config
    echo -e "\n"
    log_echo "${Green} $(gettext "检测到日志文件大小如下:") ${Font}"
    log_echo "${Green}$(du -sh /var/log/xray ${nginx_dir}/logs)${Font}"
    timeout "$(gettext "即将清除!")"
    for i in $(find /var/log/xray/ ${nginx_dir}/logs -name "*.log"); do cat /dev/null >"$i"; done
    judge "$(gettext "日志清理")"
    
    #以下为兼容代码，1个大版本后删除
    if [[ "${ID}" == "centos" ]]; then
        cron_file="/var/spool/cron/root"
    else
        cron_file="/var/spool/cron/crontabs/root"
    fi

    if [[ $(grep -c "find /var/log/xray/ /etc/nginx/logs -name" "$cron_file") -ne '0' ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "已设置旧版自动清理日志任务") ${Font}"
        log_echo "${GreenBG} $(gettext "是否需要删除旧版自动清理日志任务") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r delete_task
        case $delete_task in
        [nN][oO] | [nN])
            log_echo "${OK} ${Green} $(gettext "保留现有自动清理日志任务") ${Font}"
            return
            ;;
        *)
            sed -i "/find \/var\/log\/xray\/ \/etc\/nginx\/logs -name/d" "$cron_file"
            judge "$(gettext "删除旧版自动清理日志任务")"
            ;;
        esac
    fi
    #兼容代码结束

    echo -e "\n"
    log_echo "${GreenBG} $(gettext "是否需要设置自动清理日志") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r auto_clean_logs_fq
    case $auto_clean_logs_fq in
    [nN][oO] | [nN])
        timeout "$(gettext "清空屏幕!")"
        clear
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
                judge "$(gettext "删除自动清理日志任务")"
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
        echo "    create 640 nobody nogroup" >> "$logrotate_config"
        echo "}" >> "$logrotate_config"
        
        judge "$(gettext "设置自动清理日志")"
        ;;
    esac
}

vless_qr_config_tls_ws() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${domain}",
    "ip_version": "${ip_version}",
    "port": ${port},
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "tls": "TLS",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}",
    "nginx_build_version": "${nginx_build_version}"
}
EOF
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_qr_config_reality() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
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
    "publicKey":"${publicKey}",
    "shortIds":"${shortIds}",
    "reality_add_nginx": "${reality_add_nginx}",
    "reality_add_more": "${reality_add_more}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "ws_path": "${artpath}",
    "grpc_serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    if [[ ${reality_add_nginx} == "on" ]]; then
        jq --arg nginx_build_version "${nginx_build_version}" '. + {"nginx_build_version": $nginx_build_version}' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
    fi
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_qr_config_ws_only() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "tls": "None",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version}"
}
EOF
    info_extraction_all=$(jq -rc . ${xray_qr_config_file})
}

vless_urlquote() {
    [[ $# = 0 ]] && return 1
    echo "import urllib.request;print(urllib.request.quote('$1'));" | python3
}

vless_qr_link_image() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        vless_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?security=reality&flow=xtls-rprx-vision&fp=chrome&pbk=$(info_extraction publicKey)&sni=$(info_extraction serverNames)&target=$(info_extraction target)&sid=$(info_extraction shortIds)#$(vless_urlquote $(info_extraction host))+Reality%E5%8D%8F%E8%AE%AE"
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction ws_port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction id)@$(vless_urlquote $(info_extraction host)):$(info_extraction grpc_port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction host))+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
        fi
    fi
    {
        echo -e "\n"
        log_echo "${Red} —————————————— $(gettext "Xray 配置分享") —————————————— ${Font}"
        if [[ ${tls_mode} == "Reality" ]]; then
            log_echo "${Red} $(gettext "URL 分享链接"):${Font} ${vless_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo -e "\n"
        fi
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            log_echo "${Red} $(gettext "ws URL 分享链接"):${Font} ${vless_ws_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo -e "\n"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            log_echo "${Red} $(gettext "gRPC URL 分享链接"):${Font} ${vless_grpc_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo -e "\n"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            log_echo "${Red} $(gettext "ws URL 分享链接"):${Font} ${vless_ws_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo -e "\n"
            log_echo "${Red} $(gettext "gRPC URL 分享链接"):${Font} ${vless_grpc_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo -e "\n"
        fi
    } >>"${xray_info_file}"
}

vless_link_image_choice() {
    echo -e "\n"
    log_echo "${GreenBG} $(gettext "生成分享链接"): ${Font}"
    vless_qr_link_image
}

info_extraction() {
    echo ${info_extraction_all} | jq -r ".$1"
    [[ 0 -ne $? ]] && read_config_status=0
}

basic_information() {
    {
        echo -e "\n"
        case ${shell_mode} in
        Nginx+ws+TLS)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Nginx+ws+TLS 安装成功") ${Font}"
            ;;
        Nginx+gRPC+TLS)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Nginx+grpc+TLS 安装成功") ${Font}"
            ;;
        Nginx+ws+gRPC+TLS)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Nginx+ws+gRPC+TLS 安装成功") ${Font}"
            ;;
        Reality)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Reality 安装成功") ${Font}"
            ;;
        Reality+ws)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Reality+ws 安装成功") ${Font}"
            ;;
        Reality+gRPC)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Reality+gRPC 安装成功") ${Font}"
            ;;
        Reality+ws+gRPC)
            log_echo "${OK} ${GreenBG} $(gettext "Xray+Reality+ws+gRPC 安装成功") ${Font}"
            ;;
        ws\ ONLY)
            log_echo "${OK} ${GreenBG} $(gettext "ws ONLY 安装成功") ${Font}"
            ;;
        gRPC\ ONLY)
            log_echo "${OK} ${GreenBG} $(gettext "gRPC ONLY 安装成功") ${Font}"
            ;;
        ws+gRPC\ ONLY)
            log_echo "${OK} ${GreenBG} $(gettext "ws+gRPC ONLY 安装成功") ${Font}"
            ;;
        esac
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} $(gettext "VLESS 目前分享链接规范为实验阶段, 请自行判断是否适用") ${Font}"
        echo -e "\n"
        log_echo "${Red} —————————————— $(gettext "Xray 配置信息") —————————————— ${Font}"
        log_echo "${Red} $(gettext "主机") (host):${Font} $(info_extraction host) "
        if [[ ${tls_mode} == "None" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} $(gettext "ws 端口") (port):${Font} $(info_extraction ws_port) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} $(gettext "gRPC 端口") (port):${Font} $(info_extraction grpc_port) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} $(gettext "ws 端口") (port):${Font} $(info_extraction ws_port) "
                log_echo "${Red} $(gettext "gRPC 端口") (port):${Font} $(info_extraction grpc_port) "
            fi
        else
            log_echo "${Red} $(gettext "端口") (port):${Font} $(info_extraction port) "
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} $(gettext "Xray ws 端口") (inbound_port):${Font} $(info_extraction ws_port) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} $(gettext "Xray gRPC 端口") (inbound_port):${Font} $(info_extraction grpc_port) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} $(gettext "Xray ws 端口") (inbound_port):${Font} $(info_extraction ws_port) "
                log_echo "${Red} $(gettext "Xray gRPC 端口") (inbound_port):${Font} $(info_extraction grpc_port) "
            fi
        fi
        log_echo "${Red} $(gettext "UUIDv5 映射字符串"):${Font} $(info_extraction idc)"
        log_echo "${Red} $(gettext "用户id") (UUID):${Font} $(info_extraction id)"

        log_echo "${Red} $(gettext "加密") (encryption):${Font} None "
        log_echo "${Red} $(gettext "传输协议") (network):${Font} $(info_extraction net) "
        log_echo "${Red} $(gettext "底层传输安全") (tls):${Font} $(info_extraction tls) "  
        if [[ ${tls_mode} != "Reality" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                log_echo "${Red} $(gettext "路径") (path $(gettext "不要落下/")):${Font} /$(info_extraction path) "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                log_echo "${Red} serviceName ($(gettext "不需要加/")):${Font} $(info_extraction serviceName) "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                log_echo "${Red} $(gettext "路径") (path $(gettext "不要落下/")):${Font} /$(info_extraction path) "
                log_echo "${Red} serviceName ($(gettext "不需要加/")):${Font} $(info_extraction serviceName) "
            fi
        else
            log_echo "${Red} $(gettext "流控") (flow):${Font} xtls-rprx-vision "
            log_echo "${Red} target:${Font} $(info_extraction target) "
            log_echo "${Red} serverNames:${Font} $(info_extraction serverNames) "
            log_echo "${Red} privateKey:${Font} $(info_extraction privateKey) "
            log_echo "${Red} publicKey:${Font} $(info_extraction publicKey) "
            log_echo "${Red} shortIds:${Font} $(info_extraction shortIds) "
            if [[ "$reality_add_more" == "on" ]]; then
                if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                    log_echo "${Red} $(gettext "ws 端口") (port):${Font} $(info_extraction ws_port) "
                    log_echo "${Red} $(gettext "ws 路径") ($(gettext "不要落下/")):${Font} /$(info_extraction ws_path) "
                elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                    log_echo "${Red} $(gettext "gRPC 端口") (port):${Font} $(info_extraction grpc_port) "
                    log_echo "${Red} gRPC serviceName ($(gettext "不需要加/")):${Font} $(info_extraction grpc_serviceName) "
                elif [[ ${ws_grpc_mode} == "all" ]]; then
                    log_echo "${Red} $(gettext "ws 端口") (port):${Font} $(info_extraction ws_port) "
                    log_echo "${Red} $(gettext "ws 路径") ($(gettext "不要落下/")):${Font} /$(info_extraction ws_path) "
                    log_echo "${Red} $(gettext "gRPC 端口") (port):${Font} $(info_extraction grpc_port) "
                    log_echo "${Red} gRPC serviceName ($(gettext "不需要加/")):${Font} $(info_extraction grpc_serviceName) "
                fi
            fi
        fi
    } >"${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    cd $HOME
    echo -e "\n"
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
                rm -rf ${ssl_chainpath}/*
                log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR nobody:nogroup ${ssl_chainpath}/*
                judge "$(gettext "证书应用")"
                ;;
            esac
        elif [[ -f "${ssl_chainpath}/xray.key" || -f "${ssl_chainpath}/xray.crt" ]] && [[ ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            log_echo "${GreenBG} $(gettext "证书文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r ssl_delete_2
            case $ssl_delete_2 in
            [nN][oO] | [nN])
                rm -rf ${ssl_chainpath}/*
                log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -fR nobody:nogroup ${ssl_chainpath}/*
                judge "$(gettext "证书应用")"
                ssl_self="on"
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
                "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
                chown -fR nobody:nogroup ${ssl_chainpath}/*
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
    cat >${nginx_systemd_file} <<EOF
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

    judge "$(gettext "Nginx systemd ServerFile 添加")"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "${nginx_conf}" ]] && [[ ${tls_mode} == "TLS" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "请选择支持的 TLS 版本") (default:2): ${Font}"
        log_echo "${GreenBG} $(gettext "建议选择 TLS1.3 only (安全模式)") ${Font}"
        echo -e "1: TLS1.2 and TLS1.3 ($(gettext "兼容模式"))"
        echo -e "${Red}2${Font}: TLS1.3 only ($(gettext "安全模式"))"
        local choose_tls
        read_optimize "$(gettext "请输入"): " "choose_tls" 2 1 2 "$(gettext "请输入有效的数字")"
        if [[ ${choose_tls} == 1 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "从 2.2.1 版本起, 由于启用 h3 仅支持 TLS1.3, 请选择 TLS1.3 only (安全模式)")! ${Font}"
            tls_type
        else
            sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
            log_echo "${OK} ${GreenBG} $(gettext "已切换至 TLS1.3 only") ${Font}"
        fi
        [[ -f "${nginx_systemd_file}" ]] && systemctl restart nginx && judge "$(gettext "Nginx 重启")"
        systemctl restart xray
        judge "$(gettext "Xray 重启")"
    else
        log_echo "${Error} ${RedBG} $(gettext "Nginx/配置文件不存在 或 当前模式不支持") ${Font}"
    fi
}

reset_vless_qr_config() {
    basic_information
    vless_qr_link_image
    show_information
}

reset_UUID() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        UUID_set
        modify_UUID
        jq --arg uuid "${UUID}" \
           --arg uuid5_char "${UUID5_char}" \
           '.id = $uuid | .idc = $uuid5_char' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        service_restart
        reset_vless_qr_config
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

reset_port() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            read_optimize "$(gettext "请输入连接端口") ($(gettext "默认值"):443):" "port" 443 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
            modify_nginx_port
            jq --argjson port "${port}" '.port = $port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            log_echo "${Green} $(gettext "连接端口号"): ${port} ${Font}"
        elif [[ ${tls_mode} == "Reality" ]]; then
            read_optimize "$(gettext "请输入连接端口") ($(gettext "默认值"):443):" "port" 443 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
            xport=$((RANDOM % 1000 + 20000))
            gport=$((RANDOM % 1000 + 30000))
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${xport}"
                gport=$((RANDOM % 1000 + 30000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${ws_grpc_mode} == "onlygrpc" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${gport}"
                xport=$((RANDOM % 1000 + 20000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            fi
            jq --argjson port "$port" \
               --argjson ws_port "$xport" \
               --argjson grpc_port "$gport" \
               '.port = $port | .ws_port = $ws_port | .grpc_port = $grpc_port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            modify_inbound_port
            [[ ${reality_add_nginx} == "on" ]] && modify_nginx_port
        elif [[ ${tls_mode} == "None" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${xport}"
                gport=$((RANDOM % 1000 + 30000))
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${ws_grpc_mode} == "onlygrpc" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${gport}"
                xport=$((RANDOM % 1000 + 20000))
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 0 65535 "$(gettext "请输入 0-65535 之间的值")!"
                port_exist_check "${xport}"
                port_exist_check "${gport}"
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            fi
            jq --argjson ws_port "$xport" \
               --argjson grpc_port "$gport" \
               '.ws_port = ($ws_port | .grpc_port = $grpc_port' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            modify_inbound_port
        fi
        firewall_set
        service_restart
        reset_vless_qr_config
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
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
        jq --arg target "${target}" \
           --arg serverNames "${serverNames}" \
           '.target = $target | .serverNames = $serverNames' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        service_restart
        reset_vless_qr_config
    elif [[ ${tls_mode} != "Reality" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持修改 target") ! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

show_user() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "即将显示用户, 一次仅能显示一个") ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} $(gettext "请选择 显示用户使用的协议 ws/gRPC") ${Font}"
            echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")"
            choose_user_prot=$((choose_user_prot - 1))
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
        fi
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "请选择 要显示的用户编号"): ${Font}"
        jq -r -c .inbounds[${choose_user_prot}].settings.clients[].email ${xray_conf} | awk '{print NR""": "$0}'
        local show_user_index
        read_optimize "$(gettext "请输入"): " "show_user_index" "NULL"
        if [[ $(jq -r '.inbounds['${choose_user_prot}'].settings.clients|length' ${xray_conf}) -lt ${show_user_index} ]] || [[ ${show_user_index} == 0 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "选择错误") ! ${Font}"
            show_user
        elif [[ ${show_user_index} == 1 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "请直接在主菜单选择 [15] 显示主用户") ${Font}"
            timeout "$(gettext "回到菜单") !"
            menu
        elif [[ ${show_user_index} -gt 1 ]]; then
            show_user_index=$((show_user_index - 1))
            user_email=$(jq -r -c '.inbounds['${choose_user_prot}'].settings.clients['${show_user_index}'].email' ${xray_conf})
            user_id=$(jq -r -c '.inbounds['${choose_user_prot}'].settings.clients['${show_user_index}'].id' ${xray_conf})
        elif [[ ! -z $(echo ${show_user_index} | sed 's/[0-9]//g') ]] || [[ ${show_user_index} == '' ]]; then
            log_echo "${Error} ${RedBG} $(gettext "选择错误") ! ${Font}"
            show_user
        else
            log_echo "${Warning} ${YellowBG} $(gettext "请先检测 Xray 是否正确安装") ! ${Font}"
            timeout "$(gettext "回到菜单") !"
            menu
        fi
        if [[ ! -z ${user_email} ]] && [[ ! -z ${user_id} ]]; then
            log_echo "${Green} $(gettext "用户名"): ${user_email} ${Font}"
            log_echo "${Green} UUID: ${user_id} ${Font}"
            if [[ ${tls_mode} == "TLS" ]]; then
                if [[ ${choose_user_prot} == 0 ]]; then
                    user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?path=%2f$(vless_urlquote $(info_extraction path))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=ws#$(vless_urlquote $(info_extraction host))+ws%E5%8D%8F%E8%AE%AE"
                elif [[ ${choose_user_prot} == 1 ]]; then
                    user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?serviceName=$(vless_urlquote $(info_extraction serviceName))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction host))&type=grpc#$(vless_urlquote $(info_extraction host))+gRPC%E5%8D%8F%E8%AE%AE"
                fi
            elif [[ ${tls_mode} == "Reality" ]]; then
                user_vless_link="vless://${user_id}@$(vless_urlquote $(info_extraction host)):$(info_extraction port)?security=tls&encryption=none&headerType=none&type=raw&flow=xtls-rprx-vision#$(vless_urlquote $(info_extraction host))+reality%E5%8D%8F%E8%AE%AE"
            fi
            log_echo "${Red} $(gettext "URL 分享链接"):${Font} ${user_vless_link}"
            echo -n "${user_vless_link}" | qrencode -o - -t utf8
        fi
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否继续显示用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r show_user_continue
        case $show_user_continue in
        [yY][eE][sS] | [yY])
            show_user
            ;;
        *) ;;
        esac
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持删除用户") ! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

add_user() {
    local choose_user_prot
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        service_stop
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "即将添加用户, 一次仅能添加一个") ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} $(gettext "请选择 添加用户使用的协议 ws/gRPC") ${Font}"
            echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")"
            choose_user_prot=$((choose_user_prot - 1))
            reality_user_more=""
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
            reality_user_more="\"flow\":\"xtls-rprx-vision\","
        fi
        email_set
        UUID_set
        jq --argjson choose_user_prot "${choose_user_prot}" \
           --arg UUID "${UUID}" \
           --arg reality_user_more "${reality_user_more}" \
           --arg custom_email "${custom_email}" \
           '.inbounds[$choose_user_prot].settings.clients += [
               {"id": $UUID} +
               if $reality_user_more != "" then ($reality_user_more | fromjson) else {} end +
               {"level": 0, "email": $custom_email}
           ]' "${xray_conf}" > "${xray_conf}.tmp"
        judge "$(gettext "添加用户")"
        mv "${xray_conf}.tmp" "${xray_conf}"
        jq ". += {\"multi_user\": \"yes\"}" ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
        mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "是否继续添加用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r add_user_continue
        case $add_user_continue in
        [yY][eE][sS] | [yY])
            add_user
            ;;
        *) ;;
        esac
        service_start
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持添加用户") ! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

remove_user() {
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} != "None" ]]; then
        service_stop
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "即将删除用户, 一次仅能删除一个") ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            log_echo "${GreenBG} $(gettext "请选择 删除用户使用的协议 ws/gRPC") ${Font}"
            echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
            echo "2: gRPC"
            local choose_user_prot
            read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")"
            choose_user_prot=$((choose_user_prot - 1))
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_prot=0
        fi
        echo -e "\n"
        log_echo "${GreenBG} $(gettext "请选择 要删除的用户编号") ${Font}"
        jq -r -c .inbounds[${choose_user_prot}].settings.clients[].email ${xray_conf} | awk '{print NR""": "$0}'
        local del_user_index
        read_optimize "$(gettext "请输入"): " "del_user_index" "NULL"
        if [[ $(jq -r '.inbounds['${choose_user_prot}'].settings.clients|length' ${xray_conf}) -lt ${del_user_index} ]] || [[ ${show_user_index} == 0 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "选择错误") ! ${Font}"
            remove_user
        elif [[ ${del_user_index} == 1 ]]; then
            echo -e "\n"
            log_echo "${Error} ${RedBG} $(gettext "请直接在主菜单修改主用户的 UUID/Email") ! ${Font}"
            timeout "$(gettext "回到菜单") !"
            menu
        elif [[ ${del_user_index} -gt 1 ]]; then
            del_user_index=$((del_user_index - 1))
            jq --argjson choose_user_prot "${choose_user_prot}" --argjson del_user_index "${del_user_index}" \
               'del(.inbounds[$choose_user_prot].settings.clients[$del_user_index])' ${xray_conf} > "${xray_conf}.tmp"
            judge "$(gettext "删除用户")"
            mv "${xray_conf}.tmp" "${xray_conf}"
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "是否继续删除用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r remove_user_continue
            case $remove_user_continue in
            [yY][eE][sS] | [yY])
                remove_user
                ;;
            *) ;;
            esac
        elif [[ ! -z $(echo ${del_user_index} | sed 's/[0-9]//g') ]] || [[ ${del_user_index} == '' ]]; then
            log_echo "${Error} ${RedBG} $(gettext "选择错误") ! ${Font}"
            remove_user
        else
            log_echo "${Warning} ${YellowBG} $(gettext "请先检测 Xray 是否正确安装") ! ${Font}"
            timeout "$(gettext "回到菜单") !"
            menu
        fi
        service_start
    elif [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持删除用户") ! ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

show_access_log() {
    [[ -f "${xray_access_log}" ]] && tail -f ${xray_access_log} || log_echo "${Error} ${RedBG} $(gettext "log文件不存在") ! ${Font}"
}

show_error_log() {
    [[ -f "${xray_error_log}" ]] && tail -f ${xray_error_log} || log_echo "${Error} ${RedBG} $(gettext "log文件不存在") ! ${Font}"
}

xray_status_add() {
    if [[ -f "${xray_conf}" ]]; then
        if [[ $(jq -r .stats ${xray_conf}) != null ]]; then
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "已配置 Xray 流量统计") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要关闭此功能") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop
                jq "del(.api)|del(.stats)|del(.policy)" ${xray_conf} > "${xray_conf}.tmp"
                judge "$(gettext "关闭 Xray 流量统计")"
                mv "${xray_conf}.tmp" "${xray_conf}"
                service_start
                [[ -f "${xray_status_conf}" ]] && rm -rf ${xray_status_conf}
                ;;
            *) ;;
            esac
        else
            echo -e "\n"
            log_echo "${GreenBG} $(gettext "Xray 流量统计需要使用 api") ${Font}"
            log_echo "${GreenBG} $(gettext "可能会影响 Xray 性能") ${Font}"
            log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop
                wget -nc --no-check-certificate "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/status_config.json" -O ${xray_status_conf}
                local status_config
                status_config=$(jq -c . "${xray_status_conf}")
                jq --argjson status_config "${status_config}" \
                    '. += $status_config' "${xray_conf}" > "${xray_conf}.tmp"
                judge "$(gettext "设置 Xray 流量统计")"
                mv "${xray_conf}.tmp" "${xray_conf}"
                service_start
                ;;
            *) ;;
            esac
        fi
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装 Xray") ! ${Font}"
    fi
}

bbr_boost_sh() {
    if [[ -f "${idleleo_dir}/tcp.sh" ]]; then
        cd ${idleleo_dir} && chmod +x ./tcp.sh && ./tcp.sh
    else
        wget -N --no-check-certificate -P ${idleleo_dir} "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x ${idleleo_dir}/tcp.sh && ${idleleo_dir}/tcp.sh
    fi
}

uninstall_all() {
    stop_service_all
    if [[ -f "${xray_bin_dir}/xray" ]]; then
        systemctl disable xray
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        [[ -d "${xray_conf_dir}" ]] && rm -rf ${xray_conf_dir}
        if [[ -f "${xray_qr_config_file}" ]]; then
            jq -r 'del(.xray_version)' ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
            mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
        fi
        log_echo "${OK} ${GreenBG} $(gettext "已卸载 Xray") ${Font}"
    fi
    if [[ -d "${nginx_dir}" ]]; then
        log_echo "${GreenBG} $(gettext "是否卸载 Nginx") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            systemctl disable nginx
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*
            [[ -f "${nginx_systemd_file}" ]] && rm -rf ${nginx_systemd_file}
            if [[ -f "${xray_qr_config_file}" ]]; then
                jq 'del(.nginx_build_version)' ${xray_qr_config_file} > "${xray_qr_config_file}.tmp"
                mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            fi
            log_echo "${OK} ${GreenBG} $(gettext "已卸载 Nginx") ${Font}"
            ;;
        *) ;;
        esac
    fi
    log_echo "${GreenBG} $(gettext "是否删除所有脚本文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r remove_all_idleleo_file_fq
    case $remove_all_idleleo_file_fq in
    [yY][eE][sS] | [yY])
        rm -rf ${idleleo_commend_file}
        rm -rf ${idleleo_dir}
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已删除所有文件") ${Font}"
        log_echo "${GreenBG} $(gettext "ヾ(￣▽￣) 拜拜~") ${Font}"
        exit 0
        ;;
    *)
        systemctl daemon-reload
        log_echo "${OK} ${GreenBG} $(gettext "已保留脚本文件 (包含 SSL 证书等)") ${Font}"
        ;;
    esac
    if [[ -f "${xray_qr_config_file}" ]]; then
        log_echo "${GreenBG} $(gettext "是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r remove_config_fq
        case $remove_config_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
            ;;
        *)
            rm -rf ${xray_qr_config_file}
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
            ;;
        esac
    fi
}

delete_tls_key_and_crt() {
    [[ -f "$HOME/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d "$HOME/.acme.sh" ]] && rm -rf "$HOME/.acme.sh"
    log_echo "${OK} ${GreenBG} $(gettext "已清空证书遗留文件") ${Font}"
}

timeout() {
    timeout=0
    timeout_str=""
    while [[ ${timeout} -le 30 ]]; do
        let timeout++
        timeout_str+="#"
    done
    let timeout=timeout+5
    while [[ ${timeout} -gt 0 ]]; do
        let timeout--
        if [[ ${timeout} -gt 25 ]]; then
            let timeout_color=32
            let timeout_bg=42
            timeout_index="3"
        elif [[ ${timeout} -gt 15 ]]; then
            let timeout_color=33
            let timeout_bg=43
            timeout_index="2"
        elif [[ ${timeout} -gt 5 ]]; then
            let timeout_color=31
            let timeout_bg=41
            timeout_index="1"
        else
            timeout_index="0"
        fi
        printf "${Warning} ${GreenBG} %d%s%s ${Font} \033[%d;%dm%-s\033[0m \033[%dm%d\033[0m \r" \
            "$timeout_index" \
            "$(gettext "秒后将")" \
            "$1" \
            "$timeout_color" \
            "$timeout_bg" \
            "$timeout_str" \
            "$timeout_color" \
            "$timeout_index"
        sleep 0.1
        timeout_str=${timeout_str%?}
        [[ ${timeout} -eq 0 ]] && printf "\n"
    done
}

judge_mode() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        ws_grpc_mode=$(info_extraction ws_grpc_mode)
        tls_mode=$(info_extraction tls)
        
        case ${ws_grpc_mode} in
            onlyws) shell_mode="ws";;
            onlygRPC) shell_mode="gRPC";;
            all) shell_mode="ws+gRPC";;
            *);;
        esac
        
        case ${tls_mode} in
            TLS)
                shell_mode="Nginx+${shell_mode}+TLS"
                ;;
            Reality)
                reality_add_more=$(info_extraction reality_add_more)
                reality_add_nginx=$(info_extraction reality_add_nginx)
                
                if [[ ${reality_add_nginx} == "on" && ${reality_add_nginx} == "off" ]]; then
                    shell_mode="Reality+${shell_mode}"
                elif [[ ${reality_add_nginx} == "on" && ${reality_add_nginx} == "on" ]]; then
                    shell_mode="Nginx+Reality+${shell_mode}"
                elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "off" ]]; then
                    shell_mode="Nginx+Reality"
                else
                    shell_mode="Reality"
                fi
                ;;
            None)
                shell_mode="${shell_mode} ONLY"
                ;;
            *)
                ;;
        esac
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
    ws_grpc_choose
    port_set
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    email_set
    UUID_set
    ws_grpc_qr
    vless_qr_config_tls_ws
    stop_service_all
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_systemd
    nginx_ssl_conf_add
    ssl_judge_and_install
    nginx_conf_add
    nginx_servers_conf_add
    xray_conf_add
    tls_type
    basic_information
    enable_process_systemd
    acme_cron_update
    auto_update
    service_restart
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
    ws_grpc_qr
    firewall_set
    stop_service_all
    port_exist_check "${port}"
    reality_nginx_add_fq
    xray_conf_add
    vless_qr_config_reality
    basic_information
    enable_process_systemd
    auto_update
    service_restart
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
    ws_grpc_choose
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    email_set
    UUID_set
    ws_grpc_qr
    vless_qr_config_ws_only
    stop_service_all
    xray_install
    port_exist_check "${xport}"
    port_exist_check "${gport}"
    xray_conf_add
    basic_information
    service_restart
    enable_process_systemd
    auto_update
    vless_link_image_choice
    show_information
}

update_sh() {
    ol_version=${shell_online_version}
    echo "${ol_version}" >${shell_version_tmp}
    [[ -z ${ol_version} ]] && log_echo "${Error} ${RedBG} $(gettext "检测最新版本失败!") ${Font}" && return 1
    echo "${shell_version}" >>${shell_version_tmp}
    newest_version=$(sort -rV ${shell_version_tmp} | head -1)
    oldest_version=$(sort -V ${shell_version_tmp} | head -1)
    version_difference=$(echo "(${newest_version:0:3}-${oldest_version:0:3})>0" | bc)
    if [[ ${shell_version} != ${newest_version} ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            if [[ ${version_difference} == 1 ]]; then
                echo -e "\n"
                log_echo "${Warning} ${YellowBG} $(gettext "存在新版本, 但版本跨度较大, 可能存在不兼容情况, 是否更新") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
            else
                echo -e "\n"
                log_echo "${GreenBG} $(gettext "存在新版本, 是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            fi
            read -r update_confirm
        else
            [[ -z ${ol_version} ]] && echo "$(gettext "检测 脚本 最新版本失败!")" >>${log_file} && exit 1
            [[ ${version_difference} == 1 ]] && echo "$(gettext "脚本 版本差别过大, 跳过更新!")" >>${log_file} && exit 1
            update_confirm="YES"
        fi
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L "${idleleo_commend_file}" ]] && rm -f ${idleleo_commend_file}
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            [[ -f "${xray_qr_config_file}" ]] && jq --arg shell_version "${shell_version}" '.shell_version = $shell_version' "${xray_qr_config_file}" > "${xray_qr_config_file}.tmp" && mv "${xray_qr_config_file}.tmp" "${xray_qr_config_file}"
            clear
            log_echo "${OK} ${GreenBG} $(gettext "更新完成") ${Font}"
            [[ ${version_difference} == 1 ]] && log_echo "${Warning} ${YellowBG} $(gettext "脚本版本跨度较大, 若服务无法正常运行请卸载后重装!") ${Font}"
            ;;
        *) ;;
        esac
    else
        clear
        log_echo "${OK} ${GreenBG} $(gettext "当前版本为最新版本") ${Font}"
    fi

}

check_file_integrity() {
    if [[ ! -L "${idleleo_commend_file}" ]] && [[ ! -f "${idleleo_dir}/install.sh" ]]; then
        check_system
        pkg_install "bc,jq,wget"
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p ${idleleo_dir}
        [[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p ${idleleo_dir}/tmp
        wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
        judge "$(gettext "下载最新脚本")"
        ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
        clear
        source "$idleleo"
    fi
}

read_version() {
    shell_online_version="$(check_version shell_online_version)"
    xray_version="$(check_version xray_online_version)"
    nginx_build_version="$(check_version nginx_build_online_version)"
}

maintain() {
    log_echo "${Error} ${RedBG} $(gettext "该选项暂时无法使用") ! ${Font}"
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
        echo -e "\n"
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
    '-4' | '--add-upstream')
        nginx_upstream_server_set
        ;;
    '-5' | '--add-servernames')
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
    '-h' | '--help')
        show_help
        ;;
    '-n' | '--nginx-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        nginx_update
        ;;
    '-p' | '--port-reset')
        reset_port
        ;;
    '--purge' | '--uninstall')
        uninstall_all
        ;;
    '-s' | '-show')
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
    echo "  -1, --install-tls           $(gettext "安装 Xray") (Nginx+ws/gRPC+TLS)"
    echo "  -2, --install-reality       $(gettext "安装 Xray") (Nginx+Reality+ws/gRPC)"
    echo "  -3, --install-none          $(gettext "安装 Xray") (ws/gRPC ONLY)"
    echo "  -4, --add-upstream          $(gettext "变更 Nginx 负载均衡配置")"
    echo "  -5, --add-servernames       $(gettext "变更 Nginx serverNames 配置")"
    echo "  -au, --auto-update          $(gettext "设置自动更新")"
    echo "  -c, --clean-logs            $(gettext "清除日志文件")"
    echo "  -cs, --cert-status          $(gettext "查看证书状态")"
    echo "  -cu, --cert-update          $(gettext "更新证书有效期")"
    echo "  -cau, --cert-auto-update    $(gettext "设置证书自动更新")"
    echo "  -f, --set-fail2ban          $(gettext "设置 Fail2ban 防暴力破解")"
    echo "  -h, --help                  $(gettext "显示帮助")"
    echo "  -n, --nginx-update          $(gettext "更新") Nginx"
    echo "  -p, --port-reset            $(gettext "变更") port"
    echo "  --purge, --uninstall        $(gettext "脚本卸载")"
    echo "  -s, --show                  $(gettext "显示安装信息")"
    echo "  -t, --target-reset          $(gettext "变更") target"
    echo "  -tcp, --tcp                 $(gettext "配置 TCP 加速")"
    echo "  -tls, --tls                 $(gettext "修改 TLS 配置")"
    echo "  -u, --update                $(gettext "升级脚本")"
    echo "  -uu, --uuid-reset           $(gettext "变更") UUIDv5/$(gettext "映射字符串")"
    echo "  -xa, --xray-access          $(gettext "显示") Xray $(gettext "访问信息")"
    echo "  -xe, --xray-error           $(gettext "显示") Xray $(gettext "错误信息")"
    echo "  -x, --xray-update           $(gettext "更新") Xray"
    exit 0
}

idleleo_commend() {
    if [[ -L "${idleleo_commend_file}" ]] || [[ -f "${idleleo_dir}/install.sh" ]]; then
        ##在线运行与本地脚本比对
        [[ ! -L "${idleleo_commend_file}" ]] && chmod +x ${idleleo_dir}/install.sh && ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
        old_version=$(grep "shell_version=" ${idleleo_dir}/install.sh | head -1 | awk -F '=|"' '{print $3}')
        echo "${old_version}" >${shell_version_tmp}
        echo "${shell_version}" >>${shell_version_tmp}
        oldest_version=$(sort -V ${shell_version_tmp} | head -1)
        version_difference=$(echo "(${shell_version:0:3}-${oldest_version:0:3})>0" | bc)
        if [[ -z ${old_version} ]]; then
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            judge "$(gettext "下载最新脚本")"
            clear
            source "$idleleo"
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            if [[ ${version_difference} == 1 ]]; then
                log_echo "${Warning} ${YellowBG} $(gettext "脚本版本跨度较大, 可能存在不兼容情况, 是否继续使用") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r update_sh_fq
                case $update_sh_fq in
                [yY][eE][sS] | [yY])
                    rm -rf ${idleleo_dir}/install.sh
                    wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                    judge "$(gettext "下载最新脚本")"
                    clear
                    log_echo "${Warning} ${YellowBG} $(gettext "脚本版本跨度较大, 若服务无法正常运行请卸载后重装") ! ${Font}"
                    echo -e "\n"
                    ;;
                *)
                    source "$idleleo"
                    ;;
                esac
            else
                rm -rf ${idleleo_dir}/install.sh
                wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                judge "$(gettext "下载最新脚本")"
                clear
            fi
            source "$idleleo"
        else
            ol_version=${shell_online_version}
            echo "${ol_version}" >${shell_version_tmp}
            [[ -z ${ol_version} ]] && shell_need_update="${Red}[$(gettext "检测失败")]!${Font}"
            echo "${shell_version}" >>${shell_version_tmp}
            newest_version=$(sort -rV ${shell_version_tmp} | head -1)
            if [[ ${shell_version} != ${newest_version} ]]; then
                shell_need_update="${Red}[$(gettext "有新版")]!${Font}"
                shell_emoji="${Red}>_<${Font}"
            else
                shell_need_update="${Green}[$(gettext "最新版")]${Font}"
                shell_emoji="${Green}^O^${Font}"
            fi
            if [[ -f "${xray_qr_config_file}" ]]; then
                if [[ "$(info_extraction nginx_build_version)" == "null" ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
                    nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                elif [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
                    nginx_need_update="${Green}[$(gettext "有新版")]${Font}"
                else
                    nginx_need_update="${Green}[$(gettext "最新版")]${Font}"
                fi
                if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f "${xray_bin_dir}/xray" ]]; then
                    xray_online_version=$(check_version xray_online_version)
                    ##xray_online_version=$(check_version xray_online_pre_version)
                    if [[ "$(info_extraction xray_version)" == "null" ]]; then
                        xray_need_update="${Green}[$(gettext "已安装")] ($(gettext "版本未知"))${Font}"
                    elif [[ ${xray_version} != $(info_extraction xray_version) ]] && [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
                        xray_need_update="${Red}[$(gettext "有新版")]!${Font}"
                        ### xray_need_update="${Red}[$(gettext "请务必更新")]!${Font}"
                    elif [[ ${xray_version} == $(info_extraction xray_version) ]] || [[ $(info_extraction xray_version) == ${xray_online_version} ]]; then
                        if [[ $(info_extraction xray_version) != ${xray_online_version} ]]; then
                            xray_need_update="${Green}[$(gettext "有测试版")]${Font}"
                        else
                            xray_need_update="${Green}[$(gettext "最新版")]${Font}"
                        fi
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
        nignx_status="${Green}$(gettext "运行中..")${Font}"
    elif [[ ${tls_mode} == "None" ]] || [[ ${reality_add_nginx} == "off" ]]; then
        nignx_status="${Green}$(gettext "无需测试")${Font}"
    else
        nignx_status="${Red}$(gettext "未运行")${Font}"
    fi
    if [[ -n $(pgrep xray) ]]; then
        xray_status="${Green}$(gettext "运行中..")${Font}"
    else
        xray_status="${Red}$(gettext "未运行")${Font}"
    fi
}

curl_local_connect() {
    curl -Is -o /dev/null -w %{http_code} "https://$1/$2"
}

check_xray_local_connect() {
    if [[ -f "${xray_qr_config_file}" ]]; then
        xray_local_connect_status="${Red}$(gettext "无法连通")${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            [[ ${ws_grpc_mode} == "onlyws" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction path)) == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            [[ ${ws_grpc_mode} == "onlygrpc" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction serviceName)) == "502" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            [[ ${ws_grpc_mode} == "all" ]] && [[ $(curl_local_connect $(info_extraction host) $(info_extraction serviceName)) == "502" && $(curl_local_connect $(info_extraction host) $(info_extraction path)) == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        elif [[ ${tls_mode} == "Reality" ]]; then
            xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
        elif [[ ${tls_mode} == "None" ]]; then
            xray_local_connect_status="${Green}$(gettext "无需测试")${Font}"
        fi
    else
        xray_local_connect_status="${Red}$(gettext "未安装")${Font}"
    fi
}

check_online_version_connect() {
    xray_online_version_status=$(curl_local_connect "www.idleleo.com" "api/xray_shell_versions")
    if [[ ${xray_online_version_status} != "200" ]]; then
        if [[ ${xray_online_version_status} == "403" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "脚本维护中.. 请稍后再试!") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "无法检测所需依赖的在线版本, 请稍后再试!") ${Font}"
        fi
        sleep 0.5
        exit 0
    fi
}

set_language() {
    echo -e "\n"
    log_echo "${GreenBG} 选择语言 / Select Language / انتخاب زبان / Выберите язык ${Font}"
    echo -e "${Green}1.${Font} 中文"
    echo -e "${Green}2.${Font} English"
    echo -e "${Green}3.${Font} فارسی"
    echo -e "${Green}4.${Font} Русский"
    
    local lang_choice
    read_optimize "$(gettext "请输入数字"): " "lang_choice" "NULL" 1 4 "$(gettext "请输入 1 到 4 之间的有效数字")"
    
    case $lang_choice in
        1)
            export LANG=zh_CN.UTF-8
            rm -f "${idleleo_dir}/language.conf"
            rm -rf "${idleleo_dir}/languages"
            ;;
        2)
            export LANG=en_US.UTF-8
            ;;
        3)
            export LANG=fa_IR.UTF-8
            ;;
        4)
            export LANG=ru_RU.UTF-8
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "无效的选择") ${Font}"
            return 1
            ;;
    esac
    
    if [ "$lang_choice" -ne 1 ]; then
        echo "LANG=$LANG" > "${idleleo_dir}/language.conf"
    fi
    
    source "$idleleo"
}

#以下为兼容代码，1个大版本后删除
fix_bugs() {
    local log_cleanup_file_path="/etc/logrotate.d/custom_log_cleanup"   
    if [[ -f "${log_cleanup_file_path}" ]]; then
        echo -e "\n"
        log_echo "${Warning} ${RedBG} $(gettext "检测存在到 BUG !") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "BUG 来源于自动清理日志错误的设置") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "开始修复..") ${Font}"
        [[ -f "${nginx_dir}/sbin/nginx" ]] && chown -fR nobody:nogroup "${nginx_dir}/logs"
        chown -fR nobody:nogroup /var/log/xray/
        rm -f "${log_cleanup_file_path}"
        judge "$(gettext "错误的配置文件删除")"
        log_echo "${Warning} ${YellowBG} $(gettext "即将重新设置自动清理日志..") ${Font}"
        bash "${idleleo}" --clean-logs
    fi
}
#兼容代码结束

menu() {
    echo -e "\n"
    log_echo "Xray $(gettext "安装管理脚本") ${Red}[${shell_version}]${Font} ${shell_emoji}"
    log_echo "--- $(gettext "作者"): hello-yunshu ---"
    log_echo "--- $(gettext "修改"): www.idleleo.com ---"
    log_echo "--- https://github.com/hello-yunshu ---"
    echo -e "\n"
    log_echo "$(gettext "当前模式"): ${shell_mode}"
    log_echo "$(gettext "当前语言"): ${LANG%.*}"
    echo -e "\n"
    
    echo -e "$(gettext "可以使用")${RedW} idleleo ${Font}$(gettext "命令管理脚本")${Font}\n"
    
    log_echo "—————————————— ${GreenW}$(gettext "版本检测")${Font} ——————————————"
    log_echo "$(gettext "脚本"):  ${shell_need_update}"
    log_echo "Xray:  ${xray_need_update}"
    log_echo "Nginx: ${nginx_need_update}"
    log_echo "—————————————— ${GreenW}$(gettext "运行状态")${Font} ——————————————"
    log_echo "Xray:   ${xray_status}"
    log_echo "Nginx:  ${nignx_status}"
    log_echo "$(gettext "连通性"): ${xray_local_connect_status}"
    echo -e "—————————————— ${GreenW}$(gettext "升级向导")${Font} ——————————————"
    echo -e "${Green}0.${Font}  $(gettext "升级") $(gettext "脚本")"
    echo -e "${Green}1.${Font}  $(gettext "升级") Xray"
    echo -e "${Green}2.${Font}  $(gettext "升级") Nginx"
    echo -e "—————————————— ${GreenW}Language / 语言${Font} ———————"
    echo -e "${Green}34.${Font} 中文"
    echo -e "    English"
    echo -e "    فارسی"
    echo -e "    Русский"
    echo -e "—————————————— ${GreenW}$(gettext "安装向导")${Font} ——————————————"
    echo -e "${Green}3.${Font}  $(gettext "安装") Xray (Reality+ws/gRPC+Nginx)"
    echo -e "${Green}4.${Font}  $(gettext "安装") Xray (Nginx+ws/gRPC+TLS)"
    echo -e "${Green}5.${Font}  $(gettext "安装") Xray (ws/gRPC ONLY)"
    echo -e "—————————————— ${GreenW}$(gettext "配置变更")${Font} ——————————————"
    echo -e "${Green}6.${Font}  $(gettext "变更") UUIDv5/$(gettext "映射字符串")"
    echo -e "${Green}7.${Font}  $(gettext "变更") port"
    echo -e "${Green}8.${Font}  $(gettext "变更") target"
    echo -e "${Green}9.${Font}  $(gettext "变更") TLS $(gettext "版本")"
    echo -e "${Green}10.${Font} $(gettext "变更") Nginx $(gettext "负载均衡配置")"
    echo -e "${Green}11.${Font} $(gettext "变更") Nginx serverNames $(gettext "配置")"
    echo -e "—————————————— ${GreenW}$(gettext "用户管理")${Font} ——————————————"
    echo -e "${Green}12.${Font} $(gettext "查看") Xray $(gettext "用户")"
    echo -e "${Green}13.${Font} $(gettext "添加") Xray $(gettext "用户")"
    echo -e "${Green}14.${Font} $(gettext "删除") Xray $(gettext "用户")"
    echo -e "—————————————— ${GreenW}$(gettext "查看信息")${Font} ——————————————"
    echo -e "${Green}15.${Font} $(gettext "查看") Xray $(gettext "实时访问日志")"
    echo -e "${Green}16.${Font} $(gettext "查看") Xray $(gettext "实时错误日志")"
    echo -e "${Green}17.${Font} $(gettext "查看") Xray $(gettext "配置信息")"
    echo -e "—————————————— ${GreenW}$(gettext "服务相关")${Font} ——————————————"
    echo -e "${Green}18.${Font} $(gettext "重启") $(gettext "所有服务")"
    echo -e "${Green}19.${Font} $(gettext "启动") $(gettext "所有服务")"
    echo -e "${Green}20.${Font} $(gettext "停止") $(gettext "所有服务")"
    echo -e "${Green}21.${Font} $(gettext "查看") $(gettext "所有服务")"
    echo -e "—————————————— ${GreenW}$(gettext "证书相关")${Font} ——————————————"
    echo -e "${Green}22.${Font} $(gettext "查看") $(gettext "证书状态")"
    echo -e "${Green}23.${Font} $(gettext "更新") $(gettext "证书有效期")"
    echo -e "${Green}24.${Font} $(gettext "设置") $(gettext "证书自动更新")"
    echo -e "—————————————— ${GreenW}$(gettext "其他选项")${Font} ——————————————"
    echo -e "${Green}25.${Font} $(gettext "配置") $(gettext "自动更新")"
    echo -e "${Green}26.${Font} $(gettext "设置") TCP $(gettext "加速")"
    echo -e "${Green}27.${Font} $(gettext "设置") Fail2ban $(gettext "防暴力破解")"
    echo -e "${Green}28.${Font} $(gettext "设置") Xray $(gettext "流量统计")"
    echo -e "${Green}29.${Font} $(gettext "清除") $(gettext "日志文件")"
    echo -e "${Green}30.${Font} $(gettext "测试") $(gettext "服务器网速")"
    echo -e "—————————————— ${GreenW}$(gettext "卸载向导")${Font} ——————————————"
    echo -e "${Green}31.${Font} $(gettext "卸载") $(gettext "脚本")"
    echo -e "${Green}32.${Font} $(gettext "清空") $(gettext "证书文件")"
    echo -e "${Green}33.${Font} $(gettext "退出") \n"
    
    local menu_num
    read_optimize "$(gettext "请输入选项"): " "menu_num" "NULL" 0 34 "$(gettext "请输入 0 到 34 之间的有效数字")"
    case $menu_num in
    0)
        update_sh
        source "$idleleo"
        ;;
    1)
        xray_update
        timeout "$(gettext "清空屏幕!")"
        clear
        source "$idleleo"
        ;;
    2)
        echo -e "\n"
        log_echo "${Red}[不建议]${Font} 频繁升级 Nginx, 请确认 Nginx 有升级的必要! "
        timeout "$(gettext "开始升级!")"
        nginx_update
        timeout "$(gettext "清空屏幕!")"
        clear
        source "$idleleo"
        ;;
    3)
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        source "$idleleo"
        ;;
    4)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        source "$idleleo"
        ;;
    5)
        echo -e "\n"
        log_echo "${Warning} ${YellowBG} 此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装 [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        source "$idleleo"
        ;;
    6)
        reset_UUID
        judge "$(gettext "变更 UUIDv5/映射字符串")"
        menu
        ;;
    7)
        reset_port
        judge "$(gettext "变更 port")"
        menu
        ;;
    8)
        reset_target
        judge "$(gettext "变更 target")"
        menu
        ;;
    9)
        tls_type
        judge "$(gettext "变更 TLS 版本")"
        menu
        ;;
    10)
        nginx_upstream_server_set
        timeout "$(gettext "清空屏幕!")"
        clear
        menu
        ;;
    11)
        nginx_servernames_server_set
        timeout "$(gettext "清空屏幕!")"
        clear
        menu
        ;;
    12)
        show_user
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    13)
        add_user
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    14)
        remove_user
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    15)
        clear
        show_access_log
        ;;
    16)
        clear
        show_error_log
        ;;
    17)
        clear
        basic_information
        vless_qr_link_image
        show_information
        menu
        ;;
    18)
        service_restart
        timeout "$(gettext "清空屏幕!")"
        clear
        menu
        ;;
    19)
        service_start
        timeout "$(gettext "清空屏幕!")"
        clear
        source "$idleleo"
        ;;
    20)
        service_stop
        timeout "$(gettext "清空屏幕!")"
        clear
        source "$idleleo"
        ;;
    21)
        if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        menu
        ;;
    22)
        check_cert_status
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    23)
        cert_update_manuel
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    24)
        acme_cron_update
        timeout "$(gettext "回到菜单!")"
        clear
        menu
        ;;
    25)
        auto_update
        timeout "$(gettext "清空屏幕!")"
        clear
        menu
        ;;
    26)
        clear
        bbr_boost_sh
        ;;
    27)
        set_fail2ban
        menu
        ;;
    28)
        xray_status_add
        timeout "$(gettext "回到菜单!")"
        menu
        ;;
    29)
        clean_logs
        menu
        ;;
    30)
        clear
        bash <(curl -Lso- https://git.io/Jlkmw)
        ;;
    31)
        uninstall_all
        timeout "$(gettext "清空屏幕!")"
        clear
        source "$idleleo"
        ;;
    32)
        delete_tls_key_and_crt
        rm -rf ${ssl_chainpath}/*
        timeout "$(gettext "清空屏幕!")"
        clear
        menu
        ;;
    33)
        timeout "$(gettext "清空屏幕!")"
        clear
        exit 0
        ;;
    34)
        set_language
        bash idleleo
        ;;
    *)
        clear
        log_echo "${Error} ${RedBG} $(gettext "请输入正确的数字!") ${Font}"
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
fix_bugs
list "$@"
