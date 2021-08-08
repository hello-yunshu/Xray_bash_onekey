#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#=====================================================
#	System Request: Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	paniy
#	Dscription: Xray Onekey Management
#	Version: 2.0
#	email: admin@idleleo.com
#	Official document: www.idleleo.com
#=====================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
#Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
YellowBG="\033[43;31m"
Font="\033[0m"

#notification information
# Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"
Warning="${Red}[警告]${Font}"

shell_version="1.8.1.6"
shell_mode="未安装"
tls_mode="None"
ws_grpc_mode="None"
version_cmp="/tmp/version_cmp.tmp"
idleleo_dir="/etc/idleleo"
idleleo_conf_dir="${idleleo_dir}/conf"
xray_conf_dir="${idleleo_conf_dir}/xray"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
xray_conf="${xray_conf_dir}/config.json"
xray_default_conf="/usr/local/etc/xray/config.json"
nginx_conf="${nginx_conf_dir}/xray.conf"
nginx_upstream_conf="${nginx_conf_dir}/xray-server.conf"
idleleo_tmp="${idleleo_dir}/tmp"
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
nginx_dir="/etc/nginx"
nginx_openssl_src="/usr/local/src"
xray_bin_dir="/usr/local/bin/xray"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_systemd_file2="/etc/systemd/system/xray@.service"
xray_systemd_filed="/etc/systemd/system/xray.service.d"
xray_systemd_filed2="/etc/systemd/system/xray@.service.d"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="${idleleo_dir}/ssl_update.sh"
cert_group="nobody"
myemali="my@example.com"
nginx_version="1.20.1"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"
bt_nginx="None"
read_config_status=1
xtls_add_more="off"
old_config_status="off"
old_tls_mode="NULL"
random_num=$((RANDOM % 12 + 4))
THREAD=$(($(grep 'processor' /proc/cpuinfo | sort -u | wc -l) + 1))

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
        [[ ! -f ${xray_qr_config_file} ]] && $INS update
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        [[ ! -f ${xray_qr_config_file} ]] && $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        if [[ ! -f ${xray_qr_config_file} ]]; then
            rm /var/lib/dpkg/lock
            dpkg --configure -a
            rm /var/lib/apt/lists/lock
            rm /var/cache/apt/archives/lock
            $INS update
        fi
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内, 安装中断! ${Font}"
        exit 1
    fi

    #systemctl stop firewalld
    #systemctl disable firewalld
    #echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"

    #systemctl stop ufw
    #systemctl disable ufw
    #echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
}

is_root() {
    if [[ 0 == $UID ]]; then
        echo -e "${OK} ${GreenBG} 当前用户是 root用户, 进入安装流程 ${Font}"
        wait
    else
        echo -e "${Error} ${RedBG} 当前用户不是 root用户, 请切换到 root用户 后重新执行脚本! ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 0.5
        wait
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

pkg_install_judge() {
    if [[ "${ID}" == "centos" ]]; then
        yum list installed | grep -iw "^$1"
    else
        dpkg --get-selections | grep -iw "^$1" | grep -ivw "deinstall"
    fi
    wait
}

pkg_install() {
    install_array=(${1//,/ })
    install_status=1
    if [[ ${#install_array[@]} -gt 1 ]]; then
        for install_var in ${install_array[@]}
        do
            if [[ -z $(pkg_install_judge "${install_var}") ]]; then
                ${INS} -y install ${install_var}
                install_status=0
            fi
        done
        wait
        if [[ ${install_status} == 0 ]]; then
            judge "安装 ${1//,/ }"
        else
            echo -e "${OK} ${GreenBG} 已安装 ${1//,/ } ${Font}"
            sleep 0.5
        fi
    else
        if [[ -z $(pkg_install_judge "$1") ]]; then
            ${INS} -y install $1
            judge "安装 $1"
        else
            echo -e "${OK} ${GreenBG} 已安装 $1 ${Font}"
            sleep 0.5
        fi
    fi
}

dependency_install() {
    pkg_install "bc,curl,dbus,git,lsof,python3,qrencode,wget"

    if [[ "${ID}" == "centos" ]]; then
        pkg_install "iputils"
    else
        pkg_install "iputils-ping"
    fi

    if [[ "${ID}" == "centos" ]]; then
        pkg_install "crontabs"
    else
        pkg_install "cron"
    fi

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置"

    if [[ ${tls_mode} != "None" ]]; then
        if [[ "${ID}" == "centos" ]]; then
            if [[ -z $(${INS} group list installed | grep -i "Development Tools") ]]; then
                ${INS} -y groupinstall "Development Tools"
                judge "安装 Development Tools"
            else
                echo -e "${OK} ${GreenBG} 已安装 Development Tools ${Font}"
            fi
        else
            pkg_install "build-essential"
        fi
        judge "编译工具包 安装"
    fi

    if [[ "${ID}" == "centos" ]]; then
        pkg_install "epel-release,pcre,pcre-devel,zlib-devel"
    else
        pkg_install "libpcre3,libpcre3-dev,zlib1g-dev"
    fi
}

read_optimize() {
    read -rp "$1" $2
    if [[ -z $(eval echo \$$2) ]]; then
        if [[ $3 != "NULL" ]]; then
            eval $(echo "$2")="$3"
        else
            echo -e "${Error} ${RedBG} 请输入正确的值! ${Font}"
            read_optimize "$1" "$2" $3 $4 $5 "$6"
        fi
    elif [[ ! -z $4 ]] && [[ ! -z $5 ]]; then
        if [[ $(eval echo \$$2) -le $4 ]] || [[ $(eval echo \$$2) -gt $5 ]]; then
            echo -e "${Error} ${RedBG} $6 ${Font}"
            read_optimize "$1" "$2" $3 $4 $5 "$6"
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
    [[ ! -d "${idleleo_tmp}" ]] && mkdir -p ${idleleo_tmp}
}

port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "${GreenBG} 确定 连接端口 ${Font}"
        read_optimize "请输入连接端口 (默认值:443):" "port" 443 0 65535 "请输入 0-65535 之间的值!"
    fi
}

ws_grpc_choose() {
    echo -e "\n${GreenBG} 请选择 安装协议 ws/gRPC ${Font}"
    echo "1: ws"
    echo "2: gRPC"
    echo "3: ws+gRPC (默认)"
    read -rp "请输入: " choose_network
    if [[ $choose_network == 1 ]]; then
        [[ ${shell_mode} == "XTLS+Nginx" ]] && shell_mode="XTLS+Nginx+ws"
        ws_grpc_mode="onlyws"
    elif [[ $choose_network == 2 ]]; then
        [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+gRPC+TLS"
        [[ ${shell_mode} == "XTLS+Nginx" ]] && shell_mode="XTLS+Nginx+gRPC"
        [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="gRPC ONLY"
        ws_grpc_mode="onlygRPC"
    else
        [[ ${shell_mode} == "Nginx+ws+TLS" ]] && shell_mode="Nginx+ws+gRPC+TLS"
        [[ ${shell_mode} == "XTLS+Nginx" ]] && shell_mode="XTLS+Nginx+ws+gRPC"
        [[ ${shell_mode} == "ws ONLY" ]] && shell_mode="ws+gRPC ONLY"
        ws_grpc_mode="all"
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n${GreenBG} 是否需要自定义 ws inbound_port [Y/N]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "请输入自定义 ws inbound_port (请勿与其他端口相同！):" "xport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
                echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
                ;;
            *)
                xport=$((RANDOM + 10000))
                echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
                ;;
            esac
        else
            xport=$((RANDOM + 10000))
        fi
    fi
}

grpc_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n${GreenBG} 是否需要自定义 gRPC inbound_port [Y/N]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "请输入自定义 gRPC inbound_port (请勿与其他端口相同！):" "gport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
                echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
                ;;
            *)
                gport=$((RANDOM + 10000))
                echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
                ;;
            esac
        else
            gport=$((RANDOM + 10000))
        fi
    fi
}

firewall_set() {
    if [[ ${bt_nginx} == "Yes" ]]; then
        echo -e "${Warning} ${YellowBG} 建议使用宝塔面板开放端口, 是否继续 [Y/N]? ${Font}"
        read -r btfirewall_fq
        case $btfirewall_fq in
        [nN][oO]|[nN])
            return 0
            ;;
        esac
    fi
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    if [[ ${tls_mode} != "None" ]] && [[ "$xtls_add_more" == "off" ]]; then
        iptables -I INPUT -p tcp -m multiport --dport 53,80,${port} -j ACCEPT
        iptables -I INPUT -p udp -m multiport --dport 53,80,${port} -j ACCEPT
        iptables -I OUTPUT -p tcp -m multiport --sport 53,80,${port} -j ACCEPT
        iptables -I OUTPUT -p udp -m multiport --sport 53,80,${port} -j ACCEPT
        iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
    else
        iptables -I INPUT -p tcp -m multiport --dport 53,${xport},${gport} -j ACCEPT
        iptables -I INPUT -p udp -m multiport --dport 53,${xport},${gport} -j ACCEPT
        iptables -I OUTPUT -p tcp -m multiport --sport 53,${xport},${gport} -j ACCEPT
        iptables -I OUTPUT -p udp -m multiport --sport 53,${xport},${gport} -j ACCEPT
        iptables -I INPUT -p udp --dport 1024:65535 -j ACCEPT
    fi
    wait
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        service iptables save
        wait
        service iptables restart
        echo -e "${OK} ${GreenBG} 防火墙 重启 完成 ${Font}"
    else
        netfilter-persistent save
        wait
        systemctl restart iptables
        echo -e "${OK} ${GreenBG} 防火墙 重启 完成 ${Font}"
    fi
    wait
    echo -e "${OK} ${GreenBG} 开放防火墙相关端口 ${Font}"
    echo -e "${GreenBG} 若修改配置, 请注意关闭防火墙相关端口 ${Font}"
    echo -e "${OK} ${GreenBG} 配置 Xray FullCone ${Font}"
}

ws_path_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n${GreenBG} 是否需要自定义 ws 伪装路径 [Y/N]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "请输入自定义 ws 伪装路径 (不需要“/”):" "path" "NULL"
                echo -e "${OK} ${GreenBG} ws 伪装路径: ${path} ${Font}"
                ;;
            *)
                path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                echo -e "${OK} ${GreenBG} ws 伪装路径: ${path} ${Font}"
                ;;
            esac
        else
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        fi
    fi
}

grpc_path_set() {
    if [[ "on" != ${old_config_status} ]]; then
        if [[ ${ws_grpc_mode} == "onlygRPC" ]] || [[ ${ws_grpc_mode} == "all" ]]; then
            echo -e "\n${GreenBG} 是否需要自定义 gRPC 伪装路径 [Y/N]? ${Font}"
            read -r path_modify_fq
            case $path_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "请输入自定义 gRPC 伪装路径 (不需要“/”):" "servicename" "NULL"
                echo -e "${OK} ${GreenBG} gRPC 伪装路径: ${servicename} ${Font}"
                ;;
            *)
                servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                echo -e "${OK} ${GreenBG} gRPC 伪装路径: ${servicename} ${Font}"
                ;;
            esac
        fi
    else
        servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
    fi
}


UUID_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "\n${GreenBG} 是否需要自定义字符串映射为 UUIDv5 [Y/N]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "请输入自定义字符串 (最多30字符):" "UUID5_char" "NULL"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            echo -e "${OK} ${GreenBG} 自定义字符串: ${UUID5_char} ${Font}"
            echo -e "${OK} ${GreenBG} UUIDv5: ${UUID} ${Font}"
            ;;
        [nN][oO] | [nN] | *)
            UUID5_char="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            echo -e "${OK} ${GreenBG} UUID 映射字符串: ${UUID5_char} ${Font}"
            echo -e "${OK} ${GreenBG} UUIDv5: ${UUID} ${Font}"
            #[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
            echo -e "${OK} ${GreenBG} UUID: ${UUID} ${Font}"
            ;;
        esac
    fi
}

nginx_upstream_server_set() {
    if [[ ${tls_mode} == "TLS" ]]; then
        echo -e "\n${GreenBG} 是否变更 Nginx 负载均衡 [Y/N]? ${Font}"
        echo -e "${Warning} ${YellowBG} 如不清楚具体用途, 请勿继续! ${Font}"
        read -r nginx_upstream_server_fq
        case $nginx_upstream_server_fq in
        [yY][eE][sS] | [yY])
            echo -e "\n${GreenBG} 请选择 追加的协议为 ws 或 gRPC ${Font}"
            echo "1: 追加配置"
            echo "2: 重置配置"
            read -rp "请输入: " upstream_choose
            if [[ ${upstream_choose} == 2 ]]; then
                timeout "即将重置 Nginx 负载均衡配置"
                wait
                if [[ -f ${xray_qr_config_file} ]]; then
                    xport=$(info_extraction '\"ws_port\"')
                    gport=$(info_extraction '\"grpc_port\"')
                    rm -rf ${nginx_upstream_conf}
                    nginx_conf_servers_add
                    wait
                    [[ -f ${nginx_systemd_file} ]] && systemctl restart nginx
                    [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx restart
                else
                    echo -e "${Error} ${RedBG} 未检测到配置文件！ ${Font}"
                fi
            else
                echo -e "\n${GreenBG} 请选择 追加的协议为 ws 或 gRPC ${Font}"
                echo "1: ws"
                echo "2: gRPC"
                read -rp "请输入: " upstream_net
                read_optimize "请输入负载均衡 主机 (host):" "upstream_host" "NULL"
                read_optimize "请输入负载均衡 端口 (port):" "upstream_port" "NULL" 0 65535 "请输入 0-65535 之间的值!"
                read_optimize "请输入负载均衡 权重 (0~100, 默认值:50):" "upstream_weight" 50 0 100 "请输入 0-100 之间的值!"
                if [[ ${upstream_net} == 2 ]]; then
                    sed -i "/xray-grpc-server/a \\\t\\t\\tserver ${upstream_host}:${upstream_port} weight=${upstream_weight} max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
                else
                    sed -i "/xray-ws-server/a \\\t\\t\\tserver ${upstream_host}:${upstream_port} weight=${upstream_weight} max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
                fi
                iptables -I INPUT -p tcp --dport ${upstream_port} -j ACCEPT
                iptables -I INPUT -p udp --dport ${upstream_port} -j ACCEPT
                iptables -I OUTPUT -p tcp --sport ${upstream_port} -j ACCEPT
                iptables -I OUTPUT -p udp --sport ${upstream_port} -j ACCEPT
                echo -e "${OK} ${GreenBG} 防火墙 追加 完成 ${Font}"
                if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
                    service iptables save
                    wait
                    service iptables restart
                    echo -e "${OK} ${GreenBG} 防火墙 重启 完成 ${Font}"
                else
                    netfilter-persistent save
                    wait
                    systemctl restart iptables
                    echo -e "${OK} ${GreenBG} 防火墙 重启 完成 ${Font}"
                fi
                wait
                [[ -f ${nginx_systemd_file} ]] && systemctl restart nginx && judge "追加 Nginx 负载均衡"
                [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx restart && judge "追加 Nginx 负载均衡"
            fi
            ;;
        *) ;;
        esac
    else
        echo -e "${Error} ${RedBG} 当前模式不支持此操作! ${Font}"
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    echo "import uuid;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,'$1'));" | python3
}

modify_alterid() {
    echo -e "${Warning} ${YellowBG} VLESS 不需要 alterid ${Font}"
}

modify_listen_address() {
    sed -i "s/^\( *\)\"listen\".*/\1\"listen\": \"0.0.0.0\",/g" ${xray_conf}
}

modify_inbound_port() {
    if [[ ${tls_mode} == "TLS" ]]; then
        #        sed -i "/\"port\"/c  \    \"port\":${xport}," ${xray_conf}
        sed -i "8s/^\( *\)\"port\".*/\1\"port\": ${xport},/" ${xray_conf}
        sed -i "29s/^\( *\)\"port\".*/\1\"port\": ${gport},/" ${xray_conf}
    elif [[ ${tls_mode} == "None" ]]; then
        sed -i "8s/^\( *\)\"port\".*/\1\"port\": ${xport},/" ${xray_conf}
        sed -i "29s/^\( *\)\"port\".*/\1\"port\": ${gport},/" ${xray_conf}
    elif [[ ${tls_mode} == "XTLS" ]]; then
        #        sed -i "/\"port\"/c  \    \"port\":${port}," ${xray_conf}
        sed -i "8s/^\( *\)\"port\".*/\1\"port\": ${port},/" ${xray_conf}
        sed -i "38s/^\( *\)\"port\".*/\1\"port\": ${xport},/" ${xray_conf}
        sed -i "59s/^\( *\)\"port\".*/\1\"port\": ${gport},/" ${xray_conf}
    fi
    judge "Xray inbound port 修改"
}

modify_nginx_port() {
    sed -i "s/^\( *\).*ssl http2;$/\1listen ${port} ssl http2;/" ${nginx_conf}
    sed -i "5s/^\( *\).*ssl http2;$/\1listen [::]:${port} ssl http2;/" ${nginx_conf}
    judge "Xray port 修改"
    [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"port\".*/\1\"port\": \"${port}\",/" ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} 端口号: ${port} ${Font}"
}

modify_nginx_other() {
    if [[ -f ${nginx_dir}/conf/nginx.conf ]] && [[ $(grep -c "server_tokens off;" ${nginx_dir}/conf/nginx.conf) -eq '0' ]] && [[ ${bt_nginx} != "Yes" ]]; then
        sed -i '$i include /etc/idleleo/conf/nginx/*.conf;' ${nginx_dir}/conf/nginx.conf
        sed -i "/http\( *\){/a \\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
        sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 302 https:\/\/www.idleleo.com\/helloworld;\\n\\t\\t}" ${nginx_dir}/conf/nginx.conf
    fi
    sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${domain};/g" ${nginx_conf}
    if [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)location ws$/\1location \/${path}/" ${nginx_conf}
        sed -i "s/^\( *\)location grpc$/\1location \/${servicename}/" ${nginx_conf}
        if [[ ${shell_mode} == "Nginx+ws+TLS" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
        elif [[ ${shell_mode} == "Nginx+gRPC+TLS" ]]; then
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        elif [[ ${shell_mode} == "Nginx+ws+gRPC+TLS" ]]; then
            sed -i "s/^\( *\)#proxy_pass\(.*\)/\1proxy_pass\2/" ${nginx_conf}
            sed -i "s/^\( *\)#proxy_redirect default;/\1proxy_redirect default;/" ${nginx_conf}
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" ${nginx_conf}
        fi
    fi
    sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${domain}\$request_uri;/" ${nginx_conf}
}

modify_nginx_servers() {
    sed -i "/#xray-ws-serverc/c \\\t\\t\\tserver 127.0.0.1:${xport} weight=50 max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
    sed -i "/#xray-grpc-serverc/c \\\t\\t\\tserver 127.0.0.1:${gport} weight=50 max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
}

modify_path() {
    sed -i "s/^\( *\)\"path\".*/\1\"path\": \"\/${path}\"/" ${xray_conf}
    sed -i "s/^\( *\)\"serviceName\".*/\1\"serviceName\": \"${servicename}\"/" ${xray_conf}
    if [[ ${tls_mode} != "XTLS" ]] || [[ "$xtls_add_more" == "off" ]]; then
        judge "Xray 伪装路径 修改"
    else
        echo -e "${Warning} ${YellowBG} XTLS 不支持 path ${Font}"
    fi
}

modify_UUID() {
    sed -i "s/^\( *\)\"id\".*/\1\"id\": \"${UUID}\",/g" ${xray_conf}
    judge "Xray UUID 修改"
    [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"id\".*/\1\"id\": \"${UUID}\",/" ${xray_qr_config_file}
    [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"idc\".*/\1\"idc\": \"${UUID5_char}\",/" ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} UUIDv5: ${UUID} ${Font}"
}

web_camouflage() {
    judge "web 站点伪装"
}

xray_privilege_escalation() {
    [[ $(grep "nogroup" /etc/group) ]] && cert_group="nogroup"
    if [[ -n "$(grep "User=nobody" ${xray_systemd_file})" ]]; then
        echo -e "${OK} ${GreenBG} 检测到 Xray 的权限控制, 启动擦屁股程序 ${Font}"
        chmod -fR a+rw /var/log/xray/
        chown -fR nobody:${cert_group} /var/log/xray/
        chown -R nobody:${cert_group} ${ssl_chainpath}/*
    fi
    echo -e "${OK} ${GreenBG} Xray 擦屁股 完成 ${Font}"
}

xray_install() {
    [[ -d ${idleleo_tmp}/xray ]] && rm -rf ${idleleo_tmp}/xray
    [[ -d /usr/local/etc/xray ]] && rm -rf /usr/local/etc/xray
    [[ -d /usr/local/share/xray ]] && rm -rf /usr/local/share/xray
    mkdir -p ${idleleo_tmp}/xray
    cd ${idleleo_tmp}/xray || exit
    wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh
    ##if [[ -f install-release.sh ]] && [[ -f install-dat-release.sh ]]; then
    if [[ -f install-release.sh ]]; then
        [[ -f ${nginx_systemd_file} ]] && rm -rf ${nginx_systemd_file}
        [[ -f ${xray_systemd_file} ]] && rm -rf ${xray_systemd_file}
        [[ -f ${xray_systemd_file2} ]] && rm -rf ${xray_systemd_file2}
        [[ -d ${xray_systemd_filed} ]] && rm -rf ${xray_systemd_filed}
        [[ -d ${xray_systemd_filed2} ]] && rm -rf ${xray_systemd_filed2}
        [[ -f ${xray_bin_dir} ]] && rm -rf ${xray_bin_dir}
        systemctl daemon-reload
        bash install-release.sh --force
        #bash install-dat-release.sh --force
        judge "安装 Xray"
        xray_privilege_escalation
        [[ -f ${xray_default_conf} ]] && rm -rf ${xray_default_conf}
        ln -s ${xray_conf} ${xray_default_conf}
    else
        echo -e "${Error} ${RedBG} Xray 安装文件下载失败, 请检查下载地址是否可用! ${Font}"
        exit 4
    fi
    # 清除临时文件
    rm -rf ${idleleo_tmp}/xray

}

xray_update() {
    #mkdir -p ${idleleo_tmp}/xray
    #cd ${idleleo_tmp}/xray || exit
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh
    [[ ! -d /usr/local/etc/xray ]] && echo -e "${GreenBG} 若更新无效, 建议直接卸载再安装！ ${Font}"
    systemctl stop xray
    wait
    bash <(curl -L -s https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)
    wait
    xray_privilege_escalation
    [[ -f ${xray_default_conf} ]] && rm -rf ${xray_default_conf}
    ln -s ${xray_conf} ${xray_default_conf}
    wait
    systemctl daemon-reload
    wait
    systemctl start xray
    # 清除临时文件
    ##rm -rf ${idleleo_tmp}/xray
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        if [[ -d ${nginx_conf_dir} ]]; then
            rm -rf ${nginx_conf_dir}/*.conf
            if [[ -f  ${nginx_conf_dir}/nginx.default ]]; then
                cp -fp ${nginx_conf_dir}/nginx.default ${nginx_dir}/conf/nginx.conf
            elif [[ -f  ${nginx_dir}/conf/nginx.conf.default ]]; then
                cp -fp ${nginx_dir}/conf/nginx.conf.default ${nginx_dir}/conf/nginx.conf
            else
                sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
                sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
            fi
        else
            sed -i "/if \(.*\) {$/,+2d" ${nginx_dir}/conf/nginx.conf
            sed -i "/^include.*\*\.conf;$/d" ${nginx_dir}/conf/nginx.conf
        fi
        echo -e "${OK} ${GreenBG} Nginx 已存在, 跳过编译安装过程 ${Font}"
        wait
    elif [[ -d "/www/server/panel/BTPanel" ]]; then
        echo -e "${GreenBG} 检测到存在宝塔面板 ${Font}"
        if [[ -f "/www/server/nginx/sbin/nginx" ]] && [[ -d "/www/server/panel/vhost/nginx" ]]; then
            echo -e "${GreenBG} 检测到宝塔面板已安装 Nginx ${Font}"
            bt_nginx="Yes"
            wait
        else
            echo -e "${Warning} ${YellowBG} 检测到宝塔面板未安装 Nginx, 继续安装可能会导致冲突, 是否继续 [Y/N]? ${Font}"
            read -r have_btnginx_fq
            case $have_btnginx_fq in
            [nN][oO]|[nN])
                exit 1
                ;;
            *)
                nginx_install
                ;;
            esac
        fi
    elif [[ ! -d "/www/server/panel/BTPanel" ]] && [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${Error} ${RedBG} 检测到其他套件安装的 Nginx, 继续安装会造成冲突, 请处理后安装! ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx 下载"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc 下载"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-${nginx_version} ]] && rm -rf nginx-${nginx_version}
    tar -zxvf nginx-${nginx_version}.tar.gz

    [[ -d openssl-${openssl_version} ]] && rm -rf openssl-${openssl_version}
    tar -zxvf openssl-${openssl_version}.tar.gz

    [[ -d jemalloc-${jemalloc_version} ]] && rm -rf jemalloc-${jemalloc_version}
    tar -xvf jemalloc-${jemalloc_version}.tar.bz2

    [[ -d ${nginx_dir} ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 jemalloc ${Font}"
    wait

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "编译检查"
    make -j "${THREAD}" && make install
    judge "jemalloc 编译安装"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久, 请耐心等待 ${Font}"
    wait

    cd ../nginx-${nginx_version} || exit

    #增加http_sub_module用于反向代理替换关键词
    ./configure --prefix=${nginx_dir} \
    --user=root \
    --group=root \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-pcre \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-stream \
    --with-stream_ssl_module \
    --with-stream_realip_module \
    --with-stream_ssl_preread_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-cc-opt='-O3' \
    --with-ld-opt="-ljemalloc" \
    --with-openssl=../openssl-${openssl_version}
    judge "编译检查"
    make -j ${THREAD} && make install
    judge "Nginx 编译安装"

    cp -fp ${nginx_dir}/conf/nginx.conf ${nginx_conf_dir}/nginx.default

    # 修改基本配置
    #sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i "s/worker_processes  1;/worker_processes  auto;/" ${nginx_dir}/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" ${nginx_dir}/conf/nginx.conf

    # 删除临时文件
    rm -rf ../nginx-${nginx_version}
    rm -rf ../openssl-${openssl_version}
    rm -rf ../nginx-${nginx_version}.tar.gz
    rm -rf ../openssl-${openssl_version}.tar.gz
}

nginx_update() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ ${bt_nginx} != "Yes" ]]; then
        if [[ ${nginx_version} != $(info_extraction '\"nginx_version\"') ]] || [[ ${openssl_version} != $(info_extraction '\"openssl_version\"') ]] || [[ ${jemalloc_version} != $(info_extraction '\"jemalloc_version\"') ]]; then
            ip_check
            if [[ -f ${xray_qr_config_file} ]]; then
                domain=$(info_extraction '\"host\"')
                if [[ ${tls_mode} == "TLS" ]]; then
                    port=$(info_extraction '\"port\"')
                    if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                        xport=$(info_extraction '\"ws_port\"')
                        path=$(info_extraction '\"path\"')
                        gport=$((RANDOM + 10000))
                        servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                        gport=$(info_extraction '\"grpc_port\"')
                        servicename=$(info_extraction '\"servicename\"')
                        xport=$((RANDOM + 10000))
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${ws_grpc_mode} == "all" ]]; then
                        xport=$(info_extraction '\"ws_port\"')
                        path=$(info_extraction '\"path\"')
                        gport=$(info_extraction '\"grpc_port\"')
                        servicename=$(info_extraction '\"servicename\"')
                    fi
                    if [[ 0 -eq ${read_config_status} ]]; then
                        echo -e "${Error} ${RedBG} 旧配置文件不完整, 退出升级 ${Font}"
                        timeout "清空屏幕!"
                        clear
                        bash idleleo
                    fi
                elif [[ ${tls_mode} == "None" ]]; then
                    echo -e "${Error} ${RedBG} 当前安装模式不需要 Nginx ! ${Font}"
                    timeout "清空屏幕!"
                    clear
                    bash idleleo
                fi
            else
                echo -e "${Error} ${RedBG} 旧配置文件不存在, 退出升级 ${Font}"
                timeout "清空屏幕!"
                clear
                bash idleleo
            fi
            wait
            service_stop
            timeout "删除旧版 Nginx !"
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*.conf
            wait
            nginx_install
            wait
            if [[ ${tls_mode} == "TLS" ]]; then
                nginx_conf_add
            elif [[ ${tls_mode} == "XTLS" ]]; then
                nginx_conf_add_xtls
            fi
            wait
            service_start
            sed -i "s/^\( *\)\"nginx_version\".*/\1\"nginx_version\": \"${nginx_version}\",/" ${xray_qr_config_file}
            sed -i "s/^\( *\)\"openssl_version\".*/\1\"openssl_version\": \"${openssl_version}\",/" ${xray_qr_config_file}
            sed -i "s/^\( *\)\"jemalloc_version\".*/\1\"jemalloc_version\": \"${jemalloc_version}\"/" ${xray_qr_config_file}
            judge "Nginx 升级"
        else
            echo -e "${OK} ${GreenBG} Nginx 已为最新版 ${Font}"
        fi
    else
        echo -e "${Error} ${RedBG} Nginx 未安装或使用宝塔面板 ${Font}"
    fi
}

ssl_install() {
    pkg_install "socat"
    judge "安装 SSL 证书生成脚本依赖"

    read_optimize "请输入注册域名的邮箱 (eg:me@idleleo.com):" "myemail" "NULL"
    curl https://get.acme.sh | sh -s email=$myemail
    judge "安装 SSL 证书生成脚本"
}

domain_check() {
    echo -e "\n${GreenBG} 确定 域名 信息 ${Font}"
    read_optimize "请输入你的域名信息 (eg:www.idleleo.com):" "domain" "NULL"
    echo -e "\n${GreenBG} 请选择 公网IP 为 IPv4 或 IPv6 ${Font}"
    echo "1: IPv4 (默认)"
    echo "2: IPv6 (不推荐)"
    read -rp "请输入: " ip_version
    [[ -z ${ip_version} ]] && ip_version=1
    echo -e "${OK} ${GreenBG} 正在获取 公网IP 信息, 请耐心等待 ${Font}"
    if [[ $ip_version == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    elif [[ $ip_version == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
        domain_ip=$(ping -6 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    else
        local_ip=$(curl -4 ip.sb)
        domain_ip=$(ping -4 "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    fi
    echo -e "域名DNS 解析IP: ${domain_ip}"
    echo -e "公网IP: ${local_ip}"
    wait
    if [[ ${local_ip} == ${domain_ip} ]]; then
        echo -e "${OK} ${GreenBG} 域名DNS 解析IP 与 公网IP 匹配 ${Font}"
        wait
    else
        echo -e "${Warning} ${YellowBG} 请确保域名添加了正确的 A/AAAA 记录, 否则将无法正常使用 Xray ${Font}"
        echo -e "${Error} ${RedBG} 域名DNS 解析IP 与 公网IP 不匹配, 请选择: ${Font}"
        echo "1: 继续安装"
        echo "2: 重新输入"
        echo "3: 终止安装 (默认)"
        read -r install
        case $install in
        1)
            echo -e "${GreenBG} 继续安装 ${Font}"
            wait
            ;;
        2)
            domain_check
            ;;
        *)
            echo -e "${Error} ${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

ip_check() {
    echo -e "\n${GreenBG} 确定 公网IP 信息 ${Font}"
    echo -e "${GreenBG} 请选择 公网IP 为 IPv4 或 IPv6 ${Font}"
    echo "1: IPv4 (默认)"
    echo "2: IPv6 (不推荐)"
    read -rp "请输入: " ip_version
    [[ -z ${ip_version} ]] && ip_version=1
    echo -e "${OK} ${GreenBG} 正在获取 公网IP 信息, 请耐心等待 ${Font}"
    if [[ $ip_version == 1 ]]; then
        local_ip=$(curl -4 ip.sb)
    elif [[ $ip_version == 2 ]]; then
        local_ip=$(curl -6 ip.sb)
    else
        local_ip=$(curl -4 ip.sb)
    fi
    echo -e "公网IP: ${local_ip}"
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        wait
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用, 以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        timeout "尝试自动 kill 占用进程!"
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        wait
    fi
}

acme() {
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${OK} ${GreenBG} SSL 证书测试签发成功, 开始正式签发 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        wait
    else
        echo -e "${Error} ${RedBG} SSL 证书测试签发失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        wait
        mkdir -p ${ssl_chainpath}
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc --force; then
            chmod -f a+rw ${ssl_chainpath}/xray.crt
            chmod -f a+rw ${ssl_chainpath}/xray.key
            [[ $(grep "nogroup" /etc/group) ]] && cert_group="nogroup"
            chown -R nobody:${cert_group} ${ssl_chainpath}/*
            echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
            wait
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    cd ${xray_conf_dir} || exit
    if [[ ${tls_mode} == "TLS" ]]; then
        wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_tls/config.json -O config.json
        modify_path
        modify_inbound_port
    elif [[ ${tls_mode} == "XTLS" ]]; then
        wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_xtls/config.json -O config.json
        xray_xtls_add_more
    elif [[ ${tls_mode} == "None" ]]; then
        wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_tls/config.json -O config.json
        modify_listen_address
        modify_path
        modify_inbound_port
    fi
    modify_alterid
    modify_UUID
}

xray_xtls_add_more() {
    artpath="None"
    artxport="None"
    artservicename="None"
    artgport="None"
    echo -e "\n${GreenBG} 是否添加简单 ws/gRPC 协议 用于负载均衡 [Y/N]? ${Font}"
    echo -e "${Warning} ${YellowBG} 如不清楚具体用途, 请勿选择! ${Font}"
    read -r xtls_add_more_fq
    case $xtls_add_more_fq in
    [yY][eE][sS] | [yY])
        xtls_add_more="on"
        ws_grpc_choose
        ws_inbound_port_set
        grpc_inbound_port_set
        ws_path_set
        grpc_path_set
        port_exist_check "${xport}"
        port_exist_check "${gport}"
        modify_path
        modify_listen_address
        modify_inbound_port
        judge "添加简单 ws/gRPC 协议"
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            artxport=${xport}
            artpath=${path}
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            artgport=${gport}
            artservicename=${servicename}
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            artxport=${xport}
            artpath=${path}
            artgport=${gport}
            artservicename=${servicename}
        fi
        ;;
    *)
        xtls_add_more="off"
        ws_inbound_port_set
        grpc_inbound_port_set
        ws_path_set
        grpc_path_set
        modify_path
        modify_inbound_port
        echo -e "${OK} ${GreenBG} 已跳过添加简单 ws/gRPC 协议 ${Font}"
        ;;
    esac
}

old_config_exist_check() {
    if [[ -f ${xray_qr_config_file} ]]; then
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            echo -e "\n${GreenBG} 检测到旧配置文件, 是否读取旧文件配置 [Y/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [nN][oO]|[nN])
                rm -rf ${xray_qr_config_file}
                echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
                ;;
            *)
                echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
                old_config_status="on"
                old_config_input
                ;;
            esac
        else
            echo -e "\n${GreenBG} 检测到当前安装模式与旧配置的安装模式不一致, 是否保留旧配置文件 [Y/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
                echo -e "${OK} ${GreenBG} 停止安装 ${Font}"
                bash idleleo
                ;;
            *)
                rm -rf ${xray_qr_config_file}
                echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
                ;;
            esac
        fi
    fi
}

old_config_input () {
    if [[ ${tls_mode} == "TLS" ]]; then
        port=$(info_extraction '\"port\"')
        UUID5_char=$(info_extraction '\"idc\"')
        UUID=$(info_extraction '\id\"')
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction '\"ws_port\"')
            path=$(info_extraction '\"path\"')
            gport=$((RANDOM + 10000))
            servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction '\"grpc_port\"')
            servicename=$(info_extraction '\"servicename\"')
            xport=$((RANDOM + 10000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction '\"ws_port\"')
            path=$(info_extraction '\"path\"')
            gport=$(info_extraction '\"grpc_port\"')
            servicename=$(info_extraction '\"servicename\"')
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
            port=$(info_extraction '\"port\"')
            UUID5_char=$(info_extraction '\"idc\"')
            UUID=$(info_extraction '\id\"')
        if [[ ${xtls_add_more} == "on" ]]; then
                if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                    xport=$(info_extraction '\"ws_port\"')
                    path=$(info_extraction '\"ws_path\"')
                    gport=$((RANDOM + 10000))
                    servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                    gport=$(info_extraction '\"grpc_port\"')
                    servicename=$(info_extraction '\"grpc_servicename\"')
                    xport=$((RANDOM + 10000))
                    path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                elif [[ ${ws_grpc_mode} == "all" ]]; then
                    xport=$(info_extraction '\"ws_port\"')
                    path=$(info_extraction '\"ws_path\"')
                    gport=$(info_extraction '\"grpc_port\"')
                    servicename=$(info_extraction '\"grpc_servicename\"')
                fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        UUID5_char=$(info_extraction '\"idc\"')
        UUID=$(info_extraction '\id\"')
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            xport=$(info_extraction '\"ws_port\"')
            path=$(info_extraction '\"path\"')
            gport=$((RANDOM + 10000))
            servicename="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            gport=$(info_extraction '\"grpc_port\"')
            servicename=$(info_extraction '\"servicename\"')
            xport=$((RANDOM + 10000))
            path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            xport=$(info_extraction '\"ws_port\"')
            path=$(info_extraction '\"path\"')
            gport=$(info_extraction '\"grpc_port\"')
            servicename=$(info_extraction '\"servicename\"')
        fi
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        echo -e "\n${GreenBG} 检测到旧配置文件不完整, 是否保留旧配置文件 [Y/N]? ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        [yY][eE][sS] | [yY])
            old_config_status="off"
            echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
            ;;
        *)
            rm -rf ${xray_qr_config_file}
            old_config_status="off"
            echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
            ;;
        esac
    fi
}

nginx_conf_add() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF
    types_hash_max_size 2048;

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        ssl_certificate       /etc/idleleo/cert/xray.crt;
        ssl_certificate_key   /etc/idleleo/cert/xray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS-AES-128-GCM-SHA256:TLS-CHACHA20-POLY1305-SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_256_GCM_SHA384:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.html index.htm;
        root /400.html;
        error_page 400 https://www.idleleo.com/helloworld;
        # Config for 0-RTT in TLSv1.3
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
            grpc_set_header X-Real-IP \$remote_addr;
            grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

            # Config for 0-RTT in TLSv1.3
            proxy_set_header Early-Data \$ssl_early_data;
        }

        location ws
        {
            #proxy_pass http://xray-ws-server;
            #proxy_redirect default;
            proxy_http_version 1.1;
            proxy_connect_timeout 60s;
            proxy_send_timeout 720m;
            proxy_read_timeout 720m;
            proxy_buffering off;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;

            # Config for 0-RTT in TLSv1.3
            proxy_set_header Early-Data \$ssl_early_data;
        }

        location /
        {
            return 302 https://www.idleleo.com/helloworld;
        }
    }
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://www.idleleo.com\$request_uri;
    }
EOF
    wait
    if [[ ${bt_nginx} == "Yes" ]]; then
        ln -s ${nginx_conf} /www/server/panel/vhost/nginx/xray.conf
        echo -e "${OK} ${GreenBG} Nginx 配置文件已连接至宝塔面板 ${Font}"
    fi
    modify_nginx_port
    modify_nginx_other
    judge "Nginx 配置修改"
}

nginx_conf_add_xtls() {
    touch ${nginx_conf}
    cat >${nginx_conf} <<EOF
    server {
        listen 127.0.0.1:8080 proxy_protocol;
        server_name         serveraddr.com;
        set_real_ip_from    127.0.0.1;
        real_ip_header      X-Forwarded-For;
        real_ip_recursive   on;
        add_header Strict-Transport-Security "max-age=63072000" always;
        location /
        {
            return 302 https://www.idleleo.com/helloworld;
        }
    }

    server {
        listen 80;
        listen [::]:80;
        server_name         serveraddr.com;
        return 301 https://www.idleleo.com\$request_uri;
    }
EOF
    wait
    if [[ ${bt_nginx} == "Yes" ]]; then
        ln -s ${nginx_conf} /www/server/panel/vhost/nginx/xray.conf
        echo -e "${OK} ${GreenBG} Nginx 配置文件已连接至宝塔面板 ${Font}"
    fi
    modify_nginx_other
    judge "Nginx 配置修改"
}

nginx_conf_servers_add() {
    touch ${nginx_upstream_conf}
    cat >${nginx_upstream_conf} <<EOF
    upstream xray-ws-server {
        #xray-ws-serverc
    }

    upstream xray-grpc-server {
        #xray-grpc-serverc
    }
EOF
    wait
    if [[ ${bt_nginx} == "Yes" ]]; then
        ln -s ${nginx_upstream_conf} /www/server/panel/vhost/nginx/xray-server.conf
        echo -e "${OK} ${GreenBG} Nginx 附加文件已连接至宝塔面板 ${Font}"
    fi
    modify_nginx_servers
    judge "Nginx servers 配置修改"
}

enable_process_systemd() {
    if [[ ${tls_mode} != "None" ]]; then
        [[ -f ${nginx_systemd_file} ]] && systemctl enable nginx && judge "设置 Nginx 开机自启"
        [[ ${bt_nginx} == "Yes" ]] && echo -e "${Warning} ${GreenBG} 存在宝塔面板, 请自行设置 ${Font}"
    fi
    systemctl enable xray
    judge "设置 Xray 开机自启"
}

disable_process_systemd() {
    if [[ ${tls_mode} != "None" ]]; then
        [[ -f ${nginx_systemd_file} ]] && systemctl stop nginx && systemctl disable nginx && judge "关闭 Nginx 开机自启"
        [[ ${bt_nginx} == "Yes" ]] && echo -e "${Warning} ${GreenBG} 存在宝塔面板, 请自行设置 ${Font}"
    fi
    systemctl disable xray
    judge "关闭 Xray 开机自启"
}

stop_service_all() {
    [[ -f ${nginx_systemd_file} ]] && systemctl stop nginx && systemctl disable nginx
    [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx stop
    systemctl stop xray
    systemctl disable xray
    echo -e "${OK} ${GreenBG} 停止已有服务 ${Font}"
}

service_restart(){
    systemctl daemon-reload
    wait
    if [[ ${tls_mode} != "None" ]]; then
        [[ -f ${nginx_systemd_file} ]] && systemctl restart nginx && judge "Nginx 重启"
        [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx restart && judge "Nginx 重启"
    fi
    systemctl restart xray
    judge "Xray 重启"
}

service_start(){
    if [[ ${tls_mode} != "None" ]]; then
        [[ -f ${nginx_systemd_file} ]] && systemctl start nginx && judge "Nginx 启动"
        [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx start && judge "Nginx 启动"
    fi
    systemctl start xray
    judge "Xray 启动"
}

service_stop(){
    if [[ ${tls_mode} != "None" ]]; then
        [[ -f ${nginx_systemd_file} ]] && systemctl stop nginx && judge "Nginx 停止"
        [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx stop && judge "Nginx 停止"
    fi
    systemctl stop xray
    judge "Xray 停止"
}

acme_cron_update() {
    echo -e "\n${GreenBG} acme.sh 已自动设置证书自动更新 ${Font}"
    echo -e "${GreenBG} 是否需要重新设置证书自动更新 (不推荐) [Y/N]? ${Font}"
    read -r acme_cron_update_fq
    case $acme_cron_update_fq in
    *)
        ;;
    [yY][eE][sS] | [yY])
        if [[ "${ssl_self}" != "on" ]]; then
            wget -N -P ${idleleo_dir} --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/ssl_update.sh && chmod +x ${ssl_update_file}
            if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
                if [[ "${ID}" == "centos" ]]; then
                    #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
                    #        &> /dev/null" /var/spool/cron/root
                    sed -i "/acme.sh/c 0 3 15 * * bash ${ssl_update_file}" /var/spool/cron/root
                else
                    #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
                    #        &> /dev/null" /var/spool/cron/crontabs/root
                    sed -i "/acme.sh/c 0 3 15 * * bash ${ssl_update_file}" /var/spool/cron/crontabs/root
                fi
            fi
            judge "设置证书自动更新"
        else
            echo -e "${Error} ${RedBG} 自定义证书不支持此操作! ${Font}"
        fi
        ;;
    esac
}

network_secure() {
    check_system
    echo -e "\n${GreenBG} 设置 Fail2ban 用于防止暴力破解, 请选择: ${Font}"
    echo "1. 安装/启动 Fail2ban"
    echo "2. 卸载/停止 Fail2ban"
    echo "3. 重启 Fail2ban"
    echo "4. 查看 Fail2ban 状态"
    read -rp "请输入: " fail2ban_fq
    [[ -z ${fail2ban_fq} ]] && fail2ban_fq=1
    if [[ $fail2ban_fq == 1 ]]; then
        pkg_install "fail2ban"
        if [[ ! -f /etc/fail2ban/jail.local ]]; then
            cp -fp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        fi
        wait
        if [[ -z $(grep "filter   = sshd" /etc/fail2ban/jail.local) ]]; then
            sed -i "/sshd_log/i \enabled  = true\\nfilter   = sshd\\nmaxretry = 5\\nbantime  = 604800" /etc/fail2ban/jail.local
        fi
        if [[ ${tls_mode} != "None" ]] && [[ -z $(grep "filter   = nginx-botsearch" /etc/fail2ban/jail.local) ]]; then
            sed -i "/nginx_error_log/d" /etc/fail2ban/jail.local
            sed -i "s/http,https$/http,https,8080/g" /etc/fail2ban/jail.local
            sed -i "/^maxretry.*= 2$/c \\maxretry = 5" /etc/fail2ban/jail.local
            sed -i "/nginx-botsearch/i \[nginx-badbots]\\n\\nenabled  = true\\nport     = http,https,8080\\nfilter   = apache-badbots\\nlogpath  = /etc/nginx/logs/access.log\\nbantime  = 604800\\nmaxretry = 5\\n" /etc/fail2ban/jail.local
            sed -i "/nginx-botsearch/a \\\nenabled  = true\\nfilter   = nginx-botsearch\\nlogpath  = /etc/nginx/logs/access.log\\n           /etc/nginx/logs/error.log\\nbantime  = 604800" /etc/fail2ban/jail.local
        fi
        wait
        judge "Fail2ban 配置"
        systemctl start fail2ban
        wait
        systemctl enable fail2ban
        judge "Fail2ban 启动"
        timeout "清空屏幕!"
        clear
    fi
    if [[ $fail2ban_fq == 2 ]]; then
        [[ -f /etc/fail2ban/jail.local ]] && rm -rf /etc/fail2ban/jail.local
        systemctl stop fail2ban
        wait
        systemctl disable fail2ban
        judge "Fail2ban 停止"
        timeout "清空屏幕!"
        clear
    fi
    if [[ $fail2ban_fq == 3 ]]; then
        systemctl daemon-reload
        wait
        systemctl restart fail2ban
        judge "Fail2ban 重启"
        timeout "清空屏幕!"
        clear
    fi
    if [[ $fail2ban_fq == 4 ]]; then
        echo -e "${GreenBG} Fail2ban 配置状态: ${Font}"
        fail2ban-client status
        echo -e "${GreenBG} Fail2ban SSH 封锁情况: ${Font}"
        fail2ban-client status sshd
        if [[ ${tls_mode} != "None" ]]; then
            echo -e "${GreenBG} Fail2ban Nginx 封锁情况: ${Font}"
            fail2ban-client status nginx-badbots
            fail2ban-client status nginx-botsearch
        fi
        echo -e "${GreenBG} Fail2ban 运行状态: ${Font}"
        systemctl status fail2ban
    fi
}

clean_logs() {
    echo -e "\n${GreenBG} 检测到日志文件大小如下 ${Font}"
    echo -e "${GreenBG}$(du -sh /var/log/xray /etc/nginx/logs)${Font}"
    timeout "即将清除!"
    for i in $(find /var/log/xray/ /etc/nginx/logs -name "*.log"); do cat /dev/null >$i; done
    judge "日志清理"
    echo -e "\n${GreenBG} 是否需要设置自动清理日志 [Y/N]? ${Font}"
    read -r auto_clean_logs_fq
    case $auto_clean_logs_fq in
    [yY][eE][sS] | [yY])
        echo -e "${GreenBG} 将在每周三04:00自动清空日志 ${Font}"
        if [[ "${ID}" == "centos" ]]; then
            if [[ $(grep -c "find /var/log/xray/ /etc/nginx/logs -name" /var/spool/cron/root) -eq '0' ]]; then
                echo "0 4 * * 3 for i in \$(find /var/log/xray/ /etc/nginx/logs -name \"*.log\"); do cat /dev/null >\$i; done >/dev/null 2>&1" >> /var/spool/cron/root
                judge "设置自动清理日志"
            else
                echo -e "${Warning} ${YellowBG} 已设置自动清理日志任务 ${Font}"
            fi
        else
            if [[ $(grep -c "find /var/log/xray/ /etc/nginx/logs -name" /var/spool/cron/crontabs/root) -eq '0' ]]; then
                echo "0 4 * * 3 for i in \$(find /var/log/xray/ /etc/nginx/logs -name \"*.log\"); do cat /dev/null >\$i; done >/dev/null 2>&1" >> /var/spool/cron/crontabs/root
                judge "设置自动清理日志"
            else
                echo -e "${Warning} ${YellowBG} 已设置自动清理日志任务 ${Font}"
            fi
        fi
        ;;
    *)
        timeout "清空屏幕!"
        clear
        ;;
    esac
}

vless_qr_config_tls_ws() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${domain}",
    "port": "${port}",
    "ws_port": "${xport}",
    "grpc_port": "${gport}",
    "tls": "TLS",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${path}",
    "servicename": "${servicename}",
    "bt_nginx": "${bt_nginx}",
    "nginx_version": "${nginx_version}",
    "openssl_version": "${openssl_version}",
    "jemalloc_version": "${jemalloc_version}"
}
EOF
}

vless_qr_config_xtls() {
    cat >${xray_qr_config_file} <<-EOF
{
    "shell_mode": "${shell_mode}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "host": "${domain}",
    "port": "${port}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "tcp",
    "tls": "XTLS",
    "xtls_add_more": "${xtls_add_more}",
    "ws_port": "${artxport}",
    "ws_path": "${artpath}",
    "grpc_port": "${artgport}",
    "grpc_servicename": "${artservicename}",
    "bt_nginx": "${bt_nginx}",
    "nginx_version": "${nginx_version}",
    "openssl_version": "${openssl_version}",
    "jemalloc_version": "${jemalloc_version}"
}
EOF
}

vless_qr_config_ws_only() {
    cat >${xray_qr_config_file} <<-EOF
{
    "host": "${local_ip}",
    "ws_grpc_mode": "${ws_grpc_mode}",
    "ws_port": "${xport}",
    "grpc_port": "${gport}",
    "tls": "None",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "ws/gRPC",
    "path": "${path}",
    "servicename": "${servicename}"
}
EOF
}

vless_urlquote()
{
    [[ $# = 0 ]] && return
    echo "import urllib.request;print(urllib.request.quote('$1'));" | python3
}

vless_qr_link_image() {
    if [[ ${tls_mode} == "TLS" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?path=/$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"host\"'))&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+ws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?serviceName=$(vless_urlquote $(info_extraction '\"servicename\"'))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"host\"'))&type=grpc#$(vless_urlquote $(info_extraction '\"host\"'))+gRPC%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?path=/$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"host\"'))&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+ws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?serviceName=$(vless_urlquote $(info_extraction '\"servicename\"'))&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"host\"'))&type=grpc#$(vless_urlquote $(info_extraction '\"host\"'))+gRPC%E5%8D%8F%E8%AE%AE"
        fi
    elif [[ ${tls_mode} == "XTLS" ]]; then
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?security=xtls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#$(vless_urlquote $(info_extraction '\"host\"'))+xtls%E5%8D%8F%E8%AE%AE"
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            vless_ws_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"ws_port\"')?path=/$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
            vless_grpc_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"grpc_port\"')?serviceName=$(vless_urlquote $(info_extraction '\"servicename\"'))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction '\"host\"'))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            vless_ws_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"ws_port\"')?path=/$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
            vless_grpc_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"grpc_port\"')?serviceName=$(vless_urlquote $(info_extraction '\"servicename\"'))&encryption=none&type=grpc#$(vless_urlquote $(info_extraction '\"host\"'))+%E5%8D%95%E7%8B%ACgrpc%E5%8D%8F%E8%AE%AE"
        fi
    fi
        {
            echo -e "\n${Red} —————————————— Xray 配置分享 —————————————— ${Font}"
            if [[ ${tls_mode} == "XTLS" ]]; then
                echo -e "${Red} URL 分享链接:${Font} ${vless_link}"
                echo -e "$Red 二维码: $Font"
                echo -n "${vless_link}" | qrencode -o - -t utf8
                echo -e "\n"
            else
                if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                    echo -e "${Red} ws URL 分享链接:${Font} ${vless_ws_link}"
                    echo -e "$Red 二维码: $Font"
                    echo -n "${vless_ws_link}" | qrencode -o - -t utf8
                    echo -e "\n"
                elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                    echo -e "${Red} gRPC URL 分享链接:${Font} ${vless_grpc_link}"
                    echo -e "$Red 二维码: $Font"
                    echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
                    echo -e "\n"
                elif  [[ ${ws_grpc_mode} == "all" ]]; then
                    echo -e "${Red} ws URL 分享链接:${Font} ${vless_ws_link}"
                    echo -e "$Red 二维码: $Font"
                    echo -n "${vless_ws_link}" | qrencode -o - -t utf8
                    echo -e "\n"
                    echo -e "${Red} gRPC URL 分享链接:${Font} ${vless_grpc_link}"
                    echo -e "$Red 二维码: $Font"
                    echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
                    echo -e "\n"
                fi
            fi
        } >>"${xray_info_file}"
}

vless_link_image_choice() {
    echo -e "\n${GreenBG} 请选择生成的分享链接种类: ${Font}"
    echo "1: V2RayN/V2RayNG/Qv2ray"
    read -rp "请输入: " link_version
    [[ -z ${link_version} ]] && link_version=1
    if [[ $link_version == 1 ]]; then
        vless_qr_link_image
    else
        vless_qr_link_image
    fi
}

info_extraction() {
    grep "$1" ${xray_qr_config_file} | awk -F '"' '{print $4}'
    [[ 0 -ne $? ]] && read_config_status=0
}

basic_information() {
    {
        echo -e "\n"
        case ${shell_mode} in
        Nginx+ws+TLS)
            echo -e "${OK} ${GreenBG} Xray+Nginx+ws+TLS 安装成功 ${Font}"
            ;;
        Nginx+gRPC+TLS)
            echo -e "${OK} ${GreenBG} Xray+Nginx+grpc+TLS 安装成功 ${Font}"
            ;;
        Nginx+ws+gRPC+TLS)
            echo -e "${OK} ${GreenBG} Xray+Nginx+ws+gRPC+TLS 安装成功 ${Font}"
            ;;
        XTLS+Nginx)
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx 安装成功 ${Font}"
            ;;
        XTLS+Nginx+ws)
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx+ws 安装成功 ${Font}"
            ;;
        XTLS+Nginx+gRPC)
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx+gRPC 安装成功 ${Font}"
            ;;
        XTLS+Nginx+ws+gRPC)
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx+ws+gRPC 安装成功 ${Font}"
            ;;
        ws?ONLY)
            echo -e "${OK} ${GreenBG} ws ONLY 安装成功 ${Font}"
            ;;
        gRPC?ONLY)
            echo -e "${OK} ${GreenBG} gRPC ONLY 安装成功 ${Font}"
            ;;
        ws+gRPC?ONLY)
            echo -e "${OK} ${GreenBG} ws+gRPC ONLY 安装成功 ${Font}"
            ;;
        esac
        echo -e "\n${Warning} ${YellowBG} VLESS 目前分享链接规范为实验阶段, 请自行判断是否适用 ${Font}"
        echo -e "\n${Red} —————————————— Xray 配置信息 —————————————— ${Font}"
        echo -e "${Red} 主机 (host):${Font} $(info_extraction '\"host\"') "
        if [[ ${tls_mode} == "None" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                echo -e "${Red} ws 端口 (port):${Font} $(info_extraction '\"ws_port\"') "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                echo -e "${Red} gRPC 端口 (port):${Font} $(info_extraction '\"grpc_port\"') "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                echo -e "${Red} ws 端口 (port):${Font} $(info_extraction '\"ws_port\"') "
                echo -e "${Red} gRPC 端口 (port):${Font} $(info_extraction '\"grpc_port\"') "
            fi
        else
            echo -e "${Red} 端口 (port):${Font} $(info_extraction '\"port\"') "
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                echo -e "${Red} Xray ws 端口 (inbound_port):${Font} $(info_extraction '\"ws_port\"') "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                echo -e "${Red} Xray gRPC 端口 (inbound_port):${Font} $(info_extraction '\"grpc_port\"') "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                echo -e "${Red} Xray ws 端口 (inbound_port):${Font} $(info_extraction '\"ws_port\"') "
                echo -e "${Red} Xray gRPC 端口 (inbound_port):${Font} $(info_extraction '\"grpc_port\"') "
            fi
        fi
        echo -e "${Red} UUIDv5 映射字符串:${Font} $(info_extraction '\"idc\"')"
        echo -e "${Red} 用户id (UUID):${Font} $(info_extraction '\"id\"')"

        echo -e "${Red} 加密 (encryption):${Font} None "
        echo -e "${Red} 传输协议 (network):${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} 底层传输安全 (tls):${Font} $(info_extraction '\"tls\"') "
        if [[ ${tls_mode} != "XTLS" ]]; then
            if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                echo -e "${Red} 路径 (path 不要落下/):${Font} /$(info_extraction '\"path\"') "
            elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                echo -e "${Red} serviceName (不需要加/):${Font} $(info_extraction '\"servicename\"') "
            elif [[ ${ws_grpc_mode} == "all" ]]; then
                echo -e "${Red} 路径 (path 不要落下/):${Font} /$(info_extraction '\"path\"') "
                echo -e "${Red} serviceName (不需要加/):${Font} $(info_extraction '\"servicename\"') "
            fi
        else
            echo -e "${Red} 流控 (flow):${Font} xtls-rprx-direct "
            if [[ "$xtls_add_more" == "on" ]]; then
                if [[ ${ws_grpc_mode} == "onlyws" ]]; then
                    echo -e "${Red} ws 端口 (port):${Font} $(info_extraction '\"ws_port\"') "
                    echo -e "${Red} ws 路径 (不要落下/):${Font} /$(info_extraction '\"ws_path\"') "
                elif [[ ${ws_grpc_mode} == "onlygRPC" ]]; then
                    echo -e "${Red} gRPC 端口 (port):${Font} $(info_extraction '\"grpc_port\"') "
                    echo -e "${Red} gRPC serviceName (不需要加/):${Font} $(info_extraction '\"grpc_servicename\"') "
                elif [[ ${ws_grpc_mode} == "all" ]]; then
                    echo -e "${Red} ws 端口 (port):${Font} $(info_extraction '\"ws_port\"') "
                    echo -e "${Red} ws 路径 (不要落下/):${Font} /$(info_extraction '\"ws_path\"') "
                    echo -e "${Red} gRPC 端口 (port):${Font} $(info_extraction '\"grpc_port\"') "
                    echo -e "${Red} gRPC serviceName (不需要加/):${Font} $(info_extraction '\"grpc_servicename\"') "
                fi
            fi
        fi
    } > "${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    echo -e "\n${GreenBG} 即将申请证书, 支持使用自定义证书 ${Font}"
    echo -e "${GreenBG} 如需使用自定义证书, 请按如下步骤:  ${Font}"
    echo -e "${GreenBG} 1. 将证书文件重命名: 私钥(xray.key)、证书(xray.crt) ${Font}"
    echo -e "${GreenBG} 2. 将重命名后的证书文件放入 ${ssl_chainpath} 目录后再运行脚本 ${Font}"
    echo -e "${GreenBG} 3. 重新运行脚本 ${Font}"
    echo -e "${GreenBG} 是否继续 [Y/N]?  ${Font}"
    read -r ssl_continue
    case $ssl_continue in
    [nN][oO]|[nN])
        exit 0
        ;;
    *)
        if [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] &&  [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            echo -e "${GreenBG} 所有证书文件均已存在, 是否保留 [Y/N]? ${Font}"
            read -r ssl_delete_1
            case $ssl_delete_1 in
            [nN][oO]|[nN])
                delete_tls_key_and_crt
                rm -rf ${ssl_chainpath}/*
                echo -e "${OK} ${GreenBG} 已删除 ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -R nobody:${cert_group} ${ssl_chainpath}/*
                judge "证书应用"
                ;;
            esac
        elif [[ -f "${ssl_chainpath}/xray.key" || -f "${ssl_chainpath}/xray.crt" ]] &&  [[ ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && ! -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
            echo -e "${GreenBG} 证书文件已存在, 是否保留 [Y/N]? ${Font}"
            read -r ssl_delete_2
            case $ssl_delete_2 in
            [nN][oO]|[nN])
                rm -rf ${ssl_chainpath}/*
                echo -e "${OK} ${GreenBG} 已删除 ${Font}"
                ssl_install
                acme
                ;;
            *)
                chown -R nobody:${cert_group} ${ssl_chainpath}/*
                judge "证书应用"
                ssl_self="on"
                ;;
            esac
        elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] && [[ ! -f "${ssl_chainpath}/xray.key" || ! -f "${ssl_chainpath}/xray.crt"  ]]; then
            echo -e "${GreenBG} 证书签发残留文件已存在, 是否保留 [Y/N]? ${Font}"
            read -r ssl_delete_3
            case $ssl_delete_3 in
            [nN][oO]|[nN])
                delete_tls_key_and_crt
                echo -e "${OK} ${GreenBG} 已删除 ${Font}"
                ssl_install
                acme
                ;;
            *)
                "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
                chown -R nobody:${cert_group} ${ssl_chainpath}/*
                judge "证书应用"
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
    if [[ ${bt_nginx} == "Yes" ]]; then
        echo -e "${Warning} ${GreenBG} 存在宝塔面板, 不需要设置 ${Font}"
        return 0
    fi
    cat >${nginx_systemd_file} <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Nginx systemd ServerFile 添加"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f ${nginx_conf} ]] && [[ ${tls_mode} != "None" ]]; then
        echo -e "\n${GreenBG} 请选择支持的 TLS 版本 (default:2): ${Font}"
        echo "建议选择 TLS1.2 and TLS1.3 (一般模式)"
        echo "1: TLS1.1 TLS1.2 and TLS1.3 (兼容模式)"
        echo "2: TLS1.2 and TLS1.3 (一般模式)"
        echo "3: TLS1.3 only (激进模式)"
        read -rp "请输入: " tls_version
        [[ -z ${tls_version} ]] && tls_version=2
        if [[ $tls_version == 3 ]]; then
            if [[ ${tls_mode} == "TLS" ]]; then
                sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
            else
                sed -i "s/^\( *\)\"minVersion\".*/\1\"minVersion\": \"1.3\",/" ${xray_conf}
            fi
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            if [[ ${tls_mode} == "TLS" ]]; then
                sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.1 TLSv1.2 TLSv1.3;/" $nginx_conf
                echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 and TLS1.3 ${Font}"
            else
                echo -e "${Error} ${RedBG} XTLS 最低版本应大于 TLS1.1, 请重新选择！ ${Font}"
                tls_type
            fi
        else
            if [[ ${tls_mode} == "TLS" ]]; then
                sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.2 TLSv1.3;/" $nginx_conf
            else
                sed -i "s/^\( *\)\"minVersion\".*/\1\"minVersion\": \"1.2\",/" ${xray_conf}
            fi
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 and TLS1.3 ${Font}"
        fi
        wait
        if [[ ${tls_mode} == "TLS" ]]; then
            [[ -f ${nginx_systemd_file} ]] && systemctl restart nginx && judge "Nginx 重启"
            [[ ${bt_nginx} == "Yes" ]] && /etc/init.d/nginx restart && judge "Nginx 重启"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            systemctl restart xray
            judge "Xray 重启"
        fi
    else
        echo -e "${Error} ${RedBG} Nginx 或 配置文件不存在 或当前安装版本为 ws ONLY , 请正确安装脚本后执行${Font}"
    fi
}

Revision_port() {
    if [[ ${tls_mode} == "TLS" ]]; then
        read_optimize "请输入连接端口 (默认值:443):" "port" 443 0 65535 "请输入 0-65535 之间的值!"
        modify_nginx_port
        [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"port\".*/\1\"port\": \"${port}\",/" ${xray_qr_config_file}
        echo -e "${OK} ${GreenBG} 连接端口号: ${port} ${Font}"
    elif [[ ${tls_mode} == "XTLS" ]]; then
        read_optimize "请输入连接端口 (默认值:443):" "port" 443 0 65535 "请输入 0-65535 之间的值!"
        xport=$((RANDOM + 10000))
        gport=$((RANDOM + 10000))
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            read_optimize "请输入 ws inbound_port:" "xport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${xport}"
            gport=$((RANDOM + 10000))
            [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"ws_port\".*/\1\"ws_port\": \"${xport}\",/" ${xray_qr_config_file}
            echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
        elif [[ ${ws_grpc_mode} == "onlygrpc" ]]; then
            read_optimize "请输入 gRPC inbound_port:" "gport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${gport}"
            xport=$((RANDOM + 10000))
            [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"grpc_port\".*/\1\"grpc_port\": \"${gport}\",/" ${xray_qr_config_file}
            echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            read_optimize "请输入 ws inbound_port:" "xport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            read_optimize "请输入 gRPC inbound_port:" "gport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${xport}"
            port_exist_check "${gport}"
            [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"ws_port\".*/\1\"ws_port\": \"${xport}\",/" ${xray_qr_config_file}
            [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"grpc_port\".*/\1\"grpc_port\": \"${gport}\",/" ${xray_qr_config_file}
            echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
            echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
        fi
        wait
        modify_inbound_port
    elif [[ ${tls_mode} == "None" ]]; then
        if [[ ${ws_grpc_mode} == "onlyws" ]]; then
            read_optimize "请输入 ws inbound_port:" "xport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${xport}"
            gport=$((RANDOM + 10000))
            echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
        elif [[ ${ws_grpc_mode} == "onlygrpc" ]]; then
            read_optimize "请输入 gRPC inbound_port:" "gport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${gport}"
            xport=$((RANDOM + 10000))
            echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
        elif [[ ${ws_grpc_mode} == "all" ]]; then
            read_optimize "请输入 ws inbound_port:" "xport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            read_optimize "请输入 gRPC inbound_port:" "gport" "NULL" 0 65535 "请输入 0-65535 之间的值!"
            port_exist_check "${xport}"
            port_exist_check "${gport}"
            echo -e "${OK} ${GreenBG} ws inbound_port: ${xport} ${Font}"
            echo -e "${OK} ${GreenBG} gRPC inbound_port: ${gport} ${Font}"
        fi
        [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"ws_port\".*/\1\"ws_port\": \"${xport}\",/" ${xray_qr_config_file}
        [[ -f ${xray_qr_config_file} ]] && sed -i "s/^\( *\)\"grpc_port\".*/\1\"grpc_port\": \"${gport}\",/" ${xray_qr_config_file}
        wait
        modify_inbound_port
    fi
}

show_access_log() {
    [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${Error} ${RedBG} log文件不存在! ${Font}"
}

show_error_log() {
    [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${Error} ${RedBG} log文件不存在! ${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${Error} ${RedBG} 证书签发工具不存在, 请确认你是否使用了自己的证书! ${Font}"
    domain="$(info_extraction '\"host\"')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
}

bbr_boost_sh() {
    if [[ -f "${idleleo_dir}/tcp.sh" ]]; then
        chmod +x ${idleleo_dir}/tcp.sh && ${idleleo_dir}/tcp.sh
    else
        wget -N --no-check-certificate -P ${idleleo_dir} "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x ${idleleo_dir}/tcp.sh && ${idleleo_dir}/tcp.sh
    fi
}

mtproxy_sh() {
    wget -N --no-check-certificate "https://github.com/whunt1/onekeymakemtg/raw/master/mtproxy_go.sh" && chmod +x mtproxy_go.sh && bash mtproxy_go.sh
}

uninstall_all() {
    stop_service_all
    systemctl disable xray
    [[ -f ${xray_systemd_file} ]] && rm -rf ${xray_systemd_file}
    [[ -f ${xray_systemd_file2} ]] && rm -rf ${xray_systemd_file2}
    [[ -d ${xray_systemd_filed} ]] && rm -rf ${xray_systemd_filed}
    [[ -d ${xray_systemd_filed2} ]] && rm -rf ${xray_systemd_filed2}
    [[ -f ${xray_bin_dir} ]] && rm -rf ${xray_bin_dir}
    [[ -d ${xray_conf_dir} ]] && rm -rf ${xray_conf_dir}
    [[ -L ${xray_default_conf} ]] && rm -rf ${xray_default_conf}
    [[ -d ${idleleo_tmp} ]] && rm -rf ${idleleo_tmp}
    [[ -L /www/server/panel/vhost/nginx/xray.conf ]] && rm -rf /www/server/panel/vhost/nginx/xray.conf
    [[ -L /www/server/panel/vhost/nginx/xray-server.conf ]] && rm -rf /www/server/panel/vhost/nginx/xray-server.conf
    if [[ -d ${nginx_dir} ]]; then
        echo -e "${Green} 是否卸载 Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*
            [[ -f ${nginx_systemd_file} ]] && rm -rf ${nginx_systemd_file}
            echo -e "${OK} ${Green} 已卸载 Nginx ${Font}"
            ;;
        *) ;;
        esac
    fi
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} 已卸载, SSL 证书文件已保留\n ${Font}"
}

delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG} 已清空证书遗留文件 ${Font}"
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
        printf "${Warning} ${GreenBG} %d秒后将$1 ${Font} \033[${timeout_color};${timeout_bg}m%-s\033[0m \033[${timeout_color}m%d\033[0m \r" "$timeout_index" "$timeout_str" "$timeout_index"
        sleep 0.1
        timeout_str=${timeout_str%?}
        [[ ${timeout} -eq 0 ]] && printf "\n"
    done
}

judge_mode() {
    if [[ -f ${xray_qr_config_file} ]]; then
        ws_grpc_mode=$(info_extraction '\"ws_grpc_mode\"')
        tls_mode=$(info_extraction '\"tls\"')
        bt_nginx=$(info_extraction '\"bt_nginx\"')
        if [[ ${tls_mode} == "TLS" ]]; then
            [[ ${ws_grpc_mode} == "onlyws" ]] && shell_mode="Nginx+ws+TLS"
            [[ ${ws_grpc_mode} == "onlygRPC" ]] && shell_mode="Nginx+gRPC+TLS"
            [[ ${ws_grpc_mode} == "all" ]] && shell_mode="Nginx+ws+gRPC+TLS"
        elif [[ ${tls_mode} == "XTLS" ]]; then
            if [[ $(info_extraction '\"xtls_add_more\"') != "off" ]]; then
                xtls_add_more="on"
                [[ ${ws_grpc_mode} == "onlyws" ]] && shell_mode="XTLS+Nginx+ws"
                [[ ${ws_grpc_mode} == "onlygRPC" ]] && shell_mode="XTLS+Nginx+gRPC"
                [[ ${ws_grpc_mode} == "all" ]] && shell_mode="XTLS+Nginx+ws+gRPC"
            else
                shell_mode="XTLS+Nginx"
            fi
        elif [[ ${tls_mode} == "None" ]]; then
            [[ ${ws_grpc_mode} == "onlyws" ]] && shell_mode="ws ONLY"
            [[ ${ws_grpc_mode} == "onlygRPC" ]] && shell_mode="gRPC ONLY"
            [[ ${ws_grpc_mode} == "all" ]] && shell_mode="ws+gRPC ONLY"
        fi
        old_tls_mode=${tls_mode}
    fi
}

install_xray_ws_tls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    create_directory
    domain_check
    ws_grpc_choose
    old_config_exist_check
    port_set
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    UUID_set
    stop_service_all
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    xray_conf_add
    nginx_conf_add
    nginx_conf_servers_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    tls_type
    vless_qr_config_tls_ws
    basic_information
    vless_link_image_choice
    show_information
    service_restart
    enable_process_systemd
    acme_cron_update
}

install_xray_xtls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    create_directory
    domain_check
    old_config_exist_check
    port_set
    UUID_set
    stop_service_all
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_conf_add_xtls
    xray_conf_add
    firewall_set
    ssl_judge_and_install
    nginx_systemd
    tls_type
    vless_qr_config_xtls
    basic_information
    vless_link_image_choice
    show_information
    service_restart
    enable_process_systemd
    acme_cron_update
}

install_xray_ws_only() {
    is_root
    check_system
    dependency_install
    basic_optimization
    create_directory
    ip_check
    ws_grpc_choose
    old_config_exist_check
    ws_inbound_port_set
    grpc_inbound_port_set
    firewall_set
    ws_path_set
    grpc_path_set
    UUID_set
    stop_service_all
    xray_install
    port_exist_check "${xport}"
    port_exist_check "${gport}"
    xray_conf_add
    vless_qr_config_ws_only
    basic_information
    vless_link_image_choice
    show_information
    service_restart
    enable_process_systemd
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "${ol_version}" >${version_cmp}
    [[ -z ${ol_version} ]] && clear && echo -e "${Error} ${RedBG}  检测最新版本失败! ${Font}" && bash idleleo
    echo "${shell_version}" >>${version_cmp}
    newest_version=$(sort -rV ${version_cmp} | head -1)
    oldest_version=$(sort -V ${version_cmp} | head -1)
    version_difference=$(echo "(${newest_version:0:3}-${oldest_version:0:3})>0" | bc)
    if [[ ${shell_version} != ${newest_version} ]]; then
        if [[ ${version_difference} == 1 ]]; then
            echo -e "\n${Warning} ${YellowBG} 存在新版本, 但版本跨度较大, 可能存在不兼容情况, 是否更新 [Y/N]? ${Font}"
        else
            echo -e "\n${GreenBG} 存在新版本, 是否更新 [Y/N]? ${Font}"
        fi
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L ${idleleo_commend_file} ]] && rm -f ${idleleo_commend_file}
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            clear
            echo -e "${OK} ${GreenBG} 更新完成 ${Font}"
            [[ ${version_difference} == 1 ]] && echo -e "${Warning} ${YellowBG} 脚本版本跨度较大, 若服务无法正常运行请卸载后重装! ${Font}"
            bash idleleo
            ;;
        *) ;;
        esac
    else
        clear
        echo -e "${OK} ${GreenBG} 当前版本为最新版本 ${Font}"
        bash idleleo
    fi

}

maintain() {
    echo -e "${Error} ${RedBG} 该选项暂时无法使用! ${Font}"
    echo -e "${Error} ${RedBG} $1 ${Font}"
    exit 0
}

list() {
    case $1 in

    boost)
        bbr_boost_sh
        ;;
    crontab)
        acme_cron_update
        ;;
    nginx)
        nginx_update
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    show)
        clear
        basic_information
        vless_qr_link_image
        show_information
        ;;
    tls)
        tls_type
        ;;
    uninstall)
        uninstall_all
        ;;
    update)
        update_sh
        ;;
    xray)
        xray_update
        timeout "清空屏幕!"
        clear
        ;;
    xray_access)
        clear
        show_access_log
        ;;
    xray_error)
        clear
        show_error_log
        ;;
    *)
        menu
        ;;
    esac
}

idleleo_commend() {
    if [[ -L ${idleleo_commend_file} ]] || [[ -f ${idleleo_dir}/install.sh ]]; then
        old_version=$(grep "shell_version=" ${idleleo_dir}/install.sh | head -1 | awk -F '=|"' '{print $3}')
        echo "${old_version}" >${version_cmp}
        echo "${shell_version}" >>${version_cmp}
        oldest_version=$(sort -V ${version_cmp} | head -1)
        version_difference=$(echo "(${shell_version:0:3}-${oldest_version:0:3})>0" | bc)
        if [[ -z ${old_version} ]]; then
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            judge "下载最新脚本"
            clear
            bash idleleo
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            if [[ ${version_difference} == 1 ]]; then
                echo -e "${Warning} ${YellowBG} 脚本版本跨度较大, 可能存在不兼容情况, 是否继续使用 [Y/N]? ${Font}"
                read -r update_sh_fq
                case $update_sh_fq in
                [yY][eE][sS] | [yY])
                    rm -rf ${idleleo_dir}/install.sh
                    wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                    judge "下载最新脚本"
                    clear
                    echo -e "${Warning} ${YellowBG} 脚本版本跨度较大, 若服务无法正常运行请卸载后重装!\n ${Font}"
                    ;;
                *)
                    bash idleleo
                    ;;
                esac
            else
                rm -rf ${idleleo_dir}/install.sh
                wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
                judge "下载最新脚本"
                clear
            fi
            bash idleleo
        elif [[ ! -L ${idleleo_commend_file} ]]; then
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
        else
            echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
        fi
    else
        check_system
        pkg_install "bc,wget"
        wait
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p ${idleleo_dir}
        wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
        judge "下载最新脚本"
        ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
        clear
        bash idleleo
    fi
}

menu() {

    echo -e "\nXray 安装管理脚本 ${Red}[${shell_version}]${Font}"
    echo -e "--- authored by paniy ---"
    echo -e "--- changed by www.idleleo.com ---"
    echo -e "--- https://github.com/paniy ---\n"
    echo -e "当前已安装模式: ${shell_mode}\n"

    idleleo_commend

    echo -e "—————————————— 升级向导 ——————————————"
    echo -e "${Green}0.${Font}  升级 脚本"
    echo -e "${Green}1.${Font}  升级 Xray"
    echo -e "${Green}2.${Font}  升级 Nginx"
    echo -e "—————————————— 安装向导 ——————————————"
    echo -e "${Green}3.${Font}  安装 Xray (Nginx+ws/gRPC+tls)"
    echo -e "${Green}4.${Font}  安装 Xray (XTLS+Nginx+ws/gRPC)"
    echo -e "${Green}5.${Font}  安装 Xray (ws/gRPC ONLY)"
    echo -e "—————————————— 配置变更 ——————————————"
    echo -e "${Green}6.${Font}  变更 UUIDv5/映射字符串"
    echo -e "${Green}7.${Font}  变更 port"
    echo -e "${Green}8.${Font}  变更 TLS 版本"
    echo -e "${Green}9.${Font}  变更 Nginx 负载均衡配置"
    echo -e "—————————————— 查看信息 ——————————————"
    echo -e "${Green}10.${Font} 查看 Xray 实时访问日志"
    echo -e "${Green}11.${Font} 查看 Xray 实时错误日志"
    echo -e "${Green}12.${Font} 查看 Xray 配置信息"
    echo -e "—————————————— 服务相关 ——————————————"
    echo -e "${Green}13.${Font} 重启 所有服务"
    echo -e "${Green}14.${Font} 启动 所有服务"
    echo -e "${Green}15.${Font} 停止 所有服务"
    echo -e "${Green}16.${Font} 查看 所有服务"
    echo -e "—————————————— 其他选项 ——————————————"
    echo -e "${Green}17.${Font} 安装 TCP 加速脚本"
    echo -e "${Green}18.${Font} 设置 Fail2ban 防暴力破解"
    echo -e "${Green}19.${Font} 清除 日志文件"
    echo -e "${Green}20.${Font} 安装 MTproxy (不推荐)"
    echo -e "${Green}21.${Font} 设置 额外证书自动更新 (不推荐)"
    echo -e "${Green}22.${Font} 证书 有效期手动更新"
    echo -e "${Green}23.${Font} 卸载 Xray"
    echo -e "${Green}24.${Font} 清空 证书文件"
    echo -e "${Green}25.${Font} 退出 \n"

    read -rp "请输入数字: " menu_num
    case $menu_num in
    0)
        update_sh
        ;;
    1)
        xray_update
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    2)
        nginx_update
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    3)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        bash idleleo
        ;;
    4)
        shell_mode="XTLS+Nginx"
        tls_mode="XTLS"
        install_xray_xtls
        bash idleleo
        ;;
    5)
        echo -e "\n${Warning} ${YellowBG} 此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装 [Y/N]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        bash idleleo
        ;;
    6)
        UUID_set
        modify_UUID
        service_restart
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    7)
        Revision_port
        firewall_set
        service_restart
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    8)
        tls_type
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    9)
        nginx_upstream_server_set
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    10)
        clear
        show_access_log
        ;;
    11)
        clear
        show_error_log
        ;;
    12)
        clear
        basic_information
        vless_qr_link_image
        show_information
        bash idleleo
        ;;
    13)
        service_restart
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    14)
        service_start
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    15)
        service_stop
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    16)
        if [[ ${tls_mode} != "None" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        bash idleleo
        ;;
    17)
        clear
        bbr_boost_sh
        ;;
    18)
        network_secure
        bash idleleo
        ;;
    19)
        clean_logs
        bash idleleo
        ;;
    20)
        clear
        mtproxy_sh
        ;;
    21)
        acme_cron_update
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    22)
        service_stop
        ssl_update_manuel
        service_restart
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    23)
        uninstall_all
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    24)
        delete_tls_key_and_crt
        rm -rf ${ssl_chainpath}/*
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    25)
        timeout "清空屏幕!"
        clear
        exit 0
        ;;
    *)
        clear
        echo -e "${Error} ${RedBG} 请输入正确的数字! ${Font}"
        bash idleleo
        ;;
    esac
}

judge_mode
list "$1"
