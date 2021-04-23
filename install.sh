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

shell_version="1.6.3.6"
shell_mode="None"
shell_mode_show="未安装"
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
nginx_version="1.20.0"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"
read_config_status=1
xtls_add_ws="off"
old_config_status="off"
old_shell_mode="None"
random_num=$((RANDOM % 12 + 4))
THREAD=$(($(grep 'processor' /proc/cpuinfo | sort -u | wc -l) + 1))

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
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
        wait
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

dependency_install() {
    ${INS} install dbus wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install iputils
    else
        ${INS} -y install iputils-ping
    fi
    judge "安装 iputils-ping"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置"

    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install unzip
    judge "安装 unzip"

    ${INS} -y install qrencode
    judge "安装 qrencode"

    ${INS} -y install curl
    judge "安装 curl"

    ${INS} -y install python3
    judge "安装 python3"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    judge "编译工具包 安装"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
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
    if [[ ${shell_mode} != "wsonly" ]]; then
        [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p ${nginx_conf_dir}
    fi
    [[ ! -d "${xray_conf_dir}" ]] && mkdir -p ${xray_conf_dir}
    [[ ! -d "${idleleo_dir}/info" ]] && mkdir -p ${idleleo_dir}/info
    [[ ! -d "${idleleo_tmp}" ]] && mkdir -p ${idleleo_tmp}
}

port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "${GreenBG} 确定 连接端口  ${Font}"
        read -rp "请输入连接端口 (default:443):" port
        [[ -z ${port} ]] && port="443"
        if [[ ${port} -le 0 ]] || [[ ${port} -gt 65535 ]]; then
            echo -e "${Error} ${RedBG} 请输入 0-65535 之间的值! ${Font}"
            port_set
        fi
    fi
}

inbound_port_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "${GreenBG} 是否需要自定义 inbound_port [Y/N]? ${Font}"
        read -r inbound_port_modify_fq
        case $inbound_port_modify_fq in
        [yY][eE][sS] | [yY])
            read -rp "请输入自定义 inbound_port (请勿与连接端口相同！):" xport
            if [[ ${xport} -le 0 ]] || [[ ${xport} -gt 65535 ]]; then
                echo -e "${Error} ${RedBG} 请输入 0-65535 之间的值! ${Font}"
                inbound_port_set
            fi
            echo -e "${OK} ${GreenBG} inbound_port: ${xport} ${Font}"
            ;;
        *)
            xport=$((RANDOM + 10000))
            echo -e "${OK} ${GreenBG} inbound_port: ${xport} ${Font}"
            ;;
        esac
    fi
}

firewall_set() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        if [[ ${shell_mode} != "wsonly" ]] && [[ "$xtls_add_ws" == "off" ]]; then
            firewall-cmd --permanent --add-port=80/tcp
            firewall-cmd --permanent --add-port=443/tcp
            firewall-cmd --permanent --add-port=1024-65535/udp
            firewall-cmd --permanent --add-port=${port}/tcp
            firewall-cmd --permanent --add-port=${port}/udp
            firewall-cmd --reload
        else
            firewall-cmd --permanent --add-port=${xport}/tcp
            firewall-cmd --permanent --add-port=${xport}/udp
            firewall-cmd --reload
        fi
    else
        if [[ ${shell_mode} != "wsonly" ]]; then
            ufw allow 80,443/tcp
            ufw allow 1024:65535/udp
            ufw allow ${port}
            ufw reload
        else
            ufw allow ${xport}
            ufw reload
        fi
    fi
    echo -e "${OK} ${GreenBG} 开放防火墙相关端口 ${Font}"
    echo -e "${GreenBG} 若修改配置, 请注意关闭防火墙相关端口 ${Font}"
    echo -e "${OK} ${GreenBG} 配置 Xray FullCone ${Font}"
}

path_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "${GreenBG} 是否需要自定义伪装路径 [Y/N]? ${Font}"
        read -r path_modify_fq
        case $path_modify_fq in
        [yY][eE][sS] | [yY])
            read -rp "请输入自定义伪装路径 (不需要“/”):" camouflage
            camouflage="/${camouflage}"
            echo -e "${OK} ${GreenBG} 伪装路径: ${camouflage} ${Font}"
            ;;
        *)
            camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            echo -e "${OK} ${GreenBG} 伪装路径: ${camouflage} ${Font}"
            ;;
        esac
    fi
}

UUID_set() {
    if [[ "on" != ${old_config_status} ]]; then
        echo -e "${GreenBG} 是否需要自定义字符串映射为 UUIDv5 [Y/N]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read -rp "请输入自定义字符串 (最多30字符):" UUID5_char
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
    if [[ ${shell_mode} == "ws" ]]; then
        echo -e "${GreenBG} 是否追加 Nginx 负载均衡 [Y/N]? ${Font}"
        echo -e "${Warning} ${YellowBG} 如不清楚具体用途, 请勿继续! ${Font}"
        read -r nginx_upstream_server_fq
        case $nginx_upstream_server_fq in
        [yY][eE][sS] | [yY])
            read -rp "请输入负载均衡 主机 (host):" upstream_host
            read -rp "请输入负载均衡 端口 (port):" upstream_port
            read -rp "请输入负载均衡 权重 (0~100, 初始值为50):" upstream_weight
            sed -i "1a\\\t\\tserver ${upstream_host}:${upstream_port} weight=${upstream_weight} max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
            systemctl restart nginx
            judge "追加 Nginx 负载均衡"
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
    sed -i "/\"listen\"/c \        \"listen\": \"0.0.0.0\"," ${xray_conf}
}

modify_inbound_port() {
    if [[ ${shell_mode} == "ws" ]]; then
        #        sed -i "/\"port\"/c  \    \"port\":${xport}," ${xray_conf}
        sed -i "8c\        \"port\": ${xport}," ${xray_conf}
    elif [[ ${shell_mode} == "wsonly" ]]; then
        port=${xport}
        sed -i "8c\        \"port\": ${xport}," ${xray_conf}
    elif [[ ${shell_mode} == "xtls" ]]; then
        #        sed -i "/\"port\"/c  \    \"port\":${port}," ${xray_conf}
        sed -i "8c\        \"port\": ${port}," ${xray_conf}
        sed -i "38c\        \"port\": ${xport}," ${xray_conf}
    fi
    judge "Xray port 修改"
    if [[ ${shell_mode} != "ws" ]]; then
        [ -f ${xray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${xray_qr_config_file}
    fi
    echo -e "${OK} ${GreenBG} port: ${port} ${Font}"
}

modify_nginx_port() {
    sed -i "/ssl http2;$/c \\\t\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "5c \\\t\\tlisten [::]:${port} ssl http2;" ${nginx_conf}
    judge "Xray port 修改"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} 端口号: ${port} ${Font}"
}

modify_nginx_other() {
    sed -i '$i include /etc/idleleo/conf/nginx/*.conf;' ${nginx_dir}/conf/nginx.conf
    sed -i "/server_name/c \\\t\\tserver_name ${domain};" ${nginx_conf}
    if [[ ${shell_mode} != "xtls" ]]; then
        sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
        sed -i "/xray-serverc/c \\\t\\tserver 127.0.0.1:${xport} weight=50 max_fails=5 fail_timeout=2;" ${nginx_upstream_conf}
    fi
    sed -i "/return/c \\\t\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
    sed -i "/returc/c \\\t\\t\\treturn 302 https://www.idleleo.com/helloworld;" ${nginx_conf}
    sed -i "/locatioc/c \\\t\\tlocation \/" ${nginx_conf}
    sed -i "/error_page   500 502 503 504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 302 https:\/\/www.idleleo.com\/helloworld;\\n\\t\\t}" ${nginx_dir}/conf/nginx.conf
}

modify_path() {
    sed -i "/\"path\"/c \                \"path\":\"${camouflage}\"" ${xray_conf}
    if [[ ${shell_mode} != "xtls" ]] || [[ "$xtls_add_ws" == "on" ]]; then
        judge "Xray 伪装路径 修改"
        echo -e "${OK} ${GreenBG} 伪装路径: ${camouflage} ${Font}"
    else
        echo -e "${Warning} ${YellowBG} XTLS 不支持 path ${Font}"
    fi
}

modify_UUID() {
    sed -i "/\"id\"/c \                \"id\": \"${UUID}\"," ${xray_conf}
    judge "Xray UUID 修改"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"id\"/c \\  \"id\": \"${UUID}\"," ${xray_qr_config_file}
    [ -f ${xray_qr_config_file} ] && sed -i "/\"idc\"/c \\  \"idc\": \"${UUID5_char}\"," ${xray_qr_config_file}
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
    judge "Xray 擦屁股"
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
            if [[ -f  ${nginx_conf_dir}/original.confbackup ]]; then 
                cp -fp ${nginx_conf_dir}/original.confbackup ${nginx_dir}/conf/nginx.conf
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
    elif [[ -d "/usr/local/nginx/" ]]; then
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

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  4;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    cp -fp ${nginx_dir}/conf/nginx.conf ${nginx_conf_dir}/original.confbackup

    # 删除临时文件
    rm -rf ../nginx-${nginx_version}
    rm -rf ../openssl-${openssl_version}
    rm -rf ../nginx-${nginx_version}.tar.gz
    rm -rf ../openssl-${openssl_version}.tar.gz
}

nginx_update() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        if [[ ${nginx_version} != $(info_extraction '\"nginx_version\"') ]] || [[ ${openssl_version} != $(info_extraction '\"openssl_version\"') ]] || [[ ${jemalloc_version} != $(info_extraction '\"jemalloc_version\"') ]]; then
            if [[ ${shell_mode} == "ws" ]]; then
                if [[ -f $xray_qr_config_file ]]; then 
                    domain=$(info_extraction '\"host\"')
                    port=$(info_extraction '\"port\"')
                    xport=$(info_extraction '\"inbound_port\"')
                    camouflage=$(info_extraction '\"path\"')
                    if [[ 0 -eq ${read_config_status} ]]; then
                        echo -e "${Error} ${RedBG} 旧配置文件不完整, 退出升级 ${Font}"
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
            elif [[ ${shell_mode} == "xtls" ]]; then
                if [[ -f $xray_qr_config_file ]]; then
                    domain=$(info_extraction '\"host\"')
                    port=$(info_extraction '\"port\"')
                    if [[ 0 -eq ${read_config_status} ]]; then
                        echo -e "${Error} ${RedBG} 旧配置文件不完整, 退出升级 ${Font}"
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
            else
                echo -e "${Error} ${RedBG} 当前安装模式不需要 Nginx ! ${Font}"
                timeout "清空屏幕!"
                clear
                bash idleleo
            fi
            service_stop
            timeout "删除旧版 Nginx !"
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*.conf
            wait
            nginx_install
            wait
            if [[ ${shell_mode} == "ws" ]]; then    
                nginx_conf_add
            elif [[ ${shell_mode} == "xtls" ]]; then
                nginx_conf_add_xtls
            fi
            wait
            service_start
            sed -i "/\"nginx_version\"/c \  \"nginx_version\": \"${nginx_version}\"," ${xray_qr_config_file}
            sed -i "/\"openssl_version\"/c \  \"openssl_version\": \"${openssl_version}\"," ${xray_qr_config_file}
            sed -i "/\"jemalloc_version\"/c \  \"jemalloc_version\": \"${jemalloc_version}\"" ${xray_qr_config_file}
            judge "Nginx 升级"
        else
            echo -e "${OK} ${GreenBG} Nginx 已为最新版 ${Font}"
        fi
    else
        echo -e "${Error} ${RedBG} Nginx 未安装, 请安装后再试! ${Font}"
    fi
}

ssl_install() {
    if [[ ${ID} == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}

domain_check() {
    echo -e "\n${GreenBG} 确定 域名 信息 ${Font}"
    read -rp "请输入你的域名信息 (eg:www.idleleo.com):" domain
    echo -e "${GreenBG} 请选择 公网IP 为 IPv4 或 IPv6 ${Font}"
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
    if [[ ${shell_mode} != "xtls" ]]; then
        wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_tls/config.json -O config.json
        modify_path
        modify_inbound_port
    else
        wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_xtls/config.json -O config.json
        xray_xtls_add_ws
    fi
    if [[ ${shell_mode} == "wsonly" ]]; then
        modify_listen_address
    fi
    modify_alterid
    modify_UUID
}

xray_xtls_add_ws() {
    echo -e "${GreenBG} 是否添加简单 ws协议 用于负载均衡 [Y/N]? ${Font}"
    echo -e "${Warning} ${YellowBG} 如不清楚具体用途, 请勿选择! ${Font}"
    read -r xtls_add_ws_fq
    case $xtls_add_ws_fq in
    [yY][eE][sS] | [yY])
        xtls_add_ws="on"
        path_set
        modify_path
        artcamouflage=${camouflage}
        modify_listen_address
        inbound_port_set
        modify_inbound_port
        port_exist_check "${xport}"
        artxport=${xport}
        echo -e "${OK} ${GreenBG} ws_inbound_port: ${xport} ${Font}"
        ;;
    *)
        xtls_add_ws="off"
        artcamouflage="none"
        camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
        modify_path
        xport=$((RANDOM + 10000))
        modify_inbound_port
        artxport="none"
        echo -e "${OK} ${GreenBG} 已跳过添加简单 ws协议 ${Font}"
        ;;
    esac
}

old_config_exist_check() {
    if [[ -f $xray_qr_config_file ]]; then
        if [[ ${old_shell_mode} == ${shell_mode} ]]; then
            echo -e "${GreenBG} 检测到旧配置文件, 是否读取旧文件配置 [Y/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
                old_config_status="on"
                old_config_input
                ;;
            *)
                rm -rf $xray_qr_config_file
                echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
                ;;
            esac
        else
            echo -e "${GreenBG} 检测到当前安装模式与旧配置的安装模式不一致, 是否保留旧配置文件 [Y/N]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
                echo -e "${OK} ${GreenBG} 停止安装 ${Font}"
                bash idleleo
                ;;
            *)
                rm -rf $xray_qr_config_file
                echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
                ;;
            esac
        fi
    fi
}

old_config_input () {
    if [[ ${shell_mode} == "ws" ]]; then
        port=$(info_extraction '\"port\"')
        xport=$(info_extraction '\"inbound_port\"')
        UUID5_char=$(info_extraction '\"idc\"')
        UUID=$(info_extraction '\id\"')
        camouflage=$(info_extraction '\"path\"')
    elif [[ ${shell_mode} == "xtls" ]]; then
            port=$(info_extraction '\"port\"')
            UUID5_char=$(info_extraction '\"idc\"')
            UUID=$(info_extraction '\id\"')
        if [[ ${xtls_add_ws} == "on" ]]; then
                xport=$(info_extraction '\"wsport\"')
                camouflage=$(info_extraction '\"wspath\"')
        fi
    elif [[ ${shell_mode} == "wsonly" ]]; then
        xport=$(info_extraction '\"port\"')
        UUID5_char=$(info_extraction '\"idc\"')
        UUID=$(info_extraction '\id\"')
        camouflage=$(info_extraction '\"path\"')
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        echo -e "${GreenBG} 检测到旧配置文件不完整, 是否保留旧配置文件 [Y/N]? ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        [yY][eE][sS] | [yY])
            old_config_status="off"
            echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
            ;;
        *)
            rm -rf $xray_qr_config_file
            old_config_status="off"
            echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
            ;;
        esac
    fi
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/xray.conf
    cat >${nginx_conf_dir}/xray.conf <<EOF
    server_tokens off;
    types_hash_max_size 2048;

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        ssl_certificate       /etc/idleleo/cert/xray.crt;
        ssl_certificate_key   /etc/idleleo/cert/xray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
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

        location /ray/
        {
            proxy_pass http://xray-server;
            proxy_redirect default;
            proxy_http_version 1.1;
            proxy_connect_timeout 180s;
            proxy_send_timeout 180s;
            proxy_read_timeout 1800s;
            proxy_buffering off;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
            proxy_set_header Early-Data \$ssl_early_data;
        }
        
        locatioc
        {
            returc
        }
    }
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    touch ${nginx_conf_dir}/xray-server.conf
    cat >${nginx_conf_dir}/xray-server.conf <<EOF
    upstream xray-server { 
        xray-serverc
    }
EOF

    modify_nginx_port
    modify_nginx_other
    judge "Nginx 配置修改"
}

nginx_conf_add_xtls() {
    touch ${nginx_conf_dir}/xray.conf
    cat >${nginx_conf_dir}/xray.conf <<EOF
    server_tokens off;
    server {
        listen 127.0.0.1:8080 proxy_protocol;
        server_name serveraddr.com;
        set_real_ip_from 127.0.0.1;
        real_ip_header    X-Forwarded-For;
        real_ip_recursive on;
        add_header Strict-Transport-Security "max-age=63072000" always;
        locatioc
        {
            returc
        }
    }
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_other
    judge "Nginx 配置修改"
}

enable_process_systemd() {
    if [[ ${shell_mode} != "wsonly" ]]; then
        systemctl enable nginx
        judge "设置 Nginx 开机自启"
    fi
    systemctl enable xray
    judge "设置 Xray 开机自启"
}

disable_process_systemd() {
    if [[ ${shell_mode} != "wsonly" ]]; then
        systemctl stop nginx
        systemctl disable nginx
        judge "关闭 Xray 开机自启"
    fi
    systemctl disable xray
    judge "关闭 Xray 开机自启"
}

stop_service_all() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
    systemctl stop xray
    systemctl disable xray
    echo -e "${OK} ${GreenBG} 停止已有服务 ${Font}"
}

service_restart(){
    systemctl daemon-reload
    wait
    if [[ ${shell_mode} != "wsonly" ]]; then
        systemctl restart nginx
        judge "Nginx 重启"
    fi
    systemctl restart xray
    judge "Xray 重启"
}

service_start(){
    if [[ ${shell_mode} != "wsonly" ]]; then
        systemctl start nginx
        judge "Nginx 启动"
    fi
    systemctl start xray
    judge "Xray 启动" 
}

service_stop(){
    if [[ ${shell_mode} != "wsonly" ]]; then
        systemctl stop nginx
        judge "Nginx 停止"
    fi
    systemctl stop xray
    judge "Xray 停止"  
}

acme_cron_update() {
    wget -N -P ${idleleo_dir} --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/ssl_update.sh && chmod +x ${ssl_update_file}
    if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
        if [[ "${ID}" == "centos" ]]; then
            #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
            #        &> /dev/null" /var/spool/cron/root
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
        else
            #        sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
            #        &> /dev/null" /var/spool/cron/crontabs/root
            sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
        fi
    fi
    judge "cron 计划任务更新"
}

secure_ssh() {
    check_system
    echo -e "${GreenBG} 设置 Fail2ban 用于防止暴力破解, 请选择: ${Font}"
    echo "1. 安装/启动 Fail2ban"
    echo "2. 卸载/停止 Fail2ban"
    echo "3. 重启 Fail2ban"
    echo "4. 查看 Fail2ban 状态"
    read -rp "请输入: " fail2ban_fq
    [[ -z ${fail2ban_fq} ]] && fail2ban_fq=1
    if [[ $fail2ban_fq == 1 ]]; then
        ${INS} -y install fail2ban
        judge "Fail2ban 安装"
        if [[ ! -f /etc/fail2ban/jail.local ]]; then
            cp -fp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
        fi
        if [[ -z $(grep "filter   = sshd" /etc/fail2ban/jail.local) ]]; then
            sed -i "/sshd_log/i \enabled  = true\\nfilter   = sshd\\nmaxretry = 5\\nbantime  = 604800" /etc/fail2ban/jail.local
        fi
        if [[ ${shell_mode} != "wsonly" ]] && [[ -z $(grep "filter   = nginx-botsearch" /etc/fail2ban/jail.local) ]]; then
            sed -i "/nginx_error_log/d" /etc/fail2ban/jail.local
            sed -i "/http,https$/c \\port     = http,https,8080" /etc/fail2ban/jail.local
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
        if [[ ${shell_mode} != "wsonly" ]]; then
            echo -e "${GreenBG} Fail2ban Nginx 封锁情况: ${Font}"
            fail2ban-client status nginx-badbots
            fail2ban-client status nginx-botsearch
        fi 
        echo -e "${GreenBG} Fail2ban 运行状态: ${Font}"
        systemctl status fail2ban
    fi
}

vless_qr_config_tls_ws() {
    cat >$xray_qr_config_file <<-EOF
{
  "host": "${domain}",
  "port": "${port}",
  "inbound_port": "${xport}",
  "idc": "${UUID5_char}",
  "id": "${UUID}",
  "net": "ws",
  "path": "${camouflage}",
  "tls": "TLS",
  "nginx_version": "${nginx_version}",
  "openssl_version": "${openssl_version}",
  "jemalloc_version": "${jemalloc_version}"
}
EOF
}

vless_qr_config_xtls() {
    cat >$xray_qr_config_file <<-EOF
{
  "host": "${domain}",
  "port": "${port}",
  "idc": "${UUID5_char}",
  "id": "${UUID}",
  "net": "tcp",
  "tls": "XTLS",
  "wsport": "${artxport}",
  "wspath": "${artcamouflage}",
  "nginx_version": "${nginx_version}",
  "openssl_version": "${openssl_version}",
  "jemalloc_version": "${jemalloc_version}"
}
EOF
}

vless_qr_config_ws_only() {
    cat >$xray_qr_config_file <<-EOF
{
  "host": "${local_ip}",
  "port": "${xport}",
  "idc": "${UUID5_char}",
  "id": "${UUID}",
  "net": "ws",
  "path": "${camouflage}",
  "tls": "none"
}
EOF
}

vless_urlquote()
{
    [[ $# = 0 ]] && return
    echo "import urllib.request;print(urllib.request.quote('$1'));" | python3
}

vless_qr_link_image() {
    #vless_link="vless://$(base64 -w 0 $xray_qr_config_file)"
    if [[ ${shell_mode} == "ws" ]]; then
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?path=$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"host\"'))&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+ws%E5%8D%8F%E8%AE%AE"
    elif [[ ${shell_mode} == "xtls" ]]; then
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?security=xtls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#$(vless_urlquote $(info_extraction '\"host\"'))+xtls%E5%8D%8F%E8%AE%AE"
    elif [[ ${shell_mode} == "wsonly" ]]; then
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"host\"')):$(info_extraction '\"port\"')?path=$(vless_urlquote $(info_extraction '\"path\"'))%3Fed%3D2048&encryption=none&type=ws#$(vless_urlquote $(info_extraction '\"host\"'))+%E5%8D%95%E7%8B%ACws%E5%8D%8F%E8%AE%AE"
    fi
        {
            echo -e "\n${Red} —————————————— Xray 配置分享 —————————————— ${Font}"
            echo -e "${Red} URL 分享链接: ${vless_link} ${Font}"
            echo -e "$Red 二维码: $Font"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo -e "\n"
        } >>"${xray_info_file}"
}

vless_link_image_choice() {
    echo -e "${GreenBG} 请选择生成的分享链接种类: ${Font}"
    echo "1: V2RayN/V2RayNG/Qv2ray"
    read -rp "请输入: " link_version
    [[ -z ${link_version} ]] && link_version=1
    if [[ $link_version == 1 ]]; then
        vless_qr_link_image
    else
        vless_qr_link_image
    fi
    echo -e "${Warning} ${YellowBG} VLESS 目前分享链接规范为实验阶段, 请自行判断是否适用 ${Font}"
}

info_extraction() {
    grep "$1" $xray_qr_config_file | awk -F '"' '{print $4}'
    [[ 0 -ne $? ]] && read_config_status=0
}

basic_information() {
    {
        if [[ ${shell_mode} == "xtls" ]]; then
            echo -e "${OK} ${GreenBG} Xray+Nginx+ws+tls 安装成功 ${Font}"
        elif  [[ ${shell_mode} == "ws" ]]; then
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx 安装成功 ${Font}"
        elif  [[ ${shell_mode} == "wsonly" ]]; then
            echo -e "${OK} ${GreenBG} ws ONLY 安装成功 ${Font}"
        fi
        echo -e "${Warning} ${YellowBG} VLESS 目前分享链接规范为实验阶段, 请自行判断是否适用 ${Font}"
        echo -e "\n${Red} —————————————— Xray 配置信息 —————————————— ${Font}"
        echo -e "${Red} 主机 (host):${Font} $(info_extraction '\"host\"') "
        echo -e "${Red} 端口 (port):${Font} $(info_extraction '\"port\"') "
        if [[ ${shell_mode} == "ws" ]]; then
            echo -e "${Red} Xray 端口 (inbound_port):${Font} $(info_extraction '\"inbound_port\"') "
        fi
        echo -e "${Red} UUIDv5 映射字符串:${Font} $(info_extraction '\"idc\"')"
        echo -e "${Red} 用户id (UUID):${Font} $(info_extraction '\"id\"')"

        echo -e "${Red} 加密 (encryption):${Font} none "
        echo -e "${Red} 传输协议 (network):${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} 底层传输安全 (tls):${Font} $(info_extraction '\"tls\"') "
        if [[ ${shell_mode} != "xtls" ]]; then
            echo -e "${Red} 路径 (path 不要落下/):${Font} $(info_extraction '\"path\"') "
        else
            echo -e "${Red} 流控 (flow):${Font} xtls-rprx-direct "
            if [[ "$xtls_add_ws" == "on" ]]; then
                echo -e "${Red} ws端口 (port):${Font} $(info_extraction '\"wsport\"') "
                echo -e "${Red} ws路径 (不要落下/):${Font} $(info_extraction '\"wspath\"') "
            fi
        fi
    } >"${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
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
            judge "证书应用"
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
            judge "证书应用"
            ;;
        esac
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
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
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ ${shell_mode} != "wsonly" ]]; then
        echo -e "${GreenBG} 请选择支持的 TLS 版本 (default:2): ${Font}"
        echo "建议选择 TLS1.2 and TLS1.3 (一般模式)"
        echo "1: TLS1.1 TLS1.2 and TLS1.3 (兼容模式)"
        echo "2: TLS1.2 and TLS1.3 (一般模式)"
        echo "3: TLS1.3 only (激进模式)"
        read -rp "请输入: " tls_version
        [[ -z ${tls_version} ]] && tls_version=2
        if [[ $tls_version == 3 ]]; then
            if [[ $shell_mode == "ws"  ]]; then
                sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.3;/' $nginx_conf
            else
                sed -i "/\"minVersion\"/c \                \"minVersion\": \"1.3\"," ${xray_conf}   
            fi
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            if [[ $shell_mode == "ws"  ]]; then
                sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
                echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 and TLS1.3 ${Font}"
            else
                echo -e "${Error} ${RedBG} XTLS最低版本应大于 TLS1.1, 请重新选择！ ${Font}" 
                tls_type
            fi
        else
            if [[ $shell_mode == "ws"  ]]; then
                sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/' $nginx_conf
            else
                sed -i "/\"minVersion\"/c \                \"minVersion\": \"1.2\"," ${xray_conf}  
            fi
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 and TLS1.3 ${Font}"
        fi
        if [[ $shell_mode == "ws"  ]]; then
            systemctl restart nginx
            judge "Nginx 重启"
        elif [[ $shell_mode == "xtls"  ]]; then
            systemctl restart xray
            judge "Xray 重启"
        fi
    else
        echo -e "${Error} ${RedBG} Nginx 或 配置文件不存在 或当前安装版本为 ws ONLY , 请正确安装脚本后执行${Font}"
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
    [[ -f ${nginx_systemd_file} ]] && rm -rf ${nginx_systemd_file}
    [[ -f ${xray_systemd_file} ]] && rm -rf ${xray_systemd_file}
    [[ -f ${xray_systemd_file2} ]] && rm -rf ${xray_systemd_file2}
    [[ -d ${xray_systemd_filed} ]] && rm -rf ${xray_systemd_filed}
    [[ -d ${xray_systemd_filed2} ]] && rm -rf ${xray_systemd_filed2}
    [[ -f ${xray_bin_dir} ]] && rm -rf ${xray_bin_dir}
    [[ -d ${xray_conf_dir} ]] && rm -rf ${xray_conf_dir}
    [[ -L ${xray_default_conf} ]] && rm -rf ${xray_default_conf}
    [[ -d ${idleleo_tmp} ]] && rm -rf ${idleleo_tmp}
    if [[ -d ${nginx_dir} ]]; then
        echo -e "${Green} 是否卸载 Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf ${nginx_dir}
            rm -rf ${nginx_conf_dir}/*
            echo -e "${OK} ${Green} 已卸载 Nginx ${Font}"
            ;;
        *) ;;
        esac
    fi
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} 已卸载, SSL 证书文件已保留 ${Font}"
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
        timeout_black=" "
        printf "${Warning} ${GreenBG} %d秒后将$1 ${Font} \033[${timeout_color};${timeout_bg}m%-s\033[0m \033[${timeout_color}m%d\033[0m%s\r" "$timeout_index" "$timeout_str" "$timeout_index" "$timeout_black"
        sleep 0.1
        timeout_str=${timeout_str%?}
    done
}

judge_mode() {
    if [[ -f ${xray_bin_dir} ]]; then
        if [[ $(info_extraction '\"tls\"') == "TLS" ]]; then
            shell_mode="ws"
            shell_mode_show="Nginx+ws+tls"
        elif [[ $(info_extraction '\"tls\"') == "XTLS" ]]; then
            shell_mode="xtls"
            if [[ $(info_extraction '\"wsport\"') != "none" ]]; then
                xtls_add_ws="on"
                shell_mode_show="XTLS+Nginx+ws"
            else
                shell_mode_show="XTLS+Nginx"
            fi
        elif [[ $(info_extraction '\"tls\"') == "none" ]]; then
            shell_mode="wsonly"
            shell_mode_show="ws ONLY"
        fi
        old_shell_mode=${shell_mode}
    fi
}

install_xray_ws_tls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    create_directory
    domain_check
    old_config_exist_check
    port_set
    inbound_port_set
    firewall_set
    path_set
    UUID_set
    stop_service_all
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    xray_conf_add
    nginx_conf_add
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
    old_config_exist_check
    inbound_port_set
    firewall_set
    path_set
    UUID_set
    stop_service_all
    xray_install
    port_exist_check "${xport}"
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
    version_difference=$(echo "${newest_version:0:3}-${shell_version:0:3}"|bc)
    if [[ ${shell_version} != ${newest_version} ]]; then
        echo -e "${GreenBG} 存在新版本, 是否更新 [Y/N]? ${Font}"
        if [[ ${version_difference} -gt 0 ]]; then
            echo -e "${Warning} ${YellowBG} 版本跨度较大, 可能存在不兼容情况, 若服务无法正常运行请完全卸载重装! ${Font}"
        fi
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            [[ -L ${idleleo_commend_file} ]] && rm -f ${idleleo_commend_file}
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            clear
            echo -e "${OK} ${GreenBG} 更新完成 ${Font}"
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
        version_difference=$(echo "${shell_version:0:3}-${oldest_version:0:3}"|bc)
        if [[ -z ${old_version} ]]; then
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            clear
            bash idleleo
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            rm -rf ${idleleo_dir}/install.sh
            wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
            clear
            if [[ ${version_difference} -gt 0 ]]; then
                echo -e "${Warning} ${YellowBG} 脚本版本跨度较大, 可能存在不兼容情况, 若服务无法正常运行请完全卸载重装! ${Font}"
            fi
            bash idleleo
        elif [[ ! -L ${idleleo_commend_file} ]]; then
            ln -s ${idleleo_dir}/install.sh ${idleleo_commend_file}
            echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
        else
            echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
        fi
    else
        wget -N --no-check-certificate -P ${idleleo_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_dir}/install.sh
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
    echo -e "当前已安装模式: ${shell_mode_show}\n"

    idleleo_commend

    echo -e "—————————————— 升级向导 ——————————————"
    echo -e "${Green}0.${Font}  升级 脚本"
    echo -e "${Green}1.${Font}  升级 Xray"
    echo -e "${Green}2.${Font}  升级 Nginx"
    echo -e "—————————————— 安装向导 ——————————————"
    echo -e "${Green}3.${Font}  安装 Xray (Nginx+ws+tls)"
    echo -e "${Green}4.${Font}  安装 Xray (XTLS+Nginx)"
    echo -e "${Green}5.${Font}  安装 Xray (ws ONLY)"
    echo -e "—————————————— 配置变更 ——————————————"
    echo -e "${Green}6.${Font}  变更 UUIDv5/映射字符串"
    echo -e "${Green}7.${Font}  变更 port"
    echo -e "${Green}8.${Font}  变更 TLS 版本"
    echo -e "${Green}9.${Font}  追加 Nginx 负载均衡配置"
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
    echo -e "${Green}19.${Font} 安装 MTproxy (不推荐使用)"
    echo -e "${Green}20.${Font} 更新 证书 crontab 计划任务"
    echo -e "${Green}21.${Font} 证书 有效期更新"
    echo -e "${Green}22.${Font} 卸载 Xray"
    echo -e "${Green}23.${Font} 清空 证书文件"
    echo -e "${Green}24.${Font} 退出 \n"

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
        shell_mode="ws"
        install_xray_ws_tls
        bash idleleo
        ;;
    4)
        shell_mode="xtls"
        install_xray_xtls
        bash idleleo
        ;;
    5)
        echo -e "${Warning} ${YellowBG} 此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装 [Y/N]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="wsonly"
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
        read -rp "请输入连接端口/inbound_port:" port
        if [[ $(info_extraction '\"tls\"') == "TLS" ]]; then
            modify_nginx_port
        elif [[ $(info_extraction '\"tls\"') == "XTLS" ]]; then
            if [[ $(info_extraction '\"wsport\"') != "none" ]]; then
                read -rp "请输入 ws inbound_port:" xport
            fi
            modify_inbound_port
        else
            modify_inbound_port
        fi
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
        if [[ ${shell_mode} != "wsonly" ]]; then
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
        secure_ssh
        bash idleleo
        ;;
    19)
        clear
        mtproxy_sh
        ;;
    20)
        acme_cron_update
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    21)
        service_stop
        ssl_update_manuel
        service_restart
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    22)
        uninstall_all
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    23)
        delete_tls_key_and_crt
        rm -rf ${ssl_chainpath}/*
        timeout "清空屏幕!"
        clear
        bash idleleo
        ;;
    24)
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
