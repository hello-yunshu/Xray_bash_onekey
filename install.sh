#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
stty erase ^?

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	paniy
#	Dscription: Xray onekey Management
#	Version: 2.0
#	email:admin@idleleo.com
#	Official document: www.idleleo.com
#====================================================

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

# 版本
shell_version="1.4.5.6"
shell_mode="None"
shell_mode_show="未安装"
version_cmp="/tmp/version_cmp.tmp"
xray_conf_dir="/usr/local/etc/xray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
xray_conf="${xray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/xray.conf"
idleleo_xray_dir="/etc/idleleo"
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_xray_dir}/cert"
nginx_dir="/etc/nginx"
nginx_openssl_src="/usr/local/src"
xray_bin_dir="/usr/local/bin/xray"
xray_info_file="${idleleo_xray_dir}/info/xray_info.inf"
xray_qr_config_file="${idleleo_xray_dir}/info/vless_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_systemd_file2="/etc/systemd/system/xray@.service"
xray_systemd_filed="/etc/systemd/system/xray.service.d"
xray_systemd_filed2="/etc/systemd/system/xray@.service.d"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="${idleleo_xray_dir}/ssl_update.sh"
cert_group="nobody"
nginx_version="1.18.0"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"
old_config_status="off"
random_num=$((RANDOM % 12 + 4))
THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

source '/etc/os-release'

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    if [[ $(grep "nogroup" /etc/group) ]]; then
        cert_group="nogroup"
    fi

    $INS install dbus

    #systemctl stop firewalld
    #systemctl disable firewalld
    #echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"

    #systemctl stop ufw
    #systemctl disable ufw
    #echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败 ${Font}"
        exit 1
    fi
}

dependency_install() {
    ${INS} install wget git lsof -y

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

    #    ${INS} -y install rng-tools
    #    judge "rng-tools 安装"

    ${INS} -y install haveged
    #    judge "haveged 安装"

    #    sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    if [[ "${ID}" == "centos" ]]; then
        #       systemctl start rngd && systemctl enable rngd
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
    else
        #       systemctl start rng-tools && systemctl enable rng-tools
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
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

port_set() {
    if [[ "on" != "$old_config_status" ]]; then
        read -rp "请输入连接端口 (default:443):" port
        [[ -z ${port} ]] && port="443"
        if [[ $port -le 0 ]] || [[ $port -gt 65535 ]]; then
            echo -e "${Error} ${RedBG} 请输入 0-65535 之间的值 ${Font}"
            exit 1
        fi
    fi
}

firewall_set() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=1024-65535/udp
        firewall-cmd --permanent --add-port=${port}/tcp
        firewall-cmd --permanent --add-port=${port}/udp
        firewall-cmd --reload
    else
        ufw allow 80,443/tcp
        ufw allow 1024:65535/udp
        ufw allow ${port}
        ufw reload
    fi
    echo -e "${OK} ${GreenBG} 开放防火墙相关端口 ${Font}"
    echo -e "${OK} ${GreenBG} 配置Xray FullCone ${Font}"
}

path_set() {
    if [[ "on" == "$old_config_status" ]]; then
        camouflage="$(grep '\"path\"' $xray_qr_config_file | awk -F '"' '{print $4}')"
    else
        echo -e "${GreenBG} 是否需要自定义伪装路径 [Y/N]? ${Font}"
        read -r path_modify_fq
        case $path_modify_fq in
        [yY][eE][sS] | [yY])
            read -rp "请输入自定义伪装路径(不需要“/”):" camouflage
            camouflage="/${camouflage}"
            echo -e "${OK} ${GreenBG} 伪装路径为: ${camouflage} ${Font}"
            ;;
        *)
            camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            echo -e "${OK} ${GreenBG} 伪装路径为: ${camouflage} ${Font}"
            ;;
        esac
    fi
}

UUID_set() {
    if [[ "on" == "$old_config_status" ]]; then
        UUID="$(info_extraction '\"id\"')"
        UUID5_char="$(info_extraction '\"idc\"')"
    else
        echo -e "${GreenBG} 是否需要自定义字符串映射为UUIDv5 [Y/N]? ${Font}"
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
            echo -e "${OK} ${GreenBG} UUID映射字符串: ${UUID5_char} ${Font}"
            echo -e "${OK} ${GreenBG} UUIDv5: ${UUID} ${Font}"
            #[ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
            echo -e "${OK} ${GreenBG} UUID: ${UUID} ${Font}"
            ;;
        esac
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    echo "import uuid;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,'$1'));" | python3
}

stop_service() {
    systemctl stop nginx
    systemctl stop xray
    echo -e "${OK} ${GreenBG} 停止已有服务 ${Font}"
}

modify_alterid() {
    echo -e "${Warning} ${YellowBG} VLESS 不需要 alterid ${Font}"
}

modify_inbound_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    if [[ "$shell_mode" != "xtls" ]]; then
        PORT=$((RANDOM + 10000))
        #        sed -i "/\"port\"/c  \    \"port\":${PORT}," ${xray_conf}
        sed -i "8c\        \"port\":${PORT}," ${xray_conf}
    else
        #        sed -i "/\"port\"/c  \    \"port\":${port}," ${xray_conf}
        sed -i "8c\        \"port\":${port}," ${xray_conf}
    fi
    judge "Xray inbound_port 修改"
    echo -e "${OK} ${GreenBG} inbound_port: ${port} ${Font}"
}

modify_nginx_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    sed -i "/ssl http2;$/c \\\t\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "4c \\\t\\tlisten [::]:${port} ssl http2;" ${nginx_conf}
    judge "Xray port 修改"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} 端口号: ${port} ${Font}"
}

modify_nginx_other() {
    sed -i "/server_name/c \\\t\\tserver_name ${domain};" ${nginx_conf}
    if [[ "$shell_mode" != "xtls" ]]; then
        sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
        sed -i "/proxy_pass/c \\\t\\t\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    fi
    sed -i "/return/c \\\t\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
    sed -i "/returc/c \\\t\\t\\treturn 302 https://www.idleleo.com/helloworld;" ${nginx_conf}
    sed -i "/locatioc/c \\\t\\tlocation \/" ${nginx_conf}
    #sed -i "/#gzip  on;/c \\\t#gzip  on;\\n\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    #sed -i "/\\tserver_tokens off;\\n\\tserver_tokens off;/c \\\tserver_tokens off;" ${nginx_dir}/conf/nginx.conf
    sed -i "s/        server_name  localhost;/\t\tserver_name  localhost;\n\n\t\tif (\$host = '${local_ip}'){\n\t\t\treturn 302 https:\/\/www.idleleo.com\/helloworld;\n\t\t}\n/" ${nginx_dir}/conf/nginx.conf
    #sed -i "27i \\\tproxy_intercept_errors on;"  ${nginx_dir}/conf/nginx.conf
}

modify_path() {
    if [[ "$shell_mode" != "xtls" ]]; then
        sed -i "/\"path\"/c \                \"path\":\"${camouflage}\"" ${xray_conf}
    else
        echo -e "${Warning} ${YellowBG} XTLS 不支持 path ${Font}"
    fi
    judge "Xray 伪装路径 修改"
    echo -e "${OK} ${GreenBG} 伪装路径: ${camouflage} ${Font}"
}

modify_UUID() {
    sed -i "/\"id\"/c \                \"id\":\"${UUID}\"," ${xray_conf}
    judge "Xray UUID 修改"
    [ -f ${xray_qr_config_file} ] && sed -i "/\"id\"/c \\  \"id\": \"${UUID}\"," ${xray_qr_config_file}
    [ -f ${xray_qr_config_file} ] && sed -i "/\"idc\"/c \\  \"idc\": \"${UUID5_char}\"," ${xray_qr_config_file}
    echo -e "${OK} ${GreenBG} UUIDv5: ${UUID} ${Font}"
}

web_camouflage() {
    ##请注意 这里和LNMP脚本的默认路径冲突，千万不要在安装了LNMP的环境下使用本脚本，否则后果自负
    #rm -rf /home/wwwroot
    #mkdir -p /home/wwwroot
    #cd /home/wwwroot || exit
    #git clone https://github.com/wulabing/3DCEList.git
    judge "web 站点伪装"
}

xray_privilege_escalation() {
    if [[ -n "$(grep "User=nobody" ${xray_systemd_file})" ]]; then
        #echo -e "${OK} ${GreenBG} 检测到Xray权限不足，将提高Xray权限至root ${Font}"
        echo -e "${OK} ${GreenBG} 检测到Xray的权限控制，启动擦屁股程序 ${Font}"
        systemctl stop xray
        #sed -i "s/User=nobody/User=root/" ${xray_systemd_file}
        chmod -fR a+rw /var/log/xray/
        chown -fR nobody:${cert_group} /var/log/xray/
        chown -R nobody:${cert_group} ${ssl_chainpath}/*
        systemctl daemon-reload
        systemctl start xray
        sleep 1
    fi
}

xray_install() {
    if [[ -d /root/xray ]]; then
        rm -rf /root/xray
    fi
    if [[ -d /usr/local/etc/xray ]]; then
        rm -rf /usr/local/etc/xray
    fi
    if [[ -d /usr/local/share/xray ]]; then
        rm -rf /usr/local/share/xray
    fi
    mkdir -p /root/xray
    cd /root/xray || exit
    wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh

    ## wget http://install.direct/go.sh

    ##if [[ -f install-release.sh ]] && [[ -f install-dat-release.sh ]]; then
    if [[ -f install-release.sh ]]; then
        rm -rf ${xray_systemd_file}
        rm -rf ${xray_systemd_file2}
        rm -rf ${xray_systemd_filed}
        rm -rf ${xray_systemd_filed2}
        systemctl daemon-reload
        bash install-release.sh --force
        #bash install-dat-release.sh --force
        judge "安装 Xray"
        sleep 1
        xray_privilege_escalation
    else
        echo -e "${Error} ${RedBG} Xray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        exit 4
    fi
    # 清除临时文件
    rm -rf /root/xray
}

xray_update() {
    #mkdir -p /root/xray
    #cd /root/xray || exit
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh
    #wget -N --no-check-certificate https://raw.githubusercontent.com/XTLS/Xray-install/main/install-dat-release.sh
    if [[ -d /usr/local/etc/xray ]]; then
        #echo -e "${OK} ${GreenBG} 恢复xray原权限 ${Font}"
        systemctl stop xray
        #sed -i "s/User=root/User=nobody/" ${xray_systemd_file}
        #systemctl daemon-reload
        #systemctl start xray
        sleep 1
        bash <(curl -L -s https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)
        sleep 1
        xray_privilege_escalation
    else
        echo -e "${GreenBG} 若更新无效，建议直接卸载再安装！ ${Font}"
        systemctl stop xray
        #systemctl disable xray.service --now
        #mv -f /etc/xray/ /usr/local/etc/
        #rm -rf /usr/bin/xray/
        #rm -rf /etc/systemd/system/xray.service
        #rm -rf /lib/systemd/system/xray@.service
        #rm -rf /etc/init.d/xray
        #systemctl daemon-reload
        sleep 1
        bash <(curl -L -s https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)
        sleep 1
        xray_privilege_escalation
    fi
    # 清除临时文件
    ##rm -rf /root/xray
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        if [[ -d ${nginx_dir}/conf/conf.d ]]; then
            rm -rf ${nginx_dir}/conf/conf.d/*
        else
            mkdir ${nginx_dir}/conf/conf.d
        fi
        echo -e "${OK} ${GreenBG} Nginx已存在，跳过编译安装过程 ${Font}"
        sleep 2
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${OK} ${GreenBG} 检测到其他套件安装的Nginx，继续安装会造成冲突，请处理后安装 ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    #    if [[ -d "/etc/nginx" ]];then
    #        rm -rf /etc/nginx
    #    fi

    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Nginx 下载"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "openssl 下载"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "jemalloc 下载"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 jemalloc ${Font}"
    sleep 2

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "编译检查"
    make -j "${THREAD}" && make install
    judge "jemalloc 编译安装"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx, 过程稍久，请耐心等待 ${Font}"
    sleep 4

    cd ../nginx-${nginx_version} || exit

    #增加http_sub_module用于反向代理替换关键词
    ./configure --prefix="${nginx_dir}" \
    --with-http_ssl_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-pcre \
    --with-http_realip_module \
    --with-http_flv_module \
    --with-http_mp4_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-cc-opt='-O3' \
    --with-ld-opt="-ljemalloc" \
    --with-openssl=../openssl-"$openssl_version"
    judge "编译检查"
    make -j "${THREAD}" && make install
    judge "Nginx 编译安装"

    # 修改基本配置
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  4;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # 删除临时文件
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # 添加配置文件夹，适配旧版脚本
    mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}

domain_check() {
    read -rp "请输入你的域名信息(eg:www.idleleo.com):" domain
    echo "请选择 公网IP 为 IPv4 或 IPv6"
    echo "1: IPv4 (默认)"
    echo "2: IPv6 (不推荐)"
    read -rp "请输入: " ip_version
    [[ -z ${ip_version} ]] && ip_version=1
    echo -e "${OK} ${GreenBG} 正在获取 公网IP 信息，请耐心等待 ${Font}"
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
    echo -e "域名dns解析IP: ${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ ${local_ip} == ${domain_ip} ]]; then
        echo -e "${OK} ${GreenBG} 域名dns解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
        echo -e "${Error} ${RedBG} 请确保域名添加了正确的 A/AAAA 记录，否则将无法正常使用 Xray ${Font}"
        echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装 [Y/N]? ${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} 继续安装 ${Font}"
            sleep 2
            ;;
        *)
            echo -e "${Error} ${RedBG} 安装终止 ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}

acme() {
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${OK} ${GreenBG} SSL 证书测试签发成功，开始正式签发 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        sleep 2
    else
        echo -e "${Error} ${RedBG} SSL 证书测试签发失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        sleep 2
        mkdir -p ${ssl_chainpath}
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc --force; then
            chmod -f a+rw ${ssl_chainpath}/xray.crt
            chmod -f a+rw ${ssl_chainpath}/xray.key
            chown -R nobody:${cert_group} ${ssl_chainpath}/*
            echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
            sleep 2
        fi
    else
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add_tls() {
    cd ${xray_conf_dir} || exit
    wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_tls/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}

xray_conf_add_xtls() {
    cd ${xray_conf_dir} || exit
    wget --no-check-certificate https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/VLESS_xtls/config.json -O config.json
    modify_path
    modify_alterid
    modify_inbound_port
    modify_UUID
}

old_config_exist_check() {
    if [[ -f $xray_qr_config_file ]]; then
        echo -e "${GreenBG} 检测到旧配置文件，是否读取旧文件配置 [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            echo -e "${OK} ${GreenBG} 已保留旧配置  ${Font}"
            old_config_status="on"
            port=$(info_extraction '\"port\"')
            ;;
        *)
            rm -rf $xray_qr_config_file
            echo -e "${OK} ${GreenBG} 已删除旧配置  ${Font}"
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
        #root  /home/wwwroot/3DCEList;
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
            proxy_redirect off;
            proxy_pass http://127.0.0.1:10000;
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

start_process_systemd() {
    systemctl daemon-reload
    systemctl restart nginx
    judge "Nginx 启动"
    systemctl restart xray
    judge "Xray 启动"
}

enable_process_systemd() {
    systemctl enable xray
    judge "设置 xray 开机自启"
    systemctl enable nginx
    judge "设置 Nginx 开机自启"
}

stop_process_systemd() {
    if [[ "$shell_mode" != "xtls" ]]; then
        systemctl stop nginx
    fi
    systemctl stop xray
}
nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

acme_cron_update() {
    wget -N -P /etc/idleleo --no-check-certificate "https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/ssl_update.sh"
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

vless_qr_config_tls_ws() {
    mkdir -p ${idleleo_xray_dir}/info
    cat >$xray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "${domain}",
  "add": "${domain}",
  "port": "${port}",
  "idc": "${UUID5_char}",
  "id": "${UUID}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vless_qr_config_xtls() {
    mkdir -p ${idleleo_xray_dir}/info
    cat >$xray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "${domain}",
  "add": "${domain}",
  "port": "${port}",
  "idc": "${UUID5_char}",
  "id": "${UUID}",
  "net": "tcp",
  "type": "none",
  "host": "${domain}",
  "tls": "XTLS"
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
    if [[ "$shell_mode" != "xtls" ]]; then
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"add\"')):$(info_extraction '\"port\"')?path=$(vless_urlquote $(info_extraction '\"path\"'))?ed=2048&security=tls&encryption=none&host=$(vless_urlquote $(info_extraction '\"add\"'))&type=ws#$(vless_urlquote $(info_extraction '\"add\"'))+ws%E5%8D%8F%E8%AE%AE"
    else
        vless_link="vless://$(info_extraction '\"id\"')@$(vless_urlquote $(info_extraction '\"add\"')):$(info_extraction '\"port\"')?security=xtls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#$(vless_urlquote $(info_extraction '\"add\"'))+xtls%E5%8D%8F%E8%AE%AE"
    fi
        {
            echo -e "\n${Red} —————————————— Xray 配置分享 —————————————— ${Font}"
            echo -e "${Red} URL分享链接: ${vless_link} ${Font}"
            echo -e "$Red 二维码: $Font"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo -e "\n"
        } >>"${xray_info_file}"
}

vless_link_image_choice() {
    echo "请选择生成的分享链接种类:"
    echo "1: V2RayN/V2RayNG/Qv2ray"
    read -rp "请输入: " link_version
    [[ -z ${link_version} ]] && link_version=1
    if [[ $link_version == 1 ]]; then
        vless_qr_link_image
    else
        vless_qr_link_image
    fi
    echo -e "${Warning} ${YellowBG} VLESS 目前分享链接规范为实验阶段，请自行判断是否适用 ${Font}"
}

info_extraction() {
    grep "$1" $xray_qr_config_file | awk -F '"' '{print $4}'
}

basic_information() {
    {
        if [[ "$shell_mode" != "xtls" ]]; then
            echo -e "${OK} ${GreenBG} Xray+Nginx+ws+tls 安装成功 ${Font}"
        else
            echo -e "${OK} ${GreenBG} Xray+XTLS+Nginx 安装成功 ${Font}"
        fi
        echo -e "${Warning} ${YellowBG} VLESS 目前分享链接规范为实验阶段，请自行判断是否适用 ${Font}"
        echo -e "\n${Red} —————————————— Xray 配置信息 —————————————— ${Font}"
        echo -e "${Red} 地址 (address):${Font} $(info_extraction '\"add\"') "
        echo -e "${Red} 端口 (port):${Font} $(info_extraction '\"port\"') "
        echo -e "${Red} UUIDv5 映射字符串:${Font} $(info_extraction '\"idc\"')"
        echo -e "${Red} 用户id (UUID):${Font} $(info_extraction '\"id\"')"

        echo -e "${Red} 加密 (encryption):${Font} none "
        echo -e "${Red} 传输协议 (network):${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} 伪装类型 (type):${Font} none "
        if [[ "$shell_mode" != "xtls" ]]; then
            echo -e "${Red} 路径 (不要落下/):${Font} $(info_extraction '\"path\"') "
            echo -e "${Red} 底层传输安全 (tls):${Font} tls "
        else
            echo -e "${Red} 流控 (flow):${Font} xtls-rprx-direct "
            echo -e "${Red} 底层传输安全 (tls):${Font} XTLS "
        fi
    } >"${xray_info_file}"
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    if [[ -f "${ssl_chainpath}/xray.key" || -f "${ssl_chainpath}/xray.crt" ]]; then
        echo "证书文件已存在"
        echo -e "${GreenBG} 是否删除 [Y/N]? ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            delete_tls_key_and_crt
            rm -rf ${ssl_chainpath}/*
            echo -e "${OK} ${GreenBG} 已删除 ${Font}"
            ;;
        *) ;;

        esac
    fi

    if [[ -f "${ssl_chainpath}/xray.key" || -f "${ssl_chainpath}/xray.crt" ]]; then
        echo "证书文件已存在"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "证书文件已存在"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
        judge "证书应用"
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
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; then
        echo "请选择支持的 TLS 版本 (default:2):"
        echo "建议选择 TLS1.2 and TLS1.3 (兼容模式)"
        echo "1: TLS1.1 TLS1.2 and TLS1.3 (兼容模式)"
        echo "2: TLS1.2 and TLS1.3 (兼容模式)"
        echo "3: TLS1.3 only"
        read -rp "请输入: " tls_version
        [[ -z ${tls_version} ]] && tls_version=2
        if [[ $tls_version == 3 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Nginx 重启"
    else
        echo -e "${Error} ${RedBG} Nginx 或 配置文件不存在 或当前安装版本为 xtls ，请正确安装脚本后执行${Font}"
    fi
}

show_access_log() {
    [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${Error} ${RedBG} log文件不存在 ${Font}"
}

show_error_log() {
    [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${Error} ${RedBG} log文件不存在 ${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${Error} ${RedBG} 证书签发工具不存在，请确认你是否使用了自己的证书 ${Font}"
    domain="$(info_extraction '\"add\"')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
}

bbr_boost_sh() {
    if [[ -f "${idleleo_xray_dir}/tcp.sh" ]]; then 
        chmod +x ${idleleo_xray_dir}/tcp.sh && ${idleleo_xray_dir}/tcp.sh
    else    
        wget -N --no-check-certificate -P ${idleleo_xray_dir} "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x ${idleleo_xray_dir}/tcp.sh && ${idleleo_xray_dir}/tcp.sh
    fi
}

mtproxy_sh() {
    wget -N --no-check-certificate "https://github.com/whunt1/onekeymakemtg/raw/master/mtproxy_go.sh" && chmod +x mtproxy_go.sh && bash mtproxy_go.sh
}

uninstall_all() {
    stop_process_systemd
    systemctl disable xray
    [[ -f $nginx_systemd_file ]] && rm -rf $nginx_systemd_file
    [[ -f $xray_systemd_file ]] && rm -rf $xray_systemd_file
    [[ -f $xray_systemd_file2 ]] && rm -rf $xray_systemd_file2
    [[ -d $xray_systemd_filed ]] && rm -rf $xray_systemd_filed
    [[ -d $xray_systemd_filed2 ]] && rm -rf $xray_systemd_filed2
    [[ -f $xray_bin_dir ]] && rm -rf $xray_bin_dir
    if [[ -d $nginx_dir ]]; then
        echo -e "${Green} 是否卸载 Nginx [Y/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf $nginx_dir
            echo -e "${OK} ${Green} 已卸载 Nginx ${Font}"
            ;;
        *) ;;

        esac
    fi
    [[ -d $xray_conf_dir ]] && rm -rf $xray_conf_dir
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} 已卸载，SSL证书文件已保留 ${Font}"
}

delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG} 已清空证书遗留文件 ${Font}"
}

judge_mode() {
    if [ -f $xray_bin_dir ]; then
        if grep -q "ws" $xray_qr_config_file; then
            shell_mode="ws"
            shell_mode_show="Nginx+ws+tls"
        elif grep -q "XTLS" $xray_qr_config_file; then
            shell_mode="xtls"
            shell_mode_show="XTLS+Nginx"
        fi
    fi
}

install_xray_ws_tls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_set
    firewall_set
    path_set
    UUID_set
    stop_service
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    xray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    tls_type
    vless_qr_config_tls_ws
    basic_information
    vless_link_image_choice
    show_information
    start_process_systemd
    enable_process_systemd
    acme_cron_update
}

install_v2_xtls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_set
    firewall_set
    UUID_set
    stop_service
    xray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    nginx_conf_add_xtls
    xray_conf_add_xtls
    ssl_judge_and_install
    nginx_systemd
    vless_qr_config_xtls
    basic_information
    vless_link_image_choice
    show_information
    start_process_systemd
    enable_process_systemd
    acme_cron_update
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${GreenBG} 存在新版本，是否更新 [Y/N]? ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            rm -f ${idleleo_commend_file}
            wget -N --no-check-certificate -P ${idleleo_xray_dir} https://raw.githubusercontent.com/paniy/Xray_bash_onekey/main/install.sh && chmod +x ${idleleo_xray_dir}/install.sh
            ln -s ${idleleo_xray_dir}/install.sh ${idleleo_commend_file}
            echo -e "${OK} ${GreenBG} 更新完成 ${Font}"
            exit 0
            ;;
        *) ;;

        esac
    else
        echo -e "${OK} ${GreenBG} 当前版本为最新版本 ${Font}"
    fi

}

maintain() {
    echo -e "${Error} ${RedBG} 该选项暂时无法使用 ${Font}"
    echo -e "${Error} ${RedBG} $1 ${Font}"
    exit 0
}

list() {
    case $1 in
    tls_modify)
        tls_type
        ;;
    uninstall)
        uninstall_all
        ;;
    crontab_modify)
        acme_cron_update
        ;;
    boost)
        bbr_boost_sh
        ;;
    *)
        menu
        ;;
    esac
}

idleleo_commend() {
    if [ -L "${idleleo_commend_file}" ]; then
        echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
    else
        if [ -L "/usr/bin/idleleo-xray" ]; then
            rm -rf /usr/bin/idleleo-xray
        fi
        ln -s $(
            cd "$(dirname "$0")"
            pwd
        )/install.sh ${idleleo_commend_file}
        echo -e "${Green}可以使用${Red} idleleo ${Font}命令管理脚本\n${Font}"
    fi
}

menu() {
    update_sh
    echo -e "\nXray 安装管理脚本 ${Red}[${shell_version}]${Font}"
    echo -e "--- authored by paniy ---"
    echo -e "--- changed by www.idleleo.com ---"
    echo -e "--- https://github.com/paniy ---\n"
    echo -e "当前已安装版本: ${shell_mode_show}\n"

    idleleo_commend

    echo -e "—————————————— 安装向导 ——————————————"
    echo -e "${Green}0.${Font}  升级 脚本"
    echo -e "${Green}1.${Font}  安装 Xray (Nginx+ws+tls)"
    echo -e "${Green}2.${Font}  安装 Xray (XTLS+Nginx)"
    echo -e "${Green}3.${Font}  升级 Xray"
    echo -e "—————————————— 配置变更 ——————————————"
    echo -e "${Green}4.${Font}  变更 UUIDv5/映射字符串"
    echo -e "${Green}5.${Font}  变更 alterid"
    echo -e "${Green}6.${Font}  变更 port"
    echo -e "${Green}7.${Font}  变更 TLS 版本 (仅ws+tls有效)"
    echo -e "—————————————— 查看信息 ——————————————"
    echo -e "${Green}8.${Font}  查看 实时访问日志"
    echo -e "${Green}9.${Font}  查看 实时错误日志"
    echo -e "${Green}10.${Font} 查看 Xray 配置信息"
    echo -e "—————————————— 其他选项 ——————————————"
    echo -e "${Green}11.${Font} 安装 TCP 加速脚本"
    echo -e "${Green}12.${Font} 安装 MTproxy (不推荐使用)"
    echo -e "${Green}13.${Font} 证书 有效期更新"
    echo -e "${Green}14.${Font} 卸载 Xray"
    echo -e "${Green}15.${Font} 更新 证书crontab计划任务"
    echo -e "${Green}16.${Font} 清空 证书遗留文件"
    echo -e "${Green}17.${Font} 退出 \n"

    read -rp "请输入数字: " menu_num
    case $menu_num in
    0)
        bash idleleo
        ;;
    1)
        shell_mode="ws"
        install_xray_ws_tls
        bash idleleo
        ;;
    2)
        shell_mode="xtls"
        install_v2_xtls
        bash idleleo
        ;;
    3)
        xray_update
        bash idleleo
        ;;
    4)
        UUID_set
        modify_UUID
        start_process_systemd
        bash idleleo
        ;;
    5)
        modify_alterid
        bash idleleo
        ;;
    6)
        read -rp "请输入连接端口:" port
        if grep -q "ws" $xray_qr_config_file; then
            modify_nginx_port
            firewall_set
        elif grep -q "xtls" $xray_qr_config_file; then
            modify_inbound_port
            firewall_set
        fi
        start_process_systemd
        bash idleleo
        ;;
    7)
        tls_type
        bash idleleo
        ;;
    8)
        show_access_log
        bash idleleo
        ;;
    9)
        show_error_log
        bash idleleo
        ;;
    10)
        basic_information
        vless_qr_link_image
        show_information
        bash idleleo
        ;;
    11)
        bbr_boost_sh
        bash idleleo
        ;;
    12)
        mtproxy_sh
        bash idleleo
        ;;
    13)
        stop_process_systemd
        ssl_update_manuel
        start_process_systemd
        bash idleleo
        ;;
    14)
        uninstall_all
        bash idleleo
        ;;
    15)
        acme_cron_update
        bash idleleo
        ;;
    16)
        delete_tls_key_and_crt
        bash idleleo
        ;;
    17)
        exit 0
        ;;
    *)
        echo -e "${Error} ${RedBG} 请输入正确的数字 ${Font}"
        bash idleleo
        ;;
    esac
}

judge_mode
list "$1"
