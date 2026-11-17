set -euo pipefail
OK=; GreenBG=; Font=; Green=; Error=; RedBG=; Warning=; YellowBG=; Red=
log_echo(){ :; }
gettext(){ printf '%s' "$1"; }
fm_display_width(){ printf '%s' "${#1}"; }
fm_restart_nginx_and_check_status(){ :; }
fm_list_files(){ if [ "${1:-}" = true ]; then files=("127.0.0.1.${fm_EXTENSION}"); fi; }
pkg_install(){ :; }
ID=ubuntu
QUEUE=(10.0.0.2 8443 60)
read_optimize(){ local _p="$1" _v="$2" _d="${3:-}"; local _n="${QUEUE[0]}"; QUEUE=("${QUEUE[@]:1}"); [ -z "$_n" ] && _n="$_d"; printf -v "$_v" '%s' "$_n"; }
fm_EXTENSION=realityServers
fm_create_server_file() {
    local default_port="$1"
    local host port weight content firewall_set_fq

    fm_list_files

    read_optimize "$(gettext "请输入主机") (host):" host

    if [[ "${host}" =~ [/\ \;\&\|\$\`] ]]; then
        log_echo "${Error} ${RedBG} $(gettext "主机地址包含非法字符")! ${Font}"
        return 1
    fi

    if [[ -n "$default_port" ]]; then
        read_optimize "$(gettext "请输入端口") (port $(gettext "默认值"): ${default_port}):" port "${default_port}" 1 65535
    else
        read_optimize "$(gettext "请输入端口") (port):" port "" 1 65535
    fi

    read_optimize "$(gettext "请输入权重") (0~100 $(gettext "默认值") 50):" weight "50" 0 100

    content="server ${host}:${port} weight=${weight} max_fails=2 fail_timeout=10;"
    echo "$content" > "${host}.${fm_EXTENSION}"
    log_echo "${OK} ${GreenBG} $(gettext "文件") ${host}.${fm_EXTENSION} $(gettext "已创建") ${Font}"

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
        iptables -I INPUT -p tcp --dport ${port} -j ACCEPT
        iptables -I INPUT -p udp --dport ${port} -j ACCEPT
        iptables -I OUTPUT -p tcp --sport ${port} -j ACCEPT
        iptables -I OUTPUT -p udp --sport ${port} -j ACCEPT
        log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "追加") $(gettext "完成") ${Font}"
        if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
            service iptables save
            service iptables restart
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") $(gettext "完成") ${Font}"
        else
            netfilter-persistent save
            netfilter-persistent reload
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") $(gettext "完成") ${Font}"
        fi
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "跳过防火墙设置") ${Font}"
        ;;
    esac
    fm_restart_nginx_and_check_status
    fm_list_files
}
printf "N\n" | fm_create_server_file ""
