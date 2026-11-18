set -euo pipefail
OK=; GreenBG=; Font=; Green=; Error=; RedBG=; Warning=; YellowBG=; Red=
log_echo(){ :; }
gettext(){ printf '%s' "$1"; }
judge(){ return 0; }
systemctl(){ :; }
read_optimize(){ local _v="$2"; printf -v "$_v" '%s' '2'; }
nginx_conf=/work/evidence/F10/f10-work/bash-tls/03-xray-https.conf
tls_mode=TLS
reality_add_nginx=off
nginx_systemd_file=/nonexistent/nginx.service
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
tls_type
