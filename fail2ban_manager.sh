#!/bin/bash

# 定义当前版本号
mf_SCRIPT_VERSION="1.0.9"

mf_main_menu() {
    check_system
  
    echo -e "\n"
    log_echo "${GreenBG} $(gettext "设置 Fail2ban 用于防止暴力破解, 请选择:") ${Font}"
    log_echo "1. ${Green}$(gettext "安装") Fail2ban${Font}"
    log_echo "2. ${Green}$(gettext "管理") Fail2ban${Font}"
    log_echo "3. ${Green}$(gettext "卸载") Fail2ban${Font}"
    log_echo "4. ${Green}$(gettext "查看") Fail2ban $(gettext "状态")${Font}"
    log_echo "5. ${Green}$(gettext "退出")${Font}"
    read -rp "$(gettext "请输入:")" fail2ban_fq
    [[ -z "${fail2ban_fq}" ]] && fail2ban_fq=1

    case $fail2ban_fq in
        1) mf_install_fail2ban ;;
        2) mf_manage_fail2ban ;;
        3) mf_uninstall_fail2ban ;;
        4) mf_display_fail2ban_status ;;
        5) source "${idleleo}" ;;
        *) 
            echo -e "\n"
            log_echo "${Error} ${RedBG} $(gettext "无效的选择 请重试") ${Font}"
            ;;
    esac
}

mf_install_fail2ban() {
    if command -v fail2ban-client &> /dev/null; then
        log_echo "${OK} ${Green} $(gettext "Fail2ban 已经安装, 跳过安装步骤") ${Font}"
    else
        pkg_install "fail2ban"
        mf_configure_fail2ban
        judge "Fail2ban $(gettext "安装")"
        source "${idleleo}"
    fi
}

mf_configure_fail2ban() {

    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        cp -fp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    # 检查 Nginx 是否安装
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "Nginx 未安装, 请先安装 Nginx") ${Font}"
            return
        fi
    fi

    if [[ -z $(grep "filter   = sshd" /etc/fail2ban/jail.local) ]]; then
        sed -i "/sshd_log/i \enabled  = true\\nfilter   = sshd\\nmaxretry = 5\\nbantime  = 604800" /etc/fail2ban/jail.local
    fi

    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        sed -i "/nginx_error_log/d" /etc/fail2ban/jail.local
        sed -i "s/http,https$/http,https,8080/g" /etc/fail2ban/jail.local
        sed -i "/^maxretry.*= 2$/c \\maxretry = 5" /etc/fail2ban/jail.local
        sed -i "/nginx-botsearch/i \[nginx-badbots]\\n\\nenabled  = true\\nport     = http,https,8080\\nfilter   = apache-badbots\\nlogpath  = ${nginx_dir}/logs/access.log\\nbantime  = 604800\\nmaxretry = 5\\n" /etc/fail2ban/jail.local
        sed -i "/nginx-botsearch/a \\\nenabled  = true\\nfilter   = nginx-botsearch\\nlogpath  = ${nginx_dir}/logs/access.log\\n           ${nginx_dir}/logs/error.log\\nbantime  = 604800" /etc/fail2ban/jail.local
    fi

    # 启用 nginx-no-host 规则
    if [[ ${reality_add_nginx} == "on" ]] && [[ -z $(grep "filter   = nginx-no-host" /etc/fail2ban/jail.local) ]]; then
        mf_create_nginx_no_host_filter
        sed -i "\$ a\\\n[nginx-no-host]\nenabled  = true\nfilter   = nginx-no-host\nlogpath  = $nginx_dir/logs/error.log\nbantime  = 604800\nmaxretry = 600" /etc/fail2ban/jail.local
    fi
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "配置")"
}

mf_create_nginx_no_host_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-no-host.conf"
    if [[ ! -f "$filter_file" ]]; then
        cat >"$filter_file" <<EOF
[Definition]
failregex = \[error\].*?no host in upstream.*?, client: <HOST>,
ignoreregex =
EOF
    fi
}

mf_manage_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "Fail2ban 未安装, 请先安装 Fail2ban") ${Font}"
        return
    fi

    echo -e "\n"
    log_echo "${Green} $(gettext "请选择 Fail2ban 操作:") ${Font}"
    echo "1. $(gettext "启动") Fail2ban"
    echo "2. $(gettext "重启") Fail2ban"
    echo "3. $(gettext "停止") Fail2ban"
    echo "4. $(gettext "添加自定义规则")"
    echo "5. $(gettext "返回")"
    read_optimize "$(gettext "请输入:")" mf_action 1
    case $mf_action in
        1)
            mf_start_enable_fail2ban
            ;;
        2)
            mf_restart_fail2ban
            mf_main_menu
            ;;
        3)
            mf_stop_disable_fail2ban
            ;;
        4)
            mf_add_custom_rule
            mf_main_menu
            ;;
        5) mf_main_menu ;;
        *)
            echo -e "\n"
            log_echo "${Error} ${RedBG} $(gettext "无效的选择 请重试") ${Font}"
            mf_manage_fail2ban
            ;;
    esac
}

mf_add_custom_rule() {
    local jail_name
    local filter_name
    local log_path
    local max_retry
    local ban_time

    read_optimize "$(gettext "请输入新的 Jail 名称:")" "jail_name" NULL
    read_optimize "$(gettext "请输入 Filter 名称:")" "filter_name" NULL
    read_optimize "$(gettext "请输入日志路径:")" "log_path" NULL
    read_optimize "$(gettext "请输入最大重试次数 (默认 5):")" "max_retry" 5 1 99 "$(gettext "最大重试次数必须在 1 到 99 之间")"
    read_optimize "$(gettext "请输入封禁时间 (秒, 默认 604800 秒):")" "ban_time" 604800 1 8640000 "$(gettext "封禁时间必须在 1 到 8640000 秒之间")"

    if grep -q "\[$jail_name\]" /etc/fail2ban/jail.local; then
        log_echo "${Warning} ${YellowBG} Jail '$jail_name' $(gettext "已存在") ${Font}"
        return
    fi

    echo -e "[$jail_name]\nenabled  = true\nfilter   = $filter_name\nlogpath  = $log_path\nmaxretry = $max_retry\nbantime  = $ban_time\n" >> /etc/fail2ban/jail.local
    log_echo "${OK} ${GreenBG} $(gettext "自定义规则添加成功") ${Font}"

    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "重启以应用新规则")"
}

mf_start_enable_fail2ban() {
    systemctl daemon-reload
    systemctl start fail2ban
    systemctl enable fail2ban
    judge "Fail2ban $(gettext "启动")"
    timeout "$(gettext "清空屏幕!")"
    clear
}

mf_uninstall_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    ${INS} -y remove fail2ban
    [[ -f "/etc/fail2ban/jail.local" ]] && rm -rf /etc/fail2ban/jail.local
    if [[ -f "/etc/fail2ban/filter.d/nginx-no-host.conf" ]]; then
        rm -rf /etc/fail2ban/filter.d/nginx-no-host.conf
    fi
    judge "Fail2ban $(gettext "卸载")"
    timeout "$(gettext "清空屏幕!")"
    clear
    source "${idleleo}"
}

mf_stop_disable_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    log_echo "${OK} ${GreenBG} $(gettext "Fail2ban 停止成功") ${Font}"
    timeout "$(gettext "清空屏幕!")"
    clear
}

mf_restart_fail2ban() {
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "重启")"
    timeout "$(gettext "清空屏幕!")"
    clear
}

mf_display_fail2ban_status() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "Fail2ban 未安装, 请先安装 Fail2ban") ${Font}"
        return
    fi

    log_echo "${GreenBG} $(gettext "Fail2ban 总体状态:") ${Font}"
    fail2ban-client status

    echo -e "\n"
    log_echo "${Green} $(gettext "默认启用的 Jail 状态:") ${Font}"
    echo "----------------------------------------"
    log_echo "${Green} $(gettext "SSH 封锁情况:") ${Font}"
    fail2ban-client status sshd
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        log_echo "${Green} $(gettext "Fail2ban Nginx 封锁情况:") ${Font}"
        fail2ban-client status nginx-badbots
        fail2ban-client status nginx-botsearch
        if [[ ${reality_add_nginx} == "on" ]]; then
            log_echo "${Green} $(gettext "Fail2ban Nginx No Host 封锁情况:") ${Font}"
            fail2ban-client status nginx-no-host
        fi
    fi
    mf_main_menu
}

mf_check_for_updates() {
    local latest_version
    local update_choice

    # 直接使用 curl 下载远程版本信息
    latest_version=$(curl -s "$mf_remote_url" | grep 'mf_SCRIPT_VERSION=' | head -n 1 | sed 's/mf_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$mf_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用:") $latest_version $(gettext "当前版本:") $mf_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问 https://github.com/hello-yunshu/Xray_bash_onekey 查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否要下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本...") ${Font}"
                curl -sL "$mf_remote_url" -o "${idleleo_dir}/fail2ban_manager.sh"

                if [ $? -eq 0 ]; then
                    chmod +x "${idleleo_dir}/fail2ban_manager.sh"
                    log_echo "${OK} ${Green} $(gettext "下载完成，正在重新运行脚本...") ${Font}"
                    bash "${idleleo}" --set-fail2ban
                else
                    echo -e "\n"
                    log_echo "${Error} ${RedBG} $(gettext "下载失败，请手动下载并安装新版本") ${Font}"
                fi
                ;;
            *)
                log_echo "${OK} ${Green} $(gettext "跳过更新") ${Font}"
                ;;
        esac
    else
        log_echo "${OK} ${Green} $(gettext "当前已经是最新版本:") $mf_SCRIPT_VERSION ${Font}"
    fi
}

# 检查更新
mf_check_for_updates

mf_main_menu