#!/bin/bash

# 定义当前版本号
mf_SCRIPT_VERSION="1.2.0"

mf_main_menu() {
    check_system
    while true; do
        echo
        log_echo "${GreenBG} $(gettext "设置") Fail2ban $(gettext "用于防止暴力破解") ${Font}"
        log_echo "${Green} $(gettext "主菜单") ${Font}"
        log_echo "1. ${Green}$(gettext "安装") Fail2ban${Font}"
        log_echo "2. ${Green}$(gettext "管理") Fail2ban${Font}"
        log_echo "3. ${Green}$(gettext "卸载") Fail2ban${Font}"
        log_echo "4. ${Green}$(gettext "查看") Fail2ban $(gettext "状态")${Font}"
        log_echo "5. ${Green}$(gettext "退出")${Font}"
        local fail2ban_fq
        read_optimize "$(gettext "请选择一个选项"):" fail2ban_fq "" 1
        case $fail2ban_fq in
            1) mf_install_fail2ban ;;
            2) mf_manage_fail2ban ;;
            3) mf_uninstall_fail2ban ;;
            4) mf_display_fail2ban_status ;;
            5) source "${idleleo}" ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done    
}

mf_install_fail2ban() {
    if command -v fail2ban-client &> /dev/null; then
        log_echo "${OK} ${Green} Fail2ban $(gettext "已经安装, 跳过安装步骤") ${Font}"
    else
        pkg_install "fail2ban"
        mf_configure_fail2ban
        judge "Fail2ban $(gettext "安装")"
        source "${idleleo}"
    fi
}

mf_ensure_sshd_config() {
    cat > /etc/fail2ban/jail.d/sshd.local << 'EOF'
[sshd]
enabled = true
filter = sshd
logpath = %(sshd_log)s
backend = systemd
maxretry = 5
bantime = 604800
EOF
}

mf_configure_fail2ban() {

    # 确保 jail.d 目录存在
    mkdir -p /etc/fail2ban/jail.d

    # 如果 jail.local 不存在，创建它
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        cp -fp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    # systemd SSH 日志检查
    if ! journalctl -u ssh --since "1 hour ago" --no-pager -q | head -n 1 >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "systemd 无法读取 SSH 日志") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "跳过启用") SSH $(gettext "规则") ${Font}"
    else
        mf_ensure_sshd_config
    fi

    # 检查 Nginx 是否安装
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
            log_echo "${Warning} ${YellowBG} Nginx $(gettext "未安装, 请先安装") Nginx ${Font}"
            return
        fi
    fi

    # 配置 Nginx 相关规则
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        cat > /etc/fail2ban/jail.d/nginx-badbots.local << EOF
[nginx-badbots]
enabled  = true
port     = http,https,8080
filter   = apache-badbots
logpath  = ${nginx_dir}/logs/access.log
bantime  = 604800
maxretry = 5
EOF
        log_echo "${OK} ${GreenBG} $(gettext "已启用") nginx-badbots $(gettext "规则") ${Font}"

        cat > /etc/fail2ban/jail.d/nginx-botsearch.local << EOF
[nginx-botsearch]
enabled  = true
filter   = nginx-botsearch
logpath  = ${nginx_dir}/logs/access.log
           ${nginx_dir}/logs/error.log
bantime  = 604800
EOF
        log_echo "${OK} ${GreenBG} $(gettext "已启用") nginx-botsearch $(gettext "规则") ${Font}"
    fi

    # 启用 nginx-no-host 规则
    if [[ ${reality_add_nginx} == "on" ]]; then
        if [[ ! -f "/etc/fail2ban/jail.d/nginx-no-host.local" ]]; then
            mf_create_nginx_no_host_filter
            cat > /etc/fail2ban/jail.d/nginx-no-host.local << EOF
[nginx-no-host]
enabled  = true
filter   = nginx-no-host
logpath  = ${nginx_dir}/logs/sni_error.log
bantime  = 604800
maxretry = 5
findtime = 120
EOF
            
            log_echo "${GreenBG} $(gettext "是否启用") nginx-no-host $(gettext "规则")? [${Red}Y${Font}${GreenBG}/N] ${Font}"
            read -r enable_nginx_no_host
            case $enable_nginx_no_host in
                [nN][oO] | [nN])
                    sed -i "s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.d/nginx-no-host.local
                    log_echo "${OK} ${GreenBG} $(gettext "已禁用") nginx-no-host $(gettext "规则") ${Font}"
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "已启用") nginx-no-host $(gettext "规则") ${Font}"
                    ;;
            esac
        fi

        # 启用 nginx-tls-error 规则
        if [[ ! -f "/etc/fail2ban/jail.d/nginx-tls-error.local" ]]; then
            mf_create_nginx_tls_error_filter
            cat > /etc/fail2ban/jail.d/nginx-tls-error.local << EOF
[nginx-tls-error]
enabled  = true
filter   = nginx-tls-error
logpath  = ${nginx_dir}/logs/tls_error.log
bantime  = 43200
maxretry = 8
findtime = 300
EOF
            
            log_echo "${GreenBG} $(gettext "是否启用") nginx-tls-error $(gettext "规则")? [${Red}Y${Font}${GreenBG}/N] ${Font}"
            read -r enable_nginx_tls_error
            case $enable_nginx_tls_error in
                [nN][oO] | [nN])
                    sed -i "s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.d/nginx-tls-error.local
                    log_echo "${OK} ${GreenBG} $(gettext "已禁用") nginx-tls-error $(gettext "规则") ${Font}"
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "已启用") nginx-tls-error $(gettext "规则") ${Font}"
                    ;;
            esac
        fi
    fi
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "配置")"
}

mf_create_nginx_no_host_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-no-host.conf"
    if [[ ! -f "$filter_file" ]]; then
        cat >"$filter_file" <<'EOF'
[Definition]
datepattern = ^%%d/%%b/%%Y:%%H:%%M:%%S %%z$
failregex = ^<HOST> \[.*\] ".*".*\d+$
ignoreregex =
EOF
    fi
}

mf_create_nginx_tls_error_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-tls-error.conf"
    if [[ ! -f "$filter_file" ]]; then
        cat >"$filter_file" <<'EOF'
[Definition]
datepattern = ^%%d/%%b/%%Y:%%H:%%M:%%S %%z$
failregex = ^<HOST> \[.*\] ".*".*\d+$
ignoreregex =
EOF
    fi
}

# 检查模块是否启用
mf_is_module_enabled() {
    local module_file="$1"
    local default_status="${2:-true}"
    
    if [[ ! -f "$module_file" ]]; then
        return 1
    fi
    
    local enabled_status=$(grep -oP 'enabled\s*=\s*\K\w+' "$module_file" 2>/dev/null || echo "$default_status")
    [[ "$enabled_status" == "true" ]]
}

mf_manage_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban $(gettext "未安装, 请先安装") Fail2ban ${Font}"
        return
    fi

    while true; do
        echo
        log_echo "${Green} $(gettext "请选择") Fail2ban $(gettext "操作"): ${Font}"
        echo "1. $(gettext "管理模块")"
        echo "2. $(gettext "添加自定义规则")"
        echo "3. $(gettext "服务管理")"
        echo "4. $(gettext "返回")"
        local mf_action
        read_optimize "$(gettext "请输入"):" mf_action 1
        case $mf_action in
        1)
            mf_manage_modules
            ;;
        2)
            mf_add_custom_rule
            mf_main_menu
            ;;
        3)
            # 服务管理子菜单
            while true; do
                echo
                log_echo "${Green} $(gettext "服务管理"): ${Font}"
                echo "1. $(gettext "启动") Fail2ban"
                echo "2. $(gettext "停止") Fail2ban"
                echo "3. $(gettext "重启") Fail2ban"
                echo "4. $(gettext "返回")"
                local service_action
                read_optimize "$(gettext "请输入"):" service_action 1
                case $service_action in
                1)
                    mf_start_enable_fail2ban
                    ;;
                2)
                    mf_stop_disable_fail2ban
                    ;;
                3)
                    mf_restart_fail2ban
                    ;;
                4)
                    break
                    ;;
                *)
                    echo
                    log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                    ;;
                esac
            done
            ;;
        4) mf_main_menu ;;
        *)
            echo
            log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
            ;;
        esac
    done
}

mf_add_custom_rule() {
    local jail_name
    local filter_name
    local log_path
    local max_retry
    local ban_time

    read_optimize "$(gettext "请输入新的") Jail $(gettext "名称"):" "jail_name" NULL
    read_optimize "$(gettext "请输入") Filter $(gettext "名称"):" "filter_name" NULL
    read_optimize "$(gettext "请输入日志路径"):" "log_path" NULL
    read_optimize "$(gettext "请输入最大重试次数") ($(gettext "默认") 5):" "max_retry" 5 1 99 "$(gettext "最大重试次数必须在 1 到 99 之间")"
    read_optimize "$(gettext "请输入封禁时间") ($(gettext "秒"), $(gettext "默认") 604800):" "ban_time" 604800 1 8640000 "$(gettext "封禁时间必须在 1 到 8640000 秒之间")"

    cat > "/etc/fail2ban/jail.d/${jail_name}.local" << EOF
[$jail_name]
enabled  = true
filter   = $filter_name
logpath  = $log_path
maxretry = $max_retry
bantime  = $ban_time
EOF
    log_echo "${OK} ${GreenBG} $(gettext "自定义规则添加成功") ${Font}"

    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "重启以应用新规则")"
}

mf_manage_modules() {
    echo
    log_echo "${Green} $(gettext "管理 Fail2ban 模块") ${Font}"
    
    # 列出所有模块化配置文件
    local module_files=()
    local module_names=()
    local index=1
    
    # 查找所有 .local 文件
    for file in /etc/fail2ban/jail.d/*.local; do
        if [[ -f "$file" ]]; then
            module_files[$index]="$file"
            module_names[$index]=$(basename "$file" .local)
            index=$((index + 1))
        fi
    done
    
    if [[ ${#module_files[@]} -eq 0 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "未找到任何模块化配置文件") ${Font}"
        return
    fi
    
    # 计算列宽
    local max_name_length=15

    local compare_strings=()
    compare_strings+=("$(gettext "模块名称")")
    
    for ((i=1; i<${#module_files[@]}+1; i++)); do
        compare_strings+=("${module_names[$i]}")
    done
    
    compare_strings+=("$(gettext "返回")")
    
    for str in "${compare_strings[@]}"; do
        local length=${#str}
        if (( length > max_name_length )); then
            max_name_length=$length
        fi
    done
    
    # 计算总宽度
    local total_width=$((max_name_length + 20))
    
    # 打印表头
    printf "%s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
    printf "| %-4s | %-${max_name_length}s | %-10s |\n" "$(gettext "序号")" "$(gettext "模块名称")" "$(gettext "状态")"
    printf "%s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
    
    for ((i=1; i<${#module_files[@]}+1; i++)); do
        local module_file=${module_files[$i]}
        local module_name=${module_names[$i]}
        
        if mf_is_module_enabled "$module_file"; then
            local status_text="$(gettext "已启用")"
        else
            local status_text="$(gettext "已禁用")"
        fi
        
        printf "| %4d | %-${max_name_length}s | %-10s |\n" $i "$module_name" "$status_text"
    done
    
    # 打印表尾
    printf "%s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
    printf "| %4d | %-${max_name_length}s | %-10s |\n" 0 "$(gettext "返回")" ""
    printf "%s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"

    
    # 让用户选择要管理的模块
    local module_choice
    read_optimize "$(gettext "请选择要管理的模块"): " "module_choice" 0 0 ${#module_files[@]} "$(gettext "无效的选择, 请重试")"
    
    if [[ $module_choice -eq 0 ]]; then
        return
    fi
    
    local selected_file=${module_files[$module_choice]}
    local selected_name=${module_names[$module_choice]}
    
    # 获取当前状态
    local current_status=$(grep -oP 'enabled\s*=\s*\K\w+' "$selected_file" 2>/dev/null || echo "true")
    local new_status=$([[ "$current_status" == "true" ]] && echo "false" || echo "true")
    local status_text=$([[ "$new_status" == "true" ]] && echo "$(gettext "启用")" || echo "$(gettext "禁用")")
    
    # 确认操作
    log_echo "${GreenBG} $(gettext "是否") $status_text $selected_name $(gettext "模块") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r confirm
    
    if [[ ! $confirm =~ ^[nN][oO]|[nN]$ ]]; then
        sed -i "s/enabled\s*=\s*\w*/enabled = $new_status/" "$selected_file"

        mf_restart_fail2ban
        
        log_echo "${OK} ${GreenBG} $selected_name $(gettext "模块") $status_text ${Font}"
    else
        log_echo "${Green} $(gettext "操作已取消") ${Font}"
    fi
    
    mf_manage_modules
}

mf_start_enable_fail2ban() {
    systemctl daemon-reload
    systemctl start fail2ban
    systemctl enable fail2ban
    judge "Fail2ban $(gettext "启动")"
    # timeout "$(gettext "清空屏幕")!"
    # clear
}

mf_uninstall_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    ${INS} -y remove fail2ban
    [[ -f "/etc/fail2ban/jail.local" ]] && rm -rf /etc/fail2ban/jail.local
    rm -rf /etc/fail2ban/jail.d/*.local
    if [[ -f "/etc/fail2ban/filter.d/nginx-no-host.conf" ]]; then
        rm -rf /etc/fail2ban/filter.d/nginx-no-host.conf
    fi
    if [[ -f "/etc/fail2ban/filter.d/nginx-tls-error.conf" ]]; then
        rm -rf /etc/fail2ban/filter.d/nginx-tls-error.conf
    fi
    judge "Fail2ban $(gettext "卸载")"
    timeout "$(gettext "清空屏幕")!"
    clear
    source "${idleleo}"
}

mf_stop_disable_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    log_echo "${OK} ${GreenBG} Fail2ban $(gettext "停止成功") ${Font}"
    # timeout "$(gettext "清空屏幕")!"
    # clear
}

mf_restart_fail2ban() {
    systemctl daemon-reload
    systemctl restart fail2ban
    judge "Fail2ban $(gettext "重启")"
    # timeout "$(gettext "清空屏幕")!"
    # clear
}

mf_display_fail2ban_status() {
    echo
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban $(gettext "未安装, 请先安装") Fail2ban ${Font}"
        return
    fi

    log_echo "${GreenBG} Fail2ban $(gettext "总体状态"): ${Font}"
    fail2ban-client status

    echo
    log_echo "${Green} $(gettext "默认启用的 Jail 状态"): ${Font}"
    echo "----------------------------------------"
    
    if mf_is_module_enabled "/etc/fail2ban/jail.d/sshd.local"; then
        log_echo "${Green} SSH $(gettext "封锁情况"): ${Font}"
        fail2ban-client status sshd 2>/dev/null || log_echo "${Warning} ${YellowBG} SSH Jail $(gettext "未启用或配置异常") ${Font}"
    fi

    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if mf_is_module_enabled "/etc/fail2ban/jail.d/nginx-badbots.local"; then
            log_echo "${Green} Fail2ban Nginx $(gettext "封锁情况"): ${Font}"
            fail2ban-client status nginx-badbots 2>/dev/null || log_echo "${Warning} ${YellowBG} nginx-badbots $(gettext "未启用或配置异常") ${Font}"
        fi
        if mf_is_module_enabled "/etc/fail2ban/jail.d/nginx-botsearch.local"; then
            fail2ban-client status nginx-botsearch 2>/dev/null || log_echo "${Warning} ${YellowBG} nginx-botsearch $(gettext "未启用或配置异常") ${Font}"
        fi
        if [[ ${reality_add_nginx} == "on" ]]; then
            if mf_is_module_enabled "/etc/fail2ban/jail.d/nginx-no-host.local"; then
                fail2ban-client status nginx-no-host 2>/dev/null || log_echo "${Warning} ${YellowBG} nginx-no-host $(gettext "未启用或配置异常") ${Font}"
            fi
            if mf_is_module_enabled "/etc/fail2ban/jail.d/nginx-tls-error.local"; then
                fail2ban-client status nginx-tls-error 2>/dev/null || log_echo "${Warning} ${YellowBG} nginx-tls-error $(gettext "未启用或配置异常") ${Font}"
            fi
        fi
    fi
    echo
    mf_main_menu
}

mf_check_for_updates() {
    local latest_version
    local update_choice

    # 直接使用 curl 下载远程版本信息
    latest_version=$(curl -s "$mf_remote_url" | grep 'mf_SCRIPT_VERSION=' | head -n 1 | sed 's/mf_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$mf_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用"): $latest_version $(gettext "当前版本"): $mf_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问") https://github.com/hello-yunshu/Xray_bash_onekey $(gettext "查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本")... ${Font}"
                curl -sL "$mf_remote_url" -o "${idleleo_dir}/fail2ban_manager.sh"

                if [ $? -eq 0 ]; then
                    chmod +x "${idleleo_dir}/fail2ban_manager.sh"
                    log_echo "${OK} ${GreenBG} $(gettext "下载完成, 请重新运行脚本") ${Font}"
                    bash "${idleleo}"
                else
                    echo
                    log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
                fi
                ;;
            *)
                log_echo "${Green} $(gettext "跳过更新") ${Font}"
                ;;
        esac
    else
        log_echo "${OK} ${Green} $(gettext "当前已经是最新版本"): $mf_SCRIPT_VERSION ${Font}"
    fi
}

# 检查更新
mf_check_for_updates

mf_main_menu
