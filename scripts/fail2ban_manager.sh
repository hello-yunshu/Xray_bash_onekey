#!/bin/bash

# 定义当前版本号
mf_SCRIPT_VERSION="1.6.0"
MIN_MAIN_VERSION="2.12.10"

if [ -n "$shell_version" ]; then
    oldest=$(printf '%s\n%s\n' "$MIN_MAIN_VERSION" "$shell_version" | sort -V | head -1)
    if [ "$oldest" != "$MIN_MAIN_VERSION" ]; then
        echo "${Error} ${RedBG} fail2ban_manager.sh $(gettext "需要主脚本版本") >= ${MIN_MAIN_VERSION}, $(gettext "当前版本"): ${shell_version}, $(gettext "请先更新主脚本") ${Font}"
        return 1
    fi
fi

mf_display_width() {
    local str="$1"
    local lang="zh_CN"
    if [[ -z "${idleleo_dir:-}" || -f "${idleleo_dir}/language.conf" ]]; then
        lang="${LC_MESSAGES:-${LANG:-zh_CN}}"
    fi
    lang="${lang%%.*}"
    lang="${lang%%@*}"

    if [[ "$lang" != "zh_CN" && "$lang" != "ko_KR" ]]; then
        echo "${#str}"
        return
    fi

    local width=0 i=0 char code
    while (( i < ${#str} )); do
        char="${str:i:1}"
        printf -v code '%d' "'$char" 2>/dev/null || code=0
        (( code < 0 || code > 127 )) && width=$((width + 2)) || width=$((width + 1))
        i=$((i + 1))
    done
    echo "$width"
}

mf_pad() {
    local str="$1"
    local target_width="$2"
    local width
    width=$(mf_display_width "$str")
    local padding=$((target_width - width))
    if (( padding > 0 )); then
        printf '%s%*s' "$str" "$padding" ""
    else
        printf '%s' "$str"
    fi
}

mf_table_line() {
    local width="$1"
    printf '%*s\n' "$width" "" | tr ' ' '-'
}

mf_main_menu() {
    check_system
    while true; do
        echo
        echo -e "${GreenBG} $(gettext "设置") Fail2ban $(gettext "用于防止暴力破解") ${Font}"
        echo -e "${Green} $(gettext "主菜单") ${Font}"
        echo -e "${Green}1.${Font} $(gettext "安装") Fail2ban"
        echo -e "${Green}2.${Font} $(gettext "管理") Fail2ban"
        echo -e "${Green}3.${Font} $(gettext "卸载") Fail2ban"
        echo -e "${Green}4.${Font} $(gettext "查看") Fail2ban $(gettext "状态")"
        echo -e "${Green}5.${Font} $(gettext "退出")"
        local fail2ban_fq
        read_optimize "$(gettext "请选择一个选项"):" fail2ban_fq "" 1
        case $fail2ban_fq in
            1) mf_install_fail2ban ;;
            2) mf_manage_fail2ban ;;
            3) mf_uninstall_fail2ban ;;
            4) mf_display_fail2ban_status ;;
            5) return ;;
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
        mf_configure_fail2ban
        judge -r "Fail2ban $(gettext "配置")"
    else
        pkg_install "fail2ban"
        judge -r "Fail2ban $(gettext "安装")" || return 1
        mf_configure_fail2ban
        judge -r "Fail2ban $(gettext "配置")"
        return
    fi
}

mf_ensure_restart_policy() {
    local override_dir="/etc/systemd/system/fail2ban.service.d"
    local override_file="${override_dir}/restart-policy.conf"
    if [[ ! -f "$override_file" ]]; then
        mkdir -p "$override_dir"
        cat > "$override_file" << 'EOF'
[Unit]
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=10
EOF
        systemctl daemon-reload
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

    # Task G: Enable incremental banning globally.
    # This makes repeat offenders get progressively longer bans without
    # relaxing the base bantime/maxretry/findtime of any jail.
    # Fail2ban >= 0.10 supports bantime.increment.
    # On older versions these keys are silently ignored (no error).
    mf_ensure_incremental_ban

    # systemd SSH 日志检查
    local _ssh_unit=""
    if systemctl -q is-active ssh 2>/dev/null; then
        _ssh_unit="ssh"
    elif systemctl -q is-active sshd 2>/dev/null; then
        _ssh_unit="sshd"
    fi
    if [[ -z "${_ssh_unit}" ]] || ! journalctl -u "${_ssh_unit}" --since "1 hour ago" --no-pager -q | head -n 1 >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "systemd 无法读取 SSH 日志") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "跳过启用") SSH $(gettext "规则") ${Font}"
    else
        mf_ensure_sshd_config
    fi

    # 检查 Nginx 是否安装
    local nginx_available=true
    if [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
            log_echo "${Warning} ${YellowBG} Nginx $(gettext "未安装"), $(gettext "请先安装") Nginx ${Font}"
            nginx_available=false
        fi
    fi

    # 配置 Nginx 相关规则
    if [[ ${nginx_available} == "true" ]] && [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
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
    if [[ ${nginx_available} == "true" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        mf_create_nginx_no_host_filter
        if [[ ! -f "/etc/fail2ban/jail.d/nginx-no-host.local" ]]; then
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
        mf_create_nginx_tls_error_filter
        if [[ ! -f "/etc/fail2ban/jail.d/nginx-tls-error.local" ]]; then
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
    mf_regex_self_check
    mf_ensure_restart_policy
    systemctl daemon-reload
    systemctl enable fail2ban
    systemctl restart fail2ban
    judge -r "Fail2ban $(gettext "配置")"
}

mf_create_nginx_no_host_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-no-host.conf"
    # 始终覆盖以保证 failregex 与 Nginx log_format 一致（修复旧版 datepattern 锚点 bug）
    cat >"$filter_file" <<'EOF'
[Definition]
datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z
failregex = ^<HOST> \[[^\]]*\] "[^"]*" \S* \d+$
ignoreregex =
EOF
}

mf_create_nginx_tls_error_filter() {
    local filter_file="/etc/fail2ban/filter.d/nginx-tls-error.conf"
    cat >"$filter_file" <<'EOF'
[Definition]
datepattern = %%d/%%b/%%Y:%%H:%%M:%%S %%z
failregex = ^<HOST> \[[^\]]*\] "[^"]*" \S* \d+$
ignoreregex =
EOF
}

# fail2ban-regex 自检：日志非空时校验 failregex 是否能匹配，日志为空时仅提示不中断
mf_regex_self_check() {
    [[ ${reality_add_nginx} != "on" ]] && return 0
    command -v fail2ban-regex >/dev/null 2>&1 || return 0
    local _jail _log _filter
    local -A _jail_log=(
        [nginx-no-host]="${nginx_dir}/logs/sni_error.log"
        [nginx-tls-error]="${nginx_dir}/logs/tls_error.log"
    )
    for _jail in "${!_jail_log[@]}"; do
        _log="${_jail_log[${_jail}]}"
        _filter="/etc/fail2ban/filter.d/${_jail}.conf"
        [[ -f "${_filter}" ]] || continue
        if [[ -s "${_log}" ]]; then
            if ! fail2ban-regex "${_log}" "${_filter}" >/dev/null 2>&1; then
                log_echo "${Warning} ${YellowBG} ${_jail} $(gettext "regex 自检未通过, 请检查日志格式") ${Font}"
            else
                log_echo "${OK} ${GreenBG} ${_jail} $(gettext "regex 自检通过") ${Font}"
            fi
        else
            log_echo "${Warning} ${YellowBG} ${_log##*/} $(gettext "为空或不存在, 跳过自检") ${Font}"
        fi
    done
    return 0
}

# 检查模块是否启用
mf_is_module_enabled() {
    local module_file="$1"
    local default_status="${2:-true}"

    if [[ ! -f "$module_file" ]]; then
        return 1
    fi

    local enabled_status=$(grep -oP 'enabled\s*=\s*\K\w+' "$module_file" 2>/dev/null)
    if [[ -z "$enabled_status" ]]; then
        [[ "$default_status" == "true" ]] && return 0 || return 1
    fi
    [[ "$enabled_status" == "true" ]]
}

# Task G: Enable incremental banning with safe defaults.
# Written to jail.d/zzz-idleleo-incremental.local so it loads last
# and applies to all jails. Fail2ban < 0.10 silently ignores these keys.
mf_ensure_incremental_ban() {
    local inc_file="${FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}/zzz-idleleo-incremental.local"
    cat > "$inc_file" << 'EOF'
# Idleleo incremental ban policy (Task G)
# Repeat offenders get progressively longer bans.
# Base bantime/maxretry/findtime per jail are NOT relaxed.
[DEFAULT]
bantime.increment = true
bantime.multipliers = 1 2 4 8 16 32 64
bantime.maxtime = 180d
bantime.rndtime = 10m
bantime.overalljails = false
EOF
}

# Task G: Validate an IP address (IPv4 or IPv6).
# Uses Python ipaddress module for strict validation when available.
# Returns 0 if valid, 1 otherwise.
# Rejects: ::::, 999.1.1.1, empty strings, malformed addresses.
mf_validate_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1

    # Python is an installer dependency. Fail closed instead of falling back
    # to a weaker parser when it is unexpectedly unavailable.
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
    sys.exit(0)
except ValueError:
    sys.exit(1)
" "$ip" 2>/dev/null
}

# Task G: Validate a CIDR (IP/prefix).
# Uses Python ipaddress module for strict validation when available.
# Returns 0 if valid, 1 otherwise.
# IPv4 prefix must be 0-32, IPv6 prefix must be 0-128.
# Rejects: 1.2.3.4/100, ::::/64, 999.1.1.1/24
mf_validate_cidr() {
    local cidr="$1"
    [[ -z "$cidr" ]] && return 1

    local ip prefix
    ip="${cidr%/*}"
    prefix="${cidr#*/}"

    # If no prefix, it's just an IP
    if [[ "$ip" == "$cidr" ]]; then
        mf_validate_ip "$cidr"
        return $?
    fi

    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c "
import ipaddress, sys
try:
    ipaddress.ip_network(sys.argv[1], strict=False)
    sys.exit(0)
except ValueError:
    sys.exit(1)
" "$cidr" 2>/dev/null
}

# Task G: Get list of active jails from fail2ban-client.
mf_get_active_jails() {
    fail2ban-client status 2>/dev/null \
        | grep "Jail list:" \
        | sed 's/.*Jail list:[[:space:]]*//' \
        | tr ',' '\n' \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
        | grep -v '^$'
}

mf_jail_is_active() {
    local jail="$1"
    [[ "${jail}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
    mf_get_active_jails | grep -Fqx -- "${jail}"
}

# Task G: View banned IPs for a specific jail.
mf_view_banned_ips() {
    local jail="$1"
    [[ -z "$jail" ]] && return 1

    if ! fail2ban-client status "$jail" 2>/dev/null; then
        log_echo "${Error} ${RedBG} Jail '${jail}' $(gettext "不存在或未激活") ${Font}"
        return 1
    fi
}

# Task G: Quick unban an IP from a jail.
# Uses fail2ban-client set <jail> unbanip <ip> (real command, not shell injection).
mf_quick_unban() {
    local jail="$1"
    local ip="$2"

    if [[ -z "$jail" || -z "$ip" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "jail 和 IP 不能为空") ${Font}"
        return 1
    fi

    # Validate jail name (strict allowlist: only active jails)
    if ! mf_jail_is_active "$jail"; then
        log_echo "${Error} ${RedBG} $(gettext "jail 不在允许列表中"): ${jail} ${Font}"
        return 1
    fi

    # Validate IP (supports IPv4 and IPv6, no CIDR for unban)
    if ! mf_validate_ip "$ip"; then
        log_echo "${Error} ${RedBG} $(gettext "IP 地址格式无效"): ${ip} ${Font}"
        return 1
    fi

    # Check if IP is actually banned before attempting unban
    local banned_list
    banned_list=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:\s*//')
    if ! echo "$banned_list" | grep -qw -- "$ip"; then
        log_echo "${Warning} ${YellowBG} ${ip} $(gettext "未在") ${jail} $(gettext "的封禁列表中") ${Font}"
        return 0
    fi

    # Execute real unban command
    if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
        log_echo "${OK} ${GreenBG} ${ip} $(gettext "已从") ${jail} $(gettext "解封") ${Font}"
        # Verify unban succeeded
        local verify_list
        verify_list=$(fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list:\s*//')
        if echo "$verify_list" | grep -qw -- "$ip"; then
            log_echo "${Warning} ${YellowBG} ${ip} $(gettext "解封后仍在封禁列表中, 请检查") ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} ${ip} $(gettext "解封失败") ${Font}"
        return 1
    fi
}

# Task G: Add a trusted IP/CIDR to a jail's ignoreip.
# Uses fail2ban-client set <jail> addignoreip <ip-or-cidr>.
# Also persists to the jail's .local config file.
mf_add_trust_ip() {
    local jail="$1"
    local cidr="$2"

    if [[ -z "$jail" || -z "$cidr" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "jail 和 IP/CIDR 不能为空") ${Font}"
        return 1
    fi

    # Validate jail name
    if ! mf_jail_is_active "$jail"; then
        log_echo "${Error} ${RedBG} $(gettext "jail 不在允许列表中"): ${jail} ${Font}"
        return 1
    fi

    # Validate CIDR (supports IPv4, IPv6, and CIDR notation)
    if ! mf_validate_cidr "$cidr"; then
        log_echo "${Error} ${RedBG} $(gettext "IP/CIDR 格式无效"): ${cidr} ${Font}"
        return 1
    fi

    # Execute real addignoreip command
    if fail2ban-client set "$jail" addignoreip "$cidr" 2>/dev/null; then
        log_echo "${OK} ${GreenBG} ${cidr} $(gettext "已添加到") ${jail} $(gettext "可信名单 (运行态)") ${Font}"
        # Persist to .local config file so it survives restart
        if mf_persist_ignoreip "$jail" "$cidr" add; then
            log_echo "${OK} ${GreenBG} ${cidr} $(gettext "持久化成功") ${Font}"
        else
            # P0-C: Runtime modification succeeded but persistence failed.
            # Must explicitly tell user, not show as fully successful.
            log_echo "${Warning} ${YellowBG} $(gettext "运行态修改成功, 但持久化失败") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "重启 Fail2ban 后该可信 IP 可能丢失, 请手动检查配置文件") ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} ${cidr} $(gettext "添加可信名单失败") ${Font}"
        return 1
    fi
}

# Task G: Remove a trusted IP/CIDR from a jail's ignoreip.
# Uses fail2ban-client set <jail> delignoreip <ip-or-cidr>.
# Also removes from the jail's .local config file.
mf_remove_trust_ip() {
    local jail="$1"
    local cidr="$2"

    if [[ -z "$jail" || -z "$cidr" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "jail 和 IP/CIDR 不能为空") ${Font}"
        return 1
    fi

    # Validate jail name
    if ! mf_jail_is_active "$jail"; then
        log_echo "${Error} ${RedBG} $(gettext "jail 不在允许列表中"): ${jail} ${Font}"
        return 1
    fi

    # Validate CIDR
    if ! mf_validate_cidr "$cidr"; then
        log_echo "${Error} ${RedBG} $(gettext "IP/CIDR 格式无效"): ${cidr} ${Font}"
        return 1
    fi

    # Execute real delignoreip command
    if fail2ban-client set "$jail" delignoreip "$cidr" 2>/dev/null; then
        log_echo "${OK} ${GreenBG} ${cidr} $(gettext "已从") ${jail} $(gettext "可信名单移除 (运行态)") ${Font}"
        # Persist removal to .local config file
        if mf_persist_ignoreip "$jail" "$cidr" del; then
            log_echo "${OK} ${GreenBG} ${cidr} $(gettext "持久化移除成功") ${Font}"
        else
            # P0-C: Runtime modification succeeded but persistence failed.
            # Must explicitly tell user, not show as fully successful.
            log_echo "${Warning} ${YellowBG} $(gettext "运行态修改成功, 但持久化失败") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "重启 Fail2ban 后该可信 IP 可能仍在, 请手动检查配置文件") ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} ${cidr} $(gettext "移除可信名单失败") ${Font}"
        return 1
    fi
}

# Task G: Persist ignoreip changes to the jail's .local config file.
# This ensures trusted IPs survive a fail2ban restart.
# Args: jail, cidr, action (add|del)
# Returns 0 on success, 1 on failure (original file preserved).
# P0-C: Uses temp file, atomic replace, config validation, and preserves owner/group/mode.
mf_validate_candidate_config() {
    local candidate_file="$1"
    local config_file="$2"
    local jail_dir="${FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}"
    local config_root="${FAIL2BAN_CONFIG_DIR:-$(dirname "${jail_dir}")}"
    local validation_root
    validation_root=$(mktemp -d) || return 1

    if [[ -d "${config_root}" ]]; then
        cp -a "${config_root}/." "${validation_root}/" 2>/dev/null || {
            rm -rf "${validation_root}"
            return 1
        }
    fi
    mkdir -p "${validation_root}/$(basename "${jail_dir}")"
    if ! cp "${candidate_file}" "${validation_root}/$(basename "${jail_dir}")/$(basename "${config_file}")"; then
        rm -rf "${validation_root}"
        return 1
    fi

    if ! fail2ban-client -c "${validation_root}" -t >/dev/null 2>&1; then
        rm -rf "${validation_root}"
        return 1
    fi
    rm -rf "${validation_root}"
    return 0
}

mf_stat_value() {
    local format="$1"
    local file="$2"
    if stat -c "${format}" "${file}" 2>/dev/null; then
        return 0
    fi
    case "${format}" in
        %u) stat -f '%u' "${file}" 2>/dev/null ;;
        %g) stat -f '%g' "${file}" 2>/dev/null ;;
        %a) stat -f '%Lp' "${file}" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

mf_persist_ignoreip() {
    local jail="$1"
    local cidr="$2"
    local action="$3"
    local jail_dir="${FAIL2BAN_JAIL_D:-/etc/fail2ban/jail.d}"
    local config_file="${jail_dir}/${jail}.local"
    local _tmp_file _backup_file=""
    local _orig_uid _orig_gid _orig_mode=644
    _orig_uid=$(id -u)
    _orig_gid=$(id -g)

    [[ "${action}" == "add" || "${action}" == "del" ]] || return 1
    mkdir -p "${jail_dir}" || return 1
    if [[ "${action}" == "del" && ! -f "${config_file}" ]]; then
        return 0
    fi

    if [[ -f "${config_file}" ]]; then
        _orig_uid=$(mf_stat_value '%u' "${config_file}") || return 1
        _orig_gid=$(mf_stat_value '%g' "${config_file}") || return 1
        _orig_mode=$(mf_stat_value '%a' "${config_file}") || return 1
    fi

    _tmp_file=$(mktemp "${config_file}.tmp.XXXXXX") || return 1
    if [[ ! -f "${config_file}" ]]; then
        cat > "${_tmp_file}" << EOF
[${jail}]
enabled = true
ignoreip = ${cidr}
EOF
    else
        cp -p "${config_file}" "${_tmp_file}" || {
            rm -f "${_tmp_file}"
            return 1
        }
        local existing_line
        existing_line=$(grep "^[[:space:]]*ignoreip[[:space:]]*=" "${_tmp_file}" 2>/dev/null)
        if [[ "${action}" == "add" && -z "${existing_line}" ]]; then
            # Add new ignoreip line
            echo "ignoreip = ${cidr}" >> "${_tmp_file}"
        elif [[ "${action}" == "add" ]] && printf '%s\n' "${existing_line#*=}" | tr ' ' '\n' | grep -Fqx -- "${cidr}"; then
            # Already exists, skip (no change needed)
            rm -f "${_tmp_file}"
            return 0
        elif [[ "${action}" == "add" ]]; then
            # Append to existing ignoreip line
            sed -i "s|^[[:space:]]*ignoreip\\(.*\\)|ignoreip\\1 ${cidr}|" "${_tmp_file}"
        elif [[ "${action}" == "del" && -n "${existing_line}" ]]; then
            local filtered_file="${_tmp_file}.filtered"
            awk -v needle="${cidr}" '
                /^[[:space:]]*ignoreip[[:space:]]*=/ {
                    split($0, pair, "=")
                    count = split(pair[2], values, /[[:space:]]+/)
                    output = ""
                    for (i = 1; i <= count; i++) {
                        if (values[i] != "" && values[i] != needle) {
                            output = output " " values[i]
                        }
                    }
                    if (output != "") print "ignoreip =" output
                    next
                }
                { print }
            ' "${_tmp_file}" > "${filtered_file}" || {
                rm -f "${_tmp_file}" "${filtered_file}"
                return 1
            }
            mv "${filtered_file}" "${_tmp_file}" || {
                rm -f "${_tmp_file}" "${filtered_file}"
                return 1
            }
        fi
    fi

    # Validate the candidate in an isolated copy of the real config tree.
    if ! mf_validate_candidate_config "${_tmp_file}" "${config_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "配置验证失败, 保留原配置") ${Font}"
        rm -f "${_tmp_file}"
        return 1
    fi

    if ! chown "${_orig_uid}:${_orig_gid}" "${_tmp_file}" 2>/dev/null ||
       ! chmod "${_orig_mode}" "${_tmp_file}" 2>/dev/null; then
        rm -f "${_tmp_file}"
        return 1
    fi

    if [[ -f "${config_file}" ]]; then
        _backup_file="${config_file}.backup.$$"
        cp -p "${config_file}" "${_backup_file}" || {
            rm -f "${_tmp_file}"
            return 1
        }
    fi

    # Same-directory rename is atomic.
    if ! mv "${_tmp_file}" "${config_file}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "原子替换失败, 保留原配置") ${Font}"
        rm -f "${_tmp_file}" "${_backup_file}"
        return 1
    fi

    if ! fail2ban-client reload >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Fail2ban reload 失败, 恢复原配置") ${Font}"
        if [[ -n "${_backup_file}" && -f "${_backup_file}" ]]; then
            if cp -p "${_backup_file}" "${config_file}"; then
                rm -f "${_backup_file}"
            else
                log_echo "${Error} ${RedBG} $(gettext "原配置自动恢复失败, 备份保留于"): ${_backup_file} ${Font}"
            fi
        else
            rm -f "${config_file}" ||
                log_echo "${Error} ${RedBG} $(gettext "新配置清理失败"): ${config_file} ${Font}"
        fi
        fail2ban-client reload >/dev/null 2>&1 || true
        return 1
    fi

    rm -f "${_backup_file}"
    return 0
}

mf_manage_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban $(gettext "未安装"), $(gettext "请先安装") Fail2ban ${Font}"
        return
    fi

    while true; do
        echo
        echo -e "${Green} $(gettext "请选择") Fail2ban $(gettext "操作"): ${Font}"
        echo "1. $(gettext "管理模块")"
        echo "2. $(gettext "查看已封禁 IP")"
        echo "3. $(gettext "快速解封 IP")"
        echo "4. $(gettext "添加可信 IP/CIDR")"
        echo "5. $(gettext "移除可信 IP/CIDR")"
        echo "6. $(gettext "添加自定义规则")"
        echo "7. $(gettext "服务与配置检查")"
        echo "8. $(gettext "返回")"
        local mf_action
        read_optimize "$(gettext "请输入"):" mf_action 1
        case $mf_action in
        1)
            mf_manage_modules
            ;;
        2)
            mf_menu_view_banned_ips
            ;;
        3)
            mf_menu_quick_unban
            ;;
        4)
            mf_menu_add_trust_ip
            ;;
        5)
            mf_menu_remove_trust_ip
            ;;
        6)
            mf_add_custom_rule
            ;;
        7)
            mf_service_and_config_check
            ;;
        8) return ;;
        *)
            echo
            log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
            ;;
        esac
    done
}

# P0-C: Menu helper for viewing banned IPs.
# Lists active jails, lets user select one, then shows its banned IP list.
mf_menu_view_banned_ips() {
    local active_jails
    active_jails=$(mf_get_active_jails)
    if [[ -z "$active_jails" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "没有活跃的 Jail") ${Font}"
        return
    fi

    echo
    echo -e "${Green} $(gettext "活跃的 Jail 列表"): ${Font}"
    local jail_list=()
    local index=1
    while IFS= read -r jail; do
        [[ -n "$jail" ]] || continue
        jail_list[$index]="$jail"
        echo "${Green}${index}.${Font} ${jail}"
        index=$((index + 1))
    done <<< "$active_jails"
    echo "${Green}0.${Font} $(gettext "返回")"

    local jail_choice
    read_optimize "$(gettext "请选择要查看的 Jail"):" jail_choice 0 0 ${#jail_list[@]} "$(gettext "无效的选择, 请重试")"
    [[ $jail_choice -eq 0 ]] && return

    local selected_jail="${jail_list[$jail_choice]}"
    echo
    log_echo "${GreenBG} ${selected_jail} $(gettext "封禁列表"): ${Font}"
    mf_view_banned_ips "$selected_jail"
}

# P0-C: Menu helper for quick unbanning an IP.
# Lists active jails, lets user select one, then prompts for IP to unban.
mf_menu_quick_unban() {
    local active_jails
    active_jails=$(mf_get_active_jails)
    if [[ -z "$active_jails" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "没有活跃的 Jail") ${Font}"
        return
    fi

    echo
    echo -e "${Green} $(gettext "活跃的 Jail 列表"): ${Font}"
    local jail_list=()
    local index=1
    while IFS= read -r jail; do
        [[ -n "$jail" ]] || continue
        jail_list[$index]="$jail"
        echo "${Green}${index}.${Font} ${jail}"
        index=$((index + 1))
    done <<< "$active_jails"
    echo "${Green}0.${Font} $(gettext "返回")"

    local jail_choice
    read_optimize "$(gettext "请选择要解封的 Jail"):" jail_choice 0 0 ${#jail_list[@]} "$(gettext "无效的选择, 请重试")"
    [[ $jail_choice -eq 0 ]] && return

    local selected_jail="${jail_list[$jail_choice]}"
    local unban_ip
    read_optimize "$(gettext "请输入要解封的 IP 地址 (仅支持单个 IP, 不支持 CIDR)"):" unban_ip NULL
    if [[ -z "$unban_ip" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "IP 地址不能为空") ${Font}"
        return
    fi
    mf_quick_unban "$selected_jail" "$unban_ip"
}

# P0-C: Menu helper for adding a trusted IP/CIDR.
mf_menu_add_trust_ip() {
    local active_jails
    active_jails=$(mf_get_active_jails)
    if [[ -z "$active_jails" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "没有活跃的 Jail") ${Font}"
        return
    fi

    echo
    echo -e "${Green} $(gettext "活跃的 Jail 列表"): ${Font}"
    local jail_list=()
    local index=1
    while IFS= read -r jail; do
        [[ -n "$jail" ]] || continue
        jail_list[$index]="$jail"
        echo "${Green}${index}.${Font} ${jail}"
        index=$((index + 1))
    done <<< "$active_jails"
    echo "${Green}0.${Font} $(gettext "返回")"

    local jail_choice
    read_optimize "$(gettext "请选择要添加可信 IP 的 Jail"):" jail_choice 0 0 ${#jail_list[@]} "$(gettext "无效的选择, 请重试")"
    [[ $jail_choice -eq 0 ]] && return

    local selected_jail="${jail_list[$jail_choice]}"
    local trust_cidr
    read_optimize "$(gettext "请输入要添加的 IP/CIDR (支持 IPv4/IPv6/CIDR)"):" trust_cidr NULL
    if [[ -z "$trust_cidr" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "IP/CIDR 不能为空") ${Font}"
        return
    fi
    mf_add_trust_ip "$selected_jail" "$trust_cidr"
}

# P0-C: Menu helper for removing a trusted IP/CIDR.
mf_menu_remove_trust_ip() {
    local active_jails
    active_jails=$(mf_get_active_jails)
    if [[ -z "$active_jails" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "没有活跃的 Jail") ${Font}"
        return
    fi

    echo
    echo -e "${Green} $(gettext "活跃的 Jail 列表"): ${Font}"
    local jail_list=()
    local index=1
    while IFS= read -r jail; do
        [[ -n "$jail" ]] || continue
        jail_list[$index]="$jail"
        echo "${Green}${index}.${Font} ${jail}"
        index=$((index + 1))
    done <<< "$active_jails"
    echo "${Green}0.${Font} $(gettext "返回")"

    local jail_choice
    read_optimize "$(gettext "请选择要移除可信 IP 的 Jail"):" jail_choice 0 0 ${#jail_list[@]} "$(gettext "无效的选择, 请重试")"
    [[ $jail_choice -eq 0 ]] && return

    local selected_jail="${jail_list[$jail_choice]}"
    local trust_cidr
    read_optimize "$(gettext "请输入要移除的 IP/CIDR"):" trust_cidr NULL
    if [[ -z "$trust_cidr" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "IP/CIDR 不能为空") ${Font}"
        return
    fi
    mf_remove_trust_ip "$selected_jail" "$trust_cidr"
}

# P0-C: Service and config check submenu.
mf_service_and_config_check() {
    while true; do
        echo
        echo -e "${Green} $(gettext "服务与配置检查"): ${Font}"
        echo "1. $(gettext "启动") Fail2ban"
        echo "2. $(gettext "停止") Fail2ban"
        echo "3. $(gettext "重启") Fail2ban"
        echo "4. $(gettext "配置测试") (fail2ban-client -t)"
        echo "5. $(gettext "返回")"
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
            if fail2ban-client -t 2>&1; then
                log_echo "${OK} ${GreenBG} $(gettext "配置测试通过") ${Font}"
            else
                log_echo "${Error} ${RedBG} $(gettext "配置测试失败") ${Font}"
            fi
            ;;
        5)
            break
            ;;
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
    if [[ "${jail_name}" =~ [/\\] ]] || [[ -z "${jail_name}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "名称不能包含路径分隔符或为空") ${Font}"
        return
    fi
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
    judge -r "Fail2ban $(gettext "重启以应用新规则")"
}

mf_manage_modules() {
    while true; do
        echo
        echo -e "${Green} $(gettext "管理 Fail2ban 模块") ${Font}"

        local module_files=()
        local module_names=()
        local index=1

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

        local max_name_length=15
        local status_width
        local header_module="$(gettext "模块名称")"
        local header_status="$(gettext "状态")"
        local enabled_text="$(gettext "已启用")"
        local disabled_text="$(gettext "已禁用")"
        status_width=$(mf_display_width "$header_status")

        local length
        length=$(mf_display_width "$header_module")
        if (( length > max_name_length )); then
            max_name_length=$length
        fi
        length=$(mf_display_width "$(gettext "返回")")
        if (( length > max_name_length )); then
            max_name_length=$length
        fi
        length=$(mf_display_width "$enabled_text")
        if (( length > status_width )); then
            status_width=$length
        fi
        length=$(mf_display_width "$disabled_text")
        if (( length > status_width )); then
            status_width=$length
        fi

        for ((i=1; i<${#module_files[@]}+1; i++)); do
            length=$(mf_display_width "${module_names[$i]}")
            if (( length > max_name_length )); then
                max_name_length=$length
            fi
        done

        local total_width=$((max_name_length + status_width + 14))

        mf_table_line "$total_width"
        printf "| "; mf_pad "$(gettext "序号")" 4; printf " | "; mf_pad "$header_module" "$max_name_length"; printf " | "; mf_pad "$header_status" "$status_width"; printf " |\n"
        mf_table_line "$total_width"

        for ((i=1; i<${#module_files[@]}+1; i++)); do
            local module_file=${module_files[$i]}
            local module_name=${module_names[$i]}

            if mf_is_module_enabled "$module_file"; then
                local status_text="$enabled_text"
            else
                local status_text="$disabled_text"
            fi

            printf "| %4d | " $i; mf_pad "$module_name" "$max_name_length"; printf " | "; mf_pad "$status_text" "$status_width"; printf " |\n"
        done

        mf_table_line "$total_width"
        printf "| %4d | " 0; mf_pad "$(gettext "返回")" "$max_name_length"; printf " | "; mf_pad "" "$status_width"; printf " |\n"
        mf_table_line "$total_width"

        local module_choice
        read_optimize "$(gettext "请选择要管理的模块"): " "module_choice" 0 0 ${#module_files[@]} "$(gettext "无效的选择, 请重试")"

        if [[ $module_choice -eq 0 ]]; then
            return
        fi

        local selected_file=${module_files[$module_choice]}
        local selected_name=${module_names[$module_choice]}

        local current_status=$(grep -oP 'enabled\s*=\s*\K\w+' "$selected_file" 2>/dev/null || echo "true")
        local new_status=$([[ "$current_status" == "true" ]] && echo "false" || echo "true")
        local status_text=$([[ "$new_status" == "true" ]] && echo "$(gettext "启用")" || echo "$(gettext "禁用")")

        log_echo "${GreenBG} $(gettext "是否") $status_text $selected_name $(gettext "模块") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r confirm

        if [[ ! $confirm =~ ^[nN]([oO])?$ ]]; then
            sed -i "s/enabled\s*=\s*\w*/enabled = $new_status/" "$selected_file"

            mf_restart_fail2ban

            log_echo "${OK} ${GreenBG} $selected_name $(gettext "模块") $status_text ${Font}"
        else
            log_echo "${Green} $(gettext "操作已取消") ${Font}"
        fi

    done
}

mf_start_enable_fail2ban() {
    systemctl daemon-reload
    systemctl start fail2ban
    judge -r "Fail2ban $(gettext "启动")"
    systemctl enable fail2ban
}

mf_uninstall_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    ${INS} -y remove fail2ban
    judge -r "Fail2ban $(gettext "卸载")"
    [[ -f "/etc/fail2ban/jail.local" ]] && rm -f "/etc/fail2ban/jail.local"
    rm -f /etc/fail2ban/jail.d/*.local
    if [[ -f "/etc/fail2ban/filter.d/nginx-no-host.conf" ]]; then
        rm -f "/etc/fail2ban/filter.d/nginx-no-host.conf"
    fi
    if [[ -f "/etc/fail2ban/filter.d/nginx-tls-error.conf" ]]; then
        rm -f "/etc/fail2ban/filter.d/nginx-tls-error.conf"
    fi
    exec "${BASH:-bash}" "${idleleo}"
}

mf_stop_disable_fail2ban() {
    systemctl stop fail2ban
    systemctl disable fail2ban
    log_echo "${OK} ${GreenBG} Fail2ban $(gettext "停止") $(gettext "成功") ${Font}"
    # timeout "$(gettext "清空屏幕")!"
    # clear
}

mf_restart_fail2ban() {
    systemctl daemon-reload
    systemctl restart fail2ban
    judge -r "Fail2ban $(gettext "重启")"
    # timeout "$(gettext "清空屏幕")!"
    # clear
}

mf_display_fail2ban_status() {
    echo
    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban $(gettext "未安装"), $(gettext "请先安装") Fail2ban ${Font}"
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
}

mf_check_for_updates() {
    local latest_version
    local update_choice

    latest_version=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "$mf_remote_url" 2>/dev/null | grep 'mf_SCRIPT_VERSION=' | head -n 1 | sed 's/mf_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$mf_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用"): $latest_version $(gettext "当前版本"): $mf_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问") https://github.com/hello-yunshu/Xray_bash_onekey $(gettext "查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本")... ${Font}"
                if download_script_file "$mf_remote_url" "${scripts_dir}/fail2ban_manager.sh"; then
                    log_echo "${OK} ${GreenBG} $(gettext "下载完成, 正在重新加载...") ${Font}"
                    source "${scripts_dir}/fail2ban_manager.sh"
                    return
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

# P0-C: CLI entry point for Fail2ban management.
# Reuses the same implementation as the menu, no logic duplication.
# Usage:
#   mf_cli --list
#   mf_cli --unban <jail> <ip>
#   mf_cli --trust-add <jail> <ip-or-cidr>
#   mf_cli --trust-del <jail> <ip-or-cidr>
mf_cli() {
    local cli_action="${1:-}"
    shift || true

    if ! command -v fail2ban-client &> /dev/null; then
        log_echo "${Error} ${RedBG} Fail2ban $(gettext "未安装"), $(gettext "请先安装") Fail2ban ${Font}"
        return 1
    fi

    case "$cli_action" in
        --list)
            mf_display_fail2ban_status
            ;;
        --unban)
            local jail="${1:-}"
            local ip="${2:-}"
            if [[ -z "$jail" || -z "$ip" ]]; then
                log_echo "${Error} ${RedBG} $(gettext "用法: --fail2ban-unban <jail> <ip>") ${Font}"
                return 1
            fi
            mf_quick_unban "$jail" "$ip"
            ;;
        --trust-add)
            local jail="${1:-}"
            local cidr="${2:-}"
            if [[ -z "$jail" || -z "$cidr" ]]; then
                log_echo "${Error} ${RedBG} $(gettext "用法: --fail2ban-trust-add <jail> <ip-or-cidr>") ${Font}"
                return 1
            fi
            mf_add_trust_ip "$jail" "$cidr"
            ;;
        --trust-del)
            local jail="${1:-}"
            local cidr="${2:-}"
            if [[ -z "$jail" || -z "$cidr" ]]; then
                log_echo "${Error} ${RedBG} $(gettext "用法: --fail2ban-trust-del <jail> <ip-or-cidr>") ${Font}"
                return 1
            fi
            mf_remove_trust_ip "$jail" "$cidr"
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "未知命令"): ${cli_action} ${Font}"
            log_echo "${Info} $(gettext "可用命令"):" ${Font}
            log_echo "  --list               $(gettext "查看 Fail2ban 状态")"
            log_echo "  --unban <jail> <ip>  $(gettext "快速解封 IP")"
            log_echo "  --trust-add <jail> <ip-or-cidr>  $(gettext "添加可信 IP/CIDR")"
            log_echo "  --trust-del <jail> <ip-or-cidr>  $(gettext "移除可信 IP/CIDR")"
            return 1
            ;;
    esac
}
