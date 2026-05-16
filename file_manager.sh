#!/bin/bash

# 定义当前版本号
fm_SCRIPT_VERSION="1.5.5"
MIN_MAIN_VERSION="2.10.0"

if [ -n "$shell_version" ]; then
    oldest=$(printf '%s\n%s\n' "$MIN_MAIN_VERSION" "$shell_version" | sort -V | head -1)
    if [ "$oldest" != "$MIN_MAIN_VERSION" ]; then
        echo "${Error} ${RedBG} file_manager.sh $(gettext "需要主脚本版本") >= ${MIN_MAIN_VERSION}，$(gettext "当前版本"): ${shell_version}，$(gettext "请先更新主脚本") ${Font}"
        return 1
    fi
fi

if [ -n "$1" ]; then
    fm_EXTENSION="$1"
    fm_WORKDIR="${2:-$(pwd)}"

    if [ ! -d "$fm_WORKDIR" ]; then
        echo
        log_echo "${Error} ${RedBG} $(gettext "目录") $fm_WORKDIR $(gettext "不存在, 请检查路径") ${Font}"
        return 1
    fi

    fm_original_dir=$(pwd)

    cd "$fm_WORKDIR"
elif [ -z "$fm_EXTENSION" ]; then
    echo "$(gettext "用法"):" $0 \<$(gettext "文件扩展名")\> [\<$(gettext "目录路径")\>]
    return 1
fi

fm_display_width() {
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

fm_pad() {
    local str="$1"
    local target_width="$2"
    local width
    width=$(fm_display_width "$str")
    local padding=$((target_width - width))
    if (( padding > 0 )); then
        printf '%s%*s' "$str" "$padding" ""
    else
        printf '%s' "$str"
    fi
}

fm_table_line() {
    local width="$1"
    printf '%*s\n' "$width" "" | tr ' ' '-'
}

fm_list_files() {
    local max_length
    log_echo "${GreenBG} $(gettext "列出所有") .$fm_EXTENSION $(gettext "文件") ${Font}"

    local _prev_dotglob=$(shopt -p dotglob)
    local _prev_nullglob=$(shopt -p nullglob)

    # 设置 dotglob 选项，使通配符 * 包括以点开头的文件
    shopt -s dotglob nullglob

    files=(*.$fm_EXTENSION)

    if [ ${#files[@]} -eq 0 ]; then
        eval "${_prev_dotglob}"
        eval "${_prev_nullglob}"
        log_echo "${Warning} ${YellowBG} $(gettext "未找到") .$fm_EXTENSION $(gettext "文件") ${Font}"
        return 1
    else
        local header_text="$(gettext "文件名")"
        local max_length
        max_length=$(fm_display_width "$header_text")
        for file in "${files[@]}"; do
            local length
            length=$(fm_display_width "$file")
            if (( length > max_length )); then
                max_length=$length
            fi
        done

        if (( max_length < 10 )); then
            max_length=10
        fi

        local total_width=$((max_length + 11))
        fm_table_line "$total_width"

        printf "| "; fm_pad "$(gettext "序号")" 4; printf " | "; fm_pad "$header_text" "$max_length"; printf " |\n"

        fm_table_line "$total_width"

        local index=1
        for file in "${files[@]}"; do
            printf "| %4d | " $index; fm_pad "$file" "$max_length"; printf " |\n"
            ((index++))
        done

        fm_table_line "$total_width"

        eval "${_prev_dotglob}"
        eval "${_prev_nullglob}"
        return 0
    fi
}

fm_create_servername_file() {
    local url
    fm_list_files
    echo
    log_echo "${Green} $(gettext "请输入网址 (例如 hey.run)")"
    log_echo "${Green} $(gettext "不要包含 http:// 或 https:// 开头") ${Font}"
    read_optimize "$(gettext "请输入"):" url
    if [[ $url =~ ^(http|https):// ]]; then
        echo
        log_echo "${Error} ${RedBG} $(gettext "网址不能包含 http:// 或 https:// 前缀") ${Font}"
        return 1
    fi
    if [[ "${url}" =~ [/\ \;\&\|\$\`] ]]; then
        log_echo "${Error} ${RedBG} $(gettext "网址包含非法字符")! ${Font}"
        return 1
    fi
    echo "${url} reality;" > "${url}.serverNames"
    log_echo "${OK} ${GreenBG} $(gettext "文件") ${url}.serverNames $(gettext "已创建") ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}

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
        log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "追加完成") ${Font}"
        if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
            service iptables save
            service iptables restart
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启完成") ${Font}"
        else
            netfilter-persistent save
            systemctl restart iptables
            log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启完成") ${Font}"
        fi
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "跳过防火墙设置") ${Font}"
        ;;
    esac
    fm_restart_nginx_and_check_status
    fm_list_files
}

fm_edit_file() {
    fm_list_files
    local num_files=${#files[@]}
    local choice
    read_optimize "$(gettext "请输入要编辑的文件编号") (1-$num_files): " choice "" 1 "$num_files"

    local filename="${files[$((choice - 1))]}"

    if ! command -v vim &> /dev/null; then
        log_echo "${Warning} ${YellowBG} vim $(gettext "未安装, 正在尝试安装") ${Font}"
        pkg_install vim
    fi
    vim "$filename"
    log_echo "${OK} ${GreenBG} $(gettext "文件") $filename $(gettext "已编辑") ${Font}"
    fm_restart_nginx_and_check_status
    if [[ -f ${nginx_systemd_file} ]] && ! systemctl is-active --quiet nginx; then
        local retry_choice
        while true; do
            log_echo "${Warning} ${YellowBG} $(gettext "Nginx 未运行, 是否继续编辑")? [Y/${Red}N${Font}${YellowBG}] ${Font}"
            read -r retry_choice
            case $retry_choice in
                [yY][eE][sS] | [yY])
                    if ! fm_list_files; then
                        log_echo "${Warning} ${YellowBG} $(gettext "没有可编辑的文件") ${Font}"
                        break
                    fi
                    num_files=${#files[@]}
                    read_optimize "$(gettext "请输入要编辑的文件编号") (1-$num_files): " choice "" 1 "$num_files"
                    filename="${files[$((choice - 1))]}"
                    vim "$filename"
                    log_echo "${OK} ${GreenBG} $(gettext "文件") $filename $(gettext "已编辑") ${Font}"
                    systemctl restart nginx
                    if systemctl is-active --quiet nginx; then
                        echo
                        log_echo "${OK} ${GreenBG} Nginx $(gettext "重启成功") ${Font}"
                        break
                    fi
                    ;;
                *)
                    log_echo "${Warning} ${YellowBG} $(gettext "Nginx 未运行, 请手动修复配置") ${Font}"
                    break
                    ;;
            esac
        done
    fi
}

fm_delete_file() {
    if ! fm_list_files; then
        return
    fi

    local num_files=${#files[@]}
    local choice
    read_optimize "$(gettext "请输入要删除的文件编号") (1-$num_files): " choice "" 1 "$num_files"

    local filename="${files[$((choice - 1))]}"

    rm "$filename"
    log_echo "${OK} ${GreenBG} $(gettext "文件") $filename $(gettext "已删除") ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}

fm_create_file() {
    case $fm_EXTENSION in
        serverNames)
            fm_create_servername_file
            ;;
        *Servers)
             fm_create_server_file ""
             ;;
        *)
            echo
            log_echo "${Error} ${RedBG} $(gettext "不支持的文件扩展名") $fm_EXTENSION ${Font}"
            ;;
    esac
}

fm_main_menu() {
    fm_list_files
    while true; do
        echo
        echo -e "${GreenBG} $(gettext "主菜单") ${Font}"
        echo -e "${Green}1.${Font} $(gettext "列出所有") $fm_EXTENSION $(gettext "文件")"
        echo -e "${Green}2.${Font} $(gettext "创建一个新的") $fm_EXTENSION $(gettext "文件")"
        echo -e "${Green}3.${Font} $(gettext "编辑一个已存在的") $fm_EXTENSION $(gettext "文件")"
        echo -e "${Green}4.${Font} $(gettext "删除一个已存在的") $fm_EXTENSION $(gettext "文件")"
        echo -e "${Green}5.${Font} $(gettext "退出")"
        local choice
        read_optimize "$(gettext "请选择一个选项"):" choice "" 1 5

        case $choice in
            1) fm_list_files ;;
            2) fm_create_file ;;
            3) fm_edit_file ;;
            4) fm_delete_file ;;
            5) cd "$fm_original_dir" || true; return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效选项, 请重试") ${Font}"
                ;;
        esac
    done
}

fm_check_for_updates() {
    local latest_version
    local update_choice

    latest_version=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "$fm_remote_url" 2>/dev/null | grep 'fm_SCRIPT_VERSION=' | head -n 1 | sed 's/fm_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$fm_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用"): $latest_version $(gettext "当前版本"): $fm_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问") https://github.com/hello-yunshu/Xray_bash_onekey $(gettext "查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本")... ${Font}"
                if download_script_file "$fm_remote_url" "${idleleo_dir}/file_manager.sh"; then
                    log_echo "${OK} ${GreenBG} $(gettext "下载完成, 正在重新加载...") ${Font}"
                    source "${idleleo_dir}/file_manager.sh"
                    return
                else
                    echo
                    log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
                fi
                ;;
            *)
                log_echo "${OK} ${Green} $(gettext "跳过更新") ${Font}"
                ;;
        esac
    else
        log_echo "${OK} ${Green} $(gettext "当前已经是最新版本"): $fm_SCRIPT_VERSION ${Font}"
    fi
}

fm_restart_nginx_and_check_status() {
    if [[ -f ${nginx_systemd_file} ]]; then
        systemctl restart nginx
        if systemctl is-active --quiet nginx; then
            echo
            log_echo "${OK} ${GreenBG} Nginx $(gettext "重启成功") ${Font}"
        else
            echo
            log_echo "${Error} ${RedBG} Nginx $(gettext "重启失败"), $(gettext "请检查配置文件是否有误") ${Font}"
        fi
    fi
}
