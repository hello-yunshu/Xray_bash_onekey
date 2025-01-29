#!/bin/bash

# 定义当前版本号
fm_SCRIPT_VERSION="1.1.0"

# 检查是否提供了扩展名参数
if [ -z "$1" ]; then
    echo "$(gettext "用法"):" $0 <$(gettext "文件扩展名")> [<$(gettext "目录路径")>]
    exit 1
fi

fm_EXTENSION="$1"
fm_WORKDIR="${2:-$(pwd)}"

# 检查目录是否存在
if [ ! -d "$fm_WORKDIR" ]; then
    echo -e "\n"
    log_echo "${Error} ${RedBG} $(gettext "目录") $fm_WORKDIR $(gettext "不存在, 请检查路径") ${Font}"
    exit 1
fi

# 保存当前工作目录
fm_original_dir=$(pwd)

# 切换到工作目录
cd "$fm_WORKDIR"

# 函数: 列出当前目录下所有指定扩展名的文件
fm_list_files() {
    local max_length
    log_echo "${GreenBG} $(gettext "列出所有") .$fm_EXTENSION $(gettext "文件") ${Font}"
    
    # 设置 dotglob 选项，使通配符 * 包括以点开头的文件
    shopt -s dotglob
    
    # 使用数组存储匹配到的文件
    files=(*.$fm_EXTENSION)
    
    if [ ${#files[@]} -eq 0 ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "没有找到") .$fm_EXTENSION $(gettext "文件") ${Font}"
        return 1
    else
        # 计算最大文件名长度
        local max_length=0
        for file in "${files[@]}"; do
            local length=${#file}
            if (( length > max_length )); then
                max_length=$length
            fi
        done
        
        # 确保最小宽度为 10
        if (( max_length < 10 )); then
            max_length=10
        fi
        
        # 计算总宽度（包括边框）
        local total_width=$((max_length + 10))
        
         # 打印表头
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        # 居中文本
        local header_text="$(gettext "文件名")"
        local header_length=${#header_text}
        local padding=$(( (total_width - header_length - 4) / 2 ))
        local left_padding=$(( padding - 4 ))  # 加上序号列的宽度
        local right_padding=$(( padding - 4 )) 
        
        printf "| %-4s | %-${left_padding}s%-${header_length}s%-${right_padding}s |\n" "$(gettext "序号")" "" "$header_text" ""
        
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        # 打印文件名
        local index=1
        for file in "${files[@]}"; do
            printf "| %4d | %-*s |\n" $index $((max_length)) "$file"
            ((index++))
        done
        
        # 打印底部边框
        printf "%-${total_width}s\n" "$(printf '%*s' "$total_width" | tr ' ' '-')"
        
        return 0
    fi
}

# 函数: 创建一个新的 serverNames 文件
fm_create_servername_file() {
    local url
    fm_list_files
    echo -e "\n"
    log_echo "${Green} $(gettext "请输入网址 (例如 hey.run)")"
    log_echo "${Green} $(gettext "不要包含 http:// 或 https:// 开头") ${Font}"
    read_optimize "$(gettext "请输入"):" url
    if [[ $url =~ ^(http|https):// ]]; then
        echo -e "\n"
        log_echo "${Error} ${RedBG} $(gettext "网址不能包含 http:// 或 https:// 开头") ${Font}"
        return
    fi
    echo "${url} reality;" > "${url}.serverNames"
    log_echo "${OK} ${GreenBG} $(gettext "文件") ${url}.serverNames $(gettext "已创建") ${Font}"
    fm_restart_nginx_and_check_status
    fm_list_files
}

# 函数: 创建一个新的 wsServers 或 grpcServers 文件
fm_create_ws_or_grpc_server_file() {
    local host port weight content firewall_set_fq
    fm_list_files
    read_optimize "$(gettext "请输入主机") (host):" host
    read_optimize "$(gettext "请输入端口") (port):" port "" 1 65535
    read_optimize "$(gettext "请输入权重") (0~100 $(gettext "默认值") 50):" weight "50" 0 100
    
    content="server ${host}:${port} weight=${weight} max_fails=2 fail_timeout=10;"
    echo "$content" > "${host}.${fm_EXTENSION}"
    log_echo "${OK} ${GreenBG} $(gettext "文件") ${host}.${fm_EXTENSION} $(gettext "已创建") ${Font}"

    # 询问是否需要修改防火墙
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

# 函数: 编辑一个已存在的指定扩展名的文件
fm_edit_file() {    
    fm_list_files
    local num_files=${#files[@]}
    local choice
    read_optimize "$(gettext "请输入要编辑的文件编号") (1-$num_files): " choice "" 1 "$num_files"
    
    local filename="${files[$((choice - 1))]}"
    
    # 检查 vim 是否安装
    if ! command -v vim &> /dev/null; then
        log_echo "${Warning} ${YellowBG} vim $(gettext "未安装, 正在尝试安装") ${Font}"
        pkg_install vim
    fi
    vim "$filename"
    log_echo "${OK} ${GreenBG} $(gettext "文件") $filename $(gettext "已编辑") ${Font}"
    fm_restart_nginx_and_check_status
}

# 函数: 删除一个已存在的指定扩展名的文件
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

# 根据扩展名选择创建文件的方式
fm_create_file() {
    case $fm_EXTENSION in
        serverNames)
            fm_create_servername_file
            ;;
        wsServers|grpcServers)
            fm_create_ws_or_grpc_server_file
            ;;
        *)
            echo -e "\n"
            log_echo "${Error} ${RedBG} $(gettext "不支持的文件扩展名") $fm_EXTENSION ${Font}"
            ;;
    esac
}

# 主菜单循环
fm_main_menu() {
    fm_list_files
    while true; do
        echo
        log_echo "${GreenBG} $(gettext "主菜单") ${Font}"
        log_echo "1 ${Green}$(gettext "列出所有") $fm_EXTENSION $(gettext "文件")${Font}"
        log_echo "2 ${Green}$(gettext "创建一个新的") $fm_EXTENSION $(gettext "文件")${Font}"
        log_echo "3 ${Green}$(gettext "编辑一个已存在的") $fm_EXTENSION $(gettext "文件")${Font}"
        log_echo "4 ${Green}$(gettext "删除一个已存在的") $fm_EXTENSION $(gettext "文件")${Font}"
        log_echo "5 ${Green}$(gettext "退出")${Font}"
        local choice
        read_optimize "$(gettext "请选择一个选项"):" choice "" 1 5

        case $choice in
            1) fm_list_files ;;
            2) fm_create_file ;;
            3) fm_edit_file ;;
            4) fm_delete_file ;;
            5) source "$idleleo" ;;
            *) 
                echo -e "\n"
                log_echo "${Error} ${RedBG} $(gettext "无效选项, 请重试") ${Font}"
                ;;
        esac
    done
}

fm_check_for_updates() {
    local latest_version
    local update_choice

    # 直接使用 curl 下载远程版本信息
    latest_version=$(curl -s "$fm_remote_url" | grep 'fm_SCRIPT_VERSION=' | head -n 1 | sed 's/fm_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$fm_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用"): $latest_version $(gettext "当前版本"): $fm_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问") https://github.com/hello-yunshu/Xray_bash_onekey $(gettext "查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否要下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本")... ${Font}"
                curl -sL "$fm_remote_url" -o "${idleleo_dir}/file_manager.sh"

                if [ $? -eq 0 ]; then
                    chmod +x "${idleleo_dir}/file_manager.sh"
                    log_echo "${OK} ${Green} $(gettext "下载完成, 正在重新运行脚本")... ${Font}"
                    bash "${idleleo}" --add-servernames
                else
                    echo -e "\n"
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
            echo -e "\n"
            log_echo "${OK} ${GreenBG} Nginx $(gettext "重启成功") ${Font}"
        else
            echo -e "\n"
            log_echo "${Error} ${RedBG} Nginx $(gettext "重启失败"), $(gettext "请检查配置文件是否有误") ${Font}"
            fm_edit_file
        fi
    fi
}

# 检查更新
fm_check_for_updates

# 运行主菜单
fm_main_menu

# 恢复原始工作目录
cd "$fm_original_dir" || exit 1