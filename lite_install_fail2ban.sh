#!/bin/bash

# =================================================================
# 精简版环境脚本: lite_install.sh
# 目的: 为 fail2ban_manager.sh 提供必要的函数和变量依赖。
# =================================================================

# 路径变量 (fail2ban_manager.sh 依赖)
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# --- 全局变量 (颜色及通知信息) ---
# fonts color
Green="\033[32m"
Red="\033[31m"
GreenW="\033[1;32m"
RedW="\033[1;31m"
GreenBG="\033[42;30m"
RedBG="\033[41;30m"
YellowBG="\033[43;30m"
Font="\033[0m"

# --- 语言环境 (简化为不翻译) ---
# gettext 函数: 直接返回输入字符串，禁用翻译功能。
gettext() {
    echo -n "$1"
}

# notification information (使用 gettext 简化后的中文或英文占位符)
Info="${Green}[提醒]${Font}"
OK="${Green}[OK]${Font}"
Error="${RedW}[错误]${Font}"
Warning="${RedW}[警告]${Font}"


# --- 核心函数 ---

# log_echo: 简化后的日志输出函数
log_echo() {
    echo -e "$1"
}

# judge: 判断上一步操作 ($?) 是否成功
judge() {
    # $1: 成功时的提示信息
    # $2: 失败时的提示信息
    if [[ $? -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $1 ${Font}"
    else
        log_echo "${Error} ${RedBG} $2 ${Font}"
        # 失败不退出，留给 fail2ban 脚本自己处理
    fi
}

# read_optimize: 读取用户输入并校验 (变量名, 默认值, 最小值, 最大值)
read_optimize() {
    local prompt="$1"
    local var_name="$2"
    local default_val="$3"
    local min_val="$4"
    local max_val="$5"
    local input_val

    while true; do
        # 提示用户输入
        read -r -p "${prompt} " input_val

        # 1. 处理空输入和默认值
        if [[ -z "$input_val" ]]; then
            if [[ -n "$default_val" ]]; then
                input_val="$default_val"
            else
                log_echo "${Error} 输入不能为空，请重试！"
                continue
            fi
        fi

        # 2. 检查是否为数字 (Fail2ban 菜单选项是数字)
        if ! [[ "$input_val" =~ ^[0-9]+$ ]]; then
            log_echo "${Error} 请输入数字！"
            continue
        fi

        # 3. 检查范围 (如果提供了 min/max)
        if [[ -n "$min_val" && -n "$max_val" ]]; then
            if (( input_val < min_val || input_val > max_val )); then
                log_echo "${Error} 选择范围错误，请选择 ${min_val} 到 ${max_val} 之间的选项！"
                continue
            fi
        fi

        # 将校验后的输入值赋给指定的变量名
        eval "$var_name=\"$input_val\""
        break
    done
}

# check_system: 检测操作系统类型，用于包管理器选择 (apt/yum)
check_system() {
    if [[ -f /etc/redhat-release || -f /etc/centos-release ]]; then
        release="centos"
    elif [[ -f /etc/debian_version ]]; then
        release="debian"
    elif [[ -f /etc/issue ]]; then
        if grep -q "ubuntu" /etc/issue; then
            release="ubuntu"
        fi
    fi
    # 设置包安装命令
    if [[ $release == "centos" ]]; then
        install_pkg="yum -y install"
    elif [[ $release == "debian" || $release == "ubuntu" ]]; then
        install_pkg="apt -y install"
        apt_update="apt -y update" # 在安装前更新 apt 列表
    else
        log_echo "${Error} ${RedBG} 不支持的系统类型 ${Font}"
    fi
}

# pkg_install: 安装指定软件包
pkg_install() {
    # $1: 软件包名称 (e.g., "fail2ban")
    local package_name="$1"
    local package_display_name="${2:-$1}" # 如果未提供显示名称，则使用软件包名

    log_echo "${Info} ${GreenBG} 正在安装 ${package_display_name} (${package_name})... ${Font}"

    if [[ -n "$apt_update" && ($release == "debian" || $release == "ubuntu") ]]; then
        # 仅在 Debian/Ubuntu 上执行 apt update
        $apt_update
        judge "系统包列表更新成功" "系统包列表更新失败"
    fi

    # 安装软件包
    $install_pkg "$package_name"

    # 检查安装状态
    judge "${package_display_name} 安装成功" "${package_display_name} 安装失败"
}

# 在脚本被 source 时，检查并设置 OS 信息
check_system

# 下载文件
wget https://github.com/hello-yunshu/Xray_bash_onekey/raw/refs/heads/main/fail2ban_manager.sh -O fail2ban_install.sh

# 删除最后一行
sed -i '$d' fail2ban_install.sh

# 末尾添加一行 mf_install_fail2ban
sed -i '$a mf_install_fail2ban' fail2ban_install.sh

# 查找 mf_install_fail2ban() { 下面的第1个 source "${idleleo}"
# 替换为 mf_main_menu
sed -i '/mf_install_fail2ban() {/,/source "${idleleo}"/ s/source "${idleleo}"/mf_main_menu/' fail2ban_install.sh 

# 查找  mf_install_fail2ban() { 以下的第1个 else
# 在这个else的上一行添加 mf_main_menu
sed -i '/mf_install_fail2ban() {/,/else/ {/else/ {i\        mf_main_menu
}}' fail2ban_install.sh

# 运行
source fail2ban_install.sh
