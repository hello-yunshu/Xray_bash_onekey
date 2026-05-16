#!/bin/bash

tb_SCRIPT_VERSION="1.5.9"
MIN_MAIN_VERSION="2.10.0"

if [ -n "$shell_version" ]; then
    oldest=$(printf '%s\n%s\n' "$MIN_MAIN_VERSION" "$shell_version" | sort -V | head -1)
    if [ "$oldest" != "$MIN_MAIN_VERSION" ]; then
        echo "${Error} ${RedBG} traffic_blocker.sh $(gettext "需要主脚本版本") >= ${MIN_MAIN_VERSION}，$(gettext "当前版本"): ${shell_version}，$(gettext "请先更新主脚本") ${Font}"
        return 1
    fi
fi

tb_config_file="${xray_conf_dir}/traffic_blocker.json"
tb_geo_dir="${idleleo_dir}/share/xray"
tb_geo_remote="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

_tb_cached_remote_version=""
_tb_cached_remote_time=0

tb_all_rule_names=("country_block" "bittorrent" "private_ip" "ads")

tb_init_config() {
    if [[ ! -f "${tb_config_file}" ]]; then
        cat > "${tb_config_file}" << 'EOF'
{
    "country_block": [],
    "bittorrent": false,
    "private_ip": false,
    "ads": false,
    "geo_versions": {}
}
EOF
    else
        local tmp_file="${tb_config_file}.tmp"
        jq '.country_block //= [] |
            .bittorrent //= false |
            .private_ip //= false |
            .ads //= false |
            .geo_versions //= {}' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
    fi
}

tb_get_rule_status() {
    local rule_name="$1"
    if [[ ! -f "${tb_config_file}" ]]; then
        echo "false"
        return
    fi
    if [[ "$rule_name" == "country_block" ]]; then
        local count=$(jq '.country_block | length' "${tb_config_file}" 2>/dev/null)
        if [[ -n "$count" ]] && (( count > 0 )); then
            echo "true"
        else
            echo "false"
        fi
        return
    fi
    local status=$(jq -r --arg name "$rule_name" '.[$name]' "${tb_config_file}" 2>/dev/null)
    echo "${status:-false}"
}

tb_set_rule_status() {
    local rule_name="$1"
    local status="$2"
    if [[ ! -f "${tb_config_file}" ]]; then
        tb_init_config
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq --arg name "$rule_name" --argjson val "${status}" '.[$name] = $val' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_preset_countries=("cn:中国" "ru:俄罗斯" "ir:伊朗" "kp:朝鲜" "gb:英国" "au:澳大利亚" "tr:土耳其")

tb_get_countries() {
    if [[ ! -f "${tb_config_file}" ]]; then
        echo ""
        return
    fi
    local countries=$(jq -r '.country_block // [] | join(",")' "${tb_config_file}" 2>/dev/null)
    echo "${countries}"
}

tb_set_countries() {
    local countries_json="$1"
    if [[ ! -f "${tb_config_file}" ]]; then
        tb_init_config
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq --argjson val "$countries_json" '.country_block = $val' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_display_width() {
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

tb_pad() {
    local str="$1"
    local target_width="$2"
    local width
    width=$(tb_display_width "$str")
    local padding=$((target_width - width))
    if (( padding > 0 )); then
        printf '%s%*s' "$str" "$padding" ""
    else
        printf '%s' "$str"
    fi
}

tb_table_line() {
    local width="$1"
    printf '%*s\n' "$width" "" | tr ' ' '-'
}

tb_rule_display_name() {
    local rule_name="$1"
    case "$rule_name" in
        country_block)
            local countries=$(tb_get_countries)
            if [[ -n "$countries" ]]; then
                local max_list_len=28
                local display_list=""
                IFS=',' read -ra codes <<< "$countries"
                for code in "${codes[@]}"; do
                    local item="${display_list:+$display_list, }$code"
                    if (( ${#item} > max_list_len )); then
                        display_list="${display_list}, ..."
                        break
                    fi
                    display_list="$item"
                done
                echo "$(gettext "国家/地区阻断") (${display_list})"
            else
                echo "$(gettext "国家/地区阻断") ($(gettext "未配置"))"
            fi
            ;;
        bittorrent)  echo "$(gettext "BT 下载") (protocol:bittorrent)" ;;
        private_ip)  echo "$(gettext "私有网络") (geoip:private)" ;;
        ads)         echo "$(gettext "广告域名") (geosite:category-ads-all)" ;;
        *)           echo "$rule_name" ;;
    esac
}

tb_rule_description() {
    local rule_name="$1"
    case "$rule_name" in
        country_block) echo "$(gettext "阻断指定国家/地区的 IP 和域名流量")" ;;
        bittorrent)  echo "$(gettext "阻断 BT 下载协议流量")" ;;
        private_ip)  echo "$(gettext "阻断访问私有网络地址的流量")" ;;
        ads)         echo "$(gettext "阻断广告域名的流量")" ;;
        *)           echo "" ;;
    esac
}

tb_add_country() {
    echo
    log_echo "${Green} $(gettext "常用国家/地区"): ${Font}"
    local line=""
    local col=0
    for entry in "${tb_preset_countries[@]}"; do
        local code="${entry%%:*}"
        local name="${entry#*:}"
        local item="  ${code} - ${name}"
        if (( col + ${#item} > 60 )); then
            echo "$line"
            line="$item"
            col=${#item}
        else
            line="${line}${item}"
            col=$((col + ${#item}))
        fi
    done
    if [[ -n "$line" ]]; then
        echo "$line"
    fi
    echo
    echo "$(gettext "请输入国家/地区代码 (例如: cn, jp, ru)"):"
    read -r input_codes

    if [[ -z "$input_codes" ]]; then
        log_echo "${Green} $(gettext "操作已取消") ${Font}"
        return 1
    fi

    IFS=',' read -ra new_codes <<< "$input_codes"
    local current_json=$(jq -c '.country_block // []' "${tb_config_file}" 2>/dev/null)
    local added=()
    local skipped=()

    for code in "${new_codes[@]}"; do
        code=$(echo "$code" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        if [[ ! "$code" =~ ^[a-z]{2}$ ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "无效的国家代码, 已跳过"): $code ${Font}"
            continue
        fi
        if echo "$current_json" | jq -e --arg c "$code" 'index($c)' >/dev/null 2>&1; then
            skipped+=("$code")
            continue
        fi
        current_json=$(echo "$current_json" | jq --arg c "$code" '. += [$c]')
        added+=("$code")
    done

    if [[ ${#added[@]} -gt 0 ]]; then
        tb_set_countries "$current_json"
        log_echo "${OK} ${GreenBG} $(gettext "已添加"): ${added[*]} ${Font}"
    fi
    if [[ ${#skipped[@]} -gt 0 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "已存在, 已跳过"): ${skipped[*]} ${Font}"
    fi
    if [[ ${#added[@]} -eq 0 && ${#skipped[@]} -eq 0 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "未添加任何国家/地区") ${Font}"
    fi

    [[ ${#added[@]} -gt 0 ]] && return 0 || return 1
}

tb_remove_country() {
    local countries_str=$(tb_get_countries)
    if [[ -z "$countries_str" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "当前未配置任何国家/地区") ${Font}"
        return 1
    fi

    IFS=',' read -ra countries <<< "$countries_str"
    echo
    log_echo "${Green} $(gettext "当前已阻断"): ${Font}"
    local i=1
    for code in "${countries[@]}"; do
        local display_name="$code"
        for entry in "${tb_preset_countries[@]}"; do
            if [[ "${entry%%:*}" == "$code" ]]; then
                display_name="$code - ${entry#*:}"
                break
            fi
        done
        echo "  ${i}. ${display_name}"
        i=$((i + 1))
    done
    echo "  0. $(gettext "返回")"
    echo

    local remove_choice
    read_optimize "$(gettext "请选择要移除的编号"):" remove_choice "" 1

    if [[ "$remove_choice" -eq 0 ]] 2>/dev/null; then
        return 1
    fi

    if [[ "$remove_choice" -lt 1 || "$remove_choice" -gt ${#countries[@]} ]] 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "无效的选择") ${Font}"
        return 1
    fi

    local remove_code="${countries[$((remove_choice - 1))]}"
    local current_json=$(jq -c '.country_block // []' "${tb_config_file}" 2>/dev/null)
    current_json=$(echo "$current_json" | jq --arg c "$remove_code" 'del(.[] | select(. == $c))')
    tb_set_countries "$current_json"
    log_echo "${OK} ${GreenBG} $(gettext "已移除"): $remove_code ${Font}"
    return 0
}

tb_country_menu() {
    while true; do
        echo
        echo -e "${Green} $(gettext "国家/地区阻断管理") ${Font}"

        local countries_str=$(tb_get_countries)
        if [[ -n "$countries_str" ]]; then
            log_echo "${Info} ${Green} $(gettext "当前已阻断"): ${countries_str} ${Font}"
        else
            log_echo "${Info} $(gettext "当前未配置任何国家/地区")"
        fi

        echo
        echo "1. $(gettext "添加国家/地区")"
        echo "2. $(gettext "移除国家/地区")"
        echo "3. $(gettext "返回")"
        local country_choice
        read_optimize "$(gettext "请选择一个选项"):" country_choice "" 1
        case $country_choice in
            1) tb_add_country && tb_apply_rules ;;
            2) tb_remove_country && tb_apply_rules ;;
            3) return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done
}

tb_get_geo_remote_version() {
    local redirect_url
    redirect_url=$(curl -fsSI --connect-timeout 5 --max-time 10 -o /dev/null -w '%{redirect_url}' "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest" 2>/dev/null)
    if [[ -n "$redirect_url" ]]; then
        echo "$redirect_url" | sed 's|.*/tag/||' | tr -d '\r\n'
    else
        echo ""
    fi
}

tb_get_geo_local_version() {
    local file_name="$1"
    if [[ ! -f "${tb_config_file}" ]]; then
        echo ""
        return
    fi
    local version=$(jq -r --arg name "$file_name" '.geo_versions[$name] // ""' "${tb_config_file}" 2>/dev/null)
    echo "${version}"
}

tb_set_geo_local_version() {
    local file_name="$1"
    local version="$2"
    if [[ ! -f "${tb_config_file}" ]]; then
        tb_init_config
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq --arg name "$file_name" --arg v "$version" '.geo_versions[$name] = $v' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_get_previous_domain_strategy() {
    if [[ ! -f "${tb_config_file}" ]]; then
        echo ""
        return
    fi
    jq -r '.previous_domain_strategy // ""' "${tb_config_file}" 2>/dev/null
}

tb_set_previous_domain_strategy() {
    local strategy="$1"
    if [[ ! -f "${tb_config_file}" ]]; then
        tb_init_config
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq --arg ds "$strategy" '.previous_domain_strategy = $ds' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_clear_previous_domain_strategy() {
    if [[ ! -f "${tb_config_file}" ]]; then
        return
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq 'del(.previous_domain_strategy)' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_get_geo_file_date() {
    local file_path="$1"
    if [[ -f "$file_path" ]]; then
        stat -c %Y "$file_path" 2>/dev/null || stat -f %m "$file_path" 2>/dev/null
    else
        echo "0"
    fi
}

tb_format_date() {
    local timestamp="$1"
    if [[ "$timestamp" == "0" ]]; then
        echo "$(gettext "不存在")"
        return
    fi
    date -d "@${timestamp}" "+%Y-%m-%d %H:%M" 2>/dev/null || date -r "${timestamp}" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "$(gettext "未知")"
}

tb_is_geo_outdated() {
    local file_name="$1"
    local remote_version="${2:-}"
    local local_version=$(tb_get_geo_local_version "$file_name")

    if [[ -z "$remote_version" ]]; then
        remote_version=$(tb_get_geo_remote_version)
    fi

    if [[ -z "$remote_version" ]]; then
        return 1
    fi

    if [[ -z "$local_version" ]]; then
        return 0
    fi

    if [[ "$local_version" != "$remote_version" ]]; then
        return 0
    fi

    return 1
}

tb_download_geo_file() {
    local file_name="$1"
    local remote_version="${2:-}"
    mkdir -p "${tb_geo_dir}"

    if [[ -z "$remote_version" ]]; then
        remote_version=$(tb_get_geo_remote_version)
    fi
    local download_url="${tb_geo_remote}/${file_name}"
    log_echo "${Info} ${Green} $(gettext "正在下载"): ${file_name} ... ${Font}"

    if download_file "$download_url" "${tb_geo_dir}/${file_name}"; then
        tb_set_geo_local_version "$file_name" "${remote_version}"
        log_echo "${OK} ${GreenBG} $(gettext "下载完成"): ${file_name} (${remote_version}) ${Font}"
        return 0
    else
        log_echo "${Error} ${RedBG} $(gettext "下载失败"): ${file_name} ${Font}"
        return 1
    fi
}

tb_display_status() {
    tb_init_config

    local names=()
    local statuses=()
    local name_w
    local status_w
    local header_name="$(gettext "规则名称")"
    local header_status="$(gettext "状态")"
    local enabled_text="$(gettext "已启用")"
    local disabled_text="$(gettext "已禁用")"
    name_w=$(tb_display_width "$header_name")
    status_w=$(tb_display_width "$header_status")

    local index=0
    for rule_name in "${tb_all_rule_names[@]}"; do
        local display_name=$(tb_rule_display_name "$rule_name")
        local status=$(tb_get_rule_status "$rule_name")
        if [[ "$status" == "true" ]]; then
            local status_text="$enabled_text"
        else
            local status_text="$disabled_text"
        fi
        index=$((index + 1))
        names[$index]="$display_name"
        statuses[$index]="$status_text"

        local width
        width=$(tb_display_width "$display_name")
        if (( width > name_w )); then
            name_w=$width
        fi
        width=$(tb_display_width "$status_text")
        if (( width > status_w )); then
            status_w=$width
        fi
    done
    local return_width
    return_width=$(tb_display_width "$(gettext "返回")")
    if (( return_width > name_w )); then
        name_w=$return_width
    fi

    local total_w=$((name_w + status_w + 14))

    tb_table_line "$total_w"
    printf "| "; tb_pad "$(gettext "序号")" 4; printf " | "; tb_pad "$header_name" "$name_w"; printf " | "; tb_pad "$header_status" "$status_w"; printf " |\n"
    tb_table_line "$total_w"

    for ((index=1; index<=${#names[@]}; index++)); do
        printf "| %4d | " "$index"; tb_pad "${names[$index]}" "$name_w"; printf " | "; tb_pad "${statuses[$index]}" "$status_w"; printf " |\n"
    done

    tb_table_line "$total_w"
    printf "| %4d | " 0; tb_pad "$(gettext "返回")" "$name_w"; printf " | "; tb_pad "" "$status_w"; printf " |\n"
    tb_table_line "$total_w"

    echo
    tb_display_geo_summary
}

tb_main_menu() {
    check_system
    while true; do
        echo
        echo -e "${GreenBG} $(gettext "设置") Xray $(gettext "流量阻断") ${Font}"

        tb_display_status

        echo
        echo -e "${Green} $(gettext "主菜单") ${Font}"
        echo -e "${Green}1.${Font} $(gettext "查看阻断规则状态")"
        echo -e "${Green}2.${Font} $(gettext "管理阻断规则")"
        echo -e "${Green}3.${Font} $(gettext "更新 GeoData")"
        echo -e "${Green}4.${Font} $(gettext "重置所有阻断规则")"
        echo -e "${Green}5.${Font} $(gettext "退出")"
        local tb_choice
        read_optimize "$(gettext "请选择一个选项"):" tb_choice "" 1
        case $tb_choice in
            1) continue ;;
            2) tb_manage_rules ;;
            3) tb_geo_menu ;;
            4) tb_reset_rules ;;
            5) return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done
}

tb_display_geo_summary() {
    log_echo "${Green} $(gettext "GeoData 状态"): ${Font}"

    local now=$(date +%s)
    local remote_version=""
    if [[ $((now - _tb_cached_remote_time)) -gt 300 ]]; then
        remote_version=$(tb_get_geo_remote_version)
        _tb_cached_remote_version="${remote_version}"
        _tb_cached_remote_time=${now}
    else
        remote_version="${_tb_cached_remote_version}"
    fi

    local geoip_exists="false"
    local geosite_exists="false"
    [[ -f "${tb_geo_dir}/geoip.dat" ]] && geoip_exists="true"
    [[ -f "${tb_geo_dir}/geosite.dat" ]] && geosite_exists="true"

    if [[ "$geoip_exists" == "true" ]]; then
        local geoip_version=$(tb_get_geo_local_version "geoip.dat")
        local geoip_date=$(tb_format_date "$(tb_get_geo_file_date "${tb_geo_dir}/geoip.dat")")
        if tb_is_geo_outdated "geoip.dat" "$remote_version"; then
            log_echo "  geoip.dat:  ${Yellow}$(gettext "有更新可用")${Font} ($(gettext "本地版本"): ${geoip_version:-$(gettext "未知")}, $(gettext "更新时间"): ${geoip_date})"
        else
            log_echo "  geoip.dat:  ${Green}$(gettext "已是最新")${Font} (${geoip_version:-$(gettext "未知")}, ${geoip_date})"
        fi
    else
        log_echo "  geoip.dat:  ${Red}$(gettext "未安装")${Font}"
    fi

    if [[ "$geosite_exists" == "true" ]]; then
        local geosite_version=$(tb_get_geo_local_version "geosite.dat")
        local geosite_date=$(tb_format_date "$(tb_get_geo_file_date "${tb_geo_dir}/geosite.dat")")
        if tb_is_geo_outdated "geosite.dat" "$remote_version"; then
            log_echo "  geosite.dat: ${Yellow}$(gettext "有更新可用")${Font} ($(gettext "本地版本"): ${geosite_version:-$(gettext "未知")}, $(gettext "更新时间"): ${geosite_date})"
        else
            log_echo "  geosite.dat: ${Green}$(gettext "已是最新")${Font} (${geosite_version:-$(gettext "未知")}, ${geosite_date})"
        fi
    else
        log_echo "  geosite.dat: ${Red}$(gettext "未安装")${Font}"
    fi
}

tb_geo_auto_update() {
    if [[ $(crontab -l 2>/dev/null | grep -c "geo_update.sh") -lt 1 ]]; then
        echo
        log_echo "${GreenBG} $(gettext "设置 GeoData 定时自动更新 (每周一凌晨3点)") ${Font}"
        log_echo "${GreenBG} $(gettext "是否启用") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r geo_auto_fq
        case $geo_auto_fq in
        [yY][eE][sS] | [yY])
            if [[ ! -f "${geo_update_file}" ]]; then
                download_script_file "https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/main/geo_update.sh" "${geo_update_file}"
                judge -r "$(gettext "下载 GeoData 自动更新脚本")" || return 1
            fi
            if [[ -f "${geo_update_file}" ]]; then
                if [[ "${ID}" == "centos" ]]; then
                    pkg_install "crontabs"
                    systemctl start crond >/dev/null 2>&1 && systemctl enable crond >/dev/null 2>&1
                else
                    pkg_install "cron"
                    systemctl start cron >/dev/null 2>&1 && systemctl enable cron >/dev/null 2>&1
                fi
                (crontab -l 2>/dev/null; echo "0 3 * * 1 bash \"${geo_update_file}\"") | crontab -
                judge -r "$(gettext "设置 GeoData 自动更新")" || return 1
            fi
            ;;
        *) ;;
        esac
    else
        log_echo "${OK} ${GreenBG} $(gettext "已设置 GeoData 自动更新") ${Font}"
        log_echo "${Info} ${Green} $(gettext "当前计划"): $(crontab -l 2>/dev/null | grep "geo_update.sh") ${Font}"
        log_echo "${GreenBG} $(gettext "是否关闭") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r geo_auto_close_fq
        case $geo_auto_close_fq in
        [yY][eE][sS] | [yY])
            crontab -l 2>/dev/null | grep -v "geo_update.sh" | crontab -
            rm -rf "${geo_update_file}"
            judge -r "$(gettext "删除 GeoData 自动更新")"
            ;;
        *) ;;
        esac
    fi
}

tb_geo_menu() {
    while true; do
        echo
        echo -e "${Green} $(gettext "更新 GeoData") ${Font}"
        echo
        tb_display_geo_summary
        echo
        echo "1. $(gettext "更新全部 GeoData")"
        echo "2. $(gettext "更新") geoip.dat"
        echo "3. $(gettext "更新") geosite.dat"
        echo "4. $(gettext "检查更新")"
        echo "5. $(gettext "设置自动更新")"
        echo "6. $(gettext "返回")"
        local geo_choice
        read_optimize "$(gettext "请选择一个选项"):" geo_choice "" 1
        case $geo_choice in
            1) tb_update_all_geo ;;
            2) tb_update_geo_file "geoip.dat" ;;
            3) tb_update_geo_file "geosite.dat" ;;
            4) tb_check_geo_updates ;;
            5) tb_geo_auto_update ;;
            6) return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done
}

tb_update_all_geo() {
    echo
    log_echo "${Info} ${Green} $(gettext "正在更新全部 GeoData")... ${Font}"

    local remote_version=$(tb_get_geo_remote_version)
    local has_error=false

    if ! tb_download_geo_file "geoip.dat" "$remote_version"; then
        has_error=true
    fi
    if ! tb_download_geo_file "geosite.dat" "$remote_version"; then
        has_error=true
    fi

    if [[ "$has_error" == "true" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "部分文件更新失败") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "全部 GeoData 已更新") ${Font}"
    fi

    if [[ -f "${xray_conf}" ]]; then
        log_echo "${GreenBG} $(gettext "是否重启 Xray 以加载新数据") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r restart_confirm
        if [[ $restart_confirm =~ ^[yY]([eE][sS])?$ ]]; then
            systemctl restart xray
            judge -r "Xray $(gettext "重启")" || return 1
        fi
    fi
}

tb_update_geo_file() {
    local file_name="$1"

    echo
    if [[ -f "${tb_geo_dir}/${file_name}" ]]; then
        local local_version=$(tb_get_geo_local_version "$file_name")
        log_echo "${Info} ${Green} $(gettext "当前版本"): ${local_version:-$(gettext "未知")} ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "文件不存在, 将下载最新版本") ${Font}"
    fi

    if tb_download_geo_file "$file_name"; then
        local new_version=$(tb_get_geo_local_version "$file_name")
        log_echo "${OK} ${GreenBG} ${file_name} $(gettext "已更新至"): ${new_version} ${Font}"

        if [[ -f "${xray_conf}" ]]; then
            log_echo "${GreenBG} $(gettext "是否重启 Xray 以加载新数据") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r restart_confirm
            if [[ $restart_confirm =~ ^[yY]([eE][sS])?$ ]]; then
                systemctl restart xray
                judge -r "Xray $(gettext "重启")" || return 1
            fi
        fi
    fi
}

tb_check_geo_updates() {
    echo
    log_echo "${Info} ${Green} $(gettext "正在检查远程版本")... ${Font}"

    local remote_version=$(tb_get_geo_remote_version)

    if [[ -z "$remote_version" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法获取远程版本信息, 请检查网络连接") ${Font}"
        return
    fi

    log_echo "${Info} ${Green} $(gettext "远程最新版本"): ${remote_version} ${Font}"
    echo

    local has_update=false

    for file_name in "geoip.dat" "geosite.dat"; do
        if [[ -f "${tb_geo_dir}/${file_name}" ]]; then
            local local_version=$(tb_get_geo_local_version "$file_name")
            local file_date=$(tb_format_date "$(tb_get_geo_file_date "${tb_geo_dir}/${file_name}")")
            if tb_is_geo_outdated "$file_name" "$remote_version"; then
                log_echo "${Warning} ${YellowBG} ${file_name}: $(gettext "有更新可用") (${local_version:-$(gettext "未知")} → ${remote_version}, $(gettext "更新时间"): ${file_date}) ${Font}"
                has_update=true
            else
                log_echo "${OK} ${GreenBG} ${file_name}: $(gettext "已是最新") (${local_version:-$(gettext "未知")}) ${Font}"
            fi
        else
            log_echo "${Warning} ${YellowBG} ${file_name}: $(gettext "未安装") ${Font}"
            has_update=true
        fi
    done

    if [[ "$has_update" == "true" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否更新所有过期的文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r update_confirm
        if [[ ! $update_confirm =~ ^[nN]([oO])?$ ]]; then
            tb_update_all_geo
        fi
    else
        log_echo "${OK} ${GreenBG} $(gettext "所有 GeoData 均为最新版本") ${Font}"
    fi
}

tb_manage_rules() {
    while true; do
        echo
        echo -e "${Green} $(gettext "管理流量阻断规则") ${Font}"

        tb_init_config

        local names=()
        local statuses=()
        local name_w
        local status_w
        local header_name="$(gettext "规则名称")"
        local header_status="$(gettext "状态")"
        local enabled_text="$(gettext "已启用")"
        local disabled_text="$(gettext "已禁用")"
        name_w=$(tb_display_width "$header_name")
        status_w=$(tb_display_width "$header_status")

        local index=0
        for rule_name in "${tb_all_rule_names[@]}"; do
            local display_name=$(tb_rule_display_name "$rule_name")
            local status=$(tb_get_rule_status "$rule_name")
            if [[ "$status" == "true" ]]; then
                local status_text="$enabled_text"
            else
                local status_text="$disabled_text"
            fi
            index=$((index + 1))
            names[$index]="$display_name"
            statuses[$index]="$status_text"

            local width
            width=$(tb_display_width "$display_name")
            if (( width > name_w )); then
                name_w=$width
            fi
            width=$(tb_display_width "$status_text")
            if (( width > status_w )); then
                status_w=$width
            fi
        done
        local return_width
        return_width=$(tb_display_width "$(gettext "返回")")
        if (( return_width > name_w )); then
            name_w=$return_width
        fi

        local total_w=$((name_w + status_w + 14))

        tb_table_line "$total_w"
        printf "| "; tb_pad "$(gettext "序号")" 4; printf " | "; tb_pad "$header_name" "$name_w"; printf " | "; tb_pad "$header_status" "$status_w"; printf " |\n"
        tb_table_line "$total_w"

        for ((index=1; index<=${#names[@]}; index++)); do
            printf "| %4d | " "$index"; tb_pad "${names[$index]}" "$name_w"; printf " | "; tb_pad "${statuses[$index]}" "$status_w"; printf " |\n"
        done

        tb_table_line "$total_w"
        printf "| %4d | " 0; tb_pad "$(gettext "返回")" "$name_w"; printf " | "; tb_pad "" "$status_w"; printf " |\n"
        tb_table_line "$total_w"

        local rule_choice
        read_optimize "$(gettext "请选择要管理的规则"): " "rule_choice" 0 0 ${#tb_all_rule_names[@]} "$(gettext "无效的选择, 请重试")"

        if [[ $rule_choice -eq 0 ]]; then
            return
        fi

        local selected_rule=${tb_all_rule_names[$((rule_choice - 1))]}

        if [[ "$selected_rule" == "country_block" ]]; then
            tb_country_menu
            continue
        fi

        local current_status=$(tb_get_rule_status "$selected_rule")
        local new_status=$([[ "$current_status" == "true" ]] && echo "false" || echo "true")
        local status_text=$([[ "$new_status" == "true" ]] && echo "$(gettext "启用")" || echo "$(gettext "禁用")")
        local display_name=$(tb_rule_display_name "$selected_rule")
        local description=$(tb_rule_description "$selected_rule")

        echo
        if [[ -n "$description" ]]; then
            log_echo "${Info} ${Green} ${description} ${Font}"
        fi
        log_echo "${GreenBG} $(gettext "是否") $status_text $display_name $(gettext "规则") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r confirm

        if [[ ! $confirm =~ ^[nN]([oO])?$ ]]; then
            tb_set_rule_status "$selected_rule" "$new_status"
            log_echo "${OK} ${GreenBG} $display_name $(gettext "规则") $status_text ${Font}"
            tb_apply_rules
        else
            log_echo "${Green} $(gettext "操作已取消") ${Font}"
        fi

    done
}

tb_build_block_rules() {
    local rules_json='[]'

    if [[ "$(tb_get_rule_status country_block)" == "true" ]]; then
        local countries_str=$(tb_get_countries)
        IFS=',' read -ra countries <<< "$countries_str"
        for code in "${countries[@]}"; do
            local rule=$(jq -n --arg c "$code" '{"type":"field","outboundTag":"blocked","domain":["geosite:" + $c]}')
            rules_json=$(echo "$rules_json" | jq --argjson r "$rule" '. += [$r]')
        done
        for code in "${countries[@]}"; do
            local rule=$(jq -n --arg c "$code" '{"type":"field","outboundTag":"blocked","ip":["geoip:" + $c]}')
            rules_json=$(echo "$rules_json" | jq --argjson r "$rule" '. += [$r]')
        done
    fi

    if [[ "$(tb_get_rule_status bittorrent)" == "true" ]]; then
        rules_json=$(echo "$rules_json" | jq --argjson rule '{"type":"field","outboundTag":"blocked","protocol":["bittorrent"]}' '. += [$rule]')
    fi

    if [[ "$(tb_get_rule_status ads)" == "true" ]]; then
        rules_json=$(echo "$rules_json" | jq --argjson rule '{"type":"field","outboundTag":"blocked","domain":["geosite:category-ads-all"]}' '. += [$rule]')
    fi

    if [[ "$(tb_get_rule_status private_ip)" == "true" ]]; then
        rules_json=$(echo "$rules_json" | jq --argjson rule '{"type":"field","outboundTag":"blocked","ip":["geoip:private"]}' '. += [$rule]')
    fi

    echo "$rules_json"
}

tb_build_direct_rule() {
    local inbound_tags
    inbound_tags=$(jq -c '[.inbounds[].tag]' "${xray_conf}" 2>/dev/null)
    if [[ -z "$inbound_tags" || "$inbound_tags" == "[]" ]]; then
        echo '{}'
        return 1
    fi
    jq -n -c --argjson tags "$inbound_tags" '{"type":"field","inboundTag":$tags,"outboundTag":"direct"}'
}

tb_update_xray_config() {
    local backup_file="${xray_conf}.traffic_blocker.bak.$$"

    if ! cp -p "${xray_conf}" "${backup_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "备份 Xray 配置失败") ${Font}"
        return 1
    fi

    if ! update_json_config "${xray_conf}" "$@"; then
        rm -f "${backup_file}"
        return 1
    fi

    if ! systemctl restart xray; then
        cp -p "${backup_file}" "${xray_conf}"
        systemctl restart xray >/dev/null 2>&1 || true
        rm -f "${backup_file}"
        log_echo "${Error} ${RedBG} Xray $(gettext "重启失败, 已恢复原配置") ${Font}"
        return 1
    fi

    rm -f "${backup_file}"
    return 0
}

tb_check_geo_files() {
    local missing_files=()
    local remote_version=""

    local needs_geoip=false
    local needs_geosite=false

    if [[ "$(tb_get_rule_status country_block)" == "true" ]] || [[ "$(tb_get_rule_status private_ip)" == "true" ]]; then
        needs_geoip=true
    fi
    if [[ "$(tb_get_rule_status country_block)" == "true" ]] || [[ "$(tb_get_rule_status ads)" == "true" ]]; then
        needs_geosite=true
    fi

    if [[ "$needs_geoip" == "true" ]] && [[ ! -f "${tb_geo_dir}/geoip.dat" ]]; then
        missing_files+=("geoip.dat")
    fi
    if [[ "$needs_geosite" == "true" ]] && [[ ! -f "${tb_geo_dir}/geosite.dat" ]]; then
        missing_files+=("geosite.dat")
    fi

    if [[ ${#missing_files[@]} -gt 0 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "缺少 GeoData 文件"): ${missing_files[*]} ${Font}"
        log_echo "${Info} ${Green} $(gettext "正在下载")... ${Font}"

        remote_version=$(tb_get_geo_remote_version)
        for file in "${missing_files[@]}"; do
            if ! tb_download_geo_file "$file" "$remote_version"; then
                return 1
            fi
        done
    fi

    if [[ -z "${remote_version:-}" ]]; then
        remote_version=$(tb_get_geo_remote_version)
    fi
    local outdated_files=()
    if [[ "$needs_geoip" == "true" ]] && [[ -f "${tb_geo_dir}/geoip.dat" ]] && tb_is_geo_outdated "geoip.dat" "$remote_version"; then
        outdated_files+=("geoip.dat")
    fi
    if [[ "$needs_geosite" == "true" ]] && [[ -f "${tb_geo_dir}/geosite.dat" ]] && tb_is_geo_outdated "geosite.dat" "$remote_version"; then
        outdated_files+=("geosite.dat")
    fi

    if [[ ${#outdated_files[@]} -gt 0 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "以下 GeoData 文件有更新可用"): ${outdated_files[*]} ${Font}"
        log_echo "${GreenBG} $(gettext "是否立即更新") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r geo_update_confirm
        if [[ ! $geo_update_confirm =~ ^[nN]([oO])?$ ]]; then
            for file in "${outdated_files[@]}"; do
                if ! tb_download_geo_file "$file" "$remote_version"; then
                    log_echo "${Error} ${RedBG} $(gettext "更新失败"): ${file} ${Font}"
                    return 1
                fi
            done
        fi
    fi

    return 0
}

tb_apply_rules() {
    if [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置文件不存在") ${Font}"
        return
    fi

    if ! jq -e '.outbounds[] | select(.tag == "blocked")' "${xray_conf}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置中缺少 blocked 出站, 无法应用阻断规则") ${Font}"
        return
    fi

    if ! jq -e '.outbounds[] | select(.tag == "direct")' "${xray_conf}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置中缺少 direct 出站, 无法应用阻断规则") ${Font}"
        return
    fi

    tb_init_config

    local has_any_enabled=false
    for rule_name in "${tb_all_rule_names[@]}"; do
        if [[ "$(tb_get_rule_status "$rule_name")" == "true" ]]; then
            has_any_enabled=true
            break
        fi
    done

    echo
    log_echo "${GreenBG} $(gettext "当前阻断规则配置"): ${Font}"
    for rule_name in "${tb_all_rule_names[@]}"; do
        local display_name=$(tb_rule_display_name "$rule_name")
        local status=$(tb_get_rule_status "$rule_name")
        if [[ "$status" == "true" ]]; then
            log_echo "  ${Green}✓${Font} $display_name"
        else
            log_echo "  ${Red}✗${Font} $display_name"
        fi
    done

    echo
    log_echo "${Warning} ${YellowBG} $(gettext "应用规则将重建路由配置, 自定义路由规则将被覆盖") ${Font}"

    if [[ "$has_any_enabled" == "true" ]]; then
        if ! tb_check_geo_files; then
            log_echo "${Error} ${RedBG} $(gettext "GeoData 下载失败, 无法应用规则") ${Font}"
            return
        fi
    fi

    local block_rules
    local direct_rule
    local new_rules
    local current_domain_strategy
    local saved_domain_strategy
    local new_domain_strategy
    local clear_saved_domain_strategy=false
    local save_domain_strategy=""

    block_rules=$(tb_build_block_rules)
    direct_rule=$(tb_build_direct_rule)
    if [[ "$direct_rule" == "{}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法从 Xray 配置中提取入站标签") ${Font}"
        return
    fi
    new_rules=$(jq -n -c --argjson block "$block_rules" --argjson direct "$direct_rule" '$block + [$direct]')
    current_domain_strategy=$(jq -r '.routing.domainStrategy // "AsIs"' "${xray_conf}" 2>/dev/null)
    saved_domain_strategy=$(tb_get_previous_domain_strategy)
    new_domain_strategy="${current_domain_strategy:-AsIs}"

    if [[ "$(tb_get_rule_status country_block)" == "true" ]] || [[ "$(tb_get_rule_status private_ip)" == "true" ]]; then
        if [[ -z "$saved_domain_strategy" ]]; then
            save_domain_strategy="${current_domain_strategy:-AsIs}"
        fi
        new_domain_strategy="IPIfNonMatch"
    elif [[ -n "$saved_domain_strategy" ]]; then
        new_domain_strategy="$saved_domain_strategy"
        clear_saved_domain_strategy=true
    fi

    if [[ -n "$save_domain_strategy" ]]; then
        tb_set_previous_domain_strategy "$save_domain_strategy"
    fi

    if ! tb_update_xray_config --argjson rules "$new_rules" --arg ds "$new_domain_strategy" \
        '.routing.rules = $rules | .routing.domainStrategy = $ds'; then
        if [[ -n "$save_domain_strategy" ]]; then
            tb_clear_previous_domain_strategy
        fi
        log_echo "${Error} ${RedBG} $(gettext "修改 Xray 配置失败") ${Font}"
        return
    fi

    if [[ "$clear_saved_domain_strategy" == "true" ]]; then
        tb_clear_previous_domain_strategy
    fi

    echo
    log_echo "${OK} ${GreenBG} $(gettext "流量阻断规则已应用") ${Font}"
    if [[ "$new_domain_strategy" == "IPIfNonMatch" ]]; then
        log_echo "${Info} ${Green} $(gettext "域名解析策略已设置为") IPIfNonMatch $(gettext "以支持基于 IP 的阻断规则") ${Font}"
    fi
}

tb_reset_rules() {
    echo
    log_echo "${Warning} ${YellowBG} $(gettext "此操作将重置所有阻断规则为禁用状态") ${Font}"
    log_echo "${GreenBG} $(gettext "确认重置") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r reset_confirm

    if [[ ! $reset_confirm =~ ^[yY]([eE][sS])?$ ]]; then
        log_echo "${Green} $(gettext "操作已取消") ${Font}"
        return
    fi

    tb_init_config

    local tmp_file="${tb_config_file}.tmp"
    jq '.country_block = [] | .bittorrent = false | .private_ip = false | .ads = false' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return; }

    if [[ -f "${xray_conf}" ]]; then
        local direct_rule
        local current_domain_strategy
        local saved_domain_strategy
        local reset_domain_strategy

        direct_rule=$(tb_build_direct_rule)
        if [[ "$direct_rule" == "{}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "无法从 Xray 配置中提取入站标签") ${Font}"
            return
        fi
        local reset_rules
        reset_rules=$(jq -n -c --argjson direct "$direct_rule" '[$direct]')
        current_domain_strategy=$(jq -r '.routing.domainStrategy // "AsIs"' "${xray_conf}" 2>/dev/null)
        saved_domain_strategy=$(tb_get_previous_domain_strategy)
        reset_domain_strategy="${saved_domain_strategy:-${current_domain_strategy:-AsIs}}"

        if ! tb_update_xray_config --argjson rules "$reset_rules" --arg ds "$reset_domain_strategy" \
            '.routing.rules = $rules | .routing.domainStrategy = $ds'; then
            log_echo "${Error} ${RedBG} $(gettext "修改 Xray 配置失败") ${Font}"
            return
        fi

        tb_clear_previous_domain_strategy
    fi

    log_echo "${OK} ${GreenBG} $(gettext "所有阻断规则已重置") ${Font}"
}

tb_check_for_updates() {
    local latest_version
    local update_choice

    latest_version=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "$tb_remote_url" 2>/dev/null | grep 'tb_SCRIPT_VERSION=' | head -n 1 | sed 's/tb_SCRIPT_VERSION="//; s/"//')
    if [ -n "$latest_version" ] && [ "$latest_version" != "$tb_SCRIPT_VERSION" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "新版本可用"): $latest_version $(gettext "当前版本"): $tb_SCRIPT_VERSION ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请访问") https://github.com/hello-yunshu/Xray_bash_onekey $(gettext "查看更新说明") ${Font}"

        log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r update_choice
        case $update_choice in
            [yY][eE][sS] | [yY])
                log_echo "${Info} ${Green} $(gettext "正在下载新版本")... ${Font}"
                if download_script_file "$tb_remote_url" "${idleleo_dir}/traffic_blocker.sh"; then
                    log_echo "${OK} ${GreenBG} $(gettext "下载完成, 正在重新加载...") ${Font}"
                    source "${idleleo_dir}/traffic_blocker.sh"
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
        log_echo "${OK} ${Green} $(gettext "当前已经是最新版本"): $tb_SCRIPT_VERSION ${Font}"
    fi
}
