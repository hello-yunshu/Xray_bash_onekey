#!/bin/bash

tb_SCRIPT_VERSION="1.7.0"
MIN_MAIN_VERSION="2.12.10"

if [ -n "$shell_version" ]; then
    oldest=$(printf '%s\n%s\n' "$MIN_MAIN_VERSION" "$shell_version" | sort -V | head -1)
    if [ "$oldest" != "$MIN_MAIN_VERSION" ]; then
        printf '%b\n' "${Error} ${RedBG} traffic_blocker.sh $(gettext "需要主脚本版本") >= ${MIN_MAIN_VERSION}, $(gettext "当前版本"): ${shell_version}, $(gettext "请先更新主脚本") ${Font}"
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
    "ads": false
}
EOF
    else
        local tmp_file="${tb_config_file}.tmp"
        # COMPAT: geo_versions 已迁移至 geo_version.json，v1.7 后删除此清理
        jq '.country_block //= [] |
            .bittorrent //= false |
            .private_ip //= false |
            .ads //= false |
            del(.geo_versions)' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
        # COMPAT_END
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

tb_preset_countries=("cn" "ru" "ir" "kp" "gb" "au" "tr")

tb_country_display_name() {
    local code="$1"
    case "$code" in
        cn) gettext "中国" ;;
        ru) gettext "俄罗斯" ;;
        ir) gettext "伊朗" ;;
        kp) gettext "朝鲜" ;;
        gb) gettext "英国" ;;
        au) gettext "澳大利亚" ;;
        tr) gettext "土耳其" ;;
        *)  echo "$code" ;;
    esac
}

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
        bittorrent)  echo "$(gettext "BT 下载阻断") (protocol:bittorrent)" ;;
        private_ip)  echo "$(gettext "私有网络阻断") (geoip:private)" ;;
        ads)         echo "$(gettext "广告域名阻断") (geosite:category-ads-all)" ;;
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
    for code in "${tb_preset_countries[@]}"; do
        local name=$(tb_country_display_name "$code")
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
        local display_name="$code - $(tb_country_display_name "$code")"
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
        log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
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
    local gv_file="${xray_conf_dir}/geo_version.json"
    if [[ ! -f "${gv_file}" ]]; then
        echo ""
        return
    fi
    local version=$(jq -r --arg name "$file_name" '.geo_versions[$name] // ""' "${gv_file}" 2>/dev/null)
    echo "${version}"
}

tb_geo_updater_path() {
    printf '%s\n' "${scripts_dir:-${idleleo_dir}/scripts}/geo_update.sh"
}

# The native path lives in the Xray config. Its presence means Xray itself owns
# the schedule, so this script must not install a second automation.
tb_geo_native_cron() {
    [[ -f "${xray_conf}" ]] || return 1
    local cron
    cron=$(jq -r '.geodata.cron // empty' "${xray_conf}" 2>/dev/null) || return 1
    [[ -n "${cron}" ]] || return 1
    printf '%s\n' "${cron}"
}

# Every native asset must be an HTTPS URL naming a plain file; anything else is
# a configuration this menu cannot reason about.
tb_geo_native_assets_ok() {
    [[ -f "${xray_conf}" ]] || return 1
    jq -e '(.geodata.assets // []) as $a
        | ($a | length) > 0
        and ($a | all(.[]; (.url | type == "string") and (.url | startswith("https://")) and (.file | type == "string")))' \
        "${xray_conf}" >/dev/null 2>&1
}

# Only the cron lines this project created are recognised: the command must
# point at the managed geo_update.sh path.
tb_geo_legacy_cron_lines() {
    command -v crontab >/dev/null 2>&1 || return 1
    local updater
    updater=$(tb_geo_updater_path)
    crontab -l 2>/dev/null | awk -v script="${updater}" 'index($0, script) > 0'
}

tb_geo_native_file_state() {
    local file_path="$1" now newest
    [[ -f "${file_path}" ]] || { printf '%s\n' missing; return 0; }
    now=$(date +%s)
    newest=$(tb_get_geo_file_date "${file_path}")
    if (( now - newest <= 604800 )); then
        printf '%s\n' recent
    elif (( now - newest <= 2592000 )); then
        printf '%s\n' pending
    else
        printf '%s\n' stale
    fi
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

tb_get_previous_sniffing() {
    if [[ ! -f "${tb_config_file}" ]]; then
        echo ""
        return
    fi
    jq -r '.previous_sniffing // ""' "${tb_config_file}" 2>/dev/null
}

tb_set_previous_sniffing() {
    local sniffing_json="$1"
    if [[ ! -f "${tb_config_file}" ]]; then
        tb_init_config
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq --argjson sn "$sniffing_json" '.previous_sniffing = $sn' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_clear_previous_sniffing() {
    if [[ ! -f "${tb_config_file}" ]]; then
        return
    fi
    local tmp_file="${tb_config_file}.tmp"
    jq 'del(.previous_sniffing)' "${tb_config_file}" > "${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${tb_config_file}" || { rm -f "${tmp_file}"; return 1; }
}

tb_save_current_sniffing() {
    local saved_sniffing
    saved_sniffing=$(tb_get_previous_sniffing)
    [[ -n "$saved_sniffing" ]] && return
    local current_sniffing
    current_sniffing=$(jq -c '[.inbounds[] | {tag: .tag, sniffing: (.sniffing // null)}]' "${xray_conf}" 2>/dev/null)
    if [[ -n "$current_sniffing" && "$current_sniffing" != "[]" ]]; then
        tb_set_previous_sniffing "$current_sniffing"
    fi
}

tb_build_sniffing_restore_filter() {
    local saved_sniffing="$1"
    local filter=""
    local i=0
    local count
    count=$(echo "$saved_sniffing" | jq 'length' 2>/dev/null)
    while [[ $i -lt $count ]]; do
        local tag val part
        tag=$(echo "$saved_sniffing" | jq -r ".[$i].tag" 2>/dev/null)
        val=$(echo "$saved_sniffing" | jq -c ".[$i].sniffing" 2>/dev/null)
        if [[ "$val" == "null" ]]; then
            part="(.inbounds[] | select(.tag == \"${tag}\")) |= del(.sniffing)"
        else
            part="(.inbounds[] | select(.tag == \"${tag}\")).sniffing = \$sniffing_${i}"
        fi
        if [[ -n "$filter" ]]; then
            filter="${filter} | ${part}"
        else
            filter="${part}"
        fi
        i=$((i + 1))
    done
    echo "$filter"
}

tb_build_sniffing_restore_args() {
    local saved_sniffing="$1"
    local i=0
    local count
    count=$(echo "$saved_sniffing" | jq 'length' 2>/dev/null)
    while [[ $i -lt $count ]]; do
        local val
        val=$(echo "$saved_sniffing" | jq -c ".[$i].sniffing" 2>/dev/null)
        if [[ "$val" != "null" ]]; then
            tb_sniffing_args+=("--argjson" "sniffing_${i}" "$val")
        fi
        i=$((i + 1))
    done
}

tb_get_geo_file_date() {
    local file_path="$1"
    if [[ -f "$file_path" ]]; then
        stat -c %Y "$file_path" 2>/dev/null
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
    date -d "@${timestamp}" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "$(gettext "未知")"
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
    local file_name="$1" updater
    [[ -n "${file_name}" ]] || return 1
    if ! tb_geo_ensure_updater; then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 手动刷新脚本下载失败") ${Font}"
        return 1
    fi
    updater=$(tb_geo_updater_path)
    # All refresh paths share the same checksum-verified transaction and update
    # lock. The updater installs both files from one immutable release even
    # when the user picked a single file.
    bash "${updater}"
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

    local total_w=$((name_w + status_w + 7))

    tb_table_line "$total_w"
    printf "| "; tb_pad "$header_name" "$name_w"; printf " | "; tb_pad "$header_status" "$status_w"; printf " |\n"
    tb_table_line "$total_w"

    for ((index=1; index<=${#names[@]}; index++)); do
        printf "| "; tb_pad "${names[$index]}" "$name_w"; printf " | "; tb_pad "${statuses[$index]}" "$status_w"; printf " |\n"
    done

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
        echo -e "${Green}3.${Font} $(gettext "刷新 GeoData")"
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

tb_display_geo_native_summary() {
    local cron="$1" name path state date_text needs_help=false

    log_echo "${Green} $(gettext "GeoData 状态"): ${Font}${Green}$(gettext "由 Xray 原生 geodata 自动刷新")${Font}"
    log_echo "  $(gettext "自动刷新计划"): ${cron} ($(gettext "本地时区, 不重启 Xray"))"

    for name in geoip.dat geosite.dat; do
        path="${tb_geo_dir}/${name}"
        state=$(tb_geo_native_file_state "${path}")
        date_text=$(tb_format_date "$(tb_get_geo_file_date "${path}")")
        case "${state}" in
            missing)
                needs_help=true
                log_echo "  ${name}: ${Red}$(gettext "未安装")${Font} (${path})"
                ;;
            recent)
                log_echo "  ${name}: ${Green}$(gettext "已安装")${Font} ($(gettext "最后刷新"): ${date_text})"
                ;;
            pending)
                log_echo "  ${name}: ${Yellow}$(gettext "待执行")${Font} ($(gettext "最后刷新"): ${date_text})"
                ;;
            *)
                needs_help=true
                log_echo "  ${name}: ${Red}$(gettext "异常")${Font} ($(gettext "最后刷新"): ${date_text})"
                ;;
        esac
    done

    if ! tb_geo_native_assets_ok; then
        needs_help=true
        log_echo "  ${Red}$(gettext "配置异常: geodata.assets 缺少有效的 HTTPS 下载地址")${Font}"
    fi

    # Xray keeps the outcome of its own job internal and writes no success
    # record this script could read. Report the configuration and the real file
    # state instead of claiming a run succeeded.
    log_echo "  ${Info}${Green} $(gettext "说明: 这里只反映配置与文件现状, 不代表某次自动刷新已成功") ${Font}"
    if [[ "${needs_help}" == "true" ]]; then
        log_echo "  ${Info}${Yellow} $(gettext "可在此菜单手动刷新, 或检查") ${tb_geo_dir} $(gettext "与 Xray 错误日志") ${Font}"
    fi
}

tb_display_geo_summary() {
    local native_cron legacy_lines
    if native_cron=$(tb_geo_native_cron); then
        tb_display_geo_native_summary "${native_cron}"
        if legacy_lines=$(tb_geo_legacy_cron_lines) && [[ -n "${legacy_lines}" ]]; then
            log_echo "  ${Warning}${YellowBG} $(gettext "发现脚本安装的 geo_update.sh 周期任务, 与原生自动刷新重复") ${Font}"
            echo "${legacy_lines}"
        fi
        tb_geo_show_migration_failure
        return 0
    fi

    if legacy_lines=$(tb_geo_legacy_cron_lines) && [[ -n "${legacy_lines}" ]]; then
        log_echo "${Green} $(gettext "GeoData 状态"): ${Font}${Yellow}$(gettext "由 geo_update.sh 脚本定时刷新 (待迁移)")${Font}"
        echo "  ${legacy_lines}"
    else
        log_echo "${Green} $(gettext "GeoData 状态"): ${Font}${Warning}$(gettext "未启用自动刷新")${Font}"
    fi
    tb_geo_show_migration_failure

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
            log_echo "  geoip.dat:  ${Yellow}$(gettext "有新版本可用")${Font} ($(gettext "本地版本"): ${geoip_version:-$(gettext "未知")}, $(gettext "刷新时间"): ${geoip_date})"
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
            log_echo "  geosite.dat: ${Yellow}$(gettext "有新版本可用")${Font} ($(gettext "本地版本"): ${geosite_version:-$(gettext "未知")}, $(gettext "刷新时间"): ${geosite_date})"
        else
            log_echo "  geosite.dat: ${Green}$(gettext "已是最新")${Font} (${geosite_version:-$(gettext "未知")}, ${geosite_date})"
        fi
    else
        log_echo "  geosite.dat: ${Red}$(gettext "未安装")${Font}"
    fi
}

# GeoData migration has exactly two entry points: the startup hook in install.sh
# and this menu. `-u` itself intentionally does not migrate in the same run.
tb_geo_migration_failure_file="${idleleo_dir}/geodata_migration.failed"

tb_geo_migration_failure_text() {
    local reason time text
    [[ -f "${tb_geo_migration_failure_file}" ]] || return 1
    reason=$(sed -n 's/^reason=//p' "${tb_geo_migration_failure_file}" 2>/dev/null | head -n 1)
    time=$(sed -n 's/^time=//p' "${tb_geo_migration_failure_file}" 2>/dev/null | head -n 1)
    case "${reason}" in
        invalid_config) text=$(gettext "Xray 配置无法解析") ;;
        layout) text=$(gettext "GeoData 目录迁移失败") ;;
        native_enable) text=$(gettext "自动刷新启用失败") ;;
        native_state) text=$(gettext "自动刷新配置未生效") ;;
        restart) text=$(gettext "Xray 重启失败，已回滚") ;;
        recovery_required) text=$(gettext "回滚后服务仍未恢复，需要人工处理") ;;
        cron_cleanup) text=$(gettext "旧 cron 移除失败") ;;
        snapshot) text=$(gettext "迁移前配置快照失败") ;;
        *) text=$(gettext "未知原因") ;;
    esac
    printf '%s|%s\n' "${text}" "${time}"
}

tb_geo_show_migration_failure() {
    local detail text time
    detail=$(tb_geo_migration_failure_text) || return 0
    text=${detail%%|*}
    time=${detail#*|}
    log_echo "  ${Warning}${YellowBG} $(gettext "上次切换自动刷新失败"): ${text} (${time}) ${Font}"
}

tb_geo_remove_legacy_cron() {
    local lines updater
    if ! lines=$(tb_geo_legacy_cron_lines); then
        log_echo "${Warning} ${YellowBG} $(gettext "无法读取 crontab, 请手动检查") ${Font}"
        return 1
    fi
    if [[ -z "${lines}" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "没有找到本项目创建的 geo_update.sh 周期任务") ${Font}"
        return 0
    fi
    updater=$(tb_geo_updater_path)
    crontab -l 2>/dev/null | awk -v script="${updater}" 'index($0, script) == 0' | crontab - || return 1
    log_echo "${OK} ${GreenBG} $(gettext "已移除旧的 geo_update.sh 周期任务; 手动刷新脚本保留") ${Font}"
    declare -F judge >/dev/null 2>&1 && judge -r "$(gettext "移除旧的 GeoData 周期任务")"
    return 0
}

tb_geo_cron_description() {
    case "${1:-}" in
        "0 3 * * 1") gettext "每周一 03:00" ;;
        "0 3 * * *") gettext "每天 03:00" ;;
        "0 0 * * *") gettext "每天 00:00" ;;
        *) gettext "按配置的调度" ;;
    esac
}

# One-line state header printed before the GeoData menu and before every
# manual refresh. It answers "is automatic refresh on?" without making the
# user read file timestamps or guess from cron lines.
tb_geo_state_header() {
    local state="" cron legacy_lines detail text time
    if declare -F geodata_state >/dev/null 2>&1; then
        state=$(geodata_state)
    fi
    log_echo "${Green} $(gettext "自动刷新状态") ${Font}"
    case "${state}" in
        invalid)
            log_echo "  ${Warning}${YellowBG} $(gettext "[配置不可解析] Xray 配置无法读取, 无法确认自动刷新状态; 请先修复 config.json 后重试") ${Font}"
            ;;
        custom)
            log_echo "  ${Info}${Green} $(gettext "[自定义 geodata] 已跳过本项目托管, 不会自动接管; 现有配置保持不变") ${Font}"
            ;;
        *)
            if cron=$(tb_geo_native_cron); then
                log_echo "  ${Green}$(gettext "[自动刷新已开启] Xray 原生自动刷新:") ${cron} ($(tb_geo_cron_description "${cron}")), $(gettext "无需手动操作")${Font}"
            elif legacy_lines=$(tb_geo_legacy_cron_lines 2>/dev/null) && [[ -n "${legacy_lines}" ]]; then
                log_echo "  ${Warning}${YellowBG} $(gettext "[自动刷新未开启] 当前由 geo_update.sh 脚本定时刷新 (待迁移); 建议在本菜单启用 Xray 原生自动刷新") ${Font}"
            else
                log_echo "  ${Warning}${YellowBG} $(gettext "[自动刷新未开启] 当前不会自动刷新; 可在本菜单启用 Xray 原生定时刷新") ${Font}"
            fi
            ;;
    esac
    if detail=$(tb_geo_migration_failure_text); then
        text=${detail%%|*}
        time=${detail#*|}
        log_echo "  ${Warning}${YellowBG} $(gettext "[自动刷新开启失败]") ${text} (${time}), $(gettext "旧刷新任务与现有配置已保留, 可在此重试") ${Font}"
    fi
}

tb_geo_manual_refresh_intro() {
    local cron
    if cron=$(tb_geo_native_cron); then
        log_echo "${Info} ${Green} $(gettext "当前为自动刷新状态") (${cron}, $(tb_geo_cron_description "${cron}")), $(gettext "本次为手动补刷一次") ${Font}"
    else
        log_echo "${Info} ${Green} $(gettext "当前未开启自动刷新, 本次仅刷新一次, 不会创建定时任务") ${Font}"
    fi
}

tb_geo_manual_refresh_finish() {
    local rc="$1"
    if [[ "${rc}" -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 手动刷新失败") (rc=${rc}); $(gettext "config.json 未改动, 未创建定时任务; 现有数据已保留或由脚本回滚; 详情见") ${idleleo_dir}/logs/geo_update.log ${Font}"
        return "${rc}"
    fi
    log_echo "${OK} ${GreenBG} $(gettext "GeoData 手动刷新完成; 写入位置"): ${tb_geo_dir} ${Font}"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xray 2>/dev/null; then
        log_echo "${Info} ${Green} $(gettext "Xray 正在运行, 脚本已重启 Xray 以加载新 GeoData") ${Font}"
    else
        log_echo "${Info} ${Green} $(gettext "Xray 未运行, 未执行重启; 下次启动时加载新 GeoData") ${Font}"
    fi
}

tb_geo_ensure_updater() {
    local updater remote
    updater=$(tb_geo_updater_path)
    [[ -f "${updater}" ]] && return 0
    remote="${geo_remote_url:-}"
    if [[ -z "${remote}" && -n "${shell_version:-}" ]]; then
        remote="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/v${shell_version}/scripts/geo_update.sh"
    fi
    [[ -n "${remote}" ]] || return 1
    declare -F download_script_file >/dev/null 2>&1 || return 1
    download_script_file "${remote}" "${updater}"
}

tb_geo_run_manual_update() {
    local updater rc
    if ! tb_geo_ensure_updater; then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 手动刷新脚本下载失败") ${Font}"
        return 1
    fi
    updater=$(tb_geo_updater_path)
    tb_geo_manual_refresh_intro
    log_echo "${Info} ${Green} $(gettext "正在运行 geo_update.sh")... ${Font}"
    bash "${updater}"
    rc=$?
    tb_geo_manual_refresh_finish "${rc}"
    return "${rc}"
}

tb_geo_migrate_to_native() {
    local installer rc
    echo
    if declare -F geodata_migrate_legacy >/dev/null 2>&1; then
        geodata_migrate_legacy
        rc=$?
    else
        installer="${idleleo:-${idleleo_dir}/install.sh}"
        if [[ ! -f "${installer}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "找不到主脚本, 无法执行迁移") ${Font}"
            return 1
        fi
        bash "${installer}" --internal-geodata-migrate-legacy
        rc=$?
    fi
    if [[ ${rc} -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "已从手动/脚本模式切换为自动刷新 (Xray 原生)") ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "自动刷新启用未完成, 旧刷新任务已保留") ${Font}"
        tb_geo_show_migration_failure
    fi
    return "${rc}"
}

tb_geo_try_migrate_from_menu() {
    local native_cron legacy_lines state
    if native_cron=$(tb_geo_native_cron); then
        log_echo "${Info} ${Green} $(gettext "已是自动刷新状态, 无需迁移") ${Font}"
        return 0
    fi
    if ! legacy_lines=$(tb_geo_legacy_cron_lines) || [[ -z "${legacy_lines}" ]]; then
        log_echo "${Info} ${Green} $(gettext "未检测到项目创建的旧版脚本 cron, 跳过自动迁移") ${Font}"
        return 0
    fi
    if declare -F geodata_state >/dev/null 2>&1; then
        state=$(geodata_state)
        case "${state}" in
            custom)
                log_echo "${Info} ${Green} $(gettext "检测到自定义 geodata 配置, 跳过自动迁移") ${Font}"
                return 0
                ;;
            invalid)
                log_echo "${Warning} ${YellowBG} $(gettext "Xray 配置无法解析, 跳过自动迁移") ${Font}"
                return 0
                ;;
        esac
    fi
    if ! declare -F geodata_migrate_legacy >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "当前菜单无法调用主脚本迁移逻辑, 请重新运行主脚本") ${Font}"
        return 1
    fi
    log_echo "${Info} ${Green} $(gettext "检测到旧 geo_update.sh 脚本体系, 正在尝试切换为 Xray 原生自动刷新")... ${Font}"
    if geodata_migrate_legacy; then
        log_echo "${OK} ${GreenBG} $(gettext "已从手动/脚本模式切换为自动刷新 (Xray 原生)") ${Font}"
        return 0
    fi
    log_echo "${Warning} ${YellowBG} $(gettext "自动刷新启用失败, 旧刷新任务与现有配置已保留") ${Font}"
    tb_geo_show_migration_failure
    return 1
}

tb_geo_rescue_menu() {
    local choice
    while true; do
        echo
        log_echo "${Green} $(gettext "GeoData 自动刷新与手动刷新") ${Font}"
        tb_geo_state_header
        log_echo "${Info} ${Green} $(gettext "脚本定时模式已停用; 手动刷新不会创建定时任务") ${Font}"
        echo
        echo "1. $(gettext "立即启用 Xray 原生自动刷新 (已是则跳过)")"
        echo "2. $(gettext "手动刷新 GeoData (运行 geo_update.sh 一次)")"
        echo "3. $(gettext "移除旧的 geo_update.sh 周期任务")"
        echo "4. $(gettext "返回")"
        read_optimize "$(gettext "请选择一个选项"):" choice "" 1
        case "${choice}" in
            1) tb_geo_migrate_to_native ;;
            2) tb_geo_run_manual_update ;;
            3) tb_geo_remove_legacy_cron ;;
            4) return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done
}

# Backward-compatible name; it no longer installs a cron entry.
tb_geo_auto_update() {
    tb_geo_rescue_menu
}

tb_geo_menu() {
    # Only the first entry into this menu attempts migration. A failure keeps
    # the old cron and the user can retry from the explicit rescue submenu.
    local _header_pending=1
    if [[ "${_tb_geo_menu_migration_attempted:-0}" != "1" ]]; then
        _tb_geo_menu_migration_attempted=1
        # Show the state before the automatic migration, then let its output
        # state the outcome ("already automatic" / "switched" / "kept the old
        # task"). This makes the before/after comparison explicit.
        tb_geo_state_header
        echo
        tb_geo_try_migrate_from_menu
        echo
        _header_pending=0
    fi
    while true; do
        echo
        echo -e "${Green} $(gettext "刷新 GeoData") ${Font}"
        echo
        # The pre-migration header was just printed in this frame; later frames
        # (and later menu entries) print it again so state is never hidden.
        if [[ "${_header_pending}" == "1" ]]; then
            tb_geo_state_header
            echo
        fi
        _header_pending=1
        tb_display_geo_summary
        echo
        echo "1. $(gettext "手动刷新全部 GeoData")"
        echo "2. $(gettext "手动刷新") geoip.dat"
        echo "3. $(gettext "手动刷新") geosite.dat"
        echo "4. $(gettext "自动刷新与手动刷新")"
        echo "5. $(gettext "返回")"
        local geo_choice
        read_optimize "$(gettext "请选择一个选项"):" geo_choice "" 1
        case $geo_choice in
            1) tb_update_all_geo ;;
            2) tb_update_geo_file "geoip.dat" ;;
            3) tb_update_geo_file "geosite.dat" ;;
            4) tb_geo_rescue_menu ;;
            5) return ;;
            *)
                echo
                log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
                ;;
        esac
    done
}

tb_update_all_geo() {
    local rc
    echo
    tb_geo_manual_refresh_intro
    log_echo "${Info} ${Green} $(gettext "正在手动刷新全部 GeoData")... ${Font}"
    tb_download_geo_file geoip.dat
    rc=$?
    tb_geo_manual_refresh_finish "${rc}"
    return "${rc}"
}

tb_update_geo_file() {
    local file_name="$1" rc

    echo
    tb_geo_manual_refresh_intro
    log_echo "${Info} ${Green} ${file_name} $(gettext "正在手动刷新")... ${Font}"
    tb_download_geo_file "${file_name}"
    rc=$?
    tb_geo_manual_refresh_finish "${rc}"
    [[ "${rc}" -eq 0 ]] || return "${rc}"
    local new_version
    new_version=$(tb_get_geo_local_version "${file_name}")
    log_echo "${OK} ${GreenBG} ${file_name} $(gettext "已刷新至"): ${new_version} ${Font}"
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
            log_echo "${OK} ${GreenBG} ${description} ${Font}"
        fi
        log_echo "${GreenBG} $(gettext "是否") $status_text $display_name $(gettext "规则") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r confirm

        if [[ ! $confirm =~ ^[nN]([oO])?$ ]]; then
            tb_set_rule_status "$selected_rule" "$new_status"
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
        log_echo "${Warning} ${YellowBG} $(gettext "以下 GeoData 文件有新版本可用"): ${outdated_files[*]} ${Font}"
        log_echo "${GreenBG} $(gettext "是否立即手动刷新") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r geo_update_confirm
        if [[ ! $geo_update_confirm =~ ^[nN]([oO])?$ ]]; then
            for file in "${outdated_files[@]}"; do
                if ! tb_download_geo_file "$file" "$remote_version"; then
                    log_echo "${Error} ${RedBG} $(gettext "刷新失败"): ${file} ${Font}"
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
    local needs_sniffing=false
    local clear_saved_sniffing=false

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

    if [[ "$(tb_get_rule_status bittorrent)" == "true" ]] || [[ "$(tb_get_rule_status country_block)" == "true" ]] || [[ "$(tb_get_rule_status ads)" == "true" ]]; then
        needs_sniffing=true
    fi

    local sniffing_jq_filter=""
    if [[ "$needs_sniffing" == "true" ]]; then
        tb_save_current_sniffing
        sniffing_jq_filter='.inbounds[].sniffing = {"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}'
    else
        local saved_sniffing
        saved_sniffing=$(tb_get_previous_sniffing)
        if [[ -n "$saved_sniffing" ]]; then
            sniffing_jq_filter=$(tb_build_sniffing_restore_filter "$saved_sniffing")
            clear_saved_sniffing=true
        fi
    fi

    if [[ -n "$save_domain_strategy" ]]; then
        tb_set_previous_domain_strategy "$save_domain_strategy"
    fi

    local update_filter='.routing.rules = $rules | .routing.domainStrategy = $ds'
    local update_args=(--argjson rules "$new_rules" --arg ds "$new_domain_strategy")
    if [[ -n "$sniffing_jq_filter" ]]; then
        if [[ "$clear_saved_sniffing" == "true" ]]; then
            local saved_sniffing
            saved_sniffing=$(tb_get_previous_sniffing)
            tb_sniffing_args=()
            tb_build_sniffing_restore_args "$saved_sniffing"
            update_args+=("${tb_sniffing_args[@]}")
        fi
        update_filter="${update_filter} | ${sniffing_jq_filter}"
    fi

    if ! tb_update_xray_config "${update_args[@]}" "$update_filter"; then
        if [[ -n "$save_domain_strategy" ]]; then
            tb_clear_previous_domain_strategy
        fi
        if [[ "$needs_sniffing" == "true" ]]; then
            tb_clear_previous_sniffing
        fi
        log_echo "${Error} ${RedBG} $(gettext "修改 Xray 配置失败") ${Font}"
        return
    fi

    if [[ "$clear_saved_domain_strategy" == "true" ]]; then
        tb_clear_previous_domain_strategy
    fi
    if [[ "$clear_saved_sniffing" == "true" ]]; then
        tb_clear_previous_sniffing
    fi

    echo
    log_echo "${OK} ${GreenBG} $(gettext "流量阻断规则") $(gettext "已应用") ${Font}"
    log_echo "${OK} ${GreenBG} Xray $(gettext "已重启") ${Font}"
    if [[ "$new_domain_strategy" == "IPIfNonMatch" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "域名解析策略") $(gettext "已应用") ${Font}"
    fi
    if [[ "$needs_sniffing" == "true" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "协议嗅探") $(gettext "已应用") ${Font}"
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
        local saved_sniffing
        local reset_sniffing_filter=""

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

        saved_sniffing=$(tb_get_previous_sniffing)
        if [[ -n "$saved_sniffing" ]]; then
            reset_sniffing_filter=$(tb_build_sniffing_restore_filter "$saved_sniffing")
        fi

        local reset_filter='.routing.rules = $rules | .routing.domainStrategy = $ds'
        if [[ -n "$reset_sniffing_filter" ]]; then
            reset_filter="${reset_filter} | ${reset_sniffing_filter}"
        fi
        local reset_args=(--argjson rules "$reset_rules" --arg ds "$reset_domain_strategy")
        if [[ -n "$saved_sniffing" ]]; then
            tb_sniffing_args=()
            tb_build_sniffing_restore_args "$saved_sniffing"
            reset_args+=("${tb_sniffing_args[@]}")
        fi

        if ! tb_update_xray_config "${reset_args[@]}" "$reset_filter"; then
            log_echo "${Error} ${RedBG} $(gettext "修改 Xray 配置失败") ${Font}"
            return
        fi

        tb_clear_previous_domain_strategy
        if [[ -n "$saved_sniffing" ]]; then
            tb_clear_previous_sniffing
        fi
    fi

    log_echo "${OK} ${GreenBG} $(gettext "所有阻断规则") $(gettext "已重置") ${Font}"
    if [[ -f "${xray_conf}" ]]; then
        log_echo "${OK} ${GreenBG} Xray $(gettext "已重启") ${Font}"
        if [[ "$reset_domain_strategy" != "IPIfNonMatch" ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "域名解析策略") $(gettext "已恢复") ${Font}"
        fi
        if [[ -n "$saved_sniffing" ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "协议嗅探") $(gettext "已恢复") ${Font}"
        fi
    fi
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
                if download_script_file "$tb_remote_url" "${scripts_dir}/traffic_blocker.sh"; then
                    log_echo "${OK} ${GreenBG} $(gettext "下载完成, 正在重新加载...") ${Font}"
                    source "${scripts_dir}/traffic_blocker.sh"
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
