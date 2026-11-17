set -u
log_echo() { :; }
gettext() { printf "%s" "$1"; }
judge() { :; }
Error=""; RedBG=""; Font=""; OK=""; GreenBG=""; Warning=""; YellowBG=""
is_ws_mode() { return 0; }
is_grpc_mode() { return 0; }
is_xhttp_mode() { return 0; }
resolve_ws_backend_listen_addr() { printf '127.0.0.1'; }
update_json_config() {
    local config_file="$1"
    shift
    if [[ -z "${config_file}" ]] || [[ $# -eq 0 ]]; then
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "参数不能为空") ${Font}"
        return 1
    fi
    if [[ ! -f "${config_file}" ]]; then
        log_echo "${Error} ${RedBG} update_json_config: ${config_file} $(gettext "文件不存在") ${Font}"
        return 1
    fi

    local original_mode original_uid original_gid tmp_file _old_umask
    original_mode=$(stat -c '%a' "${config_file}" 2>/dev/null) || return 1
    original_uid=$(stat -c '%u' "${config_file}" 2>/dev/null) || return 1
    original_gid=$(stat -c '%g' "${config_file}" 2>/dev/null) || return 1
    # Use mktemp for unpredictable temp file name (same directory = same filesystem for atomic mv)
    tmp_file=$(mktemp "${config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${config_file}.tmp.$$"

    # Restrictive umask before writing sensitive content (UUID/privateKey/shortIds etc.)
    _old_umask=$(umask)
    umask 077

    if ! jq "$@" "${config_file}" > "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        return 1
    fi
    # Validate generated JSON before replacing original (fail closed on corruption)
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "生成的 JSON 无效，已保留原文件"): ${config_file} ${Font}"
        return 1
    fi
    if ! chmod "${original_mode}" "${tmp_file}" || ! chown "${original_uid}:${original_gid}" "${tmp_file}"; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${config_file} ${Font}"
        return 1
    fi
    umask "${_old_umask}"
    if ! mv "${tmp_file}" "${config_file}"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ "${config_file}" == "${xray_install_config_file}" ]]; then
        info_extraction_all=$(jq -rc . "${config_file}" 2>/dev/null) || return 1
        declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    fi
    return 0
}

modify_listen_address() {
    local listen_addr="0.0.0.0"
    if [[ ${tls_mode} == "TLS" ]]; then
        listen_addr="127.0.0.1"
    elif [[ ${tls_mode} == "None" ]]; then
        listen_addr="$(resolve_ws_backend_listen_addr)"
        log_echo "${Warning} ${YellowBG} $(gettext "无传输层加密的后端入站监听地址"): ${listen_addr} ${Font}"
    fi

    if is_ws_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-ws-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_grpc_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_xhttp_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
}

modify_inbound_port() {
    local _port_failed=0
    if [[ ${tls_mode} == "Reality" ]]; then
        if [[ ${reality_add_nginx} == "off" ]]; then
            update_json_config "${xray_conf}" --argjson port "${port:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-Reality-in")).port = $port' || _port_failed=1
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        else
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        fi
    else
        if is_ws_mode; then
            update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
        fi
        if is_grpc_mode; then
            update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
        fi
        if is_xhttp_mode; then
            update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
        fi
    fi
    if [[ ${_port_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray inbound port $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Xray inbound port $(gettext "修改") $(gettext "完成") ${Font}"
}

add_ws_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local ws_port="${2:-10086}"
    local ws_path="${3:-/ray/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${ws_port:-0}" \
       --arg path "${ws_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-ws-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "ws@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "ws",
               "security": "none",
               "wsSettings": {"path": $path}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-ws-in"]'
}

add_grpc_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local grpc_port="${2:-10087}"
    local grpc_service="${3:-grpc}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${grpc_port:-0}" \
       --arg serviceName "${grpc_service}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-gRPC-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "me@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "grpc",
               "security": "none",
               "grpcSettings": {"serviceName": $serviceName, "multiMode": true, "idle_timeout": 20}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-gRPC-in"]'
}

add_xhttp_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local xhttp_port="${2:-10088}"
    local xhttp_path="${3:-xhttp}"
    xhttp_path="/${xhttp_path#/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${xhttp_port:-0}" \
       --arg xhttp_path "${xhttp_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-xhttp-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "xhttp@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "xhttp",
               "security": "none",
               "xhttpSettings": {"path": $xhttp_path, "mode": "auto"}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-xhttp-in"]'
}

modify_path() {
    local _path_failed=0
    is_ws_mode && { update_json_config "${xray_conf}" --arg ws_path "/${path}" \
       '(.inbounds[] | select(.tag == "VLESS-ws-in")).streamSettings.wsSettings.path = $ws_path' || _path_failed=1; }
    is_grpc_mode && { update_json_config "${xray_conf}" --arg serviceName "${serviceName}" \
       '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).streamSettings.grpcSettings.serviceName = $serviceName' || _path_failed=1; }
    is_xhttp_mode && { update_json_config "${xray_conf}" --arg xhttp_path "/${xhttppath#/}" \
       '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).streamSettings.xhttpSettings.path = $xhttp_path' || _path_failed=1; }
    if [[ ${_path_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    if [[ ${tls_mode} == "Reality" ]] && [[ "$reality_add_more" == "off" ]]; then
        log_echo "${Warning} ${YellowBG} Reality $(gettext "不支持") path ${Font}"
    else
        log_echo "${OK} ${GreenBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "完成") ${Font}"
    fi
}

xray_conf="$WORK/config.json"
xray_install_config_file="$WORK/config.json"
tls_mode="TLS"
reality_add_nginx="on"
reality_add_more="off"
port=19999
xport=12443
gport=12444
xhttpport=12445
path="ray/"
serviceName="idleleo-grpc"
xhttppath="xhttp"
add_grpc_inbound 127.0.0.1 "$gport" "$serviceName"
add_xhttp_inbound 127.0.0.1 "$xhttpport" "$xhttppath"
jq --arg id "bbbbbbbb-2222-4222-8222-222222222222" '.inbounds[].settings.clients[].id = $id' "$xray_conf" > "$xray_conf.tmp" && mv "$xray_conf.tmp" "$xray_conf"
jq '.inbounds[].listen = "0.0.0.0"' "$xray_conf" > "$xray_conf.tmp" && mv "$xray_conf.tmp" "$xray_conf"
modify_listen_address
modify_inbound_port
modify_path
