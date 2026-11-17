set -u
judge(){ :; }
log_echo(){ :; }
gettext(){ printf '%s' "$1"; }
sni_guard_port_conflicts(){ return 1; }
OK=""; Error=""; RedBG=""; GreenBG=""; Font=""; Warning=""; YellowBG=""
xray_install_config_file=""
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
is_ws_mode() {
    [[ ${transport_mode} == *ws* ]]
}
is_grpc_mode() {
    [[ ${transport_mode} == *gRPC* ]]
}
is_xhttp_mode() {
    [[ ${transport_mode} == *xhttp* ]]
}
apply_install_profile() {
    case "${install_profile}" in
        reality_nginx)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="on"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Nginx+Reality"
            ;;
        reality_standard)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Reality"
            ;;
        reality_transport)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_transport_nginx)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="on"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_balance_primary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="on"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="primary"
            shell_mode="Nginx+Reality+Balance"
            ;;
        reality_balance_secondary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="off"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="secondary"
            shell_mode="Reality+Balance"
            ;;
        transport_nginx_tls)
            tls_mode="TLS"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        transport_only)
            tls_mode="None"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "未知的安装配置") ${Font}"
            return 1
            ;;
    esac
    return 0
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
is_reality_reserved_port() {
    case "$1" in
        9403|9404|9443|9444) return 0 ;;
        *) return 1 ;;
    esac
}
reality_reserved_port_conflict() {
    local configured_port
    for configured_port in "${port:-}" "${xport:-}" "${gport:-}" "${xhttpport:-}"; do
        if [[ -n "${configured_port}" ]] && is_reality_reserved_port "${configured_port}"; then
            echo "${configured_port}"
            return 0
        fi
    done
    return 1
}
validate_reality_reserved_ports() {
    local conflicting_port
    if conflicting_port=$(reality_reserved_port_conflict); then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${conflicting_port} ${Font}"
        return 1
    fi
    return 0
}
_validate_serverNames_fragment() {
    local _f="$1"
    local _bad
    _bad=$(grep -vE '^[[:space:]]*$' "${_f}" 2>/dev/null |
        grep -vE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*[[:space:]]+[A-Za-z0-9_-]+;$' 2>/dev/null)
    [[ -z "${_bad}" ]]
}
_cleanup_stale_serverNames_fragments() {
    local _frag
    [[ -d "${nginx_conf_dir}" ]] || return 0
    for _frag in "${nginx_conf_dir}"/*.serverNames; do
        [[ -f "${_frag}" ]] || continue
        [[ "$(basename "${_frag}")" == "${serverNames}.serverNames" ]] && continue
        if ! _validate_serverNames_fragment "${_frag}"; then
            log_echo "${Warning} ${YellowBG} $(gettext "自愈: 移除损坏的旧 serverNames 配置") ${_frag} ${Font}"
            rm -f "${_frag}"
        fi
    done
    return 0
}
nginx_reality_servers_add () {
    touch "${nginx_conf_dir}"/127.0.0.1.realityServers
    cat >"${nginx_conf_dir}"/127.0.0.1.realityServers <<EOF
server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;
EOF
    judge "Nginx servers $(gettext "配置修改")"

}
nginx_reality_serverNames_add () {
    _cleanup_stale_serverNames_fragments || return 1
    touch "${nginx_conf_dir}"/${serverNames}.serverNames
    cat >"${nginx_conf_dir}"/${serverNames}.serverNames <<EOF
${serverNames} reality;
EOF
    judge "Nginx serverNames $(gettext "配置修改")"

}
add_sni_guard_http_include() {
    local config_name="$1"
    local include_line="include ${nginx_conf_dir}/${config_name};"
    [[ -f "${nginx_dir}/conf/nginx.conf" ]] || return 1
    if ! grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null; then
        sed -i "/^http[[:space:]]*{/a \\    ${include_line}" "${nginx_dir}/conf/nginx.conf" || return 1
    fi
    grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null
}
write_isolate_site_config() {
    mkdir -p "${nginx_conf_dir}"
    cat >"${nginx_conf_dir}/03-isolate.conf" <<'HTTPCONF'
# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
    access_log off;
    error_log /dev/null;
}
HTTPCONF
    add_sni_guard_http_include "03-isolate.conf"
}
nginx_reality_conf_add() {
    validate_reality_reserved_ports || return 1
    touch "${nginx_conf}"
    # SNI Guard 策略分支：isolate 默认(ssl_reject_handshake)/reject 死端口/decoy 回落站点
    # 注意：ssl_reject_handshake 属于 ngx_http_ssl_module，必须在 http{} 块内生效，
    #       不能放在 stream{} 块里。isolate 策略下单独写入 03-isolate.conf 由 http 块 include。
    local _deny_port
    case "${unknown_sni_policy}" in
        reject)
            # 直接拒绝：指向无监听的死端口，TCP 连接被拒绝
            _deny_port="9404"
            ;;
        decoy)
            # decoy 回落：指向本地 9444 的 HTTPS 站点（由 03-decoy.conf 提供）
            if decoy_site_artifacts_ready; then
                _deny_port="9444"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_decoy_site_config || return 1
            else
                log_echo "${Warning} ${YellowBG} $(gettext "decoy 站点设置失败, 回退到默认隔离策略") ${Font}"
                unknown_sni_policy="isolate"
                decoy_domain=""
                _deny_port="9403"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_isolate_site_config || return 1
            fi
            ;;
        isolate|*)
            # 隔离：ssl_reject_handshake 发送 TLS alert，不转发到 Xray
            # deny upstream 指向 127.0.0.1:9403，由 http 块内的 03-isolate.conf server 提供 TLS 拒绝
            _deny_port="9403"
            if sni_guard_port_conflicts "${_deny_port}"; then
                log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                return 1
            fi
            write_isolate_site_config || return 1
            ;;
    esac
    if [[ "${unknown_sni_policy}" == "reject" ]] && sni_guard_port_conflicts "${_deny_port}"; then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
        return 1
    fi
    cat >"${nginx_conf}" <<EOF

stream {
    map \$ssl_preread_protocol \$is_valid_protocol {
        #TLSv1.2    1;
        TLSv1.3    1;
        default    0;
    }

    map \$ssl_preread_server_name \$sni_upstream {
        include ${nginx_conf_dir}/*.serverNames;
        default deny;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$final_upstream {
        # 格式：上游名称:协议标记 => 最终上游
        ~^reality:1\$     reality;
        default          deny;
    }

    map \$final_upstream \$is_abnormal {
        deny    1;
        default 0;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$error_type {
        ~^reality:0\$     "tls_error";
        ~^deny:1\$        "sni_error";
        ~^deny:0\$        "tls_sni_error";
        default          "other_error";
    }

    map \$error_type \$is_tls_error {
        "tls_error"      1;
        #"tls_sni_error"  1;
        default          0;
    }

    map \$error_type \$is_sni_error {
        "sni_error"      1;
        "tls_sni_error"  1;
        default          0;
    }

    upstream reality {
        include ${nginx_conf_dir}/*.realityServers;
    }

    upstream deny {
        server 127.0.0.1:${_deny_port};
    }

    log_format tls_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    log_format sni_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    server {
        listen 443 reuseport so_keepalive=on backlog=65535;
        proxy_pass \$final_upstream;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
        access_log ${nginx_dir}/logs/tls_error.log tls_error_log buffer=8k flush=3s if=\$is_tls_error;
        access_log ${nginx_dir}/logs/sni_error.log sni_error_log buffer=8k flush=3s if=\$is_sni_error;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx $(gettext "配置修改")"
}
modify_nginx_port() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "s/^\( *\)listen.*so_keepalive=on.*/\1listen ${port} reuseport so_keepalive=on backlog=65535;/" "${nginx_conf}"
        judge "Nginx port $(gettext "修改")"
    elif [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)listen [^[]*ssl reuseport;$/\1listen ${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*ssl reuseport;$/\1listen [::]:${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen [^[]*quic reuseport;$/\1listen ${port} quic reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*quic reuseport;$/\1listen [::]:${port} quic reuseport;/" "${nginx_conf}"
        judge "Xray port $(gettext "修改")"
    fi
    [[ "on" != ${old_config_status} ]] && log_echo "${OK} ${GreenBG} $(gettext "端口"): ${port} ${Font}"
}
modify_nginx_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" "${nginx_dir}"/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    if [[ ${tls_mode} == "TLS" ]]; then
        local escaped_domain escaped_path escaped_serviceName escaped_xhttppath
        escaped_domain=$(sed_escape "${domain}")
        escaped_path=$(sed_escape "${path}")
        escaped_serviceName=$(sed_escape "${serviceName}")
        escaped_xhttppath=$(sed_escape "${xhttppath}")
        sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${escaped_domain};/g" "${nginx_conf}"
        if is_ws_mode; then
            sed -i "s/^\( *\)location ws$/\1location \/${escaped_path}/" "${nginx_conf}"
            sed -i "s/^\( *\)#proxy_pass http:\/\/xray-ws-server;/\1proxy_pass http:\/\/xray-ws-server;/" "${nginx_conf}"
        else
            sed -i "/^\s*location ws$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_grpc_mode; then
            sed -i "s/^\( *\)location grpc$/\1location \/${escaped_serviceName}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location grpc$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_xhttp_mode; then
            sed -i "s/^\( *\)location xhttp$/\1location \/${escaped_xhttppath}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*xray-xhttp-server\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location xhttp$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
    fi
}

W=/work/evidence/f04-work
B=$W/bash
install_profile=reality_balance_primary
apply_install_profile; echo "profile-primary-rc=$?"
printf 'primary|%s|%s|%s|%s|%s|%s|%s\n' "$tls_mode" "$reality_add_nginx" "$reality_add_balance" "$reality_add_more" "$transport_mode" "$reality_balance_role" "$shell_mode"
install_profile=reality_balance_secondary
apply_install_profile; echo "profile-secondary-rc=$?"
printf 'secondary|%s|%s|%s|%s|%s|%s|%s\n' "$tls_mode" "$reality_add_nginx" "$reality_add_balance" "$reality_add_more" "$transport_mode" "$reality_balance_role" "$shell_mode"

xray_conf=$B/xray-primary.json
tls_mode=Reality; reality_add_nginx=on; reality_add_balance=on
transport_mode=None; port=8443; xport=""; gport=""; xhttpport=""
modify_inbound_port; echo "port-primary-rc=$?"
xray_conf=$B/xray-secondary.json
tls_mode=Reality; reality_add_nginx=off; reality_add_balance=on
transport_mode=None; port=8443; xport=""; gport=""; xhttpport=""
modify_inbound_port; echo "port-secondary-rc=$?"

nginx_dir=$B/nginx
old_config_status=off
serverNames=example.com
port=8443
tls_mode=Reality
reality_add_nginx=on
reality_add_balance=on
xport=""; gport=""; xhttpport=""
save_originconf=Yes

nginx_conf_dir=$B/conf-isolate/nginx
nginx_conf=$nginx_conf_dir/00-xray.conf
unknown_sni_policy=isolate
nginx_reality_conf_add; echo "conf-isolate-rc=$?"
nginx_reality_servers_add; echo "servers-rc=$?"
nginx_reality_serverNames_add; echo "names-rc=$?"
printf 'garbage line\n' > "$nginx_conf_dir/stale.example.serverNames"
nginx_reality_serverNames_add; echo "names-stale-rc=$?"

nginx_conf_dir=$B/conf-reject/nginx
nginx_conf=$nginx_conf_dir/00-xray.conf
unknown_sni_policy=reject
nginx_reality_conf_add; echo "conf-reject-rc=$?"
nginx_reality_servers_add; echo "servers-reject-rc=$?"
nginx_reality_serverNames_add; echo "names-reject-rc=$?"
