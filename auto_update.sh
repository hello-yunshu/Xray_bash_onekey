#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

idleleo_dir="/etc/idleleo"
nginx_dir="/etc/nginx"
xray_conf_dir="${idleleo_conf_dir}/xray"
xray_conf="${xray_conf_dir}/config.json"
log_dir="${idleleo_dir}/logs"
log_file="${log_dir}/auto_update.log"
running_file="${log_dir}/auto_update.running"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
get_versions_all=$(curl -s https://www.idleleo.com/api/xray_shell_versions)
info_extraction_all=$(jq -rc . ${xray_qr_config_file})

[[ ! -d "${log_dir}" ]] && mkdir -p ${log_dir}
if [[ -f "${running_file}" ]]; then
    echo "上个自动更新程序仍在运行! 检查于: $(date '+%Y-%m-%d %H:%M') 建议手动排错!" >>${log_file}
    exit 1
else
    touch ${running_file}
fi
[[ -f "${log_file}" ]] && rm -rf ${log_file}

echo "更新时间: $(date '+%Y-%m-%d %H:%M')" >${log_file}

check_online_version() {
    echo ${get_versions_all} | jq -rc ".$1"
    [[ 0 -ne $? ]] && echo "在线版本检测失败, 请稍后再试!" >>${log_file} && exit 1
}

info_extraction() {
    echo ${info_extraction_all} | jq -r ".$1"
}

shell_online_version="$(check_online_version shell_online_version)"
xray_online_version="$(check_online_version xray_tested_version)"
nginx_online_version="$(check_online_version nginx_online_version)"
openssl_online_version="$(check_online_version openssl_online_version)"
jemalloc_online_version="$(check_online_version jemalloc_tested_version)"

if [[ -f ${xray_qr_config_file} ]]; then
    if [[ $(info_extraction shell_version) == null ]] || [[ $(info_extraction shell_version) != ${shell_online_version} ]]; then
        bash idleleo -u auto_update
        [[ 0 -ne $? ]] && echo "脚本 更新失败!" >>${log_file} && exit 1
        echo "脚本 更新成功!" >>${log_file}
        add_shell_version=$(jq -r ". += {\"shell_version\": \"${shell_online_version}\"}" ${xray_qr_config_file})
        echo "${add_shell_version}" | jq . >${xray_qr_config_file}
    else
        echo "脚本 最新版!" >>${log_file}
    fi
    if [[ $(info_extraction nginx_version) == null ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
        echo "Nginx 未安装!"
    elif [[ ${nginx_online_version} != $(info_extraction nginx_version) ]] || [[ ${openssl_online_version} != $(info_extraction openssl_version) ]] || [[ ${jemalloc_online_version} != $(info_extraction jemalloc_version) ]]; then
        bash idleleo -n auto_update
        [[ 0 -ne $? ]] && echo "Nginx 更新失败!" >>${log_file} && exit 1
        echo "Nginx 更新成功!" >>${log_file}
    else
        echo "Nginx 最新版!" >>${log_file}
    fi
    if [[ -f ${xray_qr_config_file} ]] && [[ -f ${xray_conf} ]] && [[ -f /usr/local/bin/xray ]]; then
        if [[ $(info_extraction xray_version) == null ]]; then
            echo "Xray 版本未知 无法自动更新" >>${log_file}
        elif [[ ${xray_online_version} != $(info_extraction xray_version) ]]; then
            bash idleleo -x auto_update
            [[ 0 -ne $? ]] && echo "Xray 更新失败!" >>${log_file} && exit 1
            echo "Xray 更新成功!" >>${log_file}
        elif [[ ${xray_online_version} == $(info_extraction xray_version) ]]; then
            echo "Xray 最新版!" >>${log_file}
        fi
    else
        echo "Xray 未安装!" >>${log_file}
    fi
fi
rm -rf ${running_file}
