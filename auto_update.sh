#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

VERSION="1.0.1"

idleleo_dir="/etc/idleleo"
local_bin="/usr/local"
nginx_dir="${local_bin}/nginx"
xray_conf_dir="${idleleo_conf_dir}/xray"
xray_conf="${xray_conf_dir}/config.json"
log_dir="${idleleo_dir}/logs"
log_file="${log_dir}/auto_update.log"
running_file="${log_dir}/auto_update.running"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
get_versions_all=$(curl -s https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json)
info_extraction_all=$(jq -rc . ${xray_qr_config_file})

[[ ! -d "${log_dir}" ]] && mkdir -p ${log_dir}
if [[ -f "${running_file}" ]]; then
    echo "Previous auto update process is still running! Checked at: $(date '+%Y-%m-%d %H:%M') Manual troubleshooting recommended!" >>${log_file}
    exit 1
else
    touch ${running_file}
fi
[[ -f "${log_file}" ]] && rm -rf ${log_file}

echo "Update time: $(date '+%Y-%m-%d %H:%M')" >${log_file}

check_online_version() {
    echo ${get_versions_all} | jq -rc ".$1"
    [[ 0 -ne $? ]] && echo "Online version check failed, please try again later!" >>${log_file} && exit 1
}

info_extraction() {
    echo ${info_extraction_all} | jq -r ".$1"
}

shell_online_version="$(check_online_version shell_online_version)"
xray_online_version="$(check_online_version xray_online_version)"
nginx_online_version="$(check_online_version nginx_build_version)"

if [[ -f ${xray_qr_config_file} ]]; then
    if [[ $(info_extraction shell_version) == null ]] || [[ $(info_extraction shell_version) != ${shell_online_version} ]]; then
        bash idleleo -u auto_update
        [[ 0 -ne $? ]] && echo "Script update failed!" >>${log_file} && exit 1
        echo "Script updated successfully!" >>${log_file}
        add_shell_version=$(jq -r ". += {\"shell_version\": \"${shell_online_version}\"}" ${xray_qr_config_file})
        echo "${add_shell_version}" | jq . >${xray_qr_config_file}
    else
        echo "Script is up to date!" >>${log_file}
    fi
    if [[ $(info_extraction nginx_build_version) == null ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
        echo "Nginx not installed!"
    elif [[ ${nginx_online_version} != $(info_extraction nginx_build_version) ]]; then
        bash idleleo -n auto_update
        [[ 0 -ne $? ]] && echo "Nginx update failed!" >>${log_file} && exit 1
        echo "Nginx updated successfully!" >>${log_file}
    else
        echo "Nginx is up to date!" >>${log_file}
    fi
    if [[ -f ${xray_qr_config_file} ]] && [[ -f ${xray_conf} ]] && [[ -f /usr/local/bin/xray ]]; then
        if [[ $(info_extraction xray_version) == null ]]; then
            echo "Xray version unknown, cannot auto update" >>${log_file}
        elif [[ ${xray_online_version} != $(info_extraction xray_version) ]]; then
            bash idleleo -x auto_update
            [[ 0 -ne $? ]] && echo "Xray update failed!" >>${log_file} && exit 1
            echo "Xray updated successfully!" >>${log_file}
        elif [[ ${xray_online_version} == $(info_extraction xray_version) ]]; then
            echo "Xray is up to date!" >>${log_file}
        fi
    else
        echo "Xray not installed!" >>${log_file}
    fi
fi
rm -rf ${running_file}

check_update() {
    temp_file="/tmp/temp_script.sh"
    if ! curl -s -o "$temp_file" "https://github.com/hello-yunshu/Xray_bash_onekey/raw/refs/heads/main/auto_update.sh"; then
        echo "Failed to download remote script" >>${log_file}
        return 1
    }

    remote_version=$(grep "^VERSION=" "$temp_file" | cut -d'"' -f2)
    if [ -z "$remote_version" ]; then
        echo "Unable to get remote version number" >>${log_file}
        return 1
    }

    if [ "$VERSION" != "$remote_version" ]; then
        echo "New version found: $remote_version" >>${log_file}
        cp "$temp_file" "$0"
        chmod +x "$0"
        rm -f "$temp_file"
        exec "$0" "$@"
    fi

    rm -f "$temp_file"
    return 0
}


check_update