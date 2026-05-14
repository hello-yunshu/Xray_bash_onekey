#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

VERSION="1.1.1"

idleleo_dir="/etc/idleleo"
local_bin="/usr/local"
nginx_dir="${local_bin}/nginx"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
log_dir="${idleleo_dir}/logs"
log_file="${log_dir}/auto_update.log"
running_file="${log_dir}/auto_update.running"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
failed_update_marker="${log_dir}/update_failed.mark"

check_update() {
    local temp_file
    temp_file=$(mktemp /tmp/idleleo_auto_update.XXXXXX) || return 1
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "$temp_file" "https://github.com/hello-yunshu/Xray_bash_onekey/raw/refs/heads/main/auto_update.sh"; then
        echo "Failed to download remote script" >>"${log_file}"
        rm -f "$temp_file"
        return 1
    fi

    remote_version=$(grep "^VERSION=" "$temp_file" | cut -d'"' -f2)
    if [ -z "$remote_version" ]; then
        echo "Unable to get remote version number" >>"${log_file}"
        rm -f "$temp_file"
        return 1
    fi

    if [ "$VERSION" != "$remote_version" ]; then
        echo "New version found: $remote_version" >>"${log_file}"
        if bash -n "$temp_file" 2>/dev/null; then
            cp "$temp_file" "$0"
            chmod +x "$0"
            rm -f "$temp_file"
            rm -f "${running_file}"
            exec "$0" "$@"
        else
            echo "Downloaded script failed syntax check, skipping update" >>"${log_file}"
            rm -f "$temp_file"
            return 1
        fi
    fi

    rm -f "$temp_file"
    return 0
}

if [[ -f "${failed_update_marker}" ]]; then
    echo "Previous update failed, skipping auto update. Remove ${failed_update_marker} or perform manual update to re-enable." >>"${log_file}"
    exit 0
fi

[[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}"
if ! mkdir "${running_file}" 2>/dev/null; then
    echo "Previous auto update process is still running! Checked at: $(date '+%Y-%m-%d %H:%M') Manual troubleshooting recommended!" >>"${log_file}"
    exit 1
fi
trap 'rm -rf "${running_file}"' EXIT
[[ -f "${log_file}" ]] && rm -f "${log_file}"

echo "Update time: $(date '+%Y-%m-%d %H:%M')" >"${log_file}"

check_update

get_versions_all=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json 2>/dev/null)

if [[ ! -f "${xray_qr_config_file}" ]]; then
    echo "Config file not found, skipping update checks." >>"${log_file}"
    exit 0
fi

info_extraction_all=$(jq -rc . "${xray_qr_config_file}" 2>/dev/null)

check_online_version() {
    local result
    result=$(echo "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null)
    if [[ $? -ne 0 ]] || [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        echo "Online version check failed, please try again later!" >>"${log_file}"
        exit 1
    fi
    echo "${result}"
}

info_extraction() {
    echo "${info_extraction_all}" | jq -r --arg key "$1" '.[$key]' 2>/dev/null
}

shell_online_version="$(check_online_version shell_online_version)"
xray_online_version="$(check_online_version xray_online_version)"
nginx_online_version="$(check_online_version nginx_build_online_version)"

if [[ -f "${xray_qr_config_file}" ]]; then
    if [[ $(info_extraction shell_version) == null ]] || [[ $(info_extraction shell_version) != "${shell_online_version}" ]]; then
        bash "${idleleo_dir}/install.sh" -u auto_update
        [[ 0 -ne $? ]] && echo "Script update failed!" >>"${log_file}" && exit 1
        echo "Script updated successfully!" >>"${log_file}"
        add_shell_version=$(jq -r --arg sv "${shell_online_version}" '. += {"shell_version": $sv}' "${xray_qr_config_file}" 2>/dev/null)
        if [[ -n "${add_shell_version}" ]]; then
            tmp_config="${xray_qr_config_file}.tmp.$$"
            echo "${add_shell_version}" | jq . >"${tmp_config}" 2>/dev/null && mv "${tmp_config}" "${xray_qr_config_file}" || rm -f "${tmp_config}"
        fi
    else
        echo "Script is up to date!" >>"${log_file}"
    fi
    if [[ $(info_extraction nginx_build_version) != null ]] && [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        if [[ "${nginx_online_version}" != $(info_extraction nginx_build_version) ]]; then
            echo "Updating Nginx..." >>"${log_file}"
            auto_update=YES bash "${idleleo_dir}/install.sh" -n auto_update
            if [[ $? -ne 0 ]]; then
                echo "Nginx update failed!" >>"${log_file}"
                touch "${failed_update_marker}"
            else
                echo "Nginx updated successfully!" >>"${log_file}"
            fi
        else
            echo "Nginx is up to date!" >>"${log_file}"
        fi
    else
        echo "Nginx not installed!" >>"${log_file}"
    fi
    if [[ -f "${xray_qr_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f /usr/local/bin/xray ]]; then
        if [[ $(info_extraction xray_version) != null ]]; then
            if [[ "${xray_online_version}" != $(info_extraction xray_version) ]]; then
                echo "Updating Xray..." >>"${log_file}"
                auto_update=YES bash "${idleleo_dir}/install.sh" -x auto_update
                if [[ $? -ne 0 ]]; then
                    echo "Xray update failed!" >>"${log_file}"
                    touch "${failed_update_marker}"
                else
                    echo "Xray updated successfully!" >>"${log_file}"
                fi
            else
                echo "Xray is up to date!" >>"${log_file}"
            fi
        else
            echo "Xray version unknown, cannot auto update" >>"${log_file}"
        fi
    else
        echo "Xray not installed!" >>"${log_file}"
    fi
fi
