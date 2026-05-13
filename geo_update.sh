#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

VERSION="1.0.2"

idleleo_dir="/etc/idleleo"
xray_conf_dir="${idleleo_dir}/conf/xray"
xray_conf="${xray_conf_dir}/config.json"
log_dir="${idleleo_dir}/logs"
log_file="${log_dir}/geo_update.log"
running_file="${log_dir}/geo_update.running"
geo_dir="${idleleo_dir}/share/xray"
geo_remote="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
geo_version_file="${xray_conf_dir}/geo_version.json"
geo_script_remote="https://github.com/hello-yunshu/Xray_bash_onekey/raw/refs/heads/main/geo_update.sh"

check_self_update() {
    local temp_file
    temp_file=$(mktemp /tmp/idleleo_geo_update.XXXXXX) || return 1
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "$temp_file" "$geo_script_remote"; then
        echo "Failed to download remote script" >>"${log_file}"
        rm -f "$temp_file"
        return 1
    fi

    local remote_ver
    remote_ver=$(grep "^VERSION=" "$temp_file" | cut -d'"' -f2)
    if [ -z "$remote_ver" ]; then
        echo "Unable to get remote version number" >>"${log_file}"
        rm -f "$temp_file"
        return 1
    fi

    if [ "$VERSION" != "$remote_ver" ]; then
        echo "New version found: $remote_ver" >>"${log_file}"
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

[[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}"
[[ ! -d "${geo_dir}" ]] && mkdir -p "${geo_dir}"

check_self_update

if [[ -f "${running_file}" ]] && [[ $(find "${running_file}" -mmin -60 2>/dev/null) ]]; then
    echo "Previous geo update process is still running! Checked at: $(date '+%Y-%m-%d %H:%M')" >>"${log_file}"
    exit 1
fi

echo "GeoData update time: $(date '+%Y-%m-%d %H:%M')" >>"${log_file}"

touch "${running_file}"
trap 'rm -f "${running_file}"' EXIT

get_remote_version() {
    curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o /dev/null -w '%{url_effective}' "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest" 2>/dev/null | sed 's|.*/tag/||' | sed 's/^v//'
}

get_local_version() {
    local file_name="$1"
    if [[ -f "${geo_version_file}" ]]; then
        jq -r --arg name "$file_name" '.geo_versions[$name] // ""' "${geo_version_file}" 2>/dev/null
    fi
}

set_local_version() {
    local file_name="$1"
    local version="$2"
    local tmp_file="${geo_version_file}.tmp.$$"
    if [[ -f "${geo_version_file}" ]]; then
        jq --arg name "$file_name" --arg v "$version" '.geo_versions[$name] = $v' "${geo_version_file}" >"${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${geo_version_file}" || rm -f "${tmp_file}"
    else
        mkdir -p "$(dirname "${geo_version_file}")"
        echo "{\"geo_versions\":{\"${file_name}\":\"${version}\"}}" | jq . >"${tmp_file}" 2>/dev/null && mv "${tmp_file}" "${geo_version_file}" || rm -f "${tmp_file}"
    fi
}

download_geo_file() {
    local file_name="$1"
    local url="${geo_remote}/${file_name}"
    local tmp_file="${geo_dir}/${file_name}.tmp.$$"

    if ! curl -fsSL --connect-timeout 30 --retry 2 --retry-delay 3 -o "${tmp_file}" "${url}"; then
        rm -f "${tmp_file}"
        echo "Failed to download ${file_name}" >>"${log_file}"
        return 1
    fi

    if [[ ! -s "${tmp_file}" ]]; then
        rm -f "${tmp_file}"
        echo "Downloaded ${file_name} is empty" >>"${log_file}"
        return 1
    fi

    mv "${tmp_file}" "${geo_dir}/${file_name}"
    return 0
}

remote_version=$(get_remote_version)

if [[ -z "$remote_version" ]]; then
    echo "Failed to get remote version" >>"${log_file}"
    exit 1
fi

echo "Remote version: ${remote_version}" >>"${log_file}"

has_update=false
has_error=false

for file_name in "geoip.dat" "geosite.dat"; do
    cur_version=$(get_local_version "$file_name")

    if [[ "$cur_version" == "$remote_version" ]] && [[ -f "${geo_dir}/${file_name}" ]]; then
        echo "${file_name} is up to date (${cur_version})" >>"${log_file}"
        continue
    fi

    has_update=true
    echo "Updating ${file_name} (${cur_version:-none} -> ${remote_version})..." >>"${log_file}"

    if download_geo_file "$file_name"; then
        set_local_version "$file_name" "$remote_version"
        echo "${file_name} updated successfully to ${remote_version}" >>"${log_file}"
    else
        has_error=true
    fi
done

if [[ "$has_update" == "false" ]]; then
    echo "All GeoData files are up to date" >>"${log_file}"
fi

if [[ "$has_error" == "true" ]]; then
    echo "Some files failed to update" >>"${log_file}"
    exit 1
fi

if [[ "$has_update" == "true" ]] && [[ -f "${xray_conf}" ]]; then
    if systemctl is-active --quiet xray 2>/dev/null; then
        systemctl restart xray
        if systemctl is-active --quiet xray 2>/dev/null; then
            echo "Xray restarted successfully" >>"${log_file}"
        else
            echo "Xray restart failed" >>"${log_file}"
            exit 1
        fi
    fi
fi

echo "GeoData auto update completed" >>"${log_file}"
exit 0
