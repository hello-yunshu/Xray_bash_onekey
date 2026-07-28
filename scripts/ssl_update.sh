#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="nobody"
idleleo_dir="/etc/idleleo"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
ssl_chainpath="${idleleo_dir}/cert"
xray_install_config_file="${idleleo_dir}/conf/install_config.json"
acme_sh_dir="${HOME:-/root}/.acme.sh"
running_file="${idleleo_dir}/ssl_update_running"
running_file_max_age_minutes=120

if [[ -d "${running_file}" ]] && [[ -n $(find "${running_file}" -maxdepth 0 -mmin +"${running_file_max_age_minutes}" 2>/dev/null) ]]; then
    echo "Removing stale ssl update lock: ${running_file}" >&2
    rm -rf "${running_file}"
fi

if ! mkdir "${running_file}" 2>/dev/null; then
    echo "Previous ssl update process is still running!" >&2
    exit 1
fi
printf '%s\n' "$$" >"${running_file}/pid"
trap 'rm -rf "${running_file}"' EXIT

if [[ ! -f "${xray_install_config_file}" ]]; then
    echo "Config file not found: ${xray_install_config_file}" >&2
    exit 1
fi

host=$(jq -r '.host' "${xray_install_config_file}" 2>/dev/null)
if [[ -z "${host}" || "${host}" == "null" ]]; then
    echo "Failed to get domain from config" >&2
    exit 1
fi

if [[ ! -f "${acme_sh_dir}/acme.sh" ]]; then
    echo "acme.sh not found at ${acme_sh_dir}" >&2
    exit 1
fi

[[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx >/dev/null 2>&1

if ! "${acme_sh_dir}/acme.sh" --cron --home "${acme_sh_dir}" >/dev/null 2>&1; then
    echo "acme.sh cron renewal failed" >&2
    [[ -f "${nginx_systemd_file}" ]] && { systemctl start nginx >/dev/null 2>&1 || echo "Warning: Nginx start failed after SSL update" >&2; }
    exit 1
fi

if ! "${acme_sh_dir}/acme.sh" --installcert -d "${host}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc >/dev/null 2>&1; then
    echo "acme.sh installcert failed for ${host}" >&2
    [[ -f "${nginx_systemd_file}" ]] && { systemctl start nginx >/dev/null 2>&1 || echo "Warning: Nginx start failed after SSL update" >&2; }
    exit 1
fi

if [[ ! -f "${ssl_chainpath}/xray.crt" || ! -f "${ssl_chainpath}/xray.key" ]]; then
    echo "Certificate files missing after installcert" >&2
    [[ -f "${nginx_systemd_file}" ]] && { systemctl start nginx >/dev/null 2>&1 || echo "Warning: Nginx start failed after SSL update" >&2; }
    exit 1
fi

grep -q "^nogroup:" /etc/group && cert_group="nogroup"
# Task E (Section 9.3): root owns certs/keys, worker group can read but NOT write.
# Use dedicated idleleo-nginx group for cert group (fallback to nogroup).
if getent group "idleleo-nginx" >/dev/null 2>&1; then
    cert_group="idleleo-nginx"
fi
cert_user="root"
# Task E (Section 9.3): root owns certs/keys, worker group can read but NOT write.
# Use non-recursive chown to avoid affecting other files in the directory.
# Apply layered permission model consistent with apply_nginx_layered_permissions()
# in install.sh: cert dir root:idleleo-nginx 750, cert/privkey root:idleleo-nginx 640.
chown -f "${cert_user}:${cert_group}" "${ssl_chainpath}"
chown -f "${cert_user}:${cert_group}" "${ssl_chainpath}/xray.crt" "${ssl_chainpath}/xray.key"
chmod -f 750 "${ssl_chainpath}"
chmod -f 640 "${ssl_chainpath}/xray.crt"
chmod -f 640 "${ssl_chainpath}/xray.key"

[[ -f "${xray_systemd_file}" ]] && { systemctl restart xray >/dev/null 2>&1 || echo "Warning: Xray restart failed after SSL update" >&2; }
[[ -f "${nginx_systemd_file}" ]] && { systemctl start nginx >/dev/null 2>&1 || echo "Warning: Nginx start failed after SSL update" >&2; }
