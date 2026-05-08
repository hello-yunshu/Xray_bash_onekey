#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="nobody"
idleleo_dir="/etc/idleleo"
nginx_systemd_file="/etc/systemd/system/nginx.service"
ssl_chainpath="${idleleo_dir}/cert"
xray_qr_config_file="${idleleo_dir}/info/vless_qr.json"
acme_sh_dir="${HOME:-/root}/.acme.sh"
host=$(jq -r '.host' "${xray_qr_config_file}")

[[ -f "${nginx_systemd_file}" ]] && systemctl stop nginx &> /dev/null
wait

if [[ -f "${acme_sh_dir}/acme.sh" ]]; then
    "${acme_sh_dir}/acme.sh" --cron --home "${acme_sh_dir}" &> /dev/null
    "${acme_sh_dir}/acme.sh" --installcert -d "${host}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc &> /dev/null
else
    echo "acme.sh not found at ${acme_sh_dir}" >&2
fi
wait

grep -q "^nogroup:" /etc/group && cert_group="nogroup"
chmod -f a+rw "${ssl_chainpath}/xray.crt"
chmod -f a+rw "${ssl_chainpath}/xray.key"
chown -fR nobody:"${cert_group}" "${ssl_chainpath}"
wait
[[ -f "${nginx_systemd_file}" ]] && systemctl start nginx &> /dev/null
