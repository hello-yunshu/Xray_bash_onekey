#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="nobody"
idleleo_dir="/etc/idleleo"
nginx_systemd_file="/etc/systemd/system/nginx.service"
ssl_chainpath="${idleleo_dir}/cert"
xray_qr_config_file="${idleleo_dir}/info/vmess_qr.json"
host=$(jq -r '.host' ${xray_qr_config_file})
bt_nginx=$(jq -r '.bt_nginx' ${xray_qr_config_file})

[[ -f ${nginx_systemd_file} ]] && systemctl stop nginx &> /dev/null
[[ bt_nginx == "Yes" ]] && /etc/init.d/nginx stop &> /dev/null
wait
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
"/root/.acme.sh"/acme.sh --installcert -d ${host} --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc &> /dev/null
wait

[[ $(grep "nogroup" /etc/group) ]] && cert_group="nogroup"
chmod -f a+rw ${ssl_chainpath}/xray.crt
chmod -f a+rw ${ssl_chainpath}/xray.key
chown -fR nobody:${cert_group} ${ssl_chainpath}/*
wait
[[ -f ${nginx_systemd_file} ]] && systemctl start nginx &> /dev/null
[[ bt_nginx == "Yes" ]] && /etc/init.d/nginx start &> /dev/null