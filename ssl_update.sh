#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="nobody"
idleleo_xray_dir="/etc/idleleo"
ssl_chainpath="${idleleo_xray_dir}/cert"
xray_qr_config_file="${idleleo_xray_dir}/info/vmess_qr.json"
domain=$(grep '\"add\"' $xray_qr_config_file | awk -F '"' '{print $4}')

systemctl stop nginx &> /dev/null
sleep 1
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
"/root/.acme.sh"/acme.sh --installcert -d ${domain} --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
sleep 1

if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
fi
chmod -f a+rw ${ssl_chainpath}/xray.crt
chmod -f a+rw ${ssl_chainpath}/xray.key
chown -R nobody:${cert_group} ${ssl_chainpath}/*
sleep 1
systemctl start nginx &> /dev/null
