#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cert_group="nobody"
idleleo_dir="/etc/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
xray_qr_config_file="${idleleo_dir}/info/vmess_qr.json"
domain=$(grep '\"add\"' ${xray_qr_config_file} | awk -F '"' '{print $4}')

systemctl stop nginx &> /dev/null
wait
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
"/root/.acme.sh"/acme.sh --installcert -d ${domain} --fullchainpath ${ssl_chainpath}/xray.crt --keypath ${ssl_chainpath}/xray.key --ecc
wait

[[ $(grep "nogroup" /etc/group) ]] && cert_group="nogroup"
chmod -f a+rw ${ssl_chainpath}/xray.crt
chmod -f a+rw ${ssl_chainpath}/xray.key
chown -R nobody:${cert_group} ${ssl_chainpath}/*
wait
systemctl start nginx &> /dev/null
