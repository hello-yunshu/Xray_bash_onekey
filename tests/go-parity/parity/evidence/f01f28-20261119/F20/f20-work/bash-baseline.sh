set +u
ok_rc=0
mkdir -p /usr/local/nginx/sbin /usr/local/nginx/logs
: > /usr/local/nginx/sbin/nginx
chmod +x /usr/local/nginx/sbin/nginx
for f in access.log error.log sni_error.log tls_error.log; do
  : > "/usr/local/nginx/logs/$f"
done
export tls_mode=Reality
export reality_add_nginx=on
export nginx_dir=/usr/local/nginx
OK=""; Error=""; Warning=""; Font=""; Green=""; GreenBG=""; Red=""; YellowBG=""
Info=""; RedBG=""
log_echo() { printf 'LOG %s\n' "$*"; }
judge() { return 0; }
gettext() { printf '%s' "$*"; }
# shellcheck disable=SC1090
source "$1/scripts/fail2ban_manager.sh"
printf 'y\ny\n' | mf_configure_fail2ban
echo "bash_rc=$?"
