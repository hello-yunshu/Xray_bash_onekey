FROM idleleo-balance-bash:local
COPY tests/go-parity/.cache/a2/xray /usr/local/bin/xray
COPY tests/go-parity/balance/e2e_entry.sh /entry.sh
COPY tests/go-parity/balance/e2e_nginx.conf /nginx-wrapper.conf
RUN chmod 0755 /usr/local/bin/xray /entry.sh \
 && mkdir -p /usr/local/nginx/logs /etc/idleleo/conf/nginx /var/log/xray /e2e
