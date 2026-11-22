#!/usr/bin/env bash
# A1 ACME-ownership proof inside a disposable container at the real root.
# Run as root: smoke_cert_clear_realroot.sh /path/to/idleleo
set -euo pipefail
bin="${1:?usage: smoke_cert_clear_realroot.sh /path/to/idleleo}"

rm -rf /etc/idleleo /root/.acme.sh /var/lib/idleleo/certclear
mkdir -p /etc/idleleo/cert /etc/idleleo/v1 /root/.acme.sh/ca
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt \
  -subj "/CN=node.example.com" -addext "subjectAltName=DNS:node.example.com" >/dev/null 2>&1
printf 'managed-by=idleleo\n' >/etc/idleleo/cert/.managed-by-idleleo
sha256sum /etc/idleleo/cert/xray.crt | awk '{print "sha256="$1}' >>/etc/idleleo/cert/.managed-by-idleleo
sha256sum /etc/idleleo/cert/xray.key | awk '{print "sha256="$1}' >>/etc/idleleo/cert/.managed-by-idleleo
mkdir -p /root/.acme.sh/node.example.com_ecc /root/.acme.sh/other.com_ecc
cp /etc/idleleo/cert/xray.crt /root/.acme.sh/node.example.com_ecc/node.example.com.cer
printf 'different-cert\n' >/root/.acme.sh/other.com_ecc/other.com.cer
printf 'account-key\n' >/root/.acme.sh/account.key
printf 'ca-state\n' >/root/.acme.sh/ca/ca.conf
printf 'third-party\n' >/root/.acme.sh/other.com_ecc/other.com.key

"${bin}" --root / xray cert clear --yes --container --json | tee /tmp/realroot-clear.json
test ! -e /etc/idleleo/cert/xray.crt
test ! -e /etc/idleleo/cert/xray.key
test ! -e /root/.acme.sh/node.example.com_ecc
test -e /root/.acme.sh/other.com_ecc/other.com.key
test -e /root/.acme.sh/account.key
test -e /root/.acme.sh/ca/ca.conf
grep -q '"dir": "/etc/idleleo/cert"' /tmp/realroot-clear.json
echo "A1-ACME real-root: PASS"
