#!/usr/bin/env bash
# Smoke test for the new Go online SNI Guard and certificate-clear commands.
# Run inside a disposable container as root:
#   smoke_guard_cert.sh /path/to/idleleo [/tmp/idleleo-guard-smoke]
set -euo pipefail

bin="${1:?usage: smoke_guard_cert.sh /path/to/idleleo [root]}"
root="${2:-/tmp/idleleo-guard-smoke}"

rm -rf "${root}"
mkdir -p "${root}/etc/idleleo/v1" "${root}/etc/idleleo/conf/xray" \
  "${root}/etc/idleleo/conf/nginx" "${root}/etc/idleleo/cert" \
  "${root}/usr/local/nginx/conf"
printf '%s\n' "I_ACCEPT_DISPOSABLE_SANDBOX" >"${root}/.idleleo-phase01-sandbox"

cat >"${root}/etc/idleleo/v1/metadata.json" <<'JSON'
{
  "schemaVersion": 1,
  "activeEngine": "xray",
  "role": "node",
  "tls": "Reality",
  "transport": "raw",
  "runtimeConfigPath": "etc/idleleo/conf/xray/config.json",
  "runtimeSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "ownedResources": [],
  "updatedAt": "2026-01-01T00:00:00Z",
  "install": {"port": 443, "serverNames": ["node.example.com"]}
}
JSON

printf '%s\n' '{"inbounds":[{"port":443,"protocol":"vless"}]}' \
  >"${root}/etc/idleleo/conf/xray/config.json"

cat >"${root}/etc/idleleo/conf/nginx/00-xray.conf" <<'CONF'
stream {
    map $ssl_preread_server_name $sni_upstream {
        include /etc/idleleo/conf/nginx/*.serverNames;
        default deny;
    }
    upstream deny {
        server 127.0.0.1:9403;
    }
}
CONF

cat >"${root}/usr/local/nginx/conf/nginx.conf" <<'CONF'
http {
    include /etc/idleleo/conf/nginx/03-isolate.conf;
}
CONF

printf '%s\n' 'certificate' >"${root}/etc/idleleo/cert/example.com.crt"
printf '%s\n' 'private-key' >"${root}/etc/idleleo/cert/example.com.key"

# Guard show defaults to isolate even before any online change.
"${bin}" --root "${root}" xray guard show --json | tee /tmp/guard-show.json
grep -q '"policy": *"isolate"' /tmp/guard-show.json

# Reject preview: deny upstream switches to the dead port.
"${bin}" --root "${root}" xray guard set --policy reject --dry-run --json | tee /tmp/guard-reject.json
grep -q '"denyPort": *9404' /tmp/guard-reject.json
grep -q '"changed": *true' /tmp/guard-reject.json

# Isolate preview is idempotent and keeps the deny port at 9403.
"${bin}" --root "${root}" xray guard set --policy isolate --dry-run --json | tee /tmp/guard-isolate.json
grep -q '"denyPort": *9403' /tmp/guard-isolate.json

# Decoy preview: use a host entry so DNS verification passes without network.
if ! grep -q 'decoy.local' /etc/hosts 2>/dev/null; then
  printf '127.0.0.1 decoy.local\n' >>/etc/hosts
fi
"${bin}" --root "${root}" xray guard set --policy decoy --decoy-domain decoy.local --dry-run --json | tee /tmp/guard-decoy.json
grep -q '"policy": *"decoy"' /tmp/guard-decoy.json
grep -q '"selfSigned": *true' /tmp/guard-decoy.json

# Certificate clear: dry-run lists two, the real run removes them, the second
# run is idempotent and lists nothing.
"${bin}" --root "${root}" xray cert clear --dry-run --json | tee /tmp/cert-dry.json
grep -q 'example.com.crt' /tmp/cert-dry.json
grep -q 'example.com.key' /tmp/cert-dry.json
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear.json
test ! -e "${root}/etc/idleleo/cert/example.com.crt"
test ! -e "${root}/etc/idleleo/cert/example.com.key"
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear-again.json
grep -q '"removed": *\[\]' /tmp/cert-clear-again.json

echo "OPS-08/OPS-27 smoke: PASS"
