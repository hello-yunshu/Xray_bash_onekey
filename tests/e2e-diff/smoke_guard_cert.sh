#!/usr/bin/env bash
# Smoke test for the Go online SNI Guard and the hardened certificate-clear.
# Run inside a disposable container as root:
#   smoke_guard_cert.sh /path/to/idleleo [/tmp/idleleo-guard-smoke]
#
# The certificate section is the regression for audit A1: a certificate that a
# live Nginx site references must never be deleted, a file of unknown ownership
# must survive, and only the unused project-owned pair is removed.
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

# A live HTTPS site references example.com.crt; it must survive the clear.
cat >"${root}/etc/idleleo/conf/nginx/02-site.conf" <<'CONF'
server {
    listen 443 ssl;
    ssl_certificate     /etc/idleleo/cert/example.com.crt;
    ssl_certificate_key /etc/idleleo/cert/example.com.key;
}
CONF

printf '%s\n' 'certificate' >"${root}/etc/idleleo/cert/example.com.crt"
printf '%s\n' 'private-key' >"${root}/etc/idleleo/cert/example.com.key"
printf '%s\n' 'unused-cert' >"${root}/etc/idleleo/cert/xray.crt"
printf '%s\n' 'unused-key' >"${root}/etc/idleleo/cert/xray.key"
printf '%s\n' 'third-party' >"${root}/etc/idleleo/cert/third-party.pem"
# The renewal job proves example.com.* is project-owned without a directory-wide
# marker, so third-party.pem stays "unknown ownership".
mkdir -p "${root}/etc/idleleo/schedule"
cat >"${root}/etc/idleleo/schedule/jobs.json" <<'JSON'
{"certFile": "etc/idleleo/cert/example.com.crt", "certKeyFile": "etc/idleleo/cert/example.com.key"}
JSON

# Guard show derives the deployed policy from the artifacts. Metadata has no
# sniGuard record yet, so the command must still show isolate but must not claim
# the metadata is synced.
"${bin}" --root "${root}" xray guard show --json | tee /tmp/guard-show.json
grep -q '"policy": *"isolate"' /tmp/guard-show.json
grep -q '"status": *"active"' /tmp/guard-show.json
grep -q '"metadataSynced": *false' /tmp/guard-show.json

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

# Certificate clear dry-run lists the in-use pair as kept and the unused project
# pair as deletable; nothing is written.
"${bin}" --root "${root}" xray cert clear --dry-run --json | tee /tmp/cert-dry.json
grep -q '"action": *"keep"' /tmp/cert-dry.json
grep -q '"inUse": *true' /tmp/cert-dry.json
grep -q '"action": *"delete"' /tmp/cert-dry.json
test -e "${root}/etc/idleleo/cert/example.com.crt"
test -e "${root}/etc/idleleo/cert/xray.crt"

# A real clear keeps in-use, unknown and user material; removes only the unused
# project pair.
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear.json
test -e "${root}/etc/idleleo/cert/example.com.crt"
test -e "${root}/etc/idleleo/cert/example.com.key"
test -e "${root}/etc/idleleo/cert/third-party.pem"
test ! -e "${root}/etc/idleleo/cert/xray.crt"
test ! -e "${root}/etc/idleleo/cert/xray.key"

# Second run is idempotent and lists no removal.
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear-again.json
grep -q '"removed": *\[\]' /tmp/cert-clear-again.json

# With the site reference gone but the renewal job still naming the pair, the
# pair stays in use.
sed -i '/ssl_certificate/d' "${root}/etc/idleleo/conf/nginx/02-site.conf"
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear-final.json
test -e "${root}/etc/idleleo/cert/example.com.crt"
grep -q '"inUse": *true' /tmp/cert-clear-final.json

# Once every reference and the renewal target are gone, ownership of a
# non-default filename is no longer provable: the clearer must keep it and say
# so instead of guessing. This is the A1 "evidence unclear => refuse" rule.
rm -f "${root}/etc/idleleo/schedule/jobs.json"
"${bin}" --root "${root}" xray cert clear --yes --json | tee /tmp/cert-clear-orphan.json
test -e "${root}/etc/idleleo/cert/example.com.crt"
test -e "${root}/etc/idleleo/cert/example.com.key"
test -e "${root}/etc/idleleo/cert/third-party.pem"
grep -q '"owner": *"unknown"' /tmp/cert-clear-orphan.json

echo "OPS-08/OPS-27 smoke: PASS"
