#!/usr/bin/env bash
set -uo pipefail
CONTAINER=${1:?usage: certclear-dynamic-tls.sh <go-server-container> <evidence-dir>}
OUT=${2:?usage: certclear-dynamic-tls.sh <go-server-container> <evidence-dir>}
mkdir -p "$OUT"
set +e
docker exec -i "$CONTAINER" bash -s >"$OUT/certclear-dynamic-tls.log" 2>&1 <<'CONTAINER_SCRIPT'
set -euo pipefail
cert=/etc/idleleo/cert/xray.crt
key=/etc/idleleo/cert/xray.key
acme=/root/.acme.sh/cert-name-variable.invalid_ecc
fragment=/etc/idleleo/conf/nginx/03-isolate.conf
mkdir -p /etc/idleleo/cert /etc/idleleo/conf/nginx "$acme"
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -subj /CN=cert-name-variable.invalid -keyout "$key" -out "$cert" >/dev/null 2>&1
chgrp idleleo-nginx "$key"
chmod 0640 "$key"
chmod 0644 "$cert"
python3 - "$cert" "$key" <<'PY'
import hashlib, pathlib, sys
cert, key = map(pathlib.Path, sys.argv[1:])
lines = ["managed-by=idleleo", "format=2"]
for path in (cert, key):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"file={path.name}\ttype=regular\tsha256={digest}")
(cert.parent / ".managed-by-idleleo").write_text("\n".join(lines) + "\n")
PY
grep -q cert-name-variable-e2e "$fragment" && { echo "dynamic test fragment already installed"; exit 1; }
cat >> "$fragment" <<'NGINX'
# cert-name-variable-e2e
map $ssl_server_name $cert_name { default xray; }
server {
    listen 127.0.0.1:18443 ssl;
    server_name cert-name-variable.invalid;
    ssl_certificate /etc/idleleo/cert/${cert_name}.crt;
    ssl_certificate_key /etc/idleleo/cert/${cert_name}.key;
    return 200 "dynamic-cert-ok\n";
}
NGINX
cp "$cert" "$acme/cert-name-variable.invalid.cer"
cp "$key" "$acme/cert-name-variable.invalid.key"
printf 'external-renewal-state\n' > "$acme/renewal.conf"
printf 'external-account-state\n' > "$acme/account.key"
python3 - "$acme" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
lines = ["managed-by=idleleo", "format=2"]
for name in ("cert-name-variable.invalid.cer", "cert-name-variable.invalid.key"):
    p = root / name
    lines.append(f"file={p.name}\ttype=regular\tsha256={hashlib.sha256(p.read_bytes()).hexdigest()}")
(root / ".managed-by-idleleo").write_text("\n".join(lines) + "\n")
PY
acme_before=$(find "$acme" -maxdepth 1 -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
/usr/local/nginx/sbin/nginx -t
systemctl reload nginx
curl -sk --max-time 5 --resolve cert-name-variable.invalid:18443:127.0.0.1 \
  https://cert-name-variable.invalid:18443/ -o /tmp/cert-before.body
printf 'TLS_BEFORE_RC=0\n'
IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY /usr/local/bin/idleleo \
  xray cert clear --yes --container --json > /tmp/cert-clear.json
printf 'CERT_CLEAR_RC=0\n'
/usr/local/nginx/sbin/nginx -t
systemctl reload nginx
curl -sk --max-time 5 --resolve cert-name-variable.invalid:18443:127.0.0.1 \
  https://cert-name-variable.invalid:18443/ -o /tmp/cert-after.body
printf 'TLS_AFTER_RC=0\n'
acme_after=$(find "$acme" -maxdepth 1 -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
python3 - "$acme_before" "$acme_after" "$cert" "$key" "$acme" <<'PY'
import json, pathlib, sys
before, after, cert, key, acme = sys.argv[1:]
root = pathlib.Path(acme)
report = {
  "tlsBefore": pathlib.Path("/tmp/cert-before.body").read_text().strip() == "dynamic-cert-ok",
  "tlsAfter": pathlib.Path("/tmp/cert-after.body").read_text().strip() == "dynamic-cert-ok",
  "certPreserved": pathlib.Path(cert).is_file(),
  "keyPreserved": pathlib.Path(key).is_file(),
  "acmeTreeHashBefore": before,
  "acmeTreeHashAfter": after,
  "acmeTreePreservedExactly": before == after,
  "acmeAccountAndRenewalPreserved": (root / "account.key").is_file() and (root / "renewal.conf").is_file(),
  "certificateFragment": "/etc/idleleo/conf/nginx/03-isolate.conf",
}
pathlib.Path("/tmp/certclear-dynamic-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if not all(report[k] for k in ("tlsBefore", "tlsAfter", "certPreserved", "keyPreserved", "acmeTreePreservedExactly", "acmeAccountAndRenewalPreserved")):
    raise SystemExit("dynamic certificate cleanup regression failed")
PY
cat /tmp/certclear-dynamic-report.json
CONTAINER_SCRIPT
rc=$?
printf 'command_rc=%s\n' "$rc" >>"$OUT/certclear-dynamic-tls.log"
docker cp "$CONTAINER:/tmp/cert-clear.json" "$OUT/cert-clear.json" >/dev/null 2>&1 || true
docker cp "$CONTAINER:/tmp/certclear-dynamic-report.json" "$OUT/certclear-dynamic-report.json" >/dev/null 2>&1 || true
exit "$rc"
