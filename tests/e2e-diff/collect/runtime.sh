#!/usr/bin/env bash
# Collects L3 runtime state from a running e2e container.
#
# Usage (inside the container):
#   E2E_COLLECT_OUT=/out bash collect/runtime.sh
#
# Outputs:
#   runtime.json          service state, listeners, validator results, versions
#   state/<unit>.service  unit file contents (for diffing)
#   state/xray-test.log   raw `xray -test` output
#   state/nginx-test.log  raw `nginx -t` output
set -uo pipefail

OUT="${E2E_COLLECT_OUT:?E2E_COLLECT_OUT required}"
mkdir -p "$OUT/state"

XRAY_BIN="${E2E_XRAY_BIN:-/usr/local/bin/xray}"
NGINX_BIN="${E2E_NGINX_BIN:-/usr/local/nginx/sbin/nginx}"
XRAY_CONF="${E2E_XRAY_CONF:-/etc/idleleo/conf/xray/config.json}"
NGINX_CONF="${E2E_NGINX_CONF:-/usr/local/nginx/conf/nginx.conf}"

for unit in xray nginx; do
    file="/etc/systemd/system/${unit}.service"
    [[ -f "$file" ]] && cp "$file" "$OUT/state/${unit}.service"
done

xray_version=""
nginx_version=""
xray_test_rc="skipped"
nginx_test_rc="skipped"
nginx_test_supported=false

if [[ -x "$XRAY_BIN" ]]; then
    xray_version=$("$XRAY_BIN" version 2>/dev/null | head -1 || true)
    if [[ -f "$XRAY_CONF" ]]; then
        "$XRAY_BIN" -test -config "$XRAY_CONF" >"$OUT/state/xray-test.log" 2>&1
        xray_test_rc=$?
    fi
fi

if [[ -x "$NGINX_BIN" ]]; then
    nginx_version=$("$NGINX_BIN" -v 2>&1 | head -1 || true)
    nginx_test_supported=true
    if [[ -f "$NGINX_CONF" ]]; then
        "$NGINX_BIN" -t -c "$NGINX_CONF" >"$OUT/state/nginx-test.log" 2>&1
        nginx_test_rc=$?
    fi
fi

ss -lntp >"$OUT/state/listeners.txt" 2>&1 || true

export E2E_RT_OUT="$OUT/runtime.json"
export E2E_RT_XRAY_ACTIVE="$(systemctl is-active xray 2>/dev/null || true)"
export E2E_RT_XRAY_ENABLED="$(systemctl is-enabled xray 2>/dev/null || true)"
export E2E_RT_NGINX_ACTIVE="$(systemctl is-active nginx 2>/dev/null || true)"
export E2E_RT_NGINX_ENABLED="$(systemctl is-enabled nginx 2>/dev/null || true)"
export E2E_RT_XRAY_VERSION="$xray_version"
export E2E_RT_NGINX_VERSION="$nginx_version"
export E2E_RT_XRAY_TEST="$xray_test_rc"
export E2E_RT_NGINX_TEST="$nginx_test_rc"
export E2E_RT_NGINX_TEST_SUPPORTED="$nginx_test_supported"

python3 - <<'PY'
import json
import os

out = os.environ['E2E_RT_OUT']
state = os.path.join(os.path.dirname(out), 'state')

def read(name):
    try:
        with open(os.path.join(state, name), encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError:
        return ''

listeners = []
for line in read('listeners.txt').splitlines()[1:]:
    parts = line.split()
    if len(parts) >= 4:
        listeners.append({'state': parts[0], 'recvq': parts[1], 'sendq': parts[2],
                          'local': parts[3], 'peer': parts[4] if len(parts) > 4 else ''})

data = {
    'xrayActive': os.environ['E2E_RT_XRAY_ACTIVE'],
    'xrayEnabled': os.environ['E2E_RT_XRAY_ENABLED'],
    'nginxActive': os.environ['E2E_RT_NGINX_ACTIVE'],
    'nginxEnabled': os.environ['E2E_RT_NGINX_ENABLED'],
    'xrayVersion': os.environ['E2E_RT_XRAY_VERSION'],
    'nginxVersion': os.environ['E2E_RT_NGINX_VERSION'],
    'xrayTestExit': os.environ['E2E_RT_XRAY_TEST'],
    'nginxTestExit': os.environ['E2E_RT_NGINX_TEST'],
    'nginxTestSupported': os.environ['E2E_RT_NGINX_TEST_SUPPORTED'] == 'true',
    'listeners': listeners,
    'units': {
        'xray': bool(read('xray.service')),
        'nginx': bool(read('nginx.service')),
    },
}
with open(out, 'w') as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
print('runtime collected')
PY
