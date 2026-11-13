#!/usr/bin/env bash
# Runs the Go installer (idleleo xray install) inside the e2e container and
# captures L0-L3 with exactly the same collectors as the Bash side.
#
# Usage:
#   bash go_install.sh --mode reality --container
#   bash go_install.sh --mode tls --transport ws --domain example.com \
#       --cert /etc/idleleo/cert/xray.crt --cert-key /etc/idleleo/cert/xray.key --container
#
# Environment:
#   E2E_OUT      evidence directory for this side (required)
#   E2E_PROFILE  reality | tls | relay (drives certificate seeding only)
set -uo pipefail

OUT="${E2E_OUT:?E2E_OUT required}"
PROFILE="${E2E_PROFILE:?E2E_PROFILE required}"
mkdir -p "$OUT"
: >"$OUT/install.log"
: >"$OUT/expect.log"

log() { printf '%s\n' "$*" | tee -a "$OUT/capture.log"; }

state=""
for _ in $(seq 1 40); do
    state=$(systemctl is-system-running 2>/dev/null || true)
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done
log "systemd_state=${state:-not-ready}"
if [[ "$state" != running && "$state" != degraded ]]; then
    log "FATAL: systemd did not start"
    exit 2
fi

if [[ -f /seed/xray ]]; then
    install -m 0755 /seed/xray /usr/local/bin/xray
    log "seeded_xray=$(/usr/local/bin/xray version 2>/dev/null | head -1)"
fi
if [[ -f /seed/idleleo ]]; then
    install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    log "idleleo_version=$(/usr/local/bin/idleleo --version 2>/dev/null | head -1)"
fi

if [[ "$PROFILE" == "tls" ]]; then
    if [[ -f /seed/cert/xray.crt && -f /seed/cert/xray.key ]]; then
        mkdir -p /etc/idleleo/cert
        install -m 0640 /seed/cert/xray.crt /etc/idleleo/cert/xray.crt
        install -m 0640 /seed/cert/xray.key /etc/idleleo/cert/xray.key
        log "seeded_cert=yes sha256=$(sha256sum /etc/idleleo/cert/xray.crt | awk '{print $1}')"
    else
        log "FATAL: tls profile requires /seed/cert/xray.crt and xray.key"
        exit 2
    fi
fi

log "go_argv=$*"
# The Go installer refuses writes to a real root unless this container-only
# acknowledgement is present; `--container` alone is not sufficient.
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
set +e
/usr/local/bin/idleleo xray install "$@" >>"$OUT/install.log" 2>&1
install_rc=$?
set -e
log "install_exit=$install_rc"
printf '%s\n' "$install_rc" >"$OUT/rc.txt"

E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/manifest.sh >>"$OUT/capture.log" 2>&1 || true
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/runtime.sh >>"$OUT/capture.log" 2>&1 || true

RUNTIME_SRC="/etc/idleleo/conf/xray/config.json"
mkdir -p "$OUT/config"
if [[ -f "$RUNTIME_SRC" ]]; then
    cp "$RUNTIME_SRC" /tmp/e2e-runtime-raw.json
    jq '(.inbounds[]?.streamSettings.realitySettings.privateKey?) = "REDACTED"
        | (.inbounds[]?.settings.clients[]?.id?) = "REDACTED"' \
        "$RUNTIME_SRC" >"$OUT/config/config.sanitized.json" 2>/dev/null || \
        cp "$RUNTIME_SRC" "$OUT/config/config.sanitized.json"
    python3 /src/tests/e2e-diff/collect/identity.py /tmp/e2e-runtime-raw.json "$OUT/config/identity.json" \
        >>"$OUT/capture.log" 2>&1 || true
    rm -f /tmp/e2e-runtime-raw.json
else
    log "MISSING $RUNTIME_SRC"
fi

log "done=$PROFILE install_exit=$install_rc"

python3 /src/tests/e2e-diff/collect/sanitize.py "$OUT/install.log" "$OUT/expect.log" \
    "$OUT/capture.log" >>"$OUT/capture.log" 2>&1 || true

exit "$install_rc"
