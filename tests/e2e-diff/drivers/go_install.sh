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
#   E2E_OUT       evidence directory for this round (required)
#   E2E_PREV_OUT  round-1 evidence directory (round 2 only, for L6)
#   E2E_SCENARIO  M1..M10
#   E2E_ROUND     1 | 2 (round 2 appends --keep-config)
#   E2E_PROFILE   reality | tls | relay (drives certificate seeding only)
set -uo pipefail

OUT="${E2E_OUT:?E2E_OUT required}"
PROFILE="${E2E_PROFILE:?E2E_PROFILE required}"
SCENARIO="${E2E_SCENARIO:?E2E_SCENARIO required}"
ROUND="${E2E_ROUND:-1}"
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

if [[ "$PROFILE" != "relay" && -f /seed/xray ]]; then
    install -m 0755 /seed/xray /usr/local/bin/xray
    log "seeded_xray=$(/usr/local/bin/xray version 2>/dev/null | head -1)"
fi
if [[ -f /seed/idleleo ]]; then
    install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    log "idleleo_version=$(/usr/local/bin/idleleo --version 2>/dev/null | head -1)"
fi

if [[ "${E2E_ACME:-0}" == "1" ]]; then
    if [[ "$ROUND" == "1" ]]; then
        mkdir -p /etc/idleleo/cert
        ca_args=()
        [[ -f /test/certs/pebble.minica.pem ]] && ca_args=(--ca-cert /test/certs/pebble.minica.pem)
        log "acme_directory=${IDLELEO_ACME_DIRECTORY:-unset}"
        set +e
        /usr/local/bin/idleleo xray cert issue \
            --domain "${E2E_DOMAIN:-example.com}" \
            --email "${E2E_ACME_EMAIL:-e2e@example.com}" \
            --directory "${IDLELEO_ACME_DIRECTORY:?IDLELEO_ACME_DIRECTORY required for ACME}" \
            "${ca_args[@]+"${ca_args[@]}"}" \
            --webroot /etc/idleleo/conf \
            --cert-out /etc/idleleo/cert/xray.crt \
            --key-out /etc/idleleo/cert/xray.key \
            --takeover --force >>"$OUT/install.log" 2>&1
        issue_rc=$?
        set -e
        log "acme_issue_exit=$issue_rc"
        printf '%s\n' "$issue_rc" >"$OUT/acme.rc"
        if [[ "$issue_rc" != "0" ]]; then
            exit "$issue_rc"
        fi
    elif [[ -f /etc/idleleo/cert/xray.crt && -f /etc/idleleo/cert/xray.key ]]; then
        log "acme_reuse=round$ROUND"
    else
        log "FATAL: round $ROUND needs the round-1 ACME certificate pair"
        exit 2
    fi
elif [[ "$PROFILE" == "tls" ]]; then
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
GO_ARGS=("$@")
if [[ "$ROUND" == "2" ]]; then
    GO_ARGS+=(--keep-config)
    log "round2_mode=keep-config"
fi
set +e
/usr/local/bin/idleleo xray install "${GO_ARGS[@]}" >>"$OUT/install.log" 2>&1
install_rc=$?
set -e
log "install_exit=$install_rc"
printf '%s\n' "$install_rc" >"$OUT/rc.txt"

# Neither installer schedules renewal by itself, and the Bash side cannot finish
# M8 without an active scheduler (install.sh asserts one). Run the documented
# operator step on both sides so the two layouts converge instead of registering
# a harness-only difference.
if [[ "${E2E_ACME:-0}" == "1" && "$ROUND" == "1" ]]; then
    set +e
    /usr/local/bin/idleleo schedule install --interval 3600 \
        --cert-domain "${E2E_DOMAIN:-example.com}" \
        --cert-out etc/idleleo/cert/xray.crt \
        --cert-key-out etc/idleleo/cert/xray.key \
        --container --json >"$OUT/acme-schedule.json" 2>&1
    log "schedule_install_exit=$?"
    set -e
fi

E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/manifest.sh >>"$OUT/capture.log" 2>&1 || true
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/runtime.sh >>"$OUT/capture.log" 2>&1 || true
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/logs.sh >>"$OUT/capture.log" 2>&1 || true
crontab -l >"$OUT/cron.txt" 2>/dev/null || : >"$OUT/cron.txt"
if [[ "$ROUND" == "2" && -n "${E2E_PREV_OUT:-}" ]]; then
    E2E_IDEM_PREV="$E2E_PREV_OUT" E2E_IDEM_CUR="$OUT" \
        bash /src/tests/e2e-diff/collect/idempotency.sh >>"$OUT/capture.log" 2>&1 || true
fi

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
