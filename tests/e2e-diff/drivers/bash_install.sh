#!/usr/bin/env bash
# Runs the real Bash installer inside the e2e container and captures L0-L3.
#
# Derived from tests/go-parity/a2/run_bash_real_install.sh. Differences:
#   * profile-driven (reality | tls | relay) instead of mode/transport pair;
#   * TLS profile seeds a pre-generated self-signed certificate so the flow
#     takes the "证书文件已存在, 是否保留" branch instead of ACME;
#   * collection is delegated to collect/manifest.sh + collect/runtime.sh.
#
# Environment:
#   E2E_OUT      evidence directory for this side (required)
#   E2E_PROFILE  reality | tls | relay
#   E2E_ARG      install.sh entry argument (-2 / -1 / --install-relay)
#   E2E_DOMAIN E2E_TARGET E2E_PORT E2E_LOCAL_IP E2E_RELAY_HOST E2E_RELAY_PORT
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

# Seed the pinned Xray binary so the installer skips its own download; every
# config/install step still executes for real.
if [[ -f /seed/xray ]]; then
    install -m 0755 /seed/xray /usr/local/bin/xray
    mkdir -p /etc/idleleo/conf/xray /var/log/xray
    printf '%s\n' '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}' \
        >/etc/idleleo/conf/xray/config.json
    cat >/etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls/xray-core
After=network.target nss-lookup.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/idleleo/conf/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload || true
    log "seeded_xray=$(/usr/local/bin/xray version 2>/dev/null | head -1)"
    if [[ -d /src/scripts ]]; then
        mkdir -p /etc/idleleo/scripts
        for helper in fail2ban_manager.sh traffic_blocker.sh file_manager.sh \
                      auto_update.sh ssl_update.sh geo_update.sh xray_stats.sh; do
            [[ -f "/src/scripts/${helper}" ]] && install -m 0644 "/src/scripts/${helper}" "/etc/idleleo/scripts/${helper}"
        done
        src_version=$(grep -m1 '^shell_version=' /src/install.sh | awk -F'=|"' '{print $3}')
        if [[ -n "${src_version}" ]]; then
            printf '%s\n' "${src_version}" >/etc/idleleo/release-managed.version
            log "seeded_release_helpers=yes version=${src_version}"
        fi
    fi
fi

# TLS profile: pre-existing certificate, so ssl_judge_and_install keeps it and
# never contacts an ACME directory.
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

export E2E_LOG="$OUT/install.log" E2E_PROFILE="$PROFILE" E2E_INSTALL_ARG="${E2E_ARG:--2}"
export E2E_DOMAIN="${E2E_DOMAIN:-example.com}" E2E_TARGET="${E2E_TARGET:-www.cloudflare.com}"
export E2E_PORT="${E2E_PORT:-443}" E2E_LOCAL_IP="${E2E_LOCAL_IP:-127.0.0.1}"
export E2E_RELAY_HOST="${E2E_RELAY_HOST:-origin.example.com}" E2E_RELAY_PORT="${E2E_RELAY_PORT:-443}"
set +e
expect -f /src/tests/e2e-diff/drivers/bash_menu.exp >>"$OUT/expect.log" 2>&1
install_rc=$?
set -e
log "install_exit=$install_rc"
printf '%s\n' "$install_rc" >"$OUT/rc.txt"

# Captured side effects the Go side must reproduce.
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/manifest.sh >>"$OUT/capture.log" 2>&1 || true
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/runtime.sh >>"$OUT/capture.log" 2>&1 || true

RUNTIME_SRC="/etc/idleleo/conf/xray/config.json"
mkdir -p "$OUT/config"
if [[ -f "$RUNTIME_SRC" ]]; then
    # Raw copy stays in the container; only the sanitized view and hashed
    # identity leave it.
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

# The installer prints a share URI carrying the UUID; redact before the tree
# is committed.
python3 /src/tests/e2e-diff/collect/sanitize.py "$OUT/install.log" "$OUT/expect.log" \
    "$OUT/capture.log" >>"$OUT/capture.log" 2>&1 || true

exit "$install_rc"
