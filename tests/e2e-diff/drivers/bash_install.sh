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
#   E2E_OUT       evidence directory for this round (required)
#   E2E_PREV_OUT  round-1 evidence directory (round 2 only, for L6)
#   E2E_SCENARIO  M1..M10
#   E2E_ROUND     1 | 2
#   E2E_PROFILE   reality | tls | relay
#   E2E_ARG       install.sh entry argument (-2 / -1 / --install-relay)
#   E2E_MENU E2E_TRANSPORT E2E_LISTEN_ADDR
#   E2E_DOMAIN E2E_TARGET E2E_PORT E2E_LOCAL_IP E2E_RELAY_HOST E2E_RELAY_PORT
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

# The installer treats a missing /etc/idleleo/install.sh as a fresh bootstrap and
# refuses to continue without remote Release metadata. Seed the tracked copy so
# the flow under test runs locally instead of downloading itself.
mkdir -p /etc/idleleo /etc/idleleo/tmp
install -m 0755 /src/install.sh /etc/idleleo/install.sh
log "seeded_installer=yes"

# Local version metadata keeps read_version/check_online_version_connect off the
# network. The shell version must match the tracked script under test.
src_version=$(grep -m1 '^shell_version=' /src/install.sh | awk -F'=|"' '{print $3}')
src_version="${src_version:-3.3.6}"
cat >/etc/idleleo/versions.json <<JSON
{"shell_online_version":"${src_version}","shell_release_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","xray_online_version":"26.10.31","xray_installer_ref":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","xray_installer_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","nginx_build_online_version":"2026.10.15.7679"}
JSON
export XRAY_VERSIONS_FILE=/etc/idleleo/versions.json
log "seeded_versions=yes shell=${src_version}"

# Seed the pinned Xray binary so the installer skips its own download; every
# config/install step still executes for real.
# A relay owns the whole host and refuses to coexist with an Xray config, so
# only node profiles receive the seeded binary/config.
if [[ "$PROFILE" != "relay" && -f /seed/xray ]]; then
    install -m 0755 /seed/xray /usr/local/bin/xray
    mkdir -p /etc/idleleo/conf/xray /var/log/xray
    # Only round 1 gets a placeholder. Round 2 must see the config produced by
    # round 1, otherwise bash's "keep existing config" reinstall keeps the empty
    # placeholder and the idempotency round tests nothing.
    if [[ "$ROUND" == "1" && ! -f /etc/idleleo/conf/xray/config.json ]]; then
        printf '%s\n' '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}' \
            >/etc/idleleo/conf/xray/config.json
    fi
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
fi

# Helper scripts and the release marker are needed by every profile (the relay
# path also runs basic_optimization and the release reconciliation hook).
if [[ -d /src/scripts ]]; then
    mkdir -p /etc/idleleo/scripts
    for helper in fail2ban_manager.sh traffic_blocker.sh file_manager.sh \
                  auto_update.sh ssl_update.sh geo_update.sh xray_stats.sh; do
        [[ -f "/src/scripts/${helper}" ]] && install -m 0644 "/src/scripts/${helper}" "/etc/idleleo/scripts/${helper}"
    done
    printf '%s\n' "${src_version}" >/etc/idleleo/release-managed.version
    log "seeded_release_helpers=yes version=${src_version}"
fi

# TLS profile: pre-existing certificate, so ssl_judge_and_install keeps it and
# never contacts an ACME directory. M8 (E2E_ACME=1) is the exception: it must
# reach Pebble, so the self-signed pair stays out of the way and the Bash acme()
# helper gets the idleleo binary it shells out to.
if [[ "${E2E_ACME:-0}" == "1" && "${E2E_ACME_MODE:-go}" == "bash" ]]; then
    # PURE_BASH_ACME: no Go binary may participate in issuance or renewal.
    # The disposable image does not ship acme.sh and the runner has no network
    # to fetch it, so the only honest result is BLOCKED, never PASS.
    if [[ ! -x "${HOME}/.acme.sh/acme.sh" ]]; then
        log "acme_mode=pure_bash status=BLOCKED reason=acme.sh-not-installed"
        printf '%s\n' '{"status":"BLOCKED","acmeMode":"pure_bash","reason":"acme.sh is absent from the disposable image; pure Bash ACME cannot be claimed"}' \
            >"$OUT/acme-pure-bash.json"
        exit 3
    fi
    log "acme_mode=pure_bash acme.sh=$("${HOME}/.acme.sh/acme.sh" --version 2>/dev/null | head -1)"
    log "acme_mode=pure_bash status=READY (no idleleo binary will be installed)"
elif [[ "${E2E_ACME:-0}" == "1" ]]; then
    install -m 0755 /seed/idleleo /usr/local/bin/idleleo
    log "acme_mode=pebble idleleo=$(/usr/local/bin/idleleo --version 2>/dev/null | head -1)"
    # install.sh issues through `idleleo xray cert issue` but its Bash path never
    # registers a renewal scheduler, so its own post-install assertion
    # ("证书续期断言失败: 没有找到任何续期调度") always fails. Perform the
    # documented operator step (idleleo schedule install) instead of editing
    # install.sh; IDLELEO_ACME_DIRECTORY is already in the environment.
    IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
        /usr/local/bin/idleleo schedule install --interval 3600 \
        --cert-domain "${E2E_DOMAIN:-example.com}" \
        --cert-out etc/idleleo/cert/xray.crt \
        --cert-key-out etc/idleleo/cert/xray.key \
        --container --json >"$OUT/acme-schedule.json" 2>&1 ||
        log "acme_schedule=install_failed"
    log "acme_schedule=$(tr '\n' ' ' <"$OUT/acme-schedule.json" 2>/dev/null | head -c 200)"
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

export E2E_LOG="$OUT/install.log" E2E_PROFILE="$PROFILE" E2E_INSTALL_ARG="${E2E_ARG:-}"
export E2E_SCENARIO="$SCENARIO" E2E_ROUND="$ROUND" E2E_MENU="${E2E_MENU:-}"
export E2E_TRANSPORT="${E2E_TRANSPORT:-1}" E2E_LISTEN_ADDR="${E2E_LISTEN_ADDR:-0.0.0.0}"
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
E2E_COLLECT_OUT="$OUT" bash /src/tests/e2e-diff/collect/logs.sh >>"$OUT/capture.log" 2>&1 || true
crontab -l >"$OUT/cron.txt" 2>/dev/null || : >"$OUT/cron.txt"
if [[ "$ROUND" == "2" && -n "${E2E_PREV_OUT:-}" ]]; then
    E2E_IDEM_PREV="$E2E_PREV_OUT" E2E_IDEM_CUR="$OUT" \
        bash /src/tests/e2e-diff/collect/idempotency.sh >>"$OUT/capture.log" 2>&1 || true
fi

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
