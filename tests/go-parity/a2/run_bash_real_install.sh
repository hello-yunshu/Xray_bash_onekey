#!/usr/bin/env bash
# Runs the real Bash installer inside the disposable A2 systemd container and
# captures the runtime Xray config it actually deployed.
set -uo pipefail

OUT="${A2_OUT:?A2_OUT required}"
MODE="${A2_MODE:?A2_MODE required}"
TRANSPORT="${A2_TRANSPORT:?A2_TRANSPORT required}"
mkdir -p "$OUT"
: >"$OUT/capture.log"
: >"$OUT/install.log"
: >"$OUT/expect.log"

log() { printf '%s\n' "$*" | tee -a "$OUT/capture.log"; }

RUN_ID="${MODE}-${TRANSPORT}"
log "run=$RUN_ID"
log "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "image=${A2_IMAGE_ID:-unknown}"
log "install_source_sha256=$(sha256sum /src/install.sh | awk '{print $1}')"

# --- prove the systemd probe is live -------------------------------------
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

pre_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
log "container_ipv4=${pre_ip:-none}"

# Reuse the exact pinned Xray binary from a previous capture so later runs do
# not spend minutes re-downloading it. The installer still detects the right
# version and skips its own download; every config step still runs for real.
if [[ -f /seed/xray ]]; then
    install -m 0755 /seed/xray /usr/local/bin/xray
    mkdir -p /etc/idleleo/conf/xray /var/log/xray
    printf '%s\n' '{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}' \
        >/etc/idleleo/conf/xray/config.json
    # `xray_install_release` normally creates the unit and log directory. Seed
    # the equivalent side effects so later real install steps (enable/restart)
    # run against the same layout instead of a half-provisioned host.
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
    # Startup reconciles shell helpers from raw.githubusercontent before the
    # install flow runs. That fetch is unrelated to the runtime under test and
    # a transient 5xx aborts the whole run, so seed the repo copies and the
    # release marker. Every config/install step below still executes for real.
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

# --- drive the real interactive install ----------------------------------
export A2_LOG="$OUT/install.log"
export A2_MODE A2_TRANSPORT A2_TARGET A2_ADD_MORE A2_PORT_ANSWER
set +e
expect -f /src/tests/go-parity/a2/drive_install.exp >>"$OUT/expect.log" 2>&1
install_rc=$?
set -e
log "install_exit=$install_rc"

# Record what the bootstrap actually executed (install.sh may refresh itself).
if [[ -f /etc/idleleo/install.sh ]]; then
    log "executed_script_sha256=$(sha256sum /etc/idleleo/install.sh | awk '{print $1}')"
    grep -m1 '^shell_version=' /etc/idleleo/install.sh | sed 's/^/executed_/' | tee -a "$OUT/capture.log"
fi

# --- capture deployed artifacts -----------------------------------------
RUNTIME_SRC="/etc/idleleo/conf/xray/config.json"
META_SRC="/etc/idleleo/conf/install_config.json"
INFO_SRC="/etc/idleleo/info/xray_info.inf"
mkdir -p "$OUT/runtime" "$OUT/metadata" "$OUT/state"

for pair in "$RUNTIME_SRC:runtime/config.json" "$META_SRC:metadata/install_config.json" "$INFO_SRC:metadata/xray_info.inf"; do
    src=${pair%%:*}; dst=${pair#*:}
    if [[ -f "$src" ]]; then
        cp "$src" "$OUT/$dst"
        chmod 600 "$OUT/$dst"
        log "captured $src -> $dst"
    else
        log "MISSING $src"
    fi
done

if [[ -f /etc/systemd/system/xray.service ]]; then
    cp /etc/systemd/system/xray.service "$OUT/state/xray.service"
fi
systemctl is-active xray >"$OUT/state/xray-active.txt" 2>&1 || true
systemctl is-enabled xray >"$OUT/state/xray-enabled.txt" 2>&1 || true
/usr/local/bin/xray version >"$OUT/state/xray-version.txt" 2>&1 || true
ss -lntp >"$OUT/state/listeners.txt" 2>&1 || true
if [[ -f /usr/local/bin/xray && -f "$RUNTIME_SRC" ]]; then
    set +e
    /usr/local/bin/xray -test -config "$RUNTIME_SRC" >"$OUT/state/xray-test.log" 2>&1
    test_rc=$?
    set -e
    log "xray_test_exit=$test_rc"
else
    log "xray_test_skipped=missing binary or runtime"
fi

if [[ -f "$RUNTIME_SRC" ]]; then
    runtime_sha=$(sha256sum "$RUNTIME_SRC" | awk '{print $1}')
    log "runtime_sha256=$runtime_sha"
    # Sanitized copy: privateKey material is replaced before it leaves the box.
    jq '(.inbounds[]?.streamSettings.realitySettings.privateKey?) = "REDACTED"
        | (.inbounds[]?.streamSettings.realitySettings.settings?.privateKey?) = "REDACTED"' \
        "$RUNTIME_SRC" >"$OUT/runtime/config.sanitized.json" 2>/dev/null || cp "$RUNTIME_SRC" "$OUT/runtime/config.sanitized.json"
    jq -S . "$OUT/runtime/config.sanitized.json" >"$OUT/runtime/config.sorted.json" 2>/dev/null || true
fi
if [[ -f "$META_SRC" ]]; then
    jq '.privateKey = "REDACTED"' "$META_SRC" >"$OUT/metadata/install_config.sanitized.json" 2>/dev/null || \
        cp "$META_SRC" "$OUT/metadata/install_config.sanitized.json"
fi
if [[ -f "$INFO_SRC" ]]; then
    sed -E 's/(privateKey[=:][[:space:]]*).*/\1REDACTED/I' "$INFO_SRC" >"$OUT/metadata/xray_info.sanitized.inf" || true
fi

# --- structured summary --------------------------------------------------
runtime_json="$OUT/runtime/config.sanitized.json"
if [[ -f "$runtime_json" ]]; then
    jq -r '
        {
          inbounds: [.inbounds[]? | {
            tag, listen, port, protocol,
            network: .streamSettings.network,
            security: .streamSettings.security,
            wsPath: .streamSettings.wsSettings.path,
            grpcServiceName: .streamSettings.grpcSettings.serviceName,
            xhttpPath: .streamSettings.xhttpSettings.path,
            reality: (if .streamSettings.security == "reality" then {
                target: .streamSettings.realitySettings.target,
                serverNames: .streamSettings.realitySettings.serverNames,
                shortIds: .streamSettings.realitySettings.shortIds,
                publicKey: .streamSettings.realitySettings.publicKey,
                fingerprint: .streamSettings.realitySettings.fingerprint,
                spiderX: .streamSettings.realitySettings.spiderX,
                minClientVer: .streamSettings.realitySettings.minClientVer,
                maxClientVer: .streamSettings.realitySettings.maxClientVer
            } else null end),
            clients: [.settings.clients[]? | {id, email, flow}]
          }],
          routing: .routing,
          dns: .dns,
          outbounds: [.outbounds[]? | {tag, protocol}],
          log: .log,
          policy: .policy
        }' "$runtime_json" >"$OUT/runtime/summary.json"
fi

cat >"$OUT/facts.json" <<EOF
{
  "run": "$RUN_ID",
  "mode": "$MODE",
  "transport": "$TRANSPORT",
  "installExit": $install_rc,
  "systemdState": "$state",
  "executedScriptSha256": "$(sha256sum /etc/idleleo/install.sh 2>/dev/null | awk '{print $1}')",
  "sourceScriptSha256": "$(sha256sum /src/install.sh | awk '{print $1}')",
  "runtimeSha256": "${runtime_sha:-}",
  "xrayVersion": "$(head -1 "$OUT/state/xray-version.txt" 2>/dev/null | tr -d '"')",
  "serviceActive": "$(cat "$OUT/state/xray-active.txt" 2>/dev/null)"
}
EOF

log "done=$RUN_ID install_exit=$install_rc"
exit "$install_rc"
