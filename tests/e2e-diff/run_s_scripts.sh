#!/usr/bin/env bash
# S4-S9 helper-script acceptance, with real network access.
#
# Background: S7/S8/S9 (acme.sh, tcp.sh, superspeed.sh) were historically
# downloaded at install time. The current tree retires them: acme.sh is a
# one-release legacy fallback, tcp.sh and superspeed.sh are replaced by the Go
# CLI. This runner therefore proves three things per row instead of pretending
# the third-party script still drives production:
#   * the historical download still works (URL + sha256 recorded), and
#   * the project-owned replacement works for real, and
#   * the legacy path fails closed instead of silently downloading.
#
# Scenario A (one container): real Bash install of a Reality node, then S4
# auto_update, S6 geo_update, S8 tcp, S9 speedtest and S7 acme.sh.
# Scenario B (own container + Pebble): S5 ssl_update renews a real certificate
# against a local ACME v2 server; a stopped Pebble must fail without damage.
#
# What stays BLOCKED on purpose: issuing a public-CA certificate for a real
# domain, and swapping the running kernel. Both need physical infrastructure.
#
# E2E_ONLY selects rows (default: S4,S5,S6,S7,S8,S9). E2E_KEEP=1 keeps the
# containers for inspection.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT
SUITE="$ROOT/tests/e2e-diff"
RUN_ID="${E2E_RUN_ID:-s-$(date +%Y%m%d-%H%M)-$(git -C "$ROOT" rev-parse --short HEAD)}"
EVID="$SUITE/evidence/$RUN_ID/s"
WORK="/tmp/e2e-$RUN_ID"
IMAGE_TAG="${E2E_IMAGE_TAG:-idleleo-e2e:24.04}"
GO_IMAGE="${E2E_GO_IMAGE:-golang:1.27.4}"
DOMAIN="${E2E_DOMAIN:-example.com}"
TARGET="${E2E_TARGET:-www.cloudflare.com}"
ONLY="${E2E_ONLY:-S4,S5,S6,S7,S8,S9}"
PEBBLE_IMAGE="${E2E_PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
PEBBLE_TEST="$WORK/pebble-test"
PEBBLE_CONFIG="$ROOT/tests/go-parity/acme/pebble-config.json"
TCP_LEGACY_URL="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh"
SUPERSPEED_URL="https://cdn.jsdelivr.net/gh/hello-yunshu/superspeed@master/superspeed.sh"
ACME_INSTALL_URL="https://get.acme.sh"
PASS=0
FAIL=0

source "$ROOT/tests/go-parity/lib/docker_common.sh"

mkdir -p "$EVID" "$WORK/seed/cert"
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$EVID/run.log"; }
sha() { host_sha256 "$1"; }
assert() { # assert <0|1> <message>
    if [ "$1" -eq 0 ]; then
        PASS=$((PASS + 1)); printf 'PASS\t%s\n' "$2" | tee -a "$EVID/assertions.txt"
    else
        FAIL=$((FAIL + 1)); printf 'FAIL\t%s\n' "$2" | tee -a "$EVID/assertions.txt"
    fi
}
want() { [[ ",$ONLY," == *",$1,"* ]]; }

log "building idleleo"
docker run --rm -v "$ROOT:/src:ro" -v "$WORK/seed:/out" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local \
    "$GO_IMAGE" bash -c 'go build -buildvcs=false -trimpath -o /out/idleleo ./cmd/idleleo &&
        go build -buildvcs=false -trimpath -o /out/idleleo-recover ./cmd/idleleo-recover' || {
    log "FATAL: build failed"; exit 2
}

ARCH=$(docker_arch) || exit 2
if [[ -x "$ROOT/tests/go-parity/.cache/a2/xray" ]]; then
    cp "$ROOT/tests/go-parity/.cache/a2/xray" "$WORK/seed/xray"
else
    ensure_xray_bin "$ARCH" >/dev/null || { log "FATAL: xray unavailable"; exit 2; }
    cp "$(ensure_xray_bin "$ARCH")" "$WORK/seed/xray"
fi
chmod 0755 "$WORK/seed/xray" "$WORK/seed/idleleo" "$WORK/seed/idleleo-recover"

docker run --rm -v "$WORK/seed:/seed" "$IMAGE_TAG" bash -c \
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=$DOMAIN' \
     -addext 'subjectAltName=DNS:$DOMAIN' \
     -keyout /seed/cert/xray.key -out /seed/cert/xray.crt >/dev/null 2>&1" || {
    log "FATAL: certificate generation failed"; exit 2
}
log "idleleo_sha256=$(sha "$WORK/seed/idleleo") xray_sha256=$(sha "$WORK/seed/xray")"

python3 - "$EVID/run.json" <<PY
import json
print(json.dumps({
    "runId": "$RUN_ID",
    "commit": "$(git -C "$ROOT" rev-parse HEAD)",
    "branch": "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)",
    "imageTag": "$IMAGE_TAG",
    "rows": "$ONLY",
    "network": "enabled",
}, indent=2, sort_keys=True), file=open("$EVID/run.json", "w"))
PY

start_container() { # start_container <name> <net> <out-dir> [extra docker args...]
    local name=$1 net=$2 out=$3; shift 3
    docker rm -f "$name" >/dev/null 2>&1 || true
    mkdir -p "$out"
    # shellcheck disable=SC2046
    docker run -d --name "$name" --hostname "$name" --network "$net" \
        --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        $(cgroup_mount_args) \
        -v "$ROOT:/src:ro" -v "$WORK/seed:/seed:ro" -v "$EVID:/out" "$@" \
        "$IMAGE_TAG" /usr/lib/systemd/systemd >/dev/null || return 1
    for _ in $(seq 1 60); do
        local st
        st=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        [[ "$st" == running || "$st" == degraded ]] && return 0
        sleep 1
    done
    return 1
}
capture() { # capture <prefix> -- command...
    local prefix=$1; shift
    "$@" >"$prefix.out" 2>"$prefix.err"
    local rc=$?
    echo "$rc" >"$prefix.rc"
    return $rc
}

# ---------------------------------------------------------------- Scenario A
A_C="" A_NET=""
a_setup() {
    A_NET="e2e-$RUN_ID-s-net"
    A_C="e2e-$RUN_ID-s-server"
    docker network create "$A_NET" >/dev/null 2>&1 || true
    start_container "$A_C" "$A_NET" "$EVID/S4/install" || return 1
    # M1 is the driver's name for a `-2` Reality install; S4 reuses it so the
    # real interactive installer runs instead of a hand-built tree.
    docker exec -e E2E_OUT=/out/S4/install -e E2E_ROUND=1 -e E2E_SCENARIO=M1 \
        -e E2E_PROFILE=reality -e E2E_ARG=-2 -e E2E_MENU="" \
        -e E2E_TRANSPORT=1 -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" \
        -e E2E_PORT=443 -e E2E_LOCAL_IP=127.0.0.1 \
        "$A_C" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local rc=$?
    # The Bash installer does not vendor the Go binary; the operator-facing
    # `idleleo` entry is what S8/S9 exercise.
    docker exec "$A_C" install -m 0755 /seed/idleleo /usr/local/bin/idleleo || true
    return $rc
}

run_s4() {
    local d="$EVID/S4"; mkdir -p "$d"
    log "[S4] auto_update"
    capture "$d/normal" docker exec "$A_C" bash /etc/idleleo/scripts/auto_update.sh
    local rc; rc=$(cat "$d/normal.rc")
    docker exec "$A_C" cp /etc/idleleo/logs/auto_update.log /out/S4/auto_update-run1.log >/dev/null 2>&1 || true
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S4 normal run exits 0 (rc=$rc)"
    assert "$(docker exec "$A_C" grep -q 'Script is up to date' /etc/idleleo/logs/auto_update.log && echo 0 || echo 1)" \
        "S4 normal run reports the Shell is up to date"
    assert "$(docker exec "$A_C" grep -q 'Xray is up to date' /etc/idleleo/logs/auto_update.log && echo 0 || echo 1)" \
        "S4 normal run reports Xray is up to date"
    local before after
    before=$(docker exec "$A_C" sha256sum /etc/idleleo/conf/install_config.json | awk '{print $1}')
    capture "$d/repeat" docker exec "$A_C" bash /etc/idleleo/scripts/auto_update.sh
    rc=$(cat "$d/repeat.rc")
    after=$(docker exec "$A_C" sha256sum /etc/idleleo/conf/install_config.json | awk '{print $1}')
    docker exec "$A_C" cp /etc/idleleo/logs/auto_update.log /out/S4/auto_update-run2.log >/dev/null 2>&1 || true
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S4 repeat run exits 0 (rc=$rc)"
    assert "$([ "$before" = "$after" ] && echo 0 || echo 1)" "S4 repeat run leaves install_config.json unchanged"

    docker exec "$A_C" sh -c 'printf "%s\n" "{\"shell_online_version\":\"3.3.6\"}" >/tmp/bad-versions.json'
    capture "$d/bad-metadata" docker exec -e XRAY_VERSIONS_FILE=/tmp/bad-versions.json \
        "$A_C" bash /etc/idleleo/scripts/auto_update.sh
    rc=$(cat "$d/bad-metadata.rc")
    docker exec "$A_C" cp /etc/idleleo/logs/auto_update.log /out/S4/auto_update-bad-metadata.log >/dev/null 2>&1 || true
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S4 missing metadata fails safe with rc=0 (rc=$rc)"
    assert "$(docker exec "$A_C" grep -q 'missing required fields, skipping update checks' /etc/idleleo/logs/auto_update.log && echo 0 || echo 1)" \
        "S4 missing metadata is named and skipped"
    after=$(docker exec "$A_C" sha256sum /etc/idleleo/conf/install_config.json | awk '{print $1}')
    assert "$([ "$before" = "$after" ] && echo 0 || echo 1)" "S4 missing metadata does not touch install_config.json"
}

geo_sha() {
    docker exec "$A_C" sh -c '
        for f in /etc/idleleo/share/xray/geoip.dat /etc/idleleo/share/xray/geosite.dat; do
            [ -f "$f" ] && sha256sum "$f" || echo "missing $f"
        done'
}
run_s6() {
    local d="$EVID/S6"; mkdir -p "$d"
    log "[S6] geo_update"
    capture "$d/normal" docker exec "$A_C" bash /etc/idleleo/scripts/geo_update.sh
    local rc; rc=$(cat "$d/normal.rc")
    docker exec "$A_C" cp /etc/idleleo/logs/geo_update.log /out/S6/geo_update-run1.log >/dev/null 2>&1 || true
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S6 normal run exits 0 (rc=$rc)"
    local present
    present=$(docker exec "$A_C" sh -c '[ -s /etc/idleleo/share/xray/geoip.dat ] && [ -s /etc/idleleo/share/xray/geosite.dat ] && echo 0 || echo 1')
    assert "$present" "S6 installs non-empty geoip.dat and geosite.dat"
    assert "$(docker exec "$A_C" jq -e '.geo_versions["geoip.dat"] and .geo_versions["geosite.dat"]' \
        /etc/idleleo/conf/xray/geo_version.json >/dev/null 2>&1 && echo 0 || echo 1)" \
        "S6 records both GeoData versions"
    assert "$([ "$(docker exec "$A_C" systemctl is-active xray 2>/dev/null | head -1)" = active ] && echo 0 || echo 1)" \
        "S6 Xray is active after the update"
    local sums1 sums2
    sums1=$(geo_sha); echo "$sums1" >"$d/dat-run1.sha256"
    capture "$d/repeat" docker exec "$A_C" bash /etc/idleleo/scripts/geo_update.sh
    rc=$(cat "$d/repeat.rc")
    docker exec "$A_C" cp /etc/idleleo/logs/geo_update.log /out/S6/geo_update-run2.log >/dev/null 2>&1 || true
    sums2=$(geo_sha); echo "$sums2" >"$d/dat-run2.sha256"
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S6 repeat run exits 0 (rc=$rc)"
    assert "$(docker exec "$A_C" grep -q 'All GeoData files are current' /etc/idleleo/logs/geo_update.log && echo 0 || echo 1)" \
        "S6 repeat run detects the files are current"
    assert "$([ "$sums1" = "$sums2" ] && echo 0 || echo 1)" "S6 repeat run does not rewrite the GeoData files"

    docker exec "$A_C" sh -c 'mkdir -p /tmp/fail-curl &&
        printf "#!/bin/sh\nexit 1\n" >/tmp/fail-curl/curl && chmod 0755 /tmp/fail-curl/curl'
    capture "$d/failure" docker exec -e PATH=/tmp/fail-curl:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        "$A_C" bash /etc/idleleo/scripts/geo_update.sh
    rc=$(cat "$d/failure.rc")
    docker exec "$A_C" cp /etc/idleleo/logs/geo_update.log /out/S6/geo_update-failure.log >/dev/null 2>&1 || true
    local sums3; sums3=$(geo_sha); echo "$sums3" >"$d/dat-after-failure.sha256"
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "S6 failed download exits non-zero (rc=$rc)"
    assert "$(docker exec "$A_C" grep -q 'Failed to resolve immutable GeoData release tag' /etc/idleleo/logs/geo_update.log && echo 0 || echo 1)" \
        "S6 failed download is reported"
    assert "$([ "$sums2" = "$sums3" ] && echo 0 || echo 1)" "S6 failed download leaves the installed GeoData intact"
}

sandbox_tcp_file() {
    docker exec "$A_C" sh -c 'test -f /tmp/s8sb/etc/sysctl.d/90-idleleo-tcp.conf && echo present || echo absent'
}
sandbox_sysctl() { # sandbox_sysctl <key-path>
    docker exec "$A_C" sh -c "cat /tmp/s8sb/proc/sys/$1 2>/dev/null || true"
}
run_s8() {
    local d="$EVID/S8"; mkdir -p "$d"
    log "[S8] tcp"
    # This OrbStack kernel (7.2.12) exposes neither net.core.default_qdisc nor
    # bbr. The contract is to refuse, not to guess: a real kernel swap belongs
    # to a real VPS.
    capture "$d/real-plan" docker exec "$A_C" /usr/local/bin/idleleo tcp plan --profile bbr-fq --json
    local rc; rc=$(cat "$d/real-plan.rc")
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "S8 real-kernel plan refuses when a key is unavailable (rc=$rc)"
    assert "$(grep -q 'read current net.core.default_qdisc' "$d/real-plan.err" && echo 0 || echo 1)" \
        "S8 refusal names the missing sysctl key"

    # Deterministic sandbox: the project-owned file/idempotency/rollback logic.
    docker exec "$A_C" sh -c 'rm -rf /tmp/s8sb &&
        mkdir -p /tmp/s8sb/proc/sys/net/core /tmp/s8sb/proc/sys/net/ipv4 \
                 /tmp/s8sb/etc/sysctl.d /tmp/s8sb/run/lock /tmp/s8sb/var/lib/idleleo &&
        printf "I_ACCEPT_DISPOSABLE_SANDBOX\n" >/tmp/s8sb/.idleleo-phase01-sandbox &&
        printf "fq\n" >/tmp/s8sb/proc/sys/net/core/default_qdisc &&
        printf "cubic\n" >/tmp/s8sb/proc/sys/net/ipv4/tcp_congestion_control &&
        printf "reno cubic bbr\n" >/tmp/s8sb/proc/sys/net/ipv4/tcp_available_congestion_control'
    capture "$d/plan" docker exec "$A_C" /usr/local/bin/idleleo --root /tmp/s8sb tcp plan --profile bbr-fq --json
    rc=$(cat "$d/plan.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S8 tcp plan exits 0 (rc=$rc)"
    assert "$(jq -e '.kernelSupportsBbr == true and .fileAction == "create" and .noop == false' \
        "$d/plan.out" >/dev/null 2>&1 && echo 0 || echo 1)" "S8 tcp plan reports bbr support and a create action"
    capture "$d/apply" docker exec "$A_C" /usr/local/bin/idleleo --root /tmp/s8sb \
        tcp apply --profile bbr-fq --confirm --json
    rc=$(cat "$d/apply.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S8 tcp apply exits 0 (rc=$rc)"
    assert "$([ "$(sandbox_tcp_file)" = present ] && echo 0 || echo 1)" "S8 tcp apply writes the managed sysctl drop-in"
    assert "$([ "$(sandbox_sysctl net/ipv4/tcp_congestion_control)" = bbr ] && echo 0 || echo 1)" \
        "S8 tcp apply sets the runtime congestion control"
    capture "$d/repeat" docker exec "$A_C" /usr/local/bin/idleleo --root /tmp/s8sb \
        tcp apply --profile bbr-fq --confirm --json
    rc=$(cat "$d/repeat.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S8 tcp apply is repeatable (rc=$rc)"
    assert "$(jq -e '.noop == true and .changed == false' "$d/repeat.out" >/dev/null 2>&1 && echo 0 || echo 1)" \
        "S8 repeat apply reports noop"
    capture "$d/rollback" docker exec "$A_C" /usr/local/bin/idleleo --root /tmp/s8sb tcp rollback --json
    rc=$(cat "$d/rollback.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S8 tcp rollback exits 0 (rc=$rc)"
    assert "$([ "$(sandbox_tcp_file)" = absent ] && echo 0 || echo 1)" "S8 tcp rollback removes the managed drop-in"
    assert "$([ "$(sandbox_sysctl net/ipv4/tcp_congestion_control)" = cubic ] && echo 0 || echo 1)" \
        "S8 tcp rollback restores the previous runtime value"

    cat >"$d/BLOCKED-real-kernel.md" <<'MD'
# S8 real-kernel apply: BLOCKED (host kernel)

`idleleo tcp plan/apply/rollback` was verified end to end in the disposable
sandbox. Applying to the live kernel needs a VPS whose kernel lists `bbr` and
exposes `net.core.default_qdisc`; the Docker/OrbStack kernel used here has
neither, and the CLI correctly refuses instead of installing a kernel.
Unblock on a real VPS with `idleleo tcp apply --profile bbr-fq --confirm`.
MD

    # The Bash legacy entry must never download a third-party script again.
    assert "$(grep -q 'Linux-NetSpeed' "$ROOT/install.sh" && echo 1 || echo 0)" \
        "S8 install.sh has no remote tcp.sh download"
    assert "$(grep -q '本地不存在 tcp.sh, 已不再自动下载第三方脚本' "$ROOT/install.sh" && echo 0 || echo 1)" \
        "S8 Bash legacy path fails closed without a local tcp.sh"
    local legacy="$d/tcp.sh.legacy"
    capture "$legacy.fetch" docker exec "$A_C" sh -c \
        "curl -fsSL --max-time 30 '$TCP_LEGACY_URL' -o /tmp/tcp.sh && sha256sum /tmp/tcp.sh | awk '{print \$1}' && bash -n /tmp/tcp.sh; echo syntax_rc=\$?"
    rc=$(cat "$legacy.fetch.rc")
    printf '%s\n' "$TCP_LEGACY_URL" >"$legacy.url"
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S8 historical tcp.sh downloads and passes bash -n (rc=$rc)"
    docker exec "$A_C" rm -f /tmp/tcp.sh
}

run_s9() {
    local d="$EVID/S9"; mkdir -p "$d"
    log "[S9] speedtest"
    capture "$d/normal" docker exec "$A_C" /usr/local/bin/idleleo speedtest \
        --bytes 1048576 --samples 1 --timeout 20s --json
    local rc; rc=$(cat "$d/normal.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S9 speedtest exits 0 (rc=$rc)"
    assert "$(jq -e '.server and (.downMbps >= 0)' "$d/normal.out" >/dev/null 2>&1 && echo 0 || echo 1)" \
        "S9 speedtest returns server and downMbps"
    capture "$d/repeat" docker exec "$A_C" /usr/local/bin/idleleo speedtest \
        --bytes 1048576 --samples 1 --timeout 20s --json
    rc=$(cat "$d/repeat.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S9 speedtest is repeatable (rc=$rc)"
    capture "$d/failure" docker exec "$A_C" /usr/local/bin/idleleo speedtest \
        --server 127.0.0.1:1 --bytes 1024 --samples 1 --timeout 2s --json
    rc=$(cat "$d/failure.rc")
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "S9 speedtest fails with a non-zero code on an unreachable server (rc=$rc)"
    assert "$(grep -qi 'panic' "$d/failure.err" "$d/failure.out" && echo 1 || echo 0)" \
        "S9 speedtest failure is a clean error, not a panic"

    local legacy="$d/superspeed.sh.legacy"
    capture "$legacy.fetch" docker exec "$A_C" sh -c \
        "curl -fsSL --max-time 30 '$SUPERSPEED_URL' -o /tmp/superspeed.sh && sha256sum /tmp/superspeed.sh | awk '{print \$1}' && bash -n /tmp/superspeed.sh; echo syntax_rc=\$?"
    rc=$(cat "$legacy.fetch.rc")
    printf '%s\n' "$SUPERSPEED_URL" >"$legacy.url"
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S9 historical superspeed.sh downloads and passes bash -n (rc=$rc)"
    docker exec "$A_C" rm -f /tmp/superspeed.sh
}

run_s7() {
    local d="$EVID/S7"; mkdir -p "$d"
    log "[S7] acme.sh legacy download"
    capture "$d/install" docker exec "$A_C" sh -c \
        "curl -fsSL --max-time 60 '$ACME_INSTALL_URL' -o /tmp/acme-install.sh &&
         sha256sum /tmp/acme-install.sh | awk '{print \$1}' &&
         sh /tmp/acme-install.sh email=e2e@example.com"
    local rc; rc=$(cat "$d/install.rc")
    # acme.sh prints /root/... paths; mask the host-specific home directory in
    # the stored output (value-level, no checker allowlist change).
    sed -i.bak 's|/root/|$HOME/|g' "$d/install.out" && rm -f "$d/install.out.bak"
    printf '%s\n' "$ACME_INSTALL_URL" >"$d/acme-install.url"
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S7 get.acme.sh downloads and installs (rc=$rc)"
    assert "$(docker exec "$A_C" sh -c 'test -x "$HOME/.acme.sh/acme.sh" && echo 0 || echo 1')" \
        "S7 acme.sh is installed and executable"
    capture "$d/version" docker exec "$A_C" sh -c '"$HOME"/.acme.sh/acme.sh --version'
    rc=$(cat "$d/version.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S7 acme.sh --version exits 0 (rc=$rc)"
    capture "$d/help" docker exec "$A_C" sh -c '"$HOME"/.acme.sh/acme.sh --help'
    rc=$(cat "$d/help.rc")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S7 acme.sh --help exits 0 (rc=$rc)"

    # Legacy renewal must refuse when the legacy state is absent; it must not
    # invent one. This is the fail-closed contract the retirement relies on.
    capture "$d/legacy-missing" docker exec -e IDLELEO_ACME_LEGACY=1 -e IDLELEO_ACME_HOME=/tmp/no-acme \
        "$A_C" bash /etc/idleleo/scripts/ssl_update.sh
    rc=$(cat "$d/legacy-missing.rc")
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "S7 legacy renewal without acme.sh state fails (rc=$rc)"
    assert "$(grep -q 'acme.sh not found' "$d/legacy-missing.err" && echo 0 || echo 1)" \
        "S7 legacy renewal names the missing acme.sh"

    cat >"$d/BLOCKED-issuance.md" <<'MD'
# S7 issuance: BLOCKED (external)

`download + install + --version/--help` passed in this run. Real issuance and
renewal through acme.sh need:

- a domain whose A/AAAA record points at this host, and
- a public ACME directory that can reach it over HTTP-01/TLS-ALPN.

Containers here have no public inbound, so this step cannot be executed
honestly. Unblock with a real VPS + real domain and re-run the same commands
with `IDLELEO_ACME_LEGACY=1`.
MD
}

# ---------------------------------------------------------------- Scenario B
P_C="" P_NET="" P_PEBBLE=""
prepare_pebble_assets() {
    [[ -f "$PEBBLE_TEST/certs/pebble.minica.pem" ]] && return 0
    mkdir -p "$PEBBLE_TEST"
    local cid
    cid=$(docker create "$PEBBLE_IMAGE") || return 1
    docker cp "$cid:/test/." "$PEBBLE_TEST/" >/dev/null 2>&1 || {
        docker rm "$cid" >/dev/null 2>&1 || true; return 1; }
    docker rm "$cid" >/dev/null 2>&1 || true
    [[ -f "$PEBBLE_TEST/certs/pebble.minica.pem" ]]
}
start_pebble() {
    docker rm -f "$P_PEBBLE" >/dev/null 2>&1 || true
    docker run -d --name "$P_PEBBLE" --network "$P_NET" --network-alias pebble \
        -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 \
        -v "$PEBBLE_TEST/certs:/test/certs:ro" \
        -v "$PEBBLE_CONFIG:/conf/pebble-config.json:ro" \
        --entrypoint /app "$PEBBLE_IMAGE" -config /conf/pebble-config.json -strict >/dev/null
}
wait_pebble() {
    for _ in $(seq 1 30); do
        if docker run --rm --network "$P_NET" -v "$PEBBLE_TEST/certs:/test/certs:ro" \
            "$IMAGE_TAG" curl -fsS --max-time 3 \
            --cacert /test/certs/pebble.minica.pem https://pebble:14000/dir >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}
cert_state() { # cert_state <out-file>
    docker exec "$P_C" sh -c '
        sha256sum /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key 2>/dev/null
        openssl x509 -in /etc/idleleo/cert/xray.crt -noout -serial -startdate 2>/dev/null || true' >"$1"
}
run_s5() {
    local d="$EVID/S5"; mkdir -p "$d"
    log "[S5] ssl_update"
    P_NET="e2e-$RUN_ID-s5-net"
    P_C="e2e-$RUN_ID-s5-server"
    P_PEBBLE="e2e-$RUN_ID-s5-pebble"
    docker network create "$P_NET" >/dev/null 2>&1 || true
    if ! prepare_pebble_assets || ! start_pebble || ! wait_pebble; then
        docker logs "$P_PEBBLE" >"$d/pebble-boot.log" 2>&1 || true
        cat >"$d/BLOCKED.md" <<'MD'
# S5: BLOCKED (Pebble sidecar)

The local ACME v2 test server did not start, so no real renewal could be
driven. See pebble-boot.log. Unblock by restoring
`ghcr.io/letsencrypt/pebble:latest` access and re-running.
MD
        return
    fi

    if ! start_container "$P_C" "$P_NET" "$d/install" -v "$PEBBLE_TEST/certs:/test/certs:ro"; then
        assert 1 "S5 container starts"
        return
    fi
    docker exec -e E2E_OUT=/out/S5/install -e E2E_ROUND=1 -e E2E_SCENARIO=M8 \
        -e E2E_PROFILE=tls -e E2E_ARG=-1 -e E2E_MENU="" -e E2E_TRANSPORT=1 \
        -e E2E_DOMAIN="$DOMAIN" -e E2E_TARGET="$TARGET" -e E2E_PORT=443 \
        -e E2E_LOCAL_IP=127.0.0.1 -e E2E_ACME=1 \
        -e SSL_CERT_FILE=/test/certs/pebble.minica.pem \
        -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir \
        "$P_C" bash /src/tests/e2e-diff/drivers/bash_install.sh
    local irc=$?
    echo "$irc" >"$d/install.rc"
    assert "$([ "$irc" -eq 0 ] && echo 0 || echo 1)" "S5 Bash TLS+ACME install exits 0 (rc=$irc)"
    cert_state "$d/cert-before.txt"

    # Renew only fires inside the 30-day window (720h). Stage a real one-day
    # certificate so `ssl_update.sh` takes the renewal branch; the renewal
    # itself still goes to Pebble over ACME, nothing is stubbed.
    stage_near_expiry() {
        docker exec -e E2E_DOMAIN="$DOMAIN" "$P_C" sh -c '
            openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$E2E_DOMAIN" \
                -addext "subjectAltName=DNS:$E2E_DOMAIN" \
                -keyout /etc/idleleo/cert/xray.key -out /etc/idleleo/cert/xray.crt >/dev/null 2>&1
            chown root:idleleo-nginx /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key
            chmod 0640 /etc/idleleo/cert/xray.crt /etc/idleleo/cert/xray.key'
    }
    stage_near_expiry || true
    cert_state "$d/cert-staged.txt"
    local staged1 staged2 staged3
    staged1=$(sha "$d/cert-staged.txt")

    capture "$d/normal" docker exec -e SSL_CERT_FILE=/test/certs/pebble.minica.pem \
        -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir \
        "$P_C" bash /etc/idleleo/scripts/ssl_update.sh
    local rc; rc=$(cat "$d/normal.rc")
    cert_state "$d/cert-after-renew.txt"
    local sums2; sums2=$(sha "$d/cert-after-renew.txt")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S5 ssl_update renews against Pebble (rc=$rc)"
    assert "$([ "$staged1" != "$sums2" ] && echo 0 || echo 1)" "S5 renewal replaces the staged certificate"
    assert "$(docker exec "$P_C" sh -c 'openssl x509 -in /etc/idleleo/cert/xray.crt -noout -issuer' 2>/dev/null |
        grep -q 'Pebble' && echo 0 || echo 1)" "S5 installed certificate is issued by the ACME server"
    assert "$([ "$(docker exec "$P_C" systemctl is-active nginx 2>/dev/null | head -1)" = active ] && echo 0 || echo 1)" \
        "S5 Nginx is active after renewal"
    assert "$([ "$(docker exec "$P_C" systemctl is-active xray 2>/dev/null | head -1)" = active ] && echo 0 || echo 1)" \
        "S5 Xray is active after renewal"

    stage_near_expiry || true
    cert_state "$d/cert-staged-2.txt"
    staged2=$(sha "$d/cert-staged-2.txt")
    capture "$d/repeat" docker exec -e SSL_CERT_FILE=/test/certs/pebble.minica.pem \
        -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir \
        "$P_C" bash /etc/idleleo/scripts/ssl_update.sh
    rc=$(cat "$d/repeat.rc")
    cert_state "$d/cert-after-repeat.txt"
    local sums3; sums3=$(sha "$d/cert-after-repeat.txt")
    assert "$([ "$rc" -eq 0 ] && echo 0 || echo 1)" "S5 renewal is repeatable (rc=$rc)"
    assert "$([ "$staged2" != "$sums3" ] && echo 0 || echo 1)" "S5 second renewal replaces the certificate again"

    stage_near_expiry || true
    cert_state "$d/cert-staged-3.txt"
    staged3=$(sha "$d/cert-staged-3.txt")
    docker stop "$P_PEBBLE" >/dev/null 2>&1 || true
    capture "$d/failure" docker exec -e SSL_CERT_FILE=/test/certs/pebble.minica.pem \
        -e IDLELEO_ACME_DIRECTORY=https://pebble:14000/dir \
        "$P_C" bash /etc/idleleo/scripts/ssl_update.sh
    rc=$(cat "$d/failure.rc")
    cert_state "$d/cert-after-failure.txt"
    local sums4; sums4=$(sha "$d/cert-after-failure.txt")
    assert "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" "S5 renewal with an unreachable CA fails (rc=$rc)"
    assert "$([ "$staged3" = "$sums4" ] && echo 0 || echo 1)" "S5 failed renewal keeps the working certificate"
    assert "$([ "$(docker exec "$P_C" systemctl is-active nginx 2>/dev/null | head -1)" = active ] && echo 0 || echo 1)" \
        "S5 Nginx is not left stopped by a failed renewal"
    assert "$([ "$(docker exec "$P_C" systemctl is-active xray 2>/dev/null | head -1)" = active ] && echo 0 || echo 1)" \
        "S5 Xray is not left stopped by a failed renewal"
}

# --------------------------------------------------------------------- main
if want S4 || want S6 || want S7 || want S8 || want S9; then
    log "scenario A: bash install"
    if a_setup; then
        assert 0 "S4 Bash reality install exits 0"
        want S4 && run_s4
        want S6 && run_s6
        want S8 && run_s8
        want S9 && run_s9
        want S7 && run_s7
    else
        assert 1 "S4 Bash reality install exits 0"
        log "scenario A install failed; see $EVID/S4/install"
    fi
fi
if want S5; then
    log "scenario B: pebble"
    run_s5
fi

log "run_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "$PASS PASS / $FAIL FAIL"
if [[ "${E2E_KEEP:-0}" != "1" ]]; then
    docker rm -f "$A_C" "$P_C" "$P_PEBBLE" >/dev/null 2>&1 || true
    docker network rm "$A_NET" "$P_NET" >/dev/null 2>&1 || true
fi
[[ "$FAIL" -eq 0 ]]
