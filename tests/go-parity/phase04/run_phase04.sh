#!/usr/bin/env bash
# Phase 04 release qualification: Go self-update channel, real origin, real
# binaries and real failure injection. Runs inside the pinned container.
set -u

WORK=${WORK:-/work}
EVID=$WORK/evidence
ORIGIN_ROOT=$WORK/origin
PORT=18080
BASE=http://127.0.0.1:$PORT
BIN=/opt/idleleo/bin/idleleo
ARCH=$(uname -m)
case "$ARCH" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) echo "unsupported arch $ARCH" >&2; exit 2 ;;
esac
ASSET=idleleo-linux-$ARCH

export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY
mkdir -p "$EVID" "$ORIGIN_ROOT"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
size() { stat -c %s "$1"; }

mkmanifest() {
    local dir=$1 version=$2 asset=$3 digest=$4 bytes=$5
    cat >"$ORIGIN_ROOT/$dir/manifest.json" <<EOF
{"schemaVersion":1,"channel":"go","version":"$version","assets":{"linux-$ARCH":{"name":"$ASSET","sha256":"$digest","size":$bytes}}}
EOF
}

prep() {
    local dir=$1 src=$2
    mkdir -p "$ORIGIN_ROOT/$dir"
    cp "$src" "$ORIGIN_ROOT/$dir/$ASSET"
}

echo "phase04-start $(date -u +%Y-%m-%dT%H:%M:%SZ) arch=$ARCH"
echo "old=$(sha "$WORK/bin/idleleo-old") new3=$(sha "$WORK/bin/idleleo-0.3.0") new4=$(sha "$WORK/bin/idleleo-0.4.0")"

# ---- origin fixtures -------------------------------------------------------
prep go "$WORK/bin/idleleo-0.3.0"
mkmanifest go 0.3.0-phase04 "$ASSET" "$(sha "$ORIGIN_ROOT/go/$ASSET")" "$(size "$ORIGIN_ROOT/go/$ASSET")"

prep next "$WORK/bin/idleleo-0.4.0"
mkmanifest next 0.4.0-phase04 "$ASSET" "$(sha "$ORIGIN_ROOT/next/$ASSET")" "$(size "$ORIGIN_ROOT/next/$ASSET")"

prep badsha "$WORK/bin/idleleo-0.4.0"
mkmanifest badsha 0.4.0-phase04 "$ASSET" "$(printf '0%.0s' $(seq 1 64))" "$(size "$ORIGIN_ROOT/badsha/$ASSET")"

prep short "$WORK/bin/idleleo-0.4.0"
mkmanifest short 0.4.0-phase04 "$ASSET" "$(sha "$ORIGIN_ROOT/short/$ASSET")" "$(size "$ORIGIN_ROOT/short/$ASSET")"

mkdir -p "$ORIGIN_ROOT/text"
printf 'this is not an ELF binary\n' >"$ORIGIN_ROOT/text/$ASSET"
mkmanifest text 0.4.0-phase04 "$ASSET" "$(sha "$ORIGIN_ROOT/text/$ASSET")" "$(size "$ORIGIN_ROOT/text/$ASSET")"

prep downgrade "$WORK/bin/idleleo-0.4.0"
mkmanifest downgrade 0.1.9-phase04 "$ASSET" "$(sha "$ORIGIN_ROOT/downgrade/$ASSET")" "$(size "$ORIGIN_ROOT/downgrade/$ASSET")"

python3 /work/origin_server.py "$ORIGIN_ROOT" "$PORT" >"$EVID/origin.log" 2>&1 &
ORIGIN_PID=$!
trap 'kill $ORIGIN_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
    curl -fsS "$BASE/go/manifest.json" >/dev/null 2>&1 && break
    sleep 0.3
done
curl -fsS "$BASE/go/manifest.json" >/dev/null || { echo "origin did not start" >&2; exit 2; }

# ---- install the old manager ---------------------------------------------
install -d -m 0755 /opt/idleleo/bin
install -m 0755 "$WORK/bin/idleleo-old" "$BIN"
old_version=$($BIN --version)
echo "installed: $old_version"
[[ "$old_version" == *0.2.0-phase04* ]] && ok "installed old candidate 0.2.0-phase04" || bad "old candidate version: $old_version"

# ---- configure + check ----------------------------------------------------
out=$($BIN update configure --container --manifest-url "$BASE/go/manifest.json" --json 2>&1)
rc=$?
echo "$out" >"$EVID/update-configure.json"
[[ $rc -eq 0 ]] && ok "update configure rc=0" || bad "update configure rc=$rc: $out"

out=$($BIN update check --json 2>&1)
rc=$?
echo "$out" >"$EVID/update-check.json"
state=$(echo "$out" | jq -r '.state // empty')
verified=$(echo "$out" | jq -r '.verified // false')
latest=$(echo "$out" | jq -r '.latestVersion // empty')
if [[ $rc -eq 0 && "$state" == available && "$verified" == true && "$latest" == 0.3.0-phase04 ]]; then
    ok "update check available verified latest=$latest"
else
    bad "update check rc=$rc state=$state verified=$verified latest=$latest: $out"
fi

# ---- real apply -----------------------------------------------------------
out=$($BIN update apply --container --json 2>&1)
rc=$?
echo "$out" >"$EVID/update-apply.json"
action=$(echo "$out" | jq -r '.action // empty')
newsha=$(echo "$out" | jq -r '.newSha256 // empty')
health=$(echo "$out" | jq -r '.healthOutput // empty')
newver=$($BIN --version)
if [[ $rc -eq 0 && "$action" == applied && "$newsha" == "$(sha "$ORIGIN_ROOT/go/$ASSET")" && "$newver" == *0.3.0-phase04* ]]; then
    ok "update apply action=applied health=$health version=$newver"
else
    bad "update apply rc=$rc action=$action version=$newver: $out"
fi
echo "installed-binary-sha=$(sha "$BIN") expected=$newsha"
[[ "$(sha "$BIN")" == "$newsha" ]] && ok "installed sha matches manifest" || bad "installed sha mismatch"

out=$($BIN update apply --container --json 2>&1)
rc=$?
echo "$out" >"$EVID/update-apply-again.json"
[[ $rc -eq 0 && "$(echo "$out" | jq -r '.action')" == up-to-date ]] && ok "second apply is up-to-date" || bad "second apply rc=$rc: $out"

# ---- failure injection ----------------------------------------------------
before=$(sha "$BIN")

out=$($BIN update apply --container --manifest-url "$BASE/badsha/manifest.json" 2>&1)
rc=$?
echo "$out" >"$EVID/update-badsha.log"
if [[ $rc -ne 0 && "$out" == *"sha256 mismatch"* ]]; then ok "bad sha rejected rc=$rc"; else bad "bad sha rc=$rc: $out"; fi
[[ "$(sha "$BIN")" == "$before" ]] && ok "bad sha kept old binary" || bad "bad sha changed binary"

out=$($BIN update apply --container --manifest-url "$BASE/short/manifest.json" 2>&1)
rc=$?
echo "$out" >"$EVID/update-short.log"
if [[ $rc -ne 0 && "$out" == *interrupted* ]]; then ok "interrupted download rejected rc=$rc"; else bad "interrupted download rc=$rc: $out"; fi
[[ "$(sha "$BIN")" == "$before" ]] && ok "interrupted download kept old binary" || bad "interrupted download changed binary"

out=$($BIN update apply --container --manifest-url "$BASE/text/manifest.json" 2>&1)
rc=$?
echo "$out" >"$EVID/update-text.log"
if [[ $rc -ne 0 && "$out" == *"ELF"* ]]; then ok "non-ELF asset rejected rc=$rc"; else bad "non-ELF rc=$rc: $out"; fi
[[ "$(sha "$BIN")" == "$before" ]] && ok "non-ELF kept old binary" || bad "non-ELF changed binary"

out=$($BIN update apply --container --manifest-url "$BASE/downgrade/manifest.json" 2>&1)
rc=$?
echo "$out" >"$EVID/update-downgrade.log"
[[ $rc -eq 4 ]] && ok "downgrade refused exit=$rc" || bad "downgrade rc=$rc: $out"
[[ "$(sha "$BIN")" == "$before" ]] && ok "downgrade kept old binary" || bad "downgrade changed binary"

# ---- disk full ------------------------------------------------------------
mkdir -p /mnt/full
mount -t tmpfs -o size=20m tmpfs /mnt/full
mkdir -p /mnt/full/opt/idleleo/bin
install -m 0755 "$BIN" /mnt/full/opt/idleleo/bin/idleleo
$BIN update configure --container --manifest-url "$BASE/next/manifest.json" --install-path mnt/full/opt/idleleo/bin/idleleo >"$EVID/update-configure-full.json" 2>&1
out=$($BIN update apply --container 2>&1)
rc=$?
echo "$out" >"$EVID/update-diskfull.log"
if [[ $rc -ne 0 && "$out" == *"no space left"* ]]; then ok "disk full rejected rc=$rc"; else bad "disk full rc=$rc: $out"; fi
fullver=$(/mnt/full/opt/idleleo/bin/idleleo --version)
[[ "$fullver" == *0.3.0-phase04* ]] && ok "disk full kept old binary ($fullver)" || bad "disk full binary: $fullver"
umount /mnt/full

# ---- scheduler takeover ---------------------------------------------------
$BIN update configure --container --manifest-url "$BASE/next/manifest.json" >"$EVID/update-configure-next.json" 2>&1
out=$($BIN schedule run --job auto-update --json 2>&1)
rc=$?
echo "$out" >"$EVID/schedule-auto-update.json"
jobresult=$(echo "$out" | jq -r '.results[0].result // empty')
jobdetail=$(echo "$out" | jq -r '.results[0].detail // empty')
schedver=$($BIN --version)
echo "$out" | jq -r '.results[0] | "job=\(.job) result=\(.result) at=\(.at) detail=\(.detail)"'
if [[ $rc -eq 0 && "$jobresult" == ok && "$schedver" == *0.4.0-phase04* ]]; then
    ok "scheduled auto-update applied 0.4.0 at=$(echo "$out" | jq -r '.results[0].at')"
else
    bad "scheduled auto-update rc=$rc result=$jobresult version=$schedver detail=$jobdetail"
fi
echo "schedule-log: $(tail -1 /var/log/idleleo/schedule/schedule.log)"
[[ "$(tail -1 /var/log/idleleo/schedule/schedule.log)" == *"job=auto-update result=ok"* ]] && ok "schedule log recorded the real run" || bad "schedule log missing"

$BIN schedule status --json >"$EVID/schedule-status.json" 2>&1
[[ "$(jq -r '.releaseChannelConfigured' "$EVID/schedule-status.json")" == true ]] && ok "schedule status sees the release channel" || bad "schedule status channel flag"

# ---- unconfigured degradation -------------------------------------------
mv /etc/idleleo/release/channel.json /tmp/channel.json.bak
out=$($BIN schedule run --job auto-update --json 2>&1)
rc=$?
echo "$out" >"$EVID/schedule-auto-update-unconfigured.json"
jobresult=$(echo "$out" | jq -r '.results[0].result // empty')
if [[ $rc -eq 0 && "$jobresult" == degraded ]]; then ok "unconfigured auto-update is an explicit degradation"; else bad "unconfigured rc=$rc result=$jobresult"; fi
schedver=$($BIN --version)
[[ "$schedver" == *0.4.0-phase04* ]] && ok "degraded run kept binary" || bad "degraded run changed binary: $schedver"
mv /tmp/channel.json.bak /etc/idleleo/release/channel.json

# ---- systemd fixtures: restart probe + real nginx -------------------------
cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=phase04 xray restart probe
After=network.target

[Service]
ExecStart=/bin/sh -c 'echo phase04-xray-start; exec sleep infinity'
Restart=no

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xray >/dev/null 2>&1
systemctl start nginx >/dev/null 2>&1
xray_starts() { journalctl -u xray --no-pager 2>/dev/null | grep -c phase04-xray-start; }

# ---- cert renewal contract ------------------------------------------------
mkdir -p /etc/idleleo/cert
gen_cert() {
    local days=$1
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/idleleo/cert/privkey.pem \
        -out /etc/idleleo/cert/fullchain.pem \
        -days "$days" -subj "/CN=phase04.test" >/dev/null 2>&1
    chmod 600 /etc/idleleo/cert/privkey.pem
    chmod 644 /etc/idleleo/cert/fullchain.pem
}

gen_cert 365
before=$(xray_starts)
out=$($BIN schedule run --job cert-renew --json 2>&1)
rc=$?
echo "$out" >"$EVID/cert-baseline.json"
res=$(echo "$out" | jq -r '.results[0].result // empty')
after=$(xray_starts)
if [[ $rc -eq 0 && "$res" == ok && "$after" -eq "$before" ]]; then
    ok "cert baseline recorded without restart"
else
    bad "cert baseline rc=$rc result=$res starts=$before->$after"
fi

gen_cert 365
before=$(xray_starts)
out=$($BIN schedule run --job cert-renew --json 2>&1)
res=$(echo "$out" | jq -r '.results[0].result // empty')
detail=$(echo "$out" | jq -r '.results[0].detail // empty')
after=$(xray_starts)
echo "$out" >"$EVID/cert-changed.json"
if [[ "$res" == ok && "$after" -eq $((before + 1)) && "$detail" == *changed* ]]; then
    ok "changed certificate restarted xray once and reloaded nginx"
else
    bad "cert changed result=$res starts=$before->$after detail=$detail"
fi

before=$(xray_starts)
out=$($BIN schedule run --job cert-renew --json 2>&1)
res=$(echo "$out" | jq -r '.results[0].result // empty')
detail=$(echo "$out" | jq -r '.results[0].detail // empty')
after=$(xray_starts)
echo "$out" >"$EVID/cert-unchanged.json"
if [[ "$res" == ok && "$after" -eq "$before" && "$detail" == *"no restart"* ]]; then
    ok "unchanged certificate did not restart services"
else
    bad "cert unchanged result=$res starts=$before->$after detail=$detail"
fi

chmod 644 /etc/idleleo/cert/privkey.pem
gen_cert 365
chmod 644 /etc/idleleo/cert/privkey.pem
before=$(xray_starts)
out=$($BIN schedule run --job cert-renew --json 2>&1)
res=$(echo "$out" | jq -r '.results[0].result // empty')
echo "$out" >"$EVID/cert-insecure-key.json"
after=$(xray_starts)
if [[ "$res" == failed && "$after" -eq "$before" ]]; then
    ok "world-readable private key blocked the reload"
else
    bad "insecure key result=$res starts=$before->$after"
fi
chmod 600 /etc/idleleo/cert/privkey.pem

gen_cert 365
gen_cert 10
$BIN schedule run --job cert-renew --json >"$EVID/cert-short-first.json" 2>&1
out=$($BIN schedule run --job cert-renew --json 2>&1)
res=$(echo "$out" | jq -r '.results[0].result // empty')
echo "$out" >"$EVID/cert-short-second.json"
[[ "$res" == degraded ]] && ok "short-lived unchanged certificate reports explicit degradation" || bad "short cert result=$res"

# ---- service-class CLI ----------------------------------------------------
out=$($BIN service status --json 2>&1)
rc=$?
echo "$out" >"$EVID/service-status.json"
xray_active=$(echo "$out" | jq -r '.units[] | select(.name=="xray") | .active')
nginx_active=$(echo "$out" | jq -r '.units[] | select(.name=="nginx") | .active')
if [[ $rc -eq 0 && "$xray_active" == active && "$nginx_active" == active ]]; then
    ok "service status xray=$xray_active nginx=$nginx_active"
else
    bad "service status rc=$rc xray=$xray_active nginx=$nginx_active: $out"
fi

before=$(xray_starts)
out=$($BIN service restart --unit xray --container --json 2>&1)
rc=$?
echo "$out" >"$EVID/service-restart.json"
after=$(xray_starts)
[[ $rc -eq 0 && "$after" -eq $((before + 1)) ]] && ok "service restart restarted xray (starts $before->$after)" || bad "service restart rc=$rc starts=$before->$after: $out"

out=$($BIN service stop --unit xray --container --json 2>&1)
rc=$?
echo "$out" >"$EVID/service-stop.json"
active=$($BIN service status --json | jq -r '.units[] | select(.name=="xray") | .active')
[[ $rc -eq 0 && "$active" == inactive ]] && ok "service stop left xray inactive" || bad "service stop rc=$rc active=$active"

out=$($BIN service start --unit xray --container --json 2>&1)
rc=$?
echo "$out" >"$EVID/service-start.json"
active=$($BIN service status --json | jq -r '.units[] | select(.name=="xray") | .active')
[[ $rc -eq 0 && "$active" == active ]] && ok "service start restored xray" || bad "service start rc=$rc active=$active"

out=$($BIN service logs --unit xray --lines 10 --json 2>&1)
rc=$?
echo "$out" >"$EVID/service-logs.json"
[[ $rc -eq 0 && "$(echo "$out" | jq -r '.output')" == *phase04-xray-start* ]] && ok "service logs returned journal lines" || bad "service logs rc=$rc: $out"

out=$($BIN service restart --unit sshd --container 2>&1)
rc=$?
[[ $rc -eq 2 && "$out" == *"not managed"* ]] && ok "unmanaged unit rejected rc=$rc" || bad "unmanaged unit rc=$rc: $out"

mkdir -p /tmp/sandbox-root
out=$($BIN --root /tmp/sandbox-root service status --json 2>&1)
rc=$?
[[ $rc -eq 2 ]] && ok "service status refuses a sandbox root rc=$rc" || bad "sandbox service status rc=$rc: $out"

# ---- Rill status ----------------------------------------------------------
out=$($BIN rill status --json 2>&1)
rc=$?
echo "$out" >"$EVID/rill-absent.json"
[[ $rc -eq 0 && "$(echo "$out" | jq -r '.rill.status')" == absent ]] && ok "rill status reports absent on a clean system" || bad "rill absent rc=$rc: $out"

mkdir -p /etc/rill-xray-agent /var/lib/rill-xray-agent-xray/status
printf '{"enabled":true,"mode":"observe-only"}\n' >/etc/rill-xray-agent/config.json
printf '{"updatedAt":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/var/lib/rill-xray-agent-xray/status/xray-observation.json
out=$($BIN rill status --json 2>&1)
echo "$out" >"$EVID/rill-active.json"
installed=$(echo "$out" | jq -r '.rill.installed')
status=$(echo "$out" | jq -r '.rill.status')
mode=$(echo "$out" | jq -r '.rill.mode')
if [[ "$installed" == true && "$status" == active && "$mode" == observe-only ]]; then
    ok "rill status active mode=$mode"
else
    bad "rill active: $out"
fi

printf '{"updatedAt":"%s"}\n' "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)" >/var/lib/rill-xray-agent-xray/status/xray-observation.json
out=$($BIN rill status --json 2>&1)
echo "$out" >"$EVID/rill-stale.json"
status=$(echo "$out" | jq -r '.rill.status')
[[ "$status" == stale ]] && ok "rill status detects a stale observation" || bad "rill stale: $out"

# ---- read-only CLI and real stats -----------------------------------------
out=$($BIN --help 2>&1)
rc=$?
[[ $rc -eq 0 && "$out" == *"update"* && "$out" == *"service"* ]] && ok "help lists the new commands" || bad "help rc=$rc"

mkdir -p /etc/idleleo/conf/xray
cat >/etc/idleleo/conf/xray/config.json <<'EOF'
{
  "log": {"loglevel": "warning"},
  "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["HandlerService", "StatsService"]},
  "stats": {},
  "policy": {"system": {"statsInboundUplink": true, "statsInboundDownlink": true}},
  "inbounds": [{"tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": 10808}],
  "outbounds": [{"protocol": "freedom"}]
}
EOF
xray run -c /etc/idleleo/conf/xray/config.json >/tmp/xray-run.log 2>&1 &
XRAY_PID=$!
for _ in $(seq 1 40); do
    if ss -ltn 2>/dev/null | grep -q ':10085 '; then break; fi
    sleep 0.2
done
curl -fsS --socks5-hostname 127.0.0.1:10808 "http://127.0.0.1:18080/go/manifest.json" >/dev/null 2>&1 || true
out=$($BIN stats --json 2>&1)
rc=$?
echo "$out" >"$EVID/stats-json.json"
if [[ $rc -eq 0 ]] && echo "$out" | jq -e '.stat[] | select(.name=="inbound>>>socks>>>traffic>>>uplink")' >/dev/null 2>&1; then
    ok "stats --json returned a real inbound counter"
else
    bad "stats --json rc=$rc: $out"
fi

out=$($BIN --show --json 2>&1)
rc=$?
echo "$out" >"$EVID/show.json"
[[ $rc -eq 0 ]] && ok "show reads the runtime config" || bad "show rc=$rc: $out"

before=$(find /etc/idleleo -type f -printf '%p %s %T@\n' 2>/dev/null | sort | sha256sum)
$BIN --help >/dev/null 2>&1
$BIN stats --json >/dev/null 2>&1
$BIN --show --json >/dev/null 2>&1
after=$(find /etc/idleleo -type f -printf '%p %s %T@\n' 2>/dev/null | sort | sha256sum)
[[ "$before" == "$after" ]] && ok "read-only commands wrote nothing under /etc/idleleo" || bad "read-only commands changed /etc/idleleo"

setpriv --reuid=nobody --regid=nogroup --clear-groups "$BIN" stats --json >/tmp/nonroot-stats.log 2>&1
rc=$?
[[ $rc -eq 5 ]] && ok "non-root stats preserves the legacy exit 5" || bad "non-root stats rc=$rc: $(cat /tmp/nonroot-stats.log)"

kill "$XRAY_PID" 2>/dev/null || true
wait "$XRAY_PID" 2>/dev/null || true
out=$($BIN stats --json 2>&1)
rc=$?
echo "$out" >"$EVID/stats-api-down.log"
[[ $rc -eq 8 ]] && ok "stats with API down reports exit 8" || bad "stats API down rc=$rc: $out"

echo "phase04-end $(date -u +%Y-%m-%dT%H:%M:%SZ) pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
