#!/usr/bin/env bash
# OPS-21: Xray routing-layer traffic blocking, observed on a live install.
#
# Usage: bash ops21_block.sh go|bash
#
# The driver proves four things on each side:
#   1. before blocking, example.com goes through the proxy (HTTP 200 + marker);
#   2. after enabling ads + private-ip + bittorrent + country cn, the same
#      control still works (a catch-all blocks would fail this);
#   3. each blocked target is refused quickly, never by a timeout;
#   4. on the Go side, `config edit --uuid` keeps every routing rule, keeps the
#      operator's own rule, keeps the control alive and the blocked targets
#      blocked; `block off` restores the pre-apply routing.
set -uo pipefail

SIDE="${1:?side required (go|bash)}"
OUT="${E2E_OUT:?E2E_OUT required}"
DIR="$OUT/block-$SIDE"
CFG=/etc/idleleo/conf/xray/config.json
XRAY=/usr/local/bin/xray
PROBE=/src/tests/e2e-diff/drivers/ops21_probe.py
# The control target has to stay reachable without the public internet: the
# runner provides an in-network origin that serves a page containing the
# marker. Blocked targets never need egress, their rules match before dialing.
CONTROL_HOST="${E2E_CONTROL_HOST:-example.com}"
CONTROL_PORT="${E2E_CONTROL_PORT:-80}"
mkdir -p "$DIR"
: >"$DIR/block.log"
export IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$DIR/block.log"; }

# Offline geo assets, when the runner has them cached. Without egress the
# download path cannot run, and a missing geo file must be seeded, not skipped.
if [[ -d /seed/geo ]]; then
    mkdir -p /etc/idleleo/share/xray
    for name in geoip.dat geosite.dat; do
        [[ -f "/seed/geo/$name" ]] && install -m 0644 "/seed/geo/$name" "/etc/idleleo/share/xray/$name"
    done
    log "seeded_geo=$(ls /etc/idleleo/share/xray | tr '\n' ' ')"
fi

json_get() { python3 - "$1" "$2" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print("")
    sys.exit(0)
cur = doc
for part in sys.argv[2].split('.'):
    cur = cur.get(part) if isinstance(cur, dict) else None
print("" if cur is None else (cur if isinstance(cur, str) else json.dumps(cur)))
PY
}

checks="$DIR/checks.jsonl"
: >"$checks"
check() { # name ok detail
    local ok=$2
    [[ "$ok" == "true" || "$ok" == "1" ]] && ok=true || ok=false
    printf '{"name":"%s","ok":%s,"detail":%s}\n' "$1" "$ok" "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${3:-}")" >>"$checks"
    log "check $1=$ok ${3:-}"
}

wait_service() {
    local state=""
    for _ in $(seq 1 40); do
        state=$(systemctl is-active xray 2>/dev/null)
        [[ "$state" == "active" ]] && return 0
        sleep 1
    done
    return 1
}

# The control origin must not depend on the container network: this host has no
# egress and cross-container traffic is unreliable. Bind the control address to
# lo inside this container and serve it from here. The address is in a public
# (DoD) range on purpose — geoip:private and geoip:cn must not match it, or
# enabling those rules would block the control and hide a broken fallback.
ensure_control() {
    if curl -fsS --max-time 2 "http://$CONTROL_HOST:$CONTROL_PORT/" >/dev/null 2>&1; then
        return 0
    fi
    if ! ip addr show dev lo | grep -q " $CONTROL_HOST/"; then
        ip addr add "$CONTROL_HOST/32" dev lo 2>/dev/null || true
    fi
    mkdir -p /tmp/ops21-origin
    printf '<!doctype html><title>Example Domain</title><h1>Example Domain</h1>\n' \
        >/tmp/ops21-origin/index.html
    (cd /tmp/ops21-origin && exec python3 -m http.server "$CONTROL_PORT" --bind "$CONTROL_HOST" \
        >/tmp/ops21-origin.log 2>&1) &
    for _ in $(seq 1 20); do
        curl -fsS --max-time 1 "http://$CONTROL_HOST:$CONTROL_PORT/" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    return 1
}

# Reality borrows the certificate of its target during the handshake, so an
# unreachable target (this host has no egress) makes every tunnel fail with a
# reset. Stand up a loopback TLS origin signed by a local CA and point Reality at
# it, the same fixture the edit scenarios use. The control page itself stays on
# 11.0.0.2:80 so it is unaffected by the blocked categories.
setup_reality_origin() {
    local dir=/tmp/ops21-tls
    rm -rf "$dir"; mkdir -p "$dir"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e ops21 CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$dir/ca.key" -out "$dir/ca.crt" >/dev/null 2>&1 || return 1
    openssl req -newkey rsa:2048 -nodes -subj "/CN=local.test" \
        -keyout "$dir/key.pem" -out "$dir/server.csr" >/dev/null 2>&1 || return 1
    cat >"$dir/server.ext" <<'EOF'
subjectAltName=DNS:local.test
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl x509 -req -in "$dir/server.csr" -days 1 -CA "$dir/ca.crt" \
        -CAkey "$dir/ca.key" -CAcreateserial -extfile "$dir/server.ext" \
        -out "$dir/leaf.pem" >/dev/null 2>&1 || return 1
    cat "$dir/leaf.pem" "$dir/ca.crt" >"$dir/fullchain.pem"

    # The edit-time probe verifies the chain with Go's system roots; append and
    # also install it where update-ca-certificates can regenerate it.
    if command -v update-ca-certificates >/dev/null 2>&1; then
        mkdir -p /usr/local/share/ca-certificates
        cp "$dir/ca.crt" /usr/local/share/ca-certificates/e2e-ops21-ca.crt
        update-ca-certificates >/dev/null 2>&1 || true
    fi
    cat "$dir/ca.crt" >>/etc/ssl/certs/ca-certificates.crt

    cat >"$dir/serve.py" <<'PY'
import socket, ssl, sys, threading, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
# Reality dials the target with the client fingerprint, which offers h2/http1.1.
ctx.set_alpn_protocols(["h2", "http/1.1"])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8443))
srv.listen(16)


def handle(conn):
    try:
        tls = ctx.wrap_socket(conn, server_side=True)
        time.sleep(8)
        tls.close()
    except Exception:
        conn.close()


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
    python3 "$dir/serve.py" "$dir/fullchain.pem" "$dir/key.pem" >/tmp/ops21-tls.log 2>&1 &
    sleep 0.5
    return 0
}

routing() { # name
    jq -S '{rules: (.routing.rules // []), domainStrategy: (.routing.domainStrategy // "AsIs")}' \
        "$CFG" >"$DIR/routing-$1.json" 2>/dev/null
}

rule_count() { jq '.routing.rules | length' "$CFG" 2>/dev/null || echo 0; }

share_uri() {
    # The Go side reads the link from the same code path users get, so the
    # probe cannot disagree with the CLI about key, flow or shortId.
    if [[ "$SIDE" == "go" ]] && command -v "$IDLELEO" >/dev/null 2>&1; then
        "$IDLELEO" xray share --path "$CFG" --public-port 443 --json 2>/dev/null |
            python3 -c 'import json,sys; print(json.load(sys.stdin).get("shareUri",""))'
        return
    fi
    python3 - "$CFG" <<'PY'
import json, subprocess, sys
from urllib.parse import quote
cfg = json.load(open(sys.argv[1]))
inb = cfg["inbounds"][0]
ss = inb["streamSettings"]
r = ss["realitySettings"]
clients = inb["settings"]["clients"]
uuid = clients[0]["id"]
out = subprocess.check_output(["/usr/local/bin/xray", "x25519", "-i", r["privateKey"]], text=True)
pub = [line.split()[-1] for line in out.splitlines() if "Public" in line][0]
sni = (r.get("serverNames") or [""])[0]
sid = (r.get("shortIds") or [""])[0]
network = ss.get("network") or "raw"
query = ["encryption=none", "security=reality", "sni=" + sni, "fp=chrome",
         "pbk=" + pub, "sid=" + sid, "type=" + network]
flow = clients[0].get("flow") or ""
if flow:
    query.append("flow=" + quote(flow, safe=""))
if network == "ws":
    query.append("path=" + quote(ss.get("wsSettings", {}).get("path", "/"), safe=""))
elif network == "grpc":
    query.append("serviceName=" + quote(ss.get("grpcSettings", {}).get("serviceName", ""), safe=""))
print("vless://%s@127.0.0.1:443?%s#ops21" % (uuid, "&".join(query)))
PY
}

probe() { # name host port [timeout]
    python3 "$PROBE" "$URI" 127.0.0.1 443 "$2" "$3" "${4:-6000}" \
        >"$DIR/$1.json" 2>"$DIR/$1.err"
    json_get "$DIR/$1.json" outcome
}

probe_marker() { json_get "$DIR/$1.json" marker; }

# traffic_blocker.sh is sourced with `set -u`, so every variable install.sh
# normally provides has to exist before the source line.
block_color_stubs() {
    shell_version=""
    Error=""; RedBG=""; Font=""; Green=""; YellowBG=""; Warning=""
    Info=""; GreenBG=""; OK=""; Red=""
    scripts_dir=/etc/idleleo/scripts
}

apply_bash() {
    local script=/etc/idleleo/scripts/traffic_blocker.sh
    [[ -f "$script" ]] || script=$(find /etc/idleleo /usr/local -name traffic_blocker.sh 2>/dev/null | head -1)
    [[ -n "$script" && -f "$script" ]] || { log "FATAL: traffic_blocker.sh not found"; return 1; }
    xray_conf="$CFG"
    xray_conf_dir=/etc/idleleo/conf/xray
    idleleo_dir=/etc/idleleo
    block_color_stubs
    gettext() { printf '%s' "$1"; }
    log_echo() { printf '%s\n' "$*" >>"$DIR/bash-apply.log"; }
    update_json_config() { # keep install.sh's contract: jq filter with extra args
        local file="$1"; shift
        local mode
        mode=$(stat -c '%a' "$file" 2>/dev/null || echo 600)
        jq "$@" "$file" >"$file.tmp" && chmod "$mode" "$file.tmp" && mv "$file.tmp" "$file"
    }
    # shellcheck disable=SC1090
    source "$script" || return 1
    tb_init_config || return 1
    tb_set_rule_status ads true
    tb_set_rule_status private_ip true
    tb_set_rule_status bittorrent true
    tb_set_countries '["cn"]'
    tb_apply_rules </dev/null >>"$DIR/bash-apply.log" 2>&1 || return 1
    return 0
}

off_bash() {
    xray_conf="$CFG"
    xray_conf_dir=/etc/idleleo/conf/xray
    idleleo_dir=/etc/idleleo
    block_color_stubs
    gettext() { printf '%s' "$1"; }
    log_echo() { printf '%s\n' "$*" >>"$DIR/bash-off.log"; }
    update_json_config() {
        local file="$1"; shift
        local mode
        mode=$(stat -c '%a' "$file" 2>/dev/null || echo 600)
        jq "$@" "$file" >"$file.tmp" && chmod "$mode" "$file.tmp" && mv "$file.tmp" "$file"
    }
    # shellcheck disable=SC1090
    source /etc/idleleo/scripts/traffic_blocker.sh || return 1
    printf 'y\n' | tb_reset_rules >>"$DIR/bash-off.log" 2>&1
    return 0
}

IDLELEO=/usr/local/bin/idleleo
wait_service || { check serviceActive false "xray is not active"; }
if ensure_control; then
    log "control origin ready at $CONTROL_HOST:$CONTROL_PORT"
else
    log "WARN: control origin did not come up at $CONTROL_HOST:$CONTROL_PORT"
fi

if [[ "$SIDE" == "go" ]]; then
    # Point Reality at the loopback TLS origin before any probe runs; otherwise
    # the handshake has no target to borrow a certificate from.
    if setup_reality_origin && "$IDLELEO" xray config edit --target 127.0.0.1:8443 \
        --server-names local.test --yes --container --json \
        >"$DIR/reality-origin.json" 2>"$DIR/reality-origin.err"; then
        check realityOriginLocal true "target=127.0.0.1:8443 sni=local.test"
        wait_service >/dev/null || true
    else
        check realityOriginLocal false "$(tail -1 "$DIR/reality-origin.err" 2>/dev/null)"
    fi
fi

routing before
rules_before=$(rule_count)
if [[ "$SIDE" == "go" ]]; then
    # A hand-written rule that must survive both apply and config edit.
    # The temp file must keep the installer's mode and owner: Xray runs as
    # User=xray and reads a root:xray 0640 config. Rewriting it as 0600 root
    # makes the next restart fail with "permission denied".
    jq '.routing.rules = ((.routing.rules // []) + [{"type":"field","outboundTag":"blocked","domain":["full:corp.example"]}])' \
        "$CFG" >"$CFG.tmp" && chmod --reference="$CFG" "$CFG.tmp" \
        && chown --reference="$CFG" "$CFG.tmp" && mv "$CFG.tmp" "$CFG"
    routing with-user
    rules_before=$(rule_count)
    OFF_BASELINE=routing-with-user
else
    OFF_BASELINE=routing-before
fi

URI=$(share_uri)
[[ -n "$URI" ]] || { check shareUri false "cannot build a share link"; }
log "uri built network=$(python3 -c 'import sys; from urllib.parse import urlparse,parse_qs; print(parse_qs(urlparse(sys.argv[1]).query).get("type",[""])[0])' "$URI")"

# 1. baseline: the proxy works before blocking exists.
outcome=$(probe baseline "$CONTROL_HOST" "$CONTROL_PORT" 8000)
check baselineControl "$([[ "$outcome" == "ok" && "$(probe_marker baseline)" == "true" ]] && echo true || echo false)" "$outcome"

# 2. enable blocking.
if [[ "$SIDE" == "go" ]]; then
    "$IDLELEO" xray block ads enable --container --json >"$DIR/toggle-ads.json" 2>&1
    "$IDLELEO" xray block private-ip enable --container --json >"$DIR/toggle-private.json" 2>&1
    "$IDLELEO" xray block bittorrent enable --container --json >"$DIR/toggle-bt.json" 2>&1
    "$IDLELEO" xray block country add cn --container --json >"$DIR/toggle-country.json" 2>&1
    # D5: a custom list is stored and switched independently of the built-in
    # categories; it must reach routing on apply and be dropped on off while
    # staying configured.
    "$IDLELEO" xray block custom add --kind domain --value ops21.example --container --json \
        >"$DIR/custom-add.json" 2>&1
    "$IDLELEO" xray block custom enable --kind domain --container --json >"$DIR/custom-enable.json" 2>&1
    check customListConfigured \
        "$(jq -r '(.custom_domains.enabled == true) and ((.custom_domains.items // []) | index("ops21.example") != null)' \
            /etc/idleleo/conf/xray/traffic_blocker.json 2>/dev/null | grep -qx true && echo true || echo false)" ""
    no_probe=()
    [[ "${E2E_BLOCK_NO_PROBE:-0}" == "1" ]] && no_probe=(--no-probe)
    "$IDLELEO" xray block apply --yes --container "${no_probe[@]+"${no_probe[@]}"}" --json >"$DIR/apply.json" 2>"$DIR/apply.err"
    apply_rc=$?
    "$IDLELEO" xray block status --container --json >"$DIR/status-after-apply.json" 2>&1
else
    apply_bash
    apply_rc=$?
fi
echo "$apply_rc" >"$DIR/apply.rc"
wait_service || true
routing after-apply
rules_after=$(rule_count)
check applyRcZero "$([[ "$apply_rc" == "0" ]] && echo true || echo false)" "rc=$apply_rc"
check rulesAdded "$([[ "$rules_after" -gt "$rules_before" ]] && echo true || echo false)" "before=$rules_before after=$rules_after"
# The fallback must stay direct and no rule may block unconditionally: a
# catch-all block would also make the blocked probes pass.
check fallbackDirect "$(jq -r '[.routing.rules[] | select(.outboundTag=="direct" and ((.inboundTag // []) | length) > 0)] | length > 0' "$CFG" | grep -qx true && echo true || echo false)" ""
check noCatchAllBlocked "$(jq -r '[.routing.rules[] | select(.outboundTag=="blocked") | select(([.domain?, .ip?, .protocol?, .port?, .network?, .source?, .user?, .inboundTag?] | map(select(. != null)) | length) == 0)] | length == 0' "$CFG" | grep -qx true && echo true || echo false)" ""
check customRuleApplied "$(jq -r '[.routing.rules[] | select((.domain // []) | map(tostring | test("ops21\\.example")) | any)] | length == 1' "$CFG" | grep -qx true && echo true || echo false)" ""

# 3. the control must keep working: a blocked catch-all would break this.
outcome=$(probe control-after "$CONTROL_HOST" "$CONTROL_PORT" 8000)
check controlAfterApply "$([[ "$outcome" == "ok" && "$(probe_marker control-after)" == "true" ]] && echo true || echo false)" "$outcome"

# 4. each blocked type must be refused quickly.
outcome=$(probe ads doubleclick.net 80 6000)
check adsBlocked "$([[ "$outcome" == "blocked" ]] && echo true || echo false)" "$outcome"
outcome=$(probe private 10.0.0.1 80 6000)
check privateBlocked "$([[ "$outcome" == "blocked" ]] && echo true || echo false)" "$outcome"
outcome=$(probe country www.baidu.com 80 6000)
check countryBlocked "$([[ "$outcome" == "blocked" ]] && echo true || echo false)" "$outcome"

# 5. Go-only gate: config edit keeps everything.
if [[ "$SIDE" == "go" ]]; then
    new_uuid=$(cat /proc/sys/kernel/random/uuid)
    "$IDLELEO" xray config edit --uuid "$new_uuid" --yes --container --json \
        >"$DIR/edit.json" 2>"$DIR/edit.err"
    edit_rc=$?
    echo "$edit_rc" >"$DIR/edit.rc"
    wait_service || true
    # The UUID just changed; the link built before the edit is now stale and its
    # handshake would fail, which would look like a block.
    URI=$(share_uri)
    routing after-edit
    check editRcZero "$([[ "$edit_rc" == "0" ]] && echo true || echo false)" "rc=$edit_rc"
    check editUuidApplied "$(grep -q "$new_uuid" "$CFG" && echo true || echo false)" "$new_uuid"
    check editRoutingIdentical "$(cmp -s "$DIR/routing-after-apply.json" "$DIR/routing-after-edit.json" && echo true || echo false)" ""
    # Deep comparison: every rule recorded in the block state's owned_rules
    # must still be present verbatim in the edited routing.rules. A count-only
    # check would pass if one rule vanished and another appeared.
    owned_report=$(python3 - "$DIR/owned-rules.json" "$CFG" <<'PY'
import json, sys
state = json.load(open("/etc/idleleo/conf/xray/traffic_blocker.json"))
owned = state.get("owned_rules") or []
json.dump(owned, open(sys.argv[1], "w"), indent=2, sort_keys=True)
rules = (json.load(open(sys.argv[2])).get("routing") or {}).get("rules") or []
missing = []
for rule in owned:
    if rule not in rules:
        missing.append(json.dumps(rule, sort_keys=True))
print("owned=%d missing=%d%s" % (len(owned), len(missing),
      ("" if not missing else " first=" + missing[0][:120])))
sys.exit(1 if (not owned or missing) else 0)
PY
    ) && owned_ok=true || owned_ok=false
    check editOwnedRulesKept "$owned_ok" "$owned_report"
    check editUserRuleKept "$(jq -r '[.routing.rules[] | select(.domain? == ["full:corp.example"])] | length' "$CFG" | grep -qx 1 && echo true || echo false)" ""
    check editBlockReported "$([[ "$(json_get "$DIR/edit.json" blockPreserved)" == "true" ]] && echo true || echo false)" \
        "blockRuleCount=$(json_get "$DIR/edit.json" blockRuleCount)"
    outcome=$(probe control-after-edit "$CONTROL_HOST" "$CONTROL_PORT" 8000)
    check controlAfterEdit "$([[ "$outcome" == "ok" && "$(probe_marker control-after-edit)" == "true" ]] && echo true || echo false)" "$outcome"
    outcome=$(probe ads-after-edit doubleclick.net 80 6000)
    check adsBlockedAfterEdit "$([[ "$outcome" == "blocked" ]] && echo true || echo false)" "$outcome"
fi

# 6. off restores the pre-apply routing.
if [[ "$SIDE" == "go" ]]; then
    "$IDLELEO" xray block off --yes --container --json >"$DIR/off.json" 2>"$DIR/off.err"
    off_rc=$?
else
    off_bash
    off_rc=$?
fi
echo "$off_rc" >"$DIR/off.rc"
wait_service || true
URI=$(share_uri)
routing after-off
check offRcZero "$([[ "$off_rc" == "0" ]] && echo true || echo false)" "rc=$off_rc"
check offRestored "$(cmp -s "$DIR/$OFF_BASELINE.json" "$DIR/routing-after-off.json" && echo true || echo false)" "baseline=$OFF_BASELINE"
if [[ "$SIDE" == "go" ]]; then
    # off only removes the live rules; the configured custom list survives.
    check customListKept \
        "$(jq -r '(.custom_domains.enabled == true) and ((.custom_domains.items // []) | index("ops21.example") != null)' \
            /etc/idleleo/conf/xray/traffic_blocker.json 2>/dev/null | grep -qx true && echo true || echo false)" ""
    check customRuleRemoved \
        "$(jq -r '[.rules[] | select((.domain // []) | map(tostring | test("ops21\\.example")) | any)] | length == 0' \
            "$DIR/routing-after-off.json" | grep -qx true && echo true || echo false)" ""
fi
outcome=$(probe control-after-off "$CONTROL_HOST" "$CONTROL_PORT" 8000)
check controlAfterOff "$([[ "$outcome" == "ok" && "$(probe_marker control-after-off)" == "true" ]] && echo true || echo false)" "$outcome"

python3 - "$checks" "$DIR/result.json" "$SIDE" <<'PY'
import json, sys
checks = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
failed = [c["name"] for c in checks if not c["ok"]]
json.dump({"side": sys.argv[3], "checks": checks, "failed": failed,
           "status": "pass" if not failed else "fail"},
          open(sys.argv[2], "w"), indent=2)
print("failed=%s" % ",".join(failed))
PY

[[ "$(json_get "$DIR/result.json" status)" == "pass" ]] || exit 1
exit 0
