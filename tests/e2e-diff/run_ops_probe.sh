#!/usr/bin/env bash
# Phase 01 operation sweep: runs the same read/write operation on an installed
# Bash container and an installed Go container, then records both transcripts.
#
# This script does not decide PASS/FAIL on its own: it captures rc, stdout,
# stderr and the surrounding state so the comparison in
# docs/go-evolution/01-parity-and-safety.md cites real evidence. A menu that
# does not return within the timeout is recorded as HARNESS-BLOCKED, never as a
# business result.
#
# Usage:
#   BASH_CTR=e2e-...-bash GO_CTR=e2e-...-go OUT=.../ops-probe \
#       bash tests/e2e-diff/run_ops_probe.sh
set -uo pipefail

BASH_CTR="${BASH_CTR:?BASH_CTR required}"
GO_CTR="${GO_CTR:?GO_CTR required}"
OUT="${OUT:?OUT required}"
TIMEOUT="${TIMEOUT:-90}"
mkdir -p "$OUT"

snapshot() {
    local ctr=$1 dest=$2
    mkdir -p "$dest"
    docker exec "$ctr" sh -c '
        sha256sum /etc/idleleo/conf/xray/config.json 2>/dev/null || true
        systemctl is-active xray 2>/dev/null || true
        systemctl is-active nginx 2>/dev/null || true
        ss -lnt 2>/dev/null | sed -n "2,20p"
        pgrep -x xray 2>/dev/null | sort || true
    ' >"$dest/state.txt" 2>&1
}

capture() {
    local ctr=$1 dir=$2; shift 2
    mkdir -p "$dir"
    docker exec -i "$ctr" "$@" >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    echo $? >"$dir/rc.txt"
}

# bash_menu <id> <menu path>: feeds the path plus 0 (exit) to the real menu.
bash_menu() {
    local id=$1 path=$2 dir="$OUT/$1/bash"
    mkdir -p "$dir"
    {
        printf '%s\n' "$path" | tr '>' '\n'
        printf '0\n'
    } | timeout "$TIMEOUT" docker exec -i "$BASH_CTR" bash /src/install.sh \
        >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    local rc=$?
    echo "$rc" >"$dir/rc.txt"
    [[ $rc -eq 124 ]] && echo "HARNESS-BLOCKED: menu timeout" >"$dir/BLOCKED.txt"
}

go_cmd() {
    local id=$1; shift
    local dir="$OUT/$id/go"
    mkdir -p "$dir"
    timeout "$TIMEOUT" docker exec -i \
        -e IDLELEO_ALLOW_SYSTEM_WRITES=I_ACCEPT_CONTAINER_ONLY \
        "$GO_CTR" /usr/local/bin/idleleo "$@" --container \
        >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    local rc=$?
    echo "$rc" >"$dir/rc.txt"
    [[ $rc -eq 124 ]] && echo "HARNESS-BLOCKED: command timeout" >"$dir/BLOCKED.txt"
}

snapshot "$BASH_CTR" "$OUT/state/before-bash"
snapshot "$GO_CTR" "$OUT/state/before-go"

# OPS-01 查看用户
bash_menu OPS-01 '2>1>1'
go_cmd OPS-01 xray user list --json

# OPS-11 查看配置信息
capture "$BASH_CTR" "$OUT/OPS-11/bash" bash /src/install.sh --show
go_cmd OPS-11 show --json

# OPS-12 实时访问日志（取最近 20 行，非交互）
capture "$BASH_CTR" "$OUT/OPS-12/bash" bash /src/install.sh -xa 20
go_cmd OPS-12 service logs --unit xray --lines 20

# OPS-13 实时错误日志
capture "$BASH_CTR" "$OUT/OPS-13/bash" bash /src/install.sh -xe 20
go_cmd OPS-13 service logs --unit xray-err --lines 20

# OPS-15 服务重启
capture "$BASH_CTR" "$OUT/OPS-15/bash" bash /src/install.sh --service-restart
go_cmd OPS-15 service restart

# OPS-18 TCP 加速（Bash 菜单是开关，Go 是只读状态）
bash_menu OPS-18 '6>1'
go_cmd OPS-18 tcp status --json

# OPS-22 清除日志
bash_menu OPS-22 '6>5'
go_cmd OPS-22 xray logs clean --yes --json

# OPS-29 Rill AI 状态
bash_menu OPS-29 '9'
go_cmd OPS-29 rill status --json

snapshot "$BASH_CTR" "$OUT/state/after-bash"
snapshot "$GO_CTR" "$OUT/state/after-go"

for id in OPS-01 OPS-11 OPS-12 OPS-13 OPS-15 OPS-18 OPS-22 OPS-29; do
    for side in bash go; do
        printf '%s\t%s\t%s\n' "$id" "$side" "$(cat "$OUT/$id/$side/rc.txt" 2>/dev/null || echo missing)"
    done
done >"$OUT/summary.tsv"
