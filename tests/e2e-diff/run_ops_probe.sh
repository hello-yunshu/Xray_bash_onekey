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
    docker exec -i -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$ctr" "$@" \
        >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    echo $? >"$dir/rc.txt"
}

capture_timeout() {
    local secs=$1 ctr=$2 dir=$3; shift 3
    mkdir -p "$dir"
    timeout "$secs" docker exec -i -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$ctr" "$@" \
        >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    local rc=$?
    echo "$rc" >"$dir/rc.txt"
    # -xa/-xe follow the log, so a bounded capture is expected to be cut short.
    [[ $rc -eq 124 ]] && echo "TRUNCATED: bounded follow capture (${secs}s)" >"$dir/NOTE.txt"
}

# bash_menu <id> <menu path>: feeds the path plus 0 (exit) to the real menu.
bash_menu() {
    local id=$1 path=$2 dir="$OUT/$1/bash"
    mkdir -p "$dir"
    {
        printf '%s\n' "$path" | tr '>' '\n'
        printf '0\n'
    } | timeout "$TIMEOUT" docker exec -i \
        -e XRAY_VERSIONS_FILE=/etc/idleleo/versions.json "$BASH_CTR" \
        bash /etc/idleleo/install.sh >"$dir/stdout.txt" 2>"$dir/stderr.txt"
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
        "$GO_CTR" /usr/local/bin/idleleo "$@" \
        >"$dir/stdout.txt" 2>"$dir/stderr.txt"
    local rc=$?
    echo "$rc" >"$dir/rc.txt"
    [[ $rc -eq 124 ]] && echo "HARNESS-BLOCKED: command timeout" >"$dir/BLOCKED.txt"
}

snapshot "$BASH_CTR" "$OUT/state/before-bash"
snapshot "$GO_CTR" "$OUT/state/before-go"

# OPS-01 查看用户：Bash 没有独立的用户列表子命令，--show 会打印 UUID；
# Go 的 xray user list 是结构化等价视图。
capture "$BASH_CTR" "$OUT/OPS-01/bash" bash /etc/idleleo/install.sh --show
go_cmd OPS-01 xray user list --path /etc/idleleo/conf/xray/config.json --json

# OPS-11 查看配置信息
capture "$BASH_CTR" "$OUT/OPS-11/bash" bash /etc/idleleo/install.sh --show
go_cmd OPS-11 show --json

# OPS-12 实时访问日志（Bash -xa 会持续跟随，截取 6 秒；Go 为一次性快照）
capture_timeout 6 "$BASH_CTR" "$OUT/OPS-12/bash" bash /etc/idleleo/install.sh -xa 20
go_cmd OPS-12 service logs --unit xray --lines 20

# OPS-13 实时错误日志（journal 合并 stderr，等价只读观察）
capture_timeout 6 "$BASH_CTR" "$OUT/OPS-13/bash" bash /etc/idleleo/install.sh -xe 20
go_cmd OPS-13 service logs --unit xray --lines 20

# OPS-15 服务重启
capture "$BASH_CTR" "$OUT/OPS-15/bash" bash /etc/idleleo/install.sh --service-restart
go_cmd OPS-15 service restart --container

# OPS-18 TCP 加速：Bash 是交互式开关（无回显子命令），由矩阵记录；
# Go 这里只观察只读状态，不把“未执行”伪装成通过。
go_cmd OPS-18 tcp status --json

# OPS-22 清除日志
capture "$BASH_CTR" "$OUT/OPS-22/bash" bash /etc/idleleo/install.sh --clean-logs
go_cmd OPS-22 xray logs clean --yes --container

# OPS-29 Rill AI 状态
capture "$BASH_CTR" "$OUT/OPS-29/bash" bash /etc/idleleo/install.sh --rill-agent-status
go_cmd OPS-29 rill status --json

snapshot "$BASH_CTR" "$OUT/state/after-bash"
snapshot "$GO_CTR" "$OUT/state/after-go"

for id in OPS-01 OPS-11 OPS-12 OPS-13 OPS-15 OPS-18 OPS-22 OPS-29; do
    for side in bash go; do
        [[ -d "$OUT/$id/$side" ]] || continue
        printf '%s\t%s\t%s\n' "$id" "$side" "$(cat "$OUT/$id/$side/rc.txt" 2>/dev/null || echo missing)"
    done
done >"$OUT/summary.tsv"
