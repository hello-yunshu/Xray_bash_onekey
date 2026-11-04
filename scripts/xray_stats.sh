#!/usr/bin/env bash
# Read-only Xray traffic statistics reader.
#
# This script never writes the Xray configuration. It only reads the
# configured loopback API address and queries StatsService via the installed
# Xray CLI. Reset is an explicit, confirmed StatsService counter reset;
# watch is a local display loop. Neither modifies config.
#
# Exit codes:
#   0  success (zero counters are still success)
#   1  reset cancelled
#   2  prerequisite missing: stats disabled, no api.listen, Xray/API down
#   3  API call or JSON parse failed
#   4  invalid arguments
#   5  root/permission required
#   130 interrupted

set -u

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

VERSION="1.1.0"
CONFIG="${XRAY_STATS_CONFIG:-/etc/idleleo/conf/xray/config.json}"
SERVER=""
JSON_OUTPUT=0
RESET=0
WATCH_INTERVAL=""
ASSUME_YES=0
XRAY_BIN="${XRAY_STATS_BIN:-}"

usage() {
    cat <<'EOF'
Usage: xray_stats.sh [options]

Read-only Xray inbound traffic statistics.

Options:
  --config PATH    Xray config path (default: /etc/idleleo/conf/xray/config.json)
  --server ADDR    Stats API address (default: api.listen from the config)
  --json           Output a single JSON object per query
  --reset          Reset inbound counters after an explicit confirmation
  --yes            Skip the reset confirmation (automation only)
  --watch [SEC]    Refresh every SEC seconds (default 5); Ctrl-C exits 130
  --version        Print the script version
  --help           Show this help

Exit codes: 0 success, 1 reset cancelled, 2 prerequisite missing,
            3 API/JSON failure, 4 invalid arguments, 5 root required,
            130 interrupted.
EOF
}

while (($# > 0)); do
    case "$1" in
        --config)
            [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 4; }
            CONFIG="$2"
            shift 2
            ;;
        --server)
            [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 4; }
            SERVER="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=1
            shift
            ;;
        --reset)
            RESET=1
            shift
            ;;
        --yes)
            ASSUME_YES=1
            shift
            ;;
        --watch)
            WATCH_INTERVAL="5"
            if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                WATCH_INTERVAL="$2"
                shift
            fi
            shift
            ;;
        --version)
            printf '%s\n' "${VERSION}"
            exit 0
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 4
            ;;
    esac
done

if [[ "${RESET}" == "1" && -n "${WATCH_INTERVAL}" ]]; then
    printf '%s\n' "xray_stats: --reset and --watch are mutually exclusive" >&2
    exit 4
fi
if [[ "${ASSUME_YES}" == "1" && "${RESET}" != "1" ]]; then
    printf '%s\n' "xray_stats: --yes is only valid with --reset" >&2
    exit 4
fi
if [[ -n "${WATCH_INTERVAL}" && ! "${WATCH_INTERVAL}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' "xray_stats: --watch interval must be a positive integer" >&2
    exit 4
fi

trap 'exit 130' INT TERM

if [[ "$(id -u)" != "0" ]]; then
    printf '%s\n' "xray_stats: root permission is required" >&2
    exit 5
fi

if [[ ! -f "${CONFIG}" ]]; then
    printf '%s\n' "xray_stats: config not found: ${CONFIG}" >&2
    exit 2
fi
if ! jq -e . "${CONFIG}" >/dev/null 2>&1; then
    printf '%s\n' "xray_stats: config is not valid JSON: ${CONFIG}" >&2
    exit 3
fi

has_stats=$(jq -r 'has("stats")' "${CONFIG}" 2>/dev/null) || {
    printf '%s\n' "xray_stats: cannot parse stats state" >&2
    exit 3
}
if [[ "${has_stats}" != "true" ]]; then
    printf '%s\n' "xray_stats: traffic statistics are not enabled" >&2
    exit 2
fi

if [[ -z "${SERVER}" ]]; then
    SERVER=$(jq -r '.api.listen // empty' "${CONFIG}" 2>/dev/null) || {
        printf '%s\n' "xray_stats: cannot parse api.listen" >&2
        exit 3
    }
fi
if [[ -z "${SERVER}" ]]; then
    printf '%s\n' "xray_stats: stats are enabled but api.listen is missing; run the main script migration first" >&2
    exit 2
fi
case "${SERVER}" in
    127.0.0.1:*|localhost:*) ;;
    *)
        printf '%s\n' "xray_stats: refusing non-loopback stats API address: ${SERVER}" >&2
        exit 2
        ;;
esac

if [[ -z "${XRAY_BIN}" ]]; then
    if command -v xray >/dev/null 2>&1; then
        XRAY_BIN=$(command -v xray)
    elif [[ -x /usr/local/bin/xray ]]; then
        XRAY_BIN=/usr/local/bin/xray
    elif [[ -x /usr/bin/xray ]]; then
        XRAY_BIN=/usr/bin/xray
    fi
fi
if [[ -z "${XRAY_BIN}" || ! -x "${XRAY_BIN}" ]]; then
    printf '%s\n' "xray_stats: xray binary not found" >&2
    exit 2
fi

api_failure() {
    local message="$1"
    case "${message}" in
        *"failed to dial"*|*"connection refused"*|*"no such host"*|*"network is unreachable"*)
            printf '%s\n' "xray_stats: Xray is not running or the stats API is unreachable at ${SERVER}" >&2
            exit 2
            ;;
        *)
            printf '%s\n' "xray_stats: API failure: ${message}" >&2
            exit 3
            ;;
    esac
}

run_once() {
    local reset="$1"
    local stats_raw sys_raw reset_raw normalized table count uptime
    local version="${VERSION}"

    if [[ "${reset}" == "1" ]]; then
        if ! reset_raw=$("${XRAY_BIN}" api statsquery --server="${SERVER}" -pattern "inbound>>>" -reset=true 2>&1); then
            api_failure "${reset_raw}"
        fi
        if ! jq -e '.stat | type == "array"' <<<"${reset_raw}" >/dev/null 2>&1; then
            printf '%s\n' "xray_stats: statsquery reset returned invalid JSON" >&2
            exit 3
        fi
    fi

    if ! stats_raw=$("${XRAY_BIN}" api statsquery --server="${SERVER}" -pattern "inbound>>>" -reset=false 2>&1); then
        api_failure "${stats_raw}"
    fi
    if ! jq -e '.stat | type == "array"' <<<"${stats_raw}" >/dev/null 2>&1; then
        printf '%s\n' "xray_stats: statsquery returned invalid JSON" >&2
        exit 3
    fi

    if ! sys_raw=$("${XRAY_BIN}" api statssys --server="${SERVER}" 2>&1); then
        printf '%s\n' "xray_stats: statssys failed: ${sys_raw}" >&2
        exit 3
    fi
    uptime=$(jq -r '.Uptime // empty' <<<"${sys_raw}" 2>/dev/null) || {
        printf '%s\n' "xray_stats: statssys returned invalid JSON" >&2
        exit 3
    }
    if [[ -z "${uptime}" ]]; then
        printf '%s\n' "xray_stats: statssys returned no Uptime field" >&2
        exit 3
    fi

    normalized=$(jq -n \
        --argjson stats "${stats_raw}" \
        --argjson sys "${sys_raw}" \
        --arg server "${SERVER}" \
        --arg version "${version}" \
        --argjson reset "${reset}" '
        def counters:
            [ $stats.stat[]?
              | select(.name | startswith("inbound>>>"))
              | (.name | split(">>>")) as $p
              | select(($p | length) == 4 and $p[2] == "traffic")
              | {tag: $p[1], dir: $p[3], bytes: ((.value // "0") | tonumber)}
            ];
        {
          schemaVersion: 1,
          version: $version,
          server: $server,
          uptimeSeconds: ($sys.Uptime // null),
          reset: ($reset == 1),
          inbounds: (counters
            | group_by(.tag)
            | map({
                tag: .[0].tag,
                uplinkBytes: ([.[] | select(.dir == "uplink") | .bytes] | add // 0),
                downlinkBytes: ([.[] | select(.dir == "downlink") | .bytes] | add // 0),
                totalBytes: ([.[] | .bytes] | add // 0)
              }))
        }') || {
        printf '%s\n' "xray_stats: failed to build normalized output" >&2
        exit 3
    }

    if [[ "${JSON_OUTPUT}" == "1" ]]; then
        printf '%s\n' "${normalized}"
        return 0
    fi

    printf 'Uptime: %ss\n' "${uptime}"
    printf '%-24s %14s %14s %14s\n' "INBOUND" "UPLINK_BYTES" "DOWNLINK_BYTES" "TOTAL_BYTES"
    table=$(jq -r '.inbounds[]? | [.tag, .uplinkBytes, .downlinkBytes, .totalBytes] | @tsv' <<<"${normalized}") || {
        printf '%s\n' "xray_stats: failed to format inbound rows" >&2
        exit 3
    }
    count=0
    while IFS=$'\t' read -r tag up down total; do
        [[ -z "${tag}" ]] && continue
        printf '%-24s %14s %14s %14s\n' "${tag}" "${up}" "${down}" "${total}"
        count=$((count + 1))
    done <<<"${table}"
    if [[ ${count} -eq 0 ]]; then
        printf '%s\n' "No inbound traffic counters."
    fi
}

if [[ "${RESET}" == "1" ]]; then
    if [[ "${ASSUME_YES}" != "1" ]]; then
        printf '%s' "Reset inbound traffic counters? [y/N] " >&2
        answer=""
        read -r answer || answer=""
        case "${answer}" in
            [yY][eE][sS]|[yY]) ;;
            *)
                printf '%s\n' "xray_stats: reset cancelled" >&2
                exit 1
                ;;
        esac
    fi
    run_once 1
    exit 0
fi

if [[ -n "${WATCH_INTERVAL}" ]]; then
    while true; do
        if [[ "${JSON_OUTPUT}" != "1" && -t 1 ]]; then
            clear 2>/dev/null || true
        fi
        run_once 0
        sleep "${WATCH_INTERVAL}"
    done
fi

run_once 0
exit 0
