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

VERSION="1.2.0"
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

Environment:
  XRAY_STATS_WIDTH Override the table width (40-120 columns) for logs/tests.

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

# ---------------------------------------------------------------------------
# Translation. The main script exports TEXTDOMAIN/TEXTDOMAINDIR and sets LANG
# from language.conf before invoking this helper. When this script is run on
# its own, the same defaults are used. A missing catalog entry falls back to
# the English catalog for non-Chinese locales, so a partially translated
# language never produces a half-Chinese screen. If gettext is unavailable
# (offline minimal host), the Chinese msgid is used, which is the project's
# documented default language.
# ---------------------------------------------------------------------------
TEXTDOMAIN="${TEXTDOMAIN:-xray_install}"
TEXTDOMAINDIR="${TEXTDOMAINDIR:-/etc/idleleo/languages}"
export TEXTDOMAIN TEXTDOMAINDIR

_gettext_bin=$(type -P gettext 2>/dev/null || true)
_msgunfmt_bin=$(type -P msgunfmt 2>/dev/null || true)
_CAT_LANG=""
_CAT_TEXT=""
_EN_TEXT=""

# gettext itself needs a generated locale: on minimal Ubuntu/CentOS images
# with only C.utf8, LANGUAGE is ignored and the Chinese msgid comes back even
# when language.conf says en_US. Read the tracked .mo directly through
# msgunfmt instead, which is locale-independent. If msgunfmt is absent the
# gettext path below still works on hosts where the locale is generated.
_load_catalog_text() {
    local lang="$1" mo="${TEXTDOMAINDIR}/${1}/LC_MESSAGES/${TEXTDOMAIN}.mo"
    [[ -n "${_msgunfmt_bin}" && -r "${mo}" ]] || return 1
    if [[ "${_CAT_LANG}" == "${lang}" && -n "${_CAT_TEXT}" ]]; then
        return 0
    fi
    _CAT_TEXT=$("${_msgunfmt_bin}" --no-wrap "${mo}" 2>/dev/null) || {
        _CAT_TEXT=""
        _CAT_LANG=""
        return 1
    }
    _CAT_LANG="${lang}"
    return 0
}

_load_en_text() {
    local mo="${TEXTDOMAINDIR}/en/LC_MESSAGES/${TEXTDOMAIN}.mo"
    [[ -n "${_EN_TEXT}" || -z "${_msgunfmt_bin}" || ! -r "${mo}" ]] && return 0
    _EN_TEXT=$("${_msgunfmt_bin}" --no-wrap "${mo}" 2>/dev/null) || _EN_TEXT=""
    return 0
}

_catalog_lookup() {
    local text="$1" msg="$2" id str
    printf '%s\n' "${text}" | awk -v want="${msg}" '
        /^msgid "/ {
            id = substr($0, 8)
            sub(/"$/, "", id)
            next
        }
        /^msgstr "/ {
            str = substr($0, 9)
            sub(/"$/, "", str)
            if (id == want) {
                print str
                exit
            }
            id = ""
            next
        }
    '
}

_locale_lang_code() {
    if [[ -n "${XRAY_STATS_LANG:-}" ]]; then
        printf '%s' "${XRAY_STATS_LANG}"
        return 0
    fi
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        en*) printf 'en' ;;
        fr*) printf 'fr' ;;
        ru*) printf 'ru' ;;
        ko*) printf 'ko' ;;
        fa*) printf 'fa' ;;
        *) printf '' ;;
    esac
}

_t() {
    local msg="$1" out en code
    code=$(_locale_lang_code)
    if [[ "${code}" == "zh" || -z "${code}" ]]; then
        printf '%s' "${msg}"
        return 0
    fi
    if [[ -n "${_msgunfmt_bin}" ]]; then
        out=""
        if _load_catalog_text "${code}"; then
            out=$(_catalog_lookup "${_CAT_TEXT}" "${msg}")
        fi
        if [[ -z "${out}" && "${code}" != "en" ]]; then
            _load_en_text
            out=$(_catalog_lookup "${_EN_TEXT}" "${msg}")
        fi
        if [[ -n "${out}" ]]; then
            printf '%s' "${out}"
        else
            printf '%s' "${msg}"
        fi
        return 0
    fi
    if [[ -z "${_gettext_bin}" ]]; then
        printf '%s' "${msg}"
        return 0
    fi
    out=$("${_gettext_bin}" "${msg}" 2>/dev/null) || out="${msg}"
    [[ -n "${out}" ]] || out="${msg}"
    if [[ "${out}" == "${msg}" ]]; then
        out=$(LC_ALL=C.UTF-8 LANGUAGE="${code}" "${_gettext_bin}" "${msg}" 2>/dev/null) || out="${msg}"
        if [[ "${out}" == "${msg}" && "${code}" != "en" ]]; then
            en=$(LC_ALL=C.UTF-8 LANGUAGE=en "${_gettext_bin}" "${msg}" 2>/dev/null) || en="${msg}"
            if [[ -n "${en}" && "${en}" != "${msg}" ]]; then
                out="${en}"
            fi
        fi
    fi
    printf '%s' "${out}"
}

# ---------------------------------------------------------------------------
# Colour and glyph gating. Colours are real ESC bytes only on a terminal and
# only when NO_COLOR is unset and TERM is not dumb. Everything else is empty,
# so logs, pipes and CI contain no control bytes. Box drawing degrades to
# ASCII when the locale/terminal cannot be trusted with UTF-8.
# ---------------------------------------------------------------------------
_color_enabled=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    _color_enabled=1
fi
if [[ ${_color_enabled} -eq 1 ]]; then
    Bold=$'\033[1m'
    Dim=$'\033[2m'
    Green=$'\033[32m'
    Red=$'\033[31m'
    Yellow=$'\033[33m'
    Font=$'\033[0m'
else
    Bold=""
    Dim=""
    Green=""
    Red=""
    Yellow=""
    Font=""
fi

_utf8_ok() {
    [[ "${XRAY_STATS_ASCII:-0}" == "1" ]] && return 1
    [[ "${TERM:-}" == "dumb" ]] && return 1
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-UTF-8}}}" in
        C|POSIX|*.ISO-8859*|*iso8859*) return 1 ;;
    esac
    return 0
}

if _utf8_ok; then
    BOX_TL='┌'; BOX_TR='┐'; BOX_BL='└'; BOX_BR='┘'
    BOX_VL='│'; BOX_VR='│'; BOX_ML='├'; BOX_MR='┤'
    BOX_H='─'
else
    BOX_TL='+'; BOX_TR='+'; BOX_BL='+'; BOX_BR='+'
    BOX_VL='|'; BOX_VR='|'; BOX_ML='+'; BOX_MR='+'
    BOX_H='-'
fi

_repeat() {
    local count="$1" char="$2" i
    for ((i = 0; i < count; i++)); do
        printf '%s' "${char}"
    done
}

# East Asian Ambiguous symbols used by this report render one cell in common
# terminals even though their UTF-8 sequences are three bytes. Treating them as
# wide would leak one space and make the right border drift.
_char_width() {
    local ch="$1" step="$2"
    case "${ch}" in
        '↑'|'↓'|'→'|'←'|'…'|'Σ'|'·'|'─'|'│'|'┌'|'┐'|'└'|'┘'|'├'|'┤')
            printf '1'
            return 0
            ;;
    esac
    if ((step >= 3)); then
        printf '2'
    else
        printf '1'
    fi
}

# Display width without external dependencies. Under LC_ALL=C each byte is
# inspected: ASCII = 1 cell, 2-byte sequences = 1, 3/4-byte sequences = 2
# unless the character is a known narrow symbol above. That is correct for
# Chinese, Cyrillic, Latin accents and emoji, which are the characters this
# table actually emits. Combining marks are not used.
_dw() {
    local s="$1" i=0 n w=0 c v step ch
    local LC_ALL=C
    n=${#s}
    while ((i < n)); do
        c=${s:i:1}
        v=$(printf '%d' "'$c" 2>/dev/null) || v=63
        if ((v < 128)); then
            step=1
        elif ((v < 192)); then
            step=1
        elif ((v < 224)); then
            step=2
        elif ((v < 240)); then
            step=3
        else
            step=4
        fi
        ch=${s:i:step}
        w=$((w + $(_char_width "${ch}" "${step}")))
        i=$((i + step))
    done
    printf '%s' "${w}"
}

_pad_r() {
    local text="$1" width="$2" used
    used=$(_dw "${text}")
    if ((used >= width)); then
        printf '%s' "${text}"
    else
        printf '%s%*s' "${text}" "$((width - used))" ''
    fi
}

_pad_l() {
    local text="$1" width="$2" used
    used=$(_dw "${text}")
    if ((used >= width)); then
        printf '%s' "${text}"
    else
        printf '%*s%s' "$((width - used))" '' "${text}"
    fi
}

_truncate() {
    local text="$1" max="$2" out="" w=0 i=0 n c v step cw
    local LC_ALL=C
    n=${#text}
    while ((i < n)); do
        c=${text:i:1}
        v=$(printf '%d' "'$c" 2>/dev/null) || v=63
        if ((v < 128)); then
            step=1
        elif ((v < 192)); then
            step=1
        elif ((v < 224)); then
            step=2
        elif ((v < 240)); then
            step=3
        else
            step=4
        fi
        cw=$(_char_width "${text:i:step}" "${step}")
        if ((w + cw > max - 3)); then
            out="${out}..."
            break
        fi
        out="${out}${text:i:step}"
        w=$((w + cw))
        i=$((i + step))
    done
    printf '%s' "${out}"
}

_term_cols() {
    local w="${XRAY_STATS_WIDTH:-}" size=""
    [[ -n "${w}" ]] || w="${COLUMNS:-}"
    # `[[ -t 1 ]]` is useless inside $(...): the command substitution's stdout
    # is a pipe. Query the controlling terminal directly instead.
    if [[ -z "${w}" ]]; then
        size=$(stty size 2>/dev/null </dev/tty || true)
        w=${size#* }
    fi
    if [[ -z "${w}" ]] && [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
        w=$(tput cols 2>/dev/null || true)
    fi
    case "${w}" in
        ''|*[!0-9]*) w=80 ;;
    esac
    ((w < 40)) && w=40
    ((w > 120)) && w=120
    printf '%s' "${w}"
}

# Use one column less than the detected width: some terminals wrap when a
# line exactly fills the last column, and a wrapped border looks broken.
BOX_W=$(_term_cols)
((BOX_W > 40)) && BOX_W=$((BOX_W - 1))

_box_top() {
    local title="$1" title_w fill
    title_w=$(_dw "${title}")
    if ((title_w > BOX_W - 6)); then
        title=$(_truncate "${title}" $((BOX_W - 6)))
        title_w=$(_dw "${title}")
    fi
    fill=$((BOX_W - 5 - title_w))
    ((fill < 1)) && fill=1
    printf '%b%s%b%s%b %b%s%b %b%s%b\n' \
        "${Dim}" "${BOX_TL}" "${Dim}" "${BOX_H}" "${Dim}" \
        "${Bold}" "${title}" "${Dim}" \
        "$(_repeat "${fill}" "${BOX_H}")" "${BOX_TR}${Font}"
}

_box_line() {
    local visible="$1" content="$2" forced="${3:-}" used pad
    if [[ "${forced}" =~ ^[0-9]+$ ]]; then
        used="${forced}"
    else
        used=$(_dw "${visible}")
    fi
    pad=$((BOX_W - used - 4))
    ((pad < 0)) && pad=0
    printf '%b%s%b %s%*s %b%s%b\n' \
        "${Dim}" "${BOX_VL}" "${Font}" "${content}" "${pad}" '' \
        "${Dim}" "${BOX_VR}" "${Font}"
}

_box_sep() {
    printf '%b%s%b%s%b%s%b\n' \
        "${Dim}" "${BOX_ML}" "${Dim}" "$(_repeat $((BOX_W - 2)) "${BOX_H}")" \
        "${Dim}" "${BOX_MR}" "${Font}"
}

_box_bottom() {
    printf '%b%s%b%s%b%s%b\n' \
        "${Dim}" "${BOX_BL}" "${Dim}" "$(_repeat $((BOX_W - 2)) "${BOX_H}")" \
        "${Dim}" "${BOX_BR}" "${Font}"
}

_human_bytes() {
    local bytes="${1:-0}"
    awk -v b="${bytes}" 'BEGIN {
        split("B KB MB GB TB PB", unit, " ")
        i = 1
        v = b + 0
        while (v >= 1024 && i < 6) { v /= 1024; i++ }
        if (i == 1) printf "%d %s", v, unit[i]
        else if (v < 10) printf "%.2f %s", v, unit[i]
        else if (v < 100) printf "%.1f %s", v, unit[i]
        else printf "%.0f %s", v, unit[i]
    }'
}

_uptime_text() {
    local seconds="${1:-0}" days hours minutes secs
    days=$((seconds / 86400))
    hours=$(((seconds % 86400) / 3600))
    minutes=$(((seconds % 3600) / 60))
    secs=$((seconds % 60))
    if ((days > 0)); then
        printf '%dd %02d:%02d:%02d' "${days}" "${hours}" "${minutes}" "${secs}"
    else
        printf '%02d:%02d:%02d' "${hours}" "${minutes}" "${secs}"
    fi
}

if [[ "$(id -u)" != "0" ]]; then
    printf '%s\n' "xray_stats: $(_t "统计查询需要 root 权限")" >&2
    exit 5
fi

if [[ ! -f "${CONFIG}" ]]; then
    printf '%s %s\n' "xray_stats:" "$(_t "未找到配置文件") ${CONFIG}" >&2
    exit 2
fi
if ! jq -e . "${CONFIG}" >/dev/null 2>&1; then
    printf '%s %s\n' "xray_stats:" "$(_t "配置文件不是合法 JSON") ${CONFIG}" >&2
    exit 3
fi

has_stats=$(jq -r 'has("stats")' "${CONFIG}" 2>/dev/null) || {
    printf '%s %s\n' "xray_stats:" "$(_t "无法解析 stats 配置")" >&2
    exit 3
}
if [[ "${has_stats}" != "true" ]]; then
    printf '%s %s\n' "xray_stats:" "$(_t "流量统计未开启")" >&2
    exit 2
fi

if [[ -z "${SERVER}" ]]; then
    SERVER=$(jq -r '.api.listen // empty' "${CONFIG}" 2>/dev/null) || {
        printf '%s %s\n' "xray_stats:" "$(_t "无法解析 api.listen")" >&2
        exit 3
    }
fi
if [[ -z "${SERVER}" ]]; then
    printf '%s %s\n' "xray_stats:" "$(_t "统计已开启但缺少 api.listen，请先在主脚本中开启统计")" >&2
    exit 2
fi
case "${SERVER}" in
    127.0.0.1:*|localhost:*) ;;
    *)
        printf '%s %s\n' "xray_stats:" "$(_t "拒绝非回环统计 API 地址") ${SERVER}" >&2
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
    printf '%s %s\n' "xray_stats:" "$(_t "未找到 xray 可执行文件")" >&2
    exit 2
fi

api_failure() {
    local message="$1"
    case "${message}" in
        *"failed to dial"*|*"connection refused"*|*"no such host"*|*"network is unreachable"*)
            printf '%s %s\n' "xray_stats:" "$(_t "Xray 未运行或统计 API 不可达") ${SERVER}" >&2
            exit 2
            ;;
        *)
            printf '%s %s\n' "xray_stats:" "$(_t "统计 API 调用失败") ${message}" >&2
            exit 3
            ;;
    esac
}

run_once() {
    local reset="$1"
    local stats_raw sys_raw reset_raw normalized
    local version="${VERSION}"

    if [[ "${reset}" == "1" ]]; then
        if ! reset_raw=$("${XRAY_BIN}" api statsquery --server="${SERVER}" -pattern "inbound>>>" -reset=true 2>&1); then
            api_failure "${reset_raw}"
        fi
        if ! jq -e '.stat | type == "array"' <<<"${reset_raw}" >/dev/null 2>&1; then
            printf '%s %s\n' "xray_stats:" "$(_t "重置返回的结果不是合法 JSON")" >&2
            exit 3
        fi
    fi

    if ! stats_raw=$("${XRAY_BIN}" api statsquery --server="${SERVER}" -pattern "inbound>>>" -reset=false 2>&1); then
        api_failure "${stats_raw}"
    fi
    if ! jq -e '.stat | type == "array"' <<<"${stats_raw}" >/dev/null 2>&1; then
        printf '%s %s\n' "xray_stats:" "$(_t "统计查询返回的结果不是合法 JSON")" >&2
        exit 3
    fi

    if ! sys_raw=$("${XRAY_BIN}" api statssys --server="${SERVER}" 2>&1); then
        printf '%s %s\n' "xray_stats:" "$(_t "statssys 调用失败") ${sys_raw}" >&2
        exit 3
    fi
    if ! jq -e '.Uptime | numbers' <<<"${sys_raw}" >/dev/null 2>&1; then
        printf '%s %s\n' "xray_stats:" "$(_t "statssys 缺少 Uptime 字段")" >&2
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
        printf '%s %s\n' "xray_stats:" "$(_t "无法生成统计结果")" >&2
        exit 3
    }

    if [[ "${JSON_OUTPUT}" == "1" ]]; then
        printf '%s\n' "${normalized}"
        return 0
    fi

    render_report "${normalized}"
}

render_report() {
    local normalized="$1"
    local -a tags=() uplinks=() downlinks=() totals=()
    local -a human_up=() human_down=() human_total=()
    local line tag up down total
    local max_tag=0 w
    local sum_up=0 sum_down=0 sum_total=0 active=0
    local uptime uptime_text
    local inner tag_col num_w up_w down_w total_w i

    local table
    table=$(jq -r '.inbounds[]? | [(.tag | gsub("[[:cntrl:]]"; " ")), .uplinkBytes, .downlinkBytes, .totalBytes] | @tsv' <<<"${normalized}") || {
        printf '%s %s\n' "xray_stats:" "$(_t "无法格式化入站数据")" >&2
        exit 3
    }
    while IFS=$'\t' read -r tag up down total; do
        [[ -z "${tag}" ]] && continue
        tags+=("${tag}")
        uplinks+=("${up}")
        downlinks+=("${down}")
        totals+=("${total}")
        human_up+=("$(_human_bytes "${up}")")
        human_down+=("$(_human_bytes "${down}")")
        human_total+=("$(_human_bytes "${total}")")
        sum_up=$((sum_up + up))
        sum_down=$((sum_down + down))
        sum_total=$((sum_total + total))
        ((total > 0)) && active=$((active + 1))
        w=$(_dw "${tag}")
        ((w > max_tag)) && max_tag=${w}
    done <<<"${table}"

    uptime=$(jq -r '.uptimeSeconds // 0' <<<"${normalized}" 2>/dev/null) || uptime=0
    uptime_text=$(_uptime_text "${uptime}")
    inner=$((BOX_W - 4))

    local title_stats title_detail
    local label_uptime label_inbounds label_active label_up label_down label_total
    title_stats=$(_t "总览")
    title_detail=$(_t "入站明细")
    label_uptime=$(_t "运行时长")
    label_inbounds=$(_t "入站数量")
    label_active=$(_t "有流量入站")
    label_up=$(_t "上行")
    label_down=$(_t "下行")
    label_total=$(_t "合计")
    local no_traffic hint_traffic
    no_traffic=$(_t "暂无流量")
    hint_traffic=$(_t "产生一次访问后刷新")

    local header_tag header_up header_down header_total
    header_tag=$(_t "入站")
    header_up=$(_t "上行")
    header_down=$(_t "下行")
    header_total=$(_t "合计")

    up_w=$(_dw "${header_up}"); down_w=$(_dw "${header_down}"); total_w=$(_dw "${header_total}")
    ((up_w < 9)) && up_w=9
    ((down_w < 9)) && down_w=9
    ((total_w < 9)) && total_w=9
    for ((i = 0; i < ${#tags[@]}; i++)); do
        w=$(_dw "${human_up[$i]}"); ((w > up_w)) && up_w=${w}
        w=$(_dw "${human_down[$i]}"); ((w > down_w)) && down_w=${w}
        w=$(_dw "${human_total[$i]}"); ((w > total_w)) && total_w=${w}
    done
    ((up_w > 14)) && up_w=14
    ((down_w > 14)) && down_w=14
    ((total_w > 14)) && total_w=14
    num_w=$((up_w + down_w + total_w))

    # Compact layout for narrow terminals or when translated headers make the
    # numeric columns too wide for the available inner width.
    if ((inner < 46 || inner < num_w + 12)); then
        _box_top "${title_stats}"
        local overview1 overview2 overview3
        overview1="${label_uptime}: ${uptime_text}"
        overview2="↑ ${label_up}: $(_human_bytes "${sum_up}")  ↓ ${label_down}: $(_human_bytes "${sum_down}")"
        overview3="Σ ${label_total}: $(_human_bytes "${sum_total}")  ${label_inbounds}: ${#tags[@]}"
        overview1=$(_truncate "${overview1}" "${inner}")
        overview2=$(_truncate "${overview2}" "${inner}")
        overview3=$(_truncate "${overview3}" "${inner}")
        _box_line "${overview1}" "${overview1}"
        _box_line "${overview2}" "${overview2}"
        _box_line "${overview3}" "${overview3}"
        _box_sep
        _box_line "${title_detail}" "${Bold}${title_detail}${Font}"
        if (( ${#tags[@]} == 0 )); then
            local note_plain="${no_traffic} (${hint_traffic})"
            note_plain=$(_truncate "${note_plain}" "${inner}")
            _box_line "${note_plain}" "${Yellow}${note_plain}${Font}"
        else
            for ((i = 0; i < ${#tags[@]}; i++)); do
                local compact_tag compact_line
                compact_tag=$(_truncate "${tags[$i]}" "${inner}")
                _box_line "${compact_tag}" "${Bold}${compact_tag}${Font}"
                compact_line="  ↑ ${human_up[$i]}  ↓ ${human_down[$i]}  Σ ${human_total[$i]}"
                compact_line=$(_truncate "${compact_line}" "${inner}")
                _box_line "${compact_line}" "${compact_line}"
            done
            if ((active == 0)); then
                local note_plain="${no_traffic} (${hint_traffic})"
                note_plain=$(_truncate "${note_plain}" "${inner}")
                _box_line "${note_plain}" "${Yellow}${note_plain}${Font}"
            fi
        fi
        _box_bottom
        return 0
    fi

    # Table layout.
    tag_col=$((inner - num_w - 6))
    ((tag_col < 6)) && tag_col=6

    _box_top "${title_stats}"
    local overview1 overview2
    overview1="${label_uptime}: ${uptime_text}  ·  ${label_inbounds}: ${#tags[@]}  ·  ${label_active}: ${active}"
    overview2="↑ ${label_up}: $(_human_bytes "${sum_up}")  ↓ ${label_down}: $(_human_bytes "${sum_down}")  Σ ${label_total}: $(_human_bytes "${sum_total}")"
    overview1=$(_truncate "${overview1}" "${inner}")
    overview2=$(_truncate "${overview2}" "${inner}")
    _box_line "${overview1}" "${overview1}"
    _box_line "${overview2}" "${overview2}"
    _box_bottom
    printf '\n'

    _box_top "${title_detail}"
    local header_row data_row
    header_row="$(_pad_r "${header_tag}" "${tag_col}")  $(_pad_l "${header_up}" "${up_w}")  $(_pad_l "${header_down}" "${down_w}")  $(_pad_l "${header_total}" "${total_w}")"
    _box_line "" "${Bold}${header_row}${Font}" "${inner}"
    _box_sep

    if (( ${#tags[@]} == 0 )); then
        local note_plain="${no_traffic} (${hint_traffic})"
        _box_line "${note_plain}" "${Yellow}${note_plain}${Font}"
    else
        for ((i = 0; i < ${#tags[@]}; i++)); do
            local shown_tag
            shown_tag=$(_truncate "${tags[$i]}" "${tag_col}")
            data_row="$(_pad_r "${shown_tag}" "${tag_col}")  $(_pad_l "${human_up[$i]}" "${up_w}")  $(_pad_l "${human_down[$i]}" "${down_w}")  $(_pad_l "${human_total[$i]}" "${total_w}")"
            _box_line "" "${data_row}" "${inner}"
        done
        if ((active == 0)); then
            local note_plain="${no_traffic} (${hint_traffic})"
            _box_line "${note_plain}" "${Yellow}${note_plain}${Font}"
        fi
        _box_sep
        data_row="$(_pad_r "${label_total}" "${tag_col}")  $(_pad_l "$(_human_bytes "${sum_up}")" "${up_w}")  $(_pad_l "$(_human_bytes "${sum_down}")" "${down_w}")  $(_pad_l "$(_human_bytes "${sum_total}")" "${total_w}")"
        _box_line "" "${Bold}${data_row}${Font}" "${inner}"
    fi
    _box_bottom
}

_watch_tty=0
_watch_active=0
watch_cleanup() {
    if [[ "${_watch_active}" == "1" ]]; then
        _watch_active=0
        if [[ "${_watch_tty}" == "1" ]]; then
            printf '\033[?25h%s' "${Font}"
        fi
    fi
}

if [[ "${RESET}" == "1" ]]; then
    if [[ "${ASSUME_YES}" != "1" ]]; then
        printf '%s [Y/%bN%b]? ' "$(_t "重置入站流量统计")" "${Red}" "${Font}" >&2
        answer=""
        read -r answer || answer=""
        case "${answer}" in
            [yY][eE][sS]|[yY]) ;;
            *)
                printf '%s %s\n' "xray_stats:" "$(_t "重置已取消")" >&2
                exit 1
                ;;
        esac
    fi
    run_once 1
    exit 0
fi

if [[ -n "${WATCH_INTERVAL}" ]]; then
    if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
        _watch_tty=1
    fi
    _watch_active=1
    _watch_first=1
    trap 'watch_cleanup; exit 130' INT TERM
    trap 'watch_cleanup' EXIT
    if [[ "${_watch_tty}" == "1" ]]; then
        printf '\033[?25l'
    fi
    while true; do
        if [[ "${_watch_tty}" == "1" ]]; then
            printf '\033[H\033[2J'
        elif [[ "${JSON_OUTPUT}" != "1" && "${_watch_first}" != "1" ]]; then
            printf '\n'
        fi
        _watch_is_first="${_watch_first}"
        _watch_first=0
        if [[ "${JSON_OUTPUT}" != "1" ]]; then
            every=$(_t "每 %s 秒刷新，Ctrl-C 退出")
            header="$(printf "${every}" "${WATCH_INTERVAL}")"
            if [[ "${_watch_is_first}" == "1" ]]; then
                # First human frame: query before writing the title so an
                # unreachable API leaves stdout at zero bytes.
                _watch_buffered=$(run_once 0)
                _watch_rc=$?
                if [[ "${_watch_rc}" -ne 0 ]]; then
                    exit "${_watch_rc}"
                fi
                printf '%b%s%b\n\n' "${Bold}" "$(_t "实时监控") · ${header} · $(_t "最后刷新") $(date '+%H:%M:%S')" "${Font}"
                printf '%s\n' "${_watch_buffered}"
            else
                printf '%b%s%b\n\n' "${Bold}" "$(_t "实时监控") · ${header} · $(_t "最后刷新") $(date '+%H:%M:%S')" "${Font}"
                run_once 0
            fi
        else
            run_once 0
        fi
        sleep "${WATCH_INTERVAL}"
    done
fi

run_once 0
exit 0
