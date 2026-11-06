#!/bin/bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

if [[ "${_TEST_MODE:-0}" != "1" ]]; then
    cd "$(
        cd "$(dirname "$0")" || exit
        pwd
    )" || exit
fi

#=================================================================
#	System Request: Debian 12+ / Ubuntu 24.04+ / CentOS Stream 10+
#	Author:	yunyunshu
#	Description: Xray Onekey Management
#	Official document: hey.run
#=================================================================

#fonts color
# Store real ESC bytes, not the literal text "\033". A literal value only
# expands when the caller uses printf '%b' or echo -e; plain echo or
# printf '%s' would print the backslash sequence itself. Colors are empty when
# stdout is not a terminal (logs/CI/pipe) or NO_COLOR/TERM=dumb is set, so
# redirected output never contains ANSI control bytes.
_color_enabled=0
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    _color_enabled=1
fi
if [[ ${_color_enabled} -eq 1 ]]; then
    Green=$'\033[32m'
    Red=$'\033[31m'
    GreenW=$'\033[1;32m'
    RedW=$'\033[1;31m'
    Yellow=$'\033[33m'
    GreenBG=$'\033[42;30m'
    RedBG=$'\033[41;30m'
    YellowBG=$'\033[43;30m'
    Font=$'\033[0m'
else
    Green=""
    Red=""
    GreenW=""
    RedW=""
    Yellow=""
    GreenBG=""
    RedBG=""
    YellowBG=""
    Font=""
fi

# Minimal gettext fallback: returns the input string as-is when the real
# gettext binary/function is not yet available (e.g. before init_language).
# init_language sources the real gettext.sh which overrides this function.
# P1-3: the fallback shell function must NEVER be mistaken for a real gettext
# executable. All install-time detection MUST use has_gettext_binary() (type -P),
# which only searches PATH for an actual executable and ignores functions.
if ! type -P gettext >/dev/null 2>&1; then
    gettext() { printf '%s' "$1"; }
fi

# P1-3: true only when a real gettext executable exists on PATH. `type -P`
# (not `command -v`) is used so the in-script gettext() fallback function above
# is never reported as "installed". The real gettext.sh sourced by init_language
# overrides the fallback function; both may coexist, but the binary check is
# authoritative for deciding whether gettext still needs installing.
has_gettext_binary() {
    type -P gettext >/dev/null 2>&1
}

# T2/P0: true only when a real jq executable exists on PATH. `type -P` (not
# `command -v`) so a test/shell jq() function is never reported as installed;
# only an actual executable can parse JSON.
has_jq_binary() {
    type -P jq >/dev/null 2>&1
}

has_msgunfmt_binary() {
    type -P msgunfmt >/dev/null 2>&1
}

# Locale-independent catalog lookup for the interactive menu.
#
# gettext only selects a catalog when the requested locale is generated. On a
# minimal Ubuntu/CentOS image with only C/C.utf8, LANGUAGE is ignored and the
# Chinese msgid is returned even though language.conf says en_US.UTF-8. The
# menu therefore reads the tracked .mo directly and generates a case-based
# lookup function, with gettext kept as the fallback for hosts where the
# requested locale (or a newer catalog) is available.
#
# The generated function is small enough to build per process (roughly 130-190
# KB, measurable generation time, sub-millisecond lookups) and is removed from
# /tmp immediately after being sourced. No new runtime package is required:
# msgunfmt ships with gettext, which the installer already needs.
_XRAY_UI_LANG="zh"
_XRAY_CAT_LANG=""
_XRAY_CAT_READY=0
_XRAY_EN_READY=0
_XRAY_REAL_GETTEXT=""

_xray_i18n_source_catalog() {
    # Keep the msgunfmt msgid/msgstr parsing in sync with
    # scripts/xray_stats.sh::_load_catalog_text/_catalog_lookup. The two
    # processes cannot share code, so any parser rule change must be applied
    # to both implementations.
    local lang="$1" fn="$2" mo tmp id str
    mo="${TEXTDOMAINDIR}/${lang}/LC_MESSAGES/${TEXTDOMAIN}.mo"
    [[ -r "${mo}" ]] || return 1
    has_msgunfmt_binary || return 1
    tmp=$(mktemp "${TMPDIR:-/tmp}/idleleo-catalog.XXXXXX" 2>/dev/null) || return 1
    if ! msgunfmt --no-wrap "${mo}" 2>/dev/null | awk '
        /^msgid "/ {
            id = substr($0, 8)
            sub(/"$/, "", id)
            next
        }
        /^msgstr "/ {
            str = substr($0, 9)
            sub(/"$/, "", str)
            if (id != "") {
                print id "\t" str
                id = ""
            }
            next
        }
    ' >"${tmp}.tsv"; then
        rm -f "${tmp}" "${tmp}.tsv"
        return 1
    fi

    {
        printf '%s() {\n' "${fn}"
        printf '    case "$1" in\n'
        while IFS=$'\t' read -r id str; do
            [[ -n "${id}" && -n "${str}" ]] || continue
            printf '        %q) _XRAY_LOOKUP_RESULT=%q; return 0 ;;\n' "${id}" "${str}"
        done <"${tmp}.tsv"
        printf '    esac\n'
        printf '    return 1\n'
        printf '}\n'
    } >"${tmp}.sh" || {
        rm -f "${tmp}" "${tmp}.tsv" "${tmp}.sh"
        return 1
    }

    if ! . "${tmp}.sh"; then
        rm -f "${tmp}" "${tmp}.tsv" "${tmp}.sh"
        return 1
    fi
    rm -f "${tmp}" "${tmp}.tsv" "${tmp}.sh"
    return 0
}

# Install the active gettext wrapper. `zh` always returns the Chinese msgid;
# other languages use the generated selected catalog, then a real gettext call
# when it actually translated something, then the English catalog, then the
# msgid. This keeps an untranslated entry from becoming a half-Chinese,
# half-English screen.
_xray_i18n_setup() {
    local lang="${1:-zh}"
    _XRAY_UI_LANG="${lang}"
    _XRAY_REAL_GETTEXT=$(type -P gettext 2>/dev/null || true)
    _XRAY_CAT_LANG=""
    _XRAY_CAT_READY=0
    _XRAY_EN_READY=0

    if [[ "${lang}" != "zh" && -n "${lang}" ]]; then
        if _xray_i18n_source_catalog "${lang}" _xray_catalog_lookup; then
            _XRAY_CAT_LANG="${lang}"
            _XRAY_CAT_READY=1
        fi
        if [[ "${lang}" != "en" ]] &&
            _xray_i18n_source_catalog "en" _xray_catalog_lookup_en; then
            _XRAY_EN_READY=1
        fi
    fi

    gettext() {
        local msg="$1" out=""
        if [[ "${_XRAY_UI_LANG}" == "zh" ]]; then
            printf '%s' "${msg}"
            return 0
        fi
        if [[ "${_XRAY_CAT_READY}" == "1" ]]; then
            _XRAY_LOOKUP_RESULT=""
            if _xray_catalog_lookup "${msg}"; then
                out="${_XRAY_LOOKUP_RESULT}"
            fi
            if [[ -n "${out}" ]]; then
                printf '%s' "${out}"
                return 0
            fi
        fi
        if [[ -n "${_XRAY_REAL_GETTEXT}" ]]; then
            out=$("${_XRAY_REAL_GETTEXT}" "${msg}" 2>/dev/null) || out=""
            if [[ -n "${out}" && "${out}" != "${msg}" ]]; then
                printf '%s' "${out}"
                return 0
            fi
        fi
        if [[ "${_XRAY_EN_READY}" == "1" ]]; then
            _XRAY_LOOKUP_RESULT=""
            if _xray_catalog_lookup_en "${msg}"; then
                out="${_XRAY_LOOKUP_RESULT}"
            fi
            if [[ -n "${out}" ]]; then
                printf '%s' "${out}"
                return 0
            fi
        fi
        printf '%s' "${msg}"
    }
    # Prefixes are computed once at source time today; refresh them after a
    # language switch so an English menu does not keep [信息]/[错误]/[警告].
    _xray_apply_ui_prefixes
    # `shell_mode` is initialized before language selection. Refresh only the
    # still-uninstalled default, never a real detected mode.
    if [[ "${shell_mode:-}" == "未安装" || -z "${shell_mode:-}" ]]; then
        shell_mode="$(gettext "未安装")"
    fi
}

_xray_apply_ui_prefixes() {
    Info="${Green}[$(gettext "信息")]${Font}"
    OK="${Green}[OK]${Font}"
    Error="${RedW}[$(gettext "错误")]${Font}"
    Warning="${Yellow}[$(gettext "警告")]${Font}"
}

# Same fallback policy as the stats helper: a requested non-Chinese catalog is
# better served by English than by silently reverting the whole menu to Chinese.
_xray_i18n_fallback_en() {
    local en_mo="${TEXTDOMAINDIR}/en/LC_MESSAGES/${TEXTDOMAIN}.mo"
    if [ -f "${en_mo}" ]; then
        export LANG=en_US.UTF-8 2>/dev/null
        export LC_MESSAGES=en_US.UTF-8 2>/dev/null
        _xray_i18n_setup en
        return 0
    fi
    unset LANG
    unset LC_MESSAGES
    _xray_i18n_setup zh
    return 1
}

# Menu header display name. LANG can be unset (Chinese default) or point at a
# locale the image never generated, so derive it from the active UI catalog.
_xray_lang_display() {
    case "${_XRAY_UI_LANG:-zh}" in
        en) printf 'en_US' ;;
        fr) printf 'fr_FR' ;;
        fa) printf 'fa_IR' ;;
        ru) printf 'ru_RU' ;;
        ko) printf 'ko_KR' ;;
        *) printf 'zh_CN' ;;
    esac
}

#notification information
_xray_apply_ui_prefixes

# One color-safe confirmation prompt. The text is passed as %s (never embedded
# in the printf format), so user/gettext content cannot inject escapes. The
# Y/N colors are real ESC or empty and are emitted with %b.
confirm_prompt() {
    printf '%s [Y/%bN%b]? ' "$1" "${Red}" "${Font}" >&2
}

# Destructive action with a safe default: bare Enter cancels. The visible
# prompt therefore emphasises N, not Y.
confirm_prompt_no() {
    printf '%s [y/%bN%b]? ' "$1" "${Red}" "${Font}" >&2
}

# Print the [y/N] prompt and read one answer. Only y/yes returns success.
confirm_no_answer() {
    local answer=""
    confirm_prompt_no "$1"
    IFS= read -r answer || answer=""
    case "${answer}" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

shell_version="3.3.5"
shell_mode="$(gettext "未安装")"
tls_mode="None"
transport_mode="None"
# "node" (ordinary Xray node) or "relay" (Nginx Stream TCP forwarder).
node_role="node"
relay_backend_host=""
relay_backend_port=""
relay_listen_port=""
relay_listen_addr=""
relay_enabled=""
legacy_xtls_only="off"
local_bin="/usr/local"
idleleo_dir="/etc/idleleo"
idleleo="${idleleo_dir}/install.sh"
idleleo_conf_dir="${idleleo_dir}/conf"
scripts_dir="${idleleo_dir}/scripts"
log_dir="${idleleo_dir}/logs"
xray_bin_dir="${local_bin}/bin"
xray_conf_dir="${idleleo_conf_dir}/xray"
nginx_conf_dir="${idleleo_conf_dir}/nginx"
xray_conf="${xray_conf_dir}/config.json"
xray_status_conf="${xray_conf_dir}/status_config.json"
xray_default_conf="${local_bin}/etc/xray/config.json" # Retained as Xray's default config symlink.
nginx_conf="${nginx_conf_dir}/00-xray.conf"
nginx_ssl_conf="${nginx_conf_dir}/01-xray-80.conf"
nginx_upstream_conf="${nginx_conf_dir}/02-xray-server.conf"
# Managed Nginx Stream fragment for the "relay" role (single TCP target).
# Deliberately NOT in managed_nginx_files: relay and node roles never coexist,
# and a node reinstall must refuse rather than silently delete this file.
relay_stream_conf="${nginx_conf_dir}/relay-stream.conf"
# The single real Nginx main config (compile prefix). The fragment dir
# ${nginx_conf_dir} holds only managed include files, never nginx.conf.
nginx_main_conf="${local_bin}/nginx/conf/nginx.conf"
# Files this script owns inside ${nginx_conf_dir}. Only these are removed
# during reinstall; user-added .conf files (custom sites, stream blocks,
# reverse proxies, security rules) are preserved.
managed_nginx_files=(
    "00-xray.conf"
    "01-xray-80.conf"
    "02-xray-server.conf"
    "03-isolate.conf"
    "03-decoy.conf"
)
idleleo_commend_file="/usr/bin/idleleo"
ssl_chainpath="${idleleo_dir}/cert"
nginx_dir="${local_bin}/nginx"
xray_info_file="${idleleo_dir}/info/xray_info.inf"
xray_install_config_file="${idleleo_conf_dir}/install_config.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
xray_systemd_file="/etc/systemd/system/xray.service"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
auto_update_file="${scripts_dir}/auto_update.sh"
ssl_update_file="${scripts_dir}/ssl_update.sh"
geo_update_file="${scripts_dir}/geo_update.sh"
xray_stats_script="${scripts_dir}/xray_stats.sh"
shell_release_sha256=""
shell_online_version=""
xray_installer_ref=""
xray_installer_sha256=""
xray_installer_verified_at=""
xray_release_ref="v${shell_version}"
shell_release_raw_base="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/${xray_release_ref}"
shell_release_download_base="https://github.com/hello-yunshu/Xray_bash_onekey/releases/download/${xray_release_ref}"
mf_remote_url="${shell_release_raw_base}/scripts/fail2ban_manager.sh"
tb_remote_url="${shell_release_raw_base}/scripts/traffic_blocker.sh"
fm_remote_url="${shell_release_raw_base}/scripts/file_manager.sh"
au_remote_url="${shell_release_raw_base}/scripts/auto_update.sh"
ssl_remote_url="${shell_release_raw_base}/scripts/ssl_update.sh"
geo_remote_url="${shell_release_raw_base}/scripts/geo_update.sh"
main_remote_url="${shell_release_download_base}/install.sh"
update_lock_file="/run/lock/idleleo-update.lock"
release_managed_file="${idleleo_dir}/release-managed.version"
shell_version_tmp="${idleleo_dir}/tmp/shell_version.tmp"
get_versions_all=""
_get_versions_loaded=0
# Explicit non-interactive confirmation for `-u --yes` / `--update --yes`.
# `--yes` only replaces the Y/N prompt for a same-minor update; it never
# authorises a cross-minor update by itself.
update_assume_yes="off"
# `--allow-major` is the separate, explicit switch for a cross-minor update.
# It only lifts the series guard: automation still needs `--yes` for the
# confirmation, and an interactive run still sees the cross-minor prompt.
update_allow_major="off"

shell_release_asset_url() {
    if [[ "${XRAY_QUALIFICATION_MODE:-0}" == "1" && -n "${SHELL_RELEASE_BASE_OVERRIDE:-}" ]]; then
        printf '%s/releases/download/v%s/%s' "${SHELL_RELEASE_BASE_OVERRIDE%/}" "$1" "$2"
        return 0
    fi
    printf 'https://github.com/hello-yunshu/Xray_bash_onekey/releases/download/v%s/%s' "$1" "$2"
}

shell_release_raw_url() {
    if [[ "${XRAY_QUALIFICATION_MODE:-0}" == "1" && -n "${SHELL_RELEASE_BASE_OVERRIDE:-}" ]]; then
        printf '%s/raw/v%s/%s' "${SHELL_RELEASE_BASE_OVERRIDE%/}" "$1" "$2"
        return 0
    fi
    printf 'https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey/v%s/%s' "$1" "$2"
}

set_shell_release_urls() {
    local version=${1:-${shell_version}}
    xray_release_ref="v${version}"
    shell_release_raw_base="$(shell_release_raw_url "${version}" '')"
    shell_release_raw_base=${shell_release_raw_base%/}
    shell_release_download_base="$(shell_release_asset_url "${version}" '')"
    shell_release_download_base=${shell_release_download_base%/}
    mf_remote_url="${shell_release_raw_base}/scripts/fail2ban_manager.sh"
    tb_remote_url="${shell_release_raw_base}/scripts/traffic_blocker.sh"
    fm_remote_url="${shell_release_raw_base}/scripts/file_manager.sh"
    au_remote_url="${shell_release_raw_base}/scripts/auto_update.sh"
    ssl_remote_url="${shell_release_raw_base}/scripts/ssl_update.sh"
    geo_remote_url="${shell_release_raw_base}/scripts/geo_update.sh"
    main_remote_url="${shell_release_download_base}/install.sh"
}

release_sha_contract_required() {
    local version=${1:-}
    [[ "${version}" =~ ^3\.[0-9]+\.[0-9]+$ ]] || return 1
    [[ "$(printf '%s\n%s\n' '3.2.3' "${version}" | sort -V | head -n1)" == '3.2.3' ]]
}

# Dotted numeric versions (26.10.31, 2026.10.15.7679) only. Anything else is
# "not comparable" rather than "equal", so a malformed metadata value can never
# be turned into an update decision.
version_is_numeric() {
    [[ "${1:-}" =~ ^[0-9]+(\.[0-9]+)*$ ]]
}

# Prints 1 / 0 / -1 for newer / equal / older, and returns 2 when either side is
# not a dotted numeric version. Components are compared numerically, so 26.9.30
# is correctly older than 26.10.31 (a plain string compare says the opposite).
# Missing components count as zero: 26.10.0 == 26.10.
version_compare() {
    local a="${1#v}" b="${2#v}"
    local i n x y
    local -a av bv
    version_is_numeric "${a}" && version_is_numeric "${b}" || return 2
    IFS='.' read -r -a av <<<"${a}"
    IFS='.' read -r -a bv <<<"${b}"
    n=${#av[@]}
    [[ ${#bv[@]} -gt ${n} ]] && n=${#bv[@]}
    for ((i = 0; i < n; i++)); do
        x=$((10#${av[i]:-0}))
        y=$((10#${bv[i]:-0}))
        if [[ ${x} -gt ${y} ]]; then
            printf '1\n'
            return 0
        fi
        if [[ ${x} -lt ${y} ]]; then
            printf -- '-1\n'
            return 0
        fi
    done
    printf '0\n'
}

# 1 when $1 and $2 differ in major or minor series, 0 when they are in the
# same series. Numeric components are compared, so 3.9 vs 3.10 is a series
# change and 3.10 vs 3.11 is not (the old first-three-characters heuristic got
# both cases backwards).
version_series_difference() {
    local a="${1#v}" b="${2#v}"
    local a_major a_minor b_major b_minor a_rest b_rest
    version_is_numeric "${a}" && version_is_numeric "${b}" || {
        printf '0\n'
        return 0
    }
    a_major="${a%%.*}"
    a_rest="${a#*.}"
    a_minor="${a_rest%%.*}"
    b_major="${b%%.*}"
    b_rest="${b#*.}"
    b_minor="${b_rest%%.*}"
    if [[ "${a_major}" != "${b_major}" || "${a_minor}" != "${b_minor}" ]]; then
        printf '1\n'
    else
        printf '0\n'
    fi
}

# 0 when $1 is strictly newer than $2. Incomparable input is never "newer".
version_gt() {
    [[ "$(version_compare "$1" "$2")" == "1" ]]
}

# 0 when $1 is strictly older than $2. Incomparable input is never "older".
version_lt() {
    [[ "$(version_compare "$1" "$2")" == "-1" ]]
}

verified_installer_metadata_valid() {
    [[ "${xray_installer_ref:-}" =~ ^[0-9a-f]{40}$ ]] || return 1
    [[ "${xray_installer_sha256:-}" =~ ^[0-9a-f]{64}$ ]] || return 1
}

xray_installer_url() {
    local ref=${1:-${xray_installer_ref:-}}
    [[ "${ref}" =~ ^[0-9a-f]{40}$ ]] || return 1
    printf 'https://raw.githubusercontent.com/XTLS/Xray-install/%s/install-release.sh' "${ref}"
}

with_update_lock() {
    local lock_path="${update_lock_file}"
    if [[ ${IDLELEO_UPDATE_LOCK_HELD:-0} == 1 ]]; then
        "$@"
        return $?
    fi
    if ! mkdir -p "$(dirname "${lock_path}")" 2>/dev/null; then
        lock_path="${idleleo_dir}/update.lock"
        mkdir -p "$(dirname "${lock_path}")" 2>/dev/null || return 1
    fi
    if ! command -v flock >/dev/null 2>&1; then
        # macOS developer/test hosts do not ship util-linux flock. Production
        # Linux uses the shared flock path below; keep local tests runnable.
        IDLELEO_UPDATE_LOCK_HELD=1 "$@"
        return $?
    fi
    exec 9>"${lock_path}" || return 1
    if ! flock -n 9; then
        log_echo "${Warning} ${YellowBG} $(gettext "已有更新任务正在运行") ${Font}" 2>/dev/null || true
        return 1
    fi
    IDLELEO_UPDATE_LOCK_HELD=1 "$@"
    local rc=$?
    flock -u 9 2>/dev/null || true
    exec 9>&-
    return "$rc"
}

fetch_versions_json() {
    local url="$1"
    local response

    if ! response=$(curl -fsSL --connect-timeout 10 --max-time 30 \
        --retry 3 --retry-delay 1 "${url}" 2>/dev/null); then
        return 1
    fi
    if [[ -z "${response}" ]] || ! printf '%s' "${response}" | jq -e 'type == "object"' >/dev/null 2>&1; then
        return 1
    fi
    printf '%s' "${response}"
}

load_versions() {
    if [[ ${_get_versions_loaded} -eq 0 ]]; then
        local versions_cdn_url="https://cdn.jsdelivr.net/gh/hello-yunshu/Xray_bash_onekey_api@main/xray_shell_versions.json"
        local versions_origin_url="https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/xray_shell_versions.json"
        local response

        # CI qualification may inject the exact API checkout under test. This
        # keeps the production path remote-only while allowing cross-repo PR
        # validation before the API branch is merged to main.
        if [[ -n "${XRAY_VERSIONS_FILE:-}" && -f "${XRAY_VERSIONS_FILE}" ]]; then
            response=$(cat "${XRAY_VERSIONS_FILE}")
            printf '%s' "${response}" | jq -e 'type == "object"' >/dev/null 2>&1 || {
                get_versions_all=""
                return 1
            }
        elif ! response=$(fetch_versions_json "${versions_cdn_url}"); then
            response=$(fetch_versions_json "${versions_origin_url}") || {
                get_versions_all=""
                return 1
            }
        fi
        get_versions_all="${response}"
        _get_versions_loaded=1
    fi
    [[ -n "${get_versions_all}" ]]
}

# Load the minimum Release metadata required before the first managed Shell download.
load_shell_release_metadata() {
    local version release_sha
    if ! load_versions; then
        log_echo "${Error} ${RedBG} Shell Release metadata unavailable; fresh bootstrap stopped ${Font}" >&2
        return 1
    fi
    version=$(printf '%s' "${get_versions_all}" | jq -r '.shell_online_version // empty' 2>/dev/null)
    release_sha=$(printf '%s' "${get_versions_all}" | jq -r '.shell_release_sha256 // empty' 2>/dev/null)
    if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_echo "${Error} ${RedBG} Shell Release metadata version is missing or invalid; fresh bootstrap stopped ${Font}" >&2
        return 1
    fi
    if release_sha_contract_required "${version}" &&
        [[ ! "${release_sha}" =~ ^[0-9a-f]{64}$ ]]; then
        log_echo "${Error} ${RedBG} Shell Release metadata checksum is missing or invalid; fresh bootstrap stopped ${Font}" >&2
        return 1
    fi
    if [[ -n "${release_sha}" && ! "${release_sha}" =~ ^[0-9a-f]{64}$ ]]; then
        log_echo "${Error} ${RedBG} Shell Release metadata checksum format is invalid; fresh bootstrap stopped ${Font}" >&2
        return 1
    fi
    shell_online_version="${version}"
    shell_release_sha256="${release_sha}"
    set_shell_release_urls "${shell_online_version}"
}
read_config_status=1
reality_add_more="off"
reality_add_nginx="off"
reality_add_balance="off"
# Reality 负载均衡角色：primary=主服务器(安装 Nginx)，secondary=二级服务器(仅 Reality 后端)，空=未启用
reality_balance_role=""
# SNI Guard 默认值：Reality+Nginx 模式下默认启用，未知 SNI 不转发到 Xray
reality_nginx_sni_guard="on"
unknown_sni_policy="isolate"
decoy_domain=""
spiderx_path=""
old_config_status="off"
old_tls_mode="NULL"
# Distinguishes "read old config" from "locked, cannot modify".
# old_config_loaded="on" means we read the old config into memory;
# it does NOT by itself prevent parameter editing.
old_config_loaded="off"
# When "on", xray_conf_add preserves the existing Xray JSON for
# single-user configs too (保留配置重新安装 path), instead of rebuilding
# from the standard template.
reinstall_keep_config="off"
# Single state variable distinguishing the four reconfigure operations.
# Values: none | keep_config | standard_rebuild | mode_switch | clean_install
reinstall_operation="none"
# Per-field edit flags. Set to "yes" by reinstall_edit_menu when the
# user explicitly chooses to modify that field during a keep-config reinstall.
# Param functions check these to decide whether to re-prompt even when
# old_config_status="on".
change_port="no"
change_user="no"
change_transport="no"
change_inner_ports="no"
change_reality="no"
change_nginx_sni="no"
change_ws_path="no"
change_grpc_path="no"
change_xhttp_path="no"
# ---- IPv4 / IPv6 双栈模型 ----
# network_mode: auto|ipv4|ipv6|dual|manual
# ipv4_address / ipv6_address: 探测/保存的公网地址（双栈模式下同时存在）
# resolved_ipv4s / resolved_ipv6s: 域名 A/AAAA 解析结果集合（\n 分隔）
network_mode=""
ipv4_address=""
ipv6_address=""
resolved_ipv4s=""
resolved_ipv6s=""
# When "yes", email_set and UUID_set skip prompting and reuse the
# values already loaded from the old config during a mode switch.
mode_switch_reuse="off"
# Install wizard profile state. When install_wizard_preset="on", interactive
# choose functions (transport_choose, xray_reality_add_more_choose,
# reality_nginx_add_fq, reality_balance_add_fq) skip prompting and use the
# values set by apply_install_profile. This decouples menu selection from
# install-function-side prompting so the wizard never asks the same question twice.
install_profile=""
install_wizard_preset="off"
# Listen address used by NEW ws/gRPC/xHTTP ONLY deployments. Defaults to
# loopback (no transport encryption); an operator may explicitly pick another
# trusted address in the wizard or via WS_BACKEND_LISTEN_ADDR.
ws_backend_listen_addr="${WS_BACKEND_LISTEN_ADDR:-127.0.0.1}"
random_num=$((RANDOM % 12 + 4))
# P0 (config lazy-load): the top-level phase must NOT call jq before Bootstrap
# has guaranteed it. Configuration is parsed lazily via _lazy_load_info_extraction()
# once we are inside a phase where jq is guaranteed to exist (online repair can add
# it; offline commands dispatch before it and must not trigger a package install).
_info_extraction_loaded=0
# P1-4: fail-closed classification of the existing install config. Distinguishes:
#   config missing            -> normal no-config (read_config_status stays 1)
#   config present + jq gone  -> dependency/config-read error (status=0)
#   config present + malformed-> configuration corruption (status=0)
#   config present + valid    -> normal (status=1)
# The original file is ALWAYS preserved; a corrupt config is never cleared or
# downgraded to "fresh install" semantics. Returns non-zero ONLY when a config
# exists but could not be read, so callers can fail closed at the read boundary.
_lazy_load_info_extraction() {
    if [[ ${_info_extraction_loaded} -eq 1 ]]; then
        return 0
    fi
    if [[ ! -f "${xray_install_config_file}" ]]; then
        info_extraction_all=""
        _info_extraction_loaded=1
        return 0
    fi
    if ! has_jq_binary; then
        # config present + jq missing: explicit dependency/config-read error.
        # Stay UNLOADED so a later read can succeed once jq exists.
        info_extraction_all=""
        read_config_status=0
        return 1
    fi
    local _parsed
    if ! _parsed=$(jq -rc . "${xray_install_config_file}" 2>/dev/null); then
        # config present + malformed JSON: fail closed, preserve the file.
        # Stay UNLOADED so a repaired config can be re-read.
        info_extraction_all=""
        read_config_status=0
        log_echo "${Error} ${RedBG} CONFIG_PARSE_ERROR path=${xray_install_config_file} action=preserved ${Font}" 2>/dev/null || true
        return 1
    fi
    info_extraction_all="${_parsed}"
    read_config_status=1
    _info_extraction_loaded=1
    return 0
}

# P0-1: lazy-load entry for the read-only path (also used by unit tests that
# must not depend on jq being present at source time). Idempotent.
lazy_load_config_for_read() {
    _lazy_load_info_extraction
}

is_ws_mode() {
    [[ ${transport_mode} == *ws* ]]
}

is_grpc_mode() {
    [[ ${transport_mode} == *gRPC* ]]
}

is_xhttp_mode() {
    [[ ${transport_mode} == *xhttp* ]]
}

# Node role. Existing installs have no "role" field in install_config.json and
# are treated as ordinary Xray nodes ("node"). "relay" is a standalone
# Nginx-Stream TCP forwarder: no Xray binary, config, UUID or certificate.
is_relay_role() {
    [[ ${node_role:-node} == "relay" ]]
}

# True when a legacy "XTLS ONLY" installation is still present. That mode was
# removed: the script keeps the running files untouched but refuses to
# reinstall or manage it.
is_legacy_xtls_mode() {
    [[ ${legacy_xtls_only:-off} == "on" ]]
}

# P0 (lazy log): do NOT create /etc/idleleo or touch the log at top level.
# --help / self-check run with _PURE_READONLY=1 so they have zero filesystem
# side effects. File logging initializes lazily on first real (mutation) use.
LOG_FILE="${log_dir}/install.log"
log_file="${LOG_FILE}"
LOG_MAX_SIZE=$((3 * 1024 * 1024))
MAX_ARCHIVES=5
_log_check_counter=0
_LOG_INITIALIZED=0
_PURE_READONLY=1
_log_init() {
    [[ ${_LOG_INITIALIZED} -eq 1 ]] && return 0
    _LOG_INITIALIZED=1
    [[ ! -d "${log_dir}" ]] && mkdir -p "${log_dir}" 2>/dev/null
    [[ -d "${log_dir}" ]] && chmod 700 "${log_dir}" 2>/dev/null || true
    if [[ -d "${log_dir}" && ! -f "${LOG_FILE}" ]]; then
        ( umask 077; : > "${LOG_FILE}" ) 2>/dev/null || true
    fi
    [[ -f "${LOG_FILE}" ]] && chmod 600 "${LOG_FILE}" 2>/dev/null || true
}
# Existing logs and backup archives predate the 0700/0600 model; tighten them
# once on every mutable startup. This is migration, not a new permission policy.
harden_runtime_secret_permissions() {
    if [[ -d "${log_dir}" ]]; then
        chmod 700 "${log_dir}" 2>/dev/null || true
        find "${log_dir}" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null || true
    fi
    if [[ -d "${idleleo_dir}" ]]; then
        find "${idleleo_dir}" -maxdepth 1 -type f -name 'xray_bash_*.tar.gz' \
            -exec chmod 600 {} + 2>/dev/null || true
    fi
}
# Called exactly once the pure/read-only dispatch phase has passed.
enable_file_logging() {
    _PURE_READONLY=0
    harden_runtime_secret_permissions
    _log_init
}

log() {
    if [[ ${_PURE_READONLY} -eq 1 ]]; then
        # suppress all file side effects during pure read-only dispatch
        return 0
    fi
    _log_init
    _log_check_counter=$((_log_check_counter + 1))
    if [[ $((_log_check_counter % 100)) -eq 1 ]]; then
        if [ $(stat -c%s "$LOG_FILE" 2>/dev/null) -gt $LOG_MAX_SIZE ]; then
            log_rotate
        fi
    fi

    local message=$(echo -e "$1" | sed 's/\x1B\[\([0-9]\(;[0-9]\)*\)*m//g' | tr -d '\n')
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE" >/dev/null
}

log_rotate() {
    local timestamp=$(date +%Y%m%d%H%M%S)
    local archived_log="${LOG_FILE}.${timestamp}.gz"

    if ! ( umask 077; gzip -c "$LOG_FILE" > "$archived_log" ); then
        log_echo "${Error} ${RedBG} $(gettext "日志文件归档失败") ${Font}"
        return 1
    fi
    chmod 600 "$archived_log" 2>/dev/null || true

    if ! :> "$LOG_FILE"; then
        log_echo "${Error} ${RedBG} $(gettext "日志文件清空失败") ${Font}"
        return 1
    fi
    chmod 600 "$LOG_FILE" 2>/dev/null || true

    log "$(gettext "日志文件已轮转并归档为") $archived_log"

    rotate_archives
}

rotate_archives() {
    local archives
    mapfile -t archives < <(ls "${LOG_FILE}".*.gz 2>/dev/null)
    while [ ${#archives[@]} -gt $MAX_ARCHIVES ]; do
        oldest_archive=${archives[0]}
        rm "$oldest_archive"
        mapfile -t archives < <(ls "${LOG_FILE}".*.gz 2>/dev/null)
    done
}

log_echo() {
    local message=$(printf "%b" "$@")
    echo -e "$message"
    log "$message"
}

log_echo_secure() {
    local message=$(printf "%b" "$@")
    echo -e "$message"
}

# Redact secrets before diagnostic text reaches stdout or the persistent log.
# Keep this helper in the production script: CI-only redaction cannot protect
# interactive update/rollback diagnostics on real hosts.
redact_diagnostic_text() {
    sed -E \
        -e 's#vless://[^[:space:]]+#<vless link redacted>#g' \
        -e 's/((privateKey|publicKey|password|shortIds?|UUID|uuid|token)[":=[:space:]]+)[A-Za-z0-9._:@\/+-]+/\1<redacted>/gI' \
        -e 's/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/<uuid redacted>/g' \
        -e 's/(Authorization:[[:space:]]*)[^[:space:]]+([[:space:]]+[^[:space:]]+)?/\1<redacted>/gI' \
        -e 's/ghp_[A-Za-z0-9]{20,}/<github token redacted>/g' \
        -e 's/github_pat_[A-Za-z0-9_]{20,}/<github token redacted>/g' |
        awk '
            /-----BEGIN [^-]*PRIVATE KEY-----/ {
                print "<private key block redacted>"
                in_private_key = 1
                next
            }
            /-----END [^-]*PRIVATE KEY-----/ {
                in_private_key = 0
                next
            }
            !in_private_key { print }
        '
}

safe_rm() {
    local target="$1"
    if [[ -z "${target}" || "${target}" == "/" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "拒绝删除空路径或根目录"): ${target} ${Font}"
        return 1
    fi
    rm -rf "${target}"
}

sed_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//&/\\&}"
    str="${str//\//\\/}"
    printf '%s' "$str"
}

update_json_config() {
    local config_file="$1"
    shift
    if [[ -z "${config_file}" ]] || [[ $# -eq 0 ]]; then
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "参数不能为空") ${Font}"
        return 1
    fi
    if [[ ! -f "${config_file}" ]]; then
        log_echo "${Error} ${RedBG} update_json_config: ${config_file} $(gettext "文件不存在") ${Font}"
        return 1
    fi

    local original_mode original_uid original_gid tmp_file _old_umask
    original_mode=$(stat -c '%a' "${config_file}" 2>/dev/null) || return 1
    original_uid=$(stat -c '%u' "${config_file}" 2>/dev/null) || return 1
    original_gid=$(stat -c '%g' "${config_file}" 2>/dev/null) || return 1
    # Use mktemp for unpredictable temp file name (same directory = same filesystem for atomic mv)
    tmp_file=$(mktemp "${config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${config_file}.tmp.$$"

    # Restrictive umask before writing sensitive content (UUID/privateKey/shortIds etc.)
    _old_umask=$(umask)
    umask 077

    if ! jq "$@" "${config_file}" > "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        return 1
    fi
    # Validate generated JSON before replacing original (fail closed on corruption)
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Error} ${RedBG} update_json_config: $(gettext "生成的 JSON 无效，已保留原文件"): ${config_file} ${Font}"
        return 1
    fi
    if ! chmod "${original_mode}" "${tmp_file}" || ! chown "${original_uid}:${original_gid}" "${tmp_file}"; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${config_file} ${Font}"
        return 1
    fi
    umask "${_old_umask}"
    if ! mv "${tmp_file}" "${config_file}"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ "${config_file}" == "${xray_install_config_file}" ]]; then
        info_extraction_all=$(jq -rc . "${config_file}" 2>/dev/null) || return 1
        declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    fi
    return 0
}

# BEGIN RILL XRAY AGENT INTEGRATION
# P1-2: integration capability floor. Compatibility is decided by a SCHEMA
# FLOOR (>=, never a strict equality: a higher schema that still provides
# every required capability must keep passing) PLUS a REQUIRED-CAPABILITY
# floor. A candidate is compatible only when its schema is at or above the
# floor AND it really provides each required capability as a real off-line
# dispatch branch (not a comment, not a bare string).
RILL_XRAY_AGENT_INTEGRATION_SCHEMA=2
RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR=2
RILL_XRAY_AGENT_REQUIRED_CAPABILITIES="status verify mode safe-disable uninstall-v2 diagnose timeline"
# Compatibility anchors for candidate guards shipped before the capability
# floor was introduced.  They are deliberately inert: the active schema above
# remains 2, while an old strict `grep ...=1` guard can still recognize that
# this candidate preserves its schema-1 contract during a direct upgrade.
rxa_legacy_candidate_guard_anchors() {
    # Inert assignment required by legacy guards.
    # shellcheck disable=SC2034
RILL_XRAY_AGENT_INTEGRATION_SCHEMA=1
    :
}
# menu_item 9 "Rill Xray Agent" -- legacy untranslated menu anchor
rill_xray_agent_manager=${RILL_XRAY_AGENT_MANAGER:-/etc/rill-xray-agent/scripts/rill_xray_agent_manager.sh}
# P0-5: candidate validation for script self-updates. Defined here (not only
# in the manager) so it is available even when the agent files are absent.
# Validation is semantic, not string matching: the candidate's integration
# block is sourced inside an isolated sandbox with fake host tooling and the
# required runtime guarantees are actually executed (real function
# definitions, host health in healthy and broken states, offline-safe
# dispatch, reconfigure transaction, uninstall two-phase contract, menu 9).
# P1-2: capability floor. Returns 0 only when the candidate REALLY provides
# the given capability as a live off-line dispatch branch (a real case line
# that routes to a real rxa_dispatch action). A comment line, a bare string,
# or a missing dispatch fails closed. This is the semantic capability check
# that complements (not replaces) the numeric schema floor.
rxa_capability_present() {
    local candidate=${1:-} cap=${2:-}
    case "${cap}" in
        status)       grep -qE '^[[:space:]]*--rill-agent-status\)[[:space:]]*rxa_dispatch status' "${candidate}" ;;
        verify)       grep -qE '^[[:space:]]*--rill-agent-verify\)[[:space:]]*rxa_dispatch verify' "${candidate}" ;;
        mode)         grep -qE '^[[:space:]]*--rill-agent-safe-disable\)[[:space:]]*rxa_dispatch mode safe-disabled' "${candidate}" ;;
        safe-disable) grep -qE '^[[:space:]]*--rill-agent-safe-disable\)[[:space:]]*rxa_dispatch mode safe-disabled' "${candidate}" ;;
        uninstall-v2) grep -qE '^[[:space:]]*--rill-agent-uninstall\)[[:space:]]*rxa_dispatch uninstall' "${candidate}" ;;
        diagnose)     grep -qE '^[[:space:]]*--rill-agent-diagnose\)[[:space:]]*rxa_dispatch diagnose' "${candidate}" ;;
        timeline)     grep -qE '^[[:space:]]*--rill-agent-timeline\)[[:space:]]*rxa_dispatch timeline' "${candidate}" ;;
        *) return 1 ;;
    esac
}
rxa_candidate_guard() {
    # Validates a freshly downloaded install.sh candidate before it is ever
    # allowed to replace the running script. Returns 0 only when every
    # integration anchor and the shell syntax check succeed.
    local candidate=${1:-} block rtmp rc cand_schema cap
    # Diagnostics (P1): every failure records a named stage in
    # RILL_CANDIDATE_GUARD_STAGE so callers can report exactly which phase of
    # the guard rejected the candidate instead of a generic "guard" error.
    RILL_CANDIDATE_GUARD_STAGE=""
    RILL_CANDIDATE_GUARD_RC=""
    RILL_CANDIDATE_GUARD_SHA256=""
    RILL_CANDIDATE_GUARD_VERSION=""
    if [[ ! -f "${candidate}" ]]; then
        RILL_CANDIDATE_GUARD_STAGE="path"
        return 1
    fi
    RILL_CANDIDATE_GUARD_SHA256=$(sha256sum "${candidate}" 2>/dev/null | awk '{print $1}')
    RILL_CANDIDATE_GUARD_VERSION=$(sed -n 's/^shell_version=\(['"'"'"0-9.]*\).*/\1/p' "${candidate}" | head -n1)
    if ! bash -n "${candidate}" 2>/dev/null; then
        RILL_CANDIDATE_GUARD_STAGE="syntax"
        return 1
    fi
    # P1-2: schema floor (>=, never strict equality). A missing/non-numeric
    # schema marker, or one below RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR,
    # fails closed.
    cand_schema=$(sed -n 's/^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=\([0-9][0-9]*\)$/\1/p' "${candidate}" | head -n1)
    if ! [[ "${cand_schema}" =~ ^[0-9]+$ ]]; then
        RILL_CANDIDATE_GUARD_STAGE="schema"
        return 1
    fi
    if ! (( cand_schema >= RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR )); then
        RILL_CANDIDATE_GUARD_STAGE="schema"
        return 1
    fi
    # P1-2: capability floor. Every required capability must be present as a
    # real off-line dispatch branch -- a comment or a bare string is not
    # enough. Version is irrelevant: a higher schema keeps passing as long as
    # all required capabilities are really there.
    for cap in ${RILL_XRAY_AGENT_REQUIRED_CAPABILITIES}; do
        if ! rxa_capability_present "${candidate}" "${cap}"; then
            RILL_CANDIDATE_GUARD_STAGE="capability"
            return 1
        fi
    done
    if ! grep -qE '^[[:space:]]*9\)[[:space:]]*rxa_menu' "${candidate}"; then
        RILL_CANDIDATE_GUARD_STAGE="menu-anchor"
        return 1
    fi
    if ! grep -qE '^[[:space:]]*--rill-agent-status\)[[:space:]]*rxa_dispatch' "${candidate}"; then
        RILL_CANDIDATE_GUARD_STAGE="offline-dispatch-anchor"
        return 1
    fi
    block=$(sed -n '/^# [B]EGIN RILL XRAY AGENT INTEGRATION$/,/^# [E]ND RILL XRAY AGENT INTEGRATION$/p' "${candidate}")
    if [[ -z "${block}" ]]; then
        RILL_CANDIDATE_GUARD_STAGE="semantic-probe"
        return 1
    fi
    rtmp=$(mktemp -d) || { RILL_CANDIDATE_GUARD_STAGE="probe-setup"; return 1; }
    if RILL_XRAY_AGENT_PROBE_BLOCK="${block}" RILL_XRAY_AGENT_PROBE_ROOT="${rtmp}" \
        bash -c '
set -u
rt=${RILL_XRAY_AGENT_PROBE_ROOT}
mkdir -p "${rt}/bin" "${rt}/cfgs" "${rt}/xraybin" "${rt}/nginxbin" "${rt}/logs" "${rt}/state" "${rt}/etc-rill/scripts"
# Fake host tooling: the probe must never touch the real system.
cat > "${rt}/bin/systemctl" <<EOF
#!/usr/bin/env bash
exit 0
EOF
cat > "${rt}/bin/xray" <<EOF
#!/usr/bin/env bash
[ "\${1}" = "run" ] && [ "\${2}" = "-test" ] && exit 0
exit 0
EOF
cat > "${rt}/bin/nginx" <<EOF
#!/usr/bin/env bash
[ "\${1}" = "-t" ] && exit 0
exit 0
EOF
cat > "${rt}/bin/ss" <<JEOF
#!/usr/bin/env bash
printf "LISTEN 0 4096 0.0.0.0:60000 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61000 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61001 0.0.0.0:* inet sshd\n"
printf "LISTEN 0 4096 0.0.0.0:61002 0.0.0.0:* inet sshd\n"
JEOF
# jq is NOT shadowed here -- it is a declared Bootstrap prerequisite installed
# before rxa_candidate_guard ever runs (init_package_manager -> pkg_install
# "bc,jq" on the fresh install path). The probe therefore uses the real jq on
# the throwaway files under "${rt}", which keeps python3 OUT of the candidate
# the guard dependency closure. This is fail-closed: if real jq is missing the
# probe jq calls fail and the guard rejects the candidate.
chmod +x "${rt}"/bin/*
export PATH="${rt}/bin:${PATH}"
printf "%s\n" "{\"tls\":\"TLS\",\"port\":60000,\"reality_add_nginx\":\"off\",\"ws_port\":61000,\"grpc_port\":61001,\"xhttp_port\":61002}" > "${rt}/cfgs/install_config.json"
printf "%s\n" "not json" > "${rt}/cfgs/broken.json"
cp "${rt}/bin/xray" "${rt}/xraybin/xray"
cp "${rt}/bin/nginx" "${rt}/nginxbin/nginx"
printf "%s\n" "{}" > "${rt}/cfgs/xray.json"
printf "%s\n" "{}" > "${rt}/cfgs/nginx.conf"
export RILL_XRAY_AGENT_INSTALL_CONFIG="${rt}/cfgs/install_config.json"
export RILL_XRAY_AGENT_XRAY_BIN="${rt}/xraybin/xray"
export RILL_XRAY_AGENT_XRAY_CONF="${rt}/cfgs/xray.json"
export RILL_XRAY_AGENT_NGINX_BIN="${rt}/nginxbin/nginx"
export RILL_XRAY_AGENT_NGINX_CONF="${rt}/cfgs/nginx.conf"
export RILL_XRAY_AGENT_LOG_DIR="${rt}/logs"
export RILL_XRAY_AGENT_CONFIG="${rt}/cfgs/config.json"
export RILL_XRAY_AGENT_HOME="${rt}/etc-rill"
export RILL_XRAY_AGENT_STATE="${rt}/state"
export RILL_XRAY_AGENT_MANAGER="${rt}/etc-rill/scripts/rill_xray_agent_manager.sh"
export RILL_XRAY_AGENT_STATUS="${rt}/status/xray-observation.json"
export _TEST_MODE=1
menu_pause(){ return 0; }
menu_submenu_begin(){ return 0; }
menu_row(){ return 0; }
menu_blank(){ return 0; }
menu_item(){ return 0; }
menu_footer(){ return 0; }
menu_read(){ printf -v "$1" %s 0; }
eval "${RILL_XRAY_AGENT_PROBE_BLOCK}" || exit 1
# 1) real function definitions, not comment strings.
for f in rxa_candidate_guard rxa_uninstall_prepare rxa_uninstall_commit \
         rxa_uninstall_abort rxa_uninstall_finish rxa_reconfigure_enter \
         rxa_reconfigure_leave rxa_host_healthy rxa_dispatch rxa_menu; do
    declare -F "$f" >/dev/null 2>&1 || exit 2
done
# 2) healthy host must be real, not the old any-active shortcut.
rxa_host_healthy || exit 3
# 3) unparseable config must be refused.
RILL_XRAY_AGENT_INSTALL_CONFIG="${rt}/cfgs/broken.json" rxa_host_healthy && exit 4
# 4) missing xray binary must be refused.
RILL_XRAY_AGENT_XRAY_BIN="${rt}/nonexistent" rxa_host_healthy && exit 4
# 5) offline-safe dispatch must really run and emit the observe JSON.
out=$(rxa_dispatch status) || exit 5
case "$out" in *installed*) ;; *) exit 6 ;; esac
# 6) reconfigure hooks are non-fatal with no agent state.
rxa_reconfigure_enter || exit 7
rxa_reconfigure_leave 0 || exit 7
# 7) uninstall contract: prepare no-op without Rill; commit fails safe when
#    the purge script is absent; abort keeps the host rc and finish routes 1.
rxa_uninstall_prepare || exit 8
rxa_uninstall_commit >/dev/null 2>&1 && exit 9
rxa_uninstall_finish 1 >/dev/null 2>&1
[ $? -eq 1 ] || exit 10
# 8) menu case 9 target must be a real function.
rxa_menu >/dev/null 2>&1 || exit 11
exit 0
'; then
        rc=0
        RILL_CANDIDATE_GUARD_RC="0"
    else
        rc=$?
        RILL_CANDIDATE_GUARD_RC="${rc}"
        # Map the probe's distinct exit code to a named stage so a failure is
        # diagnosable, without weakening fail-closed behavior.
        case "${rc}" in
            1) RILL_CANDIDATE_GUARD_STAGE="semantic-probe" ;;
            2) RILL_CANDIDATE_GUARD_STAGE="capability" ;;
            3|4) RILL_CANDIDATE_GUARD_STAGE="host-health" ;;
            5|6) RILL_CANDIDATE_GUARD_STAGE="offline-dispatch" ;;
            7) RILL_CANDIDATE_GUARD_STAGE="reconfigure" ;;
            8|9|10) RILL_CANDIDATE_GUARD_STAGE="uninstall" ;;
            11) RILL_CANDIDATE_GUARD_STAGE="menu-anchor" ;;
            *) RILL_CANDIDATE_GUARD_STAGE="semantic-probe" ;;
        esac
    fi
    rm -rf "${rtmp}"
    return "${rc}"
}
rxa_integration_self_check() {
    # Test-only / read-only contract self-check. Emits a JSON object that the
    # candidate guard and CI can parse. No side effects: it never installs,
    # never touches the network, and never modifies host state. The booleans
    # reflect what THIS integration block actually provides (schema marker,
    # hook functions, host health contract, two-phase uninstall). P1-2:
    # additionally reports the numeric schema and the capability floor so
    # callers can decide compatibility as schema >= floor AND every required
    # capability is really present.
    local menu=0 box=0 flow=0 cap_missing=0 cap
    local block file schema floor
    file="${BASH_SOURCE[0]:-}"
    block=$(sed -n '/^# [B]EGIN RILL XRAY AGENT INTEGRATION$/,/^# [E]ND RILL XRAY AGENT INTEGRATION$/p' "$file")
    schema=$(sed -n 's/^RILL_XRAY_AGENT_INTEGRATION_SCHEMA=\([0-9][0-9]*\)$/\1/p' "$file" | head -n1)
    floor=${RILL_XRAY_AGENT_INTEGRATION_SCHEMA_FLOOR:-${schema:-0}}
    [[ "${schema}" =~ ^[0-9]+$ ]] || schema=0
    [[ "$block" == *rxa_menu* && "$file" != "" ]] && menu=1
    grep -qE '^[[:space:]]*--rill-agent-status\)[[:space:]]*rxa_dispatch' "$file" >/dev/null 2>&1 && menu=1
    [[ "$block" == *rxa_uninstall_prepare* && "$block" == *rxa_uninstall_commit* \
       && "$block" == *rxa_uninstall_abort* && "$block" == *rxa_uninstall_finish* ]] && box=1
    [[ "$block" == *rxa_host_healthy* && "$block" == *rxa_reconfigure_enter* \
       && "$block" == *rxa_reconfigure_leave* ]] && flow=1
    for cap in ${RILL_XRAY_AGENT_REQUIRED_CAPABILITIES:-}; do
        rxa_capability_present "$file" "$cap" || cap_missing=$((cap_missing + 1))
    done
    printf '{"schemaVersion":1,"integrationSchema":%d,"integrationSchemaFloor":%d,"capabilitiesMissing":%d,"menuDispatch":%s,"offlineDispatch":%s,"reconfigureHooks":%s,"uninstallHooks":%s,"hostHealthContract":%s}\n' \
        "${schema}" \
        "${floor}" \
        "${cap_missing}" \
        "$([[ $menu -eq 1 ]] && echo true || echo false)" \
        "$([[ $menu -eq 1 ]] && echo true || echo false)" \
        "$([[ $flow -eq 1 ]] && echo true || echo false)" \
        "$([[ $box -eq 1 ]] && echo true || echo false)" \
        "$([[ $flow -eq 1 ]] && echo true || echo false)"
}
if [[ -f "$rill_xray_agent_manager" ]]; then
    source "$rill_xray_agent_manager"
else
    rxa_install_testing_confirm(){
        local answer
        printf '\n%s\n' "$(gettext "提示：Rill AI 判断引擎目前仍处于测试阶段。")"
        printf '%s\n' "$(gettext "可能存在兼容性、判断准确性或稳定性问题，不能保证完全无故障。")"
        printf '%s\n' "$(gettext "安装后默认仅启用 AI 观察模式，路由辅助保持关闭。")"
        if [[ ${RILL_XRAY_AGENT_ACCEPT_TEST_RISK:-0} == 1 ]]; then
            return 0
        fi
        printf '%s' "$(gettext "确认了解测试风险并继续安装吗？ [y/N]: ")"
        IFS= read -r answer || answer=""
        case ${answer} in
            y|Y|yes|YES|Yes|是) return 0 ;;
            *)
                printf '%s\n' "$(gettext "已取消安装。")"
                return 1
                ;;
        esac
    }
    rxa_install_bootstrap(){
        local bootstrap source_dir tmp rc=0
        source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
        for bootstrap in \
            "${scripts_dir}/rill_xray_agent_bootstrap.sh" \
            "${source_dir}/scripts/rill_xray_agent_bootstrap.sh"; do
            if [[ -f ${bootstrap} ]]; then
                if [[ -f ${source_dir}/assets/rill-xray-agent-xray-bundle.tar.gz ]]; then
                    RILL_XRAY_AGENT_BUNDLE_FILE="${source_dir}/assets/rill-xray-agent-xray-bundle.tar.gz" \
                    RILL_XRAY_AGENT_BUNDLE_SHA256="$(sha256sum "${source_dir}/assets/rill-xray-agent-xray-bundle.tar.gz" | awk '{print $1}')" \
                        bash "${bootstrap}"
                else
                    rxa_release_bundle_install "${shell_version}"
                fi
                return $?
            fi
        done
        rxa_release_bundle_install "${shell_version}"
    }
    rxa_install_with_notice(){
        rxa_install_testing_confirm || return 1
        rxa_install_bootstrap
    }
    rxa_refresh_summary(){
        RILL_XRAY_AGENT_HEADER_STATE="$(gettext "AI 判断: 未安装")"
        RILL_XRAY_AGENT_HEADER_MODE="$(gettext "工作模式: 不可用")"
        RILL_XRAY_AGENT_HEADER_RUNTIME="$(gettext "服务: 未运行")"
        RILL_XRAY_AGENT_HEADER_ROUTE="$(gettext "路由辅助: 关闭")"
    }
    rxa_menu(){
        local choice
        # Compatibility with the candidate guard shipped by older releases:
        # that isolated probe only provided menu_pause().  Returning success
        # here proves that the menu target is callable without entering an
        # endless loop on missing UI helpers.  During normal execution the
        # real menu helpers are defined before this function is invoked.
        declare -F menu_submenu_begin >/dev/null 2>&1 || return 0
        while true; do
            menu_submenu_begin "$(gettext "Rill Xray AI 运维助手")"
            menu_row "$(gettext "AI 判断引擎尚未安装")"
            menu_blank
            menu_item 1 "$(gettext "安装 AI 判断引擎")"
            menu_blank
            menu_item 0 "$(gettext "返回")"
            menu_footer
            menu_read choice 1
            case ${choice} in
                0) return ;;
                1)
                    if rxa_dispatch install; then
                        if [[ -f ${rill_xray_agent_manager} ]]; then
                            # shellcheck source=/dev/null
                            source "${rill_xray_agent_manager}"
                        fi
                        menu_pause
                        return
                    fi
                    echo "$(gettext "Rill AI 判断引擎安装失败，请检查上方错误信息。")" >&2
                    menu_pause
                    ;;
            esac
        done
    }
    rxa_dispatch(){ case "${1:-}" in status) printf '%s\n' '{"installed":false,"routeAssistEnabled":false,"boundedAutoAllowed":false}' ;; install) rxa_install_with_notice ;; *) return 66 ;; esac; }
fi
# COMPAT: Rill is optional, and older managers may omit this UI-only helper.
# Keep the base menu renderable without an installed/current manager; remove
# once the no-manager menu no longer calls it and all supported managers
# provide it.
if ! declare -F rxa_health_label >/dev/null 2>&1; then
    rxa_health_label() { printf '%s\n' "$(gettext "检测：Rill 组件版本较旧，请更新")"; }
fi
# COMPAT_END
# Lifecycle coordination used by the host install/update/uninstall paths.
# Every hook is non-fatal: it never changes the host transaction return code.
# Paths honour RILL_XRAY_AGENT_* + DESTDIR (same sandbox semantics as the
# agent scripts) so confirm tests and _TEST_MODE runs never touch /etc,/var.
rxa_root() { printf '%s%s' "${DESTDIR:-}" "$1"; }
rxa_agent_dir(){ printf '%s%s' "${DESTDIR:-}" "${RILL_XRAY_AGENT_HOME:-/etc/rill-xray-agent}"; }
rxa_observe_out(){ printf '%s%s' "${DESTDIR:-}" "${RILL_XRAY_AGENT_STATUS:-/var/lib/rill-xray-agent-xray/status/xray-observation.json}"; }
rxa_reconfigure_enter() {
    local cfg mode
    cfg=${RILL_XRAY_AGENT_CONFIG:-/etc/rill-xray-agent/config.json}
    command -v rxa_get >/dev/null 2>&1 || return 0
    [[ -f "$cfg" ]] || return 0
    mode=$(rxa_get mode 2>/dev/null || printf 'observe-only')
    printf '%s' "$mode" >"${cfg}.prior-mode" 2>/dev/null || true
    rxa_apply_mode observe-only >/dev/null 2>&1 || true
}
rxa_reconfigure_leave() {
    # Reconfigure transaction end. Only a clean host transaction (rc==0) that
    # passes the FULL mode-aware host health check may restore the prior mode.
    # On any health failure the agent stays observe-only, diagnostics are
    # refreshed, and the failure is recorded (the host tx return code itself
    # is untouched: this hook stays non-fatal for the enclosing function).
    local rc=${1:-1} cfg mode
    cfg=${RILL_XRAY_AGENT_CONFIG:-/etc/rill-xray-agent/config.json}
    mode=$(cat "${cfg}.prior-mode" 2>/dev/null || printf 'observe-only')
    rm -f "${cfg}.prior-mode"
    if [[ "$rc" == 0 ]] && rxa_host_healthy; then
        rxa_apply_mode "$mode" >/dev/null 2>&1 || true
        RILL_XRAY_AGENT_OUTPUT="$(rxa_observe_out)" \
            bash "$(rxa_agent_dir)/scripts/rill_xray_agent_observe.py" >/dev/null 2>&1 || true
        return 0
    fi
    if [[ "$rc" == 0 ]]; then
        echo 'Rill 检测到 Xray 运行状态异常，已保持 AI 观察模式' >&2
        RILL_XRAY_AGENT_OUTPUT="$(rxa_observe_out)" \
            bash "$(rxa_agent_dir)/scripts/rill_xray_agent_observe.py" >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}
rxa_host_healthy() {
    # Mode-aware host health check. The required components are derived only
    # from install_config.json and the active install mode. Returns 0 only
    # when every required component is verifiably healthy. Untestable states
    # (systemctl/binary/config missing, config unparseable) are NEVER
    # "healthy": they return 1. Modes that do not require Nginx must not
    # require it here.
    local cfg="${RILL_XRAY_AGENT_INSTALL_CONFIG:-${xray_install_config_file:-}}"
    local xray_bin="${RILL_XRAY_AGENT_XRAY_BIN:-${xray_bin_dir:-}/xray}"
    local xray_cfg="${RILL_XRAY_AGENT_XRAY_CONF:-${xray_conf:-}}"
    local nginx_bin="${RILL_XRAY_AGENT_NGINX_BIN:-${nginx_dir:-}/sbin/nginx}"
    local nginx_cfg="${RILL_XRAY_AGENT_NGINX_CONF:-${nginx_main_conf:-/usr/local/nginx/conf/nginx.conf}}"
    local logs="${RILL_XRAY_AGENT_LOG_DIR:-/etc/idleleo/logs}"
    local json tls reality nginx_required=0 mark port
    local fake_active fake_listen
    # Test-only health shim (used only by CI sandbox tests, never set by
    # production callers): when FAKE_ACTIVE/FAKE_LISTEN are non-empty the
    # unit-activity and port-listening probes read from those env vars
    # instead of the live system. Real systems keep the full checks.
    fake_active=${FAKE_ACTIVE:-}
    fake_listen=${FAKE_LISTEN:-}
    _rxa_active() { [[ -z "$fake_active" ]] && { systemctl -q is-active "$1" 2>/dev/null; return; }
                    case " $fake_active " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
    _rxa_listening() { [[ -z "$fake_listen" ]] && { ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${1}\$"; return; }
                    case " $fake_listen " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
    command -v systemctl >/dev/null 2>&1 || return 1
    [[ -n "$cfg" && -f "$cfg" ]] || return 1
    json=$(jq -c . "$cfg" 2>/dev/null) || return 1
    tls=$(printf '%s' "$json" | jq -r '.tls // empty' 2>/dev/null)
    reality=$(printf '%s' "$json" | jq -r '.reality_add_nginx // empty' 2>/dev/null)
    [[ "$tls" == "TLS" || "$reality" == "on" ]] && nginx_required=1
    [[ -x "$xray_bin" ]] || return 1
    [[ -f "$xray_cfg" ]] || return 1
    "$xray_bin" run -test -config "$xray_cfg" >/dev/null 2>&1 || return 1
    _rxa_active xray || return 1
    port=$(printf '%s' "$json" | jq -r '.port // empty' 2>/dev/null)
    if [[ -n "$port" && "$port" != "null" ]]; then
        if ! _rxa_listening "$port"; then
            echo "Rill 检测到 Xray 端口 ${port} 未监听" >&2
            return 1
        fi
    fi
    for mark in update_failed.mark restore_failed.mark rollback_unverified.mark; do
        [[ -f "${logs}/${mark}" ]] && return 1
    done
    if (( nginx_required )); then
        [[ -x "$nginx_bin" ]] || return 1
        "$nginx_bin" -t -c "$nginx_cfg" >/dev/null 2>&1 || return 1
        _rxa_active nginx || return 1
        for port in ws_port grpc_port xhttp_port; do
            port=$(printf '%s' "$json" | jq -r --arg k "$port" '.[$k] // empty' 2>/dev/null)
            if [[ -n "$port" && "$port" != "null" ]]; then
                if ! _rxa_listening "$port"; then
                    echo "Rill 检测到 Nginx 端口 ${port} 未监听" >&2
                    return 1
                fi
            fi
        done
    fi
    return 0
}
rxa_host_post_verify() {
    # Host-uninstall post-verify: called after the host removal phase and
    # before commit. Returns 0 only when the host components are actually
    # gone. xray must be inactive and its binary removed; when nginx was
    # installed (nginx_dir present) nginx must be inactive and its binary
    # removed. Host-owned config retention is a user choice handled by the
    # caller; this function only checks what must be removed.
    local xray_bin="${RILL_XRAY_AGENT_XRAY_BIN:-${xray_bin_dir:-}/xray}"
    local nginx_bin="${RILL_XRAY_AGENT_NGINX_BIN:-${nginx_dir:-}/sbin/nginx}"
    if systemctl -q is-active xray 2>/dev/null; then
        echo 'Rill 卸载后校验失败：Xray 服务仍在运行' >&2
        return 1
    fi
    if [[ -e "${xray_bin}" ]]; then
        echo 'Rill 卸载后校验失败：Xray 程序文件仍然存在' >&2
        return 1
    fi
    if [[ -n "${nginx_dir:-}" && -d "${nginx_dir}" ]]; then
        if systemctl -q is-active nginx 2>/dev/null; then
            echo 'Rill 卸载后校验失败：Nginx 服务仍在运行' >&2
            return 1
        fi
        if [[ -e "${nginx_bin}" ]]; then
            echo 'Rill 卸载后校验失败：Nginx 程序文件仍然存在' >&2
            return 1
        fi
    fi
    return 0
}
rxa_uninstall_prepare() {
    # Two-phase uninstall, phase 1: freeze agent in observe-only, refresh the
    # observation and persist a DURABLE uninstall intent. Fail-closed: a mode
    # convergence failure OR a non-durable intent write returns non-zero, and
    # the host uninstall MUST NOT begin. Rill may be absent -> explicit no-op.
    command -v rxa_apply_mode >/dev/null 2>&1 || return 0
    local home="$(rxa_agent_dir)"
    [[ -f "${home}/config.json" ]] || return 0
    rxa_apply_mode observe-only >/dev/null 2>&1 || return 1
    RILL_XRAY_AGENT_OUTPUT="$(rxa_observe_out)" \
        bash "${home}/scripts/rill_xray_agent_observe.py" >/dev/null 2>&1 || true
    rxa_write_uninstall_intent_atomic prepared replace \
        || { echo 'Rill 无法可靠记录卸载准备状态，已中止卸载' >&2; return 1; }
    return 0
}
rxa_uninstall_commit() {
    # Two-phase uninstall, phase 2: only after the host uninstall fully
    # succeeded. The committed marker MUST be durable BEFORE the Rill purge:
    # a marker-write failure stops here with non-zero and diagnostics are
    # NOT purged; purge failure also returns non-zero.
    rxa_write_uninstall_intent_atomic committed append \
        || { echo 'Rill 无法可靠记录卸载完成状态，已中止清理' >&2; return 1; }
    local pf=0 uninstall_script
    uninstall_script="$(rxa_agent_dir)/scripts/rill_xray_agent_uninstall.sh"
    # Candidate guards deliberately omit the purge script to prove this path
    # fails closed.  Detect that fixture explicitly so an expected probe
    # failure is not presented to users as a real uninstall attempt.
    if [[ ! -f "${uninstall_script}" ]]; then
        [[ ${_TEST_MODE:-0} == 1 ]] || echo 'Rill 清理脚本不存在，卸载尚未完成' >&2
        return 1
    fi
    bash "${uninstall_script}" --purge || pf=$?
    if [[ "$pf" != 0 ]]; then
        echo 'Rill 清理失败，卸载尚未完成' >&2
        return 1
    fi
    return 0
}
rxa_write_uninstall_intent_atomic() {
    # Durable uninstall intent writer, phase-aware: prepared/committed/aborted
    # ALL pass through this single primitive. Same algorithm as the standalone
    # script: mkdir -> same-directory temp file -> fsync(file) -> chmod ->
    # atomic os.replace -> fsync(parent directory). Fail-closed: ANY failure
    # returns non-zero; a marker that is not durable must never be treated as
    # written.
    #   $1 = phase (prepared|committed|aborted)
    #   $2 = append|replace (committed/aborted append to the prepared ledger)
    local phase="${1:-}" mode="${2:-replace}"
    local dir dest
    dir="$(rxa_root "${RILL_XRAY_AGENT_STATE:-/var/lib/rill-xray-agent-runtime}")"
    dest="${dir}/uninstall.intent.json"
    install -d -m 0750 "${dir}" 2>/dev/null || return 1
    python3 - "$phase" "$mode" "$dir" "$dest" <<'PY' || return 1
import os,sys,tempfile,time
phase,mode,d,dest=sys.argv[1:]
fd,tmp=tempfile.mkstemp(prefix='.uninstall.intent.',dir=d)
try:
    with os.fdopen(fd,'w') as out:
        if mode=='append':
            try:
                with open(dest,'rb') as existing:
                    out.write(existing.read().decode('utf-8','replace'))
            except OSError:
                pass
        out.write('{"schemaVersion":1,"intent":"uninstall","phase":"%s","atEpochSeconds":%d}\n'
                  % (phase,int(time.time())))
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp,0o640)
    os.replace(tmp,dest)
    dfd=os.open(d,os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    sys.exit(1)
PY
}
rxa_uninstall_abort() {
    # Host uninstall failed: keep Runtime, audit, config and observation;
    # try to persist the aborted marker, but the abort-marker write failure
    # must NEVER turn a host failure into success: the original failure code
    # is always returned.
    rxa_write_uninstall_intent_atomic aborted append 2>/dev/null || echo \
        'Rill 无法可靠记录卸载中止状态' >&2
    [[ ${_TEST_MODE:-0} == 1 ]] || \
        echo 'Xray 主程序卸载失败；已保留 Rill AI 判断记录与诊断数据' >&2
    return 1
}
rxa_uninstall_finish() {
    # Called by uninstall_all() with the accumulated host phase rc. 0 routes
    # to commit (purge), anything else aborts and keeps all diagnostics.
    local rc=${1:-1}
    if [[ "$rc" == 0 ]]; then
        rxa_uninstall_commit
    else
        rxa_uninstall_abort
        return 1
    fi
}
# END RILL XRAY AGENT INTEGRATION

download_file() {
    local url="$1"
    local dest_file="$2"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]]; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
}

download_script_file() {
    local url="$1"
    local dest_file="$2"
    local syntax_shell="${3:-bash}"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]] || ! "${syntax_shell}" -n "${tmp_file}" 2>/dev/null; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
    chmod +x "${dest_file}"
}

download_json_file() {
    local url="$1"
    local dest_file="$2"
    local tmp_file="${dest_file}.tmp.$$"

    mkdir -p "$(dirname "${dest_file}")"
    rm -f "${tmp_file}"
    if ! curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 -o "${tmp_file}" "$url"; then
        rm -f "${tmp_file}"
        return 1
    fi
    if [[ ! -s "${tmp_file}" ]] || ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${dest_file}"
}

# Install or refresh the read-only stats helper from the current Release.
# The helper is optional for the install itself: any download/hash/syntax
# failure only disables stats readout, never the stats enable/disable path.
xray_stats_script_ensure() {
    local force="${1:-0}"
    local dest="${xray_stats_script}"
    if [[ -f "${dest}" && "${force}" != "1" ]]; then
        return 0
    fi

    mkdir -p "${scripts_dir}" || return 1
    local manifest asset expected actual
    manifest=$(mktemp "${TMPDIR:-/tmp}/xray-stats-manifest.XXXXXX" 2>/dev/null) || return 1
    asset=$(mktemp "${TMPDIR:-/tmp}/xray-stats-asset.XXXXXX" 2>/dev/null) || {
        rm -f "${manifest}"
        return 1
    }
    local base
    base=$(shell_release_asset_url "${shell_version}" '')
    base=${base%/}
    if ! download_json_file "${base}/release-manifest.json" "${manifest}"; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    expected=$(jq -r '.statsScriptSha256 // empty' "${manifest}" 2>/dev/null) || {
        rm -f "${manifest}" "${asset}"
        return 1
    }
    if [[ ! "${expected}" =~ ^[0-9a-f]{64}$ ]]; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    if ! download_script_file "$(shell_release_asset_url "${shell_version}" "xray_stats.sh")" "${asset}"; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    actual=$(sha256sum "${asset}" 2>/dev/null | awk '{print $1}')
    if [[ "${actual}" != "${expected}" ]]; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    if ! chmod 600 "${asset}" || ! chown root:root "${asset}" 2>/dev/null; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    if ! mv -f "${asset}" "${dest}"; then
        rm -f "${manifest}" "${asset}"
        return 1
    fi
    rm -f "${manifest}"
    return 0
}

xray_install_release() {
    local installer="${idleleo_dir}/tmp/xray-install-release.sh"
    local installer_url installer_sha actual
    local ret

    if ! verified_installer_metadata_valid; then
        log_echo "${Error} ${RedBG} Xray-install verified metadata is missing or invalid; refusing mutable fallback ${Font}" >&2
        return 1
    fi
    installer_url=$(xray_installer_url) || return 1
    installer_sha=${xray_installer_sha256}
    if ! download_script_file "$installer_url" "$installer"; then
        return 1
    fi
    actual=$(sha256sum "${installer}" 2>/dev/null | awk '{print $1}')
    if [[ "${actual}" != "${installer_sha}" ]]; then
        rm -f "${installer}"
        log_echo "${Error} ${RedBG} Xray-install SHA256 mismatch; refusing candidate ${Font}" >&2
        return 1
    fi
    if ! bash -n "${installer}" 2>/dev/null; then
        rm -f "${installer}"
        return 1
    fi
    bash "$installer" "$@"
    ret=$?
    rm -f "$installer"
    return "$ret"
}

get_public_ip() {
    local ip_version="$1"
    if [[ "${ip_version}" == "IPv6" ]]; then
        curl -6 -fsSL --max-time 10 ip.me 2>/dev/null || curl -6 -fsSL --max-time 10 ip.im 2>/dev/null
    else
        curl -4 -fsSL --max-time 10 ip.me 2>/dev/null || curl -4 -fsSL --max-time 10 ip.im 2>/dev/null
    fi
}

# ---- IPv4 / IPv6 双栈支持：网络能力检测与 URI 编码辅助 ----

# 返回 IPv4/IPv6 literal 的规范化（canonical）形式，非法输入返回空并 exit 1。
# 使用 Python stdlib ipaddress 做严格校验与压缩：
#   - IPv4 校验每个 octet 0-255（拒绝 999.999.999.999）
#   - IPv6 校验为合法地址（拒绝 1:2 / :::: / 2001:db8:0:1）
#   - 压缩形式：2001:db8::1 与 2001:0db8:0:0:0:0:0:1 归一化为同一字符串
# 兼容裸地址与 [ ] 包裹形式。python3 为脚本已声明的基础依赖。
normalize_ip_literal() {
    local input="$1"
    [[ -z "${input}" ]] && return 1
    python3 -c 'import ipaddress, sys
try:
    print(ipaddress.ip_address(sys.argv[1].strip().strip("[]")).compressed)
except Exception:
    sys.exit(1)' "${input}" 2>/dev/null
}

# 判断是否为 IPv6 literal（兼容裸地址与 [ ] 包裹形式），严格校验。
is_ipv6_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}

# 判断是否为 IPv4 literal，严格校验每个 octet 0-255。
is_ipv4_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *.* && "${candidate}" != *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}

# 将 client authority 中的 host 规范化：
#   - IPv6 literal -> 强制 [IPv6]（已带括号不重复加）
#   - IPv4 / 域名  -> 原样返回
format_uri_authority_host() {
    local input="$1"
    if is_ipv6_literal "${input}"; then
        local bare="${input#[}"
        bare="${bare%\]}"
        echo "[${bare}]"
    else
        echo "${input}"
    fi
}

# YAML 标量安全引用：IPv6 literal 因含冒号，统一加单引号避免解析歧义；
# 其余值原样返回（域名/IPv4 无需引用）。
yaml_quote_scalar() {
    local value="$1"
    if is_ipv6_literal "${value}"; then
        echo "'${value}'"
    else
        echo "${value}"
    fi
}

# 探测本机公网 IPv4/IPv6 出口能力，回填全局 network_mode / ipv4_address / ipv6_address。
# 注意：仅当出口探测成功才算某 family 可用，不依赖网卡上是否有地址。
detect_public_network_capabilities() {
    ipv4_address=$(get_public_ip "IPv4")
    ipv6_address=$(get_public_ip "IPv6")
    if [[ -n "${ipv4_address}" && -n "${ipv6_address}" ]]; then
        network_mode="dual"
    elif [[ -n "${ipv4_address}" ]]; then
        network_mode="ipv4"
    elif [[ -n "${ipv6_address}" ]]; then
        network_mode="ipv6"
    else
        network_mode="none"
    fi
}

# 将 resolve_domain_ips 输出按 family 分类，回填 resolved_ipv4s / resolved_ipv6s（\n 分隔）
classify_resolved_ips() {
    local input="$1" ip
    resolved_ipv4s=""
    resolved_ipv6s=""
    while IFS= read -r ip; do
        [[ -z "${ip}" ]] && continue
        if is_ipv6_literal "${ip}"; then
            resolved_ipv6s="${resolved_ipv6s}${ip}\n"
        elif is_ipv4_literal "${ip}"; then
            resolved_ipv4s="${resolved_ipv4s}${ip}\n"
        fi
    done <<<"${input}"
}

# 从老字段推断 network_mode（向后兼容，不在读取时强制重写 JSON）
infer_network_mode_from_config() {
    local ipv="$1"
    case "${ipv}" in
        IPv4) echo "ipv4" ;;
        IPv6) echo "ipv6" ;;
        *) echo "manual" ;;
    esac
}

# 从配置读取网络能力状态，回填全局变量。优先使用新字段，缺失时由老字段推断。
load_network_capabilities_from_config() {
    local nm ipv4 ipv6 ipv
    nm=$(info_extraction network_mode)
    ipv4=$(info_extraction ipv4_address)
    ipv6=$(info_extraction ipv6_address)
    ipv=$(info_extraction ip_version)
    if [[ -n "${nm}" ]]; then
        network_mode="${nm}"
    else
        network_mode=$(infer_network_mode_from_config "${ipv}")
    fi
    ipv4_address="${ipv4:-}"
    ipv6_address="${ipv6:-}"
}

# 在“读取现有安装状态”语义下恢复双栈 runtime globals。
# fresh process（脚本退出后重新执行 --show / 菜单 / 查看用户等）必须以安装配置为
# 依据恢复 network_mode/ipv4_address/ipv6_address，否则 install_link_image 等
# 依赖双栈状态的入口会因 globals 为空而丢失 IPv6 分享链接。
# 仅在 globals 尚未加载时 hydrate，绝不覆盖安装向导/模式切换中正在编辑的内存值。
ensure_network_runtime_state() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    [[ -n "${network_mode:-}" ]] && return 0
    load_network_capabilities_from_config
}

generate_random_port() {
    local min="$1"
    local max="$2"
    local exclude_ports="${3:-}"
    local port
    while true; do
        port=$((RANDOM % (max - min + 1) + min))
        local is_excluded=0
        for ep in ${exclude_ports}; do
            [[ "${port}" == "${ep}" ]] && is_excluded=1 && break
        done
        [[ ${is_excluded} -eq 0 ]] && echo "${port}" && return
    done
}

source '/etc/os-release'

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

# Wait for apt/dpkg locks to be released instead of deleting them.
# Waits up to $1 seconds (default 60) for the dpkg lock to become available.
# Shows the process holding the lock if it remains held.
# Returns 0 if the lock is available (or was acquired), 1 on timeout.
# NEVER deletes lock files that are held by a running process — that corrupts
# the package database.
# True if any process still has a given path open (POSIX/fcntl lock holder).
# Pure-shell scan of /proc so the apt/dpkg lock wait needs NO pre-bootstrap
# dependency (fuser/lsof no longer required before the Bootstrap contract).
_proc_fd_path_held() {
    local f="$1" fd target
    for fd in /proc/[0-9]*/fd/*; do
        [[ -e "${fd}" ]] || continue
        target=$(readlink "${fd}" 2>/dev/null) || continue
        [[ "${target}" == "${f}" ]] && return 0
    done
    return 1
}
# Best-effort holder listing for diagnostics. Prefers fuser/lsof when present,
# otherwise falls back to the pure /proc scan. Never installs anything.
_lock_holder_labels() {
    local f="$1" p
    if command -v fuser >/dev/null 2>&1; then
        fuser "${f}" 2>&1 || true
    elif command -v lsof >/dev/null 2>&1; then
        lsof "${f}" 2>/dev/null || true
    else
        for p in /proc/[0-9]*; do
            [[ -d "${p}" ]] || continue
            if readlink "${p}/fd/"* 2>/dev/null | grep -qx "${f}"; then
                printf '%s ' "${p##*/}"
            fi
        done
    fi
}

wait_for_apt_lock() {
    local timeout="${1:-60}"
    local elapsed=0
    local lock_files=(
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/apt/lists/lock"
        "/var/cache/apt/archives/lock"
    )
    if [[ -n "${APT_LOCK_FILES:-}" ]]; then
        read -r -a lock_files <<< "${APT_LOCK_FILES}"
    fi

    # apt/dpkg use POSIX/fcntl locks; flock(1) uses a different lock class and
    # can incorrectly report those files as free. Inspect actual holders via a
    # pure-shell /proc scan so no pre-bootstrap tool (fuser/lsof) is required.
    while [[ ${elapsed} -lt ${timeout} ]]; do
        local locked=0
        for lock_file in "${lock_files[@]}"; do
            [[ ! -e "${lock_file}" ]] && continue
            if _proc_fd_path_held "${lock_file}"; then
                locked=1
                break
            fi
        done

        if [[ ${locked} -eq 0 ]]; then
            return 0
        fi

        if [[ $((elapsed % 10)) -eq 0 && ${elapsed} -gt 0 ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "等待 apt/dpkg 锁释放") (${elapsed}/${timeout}s) ${Font}"
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    # Timeout reached — show holders and fail.
    log_echo "${Error} ${RedBG} $(gettext "等待 apt/dpkg 锁超时") ${Font}"
    for lock_file in "${lock_files[@]}"; do
        [[ ! -e "${lock_file}" ]] && continue
        local holders
        holders=$(_lock_holder_labels "${lock_file}")
        if [[ -n "${holders}" ]]; then
            log_echo "${Error} ${lock_file}: ${holders} ${Font}"
        fi
    done
    return 1
}

# RPM-family abstraction. Debian-family pkg logic must never see an RPM family.
is_rpm_family() {
    case "${ID:-}" in
        centos|rocky|almalinux) return 0 ;;
        *) return 1 ;;
    esac
}

# P1-8: single source of truth for the root user's crontab file. RPM family
# uses /var/spool/cron/root; Debian family uses /var/spool/cron/crontabs/root.
# Never hard-code this path anywhere else.
root_crontab_path() {
    if is_rpm_family; then
        printf '%s' "/var/spool/cron/root"
    else
        printf '%s' "/var/spool/cron/crontabs/root"
    fi
}

# Select the RPM package manager by what is actually present rather than a
# hard-coded alias (yum on modern RHEL-family releases is only a dnf shim, and
# the prompt's own Bootstrap audit forbids assuming an alias exists). Pure and
# read-only: never installs and never touches the network. Falls back to yum so
# older CentOS/Rocky/AlmaLinux keep working.
rpm_package_manager() {
    if command -v dnf >/dev/null 2>&1; then
        printf '%s' 'dnf'
    else
        printf '%s' 'yum'
    fi
}

init_package_manager() {
    # Pure/read-only: only selects INS from os-release. Never installs, never
    # touches the network. Deferred system validation happens in check_system.
    if is_rpm_family; then
        INS="$(rpm_package_manager)"
    else
        INS="apt"
    fi
}

# P1-7: pure supported-OS validation. Reads /etc/os-release ONLY (already
# sourced at top level); never installs a package, never touches the network,
# never writes /etc. Returns non-zero for unsupported distros so
# ONLINE_ROOT_MUTATION stops BEFORE apt update / dnf makecache / pkg install /
# GitHub curl / mkdir /etc/idleleo. Must be idempotent and safe to re-run.
validate_supported_system() {
    if is_rpm_family; then
        # RPM family (centos/rocky/almalinux): accepted at major version >= 10,
        # matching check_system()'s actual support condition.
        local major="${VERSION_ID%%.*}"
        if [[ "${major}" =~ ^[0-9]+$ ]] && [[ "${major}" -ge 10 ]]; then
            return 0
        fi
    fi
    local major
    case "${ID:-}" in
        debian)
            major="${VERSION_ID%%.*}"
            if [[ "${major}" =~ ^[0-9]+$ ]] && [[ "${major}" -ge 12 ]]; then
                return 0
            fi
            ;;
        ubuntu)
            major="${VERSION_ID%%.*}"
            if [[ "${major}" =~ ^[0-9]+$ ]] && [[ "${major}" -ge 24 ]]; then
                return 0
            fi
            ;;
    esac
    log_echo "${Error} ${RedBG} unsupported_system: ${ID:-unknown} ${VERSION_ID:-unknown} ${Font}"
    return 1
}

check_system() {
    if is_rpm_family && [[ ${VERSION_ID%%.*} -ge 10 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} ${VERSION} ${Font}"
        INS="$(rpm_package_manager)"
        # P0: mandatory package metadata refresh must not swallow failure.
        if [[ ! -f "${xray_install_config_file}" ]]; then
            $INS update || {
                log_echo "${Error} ${RedBG} $(gettext "软件源更新失败") ${Font}"
                exit 1
            }
        fi
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 12 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_install_config_file}" ]]; then
            wait_for_apt_lock 60 || exit 1
            dpkg --configure -a || exit 1
            $INS update || exit 1
        fi
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 24 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前系统为") Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        if [[ ! -f "${xray_install_config_file}" ]]; then
            # Wait for apt/dpkg locks instead of deleting them.
            # Deleting locks that are held by a running process corrupts the
            # package database and can leave the system in an unrecoverable state.
            if ! wait_for_apt_lock 60; then
                log_echo "${Error} ${RedBG} $(gettext "apt/dpkg 锁等待超时, 请稍后重试或手动检查占用进程") ${Font}"
                exit 1
            fi
            # Configure any interrupted packages — safe now that we hold the lock.
            dpkg --configure -a || exit 1
            $INS update || exit 1
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前系统为") ${ID} ${VERSION_ID} $(gettext "不在支持的系统列表内, 安装中断")! ${Font}"
        exit 1
    fi
}

is_root() {
    if [[ 0 == $UID ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "当前用户是 root 用户, 开始安装") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "当前用户不是 root 用户, 请切换到 root 用户后重新运行脚本")! ${Font}"
        exit 1
    fi
}

check_and_create_user_group() {
    if ! getent group nogroup > /dev/null; then
        groupadd nogroup
    fi

    if ! id nobody > /dev/null 2>&1; then
        useradd -r -g nogroup -s /sbin/nologin -c "Unprivileged User" nobody
    fi
}

check_language_update() {
    local lang_code="$1"
    local local_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/xray_install.mo"
    local version_file_url="${shell_release_raw_base}/i18n/languages/${lang_code}/LC_MESSAGES/version"

    [[ ! -f "${local_file}" ]] && return 0

    local remote_version
    remote_version=$(curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 1 "${version_file_url}" 2>/dev/null || echo "")

    if [ -z "$remote_version" ]; then
        log_echo "${Warning} ${YellowBG} $(gettext "无法获取远程语言文件信息") ${Font}"
        return 1
    fi

    local local_version
    local_version=$(cat "${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/version" 2>/dev/null || echo "")

    [ "$remote_version" != "$local_version" ]
}

update_language_file() {
    local lang_code="$1"
    local mo_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/xray_install.mo"
    local version_file="${idleleo_dir}/languages/${lang_code}/LC_MESSAGES/version"
    local github_url="${shell_release_raw_base}/i18n/languages"

    mkdir -p "${idleleo_dir}/languages/${lang_code}/LC_MESSAGES"

    log_echo "${Info} ${Green} $(gettext "正在更新语言文件")... ${Font}"

    if ! download_file "${github_url}/${lang_code}/LC_MESSAGES/xray_install.mo" "${mo_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件更新失败") ${Font}"
        return 1
    fi

    if [ ! -s "${mo_file}" ]; then
        log_echo "${Error} ${RedBG} $(gettext "语言文件无效") ${Font}"
        rm -f "${mo_file}"
        return 1
    fi

    if ! download_file "${github_url}/${lang_code}/LC_MESSAGES/version" "${version_file}"; then
        log_echo "${Error} ${RedBG} $(gettext "版本文件更新失败") ${Font}"
        return 1
    fi

    find "${idleleo_dir}/languages" -type d -exec chmod 755 {} \;
    find "${idleleo_dir}/languages" -type f -exec chmod 644 {} \;

    log_echo "${OK} ${Green} $(gettext "语言文件更新") $(gettext "完成") ${Font}"
}

# Safely read language.conf without sourcing it as a shell script.
# Only LANG= and LC_MESSAGES= assignments are parsed. The function rejects:
#   - command substitution ($(...), `...`)
#   - shell metacharacters (;, &&, ||, |, <, >, &)
#   - unknown keys (anything other than LANG or LC_MESSAGES)
#   - values that don't match the locale name pattern ([a-zA-Z0-9_.@-]+)
# Returns 0 if the file was parsed (even partially), 1 on fatal error.
safe_source_language_conf() {
    local conf_file="$1"

    if [[ -z "${conf_file}" || ! -f "${conf_file}" ]]; then
        return 1
    fi

    # Read the file line by line. This avoids any shell interpretation.
    local line key value
    local parsed_lang=""
    local parsed_lc_messages=""
    local invalid=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Skip empty lines and comments.
        line="${line#"${line%%[![:space:]]*}"}"  # trim leading whitespace
        [[ -z "${line}" || "${line}" == \#* ]] && continue

        # Reject lines that contain shell metacharacters or command substitution.
        if [[ "${line}" == *'$('* || "${line}" == *'`'* || "${line}" == *';'* || \
              "${line}" == *'&&'* || "${line}" == *'||'* || "${line}" == *'|'* || \
              "${line}" == *'<'* || "${line}" == *'>'* || "${line}" == *'&'* ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 包含可疑字符, 跳过该行"): ${line} ${Font}"
            invalid=1
            continue
        fi

        # Parse KEY=value without evaluating shell syntax. Bash's ERE engine
        # does not portably support the back-reference previously used here.
        if [[ "${line}" != *=* ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 行格式无效, 跳过"): ${line} ${Font}"
            invalid=1
            continue
        fi
        key="${line%%=*}"
        value="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        case "${value}" in
            \"*\")
                value="${value#\"}"
                value="${value%\"}"
                ;;
            \'*\')
                value="${value#\'}"
                value="${value%\'}"
                ;;
        esac
        if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 键格式无效, 跳过"): ${key} ${Font}"
            invalid=1
            continue
        fi

        # Allowlist: only LANG and LC_MESSAGES are permitted.
        case "${key}" in
            LANG|LC_MESSAGES)
                # Validate value: only locale characters (letters, digits, _ . @ -).
                if [[ ! "${value}" =~ ^[A-Za-z0-9_.@-]+$ ]]; then
                    log_echo "${Warning} ${YellowBG} $(gettext "language.conf 值包含非法字符, 跳过"): ${key}=${value} ${Font}"
                    invalid=1
                    continue
                fi
                if [[ "${key}" == "LANG" ]]; then
                    parsed_lang="${value}"
                else
                    parsed_lc_messages="${value}"
                fi
                ;;
            *)
                log_echo "${Warning} ${YellowBG} $(gettext "language.conf 未知键, 跳过"): ${key} ${Font}"
                invalid=1
                continue
                ;;
        esac
    done < "${conf_file}"

    # Reject the complete file rather than partially applying a mixed
    # valid/malicious payload.
    [[ ${invalid} -eq 0 ]] || return 1
    # Minimal images usually lack en_US.UTF-8/ru_RU.UTF-8; bash would print a
    # setlocale warning even though the catalog lookup no longer needs it.
    [[ -n "${parsed_lang}" ]] && export LANG="${parsed_lang}" 2>/dev/null
    [[ -n "${parsed_lc_messages}" ]] && export LC_MESSAGES="${parsed_lc_messages}" 2>/dev/null
    return 0
}

init_language() {
    # mode:
    #   online  - full behavior: may install gettext, may refresh translations
    #             (network) and may create ${idleleo_dir}/languages. Used only
    #             after INS is initialized and on an allowed-online mutation
    #             path, so gettext is never installed before the package
    #             manager is known (P0 bootstrap ordering fix).
    #   offline - local-only: sources gettext.sh if already present, reads the
    #             local language.conf, uses an existing .mo when available, and
    #             otherwise falls back to the default (Chinese) language.
    #             NEVER installs packages, NEVER touches the network, and never
    #             creates the /etc idleleo languages directory. Used before the
    #             offline-safe command dispatch so those commands stay truly
    #             offline-safe.
    local mode="${1:-online}"
    local allow_online=0
    [[ "${mode}" == "online" ]] && allow_online=1
    # P1-3: detect a real gettext executable (type -P), NOT command -v, so the
    # in-script gettext() fallback function is never mistaken for an install.
    if ! has_gettext_binary; then
        if [[ ${allow_online} -eq 1 ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "正在安装") gettext... ${Font}"
            if ! pkg_install "gettext"; then
                log_echo "${Error} ${RedBG} gettext $(gettext "安装") $(gettext "失败"), $(gettext "将使用默认语言") ${Font}"
                unset LANG
                unset LC_MESSAGES
                return 1
            fi
        else
            # offline + missing gettext: no install, fall back to default language
            unset LANG
            unset LC_MESSAGES
            return 1
        fi
    fi

    local gettext_paths=(
        "/usr/share/gettext/gettext.sh"
        "/usr/local/share/gettext/gettext.sh"
        "/usr/bin/gettext.sh"
        "/usr/local/bin/gettext.sh"
        "/usr/share/gettext-"*/gettext.sh
    )

    local gettext_sh=""
    for path in "${gettext_paths[@]}"; do
        if [ -f "$path" ]; then
            gettext_sh="$path"
            break
        fi
    done

    if [ -z "$gettext_sh" ]; then
        log_echo "${Error} ${RedBG} $(gettext "未找到") gettext.sh, $(gettext "将使用默认语言") ${Font}"
        unset LANG
        unset LC_MESSAGES
        return 1
    fi

    # Only online mode may create the languages directory (a /etc idleleo
    # mutation that must not happen during offline dispatch).
    if [[ ${allow_online} -eq 1 ]]; then
        [ -d "${idleleo_dir}/languages" ] || mkdir "${idleleo_dir}/languages"
    fi
    export TEXTDOMAIN="xray_install"
    export TEXTDOMAINDIR="${idleleo_dir}/languages"
    . "$gettext_sh"
    # Default until language.conf is parsed. This also refreshes the [信息]/
    # [错误]/[警告] prefixes so they cannot stay stale after a switch.
    _xray_i18n_setup zh

    if [ -f "${idleleo_dir}/language.conf" ]; then
        # Safe-read language.conf instead of sourcing it directly.
        # Only LANG= and LC_MESSAGES= assignments are allowed. Command
        # substitution, extra shell statements, and unknown keys are rejected.
        if ! safe_source_language_conf "${idleleo_dir}/language.conf"; then
            log_echo "${Warning} ${YellowBG} $(gettext "language.conf 校验失败, 将使用默认语言") ${Font}"
            unset LANG
            unset LC_MESSAGES
            return 0
        fi

        if [[ "${LANG%.*}" != "zh_CN" ]]; then
            local lang_code
            case "${LANG%.*}" in
                "en_US") lang_code="en" ;;
                "fa_IR") lang_code="fa" ;;
                "ru_RU") lang_code="ru" ;;
                "ko_KR") lang_code="ko" ;;
                "fr_FR") lang_code="fr" ;;
                *)
                    log_echo "${Warning} ${YellowBG} $(gettext "不支持的语言"):${LANG%.*}, $(gettext "将使用默认语言") ${Font}"
                    unset LANG
                    unset LC_MESSAGES
                    return 0
                    ;;
            esac
            # The menu reads the .mo directly through _xray_i18n_setup; do not
            # force LC_ALL here. gettext remains the fallback, but the catalog
            # lookup no longer depends on a generated en_US.UTF-8/ru_RU.UTF-8
            # locale on minimal images.
            local lang_file="${TEXTDOMAINDIR}/${lang_code}/LC_MESSAGES/${TEXTDOMAIN}.mo"
            local had_lang_file=0
            [ -f "$lang_file" ] && had_lang_file=1
            if [[ ${allow_online} -eq 1 && ${had_lang_file} -eq 0 ]]; then
                if ! update_language_file "$lang_code"; then
                    if _xray_i18n_fallback_en; then
                        log_echo "${Warning} ${YellowBG} $(gettext "语言文件缺失, 已回退英文") ${Font}"
                    else
                        log_echo "${Warning} ${YellowBG} $(gettext "语言文件更新失败"), $(gettext "将使用默认语言") ${Font}"
                    fi
                    return 0
                fi
            fi
            if [ ! -f "$lang_file" ]; then
                # offline: no local translation available. Match the stats helper
                # and fall back to English, never to a Chinese menu.
                if _xray_i18n_fallback_en; then
                    log_echo "${Warning} ${YellowBG} $(gettext "语言文件缺失, 已回退英文") ${Font}"
                fi
                return 0
            fi
            # Switch before probing for a remote update so those notices are
            # already in the selected language, not the Chinese default.
            _xray_i18n_setup "$lang_code"
            if [[ ${allow_online} -eq 1 && ${had_lang_file} -eq 1 ]] && check_language_update "$lang_code"; then
                log_echo "${Info} ${Green} $(gettext "发现语言文件更新") ${Font}"
                if update_language_file "$lang_code"; then
                    . "$gettext_sh"
                    _xray_i18n_setup "$lang_code"
                fi
            fi
        fi
    # else
        # log_echo "${Info} ${Green} $(gettext "未找到") language.conf, $(gettext "将使用默认语言") ${Font}"
        # unset LANG
        # unset LC_MESSAGES
    fi
}

judge() {
    local ret=$?
    local judge_mode="exit"
    if [[ "$1" == "-r" || "$1" == "--return" ]]; then
        judge_mode="return"
        shift
    fi
    local desc="$1"
    if [[ $# -gt 1 ]]; then
        "${@:2}"
        ret=$?
    fi

    if [[ $ret -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} ${desc} $(gettext "完成") ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} ${desc} $(gettext "失败") ${Font}"
        if [[ "${judge_mode}" == "return" ]]; then
            return 1
        else
            exit 1
        fi
    fi
    return $ret
}

check_version() {
    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi
    local result
    if ! result=$(printf '%s' "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null) ||
        [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi
    printf '%s\n' "${result}"
}

# Silent version reader for optional API fields (e.g. *_tested_version).
# Returns empty string on missing/null fields without printing error messages,
# so read_version can probe for tested_version without spamming users on
# older API payloads that don't yet carry the field.
check_version_silent() {
    load_versions || return 1
    local result
    if ! result=$(printf '%s' "${get_versions_all}" | jq -rc --arg key "$1" '.[$key]' 2>/dev/null) ||
        [[ -z "${result}" ]] || [[ "${result}" == "null" ]]; then
        return 1
    fi
    printf '%s\n' "${result}"
}

pkg_install_judge() {
    if is_rpm_family; then
        # Query with the same manager INS selected, never a hard-coded alias.
        "${INS}" list installed | grep -iw "^$1"
    else
        dpkg --get-selections | grep -iw "^$1" | grep -ivw "deinstall"
    fi
}

# Multi-package install with strict error propagation. A real package-manager
# failure on ANY required package records the failing name, prints no overall
# [OK], and returns 1 so the caller can abort. Return value is never masked by
# variable assignment / [[ ]] / echo / judge.
pkg_install() {
    local p
    local install_array=(${1//,/ })
    local failed=0
    local need_install=0
    for p in "${install_array[@]}"; do
        if [[ -z $(pkg_install_judge "${p}") ]]; then
            need_install=1
            if ! ${INS} -y install "${p}"; then
                log_echo "${Error} ${RedBG} $(gettext "软件包安装失败"): ${p} ${Font}"
                failed=1
            fi
        fi
    done
    if [[ ${failed} -eq 0 ]]; then
        if [[ ${need_install} -eq 0 ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "已安装") ${1//,/ } ${Font}"
            sleep 0.5
        else
            judge "$(gettext "安装") ${1//,/ }"
        fi
        return 0
    fi
    return 1
}

dependency_install() {
    pkg_install "bc,curl,dbus,git,jq,lsof,python3,qrencode" || return 1
    if is_rpm_family; then
        pkg_install "crontabs" || return 1
    else
        pkg_install "cron" || return 1
    fi
    if [[ ! -f "/var/spool/cron/root" ]] && [[ ! -f "/var/spool/cron/crontabs/root" ]]; then
        local crontab_file
        crontab_file="$(root_crontab_path)"
        touch "${crontab_file}" && chmod 600 "${crontab_file}"
        if is_rpm_family; then
            systemctl start crond && systemctl enable crond >/dev/null 2>&1
            judge "crontab $(gettext "自启动配置")"
        else
            systemctl start cron && systemctl enable cron >/dev/null 2>&1
            judge "crontab $(gettext "自启动配置")"
        fi
    fi
    if [[ ${tls_mode} != "None" ]] || is_relay_role; then
        if is_rpm_family; then
            pkg_install "epel-release,iputils,pcre,pcre-devel,zlib-devel,perl-IPC-Cmd" || return 1
        else
            # The bundled Nginx release is prebuilt with PCRE2 and zlib
            # statically linked. Do not require the removed libpcre3-dev
            # package (or any other development package) on Ubuntu 26.04+.
            pkg_install "iputils-ping" || return 1
        fi
        judge "Nginx $(gettext "链接库安装")"
    fi
    # Best-effort: the read-only stats helper is optional for install/update.
    # A missing fifth asset or failed hash must never abort installation or
    # disable the existing stats enable/disable path.
    xray_stats_script_ensure >/dev/null 2>&1 || true
}

read_optimize() {
    local prompt="$1"
    local var_name="$2"
    local default_value="${3:-NULL}"
    local min_value="${4:-}"
    local max_value="${5:-}"
    local error_msg="${6:-$(gettext "值为空或超出范围, 请重新输入")!}"
    local user_input

    while true; do
        if ! IFS= read -r -p "${prompt}" user_input; then
            log_echo "${Error} ${RedBG} $(gettext "输入已结束, 操作取消") ${Font}"
            return 1
        fi

        if [[ -z "${user_input}" ]]; then
            if [[ "${default_value}" != "NULL" ]]; then
                user_input="${default_value}"
            else
                log_echo "${Error} ${RedBG} $(gettext "值为空, 请重新输入")! ${Font}"
                continue
            fi
        fi

        if [[ -n "${min_value}" || -n "${max_value}" ]]; then
            if [[ ! "${user_input}" =~ ^[0-9]+$ ]]; then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
            if [[ -n "${min_value}" ]] && (( user_input < min_value )); then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
            if [[ -n "${max_value}" ]] && (( user_input > max_value )); then
                log_echo "${Error} ${RedBG} ${error_msg} ${Font}"
                continue
            fi
        fi

        printf -v "${var_name}" '%s' "${user_input}"
        return 0
    done
}

basic_optimization() {
    # Fail-closed: every system write must propagate failure so a caller's
    # `basic_optimization || return 1` aborts the install chain instead of
    # continuing after a half-applied limits tuning.
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf || return 1
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf || return 1
    printf '%s\n' '* soft nofile 65536' >>/etc/security/limits.conf || return 1
    printf '%s\n' '* hard nofile 65536' >>/etc/security/limits.conf || return 1

    if is_rpm_family; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config || return 1
        setenforce 0 || return 1
    fi

    return 0
}

create_directory() {
    # Fail-closed: any mkdir that cannot create a target terminates the
    # function so the caller can abort the deploy before further steps run.
    # Each existing directory short-circuits to 0 (no mkdir, no error).
    if [[ ${tls_mode} != "None" ]]; then
        [[ -d "${nginx_conf_dir}" ]] || mkdir -p "${nginx_conf_dir}" || return 1
    fi
    [[ -d "${ssl_chainpath}" ]] || mkdir -p "${ssl_chainpath}" || return 1
    [[ -d "${xray_conf_dir}" ]] || mkdir -p "${xray_conf_dir}" || return 1
    [[ -d "${idleleo_dir}/info" ]] || mkdir -p "${idleleo_dir}"/info || return 1
    [[ -d "${idleleo_conf_dir}" ]] || mkdir -p "${idleleo_conf_dir}" || return 1

    return 0
}

is_reality_reserved_port() {
    case "$1" in
        9403|9404|9443|9444) return 0 ;;
        *) return 1 ;;
    esac
}

reality_reserved_port_conflict() {
    local configured_port
    for configured_port in "${port:-}" "${xport:-}" "${gport:-}" "${xhttpport:-}"; do
        if [[ -n "${configured_port}" ]] && is_reality_reserved_port "${configured_port}"; then
            echo "${configured_port}"
            return 0
        fi
    done
    return 1
}

validate_reality_reserved_ports() {
    local conflicting_port
    if conflicting_port=$(reality_reserved_port_conflict); then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${conflicting_port} ${Font}"
        return 1
    fi
    return 0
}

validate_port_number() {
    local port="$1"
    [[ "${port}" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

validate_active_ports() {
    local -a names=()
    local -a values=()
    local i j

    if [[ -n "${port:-}" && "${port}" != "None" ]]; then
        names+=("port")
        values+=("${port}")
    fi
    if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
        names+=("ws")
        values+=("${xport}")
    fi
    if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
        names+=("gRPC")
        values+=("${gport}")
    fi
    if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
        names+=("xHTTP")
        values+=("${xhttpport}")
    fi

    for i in "${!values[@]}"; do
        validate_port_number "${values[$i]}" || return 1
        if [[ "${tls_mode:-}" == "Reality" ]] && is_reality_reserved_port "${values[$i]}"; then
            return 1
        fi
        for ((j = i + 1; j < ${#values[@]}; j++)); do
            if [[ "${values[$i]}" == "${values[$j]}" ]]; then
                log_echo "${Error} ${RedBG} $(gettext "端口重复"): ${names[$i]}=${values[$i]}, ${names[$j]}=${values[$j]} ${Font}"
                return 1
            fi
        done
    done
    return 0
}

port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_port} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "确定端口") ${Font}"
        read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
        while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${port}"; do
            echo -e "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
            read_optimize "$(gettext "请输入端口") ($(gettext "默认值"):443):" "port" 443 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
        done
    fi
}

# Reset install wizard profile state before each wizard entry.
# Must NOT clear old_config_status (preserves "retain old config" mode).
reset_install_wizard_state() {
    install_profile=""
    install_wizard_preset="off"
    reality_add_more="off"
    reality_add_nginx="off"
    reality_add_balance="off"
    reality_balance_role=""
    transport_mode="None"
}

# Apply install profile: sets tls_mode / reality_* / transport_mode / shell_mode
# based on the profile selected by the hierarchical install wizard.
#
# For profiles that include an extra transport (reality_transport,
# reality_transport_nginx, transport_nginx_tls, transport_only), transport_mode
# is NOT overwritten here — it is set beforehand by menu_choose_transport, and
# shell_mode is derived later by _transport_set_shell_mode.
#
# For profiles without extra transport (reality_nginx, reality_standard),
# transport_mode is forced to "None" and shell_mode is set directly.
apply_install_profile() {
    case "${install_profile}" in
        reality_nginx)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="on"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Nginx+Reality"
            ;;
        reality_standard)
            tls_mode="Reality"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            transport_mode="None"
            shell_mode="Reality"
            ;;
        reality_transport)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_transport_nginx)
            tls_mode="Reality"
            reality_add_more="on"
            reality_add_nginx="on"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        reality_balance_primary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="on"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="primary"
            shell_mode="Nginx+Reality+Balance"
            ;;
        reality_balance_secondary)
            tls_mode="Reality"
            reality_add_balance="on"
            reality_add_nginx="off"
            reality_add_more="off"
            transport_mode="None"
            reality_balance_role="secondary"
            shell_mode="Reality+Balance"
            ;;
        transport_nginx_tls)
            tls_mode="TLS"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        transport_only)
            tls_mode="None"
            reality_add_more="off"
            reality_add_nginx="off"
            reality_add_balance="off"
            # transport_mode set by menu_choose_transport; shell_mode derived later
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "未知的安装配置") ${Font}"
            return 1
            ;;
    esac
    return 0
}

transport_choose() {
    # Install wizard preset: transport_mode already set by menu_choose_transport.
    if [[ ${install_wizard_preset:-off} == "on" ]] &&
       [[ -n ${transport_mode:-} ]] &&
       [[ ${transport_mode} != "None" ]]; then
        _transport_set_shell_mode
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_transport} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "请选择传输协议") ${Font}"
        echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
        echo "2: gRPC"
        echo "3: xHTTP"
        echo "4: ws+xHTTP"
        echo "5: ws+gRPC+xHTTP"
        local choose_network
        read_optimize "$(gettext "请输入"): " "choose_network" 1 1 5 "$(gettext "请输入有效的数字")!" || return 1
        case ${choose_network} in
        2)
            transport_mode="onlygRPC"
            ;;
        3)
            transport_mode="onlyxhttp"
            ;;
        4)
            transport_mode="wsxhttp"
            ;;
        5)
            transport_mode="wsgRPCxhttp"
            ;;
        *)
            transport_mode="onlyws"
            ;;
        esac
        _transport_set_shell_mode
    fi
}

_transport_set_shell_mode() {
    local transport_label=""

    # Non-transport installs (standard Reality, Reality+Nginx, Reality balance
    # primary/secondary, and the not-installed state) persist
    # transport_mode="None" in the config. On script restart judge_mode reads
    # the config and calls this function; without this branch shell_mode would
    # stay at the initial "未安装" placeholder. Derive shell_mode from tls_mode
    # and the reality_* flags so the menu reflects the real installed mode.
    if [[ -z ${transport_mode:-} ||
          ${transport_mode} == "None" ||
          ${transport_mode} == "null" ]]; then
        case ${tls_mode} in
        Reality)
            if [[ ${reality_add_balance} == "on" ]]; then
                if [[ ${reality_add_nginx} == "on" ]]; then
                    shell_mode="Nginx+Reality+Balance"
                else
                    shell_mode="Reality+Balance"
                fi
            elif [[ ${reality_add_nginx} == "on" ]]; then
                shell_mode="Nginx+Reality"
            else
                shell_mode="Reality"
            fi
            ;;
        XTLS)
            # Legacy installs of the removed "XTLS ONLY" mode. The mode is no
            # longer supported: label it clearly instead of pretending it is
            # configurable, and never touch the running files.
            shell_mode="$(gettext "旧版 XTLS 模式 (已取消)")"
            ;;
        None)
            shell_mode="$(gettext "未安装")"
            ;;
        esac
        return 0
    fi

    case ${transport_mode} in
    onlyws) transport_label="ws";;
    onlygRPC) transport_label="gRPC";;
    onlyxhttp) transport_label="xHTTP";;
    wsxhttp) transport_label="ws+xHTTP";;
    wsgRPCxhttp) transport_label="ws+gRPC+xHTTP";;
    *) return;;
    esac
    case ${tls_mode} in
    TLS)
        shell_mode="Nginx+${transport_label}+TLS"
        ;;
    Reality)
        if [[ ${reality_add_more} == "on" && ${reality_add_nginx} == "off" ]]; then
            shell_mode="Reality+${transport_label}"
        elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "on" ]]; then
            shell_mode="Nginx+Reality+${transport_label}"
        elif [[ ${reality_add_nginx} == "on" && ${reality_add_more} == "off" ]]; then
            shell_mode="Nginx+Reality"
        else
            shell_mode="Reality"
        fi
        if [[ ${reality_add_balance} == "on" ]]; then
            shell_mode="${shell_mode}+Balance"
        fi
        ;;
    None)
        shell_mode="${transport_label} ONLY"
        ;;
    esac
}

xray_reality_add_more_choose() {
    # Install wizard preset: reality_add_more and transport_mode already set
    # by apply_install_profile + menu_choose_transport.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_more} == "on" ]]; then
            # transport_mode already set; derive shell_mode and init ports/paths
            _transport_set_shell_mode
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
            if is_ws_mode; then
                port_exist_check "${xport}" || return 1
            fi
            if is_grpc_mode; then
                port_exist_check "${gport}" || return 1
            fi
            if is_xhttp_mode; then
                port_exist_check "${xhttpport}" || return 1
            fi
        else
            transport_mode="None"
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
        fi
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_transport} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否添加用于负载均衡的 ws/gRPC 协议") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择")! ${Font}"
        read -r reality_add_more_fq
        case $reality_add_more_fq in
        [yY][eE][sS] | [yY])
            reality_add_more="on"
            transport_choose || return 1
            ws_inbound_port_set || return 1
            grpc_inbound_port_set || return 1
            xhttp_inbound_port_set || return 1
            ws_path_set || return 1
            grpc_path_set || return 1
            xhttp_path_set || return 1
            if is_ws_mode; then
                port_exist_check "${xport}" || return 1
            fi
            if is_grpc_mode; then
                port_exist_check "${gport}" || return 1
            fi
            if is_xhttp_mode; then
                port_exist_check "${xhttpport}" || return 1
            fi
            ;;
        *)
            reality_add_more="off"
            transport_mode="None"
            ws_inbound_port_set
            grpc_inbound_port_set
            xhttp_inbound_port_set
            ws_path_set
            grpc_path_set
            xhttp_path_set
            log_echo "${OK} ${GreenBG} $(gettext "已跳过添加简单 ws/gRPC/xHTTP 协议") ${Font}"
            ;;
        esac
    fi
}

transport_qr() {
    artpath="None"
    artxport="None"
    artserviceName="None"
    artgport="None"
    artxhttppath="None"
    artxhttpport="None"
    artnet="ws/gRPC"
    if is_ws_mode; then
        artxport=${xport}
        artpath=${path}
    fi
    if is_grpc_mode; then
        artgport=${gport}
        artserviceName=${serviceName}
    fi
    if is_xhttp_mode; then
        artxhttpport=${xhttpport}
        artxhttppath=${xhttppath}
        artnet="xHTTP"
    fi
    if [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
        artnet="ws/gRPC/xHTTP"
    elif [[ ${transport_mode} == "wsxhttp" ]]; then
        artnet="ws/xHTTP"
    fi
}

ws_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_ws_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") ws inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") ws inbound_port ($(gettext "请勿与其他端口相同")!): " "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${xport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") ws inbound_port ($(gettext "请勿与其他端口相同")!): " "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            *)
                xport=$(generate_random_port 10000 10999)
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                ;;
            esac
        fi
    fi
}

grpc_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_grpc_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") gRPC inbound_port ($(gettext "请勿与其他端口相同")!): " "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${gport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") gRPC inbound_port ($(gettext "请勿与其他端口相同")!): " "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            *)
                gport=$(generate_random_port 10000 10999)
                while [[ ${gport} == ${xport} ]]; do gport=$(generate_random_port 10000 10999); done
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                ;;
            esac
        fi
    fi
}

xhttp_inbound_port_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_inner_ports} == "yes" ]]; then
        if is_xhttp_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP inbound_port [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r inbound_port_modify_fq
            case $inbound_port_modify_fq in
            [yY][eE][sS] | [yY])
                read_optimize "$(gettext "请输入") xHTTP inbound_port ($(gettext "请勿与其他端口相同")!): " "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                while [[ ${tls_mode} == "Reality" ]] && is_reality_reserved_port "${xhttpport}"; do
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${Font}"
                    read_optimize "$(gettext "请输入") xHTTP inbound_port ($(gettext "请勿与其他端口相同")!): " "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
                done
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
                ;;
            *)
                xhttpport=$(generate_random_port 11000 11999)
                while [[ ${xhttpport} == ${xport} || ${xhttpport} == ${gport} ]]; do xhttpport=$(generate_random_port 11000 11999); done
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
                ;;
            esac
        fi
    fi
}

managed_ports_file="${idleleo_conf_dir}/managed_ports.json"
# Per-family ownership of the always-on baseline rules (loopback / DNS 53 /
# UDP high-port range). Records WHICH baseline rules the project created on
# each family so a dropped family can be cleaned and a failed family gain can
# be rolled back WITHOUT ever deleting a user's own pre-existing rule.
managed_baseline_file="${idleleo_conf_dir}/managed_baseline.list"

# Managed-firewall compatibility layer.
# The project historically only manages iptables directly; if firewalld or
# nftables frontends are introduced later, route through these helpers so
# rule idempotency and managed-port tracking remain single-sourced.
#
# Family policy is driven by network_mode (the single source of truth):
#   ipv4   -> manage iptables only
#   ipv6   -> manage ip6tables only (never touch IPv4 firewall)
#   dual   -> manage iptables + ip6tables
#   manual -> conservative: iptables only, never expand the managed set
#   auto/empty -> fall back to tool availability for legacy compatibility
# _MANAGED_FW_IPV6 remains a TEST-ONLY override; production behavior must NOT
# depend on it.
# Command availability probe (thin wrapper). Tests override this to simulate
# a missing tool deterministically: a host that really has /usr/sbin/ip6tables
# must never leak into "tool missing" test cases.
command_available() {
    command -v "$1" >/dev/null 2>&1
}

managed_fw_ipv6_enabled() {
    case "${_MANAGED_FW_IPV6:-auto}" in
        1|on|yes) return 0 ;;
        0|off|no) return 1 ;;
        *) command_available ip6tables ;;
    esac
}

# Resolve a network_mode value to the netfilter binaries that must be managed.
# A pure function of its argument (no global reads), so callers can compute the
# family set for an OLD mode independently of the CURRENT mode.
#   ipv4   -> iptables
#   ipv6   -> ip6tables
#   dual   -> iptables + ip6tables
#   manual -> iptables (conservative, never expand the managed set)
#   auto/empty -> iptables, plus ip6tables only if the tool exists (legacy)
managed_fw_families_for_mode() {
    local mode="${1:-auto}"
    case "${mode}" in
        ipv6) printf '%s\n' "ip6tables" ;;
        dual)
            printf '%s\n' "iptables"
            printf '%s\n' "ip6tables"
            ;;
        ipv4|manual) printf '%s\n' "iptables" ;;
        *)  # auto / 未设置：按工具可用性保守处理，保持旧行为
            printf '%s\n' "iptables"
            command_available ip6tables && printf '%s\n' "ip6tables"
            ;;
    esac
}

# Resolve the netfilter binaries a SAVED config was last managed with (space
# separated). Reads the new network_mode field first; falls back to the legacy
# ip_version field. Pure function of the config file — used to seed the firewall
# transaction's OLD family set BEFORE a mode switch deletes the old config,
# because after that the old network_mode is unrecoverable and a dual -> ipv4
# switch would otherwise leave stale IPv6 managed rules.
managed_fw_families_from_config() {
    local cfg="$1" nm ipv
    nm=$(jq -r '.network_mode // empty' "${cfg}" 2>/dev/null)
    if [[ -z "${nm}" ]]; then
        ipv=$(jq -r '.ip_version // empty' "${cfg}" 2>/dev/null)
        nm=$(infer_network_mode_from_config "${ipv}")
    fi
    managed_fw_families_for_mode "${nm}" | tr '\n' ' '
}

# Families that must be persisted for a firewall transaction: the UNION of the
# families the transaction touched (old ∪ new). A dual -> ipv4 switch cleans
# IPv6 managed rules at runtime, so the cleaned rules.v6 must also be saved or
# the stale rule returns on reboot; dual -> ipv6 is symmetric for rules.v4.
firewall_persist_families() {
    # Arguments are space-separated family lists (e.g. "iptables ip6tables");
    # normalize to a set and emit in canonical order (iptables before
    # ip6tables, matching managed_fw_families) so persistence order is stable.
    printf '%s\n%s\n' "${1:-}" "${2:-}" | tr ' ' '\n' | grep -v '^$' | sort -u \
        | awk '{ print ($0 == "iptables" ? "0 " : "1 ") $0 }' \
        | sort | cut -d' ' -f2- | tr '\n' ' '
}

# Persist the current netfilter state for every family in the given set (the
# transaction's family UNION, old ∪ new). A family that only existed on the OLD
# side was still cleaned at runtime, so it must be saved too or its stale rule
# returns on reboot. Best-effort (runtime rules are already active) but never
# silent: a failed save logs a warning naming the failing family instead of
# printing an unconditional success.
#
# Persistence target paths are overridable via env vars so hermetic tests never
# redirect a mock save binary into a real host path.
#
# Returns an AGGREGATE status: 0 iff every family save succeeded, non-zero if
# ANY family save failed. Each failing family still logs a warning naming it.
# The aggregate return lets a rollback distinguish "fully restored and
# persisted" from "runtime restored but reboot would still be wrong", so a
# persistence failure during restore is treated as a critical failure instead
# of being swallowed as a best-effort warning.
firewall_persist_rules() {
    local persist_families="${1:-}"
    local _fw_bin
    local _persist_rc=0
    local sysconf_dir="${FW_SYSCONF_DIR:-/etc/sysconfig}"
    local rules_v4="${FW_RULES_V4:-/etc/iptables/rules.v4}"
    local rules_v6="${FW_RULES_V6:-/etc/iptables/rules.v6}"
    for _fw_bin in ${persist_families}; do
        if is_rpm_family; then
            if ! service "${_fw_bin}" save 2>/dev/null && ! "${_fw_bin}-save" > "${sysconf_dir}/${_fw_bin}" 2>/dev/null; then
                log_echo "${Warning} ${YellowBG} $(gettext "防火墙") ${_fw_bin} $(gettext "规则持久化失败") ${Font}"
                _persist_rc=1
            fi
            service "${_fw_bin}" restart 2>/dev/null || true
        else
            if [[ "${_fw_bin}" == "ip6tables" ]]; then
                if ! ip6tables-save > "${rules_v6}" 2>/dev/null; then
                    log_echo "${Warning} ${YellowBG} $(gettext "防火墙") ip6tables $(gettext "规则持久化失败") ${Font}"
                    _persist_rc=1
                fi
            else
                if ! iptables-save > "${rules_v4}" 2>/dev/null; then
                    log_echo "${Warning} ${YellowBG} $(gettext "防火墙") iptables $(gettext "规则持久化失败") ${Font}"
                    _persist_rc=1
                fi
            fi
        fi
    done
    return ${_persist_rc}
}

# Effective netfilter binaries to manage, family-aware from network_mode.
# If _MANAGED_FW_IPV6 is explicitly set it takes precedence (test override);
# otherwise network_mode decides which families are managed.
managed_fw_families() {
    if [[ -n "${_MANAGED_FW_IPV6:-}" ]]; then
        printf '%s\n' "iptables"
        case "${_MANAGED_FW_IPV6}" in
            1|on|yes) printf '%s\n' "ip6tables" ;;
        esac
        return 0
    fi
    managed_fw_families_for_mode "${network_mode:-auto}"
}

# netfilter binaries to manage (thin wrapper; see managed_fw_families).
_managed_fw_bins() {
    managed_fw_families
}

# Fail closed: every netfilter tool required by the effective family policy
# must exist. dual/ipv6 with a missing ip6tables must NOT silently degrade to
# single-stack firewall management.
managed_fw_require_families() {
    local bin
    for bin in $(managed_fw_families); do
        command_available "${bin}" || return 1
    done
    return 0
}

firewall_rule_exists() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin rc=0
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        "${bin}" -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1 || rc=1
    done
    return ${rc}
}

# The optional 3rd argument is an explicit netfilter-bin list (space separated).
# When empty the effective family policy (current network_mode) decides which
# families to touch.
firewall_add_managed_port() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        if ! "${bin}" -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
            "${bin}" -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT || return 1
        fi
    done
}

firewall_remove_managed_port() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        while "${bin}" -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1; do
            "${bin}" -D INPUT -p "${proto}" --dport "${port}" -j ACCEPT || return 1
        done
    done
}

# Idempotent helper: add OUTPUT accept rule for a sport. Fails closed.
firewall_add_output_port() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        if ! "${bin}" -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1; then
            "${bin}" -I OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT || return 1
        fi
    done
}

# Check whether an OUTPUT sport accept rule exists.
firewall_output_rule_exists() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin rc=0
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        "${bin}" -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1 || rc=1
    done
    return ${rc}
}

# Idempotent helper: remove OUTPUT accept rule for a sport. Fails closed.
firewall_remove_output_port() {
    local proto="$1"
    local port="$2"
    local bins="${3:-}"
    local bin
    [[ -n "${bins}" ]] || bins=$(_managed_fw_bins)
    for bin in ${bins}; do
        while "${bin}" -C OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT >/dev/null 2>&1; do
            "${bin}" -D OUTPUT -p "${proto}" --sport "${port}" -j ACCEPT || return 1
        done
    done
}

# Idempotent helper: add loopback accept rules. Fails closed.
firewall_add_loopback_rules() {
    local bin
    for bin in $(_managed_fw_bins); do
        "${bin}" -C INPUT -i lo -j ACCEPT >/dev/null 2>&1 ||
            "${bin}" -A INPUT -i lo -j ACCEPT || return 1
        "${bin}" -C OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 ||
            "${bin}" -A OUTPUT -o lo -j ACCEPT || return 1
    done
}

# Idempotent helper: add UDP high-port range accept for INPUT. Fails closed.
firewall_add_udp_high_port_range() {
    local bin
    for bin in $(_managed_fw_bins); do
        "${bin}" -C INPUT -p udp --dport 1024:65535 -j ACCEPT >/dev/null 2>&1 ||
            "${bin}" -I INPUT -p udp --dport 1024:65535 -j ACCEPT || return 1
    done
}

# --- always-on baseline rule ownership (family-aware, transactional) ---------
# Track the exact baseline rules WE created per family so a dropped family can
# be cleaned of OUR rules and a failed family gain rolled back, without ever
# deleting a user's own pre-existing rule.
BASELINE_RULE_KEYS="lo-in lo-out dns-tcp-in dns-udp-in dns-tcp-out dns-udp-out udp-hi-in"

# Apply one canonical baseline rule on one family. op: check|add|remove.
# check returns 0 if the rule exists; add/remove apply the netfilter change.
baseline_rule() {
    local bin="$1" key="$2" op="$3"
    case "${key}" in
        lo-in)
            case "${op}" in
                check)  "${bin}" -C INPUT  -i lo -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -A INPUT  -i lo -j ACCEPT ;;
                remove) "${bin}" -D INPUT  -i lo -j ACCEPT ;;
            esac ;;
        lo-out)
            case "${op}" in
                check)  "${bin}" -C OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -A OUTPUT -o lo -j ACCEPT ;;
                remove) "${bin}" -D OUTPUT -o lo -j ACCEPT ;;
            esac ;;
        dns-tcp-in)
            case "${op}" in
                check)  "${bin}" -C INPUT  -p tcp --dport 53 -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -I INPUT  -p tcp --dport 53 -j ACCEPT ;;
                remove) "${bin}" -D INPUT  -p tcp --dport 53 -j ACCEPT ;;
            esac ;;
        dns-udp-in)
            case "${op}" in
                check)  "${bin}" -C INPUT  -p udp --dport 53 -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -I INPUT  -p udp --dport 53 -j ACCEPT ;;
                remove) "${bin}" -D INPUT  -p udp --dport 53 -j ACCEPT ;;
            esac ;;
        dns-tcp-out)
            case "${op}" in
                check)  "${bin}" -C OUTPUT -p tcp --sport 53 -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -I OUTPUT -p tcp --sport 53 -j ACCEPT ;;
                remove) "${bin}" -D OUTPUT -p tcp --sport 53 -j ACCEPT ;;
            esac ;;
        dns-udp-out)
            case "${op}" in
                check)  "${bin}" -C OUTPUT -p udp --sport 53 -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -I OUTPUT -p udp --sport 53 -j ACCEPT ;;
                remove) "${bin}" -D OUTPUT -p udp --sport 53 -j ACCEPT ;;
            esac ;;
        udp-hi-in)
            case "${op}" in
                check)  "${bin}" -C INPUT  -p udp --dport 1024:65535 -j ACCEPT >/dev/null 2>&1 ;;
                add)    "${bin}" -I INPUT  -p udp --dport 1024:65535 -j ACCEPT ;;
                remove) "${bin}" -D INPUT  -p udp --dport 1024:65535 -j ACCEPT ;;
            esac ;;
        *) return 2 ;;
    esac
}

# Baseline rule keys the project owns on a family (from the state file).
baseline_owned_keys() {
    local fam="$1"
    # Guard: on a fresh install (or empty/absent state file) there is nothing
    # owned. Never let awk read stdin (empty path) — that would hang.
    [[ -n "${managed_baseline_file}" && -f "${managed_baseline_file}" ]] || return 0
    awk -v f="${fam}" '$1==f {print $2}' "${managed_baseline_file}" 2>/dev/null
}

# Families that currently have at least one project-owned baseline rule.
baseline_owned_families() {
    [[ -n "${managed_baseline_file}" && -f "${managed_baseline_file}" ]] || return 0
    awk '{print $1}' "${managed_baseline_file}" 2>/dev/null | sort -u
}

# Persist baseline ownership. Args are "<family>:<key,key,...>" entries; a
# family with no keys is written as an empty set. Atomic via tmp+rename.
baseline_owned_save() {
    local file="${managed_baseline_file}.tmp.$$"
    : > "${file}"
    local entry fam keys k
    for entry in "$@"; do
        fam="${entry%%:*}"; keys="${entry#*:}"
        if [[ "${fam}" == "${entry}" ]]; then continue; fi  # no colon -> skip
        # Empty key set (family persists with nothing owned) must not attempt
        # to expand an empty array under `set -u`, nor write a bare line.
        [[ -z "${keys}" ]] && continue
        local karr
        IFS=',' read -ra karr <<< "${keys}"
        for k in "${karr[@]}"; do
            [[ -z "${k}" ]] && continue
            printf '%s %s\n' "${fam}" "${k}" >> "${file}"
        done
    done
    mkdir -p "$(dirname "${managed_baseline_file}")" || return 1
    sort -u "${file}" -o "${file}"
    mv "${file}" "${managed_baseline_file}"
}

# Corrective ownership commit used when a baseline_sync compensation could not
# fully restore the entry state: own a key iff its rule is actually present in
# runtime. A leftover project-added rule is therefore never orphaned, and an
# absent rule is never claimed (claiming it would make later removals fail
# forever). Args: v4 / v6 candidate key lists (space separated).
baseline_owned_save_verified() {
    local v4_cand="$1" v6_cand="$2"
    local k out4="" out6=""
    for k in ${v4_cand}; do
        if baseline_rule iptables "${k}" check; then out4="${out4}${k},"; fi
    done
    for k in ${v6_cand}; do
        if baseline_rule ip6tables "${k}" check; then out6="${out6}${k},"; fi
    done
    baseline_owned_save "iptables:${out4%,}" "ip6tables:${out6%,}"
}

# Hand the pending journal over to durable ownership: a rule leaves it once
# gone from runtime or owned; a present, unowned rule stays as orphan candidate.
baseline_pending_prune() {
    local fam owned k cand kept_v4="" kept_v6=""
    for fam in iptables ip6tables; do
        if [[ "${fam}" == "iptables" ]]; then
            cand="${_reinstall_baseline_pending_added_v4:-}"
        else
            cand="${_reinstall_baseline_pending_added_v6:-}"
        fi
        [[ -z "${cand}" ]] && continue
        owned="$(baseline_owned_keys "${fam}")"
        for k in ${cand}; do
            if baseline_rule "${fam}" "${k}" check && \
               ! printf '%s\n' ${owned} | grep -qxF "${k}"; then
                if [[ "${fam}" == "iptables" ]]; then
                    kept_v4="${kept_v4} ${k}"
                else
                    kept_v6="${kept_v6} ${k}"
                fi
            fi
        done
    done
    _reinstall_baseline_pending_added_v4="${kept_v4# }"
    _reinstall_baseline_pending_added_v6="${kept_v6# }"
}

# Reconcile baseline ownership toward a target family set (space separated).
# The netfilter runtime and managed_baseline.list are ONE transaction: ensure
# every baseline rule exists per target family (only rules WE add are owned),
# clean OUR baseline on dropped families, and commit ownership only after the
# target runtime is fully established. A failed add rolls back every rule added
# this call; a failed compensation/commit keeps leftovers owned (never
# orphaned) via a verified ownership commit and fails the sync retry-safely.
baseline_sync() {
    local target="$1"
    local target_list old_list
    target_list=$(printf '%s\n' ${target} | grep -v '^$' | sort -u)
    old_list=$(baseline_owned_families)
    local v4_owned v6_owned v4_added v6_added
    v4_owned="$(baseline_owned_keys iptables)"
    v6_owned="$(baseline_owned_keys ip6tables)"
    v4_added=""; v6_added=""
    # Dropped-family keys: confirmed-removed (for commit-compensation) vs failed (stay owned).
    local v4_dropped_ok="" v6_dropped_ok="" v4_dropped_fail="" v6_dropped_fail=""
    local bin key
    local _b _k _keys _rkeys _comp_fail

    for bin in ${target_list}; do
        for key in ${BASELINE_RULE_KEYS}; do
            if baseline_rule "${bin}" "${key}" check; then
                continue
            fi
            if ! baseline_rule "${bin}" "${key}" add; then
                # add failed — compensate EVERY rule added by this call across
                # all families so a midway family gain leaves no half-applied rules.
                _comp_fail=0
                for _b in iptables ip6tables; do
                    if [[ "${_b}" == "iptables" ]]; then _keys="${v4_added}"; else _keys="${v6_added}"; fi
                    for _k in ${_keys}; do
                        # A failed compensation keeps the leftover ours: it must stay owned.
                        baseline_rule "${_b}" "${_k}" remove 2>/dev/null || _comp_fail=1
                    done
                done
                if [[ ${_comp_fail} -ne 0 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则回滚未完成, 部分规则仍保留并已记录") ${Font}"
                    # Corrective commit: own rules still present, then prune the journal.
                    if baseline_owned_save_verified "${v4_owned} ${v4_added}" "${v6_owned} ${v6_added}"; then
                        baseline_pending_prune
                    else
                        log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则状态写入失败") ${Font}"
                    fi
                fi
                return 1
            fi
            if [[ "${bin}" == "iptables" ]]; then
                v4_added="${v4_added} ${key}"
                # Journal immediately (not at commit): rollback must know exactly
                # which rules THIS transaction added, never a user's own.
                _reinstall_baseline_pending_added_v4="${_reinstall_baseline_pending_added_v4} ${key}"
            else
                v6_added="${v6_added} ${key}"
                _reinstall_baseline_pending_added_v6="${_reinstall_baseline_pending_added_v6} ${key}"
            fi
        done
    done

    # Dropped-family cleanup: remove OUR baseline only; a rule still in runtime
    # whose removal fails keeps ownership and fails the sync.
    for bin in ${old_list}; do
        if ! printf '%s\n' ${target_list} | grep -qxF "${bin}"; then
            local owned_keys
            owned_keys=$(baseline_owned_keys "${bin}")
            for key in ${owned_keys}; do
                # Absent == desired state; only a present rule failing removal fails.
                if ! baseline_rule "${bin}" "${key}" check || \
                   baseline_rule "${bin}" "${key}" remove 2>/dev/null; then
                    if [[ "${bin}" == "iptables" ]]; then
                        v4_dropped_ok="${v4_dropped_ok} ${key}"
                    else
                        v6_dropped_ok="${v6_dropped_ok} ${key}"
                    fi
                else
                    if [[ "${bin}" == "iptables" ]]; then
                        v4_dropped_fail="${v4_dropped_fail} ${key}"
                    else
                        v6_dropped_fail="${v6_dropped_fail} ${key}"
                    fi
                fi
            done
        fi
    done

    # Ownership = kept old + newly added per family; a dropped family keeps only failed removals.
    local v4_all v6_all v4_final v6_final
    v4_all="$(printf '%s %s\n' "${v4_owned}" "${v4_added}" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')"
    v6_all="$(printf '%s %s\n' "${v6_owned}" "${v6_added}" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')"
    v4_final="${v4_all}"; v6_final="${v6_all}"
    if ! printf '%s\n' ${target_list} | grep -qxF iptables; then
        v4_final="$(printf '%s\n' ${v4_dropped_fail} | grep -v '^$' | tr '\n' ',' | sed 's/,$//')"
    fi
    if ! printf '%s\n' ${target_list} | grep -qxF ip6tables; then
        v6_final="$(printf '%s\n' ${v6_dropped_fail} | grep -v '^$' | tr '\n' ',' | sed 's/,$//')"
    fi
    if [[ -n "${v4_dropped_fail}" || -n "${v6_dropped_fail}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则清理未完成, 未能删除的规则仍保持记录") ${Font}"
        if baseline_owned_save "iptables:${v4_final}" "ip6tables:${v6_final}"; then
            baseline_pending_prune
        else
            log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则状态写入失败") ${Font}"
        fi
        return 1
    fi
    if ! baseline_owned_save "iptables:${v4_final}" "ip6tables:${v6_final}"; then
        # Atomic file still holds OLD state — compensate runtime to entry state.
        local _comp2_fail=0
        for _b in iptables ip6tables; do
            if [[ "${_b}" == "iptables" ]]; then
                _keys="${v4_added}"; _rkeys="${v4_dropped_ok}"
            else
                _keys="${v6_added}"; _rkeys="${v6_dropped_ok}"
            fi
            for _k in ${_keys}; do
                baseline_rule "${_b}" "${_k}" remove 2>/dev/null || _comp2_fail=1
            done
            for _k in ${_rkeys}; do
                baseline_rule "${_b}" "${_k}" add 2>/dev/null || _comp2_fail=1
            done
        done
        if [[ ${_comp2_fail} -eq 0 ]]; then
            # runtime == entry state; untouched ownership file is consistent; rerun safe.
            log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则状态写入失败") ${Font}"
            return 1
        fi
        # Compensation incomplete: verified ownership (own iff present) prevents orphan.
        log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则回滚未完成, 部分规则仍保留并已记录") ${Font}"
        if baseline_owned_save_verified "${v4_owned} ${v4_added} ${v4_dropped_ok}" \
                                        "${v6_owned} ${v6_added} ${v6_dropped_ok}"; then
            baseline_pending_prune
        else
            log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则状态写入失败") ${Font}"
        fi
        return 1
    fi
    # Ownership committed — pending journal redundant; clear it.
    _reinstall_baseline_pending_added_v4=""
    _reinstall_baseline_pending_added_v6=""
    return 0
}

atomic_write_managed_ports() {
    local json="$1"
    mkdir -p "$(dirname "${managed_ports_file}")"
    local tmp_file="${managed_ports_file}.tmp.$$"
    printf '%s' "${json}" > "${tmp_file}" || return 1
    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        rm -f "${tmp_file}"
        return 1
    fi
    mv "${tmp_file}" "${managed_ports_file}"
}

collect_new_managed_ports() {
    local -a tcp=()
    local -a udp=()
    if is_relay_role; then
        # A relay forwards a single TCP stream; never open UDP for it.
        if [[ -n "${relay_listen_port:-}" ]]; then
            tcp+=("${relay_listen_port}")
        fi
        new_ports_json=$(jq -nc \
            --argjson tcp "$(printf '%s\n' "${tcp[@]:-}" | jq -R . | jq -s 'unique')" \
            '{tcp:$tcp, udp:[]}')
        return 0
    fi
    if [[ -n "${port:-}" && "${port}" != "None" ]]; then
        tcp+=("${port}")
        udp+=("${port}")
    fi
    if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
        tcp+=("${xport}")
        udp+=("${xport}")
    fi
    if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
        tcp+=("${gport}")
        udp+=("${gport}")
    fi
    if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
        tcp+=("${xhttpport}")
        udp+=("${xhttpport}")
    fi
    new_ports_json=$(jq -nc \
        --argjson tcp "$(printf '%s\n' "${tcp[@]:-}" | jq -R . | jq -s 'unique')" \
        --argjson udp "$(printf '%s\n' "${udp[@]:-}" | jq -R . | jq -s 'unique')" \
        '{tcp:$tcp, udp:$udp}')
}

reconcile_managed_firewall() {
    local old_json="$1"
    local new_json="$2"
    local old_bins="${3:-}" new_bins="${4:-}"
    local old_tcp new_tcp old_udp new_udp port bin
    [[ -n "${old_bins}" ]] || old_bins=$(_managed_fw_bins)
    [[ -n "${new_bins}" ]] || new_bins=$(_managed_fw_bins)

    old_tcp=$(printf '%s' "${old_json}" | jq -r '.tcp[]? // empty')
    new_tcp=$(printf '%s' "${new_json}" | jq -r '.tcp[]? // empty')
    old_udp=$(printf '%s' "${old_json}" | jq -r '.udp[]? // empty')
    new_udp=$(printf '%s' "${new_json}" | jq -r '.udp[]? // empty')

    # Reconcile by set difference (old - new = remove, new - old = add). A
    # dropped family removes every old managed port even on a same-port switch.
    for bin in ${old_bins}; do
        if ! printf '%s\n' ${new_bins} | grep -qxF "${bin}"; then
            while IFS= read -r port; do
                [[ -n "${port}" ]] || continue
                firewall_remove_managed_port tcp "${port}" "${bin}" || return 1
                firewall_remove_output_port tcp "${port}" "${bin}" || return 1
            done <<< "${old_tcp}"
            while IFS= read -r port; do
                [[ -n "${port}" ]] || continue
                firewall_remove_managed_port udp "${port}" "${bin}" || return 1
                firewall_remove_output_port udp "${port}" "${bin}" || return 1
            done <<< "${old_udp}"
        fi
    done

    # Families gained (in new, not in old): add EVERY new managed port — a
    # same-port family transition (ipv4 -> dual) must still open the new family.
    for bin in ${new_bins}; do
        if ! printf '%s\n' ${old_bins} | grep -qxF "${bin}"; then
            for port in ${new_tcp}; do
                [[ -n "${port}" ]] || continue
                firewall_add_managed_port tcp "${port}" "${bin}" || return 1
                firewall_add_output_port tcp "${port}" "${bin}" || return 1
            done
            for port in ${new_udp}; do
                [[ -n "${port}" ]] || continue
                firewall_add_managed_port udp "${port}" "${bin}" || return 1
                firewall_add_output_port udp "${port}" "${bin}" || return 1
            done
        fi
    done

    # Families present in BOTH old and new: apply the port diff. Fail closed:
    # if a removal fails, abort so the caller can roll back.
    for bin in ${old_bins}; do
        printf '%s\n' ${new_bins} | grep -qxF "${bin}" || continue
        # Remove old managed TCP INPUT/OUTPUT ports no longer in the new set.
        while IFS= read -r port; do
            [[ -n "${port}" ]] || continue
            printf '%s\n' "${new_tcp}" | grep -qxF "${port}" || {
                firewall_remove_managed_port tcp "${port}" "${bin}" || return 1
                firewall_remove_output_port tcp "${port}" "${bin}" || return 1
            }
        done <<< "${old_tcp}"
        # Remove old managed UDP INPUT/OUTPUT ports no longer in the new set.
        while IFS= read -r port; do
            [[ -n "${port}" ]] || continue
            printf '%s\n' "${new_udp}" | grep -qxF "${port}" || {
                firewall_remove_managed_port udp "${port}" "${bin}" || return 1
                firewall_remove_output_port udp "${port}" "${bin}" || return 1
            }
        done <<< "${old_udp}"
        # Add new managed TCP INPUT/OUTPUT ports. Always call the idempotent
        # helper (it checks -C before -I): never skip based on membership in
        # old_tcp, because the family may start empty or a prior step may have
        # removed the rule — a same-port transition (443 -> 443) must still
        # ensure the rule exists on every common family.
        for port in ${new_tcp}; do
            [[ -n "${port}" ]] || continue
            firewall_add_managed_port tcp "${port}" "${bin}" || return 1
            firewall_add_output_port tcp "${port}" "${bin}" || return 1
        done
        # Add new managed UDP INPUT/OUTPUT ports.
        for port in ${new_udp}; do
            [[ -n "${port}" ]] || continue
            firewall_add_managed_port udp "${port}" "${bin}" || return 1
            firewall_add_output_port udp "${port}" "${bin}" || return 1
        done
    done
    return 0
}

# Apply a managed-firewall port-set change transactionally (old → new).
#   - Reconciles rules old→new; on any partial failure reverses new→old so
#     no half-applied rules remain.
#   - On success persists the new set to managed_ports.json. If the write
#     fails, reverses new→old so no stale rules remain.
#   - Tracks the transaction state in _reinstall_firewall_changed so the global
#     rollback knows exactly what must still be reversed:
#       no      — not modified, or already fully reversed
#       pending — forward changes started but reverse not confirmed; the global
#                 rollback MUST retry the reverse
#       yes     — forward change succeeded; the global rollback must reverse it
#   - A failed forward change or state-file write always tries new→old
#     immediately. The reverse error is NEVER swallowed with `|| true` — on
#     reverse failure the state stays "pending" so reinstall_backup_restore
#     retries instead of silently leaving half-applied rules.
# Returns 0 on success, 1 on failure.
apply_managed_firewall_transaction() {
    local old_json="$1" new_json="$2"
    local old_bins="${3:-}" new_bins="${4:-}"
    [[ -n "${old_bins}" ]] || old_bins=$(_managed_fw_bins)
    [[ -n "${new_bins}" ]] || new_bins=$(_managed_fw_bins)
    _reinstall_firewall_old_ports="${old_json}"
    _reinstall_firewall_new_ports="${new_json}"
    _reinstall_firewall_old_families="${old_bins}"
    _reinstall_firewall_new_families="${new_bins}"
    _reinstall_firewall_changed="pending"
    if ! reconcile_managed_firewall "${old_json}" "${new_json}" "${old_bins}" "${new_bins}"; then
        if reconcile_managed_firewall "${new_json}" "${old_json}" "${new_bins}" "${old_bins}" 2>/dev/null; then
            _reinstall_firewall_changed="no"
        else
            log_echo "${Error} ${RedBG} $(gettext "防火墙规则前向修改失败且反向恢复未完成, 全局回滚时将再次尝试") ${Font}"
        fi
        return 1
    fi
    _reinstall_firewall_changed="yes"
    if ! atomic_write_managed_ports "${new_json}"; then
        if reconcile_managed_firewall "${new_json}" "${old_json}" "${new_bins}" "${old_bins}" 2>/dev/null; then
            _reinstall_firewall_changed="no"
        else
            log_echo "${Error} ${RedBG} $(gettext "防火墙状态写入失败且反向恢复未完成, 全局回滚时将再次尝试") ${Font}"
        fi
        return 1
    fi
    return 0
}

firewall_set() {
    echo
    log_echo "${GreenBG} $(gettext "是否需要设置防火墙") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r firewall_set_fq
    case $firewall_set_fq in
    [yY][eE][sS] | [yY])
        # P1-9: persistent-firewall packages are REQUIRED once the user opts in.
        # Install failure must abort the firewall transaction (caller rollback
        # path), never silently continue without persistence.
        if is_rpm_family; then
            pkg_install "iptables-services" || return 1
        else
            pkg_install "iptables-persistent" || return 1
        fi

        # Restore dual-stack runtime state on a fresh process so the family
        # policy reflects the installed network_mode instead of tool presence.
        ensure_network_runtime_state

        # Fail closed: if the effective family policy needs a netfilter tool
        # that is not installed, abort instead of silently downgrading to a
        # single-stack firewall while still claiming dual-stack readiness.
        if ! managed_fw_require_families; then
            log_echo "${Error} ${RedBG} $(gettext "当前网络模式所需的防火墙工具缺失 (iptables/ip6tables), 防火墙配置已中止") ${Font}"
            return 1
        fi

        # Apply the always-on baseline transactionally (family-aware). Old/new
        # family sets are recorded so a later deploy failure can reverse it.
        _reinstall_baseline_old_families="$(baseline_owned_families)"
        _reinstall_baseline_new_families="$(_managed_fw_bins)"
        _reinstall_baseline_changed="pending"
        if ! baseline_sync "${_reinstall_baseline_new_families}"; then
            # Keep "pending" (NOT "no") so global rollback still retries the reverse.
            log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则配置失败") ${Font}"
            return 1
        fi
        _reinstall_baseline_changed="yes"

        # Capture the pre-deploy managed set once (loaded at reconfig start).
        # Fall back to reading managed_ports.json for a standalone firewall_set.
        if [[ -z "${_reinstall_firewall_old_ports:-}" || \
              "${_reinstall_firewall_old_ports:-}" == '{"tcp":[],"udp":[]}' ]]; then
            _reinstall_firewall_old_ports=$(cat "${managed_ports_file}" 2>/dev/null ||
                echo '{"tcp":[],"udp":[]}')
        fi
        # Pre-deploy family set from reinstall start; never recompute from the
        # current network_mode (already the target of a reinstall).
        _reinstall_firewall_old_families="${_reinstall_firewall_old_families:-}"
        # Build the full new managed set: main + transport ports, plus port 80
        # when TLS mode (ACME / HTTP redirect). Including 80 in the managed set
        # lets a TLS → Reality switch remove the now-unneeded 80 rule.
        collect_new_managed_ports
        if [[ ${tls_mode} == "TLS" ]]; then
            new_ports_json=$(printf '%s' "${new_ports_json}" |
                jq '.tcp = ((.tcp + [80]) | unique) | .udp = ((.udp + [80]) | unique)')
        fi
        _reinstall_firewall_new_ports="${new_ports_json}"
        # New family set = effective policy at apply time (network_mode already
        # reflects the target mode).
        _reinstall_firewall_new_families=$(_managed_fw_bins)

        # Apply the managed rules as a transaction (old → new). Any partial
        # failure or managed_ports.json write failure reverses the rules.
        apply_managed_firewall_transaction \
            "${_reinstall_firewall_old_ports}" \
            "${_reinstall_firewall_new_ports}" \
            "${_reinstall_firewall_old_families:-}" \
            "${_reinstall_firewall_new_families}" || {
                log_echo "${Error} ${RedBG} $(gettext "防火墙规则更新失败") ${Font}"
                return 1
            }

        # Persist old ∪ new families: a cleaned dropped-family rule must not
        # return on reboot. Non-fatal but never a silent unconditional success.
        local _persist_families
        _persist_families=$(firewall_persist_families \
            "${_reinstall_firewall_old_families:-}" \
            "${_reinstall_firewall_new_families:-}")
        firewall_persist_rules "${_persist_families}"
        log_echo "${OK} ${GreenBG} $(gettext "防火墙") $(gettext "重启") ${Font}"

        log_echo "${OK} ${GreenBG} $(gettext "开放防火墙相关端口") ${Font}"
        log_echo "${Warning} ${GreenBG} $(gettext "若修改配置, 请注意关闭防火墙相关端口") ${Font}"
        log_echo "${OK} ${GreenBG} $(gettext "配置") Xray FullCone ${Font}"
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "跳过防火墙设置") ${Font}"
        ;;
    esac
}

ws_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_ws_path} == "yes" ]]; then
            if is_ws_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") ws $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") ws $(gettext "伪装路径") ($(gettext "不需要")"/":)" "path" "NULL" || return 1
                    path="${path#/}"
                    log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                    ;;
                *)
                    path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} ws $(gettext "伪装路径"): ${path} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_ws_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") ws $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_ws_path_fq
            case $change_ws_path_fq in
            [yY][eE][sS] | [yY])
                change_ws_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

grpc_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_grpc_path} == "yes" ]]; then
            if is_grpc_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") gRPC $(gettext "伪装路径") ($(gettext "不需要")"/":)" "serviceName" "NULL" || return 1
                    serviceName="${serviceName#/}"
                    log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                    ;;
                *)
                    serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} gRPC $(gettext "伪装路径"): ${serviceName} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_grpc_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") gRPC $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_grpc_path_fq
            case $change_grpc_path_fq in
            [yY][eE][sS] | [yY])
                change_grpc_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

xhttp_path_set() {
    while true; do
        if [[ "on" != ${old_config_status} ]] || [[ ${change_xhttp_path} == "yes" ]]; then
            if is_xhttp_mode; then
                echo
                log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r path_modify_fq
                case $path_modify_fq in
                [yY][eE][sS] | [yY])
                    read_optimize "$(gettext "请输入") xHTTP $(gettext "伪装路径") ($(gettext "不需要")"/":)" "xhttppath" "NULL" || return 1
                    xhttppath="${xhttppath#/}"
                    log_echo "${Green} xHTTP $(gettext "伪装路径"): ${xhttppath} ${Font}"
                    ;;
                *)
                    xhttppath="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    log_echo "${Green} xHTTP $(gettext "伪装路径"): ${xhttppath} ${Font}"
                    ;;
                esac
            fi
            break
        elif is_xhttp_mode; then
            echo
            log_echo "${GreenBG} $(gettext "是否需要自定义") xHTTP $(gettext "伪装路径") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r change_xhttp_path_fq
            case $change_xhttp_path_fq in
            [yY][eE][sS] | [yY])
                change_xhttp_path="yes"
                continue
                ;;
            *) ;;
            esac
            break
        else
            break
        fi
    done
}

email_set() {
    # Reuse old UUID/email during mode switch without re-prompting.
    if [[ ${mode_switch_reuse} == "yes" && -n "${custom_email:-}" ]]; then
        log_echo "${Green} Xray $(gettext "用户名") (email): ${custom_email} ${Font}"
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_user} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") Xray $(gettext "用户名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_email_fq
        case $custom_email_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入正确的 email") (e.g. me@hey.run): " "custom_email" "NULL" || return 1
            ;;
        *)
            custom_email="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})@hey.run"
            ;;
        esac
        log_echo "${Green} Xray $(gettext "用户名") (email): ${custom_email} ${Font}"
    fi
}

UUID_set() {
    # Reuse old UUID during mode switch without re-prompting.
    if [[ ${mode_switch_reuse} == "yes" && -n "${UUID:-}" ]]; then
        log_echo_secure "${Green} UUID: ${UUID} ${Font}"
        return 0
    fi
    if [[ "on" != ${old_config_status} ]] || [[ ${change_user} == "yes" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义字符串映射") (UUIDv5) [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r need_UUID5
        case $need_UUID5 in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入自定义字符串") ($(gettext "最多30字符")):" "UUID5_char" "NULL" || return 1
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo_secure "${Green} $(gettext "自定义字符串"): ${UUID5_char} ${Font}"
            log_echo_secure "${Green} UUIDv5: ${UUID} ${Font}"
            echo
            ;;
        *)
            UUID5_char="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
            UUID="$(UUIDv5_tranc ${UUID5_char})"
            log_echo_secure "${Green} UUID $(gettext "映射字符串"): ${UUID5_char} ${Font}"
            log_echo_secure "${Green} UUID: ${UUID} ${Font}"
            echo
            ;;
        esac
    fi
}

target_set() {
    if [[ "on" == ${old_config_status} ]] && [[ -n $(info_extraction target) ]]; then
        echo
        log_echo "${GreenBG} $(gettext "检测到 target 域名已配置, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq
            case $old_host_fq in
            [nN][oO] | [nN])
                target_reset=1
                nginx_reality_serverNames_del
                ;;
            *)
                target_reset=0
                ;;
            esac
    fi
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local domain
        local output
        local curl_output
        # P1-9: nmap is required for the current domain-TLS detection action.
        pkg_install "nmap" || return 1

        while true; do
            echo
            log_echo "${GreenBG} $(gettext "请输入一个域名") (e.g. bing.com)${Font}"
            log_echo "${Green}$(gettext "域名必须支持 TLSv1.3、X25519、H2, 且不能跳转")${Font}"
            read_optimize "$(gettext "确认域名符合要求后请输入"): " "domain" "NULL" || return 1
            log_echo "${Green}$(gettext "正在检测域名请等待")...${Font}"

            output=$(nmap --script ssl-enum-ciphers -p 443 "${domain}")
            curl_output=$(curl -I -k -m 5 "https://${domain}" 2>&1)

            # 检测TLSv1.3支持
            if ! echo "$output" | grep -q "TLSv1.3"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") TLSv1.3 ${YellowBG}${Font}"
            fi

            # 检测X25519支持
            if ! echo "$output" | grep -q "x25519"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") X25519 ${YellowBG}${Font}"
            fi

            # 检测HTTP/2支持
            if ! echo "$curl_output" | grep -q "HTTP/2"; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名不支持") HTTP/2 ${YellowBG}${Font}"
            fi

            # 检测是否跳转
            if echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名发生了跳转") ${YellowBG}${Font}"
            fi

            if ! echo "$output" | grep -q "TLSv1.3" || \
               ! echo "$output" | grep -q "x25519" || \
               ! echo "$curl_output" | grep -q "HTTP/2" || \
               echo "$curl_output" | grep -i -q 'location:'; then
                log_echo "${Warning} ${YellowBG} $(gettext "该域名可能不满足所有要求") ${YellowBG}${Font}"
                log_echo "${GreenBG} $(gettext "是否仍要设置此域名") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r force_set_fq
                case $force_set_fq in
                    [yY][eE][sS] | [yY])
                        target=$domain
                        break
                        ;;
                    *)
                        continue
                        ;;
                esac
            else
                log_echo "${OK} ${GreenBG} $(gettext "域名") ${domain} $(gettext "满足所有要求") ${Font}"
                target=$domain
                break
            fi
        done
        log_echo "${Green} target $(gettext "域名"): ${target} ${Font}"
    fi
}

# Single-hostname validator for Reality serverNames (rejects empty/space,
# multi-domain, scheme and shell/nginx metacharacters). 0 = valid.
_serverNames_hostname_re='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
_validate_serverNames_hostname() {
    [[ -n "${1}" ]] || return 1
    [[ "${1}" =~ ${_serverNames_hostname_re} ]] && return 0
    return 1
}

# Validate a *.serverNames fragment: only blank lines or "<host> realm;" entries.
_validate_serverNames_fragment() {
    local _f="$1"
    local _bad
    _bad=$(grep -vE '^[[:space:]]*$' "${_f}" 2>/dev/null |
        grep -vE '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*[[:space:]]+[A-Za-z0-9_-]+;$' 2>/dev/null)
    [[ -z "${_bad}" ]]
}

# Remove stale/corrupt Reality *.serverNames fragments so a previous failed
# install cannot break `nginx -t` and block a reinstall. Skips the current
# ${serverNames} fragment (regenerated by nginx_reality_serverNames_add) and
# preserves valid user files.
_cleanup_stale_serverNames_fragments() {
    local _frag
    [[ -d "${nginx_conf_dir}" ]] || return 0
    for _frag in "${nginx_conf_dir}"/*.serverNames; do
        [[ -f "${_frag}" ]] || continue
        [[ "$(basename "${_frag}")" == "${serverNames}.serverNames" ]] && continue
        if ! _validate_serverNames_fragment "${_frag}"; then
            log_echo "${Warning} ${YellowBG} $(gettext "自愈: 移除损坏的旧 serverNames 配置") ${_frag} ${Font}"
            rm -f "${_frag}"
        fi
    done
    return 0
}

serverNames_set() {
    if [[ ${target_reset} == 1 ]] || [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_serverNames_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") ${target} $(gettext "域名的") serverNames [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Green} $(gettext "默认为") ${target} $(gettext "域名本身")${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
        read -r custom_serverNames_fq
        case $custom_serverNames_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个域名"): " "serverNames" "NULL" || return 1
            while ! _validate_serverNames_hostname "${serverNames}"; do
                log_echo "${Error} ${RedBG} $(gettext "serverNames 仅支持单个合法域名, 请重新输入")! ${Font}"
                read_optimize "$(gettext "请输入单个域名"): " "serverNames" "NULL" || return 1
            done
            ;;
        *)
            serverNames=$target
            ;;
        esac
        log_echo "${Green} serverNames: ${serverNames} ${Font}"
        echo
    fi
}

keys_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_keys_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") privateKey [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_keys_fq
        case $custom_keys_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入") privateKey:" "privateKey" "NULL" || return 1
            local keys
            keys=$(${xray_bin_dir}/xray x25519 -i "${privateKey}")
            password=$(parse_reality_public_key "${keys}")
            ;;
        *)
            local keys
            keys=$(${xray_bin_dir}/xray x25519)
            privateKey=$(echo "${keys}" | awk -F"PrivateKey: " '{print $2}' | awk '{print $1}')
            password=$(parse_reality_public_key "${keys}")
            ;;
        esac
        if [[ -z "${privateKey}" || -z "${password}" ]]; then
            log_echo "${Error} ${RedBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        # privateKey is persisted in config but never printed to the terminal.
        log_echo_secure "${Green} privateKey: $(gettext "已生成并保存（不显示）") ${Font}"
        log_echo_secure "${Green} publicKey (Password): ${password} ${Font}"
        echo
    fi
}

# 兼容 Xray 不同版本的 x25519 输出名称：Password、Password (PublicKey)、PublicKey
parse_reality_public_key() {
    local keys="$1"
    keys=$(printf '%s\n' "${keys}" | tr '\n' ' ')
    if echo "${keys}" | grep -q "Password (PublicKey): "; then
        echo "${keys}" | sed 's/.*Password (PublicKey): //' | awk '{print $1}'
    elif echo "${keys}" | grep -q "Password: "; then
        echo "${keys}" | awk -F"Password: " '{print $2}' | awk '{print $1}'
    elif echo "${keys}" | grep -q "PublicKey: "; then
        echo "${keys}" | awk -F"PublicKey: " '{print $2}' | awk '{print $1}'
    fi
}


shortIds_set() {
    if [[ "on" != ${old_config_status} ]] || [[ ${change_reality} == "yes" ]]; then
        local custom_shortids_fq
        echo
        log_echo "${GreenBG} $(gettext "是否需要自定义") shortIds [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r custom_shortids_fq
        case $custom_shortids_fq in
        [yY][eE][sS] | [yY])
            read_optimize "$(gettext "请输入单个 shortId"): " "shortIds" "NULL" || return 1
            while [[ ! "${shortIds}" =~ ^[0-9a-fA-F]{16}$ ]]; do
                log_echo "${Error} ${RedBG} shortIds $(gettext "值为空或超出范围, 请重新输入")! ${Font}"
                read_optimize "$(gettext "请输入单个 shortId"): " "shortIds" "NULL" || return 1
            done
            ;;
        *)
            # P1-9: openssl is required to generate a real short id.
            pkg_install "openssl" || return 1
            shortIds=$(generate_reality_short_id)
            ;;
        esac
        log_echo_secure "${Green} shortIds: ${shortIds} ${Font}"
        echo
    fi
}

ensure_sub_script() {
    local script_name="$1"
    local remote_url="$2"
    local local_file="${scripts_dir}/${script_name}"

    mkdir -p "${scripts_dir}"
    if [ ! -f "$local_file" ]; then
        log_echo "${Info} ${Green} $(gettext "本地文件") ${script_name} $(gettext "不存在, 正在下载")... ${Font}"
        if ! download_script_file "$remote_url" "$local_file"; then
            log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
            return 1
        fi
    else
        local required_version
        required_version=$(grep '^MIN_MAIN_VERSION=' "$local_file" | head -1 | sed 's/MIN_MAIN_VERSION="//; s/"//')
        if [ -z "$required_version" ]; then
            log_echo "${Warning} ${YellowBG} ${script_name} $(gettext "版本过旧, 建议更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否下载并安装新版本") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            local update_choice
            read -r update_choice
            case $update_choice in
                [yY][eE][sS] | [yY])
                    if ! download_script_file "$remote_url" "$local_file"; then
                        log_echo "${Error} ${RedBG} $(gettext "下载失败, 请手动下载并安装新版本") ${Font}"
                        return 1
                    fi
                    ;;
                *)
                    log_echo "${Warning} ${YellowBG} ${script_name} $(gettext "版本过旧, 可能存在兼容性问题") ${Font}"
                    ;;
            esac
        else
            local oldest
            oldest=$(printf '%s\n%s\n' "$required_version" "$shell_version" | sort -V | head -1)
            if [ "$oldest" != "$required_version" ]; then
                log_echo "${Error} ${RedBG} ${script_name} $(gettext "需要主脚本版本") >= ${required_version}, $(gettext "当前版本"): ${shell_version}, $(gettext "请先更新主脚本") ${Font}"
                return 1
            fi
        fi
    fi
    return 0
}


nginx_upstream_server_set() {
    echo
    log_echo "${GreenBG} $(gettext "是否变更") Nginx $(gettext "负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
    read -r nginx_upstream_server_fq
    case $nginx_upstream_server_fq in
    [yY][eE][sS] | [yY])
        if [[ ${tls_mode} == "TLS" ]]; then
            echo -e "\n${GreenBG} $(gettext "请选择协议为 ws 或 gRPC 或 xHTTP") ${Font}"
            echo "1: ws"
            echo "2: gRPC"
            echo "3: xHTTP"
            echo "4: $(gettext "返回")"
            local upstream_choose
            read_optimize "$(gettext "请输入"): " "upstream_choose" "NULL" 1 4 "$(gettext "请输入有效的数字")!"

            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                case $upstream_choose in
                1) source "${scripts_dir}/file_manager.sh" wsServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                2) source "${scripts_dir}/file_manager.sh" grpcServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                3) source "${scripts_dir}/file_manager.sh" xhttpServers ${nginx_conf_dir}; fm_check_for_updates; fm_main_menu ;;
                4) ;;
                *)
                    log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试")! ${Font}"
                    nginx_upstream_server_set
                    ;;
                esac
            fi
        elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_balance} == "on" ]] && [[ ${reality_add_nginx} == "on" ]]; then
            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                source "${scripts_dir}/file_manager.sh" realityServers ${nginx_conf_dir}
                fm_check_for_updates
                fm_main_menu
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
            return 1
        fi
        ;;
    *) ;;
    esac
}

nginx_servernames_server_set() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        echo
        log_echo "${GreenBG} $(gettext "是否变更") Nginx serverNames [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿继续")! ${Font}"
        echo -e "${Info} ${GreenBG} $(gettext "配置用途可以参考文章"): https://hey.run/posts/use-reality ${Font}"
        read -r nginx_servernames_server_fq
        case $nginx_servernames_server_fq in
        [yY][eE][sS] | [yY])
            if ensure_sub_script "file_manager.sh" "${fm_remote_url}"; then
                source "${scripts_dir}/file_manager.sh" serverNames ${nginx_conf_dir}
                fm_check_for_updates
                fm_main_menu
            fi
        ;;
        *) ;;
        esac
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

UUIDv5_tranc() {
    [[ $# = 0 ]] && return
    python3 -c "import uuid,sys;UUID_NAMESPACE=uuid.UUID('00000000-0000-0000-0000-000000000000');print(uuid.uuid5(UUID_NAMESPACE,sys.argv[1]))" "$1"
}

# ws/gRPC/xHTTP ONLY installs VLESS without any transport encryption, so they
# are meant for a trusted backend link. New deployments listen on loopback
# unless the operator explicitly selects another (internal) address; existing
# installs keep the listen address already written in config.json.
ws_backend_listen_default() {
    printf '127.0.0.1'
}

is_valid_listen_address() {
    local addr="$1" octet
    [[ -n "${addr}" ]] || return 1
    if [[ "${addr}" == *:* ]]; then
        # IPv6 literal: colon-separated hex groups, at most one "::".
        [[ "${addr}" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
        [[ "${addr}" != *":::"* ]] || return 1
        [[ "${addr}" == *:*:* ]] || return 1
        [[ "${addr#*::}" != *"::"* ]] || return 1
        return 0
    fi
    [[ "${addr}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        (( 10#${octet} <= 255 )) || return 1
    done
    return 0
}

resolve_ws_backend_listen_addr() {
    local addr="${ws_backend_listen_addr:-}"
    [[ -n "${addr}" ]] || addr="$(ws_backend_listen_default)"
    if ! is_valid_listen_address "${addr}"; then
        # Must not go to stdout: callers capture this function's output.
        printf '%s\n' "$(gettext "监听地址无效, 已回退到 127.0.0.1")" >&2
        addr="$(ws_backend_listen_default)"
    fi
    printf '%s' "${addr}"
}

modify_listen_address() {
    local listen_addr="0.0.0.0"
    if [[ ${tls_mode} == "TLS" ]]; then
        listen_addr="127.0.0.1"
    elif [[ ${tls_mode} == "None" ]]; then
        listen_addr="$(resolve_ws_backend_listen_addr)"
        log_echo "${Warning} ${YellowBG} $(gettext "无传输层加密的后端入站监听地址"): ${listen_addr} ${Font}"
    fi

    if is_ws_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-ws-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_grpc_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
    if is_xhttp_mode; then
        update_json_config "${xray_conf}" --arg addr "${listen_addr}" '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).listen = $addr'
        judge "Xray listen address $(gettext "修改")"
    fi
}

modify_inbound_port() {
    local _port_failed=0
    if [[ ${tls_mode} == "Reality" ]]; then
        if [[ ${reality_add_nginx} == "off" ]]; then
            update_json_config "${xray_conf}" --argjson port "${port:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-Reality-in")).port = $port' || _port_failed=1
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        else
            if is_ws_mode; then
                update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
            fi
            if is_grpc_mode; then
                update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
            fi
            if is_xhttp_mode; then
                update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
                   '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
            fi
        fi
    else
        if is_ws_mode; then
            update_json_config "${xray_conf}" --argjson xport "${xport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-ws-in")).port = $xport' || _port_failed=1
        fi
        if is_grpc_mode; then
            update_json_config "${xray_conf}" --argjson gport "${gport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).port = $gport' || _port_failed=1
        fi
        if is_xhttp_mode; then
            update_json_config "${xray_conf}" --argjson xhttpport "${xhttpport:-0}" \
               '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).port = $xhttpport' || _port_failed=1
        fi
    fi
    if [[ ${_port_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray inbound port $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Xray inbound port $(gettext "修改") $(gettext "完成") ${Font}"
}

add_ws_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local ws_port="${2:-10086}"
    local ws_path="${3:-/ray/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${ws_port:-0}" \
       --arg path "${ws_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-ws-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "ws@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "ws",
               "security": "none",
               "wsSettings": {"path": $path}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-ws-in"]'
}

add_grpc_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local grpc_port="${2:-10087}"
    local grpc_service="${3:-grpc}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${grpc_port:-0}" \
       --arg serviceName "${grpc_service}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-gRPC-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "me@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "grpc",
               "security": "none",
               "grpcSettings": {"serviceName": $serviceName, "multiMode": true, "idle_timeout": 20}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-gRPC-in"]'
}

add_xhttp_inbound() {
    local listen_addr="${1:-127.0.0.1}"
    local xhttp_port="${2:-10088}"
    local xhttp_path="${3:-xhttp}"
    xhttp_path="/${xhttp_path#/}"
    update_json_config "${xray_conf}" \
       --arg listen "${listen_addr}" \
       --argjson port "${xhttp_port:-0}" \
       --arg xhttp_path "${xhttp_path}" \
       '.inbounds += [{
           "port": $port,
           "listen": $listen,
           "tag": "VLESS-xhttp-in",
           "protocol": "VLESS",
           "settings": {
               "clients": [{"id": "UUID", "level": 0, "email": "xhttp@hey.run"}],
               "decryption": "none"
           },
           "streamSettings": {
               "network": "xhttp",
               "security": "none",
               "xhttpSettings": {"path": $xhttp_path, "mode": "auto"}
           }
       }] |
       .routing.rules[0].inboundTag += ["VLESS-xhttp-in"]'
}

modify_nginx_origin_conf() {
    # Use dedicated idleleo-nginx user for worker process,
    # instead of shared `nobody`. The user/group is created by ensure_idleleo_nginx_user.
    local nginx_worker_user="idleleo-nginx"
    local nginx_worker_group="idleleo-nginx"
    if ! id -u "${nginx_worker_user}" >/dev/null 2>&1; then
        # Fallback to nobody only if user creation failed (defensive, should not happen
        # because ensure_idleleo_nginx_user is called before this function).
        nginx_worker_user="nobody"
        nginx_worker_group="$(id -gn nobody 2>/dev/null || echo nogroup)"
    fi
    if grep -qE '^[[:space:]]*#?[[:space:]]*user[[:space:]]+' "${nginx_dir}"/conf/nginx.conf; then
        sed -i "/^[[:space:]]*#*[[:space:]]*user[[:space:]]/c\\user ${nginx_worker_user} ${nginx_worker_group};" "${nginx_dir}"/conf/nginx.conf
    else
        sed -i "1i user ${nginx_worker_user} ${nginx_worker_group};" "${nginx_dir}"/conf/nginx.conf
    fi
    sed -i "s/worker_processes  1;/worker_processes  auto;/" "${nginx_dir}"/conf/nginx.conf
    sed -i "s/^\( *\)worker_connections  1024;.*/\1worker_connections  4096;/" "${nginx_dir}"/conf/nginx.conf
    sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf};#d" "${nginx_dir}"/conf/nginx.conf
    sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/\*\.conf;#d" "${nginx_dir}"/conf/nginx.conf
    if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "Reality" && ${reality_add_nginx} == "on" ]]; then
        if [[ ${tls_mode} == "Reality" ]]; then
            printf '\ninclude %s;\n' "${nginx_conf}" >> "${nginx_dir}"/conf/nginx.conf
            # Create empty placeholder so nginx -t passes during nginx_install.
            # The actual stream{} block is written later by nginx_reality_conf_add.
            [[ -f "${nginx_conf}" ]] || touch "${nginx_conf}"
        else
            sed -i "\$i include ${nginx_conf_dir}/*.conf;" "${nginx_dir}"/conf/nginx.conf
        fi
    fi
    sed -i "/http\( *\){/a \\\tserver_tokens off;" "${nginx_dir}"/conf/nginx.conf
    sed -i "/error_page.*504/i \\\t\\tif (\$host = '${local_ip}') {\\n\\t\\t\\treturn 403;\\n\\t\\t}" "${nginx_dir}"/conf/nginx.conf
}

# Idempotently create a dedicated idleleo-nginx system user/group.
# - system user (no home, no login shell)
# - reuses existing user if already present
# - does NOT use shared `nobody` identity

# Returns the nginx worker user (idleleo-nginx if exists, else nobody fallback).
# Used for SSL cert ownership and other shared resources that nginx worker must read.
get_nginx_worker_user() {
    if id -u "idleleo-nginx" >/dev/null 2>&1; then
        echo "idleleo-nginx"
    else
        echo "nobody"
    fi
}

# Returns the nginx worker group (idleleo-nginx if exists, else nobody's group).
get_nginx_worker_group() {
    if id -g "idleleo-nginx" >/dev/null 2>&1; then
        echo "idleleo-nginx"
    else
        id -gn nobody 2>/dev/null || echo "nogroup"
    fi
}

ensure_idleleo_nginx_user() {
    local user_name="idleleo-nginx"
    local group_name="idleleo-nginx"
    # Create group first (some systems need group before user)
    if ! getent group "${group_name}" >/dev/null 2>&1; then
        groupadd --system "${group_name}" 2>/dev/null || \
            addgroup --system "${group_name}" 2>/dev/null || true
    fi
    if ! id -u "${user_name}" >/dev/null 2>&1; then
        # Create system user with no login shell and no home
        useradd --system --gid "${group_name}" --shell /usr/sbin/nologin --no-create-home "${user_name}" 2>/dev/null || \
            adduser --system --ingroup "${group_name}" --shell /usr/sbin/nologin --no-create-home "${user_name}" 2>/dev/null || true
    fi
    # Verify
    if ! id -u "${user_name}" >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} idleleo-nginx $(gettext "用户创建失败, 将回退到 nobody") ${Font}"
        return 1
    fi
    return 0
}

# Apply layered permission model to Nginx directory tree.
# Layered model:
#   - Binary and modules: root:root, 755 (only root can modify program)
#   - Config dir/files:   root:idleleo-nginx, dir 750, files 640 (worker can read, not write)
#   - HTML/static:        root:idleleo-nginx, dir 750, files 640 (worker read-only)
#   - Logs/temp dirs:     idleleo-nginx:idleleo-nginx, 750 (worker writes here)
#   - pid file: handled by systemd (root master creates it)
apply_nginx_layered_permissions() {
    local worker_user="idleleo-nginx"
    local worker_group="idleleo-nginx"
    local failed=0
    if ! id -u "${worker_user}" >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} idleleo-nginx $(gettext "用户不存在, 跳过分层权限") ${Font}"
        return 1
    fi

    local nginx_root="${nginx_dir}"
    [[ ! -d "${nginx_root}" ]] && return 0

    # 0) Parent directory: root:root 755 (worker user must traverse to reach subdirs)
    chown root:root "${nginx_root}" 2>/dev/null || failed=1
    chmod 755 "${nginx_root}" 2>/dev/null || failed=1

    # 1) Binary and modules: root:root 755 (only root can modify program)
    if [[ -f "${nginx_root}/sbin/nginx" ]]; then
        chown root:root "${nginx_root}/sbin/nginx" 2>/dev/null || failed=1
        chmod 755 "${nginx_root}/sbin/nginx" 2>/dev/null || failed=1
    fi
    if [[ -d "${nginx_root}/modules" ]]; then
        chown -R root:root "${nginx_root}/modules" 2>/dev/null || failed=1
        find "${nginx_root}/modules" -type d -exec chmod 755 {} + 2>/dev/null || failed=1
        find "${nginx_root}/modules" -type f -exec chmod 644 {} + 2>/dev/null || failed=1
    fi

    # 2) Built-in conf dir: root:idleleo-nginx dir 750, files 640
    if [[ -d "${nginx_root}/conf" ]]; then
        chown root:"${worker_group}" "${nginx_root}/conf" 2>/dev/null || failed=1
        chmod 750 "${nginx_root}/conf" 2>/dev/null || failed=1
        while IFS= read -r -d '' conf_file; do
            chown root:"${worker_group}" "$conf_file" 2>/dev/null || failed=1
            chmod 640 "$conf_file" 2>/dev/null || failed=1
        done < <(find "${nginx_root}/conf" -type f -print0 2>/dev/null)
    fi

    # 3) Project conf dir (/etc/idleleo/conf/nginx/): root:idleleo-nginx dir 750, files 640
    if [[ -d "${nginx_conf_dir}" ]]; then
        chown root:"${worker_group}" "${nginx_conf_dir}" 2>/dev/null || failed=1
        chmod 750 "${nginx_conf_dir}" 2>/dev/null || failed=1
        while IFS= read -r -d '' conf_file; do
            chown root:"${worker_group}" "$conf_file" 2>/dev/null || failed=1
            chmod 640 "$conf_file" 2>/dev/null || failed=1
        done < <(find "${nginx_conf_dir}" -type f -print0 2>/dev/null)
    fi

    # 4) HTML/static content: root:idleleo-nginx dir 750, files 640 (worker read-only)
    if [[ -d "${nginx_root}/html" ]]; then
        chown root:"${worker_group}" "${nginx_root}/html" 2>/dev/null || failed=1
        chmod 750 "${nginx_root}/html" 2>/dev/null || failed=1
        while IFS= read -r -d '' static_file; do
            chown root:"${worker_group}" "$static_file" 2>/dev/null || failed=1
            chmod 640 "$static_file" 2>/dev/null || failed=1
        done < <(find "${nginx_root}/html" -type f -print0 2>/dev/null)
        find "${nginx_root}/html" -type d -exec chmod 750 {} + 2>/dev/null || failed=1
    fi

    # 5) Logs/temp dirs: idleleo-nginx:idleleo-nginx 750 (worker must write here)
    local writable_dir
    for writable_dir in logs client_body_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
        if [[ -d "${nginx_root}/${writable_dir}" ]]; then
            chown -R "${worker_user}:${worker_group}" "${nginx_root}/${writable_dir}" 2>/dev/null || failed=1
            find "${nginx_root}/${writable_dir}" -type d -exec chmod 750 {} + 2>/dev/null || failed=1
            find "${nginx_root}/${writable_dir}" -type f -exec chmod 640 {} + 2>/dev/null || failed=1
        fi
    done

    # 6) SSL certificate directory (/etc/idleleo/cert/): root:idleleo-nginx dir 750, files 640
    # Certs and private keys must be readable by worker, not writable.
    if [[ -d "${ssl_chainpath}" ]]; then
        chown root:"${worker_group}" "${ssl_chainpath}" 2>/dev/null || failed=1
        chmod 750 "${ssl_chainpath}" 2>/dev/null || failed=1
        while IFS= read -r -d '' cert_file; do
            chown root:"${worker_group}" "$cert_file" 2>/dev/null || failed=1
            # Root owns, worker group can read but NOT write.
            # Private key: 640 (root rw, idleleo-nginx r, others none)
            # Public cert: 640 (root rw, idleleo-nginx r, others none)
            chmod 640 "$cert_file" 2>/dev/null || failed=1
        done < <(find "${ssl_chainpath}" -type f -print0 2>/dev/null)
    fi

    if [[ ${failed} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限应用不完整") ${Font}"
        return 1
    fi
    return 0
}

verify_nginx_layered_permissions() {
    local worker_user="idleleo-nginx"
    local worker_group="idleleo-nginx"
    local nginx_root="${nginx_dir}"
    local path actual

    id -u "${worker_user}" >/dev/null 2>&1 || return 1
    [[ -d "${nginx_root}" ]] || return 1

    if [[ -f "${nginx_root}/sbin/nginx" ]]; then
        actual=$(stat -c '%U:%G %a' "${nginx_root}/sbin/nginx" 2>/dev/null) || return 1
        [[ "${actual}" == "root:root 755" ]] || return 1
    else
        return 1
    fi

    for path in "${nginx_root}/conf" "${nginx_conf_dir}" "${nginx_root}/html" "${ssl_chainpath}"; do
        [[ -d "${path}" ]] || continue
        actual=$(stat -c '%U:%G %a' "${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "root:${worker_group} 750" ]] || return 1
    done

    while IFS= read -r -d '' path; do
        actual=$(stat -c '%U:%G %a' "${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "root:${worker_group} 640" ]] || return 1
    done < <(
        {
            [[ -d "${nginx_root}/conf" ]] && find "${nginx_root}/conf" -type f -print0 2>/dev/null
            [[ -d "${nginx_conf_dir}" ]] && find "${nginx_conf_dir}" -type f -print0 2>/dev/null
            [[ -d "${nginx_root}/html" ]] && find "${nginx_root}/html" -type f -print0 2>/dev/null
            [[ -d "${ssl_chainpath}" ]] && find "${ssl_chainpath}" -type f -print0 2>/dev/null
        }
    )

    for path in logs client_body_temp proxy_temp fastcgi_temp uwsgi_temp scgi_temp; do
        [[ -d "${nginx_root}/${path}" ]] || continue
        actual=$(stat -c '%U:%G %a' "${nginx_root}/${path}" 2>/dev/null) || return 1
        [[ "${actual}" == "${worker_user}:${worker_group} 750" ]] || return 1
    done

    # Prove the worker can read but not write TLS private keys when one exists.
    if [[ -f "${ssl_chainpath}/xray.key" ]]; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u "${worker_user}" -- test -r "${ssl_chainpath}/xray.key" || return 1
            if runuser -u "${worker_user}" -- test -w "${ssl_chainpath}/xray.key"; then
                return 1
            fi
        elif command -v su >/dev/null 2>&1; then
            su -s /bin/sh "${worker_user}" -c "test -r '${ssl_chainpath}/xray.key'" || return 1
            if su -s /bin/sh "${worker_user}" -c "test -w '${ssl_chainpath}/xray.key'"; then
                return 1
            fi
        else
            return 1
        fi
    fi

    return 0
}

modify_nginx_port() {
    if [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
        sed -i "s/^\( *\)listen.*so_keepalive=on.*/\1listen ${port} reuseport so_keepalive=on backlog=65535;/" "${nginx_conf}"
        judge "Nginx port $(gettext "修改")"
    elif [[ ${tls_mode} == "TLS" ]]; then
        sed -i "s/^\( *\)listen [^[]*ssl reuseport;$/\1listen ${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*ssl reuseport;$/\1listen [::]:${port} ssl reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen [^[]*quic reuseport;$/\1listen ${port} quic reuseport;/" "${nginx_conf}"
        sed -i "s/^\( *\)listen \[::\].*quic reuseport;$/\1listen [::]:${port} quic reuseport;/" "${nginx_conf}"
        judge "Xray port $(gettext "修改")"
    fi
    [[ "on" != ${old_config_status} ]] && log_echo "${OK} ${GreenBG} $(gettext "端口"): ${port} ${Font}"
}

modify_nginx_ssl_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" "${nginx_dir}"/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    local escaped_domain
    escaped_domain=$(sed_escape "${domain}")
    sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${escaped_domain};/g" "${nginx_ssl_conf}"
    sed -i "s/^\( *\)return 301.*/\1return 301 https:\/\/${escaped_domain}\$request_uri;/" "${nginx_ssl_conf}"
}

modify_nginx_other() {
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]] && [[ $(grep -c "server_tokens off;" "${nginx_dir}"/conf/nginx.conf) -eq '0' ]] && [[ ${save_originconf} != "Yes" ]]; then
        modify_nginx_origin_conf
    fi
    if [[ ${tls_mode} == "TLS" ]]; then
        local escaped_domain escaped_path escaped_serviceName escaped_xhttppath
        escaped_domain=$(sed_escape "${domain}")
        escaped_path=$(sed_escape "${path}")
        escaped_serviceName=$(sed_escape "${serviceName}")
        escaped_xhttppath=$(sed_escape "${xhttppath}")
        sed -i "s/^\( *\)server_name\( *\).*/\1server_name\2${escaped_domain};/g" "${nginx_conf}"
        if is_ws_mode; then
            sed -i "s/^\( *\)location ws$/\1location \/${escaped_path}/" "${nginx_conf}"
            sed -i "s/^\( *\)#proxy_pass http:\/\/xray-ws-server;/\1proxy_pass http:\/\/xray-ws-server;/" "${nginx_conf}"
        else
            sed -i "/^\s*location ws$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_grpc_mode; then
            sed -i "s/^\( *\)location grpc$/\1location \/${escaped_serviceName}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location grpc$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
        if is_xhttp_mode; then
            sed -i "s/^\( *\)location xhttp$/\1location \/${escaped_xhttppath}/" "${nginx_conf}"
            sed -i "s/^\( *\)#grpc_pass\(.*xray-xhttp-server\)/\1grpc_pass\2/" "${nginx_conf}"
        else
            sed -i "/^\s*location xhttp$/,/^\s*}/s/^/#/" "${nginx_conf}"
        fi
    fi
}

nginx_servers_add() {
    if is_ws_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.wsServers
        cat >"${nginx_conf_dir}"/127.0.0.1.wsServers <<EOF
server 127.0.0.1:${xport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
    if is_grpc_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.grpcServers
        cat >"${nginx_conf_dir}"/127.0.0.1.grpcServers <<EOF
server 127.0.0.1:${gport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
    if is_xhttp_mode; then
        touch "${nginx_conf_dir}"/127.0.0.1.xhttpServers
        cat >"${nginx_conf_dir}"/127.0.0.1.xhttpServers <<EOF
server 127.0.0.1:${xhttpport} weight=50 max_fails=2 fail_timeout=10;
EOF
    fi
}


modify_path() {
    local _path_failed=0
    is_ws_mode && { update_json_config "${xray_conf}" --arg ws_path "/${path}" \
       '(.inbounds[] | select(.tag == "VLESS-ws-in")).streamSettings.wsSettings.path = $ws_path' || _path_failed=1; }
    is_grpc_mode && { update_json_config "${xray_conf}" --arg serviceName "${serviceName}" \
       '(.inbounds[] | select(.tag == "VLESS-gRPC-in")).streamSettings.grpcSettings.serviceName = $serviceName' || _path_failed=1; }
    is_xhttp_mode && { update_json_config "${xray_conf}" --arg xhttp_path "/${xhttppath#/}" \
       '(.inbounds[] | select(.tag == "VLESS-xhttp-in")).streamSettings.xhttpSettings.path = $xhttp_path' || _path_failed=1; }
    if [[ ${_path_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "失败") ${Font}"
        return 1
    fi
    if [[ ${tls_mode} == "Reality" ]] && [[ "$reality_add_more" == "off" ]]; then
        log_echo "${Warning} ${YellowBG} Reality $(gettext "不支持") path ${Font}"
    else
        log_echo "${OK} ${GreenBG} Xray $(gettext "伪装路径") $(gettext "修改") $(gettext "完成") ${Font}"
    fi
}

modify_email_address() {
    local multi_user
    multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}")
    if [[ "${multi_user}" == "true" ]]; then
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除多余的用户") ${Font}"
    else
        update_json_config "${xray_conf}" --arg custom_email "${custom_email}" \
           '(.inbounds[].settings.clients[].email) = $custom_email'
        judge "Xray $(gettext "用户名修改")"
    fi
}

modify_UUID() {
    local multi_user
    multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}")
    if [[ "${multi_user}" == "true" ]]; then
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除多余的用户") ${Font}"
    else
        update_json_config "${xray_conf}" --arg UUID "${UUID}" \
           '(.inbounds[].settings.clients[].id) = $UUID'
        judge "Xray UUID $(gettext "修改")"
    fi
}

modify_target_serverNames() {
  update_json_config "${xray_conf}" --arg target "${target}:443" --arg serverName "${serverNames}" '
     .inbounds[0].streamSettings.realitySettings.target = $target |
     .inbounds[0].streamSettings.realitySettings.serverNames = [$serverName]'
  judge "target serverNames $(gettext "配置修改")"
}

modify_privateKey_shortIds() {
  update_json_config "${xray_conf}" --arg privateKey "${privateKey}" --arg shortId "${shortIds}" '
     .inbounds[0].streamSettings.realitySettings.privateKey = $privateKey |
     .inbounds[0].streamSettings.realitySettings.shortIds = [$shortId]'
  judge "privateKey shortIds $(gettext "配置修改")"
}

# ---- REALITY 客户端版本下限 -------------------------------------------------
# Xray 26.7.11 起，realitySettings.minClientVer 未显式设置时按 26.3.27 处理，
# 于是仍在报旧版本号的客户端（Mihomo/Clash 硬编码 1.8.2，部分旧版 v2rayN /
# Shadowrocket）会直接握手失败。上游 issue: XTLS/Xray-core#6482，处置办法是
# 显式写 minClientVer。这里只补齐缺失的字段，用户自己设过的值一律不动。
reality_min_client_ver="1.0.0"

reality_min_client_ver_repair() {
    local missing backup
    [[ -f "${xray_conf}" ]] || return 0
    is_relay_role && return 0
    # 只统计 reality 入站里缺这个字段的数量；配置不可解析时什么都不做。
    missing=$(jq -r '[.inbounds[]? | select(.streamSettings.security == "reality")
        | select((.streamSettings.realitySettings.minClientVer // "") == "")] | length' \
        "${xray_conf}" 2>/dev/null) || return 0
    [[ "${missing}" =~ ^[0-9]+$ ]] || return 0
    (( missing > 0 )) || return 0

    backup=$(mktemp "${xray_conf}.reality.XXXXXX" 2>/dev/null) || return 0
    cp -p "${xray_conf}" "${backup}" || { rm -f "${backup}"; return 0; }

    if ! update_json_config "${xray_conf}" --arg v "${reality_min_client_ver}" '
        .inbounds |= map(
            if (.streamSettings.security == "reality")
               and ((.streamSettings.realitySettings.minClientVer // "") == "")
            then .streamSettings.realitySettings.minClientVer = $v
            else . end)'; then
        cp -p "${backup}" "${xray_conf}" 2>/dev/null || true
        rm -f "${backup}"
        log_echo "${Warning} ${YellowBG} $(gettext "写入 REALITY minClientVer 失败, 已恢复原配置") ${Font}"
        return 0
    fi
    # 配置必须仍能被 Xray 接受；不接受就逐字节还原，绝不留下坏配置。
    if [[ -x "${xray_bin_dir}/xray" ]] &&
        ! XRAY_LOCATION_ASSET="${geodata_dir}" "${xray_bin_dir}/xray" run -test -config "${xray_conf}" >/dev/null 2>&1; then
        cp -p "${backup}" "${xray_conf}" 2>/dev/null || true
        rm -f "${backup}"
        log_echo "${Warning} ${YellowBG} $(gettext "加入 minClientVer 后配置测试失败, 已恢复原配置") ${Font}"
        return 0
    fi
    rm -f "${backup}"
    log_echo "${OK} ${GreenBG} $(gettext "已为 REALITY 入站补上 minClientVer"): ${reality_min_client_ver} ${Font}"
    return 0
}

# 生成 16 位 hex shortId，openssl 优先，/dev/urandom 兜底
generate_reality_short_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8 2>/dev/null || tr -dc 'a-f0-9' </dev/urandom | head -c 16
    else
        tr -dc 'a-f0-9' </dev/urandom | head -c 16
    fi
}

# 从少量普通路径模板中随机生成 spiderX，结果以 / 开头，仅含 a-z0-9/. 字符
generate_spiderx() {
    local r
    r=$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 8)
    [[ -z "${r}" ]] && r="default$(date +%s | tail -c 5)"
    case $((RANDOM % 4)) in
        0) echo "/assets/${r}.css" ;;
        1) echo "/static/${r}.js" ;;
        2) echo "/docs/${r}/index.html" ;;
        *) echo "/api/status/${r}" ;;
    esac
}

# spiderX 设置：仅新安装或新增客户端时生成，不改动老用户已有配置
spiderx_set() {
    if [[ "${old_config_status}" != "on" ]] || [[ ${change_reality} == "yes" ]]; then
        spiderx_path=$(generate_spiderx)
        log_echo "${Green} spiderX: ${spiderx_path} ${Font}"
    fi
}

# 收紧敏感配置文件权限：不影响 Xray 读取 config.json 与证书
# install_config/分享文件仅 root 可读；config.json 由实际服务账号持有
# SSL certs/keys must be root-owned with worker group read (640).
apply_sensitive_file_permissions() {
    local file="$1"
    local owner="$2"
    local mode="${3:-600}"
    [[ -f "${file}" ]] || return 0
    if ! chown "${owner}" "${file}" 2>/dev/null || ! chmod "${mode}" "${file}" 2>/dev/null; then
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${file} ${Font}"
        return 1
    fi
    return 0
}

# Xray-install 生成的 systemd 单元账号会随上游变化（旧版 User=nobody，
# 新版 User=xray）。config.json 与 /var/log/xray 的所有权必须跟随实际单元账号，
# 否则升级后 Xray 读不到旧账号持有的配置，报 status=23 permission denied。
xray_service_user() {
    local _user="" _file _value
    for _file in "${xray_systemd_file}" "${xray_systemd_file}.d"/*.conf; do
        [[ -f "${_file}" ]] || continue
        _value=$(sed -n 's/^[[:space:]]*User[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${_file}" | tail -n 1)
        [[ -n "${_value}" ]] && _user="${_value}"
    done
    if [[ -z "${_user}" ]]; then
        if id nobody >/dev/null 2>&1; then
            _user="nobody"
        else
            _user="root"
        fi
    fi
    printf '%s\n' "${_user}"
}

xray_service_group() {
    local _user="$1"
    id -gn "${_user}" 2>/dev/null || printf '%s\n' "${_user}"
}

# A readable config is insufficient when an older install or a restrictive
# umask left one of its parent directories inaccessible to the service user.
xray_config_directory_permissions() {
    local user group directory
    user=$(xray_service_user)
    group=$(xray_service_group "${user}")
    for directory in "${idleleo_dir}" "${idleleo_conf_dir}"; do
        [[ -d "${directory}" ]] || continue
        # Traversal only: do not expose directory listings or private files.
        chmod a+x "${directory}" || return 1
    done
    for directory in "${xray_conf_dir}" "${xray_default_conf%/*}"; do
        [[ -d "${directory}" ]] || continue
        chown "root:${group}" "${directory}" || return 1
        chmod 750 "${directory}" || return 1
    done
}

harden_config_permissions() {
    local failed=0
    local _nginx_worker_group
    local _xray_service_user _xray_service_group

    # An existing Nginx tree can predate the dedicated worker account (for
    # example, upgrades and Docker images shared by non-Nginx install modes).
    # Create the account before resolving the group or applying the layered
    # model; otherwise an unrelated Reality-only install fails merely
    # because Nginx happens to be present on disk.
    if [[ -d "${nginx_dir}" ]] && ! ensure_idleleo_nginx_user; then
        failed=1
    fi
    _nginx_worker_group=$(get_nginx_worker_group)
    _xray_service_user=$(xray_service_user)
    _xray_service_group=$(xray_service_group "${_xray_service_user}")

    xray_config_directory_permissions || failed=1
    if [[ -d /var/log/xray ]]; then
        chown -R "${_xray_service_user}:${_xray_service_group}" /var/log/xray || failed=1
    fi
    apply_sensitive_file_permissions "${xray_install_config_file}" "root:root" || failed=1
    apply_sensitive_file_permissions "${xray_conf}" "${_xray_service_user}:${_xray_service_group}" || failed=1
    # Root owns certs/keys, worker group can read but NOT write.
    # Private key: 640 (root rw, idleleo-nginx r, others none)
    # Public cert: 640 (root rw, idleleo-nginx r, others none)
    apply_sensitive_file_permissions "${ssl_chainpath}/xray.key" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/xray.crt" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.key" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.crt" "root:${_nginx_worker_group}" 640 || failed=1
    apply_sensitive_file_permissions "${xray_info_file}" "root:root" || failed=1
    apply_sensitive_file_permissions "${xray_info_file%.*}_clash.yaml" "root:root" || failed=1
    if [[ -d "${nginx_dir}" ]]; then
        apply_nginx_layered_permissions || failed=1
        verify_nginx_layered_permissions || failed=1
    fi
    return "${failed}"
}

modify_reality_listen_address () {
    update_json_config "${xray_conf}" '.inbounds[0].listen = "127.0.0.1"'
    judge "Xray reality listen address $(gettext "配置修改")"
}

xray_privilege_escalation() {
    local _xray_service_user _xray_service_group
    _xray_service_user=$(xray_service_user)
    _xray_service_group=$(xray_service_group "${_xray_service_user}")
    xray_config_directory_permissions || return 1
    # Even User=root may lack CAP_DAC_OVERRIDE under the unit's capability
    # bounding set, so it must own logs left at 600 by a previous account.
    mkdir -p /var/log/xray/ || return 1
    chown -fR "${_xray_service_user}:${_xray_service_group}" /var/log/xray/ || return 1
    # Access logs carry every client address/SNI: keep the directory and the
    # log files readable by the service account and its group only (750/640)
    # instead of the previous world-readable 755/644. logrotate uses
    # copytruncate and runs as root, and this script's diagnostics run as root,
    # so no other local account needs access.
    chmod -f 750 /var/log/xray/ || return 1
    find /var/log/xray/ -type f -exec chmod -f 640 {} + || return 1
    if [[ "${_xray_service_user}" != "root" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "检测到 Xray 的权限控制, 启动修改程序") ${Font}"
        # 安装器切换服务账号后（nobody -> xray），已存在的配置必须同步归属，
        # 否则升级或回滚后 Xray 仍会因 permission denied 启动失败。
        apply_sensitive_file_permissions "${xray_conf}" "${_xray_service_user}:${_xray_service_group}" || return 1
        # SSL cert files must be owned by root, not worker.
        # xray_privilege_escalation() must NOT change cert ownership to worker user.
        # Only apply_nginx_layered_permissions() and harden_config_permissions()
        # are authoritative for cert permission model (root:idleleo-nginx 640).
        if [[ -d "${nginx_dir}" ]]; then
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
        fi
    else
        apply_sensitive_file_permissions "${xray_conf}" "root:root" || return 1
    fi
    # The official installer re-installs geoip.dat/geosite.dat with `install -m
    # 644`, which resets them to root:root on every update. Restore the service
    # account's write access so the native schedule keeps working; configuration
    # and key paths are deliberately untouched here.
    if geodata_native_configured; then
        geodata_apply_permissions || \
            log_echo "${Warning} ${YellowBG} $(gettext "GeoData 文件权限恢复失败") ${Font}"
    fi
    log_echo "${OK} ${GreenBG} Xray $(gettext "修改") $(gettext "完成") ${Font}"
}

set_xray_config_path() {
    local _default_geo_dir="${local_bin}/share/xray"
    # A legacy real asset directory must go through the same transactional
    # migration as the startup hook: hidden files, same-name conflicts and a
    # partial .dat set are all handled there. Never move/overwrite inline.
    # Run it before touching the config symlink so a failure leaves no trace.
    if [[ -d "${_default_geo_dir}" && ! -L "${_default_geo_dir}" ]]; then
        geodata_migrate_asset_layout || return 1
    fi
    [[ -L "${xray_default_conf}" || -e "${xray_default_conf}" ]] && rm -f "${xray_default_conf}"
    ln -s "${xray_conf}" "${xray_default_conf}" || return 1
    if [[ ! -L "${_default_geo_dir}" ]]; then
        ln -s "${geodata_dir}" "${_default_geo_dir}" || return 1
    fi
}

# ---- GeoData 原生下载与热更新 ------------------------------------------------
# Xray 自带 geodata 模块：按 cron 下载 .dat 并热重载，不重启进程。普通节点改用
# 这个原生路径，脚本不再为它安装自己的 cron + geo_update.sh（后者保留为手动
# 刷新工具）。纯中转节点只有 Nginx，不生成任何 GeoData 配置。
geodata_dir="${idleleo_dir}/share/xray"
# Weekly, matching the legacy cron so the update cadence does not change.
geodata_cron="0 3 * * 1"
# The data source is unchanged (Loyalsoldier), so routing rule sets keep the
# exact same semantics as before. HTTPS is mandatory for native assets.
geodata_source_base="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"

# Resolve a directory to its physical path without relying on `readlink -f`
# (the local test host runs the macOS userland, production runs GNU coreutils).
_geodata_realpath() {
    local target="${1:-}"
    [[ -n "${target}" && -e "${target}" ]] || return 1
    ( cd -- "${target}" 2>/dev/null && pwd -P )
}

# The canonical managed geodata object. Emitted identically every run so that a
# byte comparison can tell "our" block from a user-authored one.
geodata_managed_json() {
    jq -n --arg cron "${geodata_cron}" --arg base "${geodata_source_base}" \
        '{cron: $cron, assets: [
            {url: ($base + "/geoip.dat"), file: "geoip.dat"},
            {url: ($base + "/geosite.dat"), file: "geosite.dat"}
        ]}'
}

# absent | managed | custom | invalid
geodata_state() {
    local current
    [[ -f "${xray_conf}" ]] || { printf '%s\n' absent; return 0; }
    current=$(jq -c '.geodata // null' "${xray_conf}" 2>/dev/null) || {
        printf '%s\n' invalid
        return 0
    }
    if [[ "${current}" == "null" ]]; then
        printf '%s\n' absent
        return 0
    fi
    if [[ "$(printf '%s' "${current}" | jq -S -c . 2>/dev/null)" == \
        "$(geodata_managed_json | jq -S -c . 2>/dev/null)" ]]; then
        printf '%s\n' managed
    else
        printf '%s\n' custom
    fi
}

# Xray resolves geoip.dat/geosite.dat from XRAY_LOCATION_ASSET, else "./" then
# /usr/local/share/xray. This is the directory the running process really reads.
geodata_asset_root() {
    local file value
    for file in "${xray_systemd_file}" "${xray_systemd_file}.d"/*.conf; do
        [[ -f "${file}" ]] || continue
        value=$(sed -n 's/.*XRAY_LOCATION_ASSET=\([^[:space:]"]*\).*/\1/p' "${file}" | tail -n 1)
        [[ -n "${value}" ]] && { printf '%s\n' "${value}"; return 0; }
    done
    printf '%s\n' "${local_bin}/share/xray"
}

# systemd sandbox: a strict ProtectSystem without a matching ReadWritePaths
# makes the native download impossible even when the mode bits look right.
geodata_sandbox_allows_write() {
    local file value protect="" writable="" token
    for file in "${xray_systemd_file}" "${xray_systemd_file}.d"/*.conf; do
        [[ -f "${file}" ]] || continue
        value=$(sed -n 's/^[[:space:]]*ProtectSystem[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' "${file}" | tail -n 1)
        [[ -n "${value}" ]] && protect="${value}"
        value=$(sed -n 's/^[[:space:]]*ReadWritePaths[[:space:]]*=[[:space:]]*//p' "${file}")
        [[ -n "${value}" ]] && writable="${writable} ${value}"
    done
    case "${protect}" in
        strict | full | yes | true) ;;
        *) return 0 ;;
    esac
    for token in ${writable}; do
        [[ "${token#-}" == "${geodata_dir}" ]] && return 0
    done
    return 1
}

geodata_files_ok() {
    local name
    for name in geoip.dat geosite.dat; do
        [[ -f "${geodata_dir}/${name}" && ! -L "${geodata_dir}/${name}" ]] || return 1
    done
    return 0
}

# Both .dat files must exist as real regular files inside the directory the
# running Xray actually reads. Native geodata refuses to invent them: Xray only
# replaces files it can already resolve, and a missing asset means the routing
# rules would silently change.
geodata_prepare_layout() {
    local name asset_root
    mkdir -p "${geodata_dir}" 2>/dev/null || {
        log_echo "${Warning} ${YellowBG} $(gettext "无法创建 GeoData 资源目录") ${Font}"
        return 1
    }
    if ! geodata_files_ok; then
        log_echo "${Warning} ${YellowBG} $(gettext "缺少 geoip.dat/geosite.dat, 跳过 GeoData 原生配置") ${Font}"
        return 1
    fi
    asset_root=$(geodata_asset_root)
    if [[ ! -e "${asset_root}" ]] || \
        [[ "$(_geodata_realpath "${asset_root}")" != "$(_geodata_realpath "${geodata_dir}")" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "GeoData 资源目录与 Xray 实际读取路径不一致, 跳过原生配置"): ${asset_root} ${Font}"
        return 1
    fi
    if ! geodata_sandbox_allows_write; then
        log_echo "${Warning} ${YellowBG} $(gettext "systemd 沙箱禁止写入 GeoData 资源目录, 跳过原生配置") ${Font}"
        return 1
    fi
    return 0
}

# Only the asset directory and the two .dat files are opened up. config.json,
# private keys and certificates keep their existing owner/mode: the service
# account gets write access to nothing but the data files it must replace.
# The 0660/0770 pair is the state this script establishes. After the first
# native download Xray writes the replacements itself (observed mode 0644,
# still owned by the service account), so what must hold over time is the
# ownership plus directory write access -- not the exact mode bits.
geodata_apply_permissions() {
    local user group name failed=0
    [[ -d "${geodata_dir}" ]] || return 0
    geodata_files_ok || return 0
    user=$(xray_service_user)
    group=$(xray_service_group "${user}")
    if [[ "${user}" == "root" ]]; then
        chmod 0755 "${geodata_dir}" || failed=1
        for name in geoip.dat geosite.dat; do
            chmod 0644 "${geodata_dir}/${name}" || failed=1
        done
        return "${failed}"
    fi
    # Group-writable directory: Xray downloads to a temporary file and renames
    # it over the old one, so the directory itself must be writable as well.
    chown "root:${group}" "${geodata_dir}" || failed=1
    chmod 0770 "${geodata_dir}" || failed=1
    for name in geoip.dat geosite.dat; do
        chown "${user}:${group}" "${geodata_dir}/${name}" || failed=1
        chmod 0660 "${geodata_dir}/${name}" || failed=1
    done
    return "${failed}"
}

# Mode bits alone do not prove DAC access (ACLs, read-only mounts). Probe as the
# service account when the tooling exists; a failure is reported, not fatal.
geodata_service_can_write() {
    local user
    user=$(xray_service_user)
    [[ "${user}" == "root" ]] && return 0
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "${user}" -- test -w "${geodata_dir}" 2>/dev/null || return 1
        runuser -u "${user}" -- test -w "${geodata_dir}/geoip.dat" 2>/dev/null || return 1
        return 0
    fi
    if command -v su >/dev/null 2>&1; then
        su -s /bin/sh "${user}" -c "test -w '${geodata_dir}' && test -w '${geodata_dir}/geoip.dat'" 2>/dev/null || return 1
        return 0
    fi
    return 0
}

geodata_config_test() {
    local binary="${xray_bin_dir}/xray"
    [[ -x "${binary}" ]] || return 1
    XRAY_LOCATION_ASSET="${geodata_dir}" "${binary}" run -test -config "${xray_conf}" >/dev/null 2>&1
}

geodata_native_configured() {
    [[ "$(geodata_state)" == "managed" ]]
}

# Low-memory hosts are the one documented caveat of the native path.
geodata_low_memory_notice() {
    local mem_kb
    mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)
    [[ -n "${mem_kb}" ]] || return 0
    (( mem_kb < 1048576 )) || return 0
    log_echo "${Warning} ${YellowBG} $(gettext "低内存设备 (小于 1 GiB): GeoData 自动刷新会有短暂内存峰值, 请留意") ${Font}"
}

# Write the managed block into the live Xray config. A user-authored geodata
# object is never overwritten; an unparsable config is left alone.
geodata_apply_config() {
    local state
    state=$(geodata_state)
    case "${state}" in
        managed)
            return 0
            ;;
        custom)
            log_echo "${Info} ${Green} $(gettext "检测到自定义 geodata 配置, 保留原样") ${Font}"
            return 0
            ;;
        invalid)
            log_echo "${Warning} ${YellowBG} $(gettext "Xray 配置无法解析, 跳过 GeoData 原生配置") ${Font}"
            return 1
            ;;
    esac
    update_json_config "${xray_conf}" --argjson geodata "$(geodata_managed_json)" \
        '.geodata = $geodata'
}

# Enable native GeoData refresh on a normal node. Never runs for role=relay.
geodata_native_enable() {
    local state backup
    is_relay_role && return 0
    [[ -x "${xray_bin_dir}/xray" ]] || return 0
    [[ -f "${xray_conf}" ]] || return 0

    geodata_low_memory_notice
    geodata_prepare_layout || return 0

    state=$(geodata_state)
    if [[ "${state}" == "custom" || "${state}" == "invalid" ]]; then
        geodata_apply_config
        geodata_apply_permissions || return 1
        return 0
    fi
    if [[ "${state}" == "managed" ]]; then
        # Idempotent re-run (reinstall / reconfigure): keep the block, re-assert
        # ownership because the official installer resets .dat to root:root 644.
        geodata_apply_permissions || return 1
        geodata_service_can_write || \
            log_echo "${Warning} ${YellowBG} $(gettext "Xray 服务账号仍无法写入 GeoData 文件, 自动刷新可能失败") ${Font}"
        return 0
    fi

    # A config that is already invalid is not ours to fix: skip instead of
    # breaking an otherwise working install.
    if ! geodata_config_test; then
        log_echo "${Warning} ${YellowBG} $(gettext "当前 Xray 配置未通过 xray run -test, 跳过 GeoData 原生配置") ${Font}"
        return 0
    fi

    backup=$(mktemp "${xray_conf}.geodata.XXXXXX" 2>/dev/null) || return 1
    cp -p "${xray_conf}" "${backup}" || { rm -f "${backup}"; return 1; }
    if ! geodata_apply_config; then
        rm -f "${backup}"
        return 1
    fi
    # Fail closed: a config Xray rejects must never reach the service.
    if ! geodata_config_test; then
        cp -p "${backup}" "${xray_conf}" || true
        rm -f "${backup}"
        log_echo "${Error} ${RedBG} $(gettext "加入 geodata 后 Xray 配置测试失败, 已恢复原配置") ${Font}"
        return 1
    fi
    rm -f "${backup}"
    if ! geodata_apply_permissions; then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 文件权限设置失败") ${Font}"
        return 1
    fi
    geodata_service_can_write || \
        log_echo "${Warning} ${YellowBG} $(gettext "Xray 服务账号仍无法写入 GeoData 文件, 自动刷新可能失败") ${Font}"
    log_echo "${OK} ${GreenBG} $(gettext "已启用 Xray 原生 GeoData 自动刷新"): ${geodata_cron} ${Font}"
    return 0
}

# Only the cron entry this script itself created is removed: the line must point
# at the managed geo_update.sh path. Hand-written schedules are left untouched.
geodata_legacy_cron_lines() {
    command -v crontab >/dev/null 2>&1 || return 1
    crontab -l 2>/dev/null | awk -v script="${geo_update_file}" 'index($0, script) > 0'
}

# A real (non-symlink) /usr/local/share/xray tree is the second legacy marker.
# Without one of these two markers there is nothing to migrate, and the startup
# hook deliberately leaves an absent .geodata block alone: a user who removed
# the block on purpose must not get it re-enabled on the next launch.
geodata_legacy_evidence() {
    local lines default_dir="${local_bin}/share/xray"
    if lines=$(geodata_legacy_cron_lines 2>/dev/null) && [[ -n "${lines}" ]]; then
        return 0
    fi
    [[ -d "${default_dir}" && ! -L "${default_dir}" ]]
}

# Xray reads the geodata block at process start; an existing install that is
# already running will not pick up the new schedule until it is restarted.
# Inactive hosts need no restart: the next service start reads the new config.
geodata_restart_if_active() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl is-active --quiet xray 2>/dev/null || return 0
    geodata_force_restart
}

# Rollback must start Xray even when the failed migration already stopped it.
geodata_force_restart() {
    command -v systemctl >/dev/null 2>&1 || return 0
    systemctl restart xray 2>/dev/null || return 1
    systemctl is-active --quiet xray 2>/dev/null || return 1
    return 0
}

# Runs after the service is confirmed healthy: with the native schedule live, a
# second external updater would restart Xray on its own and double the work.
geodata_legacy_cron_disable() {
    local lines state
    is_relay_role && return 0
    command -v crontab >/dev/null 2>&1 || return 0
    state=$(geodata_state)
    [[ "${state}" == "managed" ]] || return 0
    lines=$(geodata_legacy_cron_lines) || return 0
    [[ -n "${lines}" ]] || return 0
    if crontab -l 2>/dev/null | awk -v script="${geo_update_file}" 'index($0, script) == 0' | crontab -; then
        log_echo "${OK} ${GreenBG} $(gettext "已移除脚本创建的 geo_update.sh 周期任务, 避免与原生自动刷新重复执行") ${Font}"
        return 0
    fi
    log_echo "${Warning} ${YellowBG} $(gettext "移除 geo_update.sh 周期任务失败, 请手动检查 crontab") ${Font}"
    return 1
}

# Legacy installs may still have /usr/local/share/xray as a real directory.
# Xray's default asset root is that path, while this script and the legacy
# updater write ${geodata_dir}; leaving both trees in place makes an update
# succeed on disk but invisible to the running binary. Copy first, then replace
# the old tree with a symlink; never delete source data before it is copied.
geodata_migrate_asset_layout() {
    local default_dir="${local_bin}/share/xray"
    local target backup
    if [[ ! -e "${default_dir}" && ! -L "${default_dir}" ]]; then
        # A previous migration or a manual cleanup may have removed the symlink
        # while the managed directory still holds the assets. Restore the link
        # so Xray's default asset root keeps resolving.
        [[ -d "${geodata_dir}" ]] && geodata_files_ok || return 0
        if ! ln -s "${geodata_dir}" "${default_dir}"; then
            log_echo "${Warning} ${YellowBG} $(gettext "GeoData 资源目录软链创建失败"): ${default_dir} ${Font}"
            return 1
        fi
        log_echo "${OK} ${GreenBG} $(gettext "已恢复 GeoData 资源目录软链"): ${default_dir} ${Font}"
        return 0
    fi
    if [[ -L "${default_dir}" ]]; then
        target=$(_geodata_realpath "${default_dir}") || return 1
        [[ "${target}" == "$(_geodata_realpath "${geodata_dir}")" ]] && return 0
        log_echo "${Warning} ${YellowBG} $(gettext "GeoData 软链指向其他目录, 跳过自动迁移"): ${target} ${Font}"
        return 1
    fi
    [[ -d "${default_dir}" ]] || return 1
    # Scan every entry before touching anything: a legacy subdirectory, symlink
    # or device must never be silently deleted by the later `rm -rf backup`.
    local entry base non_regular="" copied=()
    for entry in "${default_dir}"/* "${default_dir}"/.[!.]* "${default_dir}"/..?*; do
        [[ -e "${entry}" || -L "${entry}" ]] || continue
        if [[ -L "${entry}" || ! -f "${entry}" ]]; then
            non_regular="${entry##*/}"
            break
        fi
    done
    if [[ -n "${non_regular}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 目录包含非普通条目, 跳过迁移并保留原目录"): ${non_regular} ${Font}"
        return 1
    fi
    mkdir -p "${geodata_dir}" || return 1
    # Merge regular files, but never overwrite a file the legacy updater has
    # already written into ${geodata_dir}. The old directory remains readable
    # until the managed path has both .dat files, so a failed migration cannot
    # leave Xray with a half-moved asset directory.
    for entry in "${default_dir}"/* "${default_dir}"/.[!.]* "${default_dir}"/..?*; do
        [[ -e "${entry}" || -L "${entry}" ]] || continue
        [[ -f "${entry}" && ! -L "${entry}" ]] || continue
        base="${entry##*/}"
        if [[ ! -e "${geodata_dir}/${base}" && ! -L "${geodata_dir}/${base}" ]]; then
            if ! cp -p -- "${entry}" "${geodata_dir}/${base}"; then
                if (( ${#copied[@]} > 0 )); then
                    for base in "${copied[@]}"; do rm -f "${geodata_dir}/${base}"; done
                fi
                log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 文件复制失败, 保留原目录"): ${entry} ${Font}"
                return 1
            fi
            copied+=("${base}")
        fi
    done
    if ! geodata_files_ok; then
        if (( ${#copied[@]} > 0 )); then
            for base in "${copied[@]}"; do rm -f "${geodata_dir}/${base}"; done
        fi
        log_echo "${Warning} ${YellowBG} $(gettext "迁移后缺少 geoip.dat/geosite.dat, 保留原目录"): ${default_dir} ${Font}"
        return 1
    fi
    backup="${default_dir}.legacy-migrate.$$"
    if ! mv "${default_dir}" "${backup}"; then
        log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 目录替换失败, 保留原目录"): ${default_dir} ${Font}"
        return 1
    fi
    if ! ln -s "${geodata_dir}" "${default_dir}"; then
        if ! mv "${backup}" "${default_dir}" 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "GeoData 目录迁移失败且无法恢复, 请手动检查"): ${backup} ${Font}"
        fi
        return 1
    fi
    # A same-named file in ${geodata_dir} wins by policy. If its content differs
    # from the legacy copy, keep the old tree as a backup instead of deleting it.
    local keep_backup=0
    for entry in "${backup}"/* "${backup}"/.[!.]* "${backup}"/..?*; do
        [[ -e "${entry}" || -L "${entry}" ]] || continue
        [[ -f "${entry}" && ! -L "${entry}" ]] || continue
        base="${entry##*/}"
        if [[ -e "${geodata_dir}/${base}" ]] && ! cmp -s -- "${entry}" "${geodata_dir}/${base}"; then
            keep_backup=1
            break
        fi
    done
    if [[ ${keep_backup} -eq 1 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 存在同名不同内容的文件, 旧目录备份保留于"): ${backup} ${Font}"
    else
        rm -rf "${backup}" 2>/dev/null || \
            log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 迁移备份未清理"): ${backup} ${Font}"
    fi
    log_echo "${OK} ${GreenBG} $(gettext "已将旧 GeoData 目录迁移到"): ${geodata_dir} ${Font}"
    return 0
}

geodata_migration_failure_path() {
    printf '%s\n' "${idleleo_dir}/geodata_migration.failed"
}

# A marker survives the failing process so the menu can distinguish "native is
# running" from "migration was attempted and failed, old cron retained".
geodata_migration_clear_failed() {
    rm -f "$(geodata_migration_failure_path)" 2>/dev/null || true
}

geodata_migration_mark_failed() {
    local reason="$1"
    {
        printf 'status=failed\n'
        printf 'reason=%s\n' "${reason}"
        printf 'time=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    } >"$(geodata_migration_failure_path)" 2>/dev/null || true
}

# One-time bridge from the external geo_update.sh cron to Xray's native
# scheduler. It is intentionally invoked from every mutable startup (including
# the -u path) so old installs are repaired without requiring a reinstall.
# Custom geodata, invalid configs, layout conflicts and config-test failures
# all leave the legacy cron untouched (fail closed).
geodata_migrate_legacy() {
    local state backup="" restored
    is_relay_role && { geodata_migration_clear_failed; return 0; }
    [[ -x "${xray_bin_dir}/xray" && -f "${xray_conf}" ]] || return 0
    state=$(geodata_state)
    # Automatic, but only when there is something to migrate. A managed block
    # is re-asserted every startup so the official installer resetting asset
    # ownership is repaired; an absent block with no legacy marker is respected
    # as a deliberate opt-out.
    if [[ "${state}" != "managed" ]] && ! geodata_legacy_evidence; then
        return 0
    fi
    case "${state}" in
        custom)
            geodata_migration_clear_failed
            log_echo "${Info} ${Green} $(gettext "检测到自定义 geodata 配置, 保留原样且不改动旧刷新任务") ${Font}"
            return 0
            ;;
        invalid)
            geodata_migration_mark_failed invalid_config
            log_echo "${Warning} ${YellowBG} $(gettext "Xray 配置无法解析, 保留旧 GeoData 刷新任务") ${Font}"
            return 1
            ;;
        absent)
            # Snapshot before the write so a post-write service failure can
            # restore the exact pre-migration config, not just a config that
            # happens to parse.
            backup=$(mktemp "${xray_conf}.legacy-migrate.XXXXXX" 2>/dev/null) || {
                geodata_migration_mark_failed snapshot
                return 1
            }
            if ! cp -p "${xray_conf}" "${backup}"; then
                rm -f "${backup}"
                geodata_migration_mark_failed snapshot
                return 1
            fi
            ;;
    esac
    if ! geodata_migrate_asset_layout; then
        [[ -n "${backup}" ]] && rm -f "${backup}"
        geodata_migration_mark_failed layout
        log_echo "${Warning} ${YellowBG} $(gettext "GeoData 路径迁移失败, 保留旧刷新任务") ${Font}"
        return 1
    fi
    if ! geodata_native_enable; then
        [[ -n "${backup}" ]] && rm -f "${backup}"
        geodata_migration_mark_failed native_enable
        log_echo "${Warning} ${YellowBG} $(gettext "GeoData 自动刷新启用失败, 保留旧刷新任务") ${Font}"
        return 1
    fi
    if [[ "$(geodata_state)" != "managed" ]]; then
        [[ -n "${backup}" ]] && rm -f "${backup}"
        geodata_migration_mark_failed native_state
        log_echo "${Warning} ${YellowBG} $(gettext "GeoData 自动刷新配置未生效, 保留旧刷新任务") ${Font}"
        return 1
    fi
    # Only the absent -> managed transition needs a restart. A managed block
    # found on entry is already what the running process reads.
    if [[ "${state}" == "absent" ]]; then
        if ! geodata_restart_if_active; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 重启失败, 正在回滚 GeoData 原生配置") ${Font}"
            restored=false
            if cp -p "${backup}" "${xray_conf}"; then
                if geodata_force_restart; then
                    restored=true
                fi
            fi
            if [[ "${restored}" == "true" ]]; then
                rm -f "${backup}"
                geodata_migration_mark_failed restart
                log_echo "${Warning} ${YellowBG} $(gettext "已恢复原配置并重启 Xray, 保留旧刷新任务") ${Font}"
            else
                geodata_migration_mark_failed recovery_required
                log_echo "${Error} ${RedBG} $(gettext "RECOVERY REQUIRED: 原配置恢复或服务重启失败, 备份保留于") ${backup} ${Font}"
            fi
            return 1
        fi
        rm -f "${backup}"
    fi
    if ! geodata_legacy_cron_disable; then
        geodata_migration_mark_failed cron_cleanup
        log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 刷新任务移除失败, 请手动检查 crontab") ${Font}"
        return 1
    fi
    if [[ "${state}" == "absent" ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "GeoData 已从脚本模式切换为自动刷新 (Xray 原生)") ${Font}"
    fi
    geodata_migration_clear_failed
    return 0
}

xray_install() {
    local current_xray_version
    current_xray_version=$(xray version 2>/dev/null | head -1 | awk '{print $2}')
    # 已有二进制也必须与清单钉定版本一致；否则外部装上的最新版会被直接沿用。
    if [[ -z "${current_xray_version}" ]] || [[ ! -f "${xray_conf}" ]] ||
        [[ -n "${xray_online_version}" && "${current_xray_version}" != "${xray_online_version}" ]]; then
        # An install converges to the pinned version, so a locally newer binary
        # is replaced too. Say so out loud: silently moving backwards is exactly
        # what the update path refuses to do.
        if version_gt "${current_xray_version}" "${xray_online_version}"; then
            log_echo "${Warning} ${YellowBG} $(gettext "本机版本高于清单钉定版本, 将按清单重新安装") : v${current_xray_version} → v${xray_online_version} ${Font}"
        fi
        log_echo "${OK} ${GreenBG} $(gettext "即将安装") Xray v${xray_online_version} ${Font}"
        xray_install_release install -f --version v${xray_online_version}
        judge "$(gettext "安装") Xray"
        xray_privilege_escalation || return 1
        if ! set_xray_config_path; then
            log_echo "${Error} ${RedBG} $(gettext "GeoData 布局迁移失败, 已中止安装") ${Font}"
            return 1
        fi
        systemctl daemon-reload
        xray_version=${xray_online_version}
    else
        log_echo "${OK} ${GreenBG} $(gettext "已安装") Xray ${Font}"
        xray_version="${current_xray_version}"
    fi
}

xray_install_pinned_and_check() {
    local _version="$1"
    xray_install_release install -f --version "v${_version}" || return 1
    systemctl daemon-reload || return 1
    # 安装器可能切换 systemd 服务账号，先同步配置/日志归属，再重启跑健康检查。
    xray_privilege_escalation || return 1
    systemctl restart xray || return 1
    health_check_xray_update "${_version}"
}

xray_update() {
    local current_xray_version
    local update_rolled_back=0
    rxa_reconfigure_enter
    trap 'rxa_reconfigure_leave $?' RETURN
    current_xray_version=$(info_extraction xray_version)
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    # The metadata can regress: a reverted API release, a stale CDN copy, or a
    # hand-edited version file. "Different" must never be read as "newer", so
    # this refuses to move backwards. Same-version reinstall still works, and an
    # empty/unknown installed version falls through to the normal path.
    if version_gt "${current_xray_version}" "${xray_online_version}"; then
        log_echo "${Warning} ${YellowBG} $(gettext "已安装版本高于在线清单, 不执行降级") ${Font}"
        log_echo "${Info} $(gettext "已安装") : v${current_xray_version} ${Font}"
        log_echo "${Info} $(gettext "在线清单") : v${xray_online_version} ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "如确需降级, 请手动指定版本或先卸载再安装") ${Font}"
        return 0
    fi
    # 核心更新会带来 REALITY 客户端版本策略变化；在重启前补齐 minClientVer，
    # 让本次重启同时生效（已显式设置的配置不受影响）。
    reality_min_client_ver_repair
    # COMPAT: 旧版依赖 /usr/local/etc/xray 目录存放默认配置，新版不再使用，未来可删除
    [[ ! -d "${local_bin}/etc/xray" ]] && log_echo "${GreenBG} $(gettext "若更新无效, 建议直接卸载再安装")! ${Font}"
    log_echo "${Warning} ${GreenBG} $(gettext "部分新功能需要重新安装才可生效") ${Font}"
    if [[ ${current_xray_version} != ${xray_online_version} ]]; then
        log_echo "${Info} ${GreenBG} Xray $(gettext "更新"): v${current_xray_version} → v${xray_online_version} ${Font}"
        if [[ ${auto_update} != "YES" ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "检测到存在最新版") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "脚本可能未兼容此版本") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_test_fq
            case $xray_test_fq in
            [yY][eE][sS] | [yY])
                log_echo "${OK} ${GreenBG} $(gettext "更新") Xray ! ${Font}"
                # Backup current binary as Layer 1 rollback source
                # Backup must succeed before proceeding — refuse to overwrite without backup
                if ! backup_xray_binary; then
                    log_echo "${Error} ${RedBG} $(gettext "本机备份失败, 拒绝继续更新")! ${Font}"
                    return 1
                fi
                systemctl stop xray
                # Install + comprehensive health check
                # (binary exec / version match / config parse / service active / port listening)
                if xray_install_pinned_and_check "${xray_online_version}"; then
                    xray_version=${xray_online_version}
                    judge "Xray $(gettext "更新")" true
                else
                    log_echo "${Error} ${RedBG} Xray $(gettext "更新") $(gettext "失败")! ${Font}"
                    xray_diagnose
                    log_echo "${Warning} ${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                    case $rollback_fq in
                    [nN][oO] | [nN])
                        log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                        log_echo "${Error} ${RedBG} Xray $(gettext "更新失败且未回滚, 当前服务可能不可用, 请手动检查")! ${Font}"
                        if ! systemctl is-active xray >/dev/null 2>&1; then
                            log_echo "${Error} ${RedBG} $(gettext "高优先级错误: Xray 服务已停止")! ${Font}"
                        fi
                        return 1
                        ;;
                    *)
                        log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                        # Layer 1 = local pre-update backup restore
                        if restore_xray_binary_backup; then
                            log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Xray $(gettext "版本")! ${Font}"
                            xray_version=${current_xray_version}
                            update_rolled_back=1
                        else
                            # Layer 2 = tested_version known-good fallback
                            log_echo "${Info} ${YellowBG} $(gettext "Layer 1 失败, 尝试 Layer 2 tested_version 恢复") ${Font}"
                            if fallback_xray_to_tested_version; then
                                xray_version=${xray_tested_version}
                                update_rolled_back=1
                            else
                                # Layer 3 = stop + diagnostics (already printed above)
                                log_echo "${Error} ${RedBG} Xray $(gettext "回滚失败")! ${Font}"
                                return 1
                            fi
                        fi
                        ;;
                    esac
                fi
                ;;
            *)
                return 0
                ;;
            esac
        else
            # Auto-update mode — non-interactive, automated layered rollback
            # Backup must succeed before proceeding — refuse to overwrite without backup
            if ! backup_xray_binary; then
                echo "$(gettext "本机备份失败, 拒绝继续更新")!" >>"${log_file}"
                return 1
            fi
            systemctl stop xray
            if xray_install_pinned_and_check "${xray_online_version}"; then
                xray_version=${xray_online_version}
            else
                xray_diagnose
                # Layer 1 = local backup restore
                if restore_xray_binary_backup; then
                    xray_version=${current_xray_version}
                    update_rolled_back=1
                elif fallback_xray_to_tested_version; then
                    # Layer 2 = tested_version
                    xray_version=${xray_tested_version}
                    update_rolled_back=1
                else
                    # Layer 3 = stop + diagnostics (already printed above)
                    echo "Xray $(gettext "回滚失败")!" >>"${log_file}"
                    return 1
                fi
            fi
        fi
    else
        countdown "$(gettext "重装") Xray !"
        # Backup before reinstall too (reinstall may corrupt the binary)
        # Backup must succeed — refuse to overwrite without backup
        if ! backup_xray_binary; then
            log_echo "${Error} ${RedBG} $(gettext "本机备份失败, 拒绝继续重装")! ${Font}"
            return 1
        fi
        systemctl stop xray
        xray_version=${xray_online_version}
        # Same-version reinstall must have layered rollback
        if xray_install_pinned_and_check "${xray_online_version}"; then
            judge "Xray $(gettext "重装")" true
        else
            log_echo "${Error} ${RedBG} Xray $(gettext "重装") $(gettext "失败")! ${Font}"
            xray_diagnose
            # Layer 1: local backup restore
            if [[ ${auto_update} != "YES" ]]; then
                log_echo "${Warning} ${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r rollback_fq
                case $rollback_fq in
                [nN][oO] | [nN])
                    log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                    return 1
                    ;;
                esac
            fi
            log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
            if restore_xray_binary_backup; then
                log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Xray $(gettext "版本")! ${Font}"
                xray_version=${current_xray_version}
                update_rolled_back=1
            elif fallback_xray_to_tested_version; then
                # Layer 2: tested_version fallback
                xray_version=${xray_tested_version}
                update_rolled_back=1
            else
                # Layer 3: stop + diagnostics (already printed above)
                log_echo "${Error} ${RedBG} Xray $(gettext "回滚失败")! ${Font}"
                return 1
            fi
        fi
    fi
    xray_privilege_escalation || return 1
    if ! set_xray_config_path; then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 布局迁移失败, 已中止更新") ${Font}"
        return 1
    fi
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version' || return 1
    systemctl daemon-reload
    systemctl start xray
    # Final health gate — must pass before declaring success
    if ! health_check_xray_update "${xray_version}"; then
        [[ ${auto_update} == "YES" ]] && echo "Xray $(gettext "更新") $(gettext "失败")!" >>"${log_file}"
        [[ ${auto_update} != "YES" ]] && log_echo "${Error} ${RedBG} Xray $(gettext "更新") $(gettext "失败")! ${Font}"
        xray_diagnose
        return 1
    fi
    # 服务恢复成功 ≠ 本次更新成功
    # 无论手动还是自动模式，只要发生过回滚（update_rolled_back=1），
    # 本次更新即为失败，必须返回非零。不得用 auto_update 决定失败操作的返回码。
    if [[ ${update_rolled_back} -eq 1 ]]; then
        return 1
    fi
    return 0
}

reality_balance_add_fq() {
    # Install wizard preset: reality_add_balance already set by apply_install_profile.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_balance} == "on" ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "已启用") ${Font}"
        else
            log_echo "${OK} ${GreenBG} $(gettext "已跳过") ${Font}"
        fi
        return 0
    fi
    echo
    log_echo "${GreenBG} $(gettext "是否添加 Reality 负载均衡") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    echo -e "${Warning} ${Green} $(gettext "使用此功能前，建议先阅读作者教程")! ${Font}"
    echo -e "${Warning} ${YellowBG} $(gettext "如不清楚具体用途, 请勿选择")! ${Font}"
    read -r reality_balance_add_fq
    case $reality_balance_add_fq in
        [yY][eE][sS] | [yY])
            reality_add_balance="on"
            log_echo "${OK} ${GreenBG} $(gettext "已启用") ${Font}"
        ;;
        *)
            reality_add_balance="off"
            log_echo "${OK} ${GreenBG} $(gettext "已跳过") ${Font}"
        ;;

    esac
}


# 通过公网 DNS 解析域名的 A/AAAA 记录，逐行返回 IP 或空字符串。
# 关键设计：DNS 记录类型与 DNS transport 解耦。AAAA 记录同样通过 IPv4
# 可达的 resolver 查询，因此 IPv4-only 服务器无需 IPv6 网络也能发现并校验
# 域名上是否存在 AAAA（进而识别错误/陈旧 AAAA）。dig 依次尝试主备 IPv4
# resolver，全部失败后再回退系统 resolver；其他 DNS 工具分支本就通过 IPv4
# name server 同时查询 A 与 AAAA，无需改动。
resolve_domain_ips() {
    local domain="$1" result
    if command -v dig >/dev/null 2>&1; then
        local rtype res out
        result=""
        for rtype in A AAAA; do
            out=""
            for res in @8.8.8.8 @1.1.1.1; do
                out=$(dig +short +time=3 +tries=1 "${rtype}" "${domain}" "${res}" 2>/dev/null)
                [[ -n "${out}" ]] && break
            done
            # 主备公网 resolver 均失败时才回退系统 resolver（不区分记录类型）
            if [[ -z "${out}" ]]; then
                out=$(dig +short +time=3 +tries=1 "${rtype}" "${domain}" 2>/dev/null)
            fi
            result="${result}${out}"$'\n'
        done
        result=$(printf '%s' "${result}" |
            grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$' | awk '!seen[$0]++')
    elif command -v nslookup >/dev/null 2>&1; then
        result=$({ nslookup -type=A "${domain}" 8.8.8.8 2>/dev/null; nslookup -type=AAAA "${domain}" 8.8.8.8 2>/dev/null; } |
            awk '/^Address:/ && $2 !~ /8\.8\.[0-9.]+|8\.8\.4\.4/ {print $2}' | awk '!seen[$0]++')
    elif command -v host >/dev/null 2>&1; then
        result=$({ host -t A "${domain}" 8.8.8.8 2>/dev/null; host -t AAAA "${domain}" 8.8.8.8 2>/dev/null; } |
            awk '/has address/ {print $4} /has IPv6 address/ {print $5}' | awk '!seen[$0]++')
    else
        result=$({ curl -fsSL --connect-timeout 5 "https://dns.google/resolve?name=${domain}&type=A" 2>/dev/null; \
                   curl -fsSL --connect-timeout 5 "https://dns.google/resolve?name=${domain}&type=AAAA" 2>/dev/null; } |
            jq -r '.Answer[]? | select(.type==1 or .type==28) | .data' 2>/dev/null | awk '!seen[$0]++')
    fi
    echo "${result}"
}

# 判断 needle 是否出现在 ip 集合中，按规范化（canonical）形式比较，避免
# 2001:db8::1 与 2001:0db8:0:0:0:0:0:1 这类字符串不同但地址相同的误判。
ip_in_list() {
    local needle="$1"
    local n candidate c
    n=$(normalize_ip_literal "${needle}")
    while IFS= read -r candidate; do
        [[ -n "${candidate}" ]] || continue
        c=$(normalize_ip_literal "${candidate}")
        [[ -n "${c}" && "${c}" == "${n}" ]] && return 0
    done <<<"${2:-}"
    return 1
}

ip_lists_overlap() {
    local local_ips="$1"
    local remote_ips="$2"
    local remote_ip
    while IFS= read -r remote_ip; do
        ip_in_list "${remote_ip}" "${local_ips}" && return 0
    done <<<"${remote_ips}"
    return 1
}

# A/AAAA 集合资格检查：探测本机公网 v4/v6 与域名 A/AAAA，按 family 独立校验。
# 复用 resolve_domain_ips（单一 DNS 语义源），不依赖 ping 取单个地址。
# 策略参数 policy（第 2 参数）：
#   auto（默认）、ipv4、ipv6。显式 IPv4/IPv6 选择同样执行完整 qualification，
#   绝不因用户显式选择某 family 而绕过另一 family 的记录检查。
# 回填全局 network_mode / ipv4_address / ipv6_address / resolved_ipv4s / resolved_ipv6s。
# 返回码：
#   0 = 校验通过（ipv4 / ipv6 / dual，network_mode 已设置）
#   2 = 存在错误 A 或 AAAA 记录的高风险（已识别，需调用方显式确认）
#   1 = 校验失败（无匹配 family，network_mode=none）
validate_domain_network_records() {
    local domain="$1"
    local policy="${2:-auto}"
    local resolved has_server_v4 has_server_v6 has_a has_aaaa a_ok aaaa_ok
    local bad_aaaa bad_a

    # 1) 服务器侧公网能力探测（出口探测成功才算可用）
    ipv4_address=$(get_public_ip "IPv4")
    ipv6_address=$(get_public_ip "IPv6")
    has_server_v4=0; [[ -n "${ipv4_address}" ]] && has_server_v4=1
    has_server_v6=0; [[ -n "${ipv6_address}" ]] && has_server_v6=1

    # 2) 解析域名 A/AAAA（复用统一 DNS helper）
    resolved=$(resolve_domain_ips "${domain}")
    classify_resolved_ips "${resolved}"
    has_a=0;   [[ -n "${resolved_ipv4s}" ]] && has_a=1
    has_aaaa=0;[[ -n "${resolved_ipv6s}" ]] && has_aaaa=1

    # 3) 按 family 独立校验：集合内“至少一个”匹配本机公网地址即视为该 family 可用。
    #    同一 family 的其余记录（负载均衡等场景）不判坏，仅作 warning。
    a_ok=0
    if [[ ${has_server_v4} -eq 1 && ${has_a} -eq 1 ]]; then
        ip_lists_overlap "$(printf '%b' "${resolved_ipv4s}")" "${ipv4_address}" && a_ok=1
    fi
    aaaa_ok=0
    if [[ ${has_server_v6} -eq 1 && ${has_aaaa} -eq 1 ]]; then
        ip_lists_overlap "$(printf '%b' "${resolved_ipv6s}")" "${ipv6_address}" && aaaa_ok=1
    fi

    # 4) 依据策略判定 network_mode，并识别错误 A/AAAA（高风险）。
    bad_a=0;   bad_aaaa=0
    case "${policy}" in
        ipv4)
            # 显式 IPv4：用户明确选定 IPv4 即 exposure policy，不因另一族 DNS 也正确
            # 而自动提升为 dual。但 AAAA 若存在且不匹配本机有效 v6 仍判高风险
            # (bad_aaaa)，安全校验不能因显式 family 被绕过。
            if [[ ${a_ok} -eq 1 ]]; then
                network_mode="ipv4"
                [[ ${has_aaaa} -eq 1 && ${aaaa_ok} -eq 0 ]] && bad_aaaa=1
            else
                network_mode="none"
            fi
            ;;
        ipv6)
            # 显式 IPv6：对称语义，network_mode 固定为 ipv6；A 若存在且不匹配本机
            # 有效 v4 仍判高风险 (bad_a)。
            if [[ ${aaaa_ok} -eq 1 ]]; then
                network_mode="ipv6"
                [[ ${has_a} -eq 1 && ${a_ok} -eq 0 ]] && bad_a=1
            else
                network_mode="none"
            fi
            ;;
        *)
            # auto：A 匹配 + AAAA 匹配 -> dual；仅 A -> ipv4；仅 AAAA -> ipv6；
            # 另一 family 存在记录但未匹配 -> 高风险。
            if [[ ${a_ok} -eq 1 && ${aaaa_ok} -eq 1 ]]; then
                network_mode="dual"
            elif [[ ${a_ok} -eq 1 ]]; then
                network_mode="ipv4"
                [[ ${has_aaaa} -eq 1 ]] && bad_aaaa=1
            elif [[ ${aaaa_ok} -eq 1 ]]; then
                network_mode="ipv6"
                [[ ${has_a} -eq 1 ]] && bad_a=1
            else
                network_mode="none"
            fi
            ;;
    esac

    # 5) 结构化输出（供日志/诊断）
    log_echo "IPv4: server=$( [[ ${has_server_v4} -eq 1 ]] && echo ok || echo no ), A=$( [[ ${has_a} -eq 1 ]] && echo yes || echo no )$( [[ ${a_ok} -eq 1 ]] && echo ", match" )"
    log_echo "IPv6: server=$( [[ ${has_server_v6} -eq 1 ]] && echo ok || echo no ), AAAA=$( [[ ${has_aaaa} -eq 1 ]] && echo yes || echo no )$( [[ ${aaaa_ok} -eq 1 ]] && echo ", match" )"

    if [[ ${bad_aaaa} -eq 1 || ${bad_a} -eq 1 ]]; then
        return 2
    fi
    [[ "${network_mode}" != "none" ]] && return 0
    return 1
}

# SNI Guard 策略选择：仅新安装时交互，默认 isolate
sni_guard_policy_choose() {
    local force_choose="${1:-}"
    [[ ${reality_add_nginx} != "on" ]] && return 0
    # 老用户升级：不强行改配置，按已有/默认值处理
    [[ "${force_choose}" != "force" && "${old_config_status}" == "on" ]] && return 0

    echo
    log_echo "${GreenBG} $(gettext "异常 SNI 处理方式") ${Font}"
    echo -e "${Green}1${Font}: $(gettext "隔离异常流量, 不转发到 Xray") ($(gettext "推荐"))"
    echo -e "${Green}2${Font}: $(gettext "使用指向本机 IP 的自建 HTTPS 站点作为回落") ($(gettext "高级"))"
    echo -e "${Green}3${Font}: $(gettext "直接拒绝异常 TLS 连接") ($(gettext "高级"))"
    echo -e "${Warning} $(gettext "第 2 项需要你已有自己的域名, 并且该域名的 A/AAAA 记录指向本机公网 IP。若不了解含义, 请使用默认隔离策略。") ${Font}"
    local sni_policy_choice
    read_optimize "$(gettext "请输入选项") ($(gettext "默认值"):1):" "sni_policy_choice" 1 1 3 "$(gettext "请输入有效的数字")!" || return 1
    # 切换策略前先清理旧的 isolate/decoy http 块配置（03-isolate.conf / 03-decoy.conf + include）
    decoy_conf_remove
    case ${sni_policy_choice} in
        2)
            if decoy_site_setup; then
                unknown_sni_policy="decoy"
            else
                log_echo "${Warning} ${YellowBG} $(gettext "decoy 站点设置失败, 回退到默认隔离策略") ${Font}"
                unknown_sni_policy="isolate"
            fi
            ;;
        3)
            unknown_sni_policy="reject"
            log_echo "${OK} ${GreenBG} $(gettext "已选择直接拒绝异常 TLS 连接") ${Font}"
            ;;
        *)
            unknown_sni_policy="isolate"
            log_echo "${OK} ${GreenBG} $(gettext "已选择隔离异常流量") ${Font}"
            ;;
    esac
    reality_nginx_sni_guard="on"
}

add_sni_guard_http_include() {
    local config_name="$1"
    local include_line="include ${nginx_conf_dir}/${config_name};"
    [[ -f "${nginx_dir}/conf/nginx.conf" ]] || return 1
    if ! grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null; then
        sed -i "/^http[[:space:]]*{/a \\    ${include_line}" "${nginx_dir}/conf/nginx.conf" || return 1
    fi
    grep -q "${include_line}" "${nginx_dir}/conf/nginx.conf" 2>/dev/null
}

write_isolate_site_config() {
    mkdir -p "${nginx_conf_dir}"
    cat >"${nginx_conf_dir}/03-isolate.conf" <<'HTTPCONF'
# isolate 策略 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 server 触发 TLS alert
server {
    listen 127.0.0.1:9403 ssl;
    ssl_reject_handshake on;
    access_log off;
    error_log /dev/null;
}
HTTPCONF
    add_sni_guard_http_include "03-isolate.conf"
}

decoy_site_artifacts_ready() {
    local decoy_webroot="${idleleo_dir}/decoy"
    [[ -n "${decoy_domain}" ]] || return 1
    [[ -f "${ssl_chainpath}/decoy.key" && -f "${ssl_chainpath}/decoy.crt" && -f "${decoy_webroot}/index.html" ]]
}

write_decoy_site_config() {
    local decoy_webroot="${idleleo_dir}/decoy"
    decoy_site_artifacts_ready || return 1

    mkdir -p "${nginx_conf_dir}"
    cat >"${nginx_conf_dir}/03-decoy.conf" <<EOF
# decoy 回落站点 - 由 SNI Guard 自动生成，未知 SNI 流量回落到此 HTTPS 站点
server {
    listen 127.0.0.1:9444 ssl;
    server_name ${decoy_domain};
    ssl_certificate ${ssl_chainpath}/decoy.crt;
    ssl_certificate_key ${ssl_chainpath}/decoy.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    root ${decoy_webroot};
    index index.html;
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    add_sni_guard_http_include "03-decoy.conf"
}

sni_guard_port_conflicts() {
    local guard_port="$1"
    local configured_port
    for configured_port in "${port:-}" "${xport:-}" "${gport:-}" "${xhttpport:-}"; do
        [[ -n "${configured_port}" && "${configured_port}" == "${guard_port}" ]] && return 0
    done
    return 1
}

# decoy 站点设置：校验域名指向本机、生成自签证书、生成 Nginx HTTPS 站点
decoy_site_setup() {
    echo
    log_echo "${GreenBG} $(gettext "decoy 站点设置") ${Font}"
    log_echo "${Warning} $(gettext "请输入你自己的域名, 该域名的 A/AAAA 记录必须指向本机公网 IP") ${Font}"
    local decoy_input decoy_resolved local_ips
    read_optimize "$(gettext "请输入 decoy 域名"): " "decoy_input" "NULL" || return 1
    if [[ ! "${decoy_input}" =~ ^[A-Za-z0-9.-]+$ || "${decoy_input}" != *.* ]]; then
        log_echo "${Error} ${RedBG} $(gettext "请输入 decoy 域名") ${Font}"
        return 1
    fi

    # 解析域名 A/AAAA 记录并与本机公网 IP 比对
    decoy_resolved=$(resolve_domain_ips "${decoy_input}")
    local_ips=$(printf "%s\n%s\n%s\n" "${local_ip}" "$(get_public_ip "IPv4" 2>/dev/null)" "$(get_public_ip "IPv6" 2>/dev/null)" |
        awk 'NF && !seen[$0]++')
    if [[ -z "${decoy_resolved}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法解析该域名的 A/AAAA 记录, 请检查 DNS 是否已生效") ${Font}"
        return 1
    fi
    if ! ip_lists_overlap "${local_ips}" "${decoy_resolved}"; then
        log_echo "${Warning} ${YellowBG} $(gettext "该域名 A/AAAA 记录") $(echo "${decoy_resolved}" | tr '\n' ' ') $(gettext "未指向本机公网 IP") $(echo "${local_ips}" | tr '\n' ' ') ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请先将域名 A/AAAA 记录指向本机, 或使用默认隔离策略") ${Font}"
        return 1
    fi

    decoy_domain="${decoy_input}"
    log_echo "${OK} ${GreenBG} $(gettext "域名校验通过") ${Font}"

    # 生成自签证书（高级用户可自行替换为 acme.sh 签发的正式证书）
    # P1-9: openssl is required for the self-signed cert generation below.
    pkg_install "openssl" || return 1
    mkdir -p "${ssl_chainpath}"
    if ! openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "${ssl_chainpath}/decoy.key" \
        -out "${ssl_chainpath}/decoy.crt" \
        -subj "/CN=${decoy_domain}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "自签证书生成失败") ${Font}"
        return 1
    fi
    # Root owns certs/keys, worker group can read but NOT write.
    # Private key: 640 (root rw, idleleo-nginx r, others none)
    # Public cert: 640 (root rw, idleleo-nginx r, others none)
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.key" "root:$(get_nginx_worker_group)" 640 || true
    apply_sensitive_file_permissions "${ssl_chainpath}/decoy.crt" "root:$(get_nginx_worker_group)" 640 || true

    # 生成不统一的极简站点页面（含域名与随机标识，避免统一指纹）
    local decoy_webroot="${idleleo_dir}/decoy"
    mkdir -p "${decoy_webroot}"
    local decoy_token
    decoy_token=$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 6)
    [[ -z "${decoy_token}" ]] && decoy_token="ok$(date +%s | tail -c 5)"
    cat >"${decoy_webroot}/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${decoy_domain}</title>
</head>
<body>
<h1>It works</h1>
<p>Service status: OK (${decoy_token})</p>
</body>
</html>
EOF

    # 生成 Nginx HTTPS 站点配置（监听 127.0.0.1:9444，供 stream deny upstream 回落）
    write_decoy_site_config || return 1

    log_echo "${OK} ${GreenBG} $(gettext "decoy 站点配置完成") ${Font}"
    log_echo "${Warning} $(gettext "当前使用自签证书, 浏览器访问会有证书提示。高级用户可自行替换") ${ssl_chainpath}/decoy.crt $(gettext "与") decoy.key ${Font}"
    return 0
}

# 清理 decoy 配置（切换策略或卸载时调用）
decoy_conf_remove() {
    [[ -f "${nginx_conf_dir}/03-decoy.conf" ]] && rm -f "${nginx_conf_dir}/03-decoy.conf"
    [[ -f "${nginx_conf_dir}/03-isolate.conf" ]] && rm -f "${nginx_conf_dir}/03-isolate.conf"
    if [[ -f "${nginx_dir}/conf/nginx.conf" ]]; then
        sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/03-decoy.conf;#d" "${nginx_dir}/conf/nginx.conf"
        sed -i "\#^[[:space:]]*include[[:space:]]\+${nginx_conf_dir}/03-isolate.conf;#d" "${nginx_dir}/conf/nginx.conf"
    fi
    return 0
}

ensure_reality_sni_guard_defaults() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    [[ "$(info_extraction tls)" != "Reality" ]] && return 0

    local current_guard current_policy current_decoy defaults_present
    current_guard=$(info_extraction reality_nginx_sni_guard)
    current_policy=$(info_extraction unknown_sni_policy)
    current_decoy=$(info_extraction decoy_domain)
    [[ -z "${current_guard}" ]] && current_guard="on"
    [[ -z "${current_policy}" ]] && current_policy="isolate"

    defaults_present=$(jq -r '
       has("reality_nginx_sni_guard") and
       has("unknown_sni_policy") and
       has("decoy_domain") and
       ((.reality_nginx_sni_guard // "") != "") and
       ((.unknown_sni_policy // "") != "")' "${xray_install_config_file}" 2>/dev/null) || return 1
    if [[ "${defaults_present}" != "true" ]]; then
        update_json_config "${xray_install_config_file}" \
           --arg guard "${current_guard}" \
           --arg policy "${current_policy}" \
           --arg decoy "${current_decoy}" '
           .reality_nginx_sni_guard = (if ((.reality_nginx_sni_guard // "") == "") then $guard else .reality_nginx_sni_guard end) |
           .unknown_sni_policy = (if ((.unknown_sni_policy // "") == "") then $policy else .unknown_sni_policy end) |
           .decoy_domain = (if has("decoy_domain") then .decoy_domain else $decoy end)' || return 1
    fi
    reality_nginx_sni_guard=$(info_extraction reality_nginx_sni_guard)
    unknown_sni_policy=$(info_extraction unknown_sni_policy)
    decoy_domain=$(info_extraction decoy_domain)
}

reset_sni_guard_policy() {
    if [[ ! -f "${xray_install_config_file}" ]] || [[ ! -f "${nginx_conf}" ]] || [[ ${tls_mode} != "Reality" ]] || [[ ${reality_add_nginx} != "on" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "当前模式不支持此操作")! ${Font}"
        return 1
    fi
    sni_guard_policy_choose force || return 1
    nginx_reality_conf_add || return 1
    update_json_config "${xray_install_config_file}" \
       --arg guard "${reality_nginx_sni_guard}" \
       --arg policy "${unknown_sni_policy}" \
       --arg decoy "${decoy_domain}" '
       .reality_nginx_sni_guard = $guard |
       .unknown_sni_policy = $policy |
       .decoy_domain = $decoy' || return 1
    service_restart || return 1
    reset_install_config
}


# Apply Reality+Nginx installation steps (shared by preset and interactive paths).
# Returns 0 on success, 1 on failure (propagated to caller).
_apply_reality_nginx_install() {
    validate_reality_reserved_ports || return 1
    # Drop stale/corrupt fragments before Nginx config is finalized.
    _cleanup_stale_serverNames_fragments || return 1
    nginx_exist_check || return 1
    nginx_systemd || return 1
    sni_guard_policy_choose || return 1
    nginx_reality_conf_add || return 1
    nginx_reality_servers_add || return 1
    nginx_reality_serverNames_add || return 1
}

# Skip Reality+Nginx installation. Does NOT uninstall existing Nginx.
# P0 safety: choosing "no Nginx" must not auto-remove an existing Nginx
# installation. Users who want to remove Nginx must do so explicitly.
_skip_reality_nginx_install() {
    if [[ -d "${nginx_dir}" ]]; then
        echo
        log_echo "${Warning} ${Green} $(gettext "检测到已安装") nginx ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "已跳过安装 nginx, 保留现有 nginx 不卸载") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "已跳过安装") nginx ${Font}"
    fi
}

reality_nginx_add_fq() {
    # Install wizard preset: reality_add_nginx already set by apply_install_profile.
    # Preset mode MUST NOT uninstall existing Nginx when reality_add_nginx=off.
    if [[ ${install_wizard_preset:-off} == "on" ]]; then
        if [[ ${reality_add_nginx} == "on" ]]; then
            _apply_reality_nginx_install || return 1
        else
            _skip_reality_nginx_install
        fi
        return 0
    fi

    echo
    log_echo "${Warning} ${Green} $(gettext "Reality 协议可能存在流量绕过风险") ${Font}"
    if [[ ${reality_add_balance} == "off" ]]; then
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护")($(gettext "推荐")) [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [nN][oO] | [nN])
                reality_add_nginx="off"
                _skip_reality_nginx_install
            ;;
            *)
                reality_add_nginx="on"
                _apply_reality_nginx_install || return 1
            ;;
        esac
    else
        log_echo "${Warning} ${Green} $(gettext "检测到已开启 Reality 负载均衡") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "作为 Reality 负载均衡主服务器时必须安装") ${Font}"
        log_echo "${Warning} ${Green} $(gettext "作为 Reality 负载均衡二级服务器时无需安装") ${Font}"
        log_echo "${GreenBG} $(gettext "是否额外安装 nginx 前置保护") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r reality_nginx_add_fq
        case $reality_nginx_add_fq in
            [yY][eE][sS] | [yY])
                reality_add_nginx="on"
                _apply_reality_nginx_install || return 1
            ;;
            *)
                reality_add_nginx="off"
                _skip_reality_nginx_install
            ;;
        esac
    fi
}

nginx_exist_check() {
    if [[ -f "${nginx_dir}/sbin/nginx" ]] && [[ -n "$(info_extraction nginx_build_version)" ]]; then
        # Older custom Nginx installations may predate the dedicated worker
        # account. Create it before changing config or provisioning TLS files.
        if ! ensure_idleleo_nginx_user; then
            return 1
        fi
        if [[ -d "${nginx_conf_dir}" ]]; then
            # Only remove files this script owns; preserve user-added .conf
            # (custom sites, stream blocks, reverse proxies, security rules).
            local _managed_file
            for _managed_file in "${managed_nginx_files[@]}"; do
                rm -f "${nginx_conf_dir}/${_managed_file}"
            done
            if [[ -f "${nginx_conf_dir}/nginx.default" ]]; then
                cp -fp "${nginx_conf_dir}"/nginx.default "${nginx_dir}"/conf/nginx.conf
            elif [[ -f "${nginx_dir}/conf/nginx.conf.default" ]]; then
                cp -fp "${nginx_dir}"/conf/nginx.conf.default "${nginx_dir}"/conf/nginx.conf
            else
                sed -i "/if \(.*\) {$/,+2d" "${nginx_dir}"/conf/nginx.conf
                sed -i "/^include.*\*\.conf;$/d" "${nginx_dir}"/conf/nginx.conf
            fi
        else
            sed -i "/if \(.*\) {$/,+2d" "${nginx_dir}"/conf/nginx.conf
            sed -i "/^include.*\*\.conf;$/d" "${nginx_dir}"/conf/nginx.conf
        fi
        modify_nginx_origin_conf || return 1
        nginx_build_version=$(info_extraction nginx_build_version)
        log_echo "${OK} ${GreenBG} Nginx $(gettext "已存在, 跳过编译安装过程") ${Font}"
    elif [[ -d "/etc/nginx" ]] && [[ -n "$(info_extraction nginx_version)" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "检测到其他套件安装的 Nginx, 继续安装会造成冲突, 请处理后安装")! ${Font}"
        exit 1
    else
        nginx_install || exit 1
    fi
}

# Strict tar safety check for Nginx release archives.
# Validates every tar entry BEFORE extraction and refuses dangerous archives.
# Returns 0 if the archive is safe, 1 otherwise.
# Safety rules:
#   1. All entries MUST live under the single top-level "nginx/" prefix.
#   2. Reject absolute paths (leading /).
#   3. Reject parent traversal (.. anywhere in the path).
#   4. Reject symlinks/hardlinks whose target points outside "nginx/".
#   5. Reject device files, FIFOs, sockets and other non-regular non-dir entries.
#   6. Reject file names containing control characters or NUL bytes.
#   7. Extraction uses --no-same-permissions --no-same-owner to drop tainted metadata.
# Uses Python3 tarfile for robust, cross-platform parsing (avoids tar -tvf
# output format differences between GNU tar and bsdtar).
nginx_tar_safe_check() {
    local tar_file="$1"
    local target_dir="$2"

    if [[ -z "${tar_file}" || ! -f "${tar_file}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 文件不存在") ${Font}"
        return 1
    fi
    if [[ -z "${target_dir}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 目标目录未指定") ${Font}"
        return 1
    fi

    # Use Python3 tarfile to inspect every entry. This avoids differences
    # between GNU tar and bsdtar output formats and gives us structured access
    # to entry type, link target, and path.
    local py_result
    py_result=$(python3 - "$tar_file" <<'PYEOF' 2>&1
import sys
import tarfile
import os
import re

tar_path = sys.argv[1]
bad = False
reason = ""

try:
    tf = tarfile.open(tar_path, "r:gz")
except Exception as e:
    print("ERROR: cannot open tar: %s" % e)
    sys.exit(1)

def normalize(path):
    """Collapse . and .. components, strip leading ./"""
    parts = []
    for p in path.split("/"):
        if p == "" or p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts)

CTRL_RE = re.compile(r'[\x00-\x1f\x7f]')

for member in tf.getmembers():
    name = member.name
    # Reject control characters in the path.
    if CTRL_RE.search(name):
        bad = True
        reason = "control char in path: %r" % name
        break
    # Reject absolute paths.
    if name.startswith("/"):
        bad = True
        reason = "absolute path: %s" % name
        break
    # Reject parent traversal as a full path component.
    if ".." in name.split("/"):
        bad = True
        reason = "parent traversal: %s" % name
        break
    # Require every entry to live under "nginx/" top-level prefix.
    normalized = normalize(name)
    if normalized != "nginx" and not normalized.startswith("nginx/"):
        bad = True
        reason = "non-nginx/ top-level entry: %s" % name
        break

    # Inspect entry type.
    if member.issym() or member.islnk():
        # Symlink or hardlink. Verify target stays inside nginx/.
        target = member.linkname
        if target.startswith("/"):
            bad = True
            reason = "link absolute target: %s -> %s" % (name, target)
            break
        if ".." in target.split("/"):
            # For symlinks, resolve relative to the entry's directory.
            # For hardlinks, the target is relative to archive root.
            if member.issym():
                entry_dir = os.path.dirname(name)
                resolved = normalize(entry_dir + "/" + target)
            else:
                resolved = normalize(target)
            if resolved != "nginx" and not resolved.startswith("nginx/"):
                bad = True
                reason = "link target escapes nginx/: %s -> %s" % (name, target)
                break
        else:
            # No ".." — still verify target is inside nginx/.
            if member.issym():
                entry_dir = os.path.dirname(name)
                resolved = normalize(entry_dir + "/" + target)
            else:
                resolved = normalize(target)
            if resolved != "nginx" and not resolved.startswith("nginx/"):
                bad = True
                reason = "link target outside nginx/: %s -> %s" % (name, target)
                break
    elif member.isdev():
        bad = True
        reason = "device file: %s" % name
        break
    elif member.isfifo():
        bad = True
        reason = "FIFO: %s" % name
        break
    # Regular files and directories are allowed.

tf.close()

if bad:
    print("REJECT: %s" % reason)
    sys.exit(1)
else:
    print("OK")
    sys.exit(0)
PYEOF
    )
    local py_exit=$?

    if [[ ${py_exit} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "tar 安全检查") ${py_result} ${Font}"
        return 1
    fi

    # Extract into staging with safe tar options: drop original owner/perms.
    if ! tar -xzf "${tar_file}" \
        -C "${target_dir}" \
        --no-same-permissions \
        --no-same-owner \
        --no-overwrite-dir \
        2>/dev/null; then
        # Fallback: some tar implementations (BusyBox) don't support all flags.
        # Retry with --no-same-owner only, which is the most critical safety flag.
        if ! tar -xzf "${tar_file}" -C "${target_dir}" --no-same-owner 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "tar 安全检查: 解压失败") ${Font}"
            return 1
        fi
    fi

    return 0
}

restore_nginx_preinstall_backup() {
    local backup_dir="$1"
    [[ -n "${backup_dir}" && -d "${backup_dir}" ]] || return 0
    safe_rm "${nginx_dir}" || return 1
    mv "${backup_dir}" "${nginx_dir}"
}

nginx_download_release_asset() {
    local url="$1"
    local output="$2"
    curl -fL -# --connect-timeout 10 --retry 2 --retry-delay 1 -o "${output}" "${url}"
}

nginx_verify_release_sha256() {
    local expected_sha="$1"
    local filename="$2"
    printf '%s  %s\n' "${expected_sha}" "${filename}" | sha256sum -c - >/dev/null 2>&1
}

nginx_validate_binary_file() {
    local binary="$1"
    local magic
    magic=$(head -c 4 "${binary}" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    [[ "${magic}" == "7f454c46" && -x "${binary}" ]]
}

nginx_run_config_test() {
    "${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf"
}

nginx_install() {
    # Staging-based install with mandatory manifest and SHA256.
    # Uses dedicated idleleo-nginx user with layered permissions.
    # Uses nginx_tar_safe_check() for strict archive safety validation.
    local temp_dir
    temp_dir=$(mktemp -d)
    local current_dir
    current_dir=$(pwd)

    cd "$temp_dir" || return 1

    local nginx_arch
    local nginx_filename
    local expected_nginx_filename
    case $(uname -m) in
        x86_64)
            nginx_arch="x86"
            nginx_filename="xray-nginx-custom-x86.tar.gz"
            ;;
        aarch64|arm64)
            nginx_arch="arm"
            nginx_filename="xray-nginx-custom-arm.tar.gz"
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "不支持的系统架构"): $(uname -m) ${Font}"
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
            ;;
    esac
    expected_nginx_filename="${nginx_filename}"

    log_echo "${OK} ${GreenBG} $(gettext "即将下载已编译的") Nginx v${nginx_build_version} (${nginx_arch}) ${Font}"

    local base_url="https://github.com/hello-yunshu/Xray_bash_onekey_Nginx/releases/download/v${nginx_build_version}"
    local manifest_file="${temp_dir}/release-manifest.json"

    # Manifest is mandatory (fail-closed). Missing/invalid manifest = abort.
    if ! download_json_file "${base_url}/release-manifest.json" "${manifest_file}"; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "release-manifest.json 下载失败或无效, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Validate manifest structure: must have assets array with matching arch entry.
    local manifest_filename
    local manifest_sha256
    local manifest_build_version
    local manifest_tag
    manifest_filename=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .filename // empty' "${manifest_file}" | head -n 1)
    manifest_sha256=$(jq -r --arg arch "${nginx_arch}" '.assets[]? | select(.arch == $arch) | .sha256 // empty' "${manifest_file}" | head -n 1)
    manifest_build_version=$(jq -r '.versions.nginx_build // empty' "${manifest_file}")
    manifest_tag=$(jq -r '.tag // empty' "${manifest_file}")
    if [[ -z "${manifest_filename}" || "${manifest_filename}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 中未找到架构"): ${nginx_arch} $(gettext "的产物记录, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ -z "${manifest_sha256}" || "${manifest_sha256}" == "null" ]]; then
        # SHA256 is mandatory when manifest exists. Fail-closed.
        log_echo "${Error} ${RedBG} $(gettext "manifest 中未提供 SHA256, 拒绝未校验安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ "${manifest_filename}" != "${expected_nginx_filename}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 产物文件名与架构契约不匹配, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ ! "${manifest_sha256}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest SHA256 格式无效, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if [[ "${manifest_build_version}" != "${nginx_build_version}" ||
          "${manifest_tag}" != "v${nginx_build_version}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "manifest 版本或 tag 不匹配, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    nginx_filename="${manifest_filename}"
    local nginx_sha256="${manifest_sha256}"

    local url="${base_url}/${nginx_filename}"

    if ! nginx_download_release_asset "$url" "$nginx_filename"; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "下载") $(gettext "失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx $(gettext "下载") $(gettext "完成") ${Font}"

    # Mandatory SHA256 verification (fail-closed).
    if ! nginx_verify_release_sha256 "${nginx_sha256}" "${nginx_filename}"; then
        log_echo "${Error} ${RedBG} Nginx SHA256 $(gettext "校验") $(gettext "失败") $(gettext ", 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx SHA256 $(gettext "校验") $(gettext "通过") ${Font}"

    # Strict tar safety check (replaces previous simple grep-based check).
    # Validates every entry before extraction and extracts into a staging
    # directory with --no-same-permissions --no-same-owner.
    local staging_dir="${temp_dir}/staging"
    mkdir -p "${staging_dir}"
    if ! nginx_tar_safe_check "${nginx_filename}" "${staging_dir}"; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 压缩包安全检查失败, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "Nginx 压缩包安全检查通过") ${Font}"

    # Verify extracted structure (sbin/nginx must be a regular file).
    if [[ ! -f "${staging_dir}/nginx/sbin/nginx" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "解压后未找到 sbin/nginx 或不是常规文件, 结构校验失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Verify sbin/nginx is a valid ELF binary.
    # ELF magic: 0x7f 'E' 'L' 'F'. file(1) may be unavailable on minimal systems.
    if ! nginx_validate_binary_file "${staging_dir}/nginx/sbin/nginx"; then
        log_echo "${Error} ${RedBG} $(gettext "sbin/nginx 不是可执行 ELF 二进制, 拒绝安装") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Move the validated staging tree into temp_dir root so subsequent code
    # that expects "./nginx" continues to work.
    if ! mv "${staging_dir}/nginx" "./nginx"; then
        log_echo "${Error} ${RedBG} $(gettext "staging 目录移动失败") ${Font}"
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Backup current nginx_dir before replacement (for rollback).
    local nginx_backup_dir=""
    if [[ -d "${nginx_dir}" ]]; then
        nginx_backup_dir="${nginx_dir}.pre-install.$$"
        if ! mv "${nginx_dir}" "${nginx_backup_dir}" 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 现有目录备份失败, 拒绝替换") ${Font}"
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
        fi
    fi

    # Atomic swap: move staged nginx to final location.
    if ! mv ./nginx "${nginx_dir}"; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 替换失败") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    [[ ! -d "${nginx_conf_dir}" ]] && mkdir -p "${nginx_conf_dir}"
    if ! cp -fp "${nginx_dir}"/conf/nginx.conf "${nginx_conf_dir}"/nginx.default; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Create dedicated idleleo-nginx user before modifying config.
    if ! ensure_idleleo_nginx_user; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # 修改基本配置
    if ! modify_nginx_origin_conf; then
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Apply layered permission model (replaces chown -fR nobody / chmod -fR 755).
    # Propagate permission failure so callers (nginx_update) can trigger rollback.
    if ! apply_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限应用失败, 可能影响服务运行") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi
    if ! verify_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 分层权限验证失败") ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Post-install config validation.
    if ! nginx_run_config_test >/dev/null 2>&1; then
        local _nginx_t_output
        _nginx_t_output=$(nginx_run_config_test 2>&1)
        _nginx_t_output=$(printf '%s' "${_nginx_t_output}" | redact_diagnostic_text)
        log_echo "${Error} ${RedBG} $(gettext "Nginx 配置校验失败"): ${_nginx_t_output} ${Font}"
        restore_nginx_preinstall_backup "${nginx_backup_dir}" || true
        cd "$current_dir" && rm -rf "$temp_dir"
        return 1
    fi

    # Only discard an internal pre-install backup after replacement, permission
    # verification, and nginx -t all succeed. nginx_update keeps its separate
    # outer backup until service/port health also succeeds.
    if [[ -n "${nginx_backup_dir}" && -d "${nginx_backup_dir}" ]]; then
        safe_rm "${nginx_backup_dir}" || {
            cd "$current_dir" && rm -rf "$temp_dir"
            return 1
        }
    fi

    # 删除临时文件
    cd "$current_dir" && rm -rf "$temp_dir"
    return 0
}

nginx_diagnose() {
    if [[ -x "${nginx_dir}/sbin/nginx" ]]; then
        local nginx_test_output
        nginx_test_output=$("${nginx_dir}/sbin/nginx" -t -c "${nginx_dir}/conf/nginx.conf" 2>&1)
        nginx_test_output=$(printf '%s' "${nginx_test_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "配置检测"): ${nginx_test_output} ${Font}"
    fi
    local nginx_journal_output
    nginx_journal_output=$(journalctl -u nginx --no-pager -n 10 2>/dev/null)
    if [[ -n "${nginx_journal_output}" ]]; then
        nginx_journal_output=$(printf '%s' "${nginx_journal_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "服务日志"): ${Font}"
        echo "${nginx_journal_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
    fi
}

xray_diagnose() {
    if [[ -x "${xray_bin_dir}/xray" ]]; then
        local xray_version_output
        xray_version_output=$("${xray_bin_dir}/xray" version 2>&1 | head -3)
        xray_version_output=$(printf '%s' "${xray_version_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "版本检测"): ${xray_version_output} ${Font}"
    fi
    local xray_journal_output
    xray_journal_output=$(journalctl -u xray --no-pager -n 10 2>/dev/null)
    if [[ -n "${xray_journal_output}" ]]; then
        xray_journal_output=$(printf '%s' "${xray_journal_output}" | redact_diagnostic_text)
        log_echo "${Error} $(gettext "服务日志"): ${Font}"
        echo "${xray_journal_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
    fi
    if [[ -f "${xray_error_log}" ]]; then
        local xray_error_output
        xray_error_output=$(tail -10 "${xray_error_log}" 2>/dev/null)
        if [[ -n "${xray_error_output}" ]]; then
            xray_error_output=$(printf '%s' "${xray_error_output}" | redact_diagnostic_text)
            log_echo "${Error} $(gettext "错误日志"): ${Font}"
            echo "${xray_error_output}" | while IFS= read -r line; do log_echo "  ${line}"; done
        fi
    fi
}

restore_nginx_backup() {
    local backup_dir="$1"

    service_stop || return 1
    safe_rm "${nginx_dir}" || return 1
    if ! mv "${backup_dir}" "${nginx_dir}"; then
        return 1
    fi
    apply_nginx_layered_permissions || return 1
    verify_nginx_layered_permissions || return 1
    service_start || return 1
    sleep 1
    if ! health_check_nginx_update "${port:-}"; then
        nginx_diagnose
        return 1
    fi
    return 0
}

# Layered rollback & health check helpers
# Layering order on update failure:
#   Layer 1: restore local pre-update backup (binary/script)
#   Layer 2: install known-good tested_version from API
#   Layer 3: stop service + print redacted diagnostics, no infinite retry
# Each layer is attempted at most once.

# Backup current Xray binary to ${idleleo_dir}/tmp/xray.prev with metadata.
# The backup stays on the same filesystem as the managed state.
backup_xray_binary() {
    local xray_binary="${xray_bin_dir}/xray"
    local backup_dir="${idleleo_dir}/tmp"
    if [[ ! -f "${xray_binary}" ]]; then
        # A missing binary is a repair/install, not an update with nothing to
        # protect. Keep any older xray.prev (it may still be a valid fallback)
        # and let xray_install_pinned_and_check install the pinned version.
        log_echo "${Warning} ${YellowBG} $(gettext "未找到 Xray 二进制，按安装/修复处理") ${Font}"
        return 0
    fi
    mkdir -p "${backup_dir}"
    # cp -p preserves owner/group/mode; the .prev file must not be world-readable
    if ! cp -p "${xray_binary}" "${backup_dir}/xray.prev"; then
        log_echo "${Warning} ${YellowBG} Xray $(gettext "二进制备份失败") ${Font}"
        return 1
    fi
    chmod 600 "${backup_dir}/xray.prev" 2>/dev/null
    {
        printf 'backup_time=%s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'backup_version=%s\n' "$(info_extraction xray_version 2>/dev/null)"
        printf 'backup_sha256=%s\n' "$(sha256sum "${xray_binary}" 2>/dev/null | awk '{print $1}')"
    } > "${backup_dir}/xray.prev.meta"
    chmod 600 "${backup_dir}/xray.prev.meta" 2>/dev/null
    return 0
}

# Restore Xray binary from local backup (Layer 1 rollback).
# Verifies sha256 against recorded metadata before restoring.
restore_xray_binary_backup() {
    local backup_file="${idleleo_dir}/tmp/xray.prev"
    local backup_meta="${idleleo_dir}/tmp/xray.prev.meta"
    local target="${xray_bin_dir}/xray"

    if [[ ! -f "${backup_file}" ]]; then
        log_echo "${Warning} ${YellowBG} Xray $(gettext "本机备份不存在, 跳过 Layer 1 恢复") ${Font}"
        return 1
    fi
    if [[ -f "${backup_meta}" ]]; then
        local expected_sha actual_sha
        expected_sha=$(grep '^backup_sha256=' "${backup_meta}" | cut -d= -f2-)
        actual_sha=$(sha256sum "${backup_file}" 2>/dev/null | awk '{print $1}')
        if [[ -n "${expected_sha}" && "${expected_sha}" != "${actual_sha}" ]]; then
            log_echo "${Error} ${RedBG} Xray $(gettext "备份校验失败, 拒绝恢复") ${Font}"
            return 1
        fi
    fi
    systemctl stop xray >/dev/null 2>&1
    if ! mv -f "${backup_file}" "${target}"; then
        log_echo "${Error} ${RedBG} Xray $(gettext "二进制恢复失败") ${Font}"
        return 1
    fi
    chmod 755 "${target}" 2>/dev/null
    systemctl start xray >/dev/null 2>&1
    sleep 1
    if ! systemctl -q is-active xray; then
        xray_diagnose
        return 1
    fi
    return 0
}

# Layer 2 fallback: install Xray from API tested_version (known-good baseline).
# Returns 0 on success, 1 if tested_version is missing or installation fails.
fallback_xray_to_tested_version() {
    local tested_ver
    tested_ver=$(check_version_silent xray_tested_version)
    if [[ -z "${tested_ver}" || "${tested_ver}" == "null" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "tested_version 不可用, 跳过 Layer 2 恢复") ${Font}"
        return 1
    fi
    log_echo "${Info} ${GreenBG} $(gettext "尝试使用 tested_version 恢复"): v${tested_ver} ${Font}"
    systemctl stop xray >/dev/null 2>&1
    if ! xray_install_release install -f --version "v${tested_ver}"; then
        log_echo "${Error} ${RedBG} Xray tested_version $(gettext "安装失败") ${Font}"
        return 1
    fi
    if ! "${xray_bin_dir}/xray" -version &>/dev/null; then
        log_echo "${Error} ${RedBG} Xray tested_version $(gettext "二进制不可执行") ${Font}"
        return 1
    fi
    xray_privilege_escalation || return 1
    systemctl start xray >/dev/null 2>&1
    sleep 1
    if ! systemctl -q is-active xray; then
        xray_diagnose
        return 1
    fi
    update_json_config "${xray_install_config_file}" --arg xray_version "${tested_ver}" '.xray_version = $xray_version' >/dev/null 2>&1
    log_echo "${OK} ${GreenBG} Xray $(gettext "已恢复到 tested_version"): v${tested_ver} ${Font}"
    return 0
}

# Layer 2 fallback: install Nginx from API tested_version (known-good baseline).
fallback_nginx_to_tested_version() {
    local tested_ver
    tested_ver=$(check_version_silent nginx_build_tested_version)
    if [[ -z "${tested_ver}" || "${tested_ver}" == "null" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "tested_version 不可用, 跳过 Layer 2 恢复") ${Font}"
        return 1
    fi
    log_echo "${Info} ${GreenBG} $(gettext "尝试使用 tested_version 恢复"): v${tested_ver} ${Font}"
    systemctl stop nginx >/dev/null 2>&1
    # Save and override global version used by nginx_install
    local _saved_version="${nginx_build_version}"
    nginx_build_version="${tested_ver}"
    if ! nginx_install; then
        nginx_build_version="${_saved_version}"
        log_echo "${Error} ${RedBG} Nginx tested_version $(gettext "安装失败") ${Font}"
        return 1
    fi
    systemctl start nginx >/dev/null 2>&1
    sleep 1
    if ! health_check_nginx_update "${port:-}"; then
        nginx_build_version="${_saved_version}"
        nginx_diagnose
        return 1
    fi
    if ! update_json_config "${xray_install_config_file}" --arg nginx_build_version "${tested_ver}" \
        '.nginx_build_version = $nginx_build_version' >/dev/null 2>&1; then
        nginx_build_version="${_saved_version}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} Nginx $(gettext "已恢复到 tested_version"): v${tested_ver} ${Font}"
    return 0
}

rollback_nginx_update() {
    local backup_dir="$1"
    local previous_version="$2"
    nginx_rollback_layer=0

    # Layer 1: the exact pre-update directory.
    if restore_nginx_backup "${backup_dir}"; then
        if update_json_config "${xray_install_config_file}" \
            --arg nginx_build_version "${previous_version}" \
            '.nginx_build_version = $nginx_build_version'; then
            nginx_rollback_layer=1
            return 0
        fi
        log_echo "${Error} ${RedBG} Nginx $(gettext "旧版本记录恢复失败, 继续 tested_version 恢复") ${Font}"
    fi

    # Layer 2: one known-good API fallback attempt. Keep any still-existing
    # local backup until the fallback has passed its own health check.
    log_echo "${Info} ${YellowBG} $(gettext "Layer 1 失败, 尝试 Layer 2 tested_version 恢复") ${Font}"
    if fallback_nginx_to_tested_version; then
        [[ -e "${backup_dir}" || -L "${backup_dir}" ]] && safe_rm "${backup_dir}"
        nginx_rollback_layer=2
        return 0
    fi

    # Layer 3: fail closed, keep remaining evidence/backups, stop and redact.
    log_echo "${Error} ${RedBG} Nginx $(gettext "所有回滚层均失败")! ${Font}"
    systemctl stop nginx >/dev/null 2>&1
    nginx_diagnose
    log_echo "${Error} ${RedBG} Nginx $(gettext "更新失败且所有回滚层均失败, 请手动检查") ${Font}"
    return 1
}

recover_failed_nginx_update() {
    local backup_dir="$1"
    local previous_version="$2"
    if rollback_nginx_update "${backup_dir}" "${previous_version}"; then
        if [[ ${nginx_rollback_layer} -eq 1 ]]; then
            log_echo "${OK} ${GreenBG} $(gettext "已成功回滚到之前的") Nginx $(gettext "版本")! ${Font}"
        else
            log_echo "${OK} ${GreenBG} Nginx $(gettext "已恢复到 tested_version")! ${Font}"
        fi
    fi
    # The attempted update failed even when service recovery succeeded.
    return 1
}

# Health check: Xray after update. Verifies binary, version, config, service, port.
health_check_xray_update() {
    local expected_version="$1"
    local xray_binary="${xray_bin_dir}/xray"

    [[ ! -x "${xray_binary}" ]] && { log_echo "${Error} ${RedBG} Xray $(gettext "二进制不可执行") ${Font}"; return 1; }
    if ! "${xray_binary}" -version &>/dev/null; then
        log_echo "${Error} ${RedBG} Xray $(gettext "二进制执行失败") ${Font}"
        return 1
    fi
    if [[ -n "${expected_version}" ]]; then
        local actual_version
        # Read the entire stream: head can close the pipe early and cause the
        # Xray process to receive SIGPIPE under callers using pipefail.
        actual_version=$("${xray_binary}" version 2>/dev/null | awk 'NR == 1 {print $2}')
        # Xray prints "vX.Y.Z" or "X.Y.Z"; accept either form
        if [[ "${actual_version}" != "v${expected_version}" && "${actual_version}" != "${expected_version}" ]]; then
            log_echo "${Error} ${RedBG} Xray $(gettext "版本不匹配"): expected=${expected_version}, actual=${actual_version} ${Font}"
            return 1
        fi
    fi
    # Config syntax check (does not require running service)
    if [[ -f "${xray_conf}" ]]; then
        if ! "${xray_binary}" run -test -config "${xray_conf}" &>/dev/null; then
            log_echo "${Error} ${RedBG} Xray $(gettext "配置解析失败") ${Font}"
            return 1
        fi
    fi
    if ! systemctl -q is-active xray; then
        log_echo "${Error} ${RedBG} Xray $(gettext "服务未运行") ${Font}"
        return 1
    fi
    # Port listening check (only when port is known from config)
    local listen_port
    listen_port=$(info_extraction port 2>/dev/null)
    if [[ -n "${listen_port}" && "${listen_port}" != "null" ]]; then
        if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${listen_port}\$"; then
            log_echo "${Warning} ${YellowBG} Xray $(gettext "端口未监听"): ${listen_port} ${Font}"
            return 1
        fi
    fi
    return 0
}

# Health check: Nginx after update. Verifies nginx -t, service, port.
health_check_nginx_update() {
    local listen_port="$1"
    local nginx_binary="${nginx_dir}/sbin/nginx"

    [[ ! -x "${nginx_binary}" ]] && { log_echo "${Error} ${RedBG} Nginx $(gettext "二进制不可执行") ${Font}"; return 1; }
    if ! "${nginx_binary}" -t -c "${nginx_dir}/conf/nginx.conf" &>/dev/null; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "配置检测失败") ${Font}"
        nginx_diagnose
        return 1
    fi
    if ! systemctl -q is-active nginx; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "服务未运行") ${Font}"
        return 1
    fi
    if ! verify_nginx_layered_permissions; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "分层权限验证失败") ${Font}"
        return 1
    fi
    if [[ -n "${listen_port}" && "${listen_port}" != "null" ]]; then
        if ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${listen_port}\$"; then
            log_echo "${Warning} ${YellowBG} Nginx $(gettext "端口未监听"): ${listen_port} ${Font}"
            return 1
        fi
    fi
    return 0
}

activate_nginx_update() {
    local listen_port="${1:-}"
    apply_nginx_layered_permissions || return 1
    verify_nginx_layered_permissions || return 1
    service_start || return 1
    sleep 1
    health_check_nginx_update "${listen_port}"
}

# Health check: install.sh after update. Verifies bash -n and shell_version marker.
health_check_shell_update() {
    local script_file="$1"
    local expected_version="$2"

    [[ -z "${script_file}" ]] && script_file="${idleleo_dir}/install.sh"
    if [[ ! -f "${script_file}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "脚本不存在"): ${script_file} ${Font}"
        return 1
    fi
    if ! bash -n "${script_file}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "脚本语法检查失败") ${Font}"
        return 1
    fi
    if [[ -n "${expected_version}" ]]; then
        local actual_version
        actual_version=$(grep -E '^shell_version=' "${script_file}" | head -1 | awk -F'=|"' '{print $3}')
        if [[ "${actual_version}" != "${expected_version}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "脚本版本不匹配"): expected=${expected_version}, actual=${actual_version} ${Font}"
            return 1
        fi
    fi
    return 0
}

nginx_update() {
    [[ -f "/etc/idleleo/logs/update_failed.mark" ]] && rm -rf "/etc/idleleo/logs/update_failed.mark"
    if is_relay_role; then
        nginx_update_relay
        return $?
    fi
    local save_originconf=""
    if [[ -f "${nginx_dir}/sbin/nginx" ]]; then
        current_nginx_build_version=$(info_extraction nginx_build_version)
        if [[ ${nginx_build_version} != ${current_nginx_build_version} ]]; then
            log_echo "${Info} ${GreenBG} Nginx $(gettext "更新"): v${current_nginx_build_version} → v${nginx_build_version} ${Font}"
            ip_check
            if [[ -f "${xray_install_config_file}" ]]; then
                domain=$(info_extraction host)
                if [[ ${tls_mode} == "TLS" ]]; then
                    port=$(info_extraction port)
                    if [[ ${transport_mode} == "onlyws" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(generate_random_port 30000 30999)
                        while [[ ${gport} == ${xport} ]]; do gport=$(generate_random_port 30000 30999); done
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "onlygRPC" ]]; then
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xport=$(generate_random_port 20000 20999)
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                        xport=$(generate_random_port 20000 20999)
                        path="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                        gport=$(generate_random_port 30000 30999)
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "wsxhttp" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                        gport=$(generate_random_port 30000 30999)
                        serviceName="$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"
                    elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                        xport=$(info_extraction ws_port)
                        path=$(info_extraction path)
                        gport=$(info_extraction grpc_port)
                        serviceName=$(info_extraction serviceName)
                        xhttpport=$(info_extraction xhttp_port)
                        xhttppath=$(info_extraction xhttp_path)
                    fi
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不完整, 退出更新")!" >>"${log_file}" && return 1
                        log_echo "${Error} ${RedBG} $(gettext "配置不完整, 退出更新")! ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]]; then
                    port=$(info_extraction port)
                    serverNames=$(info_extraction serverNames)
                    if [[ 0 -eq ${read_config_status} ]]; then
                        [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不完整, 退出更新")!" >>"${log_file}" && return 1
                        log_echo "${Error} ${RedBG} $(gettext "配置不完整, 退出更新")! ${Font}"
                        return 1
                    fi
                elif [[ ${tls_mode} == "None" ]]; then
                    [[ ${auto_update} == "YES" ]] && echo "$(gettext "当前安装模式不需要") Nginx !" >>"${log_file}" && return 1
                    log_echo "${Error} ${RedBG} $(gettext "当前安装模式不需要") Nginx ! ${Font}"
                    return 1
                fi
            else
                [[ ${auto_update} == "YES" ]] && echo "Nginx $(gettext "配置不存在, 退出更新")!" >>"${log_file}" && return 1
                log_echo "${Error} ${RedBG} $(gettext "配置不存在, 退出更新")! ${Font}"
                return 1
            fi
            service_stop || return 1
            backup_nginx_dir="${nginx_dir}_backup_${current_nginx_build_version}"
            if [[ -e "${backup_nginx_dir}" || -L "${backup_nginx_dir}" ]]; then
                safe_rm "${backup_nginx_dir}" || return 1
            fi
            if ! cp -a "${nginx_dir}" "${backup_nginx_dir}"; then
                log_echo "${Error} ${RedBG} $(gettext "备份旧版") Nginx $(gettext "失败") ${Font}"
                return 1
            fi
            log_echo "${OK} ${GreenBG} $(gettext "备份旧版") Nginx $(gettext "完成") ${Font}"
            countdown "$(gettext "删除旧版") Nginx !"
            safe_rm "${nginx_dir}" || return 1
            if [[ ${auto_update} != "YES" ]]; then
                echo
                log_echo "${GreenBG} $(gettext "是否保留原 Nginx 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                read -r save_originconf_fq
            else
                save_originconf_fq=1
            fi
            case $save_originconf_fq in
            [nN][oO] | [nN])
                rm -rf "${nginx_conf_dir}"/*.conf
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除")! ${Font}"
                ;;
            *)
                save_originconf="Yes"
                log_echo "${OK} ${GreenBG} $(gettext "原配置文件已保留")! ${Font}"
                ;;
            esac
            if ! nginx_install; then
                # nginx_install returns 1 on hard failure (not exit).
                # Enter rollback path directly — same as startup failure.
                local nginx_start_failed=1
                local service_start_failed=1
            else
                # nginx_install succeeded, proceed with config and startup
                local nginx_start_failed=0
                local service_start_failed=0
                if [[ ${tls_mode} == "TLS" ]] && [[ ${save_originconf} != "Yes" ]]; then
                    if ! (nginx_ssl_conf_add && nginx_conf_add && nginx_servers_conf_add); then
                        nginx_start_failed=1
                        service_start_failed=1
                    fi
                elif [[ ${tls_mode} == "Reality" ]] && [[ ${reality_add_nginx} == "on" ]] && [[ ${save_originconf} != "Yes" ]]; then
                    if ! (nginx_reality_conf_add && nginx_reality_servers_add && nginx_reality_serverNames_add); then
                        nginx_start_failed=1
                        service_start_failed=1
                    fi
                fi
                if [[ ${nginx_start_failed} -eq 0 ]] && ! activate_nginx_update "${port}"; then
                    nginx_start_failed=1
                    service_start_failed=1
                fi
            fi
            if [[ ${nginx_start_failed} -eq 0 ]] && ! update_json_config "${xray_install_config_file}" \
                --arg nginx_build_version "${nginx_build_version}" \
                '.nginx_build_version = $nginx_build_version'; then
                log_echo "${Error} ${RedBG} Nginx $(gettext "版本记录更新失败, 执行回滚") ${Font}"
                nginx_start_failed=1
            fi
            if [[ ${nginx_start_failed} -eq 1 ]]; then
                log_echo "${Error} ${RedBG} Nginx $(gettext "启动") $(gettext "失败")! ${Font}"
                if [[ ${service_start_failed} -eq 0 ]]; then
                    nginx_diagnose
                fi
                # Layered rollback — Layer 1 (local backup) → Layer 2 (tested_version) → Layer 3 (stop + diagnostics).
                # Each layer is attempted at most once. No infinite retry, no recursive update.
                if [[ ${auto_update} != "YES" ]]; then
                    echo
                    log_echo "${GreenBG} $(gettext "是否回滚到之前的版本") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
                    read -r rollback_fq
                else
                    rollback_fq="y"
                fi
                case $rollback_fq in
                [nN][oO] | [nN])
                    log_echo "${Info} ${YellowBG} $(gettext "未执行回滚操作")! ${Font}"
                    return 1
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "正在回滚")... ${Font}"
                    recover_failed_nginx_update "${backup_nginx_dir}" "${current_nginx_build_version}"
                    return $?
                    ;;
                esac
            elif [[ ${service_start_failed} -eq 1 ]]; then
                return 1
            else
                judge "Nginx $(gettext "更新")"
                safe_rm "${backup_nginx_dir}" || return 1
                judge "$(gettext "删除") Nginx $(gettext "备份")"
            fi
        else
            log_echo "${OK} ${GreenBG} Nginx $(gettext "已为最新版") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} Nginx $(gettext "未安装") ${Font}"
    fi
    return 0
}

auto_update() {
    local crontab_file
    crontab_file="$(root_crontab_path)"
    if [[ ! -f "${auto_update_file}" ]] || [[ $(crontab -l | grep -c "auto_update.sh") -lt 1 ]]; then
        echo
        log_echo "${GreenBG} $(gettext "设置后台定时自动更新程序 (包含: 脚本/Xray/Nginx)") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "可能自动更新后有兼容问题, 谨慎启用") ${Font}"
        log_echo "${GreenBG} $(gettext "是否启用") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_fq
        case $auto_update_fq in
        [yY][eE][sS] | [yY])
            download_script_file "${au_remote_url}" "${auto_update_file}"
            judge -r "$(gettext "下载自动更新脚本")" || return 1
            echo "0 1 * * * bash \"${auto_update_file}\"" >>"${crontab_file}"
            judge -r "$(gettext "设置自动更新")"
            ;;
        *) ;;
        esac
    else
        log_echo "${OK} ${GreenBG} $(gettext "已设置自动更新") ${Font}"
        log_echo "${GreenBG} $(gettext "是否关闭") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r auto_update_close_fq
        case $auto_update_close_fq in
        [yY][eE][sS] | [yY])
            sed -i "/auto_update.sh/d" "${crontab_file}"
            rm -rf "${auto_update_file}"
            judge -r "$(gettext "删除自动更新")"
            ;;
        *) ;;
        esac
    fi
}

ssl_install() {
    # P1-9: socat is required for the acme.sh SSL workflow below.
    pkg_install "socat" || return 1
    judge -r "$(gettext "安装 SSL 证书生成脚本依赖")" || return 1
    local acme_install_file="${idleleo_dir}/tmp/acme-install.sh"
    if ! download_script_file "https://get.acme.sh" "$acme_install_file" sh; then
        log_echo "${Error} ${RedBG} $(gettext "下载 SSL 证书生成脚本失败") ${Font}"
        exit 1
    fi
    sh "$acme_install_file" email=${custom_email}
    local acme_install_ret=$?
    rm -f "$acme_install_file"
    if [[ $acme_install_ret -eq 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "安装 SSL 证书生成脚本") $(gettext "完成") ${Font}"
        sleep 0.5
    else
        log_echo "${Error} ${RedBG} $(gettext "安装 SSL 证书生成脚本") $(gettext "失败") ${Font}"
        exit 1
    fi
}

domain_check() {
    local ip_version_fq install
    while true; do
        if [[ "on" == ${old_config_status} ]] && [[ -n $(info_extraction host) ]] && [[ -n $(info_extraction ip_version) ]]; then
            echo
            log_echo "${GreenBG} $(gettext "检测到原域名配置存在, 是否跳过域名设置") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq || return 1
            case $old_host_fq in
            [nN][oO] | [nN]) ;;
            *)
                domain=$(info_extraction host)
                ip_version=$(info_extraction ip_version)
                load_network_capabilities_from_config
                if [[ ${ip_version} == "IPv4" ]]; then
                    local_ip=$(get_public_ip "IPv4")
                elif [[ ${ip_version} == "IPv6" ]]; then
                    local_ip=$(get_public_ip "IPv6")
                else
                    local_ip=${ip_version}
                fi
                if [[ -z ${local_ip} ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
                    return 1
                fi
                log_echo "${OK} ${GreenBG} $(gettext "已跳过域名设置") ${Font}"
                return 0
                ;;
            esac
        fi
        echo
        log_echo "${GreenBG} $(gettext "确定域名信息") ${Font}"
        read_optimize "$(gettext "请输入你的域名信息") (e.g. www.hey.run):" "domain" "NULL" || return 1
        echo -e "\n${GreenBG} $(gettext "请选择网络与域名校验方式") ${Font}"
        echo -e "${Green}1${Font}: $(gettext "自动检测") (IPv4/IPv6) ($(gettext "推荐"))"
        echo -e "${Red}2${Font}: IPv4 ($(gettext "默认"))"
        echo "3: IPv6"
        echo "4: $(gettext "手动输入域名") ($(gettext "服务器商仅提供域名"))"
        read_optimize "$(gettext "请输入"): " "ip_version_fq" 2 1 4 "$(gettext "请输入有效的数字")!" || return 1
        log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
        if [[ ${ip_version_fq} == 1 ]]; then
            # 自动检测：A/AAAA 集合资格检查
            validate_domain_network_records "${domain}"
            local vdn_rc=$?
            if [[ ${vdn_rc} -eq 0 ]]; then
                case "${network_mode}" in
                    ipv6) ip_version="IPv6" ;;
                    *) ip_version="IPv4" ;;
                esac
                local_ip="${ipv4_address:-${ipv6_address:-}}"
                log_echo "${OK} ${GreenBG} $(gettext "域名 DNS 解析记录与公网 IP 匹配") ${Font}"
                break
            elif [[ ${vdn_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "检测到错误的 A/AAAA 记录, 可能导致部分客户端连接失败") ${Font}"
                log_echo "${Warning} ${YellowBG} $(gettext "请修正或删除错误的 DNS 记录后再继续, 请选择"): ${Font}"
                echo "1: $(gettext "仍然继续安装") ($(gettext "高风险"))"
                echo "2: $(gettext "重新输入")"
                log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1)
                    case "${network_mode}" in
                        ipv6) ip_version="IPv6" ;;
                        *) ip_version="IPv4" ;;
                    esac
                    local_ip="${ipv4_address:-${ipv6_address:-}}"
                    log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
                    break
                    ;;
                2) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            else
                log_echo "${Error} ${RedBG} $(gettext "无法通过域名 A/AAAA 记录校验公网 IP"), $(gettext "请选择"): ${Font}"
                echo "1: $(gettext "重新输入")"
                log_echo "${Red}2${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            fi
        elif [[ ${ip_version_fq} == 2 ]]; then
            # 显式 IPv4：执行完整 A/AAAA qualification（含对错误 AAAA 的高风险提示）
            validate_domain_network_records "${domain}" "ipv4"
            local vdn_rc=$?
            if [[ ${vdn_rc} -eq 0 ]]; then
                ip_version="IPv4"
                local_ip="${ipv4_address}"
                log_echo "${OK} ${GreenBG} $(gettext "域名 DNS 解析记录与公网 IP 匹配") ${Font}"
                break
            elif [[ ${vdn_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "检测到错误的 A/AAAA 记录, 可能导致部分客户端连接失败") ${Font}"
                log_echo "${Warning} ${YellowBG} $(gettext "请修正或删除错误的 DNS 记录后再继续, 请选择"): ${Font}"
                echo "1: $(gettext "仍然继续安装") ($(gettext "高风险"))"
                echo "2: $(gettext "重新输入")"
                log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1)
                    ip_version="IPv4"
                    local_ip="${ipv4_address}"
                    log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
                    break
                    ;;
                2) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            else
                log_echo "${Error} ${RedBG} $(gettext "无法通过域名 A/AAAA 记录校验公网 IP"), $(gettext "请选择"): ${Font}"
                echo "1: $(gettext "重新输入")"
                log_echo "${Red}2${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            fi
        elif [[ ${ip_version_fq} == 3 ]]; then
            # 显式 IPv6：执行完整 A/AAAA qualification（含对错误 A 的高风险提示）
            validate_domain_network_records "${domain}" "ipv6"
            local vdn_rc=$?
            if [[ ${vdn_rc} -eq 0 ]]; then
                ip_version="IPv6"
                local_ip="${ipv6_address}"
                log_echo "${OK} ${GreenBG} $(gettext "域名 DNS 解析记录与公网 IP 匹配") ${Font}"
                break
            elif [[ ${vdn_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "检测到错误的 A/AAAA 记录, 可能导致部分客户端连接失败") ${Font}"
                log_echo "${Warning} ${YellowBG} $(gettext "请修正或删除错误的 DNS 记录后再继续, 请选择"): ${Font}"
                echo "1: $(gettext "仍然继续安装") ($(gettext "高风险"))"
                echo "2: $(gettext "重新输入")"
                log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1)
                    ip_version="IPv6"
                    local_ip="${ipv6_address}"
                    log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
                    break
                    ;;
                2) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            else
                log_echo "${Error} ${RedBG} $(gettext "无法通过域名 A/AAAA 记录校验公网 IP"), $(gettext "请选择"): ${Font}"
                echo "1: $(gettext "重新输入")"
                log_echo "${Red}2${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            fi
        elif [[ ${ip_version_fq} == 4 ]]; then
            log_echo "${Warning} ${GreenBG} $(gettext "此选项用于服务器商仅提供域名访问服务器") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "请为服务器商提供的域名添加 CNAME 记录") ${Font}"
            read_optimize "$(gettext "请输入"): " "local_ip" "NULL" || return 1
            ip_version=${local_ip}
            network_mode="manual"
            ipv4_address=""
            ipv6_address=""
            break
        else
            # 默认（IPv4）：执行完整 A/AAAA qualification（含对错误 AAAA 的高风险提示）
            validate_domain_network_records "${domain}" "ipv4"
            local vdn_rc=$?
            if [[ ${vdn_rc} -eq 0 ]]; then
                ip_version="IPv4"
                local_ip="${ipv4_address}"
                log_echo "${OK} ${GreenBG} $(gettext "域名 DNS 解析记录与公网 IP 匹配") ${Font}"
                break
            elif [[ ${vdn_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "检测到错误的 A/AAAA 记录, 可能导致部分客户端连接失败") ${Font}"
                echo "1: $(gettext "仍然继续安装") ($(gettext "高风险"))"
                echo "2: $(gettext "重新输入")"
                log_echo "${Red}3${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 3 1 3 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1)
                    ip_version="IPv4"
                    local_ip="${ipv4_address}"
                    log_echo "${OK} ${GreenBG} $(gettext "继续安装") ${Font}"
                    break
                    ;;
                2) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            else
                log_echo "${Error} ${RedBG} $(gettext "无法通过域名 A/AAAA 记录校验公网 IP"), $(gettext "请选择"): ${Font}"
                echo "1: $(gettext "重新输入")"
                log_echo "${Red}2${Font}: $(gettext "终止安装") ($(gettext "默认"))"
                read_optimize "$(gettext "请输入"): " "install" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                case $install in
                1) continue ;;
                *) log_echo "${Error} ${RedBG} $(gettext "安装终止") ${Font}"; exit 2 ;;
                esac
            fi
        fi
    done
}

ip_check() {
    if [[ "on" == ${old_config_status} || ${auto_update} == "YES" ]] && [[ -n $(info_extraction host) ]] && [[ -n $(info_extraction ip_version) ]]; then
        if [[ ${auto_update} != "YES" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "检测到原IP配置存在, 是否跳过IP设置") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r old_host_fq || return 1
        else
            old_host_fq=1
        fi
        case $old_host_fq in
        [nN][oO] | [nN]) ;;
        *)
            ip_version=$(info_extraction ip_version)
            load_network_capabilities_from_config
            if [[ ${ip_version} == "IPv4" ]]; then
                local_ip=$(get_public_ip "IPv4")
            elif [[ ${ip_version} == "IPv6" ]]; then
                local_ip=$(get_public_ip "IPv6")
            else
                local_ip=${ip_version}
            fi
            if [[ -z ${local_ip} ]]; then
                log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
                return 1
            fi
            echo
            log_echo "${OK} ${GreenBG} $(gettext "已跳过IP设置") ${Font}"
            return 0
            ;;
        esac
    fi
    echo
    log_echo "${GreenBG} $(gettext "确定公网IP信息") ${Font}"
    log_echo "${GreenBG} $(gettext "请选择公网IP为IPv4或IPv6") ${Font}"
    echo -e "${Green}1${Font}: $(gettext "自动检测") (IPv4/IPv6) ($(gettext "推荐"))"
    echo -e "${Red}2${Font}: IPv4 ($(gettext "默认"))"
    echo "3: IPv6"
    echo "4: $(gettext "手动输入")"
    local ip_version_fq
    read_optimize "$(gettext "请输入"): " "ip_version_fq" 2 1 4 "$(gettext "请输入有效的数字")!" || return 1
    [[ -z ${ip_version_fq} ]] && ip_version_fq=2
    log_echo "${OK} ${GreenBG} $(gettext "正在获取公网IP信息, 请耐心等待") ${Font}"
    if [[ ${ip_version_fq} == 1 ]]; then
        detect_public_network_capabilities
        if [[ "${network_mode}" == "dual" ]]; then
            ip_version="IPv4"
            local_ip="${ipv4_address}"
            log_echo "${OK} ${GreenBG} $(gettext "已检测到 IPv4 和 IPv6 均可用, 将启用双栈") ${Font}"
        elif [[ "${network_mode}" == "ipv4" ]]; then
            ip_version="IPv4"
            local_ip="${ipv4_address}"
            log_echo "${OK} ${GreenBG} $(gettext "当前仅 IPv4 可用") ${Font}"
        elif [[ "${network_mode}" == "ipv6" ]]; then
            ip_version="IPv6"
            local_ip="${ipv6_address}"
            log_echo "${OK} ${GreenBG} $(gettext "当前仅 IPv6 可用") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
            return 1
        fi
    elif [[ ${ip_version_fq} == 2 ]]; then
        local_ip=$(get_public_ip "IPv4")
        ip_version="IPv4"
        network_mode="ipv4"
        ipv4_address="${local_ip}"
        ipv6_address=""
    elif [[ ${ip_version_fq} == 3 ]]; then
        local_ip=$(get_public_ip "IPv6")
        ip_version="IPv6"
        network_mode="ipv6"
        ipv6_address="${local_ip}"
        ipv4_address=""
    elif [[ ${ip_version_fq} == 4 ]]; then
        read_optimize "$(gettext "请输入"): " "local_ip" "NULL" || return 1
        ip_version=${local_ip}
        network_mode="manual"
        ipv4_address=""
        ipv6_address=""
    else
        local_ip=$(get_public_ip "IPv4")
        ip_version="IPv4"
        network_mode="ipv4"
        ipv4_address="${local_ip}"
        ipv6_address=""
    fi
    if [[ -z ${local_ip} ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法获取公网IP地址"), $(gettext "安装终止")! ${Font}"
        return 1
    fi
    log_echo "$(gettext "公网IP/域名"): ${local_ip}"
}

port_listener_info() {
    local port="$1"
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null ||
        ss -H -ltnp "sport = :${port}" 2>/dev/null
}

# Check whether a PID belongs to a project-managed service.
# Returns 0 (project service) only when the executable path can be
# positively identified as the project's xray or nginx. The systemd unit
# name alone is NOT sufficient (a third-party nginx also has nginx.service).
# If the PID cannot be positively confirmed, returns 1 (treat as third-party).
is_project_service_pid() {
    local pid="$1"
    [[ -z "${pid}" || "${pid}" == "-" ]] && return 1

    # Check 1: executable path via /proc/<pid>/exe — the primary check.
    local exe_path
    exe_path=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
    if [[ -n "${exe_path}" ]]; then
        case "${exe_path}" in
            "${xray_bin_dir}/xray") return 0 ;;
            "${nginx_dir}/sbin/nginx") return 0 ;;
            *) return 1 ;;  # Non-project path → third-party
        esac
    fi

    # Check 2: comm (process name) + cgroup fallback — only when exe path
    # is unavailable (e.g. permission denied). Require BOTH a matching
    # process name AND a matching systemd unit to avoid false positives.
    local comm cgroup
    comm=$(cat "/proc/${pid}/comm" 2>/dev/null || true)
    cgroup=$(cat "/proc/${pid}/cgroup" 2>/dev/null || true)
    if [[ "${comm}" == "xray" ]] && echo "${cgroup}" | grep -qE 'xray\.service|/xray\b'; then
        return 0
    fi
    if [[ "${comm}" == "nginx" ]] && echo "${cgroup}" | grep -qE 'nginx\.service|/nginx\b'; then
        return 0
    fi

    return 1
}

port_exist_check() {
    local port="${1:-}"

    [[ -z "${port}" ]] && return 0

    [[ "${port}" =~ ^[0-9]+$ ]] || {
        log_echo "${Error} ${RedBG} $(gettext "端口格式无效"): ${port} ${Font}"
        return 1
    }

    if ! port_listener_info "${port}" | grep -q .; then
        log_echo "${OK} ${GreenBG} ${port} $(gettext "端口未被占用") ${Font}"
        return 0
    fi

    # Port is occupied. Precisely identify whether the occupant is a
    # project-managed service (xray.service / nginx.service with project
    # binary path). A name-only match (e.g. third-party "nginx" from apt)
    # is NOT sufficient and must be treated as third-party.
    local listener_output pids pid all_project=1
    listener_output=$(port_listener_info "${port}")

    # Extract PIDs from ss/lsof output. Format varies:
    #   ss:   users:(("xray",pid=1234,fd=5))
    #   lsof: COMMAND PID USER FD TYPE SIZE/OFF NODE NAME
    pids=$(echo "${listener_output}" | grep -oE 'pid=[0-9]+' | sed 's/pid=//')
    if [[ -z "${pids}" ]]; then
        # lsof format: second column is PID
        pids=$(echo "${listener_output}" | awk 'NR>1{print $2}')
    fi

    if [[ -z "${pids}" ]]; then
        # Cannot extract any PID — cannot positively confirm project service.
        all_project=0
    else
        for pid in ${pids}; do
            if ! is_project_service_pid "${pid}"; then
                all_project=0
                break
            fi
        done
    fi

    if [[ ${all_project} -eq 1 ]]; then
        log_echo "${OK} ${GreenBG} ${port} $(gettext "端口由本项目服务占用, 将在安装前停止") ${Font}"
        return 0
    fi

    log_echo "${Error} ${RedBG} $(gettext "检测到端口被占用"): ${port} ${Font}"
    echo "${listener_output}"
    log_echo "${Warning} ${YellowBG} $(gettext "脚本不会自动终止占用该端口的进程") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "请更换端口或自行停止对应服务后重试") ${Font}"
    return 1
}

acme() {
    systemctl restart nginx
    #暂时解决ca问题
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --server letsencrypt --keylength ec-256 --force --test; then
        log_echo "${OK} ${GreenBG} SSL $(gettext "证书测试签发成功, 开始正式签发") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
    else
        log_echo "${Error} ${RedBG} SSL $(gettext "证书测试签发失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" -w "${idleleo_conf_dir}" --server letsencrypt --keylength ec-256 --force; then
        log_echo "${OK} ${GreenBG} SSL $(gettext "证书生成") $(gettext "成功") ${Font}"
        mkdir -p "${ssl_chainpath}"
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --force --reloadcmd "chown -f root:idleleo-nginx ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && systemctl restart nginx && systemctl restart xray"; then
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            log_echo "${OK} ${GreenBG} SSL $(gettext "证书配置") $(gettext "成功") ${Font}"
            systemctl stop nginx
        else
            log_echo "${Error} ${RedBG} SSL $(gettext "证书配置") $(gettext "失败") ${Font}"
            return 1
        fi
    else
        log_echo "${Error} ${RedBG} SSL $(gettext "证书生成") $(gettext "失败") ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
}

xray_conf_add() {
    # Source of truth for multi-user is the actual Xray config, not
    # install_config.json — install_config_* may have already overwritten
    # the metadata before this function runs.
    local _multi_user_detected
    _multi_user_detected=$(detect_multi_user_from_xray_conf)

    # standard_rebuild and mode_switch must always rebuild from template —
    # never preserve the old mode's Xray JSON, even if multi-user is detected.
    case "${reinstall_operation}" in
        standard_rebuild|mode_switch|clean_install)
            _multi_user_detected="no"
            # Remove old multi-user metadata so it doesn't interfere.
            if [[ -f "${xray_install_config_file}" ]]; then
                update_json_config "${xray_install_config_file}" 'del(.multi_user)' 2>/dev/null || true
            fi
            ;;
    esac

    if [[ "${_multi_user_detected}" == "yes" ]]; then
        # Ensure metadata reflects reality so subsequent reads are consistent.
        if [[ -f "${xray_install_config_file}" ]]; then
            local _cur_multi_user
            _cur_multi_user=$(info_extraction multi_user 2>/dev/null)
            [[ "${_cur_multi_user}" != "yes" ]] && \
                update_json_config "${xray_install_config_file}" --arg mu "yes" '.multi_user = $mu' 2>/dev/null || true
        fi
    fi

    # keep-config path — preserve the existing Xray JSON and apply only the
    # user-selected changes. This protects custom routing/outbounds/DNS and
    # multi-user configs. Allowed for both single-user and multi-user: multi-user
    # may modify non-user fields (port, path, Reality params) but NOT UUID/email.
    # Falls back to template rebuild when there is no existing config file.
    if [[ "${reinstall_keep_config}" == "on" && -f "${xray_conf}" ]]; then
        # Apply selected changes to the existing config in-place.
        # Only modify fields the user explicitly chose to change.
        # All modify_* calls must propagate errors (|| return 1).
        if [[ "${change_port}" == "yes" ]]; then
            modify_inbound_port || return 1
        fi
        if [[ "${change_inner_ports}" == "yes" ]]; then
            modify_inbound_port || return 1
        fi
        if [[ "${change_ws_path}" == "yes" || "${change_grpc_path}" == "yes" || "${change_xhttp_path}" == "yes" ]]; then
            modify_path || return 1
        fi
        # UUID/email changes are NOT allowed in keep-config — use user management.
        # change_user is intentionally not handled here; the edit menu no longer
        # offers it and directs users to the user-management entry point.
        if [[ "${change_reality}" == "yes" ]] && [[ ${tls_mode} == "Reality" ]]; then
            modify_target_serverNames || return 1
            modify_privateKey_shortIds || return 1
        fi
        # Transport structure changes are NOT supported in keep-config.
        # change_transport is intentionally not handled here — the edit menu
        # redirects transport changes to standard template rebuild.
        return 0
    fi

    # Template rebuild path (fresh install, standard_rebuild, or mode_switch)
    if [[ "${_multi_user_detected}" != "yes" ]] && \
       [[ "${reinstall_keep_config}" != "on" || ! -f "${xray_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            judge "$(gettext "下载 Xray TLS 配置")" download_json_file "${shell_release_raw_base}/config/vless_tls.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                add_grpc_inbound "127.0.0.1" "${gport}" "${serviceName}"
                add_xhttp_inbound "127.0.0.1" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        elif [[ ${tls_mode} == "Reality" ]]; then
            judge "$(gettext "下载 Xray Reality 配置")" download_json_file "${shell_release_raw_base}/config/vless_reality.json" "${xray_conf}"
            modify_target_serverNames
            modify_privateKey_shortIds
            xray_reality_add_more
        elif [[ ${tls_mode} == "None" ]]; then
            judge "$(gettext "下载 Xray 配置")" download_json_file "${shell_release_raw_base}/config/vless_tls.json" "${xray_conf}"
            if [[ ${transport_mode} == "onlygRPC" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                update_json_config "${xray_conf}" 'del(.inbounds[] | select(.tag == "VLESS-ws-in")) | .routing.rules[0].inboundTag = []'
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
                add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
            fi
            modify_listen_address
            modify_path
            modify_inbound_port
        fi
        modify_email_address
        modify_UUID
    else
        echo
        log_echo "${Warning} ${GreenBG} $(gettext "检测到 Xray 配置过多用户") ${Font}"
        log_echo "${GreenBG} $(gettext "是否保留原 Xray 配置文件") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r save_originxray_fq
        case $save_originxray_fq in
        [nN][oO] | [nN])
            rm -rf "${xray_conf}"
            update_json_config "${xray_install_config_file}" 'del(.multi_user)'
            log_echo "${OK} ${GreenBG} $(gettext "原配置文件已删除")! ${Font}"
            xray_conf_add
            ;;
        *) ;;
        esac
    fi
}

xray_reality_add_more() {
    if [[ ${reality_add_more} == "on" ]]; then
        if is_ws_mode; then
            add_ws_inbound "0.0.0.0" "${xport}" "${path}"
        fi
        if is_grpc_mode; then
            add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
        fi
        if is_xhttp_mode; then
            add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
        fi
        modify_path
        modify_listen_address
        modify_inbound_port
        judge "$(gettext "添加简单 ws/gRPC/xHTTP 协议")"
    else
        if is_ws_mode; then
            add_ws_inbound "0.0.0.0" "${xport}" "${path}"
        fi
        if is_grpc_mode; then
            add_grpc_inbound "0.0.0.0" "${gport}" "${serviceName}"
        fi
        if is_xhttp_mode; then
            add_xhttp_inbound "0.0.0.0" "${xhttpport}" "${xhttppath}"
        fi
        modify_path
        modify_inbound_port
    fi

    if [[ ${reality_add_nginx} == "on" ]] && [[ ${reality_add_balance} == "off" ]]; then
        modify_reality_listen_address
    fi
}

old_config_exist_check() {
    # Role guards: a relay owns the whole server, and the removed "XTLS ONLY"
    # mode is not migrated. Neither may be silently overwritten by a node
    # install; the operator has to act first.
    if [[ -f "${xray_install_config_file}" ]] && is_relay_role; then
        log_echo "${Error} ${RedBG} $(gettext "当前服务器为中转节点, 不支持与普通节点混装") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "请先删除中转节点, 再安装普通节点") ${Font}"
        return 1
    fi
    if is_legacy_xtls_mode; then
        log_echo "${Error} ${RedBG} $(gettext "检测到旧版 XTLS 模式, 该模式已取消, 不支持重装或模式切换") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "现有配置与服务不会被改动; 如需继续使用请卸载后重新部署") ${Font}"
        return 1
    fi
    # Reset reinstall flags — only set to "on" inside this function when the
    # user explicitly chooses 保留配置重新安装 / mode switch. Ensures a
    # previous reinstall does not leak into a subsequent fresh install.
    reinstall_keep_config="off"
    reinstall_operation="none"
    mode_switch_reuse="off"
    # Reset all change_* flags to prevent leakage from prior reinstall.
    change_port="no"
    change_user="no"
    change_transport="no"
    change_inner_ports="no"
    change_reality="no"
    change_nginx_sni="no"
    change_ws_path="no"
    change_grpc_path="no"
    change_xhttp_path="no"
    # Capture the pre-deploy managed port set for the firewall transaction.
    # managed_ports.json still holds the old value at this point (before any
    # deploy changes), so it is the correct source for rollback.
    _reinstall_firewall_old_ports=$(cat "${managed_ports_file}" 2>/dev/null ||
        echo '{"tcp":[],"udp":[]}')
    # Capture the family set the OLD config was last managed with. This MUST
    # happen before the mode-switch branch below deletes the old config: after
    # that the old network_mode is unrecoverable, and a dual -> ipv4 switch
    # would otherwise fall back to the CURRENT mode (already the target) and
    # leave stale IPv6 managed rules behind.
    _reinstall_firewall_old_families=""
    if [[ -f "${xray_install_config_file}" ]]; then
        _reinstall_firewall_old_families=$(managed_fw_families_from_config "${xray_install_config_file}")
    fi
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_changed="no"
    # Reset baseline-rule transaction state for this reinstall; the OLD family
    # set is captured from the ownership state when firewall_set applies the
    # baseline (baseline_sync), so a failed family gain can be reversed here.
    _reinstall_baseline_old_families=""
    _reinstall_baseline_new_families=""
    _reinstall_baseline_changed="no"
    _reinstall_baseline_pending_added_v4=""
    _reinstall_baseline_pending_added_v6=""
    if [[ -f "${xray_install_config_file}" ]]; then
        # Snapshot the running config before any reinstall or mode switch
        # So a failed deploy can be rolled back. Skip in test mode
        # where systemctl/xray binaries may not exist.
        if [[ -z "${_TEST_MODE:-}" ]]; then
            if ! _reinstall_backup_dir=$(reinstall_backup_create 2>/dev/null); then
                log_echo "${Error} ${RedBG} $(gettext "无法完成安全备份, 已取消重新配置") ${Font}"
                _reinstall_backup_dir=""
                return 1
            fi
        fi
        if [[ ${old_tls_mode} == ${tls_mode} ]]; then
            # Split into two explicit paths — keep-config reinstall
            # vs. standard-template rebuild — instead of a single Y/N that
            # conflates "read old config" with "lock all parameters".
            echo
            log_echo "${GreenBG} $(gettext "检测到已有安装配置") ${Font}"
            log_echo "  ${Green}1)${Font} $(gettext "保留配置重新安装")"
            log_echo "  ${Green}2)${Font} $(gettext "使用标准模板重建")"
            log_echo "  ${Green}3)${Font} $(gettext "返回")"
            echo
            log_echo "${GreenBG} $(gettext "请选择") [1/2/3]: ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            1)
                # 保留配置重新安装: read old params, preserve the existing
                # Xray JSON (custom routing/outbounds/DNS are kept).
                log_echo "${OK} ${GreenBG} $(gettext "已选择保留配置重新安装") ${Font}"
                old_config_status="on"
                old_config_loaded="on"
                reinstall_keep_config="on"
                reinstall_operation="keep_config"
                old_config_input
                # Let the user pick which params to modify; unselected
                # fields keep their old values during the reinstall.
                reinstall_edit_menu
                ;;
            2)
                # 使用标准模板重建: warn that custom fields may be removed,
                # then drop the old config and proceed with fresh input.
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "自定义 routing、outbounds、DNS 和其他非标准字段可能被移除") ${Font}"
                log_echo "${Warning} ${YellowBG} $(gettext "原配置已备份") ${Font}"
                log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r _rebuild_confirm
                case $_rebuild_confirm in
                [yY][eE][sS] | [yY])
                    rm -rf "${xray_install_config_file}"
                    old_config_status="off"
                    reinstall_keep_config="off"
                    reinstall_operation="standard_rebuild"
                    log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件, 将使用标准模板重建") ${Font}"
                    ;;
                *)
                    log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                    menu
                    ;;
                esac
                ;;
            3|*)
                log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                menu
                ;;
            esac
        else
            # Dedicated mode-switch entry. Show what can be reused,
            # what cannot, and what is backed up. Only proceed after
            # explicit confirmation. The backup was already created at the
            # top of this function, so reinstall_finalize will restore on
            # deploy failure.
            echo
            log_echo "${Warning} ${YellowBG} $(gettext "检测到当前安装模式与配置文件的安装模式不一致") ${Font}"
            log_echo "  $(gettext "当前模式"): ${old_tls_mode}"
            log_echo "  $(gettext "目标模式"): ${tls_mode}"
            echo
            log_echo "${GreenBG} $(gettext "可以复用") ${Font}"
            log_echo "  - UUID"
            log_echo "  - $(gettext "用户名 (email)")"
            echo
            log_echo "${YellowBG} $(gettext "不能直接复用") ${Font}"
            log_echo "  - $(gettext "模式相关参数 (target/privateKey/shortIds/路径等)")"
            echo
            log_echo "${GreenBG} $(gettext "将保留") ${Font}"
            log_echo "  - $(gettext "原 Xray 配置备份")"
            log_echo "  - $(gettext "原 Nginx 配置备份")"
            log_echo "  - $(gettext "原证书")"
            echo
            log_echo "${GreenBG} $(gettext "是否继续切换模式") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r old_config_fq
            case $old_config_fq in
            [yY][eE][sS] | [yY])
                # Reuse mode-independent params from the old config.
                custom_email=$(info_extraction email 2>/dev/null)
                UUID5_char=$(info_extraction idc 2>/dev/null)
                UUID=$(info_extraction id 2>/dev/null)
                mode_switch_reuse="yes"
                reinstall_operation="mode_switch"
                rm -rf "${xray_install_config_file}"
                old_config_status="off"
                reinstall_keep_config="off"
                log_echo "${OK} ${GreenBG} $(gettext "已删除旧配置文件, 将使用目标模式标准模板生成新配置") ${Font}"
                ;;
            *)
                log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
                menu
                ;;
            esac
        fi
    fi
}

old_config_input() {
    info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    _info_cache_invalidate
    custom_email=$(info_extraction email)
    UUID5_char=$(info_extraction idc)
    UUID=$(info_extraction id)
    if [[ ${tls_mode} == "TLS" ]]; then
        port=$(info_extraction port)
        if is_ws_mode; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
        fi
        if is_grpc_mode; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
        if is_xhttp_mode; then
            xhttpport=$(info_extraction xhttp_port)
            xhttppath=$(info_extraction xhttp_path)
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        port=$(info_extraction port)
        target=$(info_extraction target)
        serverNames=$(info_extraction serverNames)
        privateKey=$(info_extraction privateKey)
        password=$(info_reality_public_key)
        shortIds=$(info_extraction shortIds)
        # SNI Guard / spiderX 升级兼容：缺失字段补默认值，不覆盖老用户已有配置
        spiderx_path=$(info_extraction spiderx_path)
        reality_nginx_sni_guard=$(info_extraction reality_nginx_sni_guard)
        [[ -z "${reality_nginx_sni_guard}" ]] && reality_nginx_sni_guard="on"
        unknown_sni_policy=$(info_extraction unknown_sni_policy)
        [[ -z "${unknown_sni_policy}" ]] && unknown_sni_policy="isolate"
        decoy_domain=$(info_extraction decoy_domain)
        ensure_reality_sni_guard_defaults
        if [[ ${reality_add_more} == "on" ]]; then
            if is_ws_mode; then
                xport=$(info_extraction ws_port)
                path=$(info_extraction ws_path)
            fi
            if is_grpc_mode; then
                gport=$(info_extraction grpc_port)
                serviceName=$(info_extraction grpc_serviceName)
            fi
            if is_xhttp_mode; then
                xhttpport=$(info_extraction xhttp_port)
                xhttppath=$(info_extraction xhttp_path)
            fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if is_ws_mode; then
            xport=$(info_extraction ws_port)
            path=$(info_extraction path)
        fi
        if is_grpc_mode; then
            gport=$(info_extraction grpc_port)
            serviceName=$(info_extraction serviceName)
        fi
        if is_xhttp_mode; then
            xhttpport=$(info_extraction xhttp_port)
            xhttppath=$(info_extraction xhttp_path)
        fi
    fi
    if [[ 0 -eq ${read_config_status} ]]; then
        # The old prompt said "已保留配置文件" while setting
        # old_config_status="off", which meant the install flow would
        # re-prompt and overwrite. Provide clear, behavior-matching options.
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "检测到配置文件不完整") ${Font}"
        log_echo "  ${Green}1)${Font} $(gettext "尝试从实际 Xray 配置补全安装信息")"
        log_echo "  ${Green}2)${Font} $(gettext "备份旧配置后使用标准模板重建")"
        log_echo "  ${Green}3)${Font} $(gettext "返回")"
        echo
        log_echo "${GreenBG} $(gettext "请选择") [1/2/3]: ${Font}"
        read -r old_config_input_fq
        case $old_config_input_fq in
        1)
            # Keep what was read; the install flow will use available
            # values and fall back to defaults for missing fields.
            old_config_status="on"
            reinstall_keep_config="on"
            log_echo "${OK} ${GreenBG} $(gettext "将尝试使用已读取的配置继续") ${Font}"
            ;;
        2)
            rm -rf "${xray_install_config_file}"
            old_config_status="off"
            reinstall_keep_config="off"
            log_echo "${OK} ${GreenBG} $(gettext "已删除不完整配置文件, 将使用标准模板重建") ${Font}"
            ;;
        3|*)
            log_echo "${OK} ${GreenBG} $(gettext "已取消, 返回菜单") ${Font}"
            menu
            ;;
        esac
    fi
}

# Reinstall parameter edit menu.
# Called after old_config_input reads the old config. Lets the user pick
# which fields to modify; unselected fields keep their old values.
# Sets the per-field change_* flags that param functions check.
reinstall_edit_menu() {
    echo
    log_echo "${GreenBG} $(gettext "当前配置摘要") ${Font}"
    log_echo "  $(gettext "安装模式"): ${tls_mode}"
    [[ -n "${transport_mode:-}" ]] && log_echo "  $(gettext "传输组合"): ${transport_mode}"
    [[ -n "${port:-}" ]] && log_echo "  $(gettext "主端口"): ${port}"
    if [[ ${tls_mode} == "Reality" ]]; then
        [[ -n "${target:-}" ]] && log_echo "  target: ${target}"
        [[ -n "${serverNames:-}" ]] && log_echo "  serverNames: ${serverNames}"
    fi
    if is_ws_mode; then
        [[ -n "${xport:-}" ]] && log_echo "  ws $(gettext "端口"): ${xport}"
        [[ -n "${path:-}" ]] && log_echo "  ws $(gettext "路径"): ${path}"
    fi
    if is_grpc_mode; then
        [[ -n "${gport:-}" ]] && log_echo "  gRPC $(gettext "端口"): ${gport}"
        [[ -n "${serviceName:-}" ]] && log_echo "  gRPC serviceName: ${serviceName}"
    fi
    if is_xhttp_mode; then
        [[ -n "${xhttpport:-}" ]] && log_echo "  xHTTP $(gettext "端口"): ${xhttpport}"
        [[ -n "${xhttppath:-}" ]] && log_echo "  xHTTP $(gettext "路径"): ${xhttppath}"
    fi
    echo
    log_echo "${GreenBG} $(gettext "可选择需要修改的项目 (未选择的保持原值)") ${Font}"
    log_echo "  ${Green}1)${Font} $(gettext "修改主端口")"
    log_echo "  ${Green}2)${Font} $(gettext "修改内部端口")"
    log_echo "  ${Green}3)${Font} $(gettext "修改传输路径")"
    log_echo "  ${Green}4)${Font} $(gettext "修改 Reality 参数")"
    log_echo "  ${Green}5)${Font} $(gettext "不再修改, 开始重新部署")"
    echo
    log_echo "${Warning} ${YellowBG} $(gettext "UUID 和多用户信息请使用现有用户管理或 UUID 变更功能") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "传输组合变更请使用标准模板重建") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "Nginx/SNI 修改请使用标准模板重建") ${Font}"
    echo
    local _edit_choice
    while true; do
        log_echo "${GreenBG} $(gettext "请选择") [1-5]: ${Font}"
        read -r _edit_choice
        case $_edit_choice in
        1) change_port="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改主端口") ${Font}" ;;
        2) change_inner_ports="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改内部端口") ${Font}" ;;
        3) change_ws_path="yes"; change_grpc_path="yes"; change_xhttp_path="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改传输路径") ${Font}" ;;
        4) change_reality="yes"; log_echo "${OK} ${GreenBG} $(gettext "已选择修改 Reality 参数") ${Font}" ;;
        5) break ;;
        *) log_echo "${Error} ${RedBG} $(gettext "值为空或超出范围, 请重新输入") ${Font}" ;;
        esac
    done
}

nginx_ssl_conf_add() {
    touch "${nginx_ssl_conf}"
    cat >"${nginx_ssl_conf}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name serveraddr.com;

    location ^~ /.well-known/acme-challenge/ {
        root ${idleleo_dir}/conf;
        default_type "text/plain";
        allow all;
    }
    location = /.well-known/acme-challenge/ {
        return 404;
    }

    location / {
        return 301 https://www.hey.run\$request_uri;
    }
}
EOF
    modify_nginx_ssl_other
    judge "Nginx SSL $(gettext "配置修改")"
}

nginx_conf_add() {
    touch "${nginx_conf}"
    cat >"${nginx_conf}" <<EOF
server {
    listen 443 ssl reuseport;
    listen [::]:443 ssl reuseport;
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    http2 on;
    set_real_ip_from      127.0.0.1;
    real_ip_header        X-Forwarded-For;
    real_ip_recursive     on;
    ssl_certificate       ${idleleo_dir}/cert/xray.crt;
    ssl_certificate_key   ${idleleo_dir}/cert/xray.key;
    ssl_protocols         TLSv1.3;
    ssl_ciphers           ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
    ssl_ecdh_curve        X25519:prime256v1:secp384r1;
    server_name           serveraddr.com;
    root /var/www/html;
    error_page 403 https://hey.run/helloworld;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_early_data on;
    # OCSP stapling stays disabled by default; enable only with a valid issuer chain.
    # ssl_stapling on;
    # ssl_stapling_verify on;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=31536000";

    location grpc
    {
        #grpc_pass grpc://xray-grpc-server;
        #proxy_pass http://xray-grpc-server;
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host \$http_host;
    }

    location ws
    {
        #proxy_pass http://xray-ws-server;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_connect_timeout 60s;
        proxy_send_timeout 720m;
        proxy_read_timeout 720m;
        proxy_buffering off;
        client_max_body_size 0;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
    }

    location xhttp
    {
        #grpc_pass grpc://xray-xhttp-server;
        grpc_connect_timeout 60s;
        grpc_read_timeout 720m;
        grpc_send_timeout 720m;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header Early-Data \$ssl_early_data;
        grpc_set_header Host \$host;
        # grpc_pass ignores proxy_buffering (ngx_http_proxy_module only); the
        # gRPC module keeps its own buffering default, so no proxy_buffering
        # line belongs here. The proxy_pass alternative below is inactive and
        # its commented proxy_buffering only matters if it is switched back on.
        # Request bodies above nginx's 1m default must still pass: stream-one /
        # stream-up uploads used to fail with 413 while ws stayed healthy.
        client_max_body_size 0;
        #proxy_pass http://xray-xhttp-server;
        #proxy_redirect off;
        #proxy_http_version 1.1;
        #proxy_connect_timeout 60s;
        #proxy_send_timeout 720m;
        #proxy_read_timeout 720m;
        #proxy_buffering off;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        #proxy_set_header Host \$http_host;
    }

    location /
    {
        return 403;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx $(gettext "配置修改")"
}

nginx_reality_conf_add() {
    validate_reality_reserved_ports || return 1
    touch "${nginx_conf}"
    # SNI Guard 策略分支：isolate 默认(ssl_reject_handshake)/reject 死端口/decoy 回落站点
    # 注意：ssl_reject_handshake 属于 ngx_http_ssl_module，必须在 http{} 块内生效，
    #       不能放在 stream{} 块里。isolate 策略下单独写入 03-isolate.conf 由 http 块 include。
    local _deny_port
    case "${unknown_sni_policy}" in
        reject)
            # 直接拒绝：指向无监听的死端口，TCP 连接被拒绝
            _deny_port="9404"
            ;;
        decoy)
            # decoy 回落：指向本地 9444 的 HTTPS 站点（由 03-decoy.conf 提供）
            if decoy_site_artifacts_ready; then
                _deny_port="9444"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_decoy_site_config || return 1
            else
                log_echo "${Warning} ${YellowBG} $(gettext "decoy 站点设置失败, 回退到默认隔离策略") ${Font}"
                unknown_sni_policy="isolate"
                decoy_domain=""
                _deny_port="9403"
                if sni_guard_port_conflicts "${_deny_port}"; then
                    log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                    return 1
                fi
                write_isolate_site_config || return 1
            fi
            ;;
        isolate|*)
            # 隔离：ssl_reject_handshake 发送 TLS alert，不转发到 Xray
            # deny upstream 指向 127.0.0.1:9403，由 http 块内的 03-isolate.conf server 提供 TLS 拒绝
            _deny_port="9403"
            if sni_guard_port_conflicts "${_deny_port}"; then
                log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
                return 1
            fi
            write_isolate_site_config || return 1
            ;;
    esac
    if [[ "${unknown_sni_policy}" == "reject" ]] && sni_guard_port_conflicts "${_deny_port}"; then
        log_echo "${Error} ${RedBG} $(gettext "端口不允许使用, 请重新输入")! ${_deny_port} ${Font}"
        return 1
    fi
    cat >"${nginx_conf}" <<EOF

stream {
    map \$ssl_preread_protocol \$is_valid_protocol {
        #TLSv1.2    1;
        TLSv1.3    1;
        default    0;
    }

    map \$ssl_preread_server_name \$sni_upstream {
        include ${nginx_conf_dir}/*.serverNames;
        default deny;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$final_upstream {
        # 格式：上游名称:协议标记 => 最终上游
        ~^reality:1\$     reality;
        default          deny;
    }

    map \$final_upstream \$is_abnormal {
        deny    1;
        default 0;
    }

    map "\$sni_upstream:\$is_valid_protocol" \$error_type {
        ~^reality:0\$     "tls_error";
        ~^deny:1\$        "sni_error";
        ~^deny:0\$        "tls_sni_error";
        default          "other_error";
    }

    map \$error_type \$is_tls_error {
        "tls_error"      1;
        #"tls_sni_error"  1;
        default          0;
    }

    map \$error_type \$is_sni_error {
        "sni_error"      1;
        "tls_sni_error"  1;
        default          0;
    }

    upstream reality {
        include ${nginx_conf_dir}/*.realityServers;
    }

    upstream deny {
        server 127.0.0.1:${_deny_port};
    }

    log_format tls_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    log_format sni_error_log '\$remote_addr [\$time_local] "\$ssl_preread_server_name" '
                             '\$ssl_preread_protocol \$status';

    server {
        listen 443 reuseport so_keepalive=on backlog=65535;
        proxy_pass \$final_upstream;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
        access_log ${nginx_dir}/logs/tls_error.log tls_error_log buffer=8k flush=3s if=\$is_tls_error;
        access_log ${nginx_dir}/logs/sni_error.log sni_error_log buffer=8k flush=3s if=\$is_sni_error;
    }
}
EOF
    modify_nginx_port
    modify_nginx_other
    judge "Nginx $(gettext "配置修改")"
}

nginx_reality_servers_add () {
    touch "${nginx_conf_dir}"/127.0.0.1.realityServers
    cat >"${nginx_conf_dir}"/127.0.0.1.realityServers <<EOF
server 127.0.0.1:9443 weight=50 max_fails=2 fail_timeout=10;
EOF
    judge "Nginx servers $(gettext "配置修改")"

}

nginx_reality_serverNames_add () {
    _cleanup_stale_serverNames_fragments || return 1
    touch "${nginx_conf_dir}"/${serverNames}.serverNames
    cat >"${nginx_conf_dir}"/${serverNames}.serverNames <<EOF
${serverNames} reality;
EOF
    judge "Nginx serverNames $(gettext "配置修改")"

}

nginx_reality_serverNames_del () {
    [[ -f "${nginx_conf_dir}/${serverNames}.serverNames" ]] && rm -f "${nginx_conf_dir}/${serverNames}.serverNames"
    judge "Nginx serverNames $(gettext "配置删除")"

}

nginx_servers_conf_add() {
    touch "${nginx_upstream_conf}"
    > "${nginx_upstream_conf}"
    if is_ws_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-ws-server {
    include ${nginx_conf_dir}/*.wsServers;
}

EOF
    fi
    if is_grpc_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-grpc-server {
    include ${nginx_conf_dir}/*.grpcServers;
}

EOF
    fi
    if is_xhttp_mode; then
        cat >>"${nginx_upstream_conf}" <<EOF
upstream xray-xhttp-server {
    include ${nginx_conf_dir}/*.xhttpServers;
}

EOF
    fi
    nginx_servers_add
    judge "Nginx servers $(gettext "配置修改")"
}

enable_process_systemd() {
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] || return 1
        systemctl enable nginx
        judge -r "$(gettext "设置 Nginx 开机自启")" || return 1
        return 0
    fi
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl enable nginx
            judge -r "$(gettext "设置 Nginx 开机自启")" || return 1
        fi
    fi
    systemctl enable xray
    judge -r "$(gettext "设置") Xray $(gettext "开机自启")" || return 1
}

disable_process_systemd() {
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] || return 0
        systemctl stop nginx && systemctl disable nginx
        judge -r "$(gettext "关闭 Nginx 开机自启")" || return 1
        return 0
    fi
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl stop nginx && systemctl disable nginx
            judge -r "$(gettext "关闭 Nginx 开机自启")" || return 1
        fi
    fi
    systemctl disable xray
    judge -r "$(gettext "关闭") Xray $(gettext "开机自启")" || return 1
}

stop_service_all() {
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] && { systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; }
        log_echo "${OK} ${GreenBG} $(gettext "停止") ${Font}"
        return 0
    fi
    [[ -f "${nginx_systemd_file}" ]] && { systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; }
    systemctl stop xray 2>/dev/null
    systemctl disable xray 2>/dev/null
    if [[ ${tls_mode} != "TLS" ]] && [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
        log_echo "${OK} ${GreenBG} $(gettext "已清理残留的证书自动更新定时任务") ${Font}"
    fi
    log_echo "${OK} ${GreenBG} $(gettext "停止") ${Font}"
}

acme_cron_cleanup() {
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
        log_echo "${OK} ${GreenBG} $(gettext "已清理证书自动更新定时任务") ${Font}"
    fi
}

service_restart() {
    systemctl daemon-reload
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] || return 1
        systemctl restart nginx
        if ! judge -r "Nginx $(gettext "重启")"; then
            nginx_diagnose
            return 1
        fi
        return 0
    fi
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl restart nginx
            if ! judge -r "Nginx $(gettext "重启")"; then
                nginx_diagnose
                return 1
            fi
        fi
    fi
    systemctl restart xray
    if ! judge -r "Xray $(gettext "重启")"; then
        xray_diagnose
        return 1
    fi
}

service_start() {
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] || return 1
        systemctl start nginx
        if ! judge -r "Nginx $(gettext "启动")"; then
            nginx_diagnose
            return 1
        fi
        return 0
    fi
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl start nginx
            if ! judge -r "Nginx $(gettext "启动")"; then
                nginx_diagnose
                return 1
            fi
        fi
    fi
    systemctl start xray
    if ! judge -r "Xray $(gettext "启动")"; then
        xray_diagnose
        return 1
    fi
}

service_stop() {
    if is_relay_role; then
        [[ -f "${nginx_systemd_file}" ]] || return 1
        systemctl stop nginx
        judge -r "Nginx $(gettext "停止")" || return 1
        return 0
    fi
    if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl stop nginx
            judge -r "Nginx $(gettext "停止")" || return 1
        fi
    fi
    systemctl stop xray
    judge -r "Xray $(gettext "停止")" || return 1
}

acme_cron_update() {
    if [[ ${tls_mode} == "TLS" ]]; then
        local crontab_file
        crontab_file="$(root_crontab_path)"
        if [[ -f "${ssl_update_file}" ]] && [[ $(crontab -l | grep -Fc -- "${ssl_update_file}") == "1" ]]; then
            echo
            log_echo "${Warning} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
            log_echo "${Warning} ${GreenBG} $(gettext "老版本请及时删除 废弃的 改版证书自动更新")! ${Font}"
            log_echo "${GreenBG} $(gettext "已设置改版证书自动更新") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除改版证书自动更新 (请删除)") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
            read -r remove_acme_cron_update_fq
            case $remove_acme_cron_update_fq in
            [nN][oO] | [nN]) ;;
            *)
                sed -i "\|${ssl_update_file}|d" "${crontab_file}"
                rm -rf "${ssl_update_file}"
                judge -r "$(gettext "删除改版证书自动更新")"
                ;;
            esac
        else
            echo
            log_echo "${OK} ${GreenBG} $(gettext "新版本已自动设置证书自动更新") ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

check_cert_status() {
    if [[ ${tls_mode} == "TLS" ]]; then
        host="$(info_extraction host)"
        if [[ -d "$HOME/.acme.sh/${host}_ecc" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.key" ]] && [[ -f "$HOME/.acme.sh/${host}_ecc/${host}.cer" ]]; then
            modifyTime=$(stat -c %Y "$HOME/.acme.sh/${host}_ecc/${host}.cer" 2>/dev/null)
            currentTime=$(date +%s)
            ((stampDiff = currentTime - modifyTime))
            ((days = stampDiff / 86400))
            ((remainingDays = 90 - days))
            tlsStatus=${remainingDays}
            [[ ${remainingDays} -le 0 ]] && tlsStatus="${Yellow}$(gettext "已过期")${Font}"
            echo
            log_echo "${Green}$(gettext "证书生成日期"): $(date -d "@${modifyTime}" +"%F %H:%M:%S")${Font}"
            log_echo "${Green}$(gettext "证书生成天数"): ${days}${Font}"
            log_echo "${Green}$(gettext "证书剩余天数"): ${tlsStatus}${Font}"
            echo
            if [[ ${remainingDays} -le 0 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "是否立即更新证书") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r cert_update_manuel_fq
                case $cert_update_manuel_fq in
                [yY][eE][sS] | [yY])
                    # Service state handling lives inside cert_update_manuel so
                    # a failed renewal can always restore what it stopped.
                    cert_update_manuel || return 1
                    ;;
                *) ;;
                esac
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发")! ${Font}"
        fi
    else
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
    fi
}

cert_update_manuel() {
    if [[ ${tls_mode} != "TLS" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作")! ${Font}"
        return 1
    fi

    # Every precondition is checked before a service is stopped, so a missing
    # prerequisite can never leave Xray down.
    if [[ ! -f "${amce_sh_file}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "证书签发工具不存在, 请确认是否证书为脚本签发")! ${Font}"
        return 1
    fi

    local _cert_host _cert_group _xray_was_active="no" _rc=0
    _cert_host="$(info_extraction host)"
    if [[ -z "${_cert_host}" || "${_cert_host}" == "null" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "无法读取域名, 已取消证书更新")! ${Font}"
        return 1
    fi
    if [[ ! -d "${ssl_chainpath}" ]] && ! mkdir -p "${ssl_chainpath}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "证书目录不可用, 已取消证书更新")! ${Font}"
        return 1
    fi
    _cert_group="$(get_nginx_worker_group)"
    if [[ -z "${_cert_group}" ]] ||
        { command -v getent >/dev/null 2>&1 && ! getent group "${_cert_group}" >/dev/null 2>&1; }; then
        log_echo "${Error} ${RedBG} $(gettext "证书所需的服务组不存在, 已取消证书更新")! ${Font}"
        return 1
    fi

    if systemctl is-active --quiet xray 2>/dev/null; then
        _xray_was_active="yes"
        if ! systemctl stop xray >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} $(gettext "无法停止 Xray, 已取消证书更新")! ${Font}"
            return 1
        fi
    fi

    local _reloadcmd="chown -f root:${_cert_group} ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key"
    # --reloadcmd is persisted in the acme.sh renewal config. It must not
    # restart services: this function and ssl_update.sh already restart them
    # once, and a restart inside the hook would double-restart every renewal.
    if ! "${amce_sh_file}" --cron --home "$(dirname "${amce_sh_file}")"; then
        log_echo "${Error} ${RedBG} acme.sh $(gettext "续签失败")! ${Font}"
        _rc=1
    elif ! "${amce_sh_file}" --installcert -d "${_cert_host}" \
        --fullchainpath "${ssl_chainpath}/xray.crt" \
        --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "${_reloadcmd}"; then
        log_echo "${Error} ${RedBG} $(gettext "证书安装失败")! ${Font}"
        _rc=1
    elif ! apply_nginx_layered_permissions; then
        _rc=1
    elif ! verify_nginx_layered_permissions; then
        _rc=1
    elif ! service_restart; then
        _rc=1
    fi

    if [[ ${_rc} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "证书更新") $(gettext "失败")! ${Font}"
        if [[ "${_xray_was_active}" == "yes" ]] && ! systemctl is-active --quiet xray 2>/dev/null; then
            if systemctl start xray >/dev/null 2>&1; then
                log_echo "${OK} ${GreenBG} $(gettext "已恢复 Xray 原有运行状态") ${Font}"
            else
                log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复失败, 请手动检查")! ${Font}"
            fi
        fi
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "证书更新") $(gettext "完成") ${Font}"
}

set_fail2ban() {
    if ! ensure_sub_script "fail2ban_manager.sh" "${mf_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/fail2ban_manager.sh"
    mf_check_for_updates
    mf_main_menu
}

# CLI entry point for Fail2ban management.
# Reuses the same mf_cli() implementation as the menu — no duplicated logic.
set_fail2ban_cli() {
    if ! ensure_sub_script "fail2ban_manager.sh" "${mf_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/fail2ban_manager.sh"
    mf_cli "$@"
}

set_traffic_blocker() {
    if [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "未安装"), $(gettext "请先安装") Xray ${Font}"
        return 1
    fi
    if ! ensure_sub_script "traffic_blocker.sh" "${tb_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/traffic_blocker.sh"
    tb_check_for_updates
    tb_main_menu
}

# Direct GeoData entry (audit P2-9): the same page was buried under
# "other options -> traffic blocker -> refresh". Keep the safe update check.
set_geodata_menu() {
    if [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} Xray $(gettext "未安装"), $(gettext "请先安装") Xray ${Font}"
        return 1
    fi
    if ! ensure_sub_script "traffic_blocker.sh" "${tb_remote_url}"; then
        return 1
    fi
    source "${scripts_dir}/traffic_blocker.sh"
    tb_check_for_updates
    tb_geo_menu
}

setup_auto_clean_logs() {
    local logrotate_config="${LOGROTATE_CONFIG_PATH:-/etc/logrotate.d/xray_log_cleanup}"
    local logrotate_dir tmp_config nginx_user nginx_group
    echo

    log_echo "${GreenBG} $(gettext "是否需要设置自动清理日志") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
    read -r auto_clean_logs_fq
    case $auto_clean_logs_fq in
    [nN][oO] | [nN])
        log_echo "${OK} ${Green} $(gettext "已跳过设置自动清理日志") ${Font}"
        ;;
    *)
        log_echo "${OK} ${Green} $(gettext "将每周轮转并压缩日志") ${Font}"

        pkg_install "logrotate" || return 1
        systemctl enable --now logrotate.timer || return 1

        logrotate_dir="$(dirname "${logrotate_config}")"
        if [[ -f "${logrotate_config}" ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "已设置自动清理日志任务") ${Font}"
            log_echo "${GreenBG} $(gettext "是否需要删除现有自动清理日志任务") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r delete_task
            case $delete_task in
            [yY][eE][sS] | [yY])
                rm -f "${logrotate_config}" || return 1
                judge -r "$(gettext "删除自动清理日志任务")" || return 1
                ;;
            *)
                log_echo "${OK} ${Green} $(gettext "保留现有自动清理日志任务") ${Font}"
                return 0
                ;;
            esac
        fi

        nginx_user="$(get_nginx_worker_user)"
        nginx_group="$(get_nginx_worker_group)"
        tmp_config="$(mktemp "${logrotate_dir}/.xray_log_cleanup.XXXXXX")" || return 1
        if ! cat >"${tmp_config}" <<EOF
/var/log/xray/*.log {
    weekly
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
${nginx_dir}/logs/*.log {
    weekly
    rotate 3
    compress
    missingok
    notifempty
    create 640 ${nginx_user} ${nginx_group}
    sharedscripts
    postrotate
        if pgrep -x nginx >/dev/null 2>&1; then
            ${nginx_dir}/sbin/nginx -s reopen -c ${nginx_dir}/conf/nginx.conf
        fi
    endscript
}
EOF
        then
            rm -f "${tmp_config}"
            return 1
        fi
        chmod 644 "${tmp_config}" || { rm -f "${tmp_config}"; return 1; }
        if ! logrotate --debug "${tmp_config}" >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} $(gettext "logrotate 配置检查失败") ${Font}"
            rm -f "${tmp_config}"
            return 1
        fi
        if ! mv -f "${tmp_config}" "${logrotate_config}"; then
            rm -f "${tmp_config}"
            return 1
        fi
        judge -r "$(gettext "设置自动清理日志")"
        ;;
    esac
}

truncate_log_file_for_cleanup() {
    : >"$1"
}

clean_logs() {
    local log_file error failed_count=0
    echo
    log_echo "${Green} $(gettext "检测到日志文件大小如下:") ${Font}"
    log_echo "${Green}$(du -sh /var/log/xray "${nginx_dir}"/logs 2>/dev/null)${Font}"
    countdown "$(gettext "即将清除")!"
    while IFS= read -r -d '' log_file; do
        if error=$(truncate_log_file_for_cleanup "${log_file}" 2>&1); then
            continue
        fi
        failed_count=$((failed_count + 1))
        log_echo "${Warning} ${YellowBG} $(gettext "未能清理"): ${log_file} (${error:-$(gettext "未知错误")}) ${Font}"
    done < <(find /var/log/xray/ "${nginx_dir}"/logs -type f -name "*.log" -print0 2>/dev/null)

    if [[ ${failed_count} -eq 0 ]]; then
        judge -r "$(gettext "日志清理")" true || return 1
    else
        log_echo "${Warning} ${YellowBG} $(gettext "日志清理完成，但部分文件未清理") (${failed_count}) ${Font}"
    fi
    setup_auto_clean_logs
}

# Detect multi-user setup by inspecting the actual Xray config.
# Returns "yes" if any inbound has more than one client, "no" otherwise.
# This is the source of truth for reinstall decisions — install_config.json's
# multi_user field may already have been overwritten by a prior install_config_*.
detect_multi_user_from_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        echo "no"
        return
    fi
    local result
    result=$(jq -r '[.inbounds[].settings.clients | length] | any(. > 1) // false' "${xray_conf}" 2>/dev/null || echo "false")
    if [[ "${result}" == "true" ]]; then
        echo "yes"
    else
        echo "no"
    fi
}

# Count total Reality clients across all inbounds in the actual Xray config.
count_reality_clients_in_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        echo 0
        return
    fi
    jq -r '[.inbounds[] | select(.protocol == "vless") | .settings.clients | length] | add // 0' "${xray_conf}" 2>/dev/null || echo 0
}

# Extract the deduplicated UUID set from all VLESS inbounds in the actual
# Xray config. Returns a sorted, newline-separated list of UUIDs. Used for
# Stable user-identity comparison across reconfigures.
extract_uuid_set_from_xray_conf() {
    if [[ ! -f "${xray_conf}" ]]; then
        return
    fi
    jq -r '[.inbounds[] | select(.protocol == "vless") | .settings.clients[]?.id // empty] | unique | sort | .[]' "${xray_conf}" 2>/dev/null
}

# Merge new install_config fields onto the existing file, preserving
# multi_user, reality_clients, and any other top-level extension fields
# the script does not manage (custom routing metadata, third-party tool
# markers, etc.).
# Usage: _install_config_merge_write <new_fields_file>
#   <new_fields_file>: path to a file containing the new-field JSON object.
_install_config_merge_write() {
    local new_fields_file="$1"
    local tmp_file _old_umask original_mode original_uid original_gid

    if [[ -z "${new_fields_file}" || ! -f "${new_fields_file}" ]]; then
        log_echo "${Error} ${RedBG} _install_config_merge_write: $(gettext "参数不能为空") ${Font}"
        return 1
    fi
    if ! jq empty "${new_fields_file}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} _install_config_merge_write: $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
        return 1
    fi

    _old_umask=$(umask)
    umask 077
    tmp_file=$(mktemp "${xray_install_config_file}.tmp.XXXXXX" 2>/dev/null) || tmp_file="${xray_install_config_file}.tmp.$$"

    # Only merge if the existing file contains a valid JSON object. An empty
    # or corrupt file (e.g. left by a failed prior write) is treated as
    # "no existing config" so the new fields become the baseline.
    if [[ -s "${xray_install_config_file}" ]] && jq -e 'type == "object"' "${xray_install_config_file}" >/dev/null 2>&1; then
        original_mode=$(stat -c '%a' "${xray_install_config_file}" 2>/dev/null) || original_mode="600"
        original_uid=$(stat -c '%u' "${xray_install_config_file}" 2>/dev/null) || original_uid="$(id -u)"
        original_gid=$(stat -c '%g' "${xray_install_config_file}" 2>/dev/null) || original_gid="$(id -g)"
        # jq merge: right operand (new fields) wins for overlapping keys;
        # left operand's (old file) unique top-level keys are preserved.
        if ! jq -s '.[0] * .[1]' "${xray_install_config_file}" "${new_fields_file}" > "${tmp_file}" 2>/dev/null; then
            umask "${_old_umask}"
            rm -f "${tmp_file}"
            log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
            return 1
        fi
    else
        original_mode="600"
        original_uid="$(id -u)"
        original_gid="$(id -g)"
        if ! jq -c . "${new_fields_file}" > "${tmp_file}" 2>/dev/null; then
            umask "${_old_umask}"
            rm -f "${tmp_file}"
            log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
            return 1
        fi
    fi

    if ! jq empty "${tmp_file}" >/dev/null 2>&1; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Error} ${RedBG} $(gettext "生成的 JSON 无效，已保留原文件"): ${xray_install_config_file} ${Font}"
        return 1
    fi
    if ! chmod "${original_mode}" "${tmp_file}" 2>/dev/null; then
        umask "${_old_umask}"
        rm -f "${tmp_file}"
        log_echo "${Warning} ${YellowBG} $(gettext "配置文件权限收紧失败"): ${xray_install_config_file} ${Font}"
        return 1
    fi
    chown "${original_uid}:${original_gid}" "${tmp_file}" 2>/dev/null || true
    umask "${_old_umask}"
    if ! mv "${tmp_file}" "${xray_install_config_file}"; then
        rm -f "${tmp_file}"
        return 1
    fi
    info_extraction_all=$(jq -rc . "${xray_install_config_file}" 2>/dev/null) || return 1
    declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate
    return 0
}

install_config_tls_ws() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${domain}",
    "ip_version": "${ip_version}",
    "network_mode": "${network_mode:-$(infer_network_mode_from_config "${ip_version}")}",
    "ipv4_address": "${ipv4_address:-}",
    "ipv6_address": "${ipv6_address:-}",
    "port": ${port},
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "tls": "TLS",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "${artnet}",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}",
    "nginx_build_version": "${nginx_build_version:-}"
}
EOF
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

install_config_reality() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "network_mode": "${network_mode:-$(infer_network_mode_from_config "${ip_version}")}",
    "ipv4_address": "${ipv4_address:-}",
    "ipv6_address": "${ipv6_address:-}",
    "port": ${port},
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "raw",
    "tls": "Reality",
    "target": "${target}",
    "serverNames":"${serverNames}",
    "privateKey":"${privateKey}",
    "publicKey":"${password}",
    "password":"${password}",
    "shortIds":"${shortIds}",
    "spiderx_path":"${spiderx_path}",
    "reality_add_nginx": "${reality_add_nginx}",
    "reality_add_balance": "${reality_add_balance}",
    "reality_balance_role": "${reality_balance_role}",
    "reality_add_more": "${reality_add_more}",
    "reality_nginx_sni_guard": "${reality_nginx_sni_guard}",
    "unknown_sni_policy": "${unknown_sni_policy}",
    "decoy_domain": "${decoy_domain}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "ws_path": "${artpath}",
    "grpc_serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}"
}
EOF
    if [[ ${reality_add_nginx} == "on" ]]; then
        # nginx_build_version is only meaningful when Reality fronted by Nginx.
        jq --arg nginx_build_version "${nginx_build_version}" \
            '. + {"nginx_build_version": $nginx_build_version}' "${_new_fields}" > "${_new_fields}.tmp" 2>/dev/null \
            && mv "${_new_fields}.tmp" "${_new_fields}"
    fi
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

install_config_ws_only() {
    local _new_fields
    _new_fields=$(mktemp)
    cat >"${_new_fields}" <<-EOF
{
    "shell_mode": "${shell_mode}",
    "transport_mode": "${transport_mode}",
    "host": "${local_ip}",
    "ip_version": "${ip_version}",
    "network_mode": "${network_mode:-$(infer_network_mode_from_config "${ip_version}")}",
    "ipv4_address": "${ipv4_address:-}",
    "ipv6_address": "${ipv6_address:-}",
    "ws_port": "${artxport}",
    "grpc_port": "${artgport}",
    "xhttp_port": "${artxhttpport}",
    "tls": "None",
    "email": "${custom_email}",
    "idc": "${UUID5_char}",
    "id": "${UUID}",
    "net": "${artnet}",
    "path": "${artpath}",
    "serviceName": "${artserviceName}",
    "xhttp_path": "${artxhttppath}",
    "shell_version": "${shell_version}",
    "xray_version": "${xray_version:-}"
}
EOF
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
}

vless_urlquote() {
    [[ $# = 0 ]] && return 1
    python3 -c "import urllib.request,sys;print(urllib.request.quote(sys.argv[1]))" "$1"
}

info_ws_path() {
    local value
    value=$(info_extraction path)
    if [[ -z ${value} || ${value} == "None" ]]; then
        value=$(info_extraction ws_path)
    fi
    echo "${value}"
}

info_grpc_serviceName() {
    local value
    value=$(info_extraction serviceName)
    if [[ -z ${value} || ${value} == "None" ]]; then
        value=$(info_extraction grpc_serviceName)
    fi
    echo "${value}"
}

format_xhttp_path() {
    local raw_path="$1"
    echo "/${raw_path#/}"
}

info_xhttp_path() {
    local value
    value=$(info_extraction xhttp_path)
    echo "${value}"
}

# publicKey 是当前规范名称；password 是 Xray 历史名称，保留以兼容旧配置。
info_reality_public_key() {
    local value
    value=$(info_extraction publicKey)
    [[ -z "${value}" ]] && value=$(info_extraction password)
    echo "${value}"
}

# 修复旧配置缺少公钥的情况：优先迁移旧 password，否则由 privateKey 重新推导。
ensure_reality_public_key() {
    [[ $(info_extraction tls) != "Reality" ]] && return 0
    [[ ! -f "${xray_install_config_file}" ]] && return 1

    local public_key private_key keys
    public_key=$(info_reality_public_key)
    if [[ -z "${public_key}" ]]; then
        private_key=$(info_extraction privateKey)
        if [[ -z "${private_key}" || ! -x "${xray_bin_dir}/xray" ]]; then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        if ! keys=$(${xray_bin_dir}/xray x25519 -i "${private_key}" 2>/dev/null); then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
        public_key=$(parse_reality_public_key "${keys}")
        if [[ -z "${public_key}" ]]; then
            log_echo "${Warning} ${YellowBG} Reality publicKey $(gettext "配置修改") $(gettext "失败") ${Font}"
            return 1
        fi
    fi

    if [[ $(info_extraction publicKey) != "${public_key}" || $(info_extraction password) != "${public_key}" ]]; then
        update_json_config "${xray_install_config_file}" --arg publicKey "${public_key}" \
           '.publicKey = $publicKey | .password = $publicKey' || return 1
        chmod -f 600 "${xray_install_config_file}" 2>/dev/null
    fi
    return 0
}

reality_client_meta() {
    local user_id="$1"
    local field="$2"
    [[ -z "${user_id}" || -z "${field}" || ! -f "${xray_install_config_file}" ]] && return 0
    jq -r --arg user_id "${user_id}" --arg field "${field}" \
       '.reality_clients[$user_id][$field] // empty' "${xray_install_config_file}" 2>/dev/null
}

generate_vless_link() {
    local user_id="$1"
    local mode="$2"
    local override_host="${3:-}"
    local host port quoted_host authority_host result
    local raw_host

    # 拆开 authority host 格式与 query/fragment 编码：
    # authority 中 IPv6 literal 必须使用 [IPv6]，不 percent-encode 冒号；
    # query/fragment 仍按各自语义 URL encode。
    if [[ -n "${override_host}" ]]; then
        raw_host="${override_host}"
    else
        raw_host=$(info_extraction host)
    fi
    authority_host=$(format_uri_authority_host "${raw_host}")
    quoted_host=$(vless_urlquote "${raw_host}")

    case "$mode" in
        ws_tls)
            port=$(info_extraction port)
            local path
            path=$(info_ws_path)
            path=$(vless_urlquote "${path}")
            result="vless://${user_id}@${authority_host}:${port}?path=%2f${path}%3Fed%3D2048&security=tls&encryption=none&host=${quoted_host}&type=ws&fp=chrome#${quoted_host}+ws%E5%8D%8F%E8%AE%AE"
            ;;
        grpc_tls)
            port=$(info_extraction port)
            local service_name
            service_name=$(info_grpc_serviceName)
            service_name=$(vless_urlquote "${service_name}")
            result="vless://${user_id}@${authority_host}:${port}?serviceName=${service_name}&security=tls&encryption=none&host=${quoted_host}&type=grpc&fp=chrome#${quoted_host}+gRPC%E5%8D%8F%E8%AE%AE"
            ;;
        xhttp_tls)
            port=$(info_extraction port)
            local xhttp_path
            xhttp_path=$(info_xhttp_path)
            xhttp_path=$(vless_urlquote "$(format_xhttp_path "${xhttp_path}")")
            result="vless://${user_id}@${authority_host}:${port}?path=${xhttp_path}&mode=auto&security=tls&encryption=none&host=${quoted_host}&type=xhttp&fp=chrome#${quoted_host}+xHTTP%E5%8D%8F%E8%AE%AE"
            ;;
        ws)
            port=$(info_extraction ws_port)
            local path
            path=$(info_ws_path)
            path=$(vless_urlquote "${path}")
            result="vless://${user_id}@${authority_host}:${port}?path=%2f${path}%3Fed%3D2048&encryption=none&type=ws#${quoted_host}+%E5%8D%95%E7%8B%ADws%E5%8D%8F%E8%AE%AE"
            ;;
        grpc)
            port=$(info_extraction grpc_port)
            local service_name
            service_name=$(info_grpc_serviceName)
            service_name=$(vless_urlquote "${service_name}")
            result="vless://${user_id}@${authority_host}:${port}?serviceName=${service_name}&encryption=none&type=grpc#${quoted_host}+%E5%8D%95%E7%8B%ADgrpc%E5%8D%8F%E8%AE%AE"
            ;;
        xhttp)
            port=$(info_extraction xhttp_port)
            local xhttp_path
            xhttp_path=$(info_xhttp_path)
            xhttp_path=$(vless_urlquote "$(format_xhttp_path "${xhttp_path}")")
            result="vless://${user_id}@${authority_host}:${port}?path=${xhttp_path}&mode=auto&security=none&encryption=none&host=${quoted_host}&type=xhttp#${quoted_host}+%E5%8D%95%E7%8B%ADxHTTP%E5%8D%8F%E8%AE%AE"
            ;;
        reality)
            port=$(info_extraction port)
            local pbk sni target sid spx spx_param
            pbk=$(info_reality_public_key)
            sni=$(info_extraction serverNames)
            target=$(info_extraction target)
            sid=$(reality_client_meta "${user_id}" shortIds)
            [[ -z "${sid}" ]] && sid=$(info_extraction shortIds)
            spx=$(reality_client_meta "${user_id}" spiderx_path)
            [[ -z "${spx}" ]] && spx=$(info_extraction spiderx_path)
            # 仅当存在 spiderX 时拼接 spx= 参数，老配置无 spiderX 保持兼容
            if [[ -n "${spx}" ]]; then
                spx_param="&spx=$(vless_urlquote "${spx}")"
            else
                spx_param=""
            fi
            result="vless://${user_id}@${authority_host}:${port}?security=reality&flow=xtls-rprx-vision&fp=chrome&pbk=${pbk}&sni=${sni}&target=${target}&sid=${sid}${spx_param}#${quoted_host}+Reality%E5%8D%8F%E8%AE%AE"
            ;;
        *)
            return 1
            ;;
    esac

    echo "$result"
}

generate_clash_config() {
    local type=$1
    local port=$2
    local path=$3
    local service_name=$4
    local security=$5
    local flow=$6
    local pbk=$7
    local sni=$8
    local target=$9
    local sid=${10}
    local tls=${11}
    local transport_label=${12:-$type}
    local spx=${13:-}
    local override_host=${14:-}

    local clash_name
    local clash_host
    if [[ -n "${override_host}" ]]; then
        clash_host="${override_host}"
    else
        clash_host=$(info_extraction host)
    fi
    clash_name="VLESS-${clash_host}-${transport_label}"
    local clash_server
    clash_server=$(yaml_quote_scalar "${clash_host}")
    local clash_config=""
    local flow_line=""
    [[ -n "${flow}" ]] && flow_line="
    flow: ${flow}"

    if [[ ${type} == "ws" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: ${clash_server}
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: ws
    ws-opts:
      path: ${path}
      headers:
        Host: ${clash_host}
    skip-cert-verify: false"

    elif [[ ${type} == "grpc" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: ${clash_server}
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: grpc
    grpc-opts:
      grpc-service-name: ${service_name}
    skip-cert-verify: false"

    elif [[ ${type} == "tcp" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: ${clash_server}
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: tcp
    skip-cert-verify: false"

    elif [[ ${type} == "xhttp" ]]; then
        clash_config="  - name: ${clash_name}
    type: vless
    server: ${clash_server}
    port: ${port}
    uuid: $(info_extraction id)
    client-fingerprint: chrome
    tls: ${tls}${flow_line}
    network: xhttp
    xhttp-opts:
      path: ${path}
      mode: auto
    skip-cert-verify: false"
    fi

    if [[ ${tls} == "true" && -n "${sni}" ]]; then
        clash_config="${clash_config}
    servername: ${sni}"
    fi

    if [[ ${security} == "reality" ]]; then
        clash_config="${clash_config}
    reality-opts:
      public-key: ${pbk}
      short-id: ${sid}"
        if [[ -n "${spx}" ]]; then
            clash_config="${clash_config}
      spider-x: ${spx}"
        fi
    fi

    echo ""
    echo "${clash_config}"
}

install_link_image() {
    if is_relay_role; then
        # A relay has no VLESS inbound, so no share link or QR code exists.
        return 0
    fi
    # Defensive hydration: a fresh process reaching this entry without
    # judge_mode() must still restore dual-stack state for IPv6 links.
    ensure_network_runtime_state
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_public_key || return 1
    fi
    local main_id
    main_id=$(info_extraction id)
    # Each transport's link variable is set only when that transport is enabled;
    # pre-initialize so ${...} checks stay safe under `set -u` for disabled modes.
    local vless_link="" vless_link_v6="" vless_ws_link="" vless_grpc_link="" vless_xhttp_link=""
    local vless_ws_link_v6="" vless_grpc_link_v6="" vless_xhttp_link_v6=""

    # 直接-IP 模式（Reality/None）双栈：为 IPv6 单独生成客户端入口。
    # host 字段保留 canonical（默认 IPv4），不改变老代码语义。
    local dual_direct_ip=0
    if [[ ${tls_mode} == "Reality" || ${tls_mode} == "None" ]] \
        && [[ "${network_mode}" == "dual" ]] && [[ -n "${ipv6_address}" ]]; then
        dual_direct_ip=1
    fi

    if [[ ${tls_mode} == "TLS" ]]; then
        is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws_tls")
        is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc_tls")
        is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp_tls")
    elif [[ ${tls_mode} == "Reality" ]]; then
        vless_link=$(generate_vless_link "$main_id" "reality")
        [[ ${dual_direct_ip} -eq 1 ]] && vless_link_v6=$(generate_vless_link "$main_id" "reality" "${ipv6_address}")
        if [[ ${reality_add_more} == "on" ]]; then
            is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws")
            is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc")
            is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp")
            # 双栈：Reality 附加 transport 同样输出 IPv6 直连入口
            if [[ ${dual_direct_ip} -eq 1 ]]; then
                [[ -n "${vless_ws_link}" ]] && vless_ws_link_v6=$(generate_vless_link "$main_id" "ws" "${ipv6_address}")
                [[ -n "${vless_grpc_link}" ]] && vless_grpc_link_v6=$(generate_vless_link "$main_id" "grpc" "${ipv6_address}")
                [[ -n "${vless_xhttp_link}" ]] && vless_xhttp_link_v6=$(generate_vless_link "$main_id" "xhttp" "${ipv6_address}")
            fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        is_ws_mode && vless_ws_link=$(generate_vless_link "$main_id" "ws")
        is_grpc_mode && vless_grpc_link=$(generate_vless_link "$main_id" "grpc")
        is_xhttp_mode && vless_xhttp_link=$(generate_vless_link "$main_id" "xhttp")
        # 双栈：None transport 同样输出 IPv6 直连入口
        if [[ ${dual_direct_ip} -eq 1 ]]; then
            [[ -n "${vless_ws_link}" ]] && vless_ws_link_v6=$(generate_vless_link "$main_id" "ws" "${ipv6_address}")
            [[ -n "${vless_grpc_link}" ]] && vless_grpc_link_v6=$(generate_vless_link "$main_id" "grpc" "${ipv6_address}")
            [[ -n "${vless_xhttp_link}" ]] && vless_xhttp_link_v6=$(generate_vless_link "$main_id" "xhttp" "${ipv6_address}")
        fi
    fi

    clash_config_content="proxies:"

    if [[ ${tls_mode} == "TLS" ]]; then
        if is_ws_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction port)" "/$(info_ws_path)" "" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
        if is_grpc_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction port)" "" "$(info_grpc_serviceName)" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
        if is_xhttp_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "tls" "" "" "$(info_extraction host)" "" "" "true")"
        fi
    elif [[ ${tls_mode} == "Reality" ]]; then
        clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "reality" "xtls-rprx-vision" "$(info_reality_public_key)" "$(info_extraction serverNames)" "$(info_extraction target)" "$(info_extraction shortIds)" "true" "tcp" "$(info_extraction spiderx_path)")"
        # 双栈直接-IP：额外输出 IPv6 Reality 入口（server 指向 IPv6 literal）
        if [[ ${dual_direct_ip} -eq 1 ]]; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "tcp" "$(info_extraction port)" "" "" "reality" "xtls-rprx-vision" "$(info_reality_public_key)" "$(info_extraction serverNames)" "$(info_extraction target)" "$(info_extraction shortIds)" "true" "tcp-v6" "$(info_extraction spiderx_path)" "${ipv6_address}")"
        fi
        if [[ ${reality_add_more} == "on" ]]; then
            if is_ws_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false")"
                if [[ ${dual_direct_ip} -eq 1 ]]; then
                    clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false" "ws-v6" "" "${ipv6_address}")"
                fi
            fi
            if is_grpc_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false")"
                if [[ ${dual_direct_ip} -eq 1 ]]; then
                    clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false" "grpc-v6" "" "${ipv6_address}")"
                fi
            fi
            if is_xhttp_mode; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false")"
                if [[ ${dual_direct_ip} -eq 1 ]]; then
                    clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false" "xhttp-v6" "" "${ipv6_address}")"
                fi
            fi
        fi
    elif [[ ${tls_mode} == "None" ]]; then
        if is_ws_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false")"
            if [[ ${dual_direct_ip} -eq 1 ]]; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "ws" "$(info_extraction ws_port)" "/$(info_ws_path)" "" "none" "" "" "" "" "" "false" "ws-v6" "" "${ipv6_address}")"
            fi
        fi
        if is_grpc_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false")"
            if [[ ${dual_direct_ip} -eq 1 ]]; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "grpc" "$(info_extraction grpc_port)" "" "$(info_grpc_serviceName)" "none" "" "" "" "" "" "false" "grpc-v6" "" "${ipv6_address}")"
            fi
        fi
        if is_xhttp_mode; then
            clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false")"
            if [[ ${dual_direct_ip} -eq 1 ]]; then
                clash_config_content="${clash_config_content}
$(generate_clash_config "xhttp" "$(info_extraction xhttp_port)" "$(format_xhttp_path "$(info_xhttp_path)")" "" "none" "" "" "" "" "" "false" "xhttp-v6" "" "${ipv6_address}")"
            fi
        fi
    fi
    
    {
        echo
        log_echo "${Red} —————————————— Xray $(gettext "链接分享") —————————————— ${Font}"
        if [[ ${tls_mode} == "Reality" ]]; then
            log_echo_secure "${Red} URL $(gettext "分享链接"):${Font} ${vless_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_link}" | qrencode -o - -t utf8
            echo
            if [[ ${dual_direct_ip} -eq 1 && -n "${vless_link_v6}" ]]; then
                log_echo_secure "${Red} IPv6 URL $(gettext "分享链接"):${Font} ${vless_link_v6}"
                log_echo "${Red} $(gettext "二维码"): ${Font}"
                echo -n "${vless_link_v6}" | qrencode -o - -t utf8
                echo
            fi
        fi
        if is_ws_mode && [[ -n "${vless_ws_link}" ]]; then
            log_echo_secure "${Red} ws URL $(gettext "分享链接"):${Font} ${vless_ws_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_ws_link}" | qrencode -o - -t utf8
            echo
            if [[ ${dual_direct_ip} -eq 1 && -n "${vless_ws_link_v6}" ]]; then
                log_echo_secure "${Red} IPv6 ws URL $(gettext "分享链接"):${Font} ${vless_ws_link_v6}"
                log_echo "${Red} $(gettext "二维码"): ${Font}"
                echo -n "${vless_ws_link_v6}" | qrencode -o - -t utf8
                echo
            fi
        fi
        if is_grpc_mode && [[ -n "${vless_grpc_link}" ]]; then
            log_echo_secure "${Red} gRPC URL $(gettext "分享链接"):${Font} ${vless_grpc_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_grpc_link}" | qrencode -o - -t utf8
            echo
            if [[ ${dual_direct_ip} -eq 1 && -n "${vless_grpc_link_v6}" ]]; then
                log_echo_secure "${Red} IPv6 gRPC URL $(gettext "分享链接"):${Font} ${vless_grpc_link_v6}"
                log_echo "${Red} $(gettext "二维码"): ${Font}"
                echo -n "${vless_grpc_link_v6}" | qrencode -o - -t utf8
                echo
            fi
        fi
        if is_xhttp_mode && [[ -n "${vless_xhttp_link}" ]]; then
            log_echo_secure "${Red} xHTTP URL $(gettext "分享链接"):${Font} ${vless_xhttp_link}"
            log_echo "${Red} $(gettext "二维码"): ${Font}"
            echo -n "${vless_xhttp_link}" | qrencode -o - -t utf8
            echo
            if [[ ${dual_direct_ip} -eq 1 && -n "${vless_xhttp_link_v6}" ]]; then
                log_echo_secure "${Red} IPv6 xHTTP URL $(gettext "分享链接"):${Font} ${vless_xhttp_link_v6}"
                log_echo "${Red} $(gettext "二维码"): ${Font}"
                echo -n "${vless_xhttp_link_v6}" | qrencode -o - -t utf8
                echo
            fi
        fi
        
        # 输出Clash配置
        log_echo "${Red} —————————————— Clash $(gettext "配置分享") —————————————— ${Font}"
        log_echo "${Red} Clash $(gettext "配置分享"): ${Font}"
        echo "${clash_config_content}"
        echo
        # 添加结束线
        log_echo "${Red} ——————————————————  END  —————————————————— ${Font}"
        echo
    } >>"${xray_info_file}"
    
    # 保存Clash配置到文件
    echo "${clash_config_content}" > "${xray_info_file%.*}_clash.yaml"
    apply_sensitive_file_permissions "${xray_info_file%.*}_clash.yaml" "root:root" || true
}

vless_link_image_choice() {
    echo
    log_echo "${GreenBG} $(gettext "生成分享链接"): ${Font}"
    install_link_image
}

declare -A _info_cache=()
_info_cache_loaded=0

_info_cache_invalidate() {
    declare -gA _info_cache=()
    _info_cache_loaded=0
    # P0-1: also reset the lazy-load latch so the next read re-parses the
    # config file instead of reusing a stale info_extraction_all.
    _info_extraction_loaded=0
}

_info_cache_load() {
    # P0-1: lazy-load first so info_extraction_all reflects the real config
    # before any cache is built. _lazy_load_info_extraction is idempotent and
    # fails closed (non-zero) only when a config exists but cannot be read.
    _lazy_load_info_extraction || return 1
    if [[ ${_info_cache_loaded} -eq 0 ]] && [[ -n "${info_extraction_all:-}" ]]; then
        while IFS=$'\t' read -r key value; do
            _info_cache["$key"]="$value"
        done < <(echo "${info_extraction_all}" | jq -r 'to_entries | .[] | [.key, .value // ""] | @tsv' 2>/dev/null)
        _info_cache_loaded=1
    fi
}

info_extraction() {
    # P0-1: the public read entry point ALWAYS routes through the lazy loader.
    # A corrupt/missing-jq config fails closed instead of silently returning empty.
    if [[ ${_info_cache_loaded} -eq 0 ]]; then
        _info_cache_load || return 1
    fi
    if [[ -n "${_info_cache[$1]+x}" ]]; then
        echo "${_info_cache[$1]}"
    else
        local result
        result=$(echo "${info_extraction_all:-}" | jq -r ".$1 // empty" 2>/dev/null)
        local jq_exit_code=$?
        echo "$result"
        if [[ $jq_exit_code -ne 0 ]]; then
            read_config_status=0
        fi
    fi
}

install_iftop() {
    if ! command -v iftop &>/dev/null; then
        log_echo "${Info} ${Green} $(gettext "正在安装") iftop... ${Font}"
        check_system
        # P1-9: iftop is an OPTIONAL feature dependency. On install failure the
        # feature degrades to unavailable (with a warning), not a hard fail.
        if ! pkg_install "iftop"; then
            log_echo "${Warning} ${YellowBG} $(gettext "iftop 安装失败, 流量监控功能不可用") ${Font}"
            return 1
        fi
    else
        log_echo "${OK} ${GreenBG} $(gettext "已安装") iftop ${Font}"
    fi
}

monitor_traffic_with_iftop() {
    if [[ ! -f "${xray_install_config_file}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        exit 1
    fi

    install_iftop

    local port
    local interface

    port=$(info_extraction port)
    if [[ -z "${port}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        exit 1
    fi

    interface=$(ip route show | awk '/default/ {print $5; exit}')
    if [[ -z "${interface}" ]]; then
        interface="any"
        log_echo "${Warning} ${YellowBG} $(gettext "无法获取网卡, 将监控所有网卡") ${Font}"
    else
        log_echo "${OK} ${GreenBG} $(gettext "监控网卡"): ${interface} ${Font}"
    fi

    log_echo "${OK} ${GreenBG} $(gettext "监控端口"): ${port} ${Font}"
    echo
    log_echo "${Info} ${Green} $(gettext "按 q 键退出 iftop") ${Font}"
    countdown "$(gettext "启动") iftop"
    sleep 3

    if [[ "${interface}" == "any" ]]; then
        iftop -i any -n -f "port ${port}"
    else
        iftop -i "${interface}" -n -f "port ${port}"
    fi
}

basic_information() {
    if is_relay_role; then
        relay_basic_information
        return 0
    fi
    ensure_reality_public_key || true
    {
        echo
        log_echo "${OK} ${GreenBG} Xray+${shell_mode} $(gettext "安装") $(gettext "完成") ${Font}"
        echo
        log_echo "${Warning} ${YellowBG} VLESS $(gettext "目前分享链接规范为实验阶段, 请自行判断是否适用") ${Font}"
        if is_xhttp_mode; then
            log_echo "${Warning} ${YellowBG} $(gettext "当前 xHTTP 仅支持 stream-one 和 stream-up 模式") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "xHTTP 需要 mihomo (Meta) 内核, 原版 Clash 不支持") ${Font}"
        fi
        echo
        log_echo "${Red} —————————————— Xray $(gettext "配置信息") —————————————— ${Font}"
        log_echo "${Red} $(gettext "主机") (host):${Font} $(info_extraction host) "
        if [[ ${tls_mode} == "None" ]]; then
            if is_ws_mode; then
                log_echo "${Red} ws $(gettext "端口") (port):${Font} $(info_extraction ws_port) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} gRPC $(gettext "端口") (port):${Font} $(info_extraction grpc_port) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} xHTTP $(gettext "端口") (port):${Font} $(info_extraction xhttp_port) "
            fi
        else
            log_echo "${Red} $(gettext "端口") (port):${Font} $(info_extraction port) "
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if is_ws_mode; then
                log_echo "${Red} Xray ws $(gettext "端口") (inbound_port):${Font} $(info_extraction ws_port) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} Xray gRPC $(gettext "端口") (inbound_port):${Font} $(info_extraction grpc_port) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} Xray xHTTP $(gettext "端口") (inbound_port):${Font} $(info_extraction xhttp_port) "
            fi
        fi
        log_echo_secure "${Red} UUIDv5 $(gettext "映射字符串"):${Font} $(info_extraction idc)"
        log_echo_secure "${Red} $(gettext "用户id") (UUID):${Font} $(info_extraction id)"

        log_echo "${Red} $(gettext "加密") (encryption):${Font} None "
        log_echo "${Red} $(gettext "传输协议") (network):${Font} $(info_extraction net) "
        log_echo "${Red} $(gettext "底层传输安全") (tls):${Font} $(info_extraction tls) "
        if [[ ${tls_mode} == "None" ]]; then
            local _none_listen
            _none_listen=$(none_mode_listen_address)
            [[ -n "${_none_listen}" ]] &&
                log_echo "${Red} $(gettext "监听地址") (listen):${Font} ${_none_listen} "
            log_echo "${Warning} ${YellowBG} $(gettext "此模式没有传输层加密 (VLESS 载荷自身仍有加密), 只应用于可信后端链路") ${Font}"
            case "${_none_listen}" in
            127.0.0.1 | ::1 | "")
                log_echo "${Warning} ${YellowBG} $(gettext "当前仅监听本机, 外部客户端需经可信代理接入, 或改用 TLS/Reality 模式") ${Font}"
                ;;
            esac
        fi
        if [[ ${tls_mode} != "Reality" ]]; then
            if is_ws_mode; then
                log_echo "${Red} $(gettext "路径") (path $(gettext "不要落下")/):${Font} /$(info_ws_path) "
            fi
            if is_grpc_mode; then
                log_echo "${Red} serviceName ($(gettext "不需要加")/):${Font} $(info_grpc_serviceName) "
            fi
            if is_xhttp_mode; then
                log_echo "${Red} xHTTP $(gettext "路径") (path $(gettext "不要落下")/):${Font} $(format_xhttp_path "$(info_xhttp_path)") "
            fi
        else
            if [[ ${tls_mode} == "Reality" ]]; then
                log_echo "${Red} $(gettext "流控") (flow):${Font} xtls-rprx-vision "
                log_echo "${Red} target:${Font} $(info_extraction target) "
                log_echo "${Red} serverNames:${Font} $(info_extraction serverNames) "
                log_echo_secure "${Red} privateKey:${Font} $(gettext "已生成并保存（不显示）") "
                log_echo_secure "${Red} publicKey (Password):${Font} $(info_reality_public_key) "
                log_echo_secure "${Red} shortIds:${Font} $(info_extraction shortIds) "
                if [[ -n "$(info_extraction spiderx_path)" ]]; then
                    log_echo "${Red} spiderX:${Font} $(info_extraction spiderx_path) "
                fi
                if [[ "$reality_add_more" == "on" ]]; then
                    if is_ws_mode; then
                        log_echo "${Red} ws $(gettext "端口") (port):${Font} $(info_extraction ws_port) "
                        log_echo "${Red} ws $(gettext "路径") ($(gettext "不要落下")/):${Font} /$(info_ws_path) "
                    fi
                    if is_grpc_mode; then
                        log_echo "${Red} gRPC $(gettext "端口") (port):${Font} $(info_extraction grpc_port) "
                        log_echo "${Red} gRPC serviceName ($(gettext "不需要加")/):${Font} $(info_grpc_serviceName) "
                    fi
                    if is_xhttp_mode; then
                        log_echo "${Red} xHTTP $(gettext "端口") (port):${Font} $(info_extraction xhttp_port) "
                        log_echo "${Red} xHTTP $(gettext "路径") (path $(gettext "不要落下")/):${Font} $(format_xhttp_path "$(info_xhttp_path)") "
                    fi
                fi
            fi
        fi
    } >"${xray_info_file}"
        chmod -f 600 "${xray_info_file}" 2>/dev/null
}

show_information() {
    cat "${xray_info_file}"
}

ssl_judge_and_install() {
    cd $HOME
    echo
    local has_cert_files="false"
    local has_acme_files="false"

    [[ -f "${ssl_chainpath}/xray.key" && -f "${ssl_chainpath}/xray.crt" ]] && has_cert_files="true"
    [[ -f "$HOME/.acme.sh/acme.sh" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] && has_acme_files="true"

    if [[ ${has_cert_files} != "true" && ${has_acme_files} != "true" ]]; then
        log_echo "${GreenBG} $(gettext "即将申请证书, 支持使用自定义证书") ${Font}"
        log_echo "${Green} $(gettext "如需使用自定义证书, 请按如下步骤:") ${Font}"
        log_echo " $(gettext "1. 将证书文件重命名: 私钥(xray.key)、证书(xray.crt)")"
        log_echo " $(gettext "2. 将重命名后的证书文件放入") ${ssl_chainpath} $(gettext "目录后再运行脚本")"
        log_echo " $(gettext "3. 重新运行脚本")"
        log_echo "${GreenBG} $(gettext "是否继续") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r ssl_continue
        case $ssl_continue in
        [nN][oO] | [nN])
            return 1
            ;;
        esac
    fi

    if [[ ${has_cert_files} == "true" ]]; then
        if [[ ${has_acme_files} == "true" ]]; then
            log_echo "${GreenBG} $(gettext "所有证书文件均已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        else
            log_echo "${GreenBG} $(gettext "证书文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        fi
        read -r ssl_delete_choice
        case $ssl_delete_choice in
        [nN][oO] | [nN])
            [[ ${has_acme_files} == "true" ]] && delete_tls_key_and_crt
            rm -rf "${ssl_chainpath}"/*
            log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
            ssl_install
            acme
            ;;
        *)
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            judge "$(gettext "证书应用")"
            ;;
        esac
    elif [[ ${has_acme_files} == "true" ]]; then
        log_echo "${GreenBG} $(gettext "证书签发残留文件已存在, 是否保留") [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r ssl_delete_3
        case $ssl_delete_3 in
        [nN][oO] | [nN])
            delete_tls_key_and_crt
            log_echo "${OK} ${GreenBG} $(gettext "已删除") ${Font}"
            ssl_install
            acme
            ;;
        *)
            "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath "${ssl_chainpath}/xray.crt" --keypath "${ssl_chainpath}/xray.key" --ecc --reloadcmd "chown -f root:idleleo-nginx ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && chmod -f 640 ${ssl_chainpath}/xray.crt ${ssl_chainpath}/xray.key && systemctl restart nginx && systemctl restart xray"
            # Reuse authoritative layered permission model.
            apply_nginx_layered_permissions || return 1
            verify_nginx_layered_permissions || return 1
            judge "$(gettext "证书应用")"
            ;;
        esac
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >"${nginx_systemd_file}" <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=${nginx_dir}/logs/nginx.pid
ExecStartPre=${nginx_dir}/sbin/nginx -t
ExecStart=${nginx_dir}/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=${nginx_dir}/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge -r "Nginx systemd ServerFile $(gettext "添加")" || return 1
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "${nginx_conf}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            while true; do
                echo
                log_echo "${GreenBG} $(gettext "请选择支持的 TLS 版本") (default:2): ${Font}"
                log_echo "${GreenBG} $(gettext "建议选择 TLSv1.3 only (安全模式)") ${Font}"
                echo -e "1: TLSv1.2 and TLSv1.3 ($(gettext "兼容模式"))"
                echo -e "${Red}2${Font}: TLSv1.3 only ($(gettext "安全模式"))"
                local choose_tls
                read_optimize "$(gettext "请输入"): " "choose_tls" 2 1 2 "$(gettext "请输入有效的数字")!" || return 1
                if [[ ${choose_tls} == 1 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "由于 h3 仅支持 TLSv1.3, 此处只支持 TLSv1.3 only (安全模式)")! ${Font}"
                else
                    sed -i "s/^\( *\)ssl_protocols\( *\).*/\1ssl_protocols\2TLSv1.3;/" $nginx_conf
                    log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.3 only ${Font}"
                    break
                fi
            done
        elif [[ ${tls_mode} == "Reality" && ${reality_add_nginx} == "on" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "请选择 TLS 版本") (default:1): ${Font}"
            log_echo "${GreenBG} $(gettext "建议选择 TLSv1.3 (安全模式)") ${Font}"
            echo -e "${Red}1${Font}: TLSv1.3 ($(gettext "默认"))"
            echo -e "2: TLSv1.2+ ($(gettext "兼容模式"))"
            local tls_version_choice
            read_optimize "$(gettext "请输入"): " "tls_version_choice" 1 1 2 "$(gettext "请输入有效的数字")!" || return 1
            if [[ ${tls_version_choice} == 2 ]]; then
                sed -i "s/^\( *\)#TLSv1.2\( *\)1;\( *\)$/\1TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.2+ ${Font}"
            else
                sed -i "s/^\( *\)TLSv1.2\( *\)1;\( *\)$/\1#TLSv1.2\21;\3/" $nginx_conf
                log_echo "${OK} ${GreenBG} $(gettext "已切换至") TLSv1.3 ${Font}"
            fi
        else
            log_echo "${Error} ${RedBG} $(gettext "当前模式不支持此操作") ${Font}"
            return 1
        fi
        if [[ -f "${nginx_systemd_file}" ]]; then
            systemctl restart nginx
            judge -r "Nginx $(gettext "重启")" || return 1
        fi
        systemctl restart xray
        judge -r "Xray $(gettext "重启")" || return 1
        return 0
    else
        log_echo "${Error} ${RedBG} $(gettext "Nginx 配置文件不存在或当前模式不支持") ${Font}"
        return 1
    fi
}

reset_install_config() {
    [[ -f "${xray_install_config_file}" ]] && info_extraction_all=$(jq -rc . "${xray_install_config_file}")
    _info_cache_invalidate
    basic_information
    install_link_image
    show_information
}

reset_UUID() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        old_config_status="off"
        UUID_set
        old_config_status="${_saved_old_config_status}"
        modify_UUID
        update_json_config "${xray_install_config_file}" --arg uuid "${UUID}" \
           --arg uuid5_char "${UUID5_char}" \
           '.id = $uuid | .idc = $uuid5_char'
        service_restart || return 1
        reset_install_config
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

reset_port() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local _saved_old_config_status="${old_config_status}"
        local old_ports_json new_ports_json
        # Snapshot current port values so we can restore them on any failure.
        local _old_port="${port:-}"
        local _old_xport="${xport:-}"
        local _old_gport="${gport:-}"
        local _old_xhttpport="${xhttpport:-}"
        local _rollback_config_file=""
        local _rollback_xray_conf=""
        old_config_status="off"
        old_ports_json=$(cat "${managed_ports_file}" 2>/dev/null || echo '{"tcp":[],"udp":[]}')

        # ----- Phase 1: collect input only (no config writes) -----
        if [[ ${tls_mode} == "TLS" ]]; then
            port_set || { _reset_port_restore; return 1; }
        elif [[ ${tls_mode} == "Reality" ]]; then
            port_set || { _reset_port_restore; return 1; }
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
        elif [[ ${tls_mode} == "None" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                read_optimize "$(gettext "请输入") ws inbound_port:" "xport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") gRPC inbound_port:" "gport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                read_optimize "$(gettext "请输入") xHTTP inbound_port:" "xhttpport" "NULL" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || { _reset_port_restore; return 1; }
                log_echo "${Green} ws inbound_port: ${xport} ${Font}"
                log_echo "${Green} gRPC inbound_port: ${gport} ${Font}"
                log_echo "${Green} xHTTP inbound_port: ${xhttpport} ${Font}"
            fi
        fi

        # ----- Phase 2: validate (no config writes yet) -----
        collect_new_managed_ports
        validate_active_ports || { _reset_port_restore; return 1; }
        if [[ -n "${port:-}" && "${port}" != "None" ]]; then
            port_exist_check "${port}" || { _reset_port_restore; return 1; }
        fi
        if is_ws_mode && [[ -n "${xport:-}" && "${xport}" != "None" ]]; then
            port_exist_check "${xport}" || { _reset_port_restore; return 1; }
        fi
        if is_grpc_mode && [[ -n "${gport:-}" && "${gport}" != "None" ]]; then
            port_exist_check "${gport}" || { _reset_port_restore; return 1; }
        fi
        if is_xhttp_mode && [[ -n "${xhttpport:-}" && "${xhttpport}" != "None" ]]; then
            port_exist_check "${xhttpport}" || { _reset_port_restore; return 1; }
        fi

        # ----- Phase 3: snapshot configs for rollback, then write -----
        _rollback_config_file=$(mktemp)
        _rollback_xray_conf=$(mktemp)
        _rollback_managed_ports=$(mktemp)
        cp "${xray_install_config_file}" "${_rollback_config_file}" 2>/dev/null || true
        cp "${xray_conf}" "${_rollback_xray_conf}" 2>/dev/null || true
        cp "${managed_ports_file}" "${_rollback_managed_ports}" 2>/dev/null || true

        if [[ ${tls_mode} == "TLS" ]]; then
            modify_nginx_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            update_json_config "${xray_install_config_file}" --argjson port "${port:-0}" '.port = $port' || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        elif [[ ${tls_mode} == "Reality" ]]; then
            local port_update_expr='.port = $port'
            if is_ws_mode; then
                port_update_expr="${port_update_expr} | .ws_port = \$ws_port"
            fi
            if is_grpc_mode; then
                port_update_expr="${port_update_expr} | .grpc_port = \$grpc_port"
            fi
            if is_xhttp_mode; then
                port_update_expr="${port_update_expr} | .xhttp_port = \$xhttp_port"
            fi
            update_json_config "${xray_install_config_file}" --argjson port "${port:-0}" \
               --argjson ws_port "${xport:-0}" \
               --argjson grpc_port "${gport:-0}" \
               --argjson xhttp_port "${xhttpport:-0}" \
               "${port_update_expr}" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            modify_inbound_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            if [[ ${reality_add_nginx} == "on" ]]; then
                modify_nginx_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            fi
        elif [[ ${tls_mode} == "None" ]]; then
            local none_port_update=""
            if is_ws_mode; then
                none_port_update="${none_port_update} | .ws_port = \$ws_port"
            fi
            if is_grpc_mode; then
                none_port_update="${none_port_update} | .grpc_port = \$grpc_port"
            fi
            if is_xhttp_mode; then
                none_port_update="${none_port_update} | .xhttp_port = \$xhttp_port"
            fi
            if [[ -n "${none_port_update}" ]]; then
                update_json_config "${xray_install_config_file}" --argjson ws_port "${xport:-0}" \
                   --argjson grpc_port "${gport:-0}" \
                   --argjson xhttp_port "${xhttpport:-0}" \
                   "${none_port_update# | }" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
            fi
            modify_inbound_port || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        fi

        # ----- Phase 4: apply runtime + firewall -----
        if ! service_restart; then
            _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
            return 1
        fi
        if ! reconcile_managed_firewall "${old_ports_json}" "${new_ports_json}"; then
            _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
            service_restart >/dev/null 2>&1 || true
            return 1
        fi
        atomic_write_managed_ports "${new_ports_json}" || { _reset_port_rollback "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"; return 1; }
        rm -f "${_rollback_config_file}" "${_rollback_xray_conf}" "${_rollback_managed_ports}"
        reset_install_config
        old_config_status="${_saved_old_config_status}"
        return 0
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

# Helper: restore port variables on validation failure (no config was written).
_reset_port_restore() {
    port="${_old_port:-}"
    xport="${_old_xport:-}"
    gport="${_old_gport:-}"
    xhttpport="${_old_xhttpport:-}"
    old_config_status="${_saved_old_config_status:-}"
}

# Helper: restore config files, firewall rules, managed_ports.json, AND port
# variables on write/apply failure. This treats config + firewall as one
# transaction: if any step fails, both are rolled back.
_reset_port_rollback() {
    local rb_config="$1"
    local rb_xray="$2"
    local rb_managed_ports="${3:-}"
    # Restore config files
    [[ -f "${rb_config}" ]] && cp "${rb_config}" "${xray_install_config_file}" 2>/dev/null || true
    [[ -f "${rb_xray}" ]] && cp "${rb_xray}" "${xray_conf}" 2>/dev/null || true
    # Restore managed_ports.json from snapshot
    if [[ -n "${rb_managed_ports}" && -f "${rb_managed_ports}" ]]; then
        cp "${rb_managed_ports}" "${managed_ports_file}" 2>/dev/null || true
    fi
    # Best-effort firewall rollback: reverse the reconciliation to undo any
    # partial firewall changes. Best-effort means we log but don't fail if
    # rollback itself encounters errors (the config is already restored).
    if [[ -n "${new_ports_json:-}" && -n "${old_ports_json:-}" ]]; then
        reconcile_managed_firewall "${new_ports_json}" "${old_ports_json}" 2>/dev/null || true
    fi
    rm -f "${rb_config}" "${rb_xray}" "${rb_managed_ports}"
    port="${_old_port:-}"
    xport="${_old_xport:-}"
    gport="${_old_gport:-}"
    xhttpport="${_old_xhttpport:-}"
    old_config_status="${_saved_old_config_status:-}"
}

reset_target() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ ${tls_mode} == "Reality" ]]; then
        target_reset=1
        serverNames=$(info_extraction serverNames)
        nginx_reality_serverNames_del
        target_set
        serverNames_set
        modify_target_serverNames
        if [[ ${reality_add_nginx} == "on" ]]; then
            nginx_reality_serverNames_add
        fi
        update_json_config "${xray_install_config_file}" --arg target "${target}" \
           --arg serverNames "${serverNames}" \
           '.target = $target | .serverNames = $serverNames'
        service_restart || return 1
        reset_install_config
        return 0
    elif [[ ${tls_mode} != "Reality" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持修改") target ! ${Font}"
        return 1
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return 1
    fi
}

show_user() {
    # Defensive hydration so multi-user views still emit IPv6 links on a fresh process.
    ensure_network_runtime_state
    if [[ ${tls_mode} == "None" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "此模式不支持查看用户")! ${Font}"
        return
    fi
    if [[ ! -f "${xray_install_config_file}" ]] || [[ ! -f "${xray_conf}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
        return
    fi
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_public_key || return 1
    fi

    local choose_user_prot show_user_index user_email user_id user_vless_link show_user_continue
    local user_vless_link_v6 dual_direct_ip

    while true; do
        user_email=""
        user_id=""
        user_vless_link=""
        user_vless_link_v6=""
        echo
        log_echo "${GreenBG} $(gettext "即将显示用户, 一次仅能显示一个") ${Font}"
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                choose_user_tag="VLESS-ws-in"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                choose_user_tag="VLESS-gRPC-in"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                choose_user_tag="VLESS-xhttp-in"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                log_echo "${GreenBG} $(gettext "请选择显示用户使用的协议") ws/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                else
                    choose_user_tag="VLESS-ws-in"
                fi
            else
                log_echo "${GreenBG} $(gettext "请选择显示用户使用的协议") ws/gRPC/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: gRPC"
                echo "3: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 1 ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                else
                    choose_user_tag="VLESS-xhttp-in"
                fi
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_tag="VLESS-Reality-in"
        fi
        echo
        log_echo "${GreenBG} $(gettext "请选择要显示的用户编号"): ${Font}"
        jq -r -c --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients[].email' "${xray_conf}" | awk '{print NR""": "$0}'
        read_optimize "$(gettext "请输入"): " "show_user_index" "NULL"
        if [[ ${show_user_index} == 1 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "请直接在主菜单选择 [查看 Xray 配置信息] 显示主用户") ${Font}"
            echo
        elif [[ ${show_user_index} -gt 1 ]] && [[ $(jq -r --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients|length' "${xray_conf}") -ge ${show_user_index} ]]; then
            local idx=$((show_user_index - 1))
            user_email=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${idx}" '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].email' "${xray_conf}")
            user_id=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${idx}" '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].id' "${xray_conf}")
        else
            log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
            continue
        fi
        if [[ -n ${user_email} ]] && [[ -n ${user_id} ]]; then
            log_echo "${Green} $(gettext "用户名"): ${user_email} ${Font}"
            log_echo_secure "${Green} UUID: ${user_id} ${Font}"
            # 直接-IP 模式（Reality）双栈：为多用户单独输出 IPv6 直连入口
            dual_direct_ip=0
            if [[ ${tls_mode} == "Reality" ]] \
                && [[ "${network_mode}" == "dual" ]] && [[ -n "${ipv6_address}" ]]; then
                dual_direct_ip=1
            fi
            if [[ ${tls_mode} == "TLS" ]]; then
                if [[ ${choose_user_tag} == "VLESS-ws-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "ws_tls")
                elif [[ ${choose_user_tag} == "VLESS-gRPC-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "grpc_tls")
                elif [[ ${choose_user_tag} == "VLESS-xhttp-in" ]]; then
                    user_vless_link=$(generate_vless_link "$user_id" "xhttp_tls")
                fi
            elif [[ ${tls_mode} == "Reality" ]]; then
                user_vless_link=$(generate_vless_link "$user_id" "reality")
                [[ ${dual_direct_ip} -eq 1 ]] && user_vless_link_v6=$(generate_vless_link "$user_id" "reality" "${ipv6_address}")
            fi
            log_echo_secure "${Red} URL $(gettext "分享链接"):${Font} ${user_vless_link}"
            echo -n "${user_vless_link}" | qrencode -o - -t utf8
            echo
            if [[ ${dual_direct_ip} -eq 1 && -n "${user_vless_link_v6}" ]]; then
                log_echo_secure "${Red} IPv6 URL $(gettext "分享链接"):${Font} ${user_vless_link_v6}"
                echo -n "${user_vless_link_v6}" | qrencode -o - -t utf8
                echo
            fi
        fi
        echo
        log_echo "${GreenBG} $(gettext "是否继续显示用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
        read -r show_user_continue
        case $show_user_continue in
        [yY][eE][sS] | [yY])
            ;;
        *)
            break
            ;;
        esac
    done
}

add_user() {
    local choose_user_prot reality_user_more
    # Defensive hydration so user-facing links keep dual-stack state on fresh processes.
    ensure_network_runtime_state
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local add_user_continue
        while true; do
            echo
            log_echo "${GreenBG} $(gettext "即将添加用户, 一次仅能添加一个") ${Font}"
            local new_reality_short_id="" new_reality_spiderx=""
            if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "None" ]]; then
                if [[ ${transport_mode} == "onlyws" ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${transport_mode} == "onlygRPC" ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                elif [[ ${transport_mode} == "wsxhttp" ]]; then
                    log_echo "${GreenBG} $(gettext "请选择添加用户使用的协议") ws/xHTTP ${Font}"
                    echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                    echo "2: xHTTP"
                    read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                    if [[ ${choose_user_prot} -eq 2 ]]; then
                        choose_user_tag="VLESS-xhttp-in"
                    else
                        choose_user_tag="VLESS-ws-in"
                    fi
                else
                    log_echo "${GreenBG} $(gettext "请选择添加用户使用的协议") ws/gRPC/xHTTP ${Font}"
                    echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                    echo "2: gRPC"
                    echo "3: xHTTP"
                    read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                    if [[ ${choose_user_prot} -eq 1 ]]; then
                        choose_user_tag="VLESS-ws-in"
                    elif [[ ${choose_user_prot} -eq 2 ]]; then
                        choose_user_tag="VLESS-gRPC-in"
                    else
                        choose_user_tag="VLESS-xhttp-in"
                    fi
                fi
                reality_user_more="{}"
            elif [[ ${tls_mode} == "Reality" ]]; then
                choose_user_tag="VLESS-Reality-in"
                reality_user_more='{"flow":"xtls-rprx-vision"}'
                new_reality_short_id=$(generate_reality_short_id)
                new_reality_spiderx=$(generate_spiderx)
            fi
            email_set
            local existing_emails
            existing_emails=$(jq -r --arg tag "${choose_user_tag}" \
                '.inbounds[] | select(.tag == $tag) | .settings.clients[].email' \
                "${xray_conf}" 2>/dev/null)
            if echo "${existing_emails}" | grep -qFx "${custom_email}"; then
                log_echo "${Error} ${RedBG} $(gettext "该用户名已存在, 请使用不同的用户名")! ${Font}"
                continue
            fi
            UUID_set
            update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" \
               --arg UUID "${UUID}" \
               --argjson reality_user_more "${reality_user_more}" \
               --arg custom_email "${custom_email}" \
               '(.inbounds[] | select(.tag == $choose_user_tag)).settings.clients += [
                   {"id": $UUID} +
                   ($reality_user_more // {}) +
                   {"level": 0, "email": $custom_email}
               ]'
            judge -r "$(gettext "添加用户")" || return 1
            if [[ ${tls_mode} == "Reality" ]]; then
                update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --arg shortId "${new_reality_short_id}" \
                   '(.inbounds[] | select(.tag == $choose_user_tag) | .streamSettings.realitySettings.shortIds) |= (((. // []) + [$shortId]) | unique)' || return 1
                update_json_config "${xray_install_config_file}" --arg uuid "${UUID}" \
                   --arg shortId "${new_reality_short_id}" \
                   --arg spx "${new_reality_spiderx}" \
                   '.multi_user = "yes" |
                    .reality_clients = (.reality_clients // {}) |
                    .reality_clients[$uuid] = {"shortIds": $shortId, "spiderx_path": $spx}' || return 1
                log_echo_secure "${Green} $(gettext "已为当前客户端生成独立 shortId。") ${Font}"
                log_echo "${Green} spiderX: ${new_reality_spiderx} ${Font}"
            else
                update_json_config "${xray_install_config_file}" ". += {\"multi_user\": \"yes\"}"
            fi
            echo
            log_echo "${GreenBG} $(gettext "是否继续添加用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r add_user_continue
            case $add_user_continue in
            [yY][eE][sS] | [yY])
                continue
                ;;
            *)
                break
                ;;
            esac
        done
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

remove_user() {
    if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]]; then
        local choose_user_prot
        if [[ ${tls_mode} == "TLS" ]] || [[ ${tls_mode} == "None" ]]; then
            if [[ ${transport_mode} == "onlyws" ]]; then
                choose_user_tag="VLESS-ws-in"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                choose_user_tag="VLESS-gRPC-in"
            elif [[ ${transport_mode} == "onlyxhttp" ]]; then
                choose_user_tag="VLESS-xhttp-in"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                log_echo "${GreenBG} $(gettext "请选择删除用户使用的协议") ws/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 2 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-xhttp-in"
                else
                    choose_user_tag="VLESS-ws-in"
                fi
            else
                log_echo "${GreenBG} $(gettext "请选择删除用户使用的协议") ws/gRPC/xHTTP ${Font}"
                echo -e "${Red}1${Font}: ws ($(gettext "默认"))"
                echo "2: gRPC"
                echo "3: xHTTP"
                read_optimize "$(gettext "请输入"): " "choose_user_prot" 1 1 3 "$(gettext "请输入有效的数字")!"
                if [[ ${choose_user_prot} -eq 1 ]]; then
                    choose_user_tag="VLESS-ws-in"
                elif [[ ${choose_user_prot} -eq 2 ]]; then
                    choose_user_tag="VLESS-gRPC-in"
                else
                    choose_user_tag="VLESS-xhttp-in"
                fi
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            choose_user_tag="VLESS-Reality-in"
        fi
        local del_user_index
        local remove_user_continue
        while true; do
            echo
            log_echo "${GreenBG} $(gettext "即将删除用户, 一次仅能删除一个") ${Font}"
            log_echo "${GreenBG} $(gettext "请选择要删除的用户编号") ${Font}"
            jq -r -c --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients[].email' "${xray_conf}" | awk '{print NR""": "$0}'
            read_optimize "$(gettext "请输入"): " "del_user_index" "NULL"
            if [[ -z "${del_user_index}" ]] || [[ -n $(echo "${del_user_index}" | sed 's/[0-9]//g') ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ ${del_user_index} == 0 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ $(jq -r --arg tag "${choose_user_tag}" '(.inbounds[] | select(.tag == $tag)).settings.clients|length' "${xray_conf}") -lt ${del_user_index} ]]; then
                log_echo "${Error} ${RedBG} $(gettext "选择错误")! ${Font}"
                continue
            elif [[ ${del_user_index} == 1 ]]; then
                echo
                log_echo "${Error} ${RedBG} $(gettext "主用户无法删除")! ${Font}"
                echo
                continue
            elif [[ ${del_user_index} -gt 1 ]]; then
                del_user_index=$((del_user_index - 1))
                local removed_user_id="" removed_short_id=""
                if [[ ${tls_mode} == "Reality" ]]; then
                    removed_user_id=$(jq -r -c --arg tag "${choose_user_tag}" --argjson idx "${del_user_index}" \
                        '(.inbounds[] | select(.tag == $tag)).settings.clients[$idx].id // empty' "${xray_conf}")
                    removed_short_id=$(reality_client_meta "${removed_user_id}" shortIds)
                fi
                update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --argjson del_user_index "${del_user_index}" \
                   'del((.inbounds[] | select(.tag == $choose_user_tag)).settings.clients[$del_user_index])'
                judge -r "$(gettext "删除用户")" || return 1
                if [[ ${tls_mode} == "Reality" ]]; then
                    if [[ -n "${removed_short_id}" ]]; then
                        update_json_config "${xray_conf}" --arg choose_user_tag "${choose_user_tag}" --arg shortId "${removed_short_id}" \
                           '(.inbounds[] | select(.tag == $choose_user_tag) | .streamSettings.realitySettings.shortIds) |= map(select(. != $shortId))' || return 1
                    fi
                    if [[ -n "${removed_user_id}" ]]; then
                        update_json_config "${xray_install_config_file}" --arg uuid "${removed_user_id}" 'del(.reality_clients[$uuid])' || return 1
                    fi
                fi
                local remaining_multi_user
                remaining_multi_user=$(jq '[.inbounds[].settings.clients | length] | any(. > 1)' "${xray_conf}" 2>/dev/null)
                if [[ "${remaining_multi_user}" != "true" ]]; then
                    update_json_config "${xray_install_config_file}" 'del(.multi_user) | del(.reality_clients)'
                fi
            fi
            echo
            log_echo "${GreenBG} $(gettext "是否继续删除用户") [Y/${Red}N${Font}${GreenBG}]?  ${Font}"
            read -r remove_user_continue
            case $remove_user_continue in
            [yY][eE][sS] | [yY])
                continue
                ;;
            *)
                break
                ;;
            esac
        done
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

show_access_log() {
    [[ -f "${xray_access_log}" ]] && tail -f ${xray_access_log} || log_echo "${Error} ${RedBG} log $(gettext "文件不存在")! ${Font}"
}

show_error_log() {
    [[ -f "${xray_error_log}" ]] && tail -f ${xray_error_log} || log_echo "${Error} ${RedBG} log $(gettext "文件不存在")! ${Font}"
}

# True when something is already listening on the requested loopback port.
# ss/lsof are preferred; /dev/tcp is a last-resort check for minimal images.
xray_stats_port_in_use() {
    local host="$1" port="$2"
    [[ -n "${host}" && "${port}" =~ ^[0-9]+$ ]] || return 1
    if command -v ss >/dev/null 2>&1; then
        ss -lnt 2>/dev/null |
            awk -v p=":${port}" '$4 ~ (p "$") { found = 1 } END { exit !found }'
        return $?
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
        return $?
    fi
    (exec 3<>"/dev/tcp/${host}/${port}") >/dev/null 2>&1
}

# Migrate an already-enabled stats config that predates api.listen.
# Writes only .api.listen, via the existing atomic update_json_config helper.
# No-op when stats is off or api.listen is already present, so repeated runs
# cannot change a single byte. On any test failure the original bytes are
# restored atomically with the original mode/owner preserved.
xray_stats_listen_ensure() {
    local listen="${1:-127.0.0.1:10085}"
    local conf="${xray_conf}"
    [[ -f "${conf}" ]] || return 0

    local has_stats has_api current
    has_stats=$(jq -r 'has("stats")' "${conf}" 2>/dev/null) || {
        log_echo "${Error} ${RedBG} $(gettext "流量统计配置解析失败") ${Font}"
        return 1
    }
    [[ "${has_stats}" == "true" ]] || return 0
    has_api=$(jq -r 'has("api")' "${conf}" 2>/dev/null) || {
        log_echo "${Error} ${RedBG} $(gettext "流量统计配置解析失败") ${Font}"
        return 1
    }
    [[ "${has_api}" == "true" ]] || {
        log_echo "${Error} ${RedBG} $(gettext "流量统计配置缺少 api 段") ${Font}"
        return 1
    }
    current=$(jq -r '.api.listen // empty' "${conf}" 2>/dev/null) || {
        log_echo "${Error} ${RedBG} $(gettext "流量统计配置解析失败") ${Font}"
        return 1
    }
    [[ -z "${current}" ]] || return 0

    local host="${listen%:*}" port="${listen##*:}"
    if [[ "${host}" != "127.0.0.1" || ! "${port}" =~ ^[0-9]+$ ]]; then
        log_echo "${Error} ${RedBG} $(gettext "统计 API 仅允许监听 127.0.0.1") ${Font}"
        return 1
    fi
    if xray_stats_port_in_use "${host}" "${port}"; then
        log_echo "${Error} ${RedBG} $(gettext "统计 API 端口已被占用"): ${listen} ${Font}"
        return 1
    fi

    local backup restore
    backup=$(mktemp "${conf}.stats-listen.XXXXXX" 2>/dev/null) || return 1
    if ! cp -p "${conf}" "${backup}" 2>/dev/null; then
        rm -f "${backup}"
        return 1
    fi
    if ! update_json_config "${conf}" --arg listen "${listen}" '.api.listen = $listen'; then
        rm -f "${backup}"
        return 1
    fi
    if [[ ! -x "${xray_bin_dir}/xray" ]] ||
        ! "${xray_bin_dir}/xray" run -test -config "${conf}" >/dev/null 2>&1; then
        restore="${conf}.stats-restore.$$"
        if cp -p "${backup}" "${restore}" 2>/dev/null && mv -f "${restore}" "${conf}"; then
            rm -f "${backup}"
            log_echo "${Error} ${RedBG} $(gettext "Xray 配置测试失败, 已还原原配置") ${Font}"
            return 1
        fi
        rm -f "${restore}"
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置测试失败, 还原失败") ${Font}"
        return 1
    fi
    rm -f "${backup}"
    return 0
}

xray_status_add() {
    if [[ -f "${xray_conf}" ]]; then
        if [[ $(jq -r .stats "${xray_conf}") != "null" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "已配置 Xray 流量统计") ${Font}"
            log_echo "${GreenBG} $(gettext "关闭统计会重启 Xray (短暂中断)") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop || return 1
                update_json_config "${xray_conf}" "del(.api)|del(.stats)|del(.policy)"
                if ! judge -r "$(gettext "关闭 Xray 流量统计")"; then
                    service_start
                    return 1
                fi
                service_start || return 1
                rm -f "${xray_status_conf}"
                return 0
                ;;
            *) ;;
            esac
        else
            echo
            log_echo "${GreenBG} Xray $(gettext "流量统计需要使用") api ${Font}"
            log_echo "${GreenBG} $(gettext "将写入 stats/api/policy 并重启 Xray (短暂中断)") ${Font}"
            log_echo "${GreenBG} $(gettext "可能会影响 Xray 性能") ${Font}"
            log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            read -r xray_status_add_fq
            case $xray_status_add_fq in
            [yY][eE][sS] | [yY])
                service_stop || return 1
                if ! judge -r "$(gettext "下载流量统计配置")" download_json_file "${shell_release_raw_base}/config/status_config.json" "${xray_status_conf}"; then
                    service_start
                    return 1
                fi
                local status_config
                if ! status_config=$(jq -c . "${xray_status_conf}"); then
                    rm -f "${xray_status_conf}"
                    log_echo "${Error} ${RedBG} $(gettext "流量统计配置解析失败") ${Font}"
                    service_start
                    return 1
                fi
                if ! update_json_config "${xray_conf}" --argjson status_config "${status_config}" \
                    '. += $status_config'; then
                    rm -f "${xray_status_conf}"
                    service_start
                    return 1
                fi
                # Older status_config fragments may not carry api.listen yet.
                # This is the only enable path allowed to add it.
                if ! xray_stats_listen_ensure; then
                    rm -f "${xray_status_conf}"
                    service_start
                    return 1
                fi
                if ! judge -r "$(gettext "设置 Xray 流量统计")"; then
                    rm -f "${xray_status_conf}"
                    service_start
                    return 1
                fi
                # The downloaded status_config is a merge source only; leaving
                # it behind made two files look like duplicated live config.
                rm -f "${xray_status_conf}"
                service_start || return 1
                ;;
            *) ;;
            esac
        fi
    else
        log_echo "${Warning} ${YellowBG} $(gettext "请先安装") Xray ! ${Font}"
    fi
}

# CLI/menu delegate for the read-only stats helper. Config mutation remains
# here: only --stats may offer the one-time api.listen migration, and only
# after an explicit confirmation. The helper itself never writes config.
# Legacy enable path left this downloaded merge source in the live config
# directory. It is never live config; remove it on startup and --stats so an
# upgraded node cannot keep looking at two similar files.
xray_stats_cleanup_legacy_config() {
    [[ -f "${xray_status_conf}" ]] || return 0
    rm -f "${xray_status_conf}" 2>/dev/null || return 1
}

xray_stats_cli() {
    local mode="${1:-}"
    shift || true
    if [[ "$(id -u)" != "0" ]]; then
        printf '%s\n' "$(gettext "统计查询需要 root 权限")" >&2
        return 5
    fi
    # Mutating cleanup must happen only after the root gate: --stats is a
    # documented read-only command and must never delete files as non-root.
    xray_stats_cleanup_legacy_config || true
    if [[ ! -f "${xray_stats_script}" ]]; then
        if [[ "${mode}" == "reset" ]]; then
            printf '%s\n' "$(gettext "统计脚本缺失, 请先运行 --stats 完成下载与校验")" >&2
            return 2
        fi
        if ! xray_stats_script_ensure; then
            printf '%s\n' "$(gettext "统计脚本下载或校验失败, 不影响统计开关")" >&2
            return 2
        fi
    fi

    if [[ "${mode}" == "stats" && -f "${xray_conf}" ]]; then
        local has_stats listen_answer
        has_stats=$(jq -r 'has("stats")' "${xray_conf}" 2>/dev/null) || has_stats="false"
        listen_answer=$(jq -r '.api.listen // empty' "${xray_conf}" 2>/dev/null) || listen_answer=""
        if [[ "${has_stats}" == "true" && -z "${listen_answer}" ]]; then
            confirm_prompt "$(gettext "统计已开启但缺少 api.listen, 是否补写并重启 Xray")"
            local _answer=""
            read -r _answer || _answer=""
            case "${_answer}" in
                [yY][eE][sS] | [yY])
                    service_stop || return 1
                    if ! xray_stats_listen_ensure; then
                        service_start
                        return 1
                    fi
                    service_start || return 1
                    ;;
                *)
                    printf '%s\n' "$(gettext "未修改配置, 统计查询需要 api.listen")" >&2
                    return 2
                    ;;
            esac
        fi
    fi

    local -a stats_args=()
    case "${mode}" in
        stats)
            stats_args=("$@")
            ;;
        reset)
            stats_args=(--reset "$@")
            ;;
        watch)
            local interval="5"
            if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
                interval="$1"
                shift
            fi
            stats_args=(--watch "${interval}" "$@")
            ;;
        *)
            printf '%s\n' "xray_stats_cli: unsupported mode: ${mode}" >&2
            return 4
            ;;
    esac
    # The stats helper resolves its own catalog and falls back to English.
    # Pass the menu's actual language directly; never downgrade to zh merely
    # because a gettext probe failed on a minimal image.
    local _stats_lang="${_XRAY_UI_LANG:-zh}"
    XRAY_STATS_LANG="${_stats_lang}" bash "${xray_stats_script}" --config "${xray_conf}" "${stats_args[@]}"
}

bbr_boost_sh() {
    read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
    if [[ -f "${scripts_dir}/tcp.sh" ]]; then
        cd "${scripts_dir}" && chmod +x ./tcp.sh && ./tcp.sh
    else
        if download_script_file "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" "${scripts_dir}/tcp.sh"; then
            "${scripts_dir}/tcp.sh"
        else
            log_echo "${Error} ${RedBG} TCP $(gettext "加速脚本下载失败") ${Font}"
            return 1
        fi
    fi
    read -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
}

uninstall_xray() {
    # Failure propagation: every removal step contributes to rcx. The final
    # log_echo must never mask an earlier failure (a non-zero rcx is returned
    # so uninstall_all() can route host commit vs abort correctly).
    #
    # `--purge` is dispatched as an offline root mutation, so read_version has
    # not populated the pinned Xray-install metadata. Offline removal must not
    # depend on downloading an installer: stop/disable the service and remove
    # the known host files directly. The pinned installer path is retained only
    # when metadata is already available (e.g. an in-process call).
    local rcx=0
    local had_xray_unit=0
    if [[ -f "${xray_systemd_file}" || -f "${xray_systemd_file%.service}@.service" ]]; then
        had_xray_unit=1
        systemctl disable xray 2>/dev/null || rcx=1
        systemctl stop xray 2>/dev/null || true
    fi

    if verified_installer_metadata_valid; then
        if ! xray_install_release remove --purge; then
            rcx=1
            log_echo "${Warning} ${YellowBG} Xray-install remove failed; falling back to direct removal ${Font}"
        fi
    fi

    if [[ -f "${xray_bin_dir}/xray" ]]; then
        safe_rm "${xray_bin_dir}/xray" || rcx=1
    fi
    [[ -d "${xray_conf_dir}" ]] && { safe_rm "${xray_conf_dir}" || rcx=1; }
    [[ -d "${local_bin}/etc/xray" ]] && { safe_rm "${local_bin}/etc/xray" || rcx=1; }
    if [[ -d "${local_bin}/share/xray" || -L "${local_bin}/share/xray" ]]; then
        safe_rm "${local_bin}/share/xray" || rcx=1
    fi
    [[ -d "/var/log/xray" ]] && { safe_rm "/var/log/xray" || rcx=1; }
    [[ -f "${xray_systemd_file}" ]] && { safe_rm "${xray_systemd_file}" || rcx=1; }
    if [[ -f "${xray_systemd_file%.service}@.service" ]]; then
        safe_rm "${xray_systemd_file%.service}@.service" || rcx=1
    fi
    [[ -d "${xray_systemd_file}.d" ]] && { safe_rm "${xray_systemd_file}.d" || rcx=1; }
    # Not tied to the binary or unit surviving: purge is exactly the path where
    # one of them may already be gone. systemd must still drop any stale state.
    systemctl daemon-reload 2>/dev/null || rcx=1
    if [[ -f "${xray_install_config_file}" ]]; then
        # Purge must stay a cleanup operation even when interrupted metadata
        # is corrupt. The file is preserved or removed by the caller's explicit
        # keep-config choice; a failed metadata edit is diagnostic, not a
        # reason to report that the already-removed files were not removed.
        update_json_config "${xray_install_config_file}" -r 'del(.xray_version)' \
            || log_echo "${Warning} ${YellowBG} $(gettext "安装配置损坏, 跳过") .xray_version $(gettext "元数据清理") ${Font}"
    fi
    if [[ "$rcx" == 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "已卸载") Xray ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "Xray 卸载失败") ${Font}"
    fi
    return "$rcx"
}

uninstall_nginx() { 
    local rcn=0
    if [[ "${1}" != "--force" ]]; then
        log_echo "${GreenBG} $(gettext "是否卸载") Nginx [${Red}Y${Font}${GreenBG}/N]? ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [nN][oO] | [nN]) 
            log_echo "${OK} ${GreenBG} $(gettext "已取消卸载") Nginx ${Font}"        
            return
            ;;
        esac
    fi
    if [[ -f "${nginx_systemd_file}" ]]; then
        systemctl disable nginx 2>/dev/null || rcn=1
        systemctl stop nginx 2>/dev/null || true
    fi
    [[ -d "${nginx_dir}" ]] && { safe_rm "${nginx_dir}" || rcn=1; }
    [[ -d "${nginx_conf_dir}" ]] && { safe_rm "${nginx_conf_dir}" || rcn=1; }
    [[ -f "${nginx_systemd_file}" ]] && { safe_rm "${nginx_systemd_file}" || rcn=1; }
    if [[ -f "${xray_install_config_file}" ]]; then
        # Same corrupt-metadata rule as uninstall_xray: a failed edit is a
        # warning; it does not turn a completed file cleanup into a failure.
        update_json_config "${xray_install_config_file}" 'del(.nginx_build_version)' \
            || log_echo "${Warning} ${YellowBG} $(gettext "安装配置损坏, 跳过") .nginx_build_version $(gettext "元数据清理") ${Font}"
    fi
    if [[ "$rcn" == 0 ]]; then
        log_echo "${OK} ${GreenBG} $(gettext "已卸载") Nginx ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "Nginx 卸载失败") ${Font}"
    fi
    return "$rcn"
}

uninstall_all() {
    relay_bootstrap_role || true
    if is_relay_role; then
        relay_uninstall
        return $?
    fi
    # Fail-closed: if the Rill agent cannot be frozen in observe-only, do not
    # begin the host removal at all.
    if ! rxa_uninstall_prepare; then
        log_echo "${Error} ${RedBG} $(gettext "Rill Agent 准备失败, 已取消卸载") ${Font}"
        return 1
    fi
    local rxa_uninstall_rc=0
    stop_service_all || rxa_uninstall_rc=1
    acme_cron_cleanup || rxa_uninstall_rc=1
    local crontab_file
    crontab_file="$(root_crontab_path)"
    if [[ -f "${crontab_file}" ]]; then
        sed -i "/auto_update.sh/d" "${crontab_file}"
        sed -i "/geo_update.sh/d" "${crontab_file}"
        sed -i "\|${ssl_update_file}|d" "${crontab_file}"
    fi
    [[ -f "/etc/logrotate.d/xray_log_cleanup" ]] && rm -f "/etc/logrotate.d/xray_log_cleanup"
    [[ -L "/usr/local/etc/xray/config.json" ]] && rm -f "/usr/local/etc/xray/config.json"
    [[ -L "/usr/local/share/xray" ]] && rm -f "/usr/local/share/xray"
    # Node cleanup must not depend on the binary surviving: a missing binary is
    # exactly the case where stale units/config dirs are most likely.
    uninstall_xray || rxa_uninstall_rc=1
    echo
    uninstall_nginx --force || rxa_uninstall_rc=1
    echo
    local keep_config=true
    if [[ -f "${xray_install_config_file}" ]]; then
        log_echo "${GreenBG} $(gettext "是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
        read -r remove_config_fq
        case $remove_config_fq in
        [yY][eE][sS] | [yY])
            log_echo "${OK} ${GreenBG} $(gettext "已保留配置文件") ${Font}"
            ;;
        *)
            keep_config=false
            log_echo "${OK} ${GreenBG} $(gettext "将删除配置文件") ${Font}"
            ;;
        esac
    fi
    log_echo "${GreenBG} $(gettext "是否删除所有脚本文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r remove_all_idleleo_file_fq
    case $remove_all_idleleo_file_fq in
    [yY][eE][sS] | [yY])
        # The managed tree, including logs/, is about to disappear. Keep the
        # terminal messages but stop file logging, otherwise the final
        # log_echo calls make tee print "No such file or directory".
        LOG_FILE=/dev/null
        log_file=/dev/null
        if [[ "${keep_config}" == "true" && -f "${xray_install_config_file}" ]]; then
            local _tmp_config
            _tmp_config=$(mktemp)
            cp -f "${xray_install_config_file}" "${_tmp_config}"
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
            mkdir -p "${idleleo_conf_dir}"
            mv -f "${_tmp_config}" "${xray_install_config_file}"
        else
            safe_rm "${idleleo_commend_file}"
            safe_rm "${idleleo_dir}"
        fi
        systemctl daemon-reload || rxa_uninstall_rc=1
        log_echo "${OK} ${GreenBG} $(gettext "已删除所有文件") ${Font}"
        log_echo "${GreenBG} $(gettext "ヾ(￣▽￣) 拜拜~") ${Font}"
        # Only a clean host phase AND a passing host post-verify may commit.
        if [[ "$rxa_uninstall_rc" == 0 ]] && ! rxa_host_post_verify; then
            rxa_uninstall_rc=1
            log_echo "${Error} ${RedBG} $(gettext "卸载后校验失败, 已保留 Rill 诊断") ${Font}"
        fi
        rxa_uninstall_finish_if_present "$rxa_uninstall_rc"
        exit "$?"
        ;;
    *)
        if [[ "${keep_config}" == "false" && -f "${xray_install_config_file}" ]]; then
            rm -rf "${xray_install_config_file}"
            log_echo "${OK} ${GreenBG} $(gettext "已删除配置文件") ${Font}"
        fi
        systemctl daemon-reload || rxa_uninstall_rc=1
        log_echo "${OK} ${GreenBG} $(gettext "已保留脚本文件 (包含 SSL 证书等)") ${Font}"
        ;;
    esac
    # Only a clean host phase AND a passing host post-verify may commit.
    if [[ "$rxa_uninstall_rc" == 0 ]] && ! rxa_host_post_verify; then
        rxa_uninstall_rc=1
        log_echo "${Error} ${RedBG} $(gettext "卸载后校验失败, 已保留 Rill 诊断") ${Font}"
    fi
    rxa_uninstall_finish_if_present "$rxa_uninstall_rc"
}

# uninstall_all must not treat "Rill is not installed" as a Rill failure.
# rxa_uninstall_prepare() is already a no-op in that case; route finish through
# this wrapper so a clean node purge returns the host rc. The candidate probe
# still calls rxa_uninstall_commit() directly and requires its fail-closed
# behavior when the purge script is missing.
rxa_uninstall_finish_if_present() {
    local rc="$1"
    if command -v rxa_apply_mode >/dev/null 2>&1; then
        rxa_uninstall_finish "${rc}"
    else
        return "${rc}"
    fi
}

delete_tls_key_and_crt() {
    [[ -f "$HOME/.acme.sh/acme.sh" ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d "$HOME/.acme.sh" ]] && rm -rf "$HOME/.acme.sh"
    log_echo "${OK} ${GreenBG} $(gettext "已清空证书遗留文件") ${Font}"
}

countdown() {
    # The progress bar uses raw ANSI cursor sequences. Skip it when stdout is
    # not a TTY, and also under NO_COLOR/TERM=dumb, so those modes see zero ESC.
    [[ -t 1 && "${_color_enabled}" == "1" ]] || return 0
    countdown_cnt=0
    countdown_str=""
    while [[ ${countdown_cnt} -le 30 ]]; do
        let countdown_cnt++
        countdown_str+="#"
    done
    let countdown_cnt=countdown_cnt+5
    while [[ ${countdown_cnt} -gt 0 ]]; do
        let countdown_cnt--
        if [[ ${countdown_cnt} -gt 25 ]]; then
            let countdown_color=32
            let countdown_bg=42
            countdown_index="3"
        elif [[ ${countdown_cnt} -gt 15 ]]; then
            let countdown_color=33
            let countdown_bg=43
            countdown_index="2"
        elif [[ ${countdown_cnt} -gt 5 ]]; then
            let countdown_color=31
            let countdown_bg=41
            countdown_index="1"
        else
            countdown_index="0"
        fi
        # Colors are passed as %b arguments, never concatenated into the
        # printf format string: the countdown title is dynamic text and must
        # not be able to inject a conversion specifier.
        printf '%b %d%s%s %b \033[%d;%dm%-s\033[0m \033[%dm%d\033[0m \r' \
            "${Warning} ${GreenBG}" \
            "$countdown_index" \
            " $(gettext "秒后") " \
            "$1" \
            "${Font}" \
            "$countdown_color" \
            "$countdown_bg" \
            "$countdown_str" \
            "$countdown_color" \
            "$countdown_index"
        sleep 0.1
        countdown_str=${countdown_str%?}
        [[ ${countdown_cnt} -eq 0 ]] && printf "\n"
    done
}

judge_mode() {
    # Restore dual-stack runtime state on a fresh process so --show / menus
    # still emit IPv6 links after the script exits and re-runs.
    ensure_network_runtime_state
    if [[ -f "${xray_install_config_file}" ]]; then
        node_role=$(info_extraction role)
        [[ -z ${node_role} || ${node_role} == "null" ]] && node_role="node"
        if is_relay_role; then
            _relay_state_load
            shell_mode="$(gettext "中转节点")"
            tls_mode="None"
            transport_mode="None"
            old_tls_mode=${tls_mode}
            return 0
        fi
        transport_mode=$(info_extraction transport_mode)
        [[ -z ${transport_mode} || ${transport_mode} == "null" ]] && transport_mode="None"
        tls_mode=$(info_extraction tls)
        if [[ ${tls_mode} == "XTLS" ]]; then
            # The "XTLS ONLY" mode is gone. Do not migrate or rewrite anything:
            # only mark it so reinstall is refused and the UI stops pretending
            # the mode is still configurable.
            legacy_xtls_only="on"
        fi
        if [[ ${tls_mode} == "Reality" ]]; then
            reality_add_more=$(info_extraction reality_add_more)
            reality_add_nginx=$(info_extraction reality_add_nginx)
            reality_add_balance=$(info_extraction reality_add_balance)
            reality_balance_role=$(info_extraction reality_balance_role)
            [[ -z ${reality_balance_role} || ${reality_balance_role} == "null" ]] && reality_balance_role=""
        fi
        _transport_set_shell_mode
        old_tls_mode=${tls_mode}
    fi
}

#=================================================================
# 中转节点 (relay role)
#
# A relay is a standalone server that forwards ONE local TCP port to a landing
# node with Nginx Stream. It installs no Xray binary, keeps no UUID/private
# key/certificate, terminates no TLS, and never asks for backend credentials.
# Clients keep the landing node's Reality parameters (public key, SNI, ShortId)
# and only change the server address and port.
#
# Everything below is scoped to role=relay. Ordinary nodes keep the historical
# code paths: an install_config.json without "role" is a normal node.
#=================================================================

# Read role-specific fields back from install_config.json into globals.
_relay_state_load() {
    local _v
    _v=$(info_extraction relay_backend_host); [[ ${_v} == "null" ]] && _v=""
    relay_backend_host="${_v}"
    _v=$(info_extraction relay_backend_port); [[ ${_v} == "null" ]] && _v=""
    relay_backend_port="${_v}"
    _v=$(info_extraction relay_listen_port); [[ ${_v} == "null" ]] && _v=""
    relay_listen_port="${_v}"
    _v=$(info_extraction relay_listen_addr); [[ ${_v} == "null" ]] && _v=""
    relay_listen_addr="${_v}"
    _v=$(info_extraction relay_enabled); [[ ${_v} == "null" ]] && _v=""
    relay_enabled="${_v}"
    [[ -n "${relay_listen_addr}" ]] || relay_listen_addr="0.0.0.0"
    # `port` is the role-neutral listening port used by shared health checks.
    [[ -n "${relay_listen_port}" ]] && port="${relay_listen_port}"
}

# Set the role globals straight from install_config.json. Used by dispatch
# paths that run without judge_mode() (offline root mutations such as
# --service-restart / --purge), so they never fall back to the Xray code path
# on a relay host.
relay_bootstrap_role() {
    [[ -f "${xray_install_config_file}" ]] || return 1
    [[ "$(info_extraction role 2>/dev/null)" == "relay" ]] || return 1
    node_role="relay"
    tls_mode="None"
    transport_mode="None"
    shell_mode="$(gettext "中转节点")"
    _relay_state_load
    return 0
}

# Backend host: IPv4/IPv6 literal or DNS name. Rejects anything that could be
# spliced into the generated Nginx config (spaces, ; { } quotes, newlines).
relay_is_valid_host() {
    local host="${1:-}"
    [[ -n "${host}" && ${#host} -le 253 ]] || return 1
    is_ipv6_literal "${host}" && return 0
    is_ipv4_literal "${host}" && return 0
    # A bare number is neither an IP nor a legal hostname (numeric TLDs are
    # invalid), and `proxy_pass 443:443` would be ambiguous. Refuse it.
    [[ "${host}" =~ ^[0-9]+$ ]] && return 1
    [[ "${host}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    [[ "${host}" != *".."* ]] || return 1
    [[ "${host}" != *".-"* && "${host}" != *"-."* ]] || return 1
    return 0
}

relay_validate_inputs() {
    local _p
    if ! relay_is_valid_host "${relay_backend_host}"; then
        log_echo "${Error} ${RedBG} $(gettext "落地服务器地址无效") ${Font}"
        return 1
    fi
    for _p in "${relay_backend_port}" "${relay_listen_port}"; do
        if [[ ! "${_p}" =~ ^[0-9]+$ ]] || (( _p < 1 || _p > 65535 )); then
            log_echo "${Error} ${RedBG} $(gettext "端口无效, 必须是 1-65535") ${Font}"
            return 1
        fi
    done
    if ! is_valid_listen_address "${relay_listen_addr}"; then
        log_echo "${Error} ${RedBG} $(gettext "监听地址无效") ${Font}"
        return 1
    fi
    return 0
}

# Emit the managed stream{} block on stdout. Pure: no filesystem access, so it
# can be asserted directly in tests.
relay_render_stream_conf() {
    local listen_addr="$1"
    local listen_port="$2"
    local backend_host="$3"
    local backend_port="$4"
    local listen_line backend_target

    if [[ "${listen_addr}" == *:* ]]; then
        listen_line="listen [${listen_addr}]:${listen_port};"
    else
        listen_line="listen ${listen_addr}:${listen_port};"
    fi
    if [[ "${backend_host}" == *:* ]]; then
        backend_target="[${backend_host}]:${backend_port}"
    else
        backend_target="${backend_host}:${backend_port}"
    fi

    cat <<EOF
# Managed by Xray_bash_onekey (relay node). Do not edit by hand.
# Rewritten by the installer and the updater; change it from the script menu.
stream {
    server {
        ${listen_line}
        proxy_pass ${backend_target};
        proxy_connect_timeout 10s;
        proxy_timeout 720m;
        proxy_socket_keepalive on;
    }
}
EOF
}

relay_stream_conf_install() {
    local content_file="$1"

    [[ -f "${content_file}" ]] || return 1
    mkdir -p "${nginx_conf_dir}" || return 1
    if ! cp -f "${content_file}" "${relay_stream_conf}"; then
        log_echo "${Error} ${RedBG} $(gettext "写入中转配置失败") ${Font}"
        return 1
    fi
    chmod 640 "${relay_stream_conf}" 2>/dev/null || true
    chown "root:$(get_nginx_worker_group)" "${relay_stream_conf}" 2>/dev/null || true
    return 0
}

# Strip our managed include + marker from the main config. Uses awk instead of
# GNU-only `sed` alternate delimiters so the same code path also behaves on the
# BSD userland used by developer hosts (production always rewrites in place, so
# the file keeps its owner and mode).
nginx_relay_main_conf_strip() {
    local include_line="include ${relay_stream_conf};"
    local marker="# Xray_bash_onekey relay node (managed)"
    local tmp

    [[ -f "${nginx_main_conf}" ]] || return 0
    tmp=$(mktemp) || return 1
    if ! awk -v inc="${include_line}" -v marker="${marker}" '
        {
            line = $0
            sub(/^[ \t]+/, "", line)
            if (line == inc || line == marker) { next }
            print
        }
    ' "${nginx_main_conf}" >"${tmp}"; then
        rm -f "${tmp}"
        return 1
    fi
    cat "${tmp}" >"${nginx_main_conf}" || {
        rm -f "${tmp}"
        return 1
    }
    rm -f "${tmp}"
    return 0
}

# Add the top-level include that makes Nginx read the managed stream fragment.
# Only one stream{} context may come from us; a user-owned top-level stream
# block in nginx.conf is refused instead of being silently duplicated.
nginx_relay_main_conf_prepare() {
    local include_line="include ${relay_stream_conf};"

    [[ -f "${nginx_main_conf}" ]] || return 1
    if grep -qE '^[[:space:]]*stream[[:space:]]*\{' "${nginx_main_conf}"; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 主配置中已存在自定义 stream 块, 请手动处理后重试") ${Font}"
        return 1
    fi
    nginx_relay_main_conf_strip || return 1
    printf '\n# Xray_bash_onekey relay node (managed)\n%s\n' "${include_line}" >>"${nginx_main_conf}" || return 1
    grep -qF "${include_line}" "${nginx_main_conf}" || return 1
    return 0
}

nginx_relay_main_conf_remove() {
    nginx_relay_main_conf_strip || return 1
    return 0
}

# Restore the previous forwarding state after a failed apply.
_relay_apply_rollback() {
    local existed="$1"
    local backup="$2"
    local prev_active="$3"

    if [[ "${existed}" == "yes" && -f "${backup}" ]]; then
        cp -fp "${backup}" "${relay_stream_conf}" 2>/dev/null || true
        nginx_relay_main_conf_prepare >/dev/null 2>&1 || true
    else
        rm -f "${relay_stream_conf}"
        nginx_relay_main_conf_remove
    fi
    rm -f "${backup}"

    if nginx_run_config_test >/dev/null 2>&1; then
        if [[ "${prev_active}" == "yes" ]]; then
            systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1
        else
            systemctl stop nginx >/dev/null 2>&1
        fi
        log_echo "${Warning} ${YellowBG} $(gettext "已恢复上一次的转发配置") ${Font}"
    else
        log_echo "${Error} ${RedBG} $(gettext "恢复转发配置后 Nginx 校验仍失败, 请查看 Nginx 错误日志") ${Font}"
    fi
}

# Write a new forwarding config as a transaction: remember the previous file and
# service state, validate with `nginx -t`, only then reload/start, and roll back
# to the previous forwarding when validation or startup fails.
nginx_relay_apply_config() {
    local content_file="$1"
    local backup=""
    local existed="no"
    local prev_active="no"

    [[ -f "${content_file}" ]] || return 1
    if [[ -f "${relay_stream_conf}" ]]; then
        existed="yes"
        backup=$(mktemp) || return 1
        if ! cp -fp "${relay_stream_conf}" "${backup}"; then
            rm -f "${backup}"
            return 1
        fi
    fi
    systemctl is-active --quiet nginx 2>/dev/null && prev_active="yes"

    if ! relay_stream_conf_install "${content_file}" ||
        ! nginx_relay_main_conf_prepare ||
        ! nginx_run_config_test >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Nginx 配置校验失败, 已恢复原转发配置") ${Font}"
        _relay_apply_rollback "${existed}" "${backup}" "${prev_active}"
        return 1
    fi

    if [[ "${prev_active}" == "yes" ]]; then
        if ! judge -r "Nginx $(gettext "重启")" systemctl reload nginx; then
            nginx_diagnose
            _relay_apply_rollback "${existed}" "${backup}" "${prev_active}"
            return 1
        fi
    elif ! judge -r "Nginx $(gettext "启动")" systemctl start nginx; then
        nginx_diagnose
        _relay_apply_rollback "${existed}" "${backup}" "${prev_active}"
        return 1
    fi
    rm -f "${backup}"
    return 0
}

relay_create_directory() {
    [[ -d "${nginx_conf_dir}" ]] || mkdir -p "${nginx_conf_dir}" || return 1
    [[ -d "${idleleo_conf_dir}" ]] || mkdir -p "${idleleo_conf_dir}" || return 1
    [[ -d "${idleleo_dir}/info" ]] || mkdir -p "${idleleo_dir}/info" || return 1
    return 0
}

# A relay owns the whole server. Never overwrite an existing managed node or a
# managed Nginx site: refuse and let the operator decide.
relay_preflight() {
    local _f
    if [[ -f "${xray_install_config_file}" ]]; then
        local _role
        _role=$(info_extraction role)
        if [[ "${_role}" == "relay" ]]; then
            # Reinstalling/reconfiguring the relay itself is allowed.
            _relay_state_load
            return 0
        fi
        if [[ -f "${xray_conf}" ]] || [[ -f "${nginx_conf}" ]] ||
            [[ -f "${nginx_ssl_conf}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "检测到已有普通节点安装, 中转节点需要独立服务器") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "请先卸载原节点或改用普通节点安装, 本脚本不会覆盖现有配置") ${Font}"
            return 1
        fi
    fi
    for _f in "${nginx_conf}" "${nginx_ssl_conf}" "${nginx_upstream_conf}" \
        "${nginx_conf_dir}/03-isolate.conf" "${nginx_conf_dir}/03-decoy.conf"; do
        if [[ -f "${_f}" ]]; then
            log_echo "${Error} ${RedBG} $(gettext "检测到脚本管理的 Nginx 站点配置"): ${_f} ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "中转节点不能与普通节点或受管站点混装, 请先手动处理") ${Font}"
            return 1
        fi
    done
    if [[ -f "${xray_conf}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "检测到 Xray 配置文件"): ${xray_conf} ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "中转节点不安装 Xray, 请先手动处理现有 Xray 配置") ${Font}"
        return 1
    fi
    return 0
}

relay_wizard() {
    local _default_host="${relay_backend_host:-NULL}"
    local _default_bport="${relay_backend_port:-443}"
    local _default_lport="${relay_listen_port:-443}"
    local _advanced

    echo
    log_echo "${GreenBG} $(gettext "中转节点安装向导") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "中转节点只做 TCP 透明转发, 不安装 Xray, 不终止 TLS/REALITY") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "客户端只修改服务器地址和端口, 落地节点的 REALITY 公钥/SNI/ShortId 保持不变") ${Font}"
    echo
    while true; do
        read_optimize "$(gettext "落地服务器地址 (IP 或域名)"): " "relay_backend_host" "${_default_host}" || return 1
        relay_is_valid_host "${relay_backend_host}" && break
        log_echo "${Error} ${RedBG} $(gettext "落地服务器地址无效, 请重新输入") ${Font}"
    done
    read_optimize "$(gettext "落地服务器端口") (default: 443): " "relay_backend_port" "${_default_bport}" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
    read_optimize "$(gettext "本机监听端口") (default: 443): " "relay_listen_port" "${_default_lport}" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1

    [[ -n "${relay_listen_addr}" ]] || relay_listen_addr="0.0.0.0"
    echo
    log_echo "${GreenBG} $(gettext "监听地址"): ${relay_listen_addr} ($(gettext "默认监听所有地址")) ${Font}"
    log_echo "${GreenBG} $(gettext "是否需要指定其他监听地址") [y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r _advanced
    case ${_advanced:-} in
    [yY][eE][sS] | [yY])
        while true; do
            read_optimize "$(gettext "监听地址 (IPv4/IPv6)"): " "relay_listen_addr" "${relay_listen_addr}" || return 1
            is_valid_listen_address "${relay_listen_addr}" && break
            log_echo "${Error} ${RedBG} $(gettext "监听地址无效, 请重新输入") ${Font}"
        done
        ;;
    *) ;;
    esac
    return 0
}

relay_config_write() {
    local _new_fields
    _new_fields=$(mktemp) || return 1
    if ! jq -nc \
        --arg host "${local_ip:-}" \
        --arg ip_version "${ip_version:-}" \
        --arg network_mode "${network_mode:-ipv4}" \
        --arg ipv4 "${ipv4_address:-}" \
        --arg ipv6 "${ipv6_address:-}" \
        --arg backend_host "${relay_backend_host}" \
        --argjson backend_port "${relay_backend_port}" \
        --argjson listen_port "${relay_listen_port}" \
        --arg listen_addr "${relay_listen_addr}" \
        --arg shell_version "${shell_version}" \
        --arg nginx_version "${nginx_build_version:-}" \
        '{role:"relay", shell_mode:"Relay", transport_mode:"None", tls:"None",
          host:$host, ip_version:$ip_version, network_mode:$network_mode,
          ipv4_address:$ipv4, ipv6_address:$ipv6,
          relay_backend_host:$backend_host, relay_backend_port:$backend_port,
          relay_listen_port:$listen_port, relay_listen_addr:$listen_addr,
          relay_enabled:"on", shell_version:$shell_version,
          nginx_build_version:$nginx_version}' >"${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    if ! _install_config_merge_write "${_new_fields}"; then
        rm -f "${_new_fields}"
        return 1
    fi
    rm -f "${_new_fields}"
    node_role="relay"
    return 0
}

# Render + validate + apply the current relay_* globals, then persist them.
relay_apply_change() {
    local _tmp

    relay_validate_inputs || return 1
    _tmp=$(mktemp) || return 1
    relay_render_stream_conf "${relay_listen_addr}" "${relay_listen_port}" \
        "${relay_backend_host}" "${relay_backend_port}" >"${_tmp}"
    if ! nginx_relay_apply_config "${_tmp}"; then
        rm -f "${_tmp}"
        return 1
    fi
    rm -f "${_tmp}"
    if ! relay_config_write; then
        log_echo "${Warning} ${YellowBG} $(gettext "转发已生效, 但配置记录写入失败, 请重新运行安装向导") ${Font}"
        return 1
    fi
    return 0
}

# Best-effort firewall follow-up after the listening port changes. Only runs when
# the operator opted into firewall management at install time.
relay_firewall_sync() {
    local _old
    command -v iptables >/dev/null 2>&1 || return 0
    [[ -f "${managed_ports_file}" ]] || return 0
    _old=$(cat "${managed_ports_file}" 2>/dev/null) || return 0
    [[ -n "${_old}" ]] || return 0
    collect_new_managed_ports
    if ! apply_managed_firewall_transaction "${_old}" "${new_ports_json}" \
        "$(_managed_fw_bins)" "$(_managed_fw_bins)"; then
        log_echo "${Warning} ${YellowBG} $(gettext "防火墙端口同步失败, 请手动放行新端口") ${Font}"
        return 1
    fi
    firewall_persist_rules "$(_managed_fw_bins)" || true
    return 0
}

relay_modify_target() {
    local _old_host _old_port

    _relay_state_load
    if [[ -z "${relay_backend_host}" || -z "${relay_backend_port}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "当前没有可修改的中转配置") ${Font}"
        return 1
    fi
    _old_host="${relay_backend_host}"
    _old_port="${relay_backend_port}"

    echo
    log_echo "${GreenBG} $(gettext "修改落地目标") ${Font}"
    read_optimize "$(gettext "落地服务器地址 (IP 或域名)"): " "relay_backend_host" "${relay_backend_host}" || return 1
    if ! relay_is_valid_host "${relay_backend_host}"; then
        log_echo "${Error} ${RedBG} $(gettext "落地服务器地址无效, 已取消") ${Font}"
        relay_backend_host="${_old_host}"
        return 1
    fi
    read_optimize "$(gettext "落地服务器端口"): " "relay_backend_port" "${relay_backend_port}" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1

    if ! relay_apply_change; then
        relay_backend_host="${_old_host}"
        relay_backend_port="${_old_port}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "落地目标已更新") ${Font}"
    return 0
}

relay_modify_listen_port() {
    local _old_port

    _relay_state_load
    if [[ -z "${relay_listen_port}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "当前没有可修改的中转配置") ${Font}"
        return 1
    fi
    _old_port="${relay_listen_port}"

    echo
    log_echo "${GreenBG} $(gettext "修改监听端口") ${Font}"
    read_optimize "$(gettext "本机监听端口"): " "relay_listen_port" "${relay_listen_port}" 1 65535 "$(gettext "请输入 1-65535 之间的值")!" || return 1
    if [[ "${relay_listen_port}" != "${_old_port}" ]] &&
        ! port_exist_check "${relay_listen_port}"; then
        relay_listen_port="${_old_port}"
        return 1
    fi
    if ! relay_apply_change; then
        relay_listen_port="${_old_port}"
        return 1
    fi
    port="${relay_listen_port}"
    relay_firewall_sync || true
    log_echo "${OK} ${GreenBG} $(gettext "监听端口已更新") ${Font}"
    return 0
}

relay_test_backend() {
    _relay_state_load
    if [[ -z "${relay_backend_host}" || -z "${relay_backend_port}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "当前没有可测试的中转配置") ${Font}"
        return 1
    fi
    log_echo "$(gettext "测试到落地节点的 TCP 连通性"): ${relay_backend_host}:${relay_backend_port} "
    if timeout 5 bash -c ':</dev/tcp/$1/$2' _ "${relay_backend_host}" "${relay_backend_port}" >/dev/null 2>&1; then
        log_echo "${OK} ${GreenBG} $(gettext "TCP 连接成功 (仅代表端口可达, 不代表 REALITY/TLS 握手成功)") ${Font}"
        return 0
    fi
    log_echo "${Error} ${RedBG} $(gettext "无法连接落地节点端口, 请检查地址/端口/防火墙") ${Font}"
    return 1
}

relay_entry_display() {
    local _host="${local_ip:-$(info_extraction host)}"

    if [[ "${relay_listen_addr}" == "0.0.0.0" || -z "${relay_listen_addr}" ]]; then
        printf '%s:%s' "${_host}" "${relay_listen_port}"
    elif [[ "${relay_listen_addr}" == *:* ]]; then
        printf '[%s]:%s' "${relay_listen_addr}" "${relay_listen_port}"
    else
        printf '%s:%s' "${relay_listen_addr}" "${relay_listen_port}"
    fi
}

relay_basic_information() {
    _relay_state_load
    {
        echo
        log_echo "${OK} ${GreenBG} $(gettext "中转节点") $(gettext "安装") $(gettext "完成") ${Font}"
        echo
        log_echo "${Red} —————————————— $(gettext "中转节点配置信息") —————————————— ${Font}"
        log_echo "${Red} $(gettext "本机中转入口"):${Font} $(relay_entry_display) "
        log_echo "${Red} $(gettext "落地服务器"):${Font} ${relay_backend_host}:${relay_backend_port} "
        log_echo "${Red} $(gettext "转发方式"):${Font} Nginx Stream TCP $(gettext "透传") "
        log_echo "${Red} $(gettext "监听地址"):${Font} ${relay_listen_addr} "
        log_echo "${Red} $(gettext "启用状态"):${Font} ${relay_enabled:-on} "
        if command -v "${nginx_dir}/sbin/nginx" >/dev/null 2>&1; then
            log_echo "${Red} Nginx:${Font} $(info_extraction nginx_build_version) "
        fi
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "客户端只修改服务器地址和端口, 落地节点的 REALITY 公钥/SNI/ShortId 等参数保持不变") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "TCP 端口可达不代表 REALITY/TLS 握手成功, 请以客户端实际连接为准") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "本机不安装 Xray, 不终止 TLS, 也不保存落地节点的私钥") ${Font}"
    } >"${xray_info_file}"
    chmod -f 600 "${xray_info_file}" 2>/dev/null
}

relay_show_information() {
    relay_basic_information
    show_information
}

relay_status_refresh() {
    local _probe_addr

    if pgrep -x nginx >/dev/null 2>&1; then
        nginx_status="${Green}$(gettext "运行中")..${Font}"
    else
        nginx_status="${Red}$(gettext "未运行")${Font}"
    fi
    _probe_addr="${relay_listen_addr}"
    case "${_probe_addr}" in
    0.0.0.0 | "") _probe_addr="127.0.0.1" ;;
    ::) _probe_addr="::1" ;;
    esac
    if [[ -n "${relay_listen_port}" ]] &&
        timeout 3 bash -c ':</dev/tcp/$1/$2' _ "${_probe_addr}" "${relay_listen_port}" >/dev/null 2>&1; then
        relay_local_connect_status="${Green}$(gettext "本地正常")${Font}"
    else
        relay_local_connect_status="${Red}$(gettext "无法连通")${Font}"
    fi
}

show_nginx_error_log() {
    local _log="${nginx_dir}/logs/error.log"

    if [[ ! -f "${_log}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "Nginx 错误日志不存在") ${Font}"
        return 1
    fi
    tail -n 40 "${_log}"
}

install_nginx_relay() {
    local _tmp_conf

    is_root
    check_system
    dependency_install || return 1
    relay_preflight || return 1
    rxa_reconfigure_enter
    trap 'rxa_reconfigure_leave $?' RETURN
    basic_optimization || return 1
    relay_create_directory || return 1
    ip_check || return 1
    relay_wizard || return 1
    relay_validate_inputs || return 1
    port_exist_check "${relay_listen_port}" || return 1
    # Persist the role/target BEFORE touching Nginx: a host that aborted midway
    # must still be identifiable as a relay, never mistaken for a node.
    relay_config_write || return 1
    nginx_exist_check || return 1
    nginx_systemd || return 1
    # Record the concrete Nginx build only once the binary is actually in place.
    update_json_config "${xray_install_config_file}" \
        --arg nginx_build_version "${nginx_build_version:-}" \
        '.nginx_build_version = $nginx_build_version' || return 1

    _tmp_conf=$(mktemp) || return 1
    relay_render_stream_conf "${relay_listen_addr}" "${relay_listen_port}" \
        "${relay_backend_host}" "${relay_backend_port}" >"${_tmp_conf}"
    if ! nginx_relay_apply_config "${_tmp_conf}"; then
        rm -f "${_tmp_conf}"
        return 1
    fi
    rm -f "${_tmp_conf}"

    firewall_set || return 1
    enable_process_systemd || return 1
    auto_update || return 1
    trap - RETURN
    relay_basic_information
    show_information
}

# A relay owns the host, but a mixed/interrupted installation may still carry
# the node surface. Purge is a cleanup contract, so remove that stale surface
# rather than reporting success while leaving Xray binaries, configs or units.
relay_clean_xray_residue() {
    local residue=0
    [[ -e "${xray_bin_dir}/xray" ]] && residue=1
    [[ -e "${local_bin}/etc/xray" || -L "${local_bin}/etc/xray" ]] && residue=1
    [[ -e "${local_bin}/share/xray" || -L "${local_bin}/share/xray" ]] && residue=1
    [[ -e "${xray_conf_dir}" ]] && residue=1
    [[ -f "${xray_systemd_file}" || -f "${xray_systemd_file%.service}@.service" ]] && residue=1
    (( residue == 0 )) && return 0
    log_echo "${Warning} ${YellowBG} $(gettext "检测到旧 node 残留, 一并清理") ${Font}"
    uninstall_xray
}

relay_uninstall() {
    local _confirm _keep_config _remove_scripts

    echo
    log_echo "${Warning} ${YellowBG} $(gettext "将删除中转配置并卸载 Nginx, 是否继续") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
    read -r _confirm
    case ${_confirm:-} in
    [yY][eE][sS] | [yY]) ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "已取消") ${Font}"
        return 1
        ;;
    esac

    systemctl stop nginx 2>/dev/null
    systemctl disable nginx 2>/dev/null
    nginx_relay_main_conf_remove
    rm -f "${relay_stream_conf}"
    if [[ -x "${nginx_dir}/sbin/nginx" ]] && ! nginx_run_config_test >/dev/null 2>&1; then
        log_echo "${Warning} ${YellowBG} $(gettext "删除中转配置后 Nginx 仍无法通过校验, 请手动检查") ${Font}"
    fi
    uninstall_nginx --force || return 1
    relay_clean_xray_residue || return 1

    log_echo "${GreenBG} $(gettext "是否保留配置文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r _keep_config
    case ${_keep_config:-} in
    [yY][eE][sS] | [yY])
        if [[ -f "${xray_install_config_file}" ]]; then
            update_json_config "${xray_install_config_file}" \
                'del(.role, .relay_backend_host, .relay_backend_port, .relay_listen_port, .relay_listen_addr, .relay_enabled, .nginx_build_version)' || return 1
        fi
        ;;
    *)
        rm -f "${xray_install_config_file}"
        ;;
    esac

    log_echo "${GreenBG} $(gettext "是否删除所有脚本文件") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r _remove_scripts
    case ${_remove_scripts:-} in
    [yY][eE][sS] | [yY])
        # Same as the node purge: logs/ disappears with the managed tree, so
        # the remaining messages must not tee into a deleted log file.
        LOG_FILE=/dev/null
        log_file=/dev/null
        safe_rm "${idleleo_commend_file}"
        safe_rm "${idleleo_dir}"
        log_echo "${OK} ${GreenBG} $(gettext "已删除所有文件") ${Font}"
        ;;
    *)
        log_echo "${OK} ${GreenBG} $(gettext "已保留脚本文件") ${Font}"
        ;;
    esac
    systemctl daemon-reload 2>/dev/null || true
    node_role="node"
    log_echo "${OK} ${GreenBG} $(gettext "中转节点已删除") ${Font}"
    return 0
}

# Relay-scoped menu helpers. A relay never shows Xray/Rill entries: they would
# either fail or mislead, because no Xray binary, config or UUID exists.
menu_relay_service() {
    local menu_num

    while true; do
        menu_submenu_begin "$(gettext "服务相关")"
        menu_item 1 "$(gettext "重启") Nginx"
        menu_item 2 "$(gettext "启动") Nginx"
        menu_item 3 "$(gettext "停止") Nginx"
        menu_item 4 "$(gettext "查看") Nginx $(gettext "状态")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
        0) return ;;
        1)
            service_restart
            menu_pause
            ;;
        2)
            service_start
            menu_pause
            ;;
        3)
            service_stop
            menu_pause
            ;;
        4)
            systemctl status nginx --no-pager
            menu_pause
            ;;
        esac
    done
}

menu_relay_update() {
    local menu_num

    while true; do
        menu_submenu_begin "$(gettext "更新向导")"
        menu_item 1 "$(gettext "更新") $(gettext "脚本")"
        menu_item 2 "$(gettext "更新") Nginx"
        menu_item 3 "$(gettext "配置") $(gettext "自动更新")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
        0) return ;;
        1) menu_action 0 ;;
        2)
            echo
            log_echo "${Red}[$(gettext "不建议")]${Font} $(gettext "频繁更新 Nginx, 请确认 Nginx 有更新的必要")!"
            countdown "$(gettext "开始更新")!"
            nginx_update
            menu_pause
            ;;
        3)
            auto_update
            menu_pause
            ;;
        esac
    done
}

menu_relay_main() {
    local menu_num

    while true; do
        _relay_state_load
        relay_status_refresh
        menu_clear
        menu_title "$(gettext "中转节点管理") ${Red}[${shell_version}]${Font}"
        menu_spaced_fields \
            "$(gettext "当前模式"): $(gettext "中转节点")" \
            "$(gettext "当前语言"): $(_xray_lang_display)"
        menu_divider "$(gettext "转发信息")"
        menu_fields \
            "$(gettext "入口"): $(relay_entry_display)" \
            "$(gettext "落地"): ${relay_backend_host}:${relay_backend_port}"
        menu_divider "$(gettext "运行状态")"
        menu_fields "Nginx: ${nginx_status}" "$(gettext "连通性"): ${relay_local_connect_status}"
        menu_footer
        echo
        menu_title "$(gettext "中转节点菜单")"
        menu_blank
        menu_item 1 "$(gettext "查看信息")"
        menu_item 2 "$(gettext "修改落地目标")"
        menu_item 3 "$(gettext "修改监听端口")"
        menu_item 4 "$(gettext "服务相关")"
        menu_item 5 "$(gettext "更新向导")"
        menu_item 6 "$(gettext "测试后端连通")"
        menu_item 7 "Nginx $(gettext "错误日志")"
        menu_item 8 "$(gettext "修改语言") / Language"
        menu_item 9 "$(gettext "删除中转")"
        menu_blank
        menu_item 0 "$(gettext "退出")"
        menu_footer
        menu_read menu_num 9
        case $menu_num in
        0) exit 0 ;;
        1)
            clear
            relay_show_information
            menu_pause
            ;;
        2)
            relay_modify_target
            menu_pause
            ;;
        3)
            relay_modify_listen_port
            menu_pause
            ;;
        4) menu_relay_service ;;
        5) menu_relay_update ;;
        6)
            relay_test_backend
            menu_pause
            ;;
        7)
            clear
            show_nginx_error_log
            menu_pause
            ;;
        8) menu_action 99 ;;
        9)
            if relay_uninstall; then
                exec "${BASH:-bash}" "${idleleo}"
            fi
            ;;
        esac
    done
}

# Third-level menu entry: standalone relay node.
menu_install_relay() {
    echo
    log_echo "${Warning} ${YellowBG} $(gettext "中转节点需要一台独立服务器, 只做单目标 TCP 转发") ${Font}"
    log_echo "${Warning} ${YellowBG} $(gettext "不安装 Xray, 不终止 TLS/REALITY, 也不需要落地节点的 SSH 凭据") ${Font}"
    log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r relay_fq
    case ${relay_fq:-} in
    [yY][eE][sS] | [yY]) ;;
    *) return 0 ;;
    esac
    node_role="relay"
    tls_mode="None"
    transport_mode="None"
    install_nginx_relay
    local install_rc=$?
    if [[ ${install_rc} -eq 0 ]]; then
        exec "${BASH:-bash}" "${idleleo}"
    fi
    log_echo "${Error} ${RedBG} $(gettext "中转节点安装失败") ${Font}"
    return "${install_rc}"
}

# Relay branch of the Nginx update path: keep the managed stream config across
# the binary replacement and roll back to the previous build on failure.
nginx_update_relay() {
    local current_nginx_build_version backup_nginx_dir
    local nginx_start_failed=0

    if [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "未安装") ${Font}"
        return 1
    fi
    current_nginx_build_version=$(info_extraction nginx_build_version)
    if [[ "${nginx_build_version}" == "${current_nginx_build_version}" ]]; then
        log_echo "${OK} ${GreenBG} Nginx $(gettext "已为最新版") ${Font}"
        return 0
    fi
    _relay_state_load
    relay_validate_inputs || return 1

    log_echo "${Info} ${GreenBG} Nginx $(gettext "更新"): v${current_nginx_build_version} → v${nginx_build_version} ${Font}"
    systemctl stop nginx 2>/dev/null
    backup_nginx_dir="${nginx_dir}_backup_${current_nginx_build_version}"
    if [[ -e "${backup_nginx_dir}" || -L "${backup_nginx_dir}" ]]; then
        safe_rm "${backup_nginx_dir}" || return 1
    fi
    if ! cp -a "${nginx_dir}" "${backup_nginx_dir}"; then
        log_echo "${Error} ${RedBG} $(gettext "备份旧版") Nginx $(gettext "失败") ${Font}"
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "备份旧版") Nginx $(gettext "完成") ${Font}"
    safe_rm "${nginx_dir}" || return 1

    if ! nginx_install; then
        recover_failed_nginx_update "${backup_nginx_dir}" "${current_nginx_build_version}"
        return $?
    fi
    nginx_systemd || nginx_start_failed=1
    if [[ ${nginx_start_failed} -eq 0 ]] &&
        ! relay_stream_conf_write_current; then
        nginx_start_failed=1
    fi
    if [[ ${nginx_start_failed} -eq 0 ]] && ! nginx_relay_main_conf_prepare; then
        nginx_start_failed=1
    fi
    if [[ ${nginx_start_failed} -eq 0 ]] && ! nginx_run_config_test >/dev/null 2>&1; then
        nginx_start_failed=1
    fi
    if [[ ${nginx_start_failed} -eq 0 ]] &&
        ! activate_nginx_update "${relay_listen_port}"; then
        nginx_start_failed=1
    fi
    if [[ ${nginx_start_failed} -eq 0 ]] &&
        ! update_json_config "${xray_install_config_file}" \
            --arg nginx_build_version "${nginx_build_version}" \
            '.nginx_build_version = $nginx_build_version'; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "版本记录更新失败, 执行回滚") ${Font}"
        nginx_start_failed=1
    fi
    if [[ ${nginx_start_failed} -eq 1 ]]; then
        log_echo "${Error} ${RedBG} Nginx $(gettext "启动") $(gettext "失败")! ${Font}"
        nginx_diagnose
        recover_failed_nginx_update "${backup_nginx_dir}" "${current_nginx_build_version}"
        return $?
    fi
    safe_rm "${backup_nginx_dir}" || return 1
    judge "Nginx $(gettext "更新")"
    return 0
}

# Rewrite the managed stream fragment from stored state (used after an update
# replaced the Nginx tree).
relay_stream_conf_write_current() {
    local _tmp
    _tmp=$(mktemp) || return 1
    relay_render_stream_conf "${relay_listen_addr}" "${relay_listen_port}" \
        "${relay_backend_host}" "${relay_backend_port}" >"${_tmp}"
    if ! relay_stream_conf_install "${_tmp}"; then
        rm -f "${_tmp}"
        return 1
    fi
    rm -f "${_tmp}"
    return 0
}

install_xray_ws_tls() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install || return 1
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path. Creating nginx_conf_dir/ssl_chainpath/xray_conf_dir/
    # idleleo info + conf dirs first would pollute the manifest recorded file
    # existence and break rollback to the true source state.
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return below triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    domain_check || return 1
    transport_choose || return 1
    port_set || return 1
    ws_inbound_port_set || return 1
    grpc_inbound_port_set || return 1
    xhttp_inbound_port_set || return 1
    validate_active_ports || return 1
    port_exist_check 80 || return 1
    port_exist_check "${port}" || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    firewall_set || return 1
    ws_path_set || return 1
    grpc_path_set || return 1
    xhttp_path_set || return 1
    email_set || return 1
    UUID_set || return 1
    transport_qr
    install_config_tls_ws || return 1
    stop_service_all
    xray_install || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    nginx_exist_check || return 1
    nginx_systemd || return 1
    nginx_ssl_conf_add || return 1
    ssl_judge_and_install || return 1
    nginx_conf_add || return 1
    nginx_servers_conf_add || return 1
    xray_conf_add || return 1
    harden_config_permissions || return 1
    # Native GeoData refresh must be deployed before the service starts so the
    # first scheduled download already finds a writable asset directory.
    geodata_native_enable || return 1
    if [[ ${reality_add_nginx} == "on" ]]; then
        tls_type || return 1
    fi
    enable_process_systemd || return 1
    acme_cron_update
    auto_update || return 1
    service_restart || return 1
    # The native schedule only replaces the external updater once the service
    # is confirmed healthy; a user-written cron entry is never touched.
    geodata_legacy_cron_disable || true
    setup_auto_clean_logs || return 1
    # Clear trap before finalize — finalize handles its own restore.
    trap - RETURN
    # Propagate reinstall_finalize's exact return code to the caller:
    #   1 = deploy failed but restore succeeded
    #   2 = deploy failed and restore failed (backup retained)
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    # Success info only after final safety gate passes.
    basic_information
    vless_link_image_choice
    show_information
}

install_xray_reality() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install || return 1
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path (see install_xray_ws_tls).
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return below triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    ip_check || return 1
    port_set || return 1
    email_set || return 1
    UUID_set || return 1
    target_set || return 1
    serverNames_set || return 1
    shortIds_set || return 1
    spiderx_set || return 1
    xray_reality_add_more_choose || return 1
    validate_active_ports || return 1
    port_exist_check "${port}" || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    xray_install || return 1
    keys_set || return 1
    transport_qr
    firewall_set || return 1
    stop_service_all
    reality_balance_add_fq
    reality_nginx_add_fq || return 1
    xray_conf_add || return 1
    # 26.7.11 起 REALITY 未显式 minClientVer 会按 26.3.27 要求客户端版本,
    # 旧客户端因此握手失败；配置一生成就补齐，避免装完即不可用。
    reality_min_client_ver_repair
    install_config_reality || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    harden_config_permissions || return 1
    # Native GeoData refresh must be deployed before the service starts so the
    # first scheduled download already finds a writable asset directory.
    geodata_native_enable || return 1
    if [[ ${reality_add_nginx} == "on" ]]; then
        tls_type || return 1
    fi
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    # The native schedule only replaces the external updater once the service
    # is confirmed healthy; a user-written cron entry is never touched.
    geodata_legacy_cron_disable || true
    setup_auto_clean_logs || return 1
    trap - RETURN
    # Propagate reinstall_finalize's exact return code (1 restore-ok / 2 restore-failed).
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    basic_information
    vless_link_image_choice
    show_information
}

install_xray_ws_only() {
    is_root
    check_and_create_user_group
    check_system
    dependency_install || return 1
    # Snapshot the source configuration BEFORE create_directory modifies any
    # managed path (see install_xray_ws_tls).
    old_config_exist_check || return 1
    rxa_reconfigure_enter
    # Register RETURN trap AFTER old_config_exist_check so _reinstall_backup_dir
    # is already populated. Any non-zero return triggers a single restore.
    local _tx_backup="${_reinstall_backup_dir:-}"
    if [[ -n "${_tx_backup}" ]]; then
        # Capture _tx_backup value NOW (double quotes) so the trap fires with a
        # literal path even after the local variable is destroyed on return.
        trap "rxa_rc=\$?; reinstall_rollback_on_return \"\$rxa_rc\" \"${_tx_backup}\"; rxa_reconfigure_leave \"\$rxa_rc\"" RETURN
    else
        trap 'rxa_reconfigure_leave $?' RETURN
    fi
    basic_optimization || return 1
    create_directory || return 1
    ip_check || return 1
    transport_choose || return 1
    ws_inbound_port_set || return 1
    grpc_inbound_port_set || return 1
    xhttp_inbound_port_set || return 1
    validate_active_ports || return 1
    if is_ws_mode; then
        port_exist_check "${xport}" || return 1
    fi
    if is_grpc_mode; then
        port_exist_check "${gport}" || return 1
    fi
    if is_xhttp_mode; then
        port_exist_check "${xhttpport}" || return 1
    fi
    firewall_set || return 1
    ws_path_set || return 1
    grpc_path_set || return 1
    xhttp_path_set || return 1
    email_set || return 1
    UUID_set || return 1
    transport_qr
    # No transport encryption here: never fall back to the 0.0.0.0 wildcard.
    ws_backend_listen_addr="$(resolve_ws_backend_listen_addr)"
    install_config_ws_only || return 1
    stop_service_all
    xray_install || return 1
    update_json_config "${xray_install_config_file}" --arg xray_version "${xray_version}" '.xray_version = $xray_version'
    xray_conf_add || return 1
    harden_config_permissions || return 1
    # Native GeoData refresh must be deployed before the service starts so the
    # first scheduled download already finds a writable asset directory.
    geodata_native_enable || return 1
    enable_process_systemd || return 1
    auto_update || return 1
    service_restart || return 1
    # The native schedule only replaces the external updater once the service
    # is confirmed healthy; a user-written cron entry is never touched.
    geodata_legacy_cron_disable || true
    setup_auto_clean_logs || return 1
    trap - RETURN
    # Propagate reinstall_finalize's exact return code (1 restore-ok / 2 restore-failed).
    reinstall_finalize
    local finalize_rc=$?
    if [[ ${finalize_rc} -ne 0 ]]; then
        return "${finalize_rc}"
    fi
    rxa_reconfigure_leave 0
    basic_information
    vless_link_image_choice
    show_information
}

rxa_stage_begin() {
    local n=$1 text=$2
    if [[ -t 1 ]]; then
        printf '[%s/6] %s                 ⠹ 处理中…\n' "$n" "$text"
    else
        printf '[%s/6] %s ... 处理中\n' "$n" "$text"
    fi
}

rxa_stage_done() {
    local n=$1 text=$2 result=${3:-完成}
    printf '[%s/6] %s ... %s\n' "$n" "$text" "$result"
}

_rxa_update_title_shown=0
rxa_update_title() {
    [[ ${_rxa_update_title_shown:-0} -eq 1 ]] && return 0
    _rxa_update_title_shown=1
    log_echo "${Info} ${Green} $(gettext "正在更新 Xray 管理脚本，请勿关闭终端……") ${Font}"
}

rxa_clear_screen() {
    if [[ -t 1 && -n ${TERM:-} && ${TERM} != "dumb" && -z "${NO_COLOR:-}" ]]; then
        clear
    fi
}

rxa_release_checksum() {
    local version=$1 asset=$2 sums
    sums=$(mktemp "${TMPDIR:-/tmp}/xray-sums.XXXXXX") || return 1
    if ! curl -fsSL --connect-timeout 10 --max-time 30 --retry 2 \
        "$(shell_release_asset_url "${version}" SHA256SUMS)" -o "$sums"; then
        rm -f "$sums"
        return 1
    fi
    awk -v asset="$asset" '{name=$2; sub(/^\*/, "", name); if (name == asset) {print $1; exit}}' "$sums"
    rm -f "$sums"
}

rxa_download_release_asset() {
    local version=$1 asset=$2 dest=$3 expected=${4:-} actual release_sum
    release_sum=$(rxa_release_checksum "$version" "$asset") || return 1
    [[ "$release_sum" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ -z "$expected" || "$expected" == "$release_sum" ]] || return 1
    mkdir -p "$(dirname "$dest")" || return 1
    if ! curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 \
        "$(shell_release_asset_url "${version}" "${asset}")" -o "${dest}.tmp.$$"; then
        rm -f "${dest}.tmp.$$"
        return 1
    fi
    actual=$(sha256sum "${dest}.tmp.$$" | awk '{print $1}')
    if [[ "$actual" != "$release_sum" ]]; then
        rm -f "${dest}.tmp.$$"
        return 1
    fi
    mv -f "${dest}.tmp.$$" "$dest"
    chmod +x "$dest" 2>/dev/null || true
}

rxa_release_bundle_install() {
    local version=$1 mode=${2:-} supplied_bundle=${3:-} supplied_expected=${4:-}
    local tmp tree bundle expected bootstrap installer cleanup=1
    local -a installer_args=()
    if [[ -n "$mode" ]]; then
        installer_args+=("$mode")
    fi
    if [[ -n "$supplied_bundle" ]]; then
        bundle="$supplied_bundle"
        expected="$supplied_expected"
        cleanup=0
    else
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/xray-rill-release.XXXXXX") || return 1
        bundle="${tmp}/rill-xray-agent-xray-bundle.tar.gz"
        tree="${tmp}/tree"
        expected=$(rxa_release_checksum "$version" "rill-xray-agent-xray-bundle.tar.gz") || { rm -rf "$tmp"; return 1; }
        [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { rm -rf "$tmp"; return 1; }
        if ! rxa_download_release_asset "$version" "rill-xray-agent-xray-bundle.tar.gz" "$bundle" "$expected"; then
            rm -rf "$tmp"
            return 1
        fi
    fi
    [[ -f "$bundle" && "$expected" =~ ^[0-9a-f]{64}$ ]] || { ((cleanup)) && rm -rf "$tmp"; return 1; }
    [[ "$(sha256sum "$bundle" | awk '{print $1}')" == "$expected" ]] || { ((cleanup)) && rm -rf "$tmp"; return 1; }
    if (( ! cleanup )); then
        tmp=$(mktemp -d "${TMPDIR:-/tmp}/xray-rill-release.XXXXXX") || return 1
        tree="${tmp}/tree"
    fi
    mkdir -p "$tree"
    tar -xzf "$bundle" -C "$tree" --no-same-owner --no-same-permissions || { rm -rf "$tmp"; return 1; }
    bootstrap="${tree}/scripts/rill_xray_agent_bootstrap.sh"
    installer="${tree}/scripts/rill_xray_agent_install.sh"
    local member
    for member in "$tree"/*; do
        case "$(basename "$member")" in
            scripts|systemd|rill_payload) ;;
            *) rm -rf "$tmp"; return 1 ;;
        esac
    done
    if [[ -f "$bootstrap" ]]; then
        RILL_XRAY_AGENT_BUNDLE_FILE="$bundle" \
        RILL_XRAY_AGENT_BUNDLE_SHA256="$expected" \
            bash "$bootstrap" "${installer_args[@]}"
    elif [[ -f "$installer" ]] && bash -n "$installer"; then
        # Compatibility with older immutable bundles that predate the wrapper.
        # The outer path has already checked the Release SHA-256 and extracted
        # the archive safely; the bundled installer still enforces its own
        # root/installed-component and upgrade-mode checks.
        bash "$installer" "${installer_args[@]}"
    else
        rm -rf "$tmp"
        return 1
    fi
    local rc=$?
    rm -rf "$tmp"
    return "$rc"
}

rxa_rill_installed() {
    # The executable payload is the durable installed-component marker. A
    # leftover config/state tree (or a leftover unit file) is not enough.
    [[ -x "$(rxa_root /opt/rill-xray-agent/bin/rill-xray-agent)" ]]
}

core_candidate_guard() {
    local candidate=${1:-} candidate_shell_version
    CORE_CANDIDATE_GUARD_STAGE=""
    [[ -f "${candidate}" ]] || { CORE_CANDIDATE_GUARD_STAGE=path; return 1; }
    bash -n "${candidate}" 2>/dev/null || { CORE_CANDIDATE_GUARD_STAGE=syntax; return 1; }
    candidate_shell_version=$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${candidate}" | head -n1)
    [[ "${candidate_shell_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { CORE_CANDIDATE_GUARD_STAGE=shell-version; return 1; }
    grep -q '^xray_install_release()' "${candidate}" || { CORE_CANDIDATE_GUARD_STAGE=installer-anchor; return 1; }
    grep -q '^read_version()' "${candidate}" || { CORE_CANDIDATE_GUARD_STAGE=version-anchor; return 1; }
    grep -q '^xray_update()' "${candidate}" || { CORE_CANDIDATE_GUARD_STAGE=update-anchor; return 1; }
    return 0
}

candidate_guard() {
    local candidate=${1:-}
    core_candidate_guard "${candidate}" || return 1
    # Rill is a plug-in: its stronger compatibility guard remains active only
    # when the component is actually installed on the host.
    if rxa_rill_installed; then
        rxa_candidate_guard "${candidate}" || return 1
    fi
    return 0
}

rxa_reload_manager() {
    local manager="$(rxa_agent_dir)/scripts/rill_xray_agent_manager.sh"
    [[ -r "${manager}" ]] || return 1
    # shellcheck disable=SC1090
    source "${manager}"
}

rxa_auto_confirmation_is_revoked() {
    local policy
    declare -F rxa_root_policy >/dev/null 2>&1 || return 1
    policy=$(rxa_root_policy status 2>/dev/null) || return 1
    jq -e '.policy.autoConfirmed == false' <<<"${policy}" >/dev/null 2>&1
}

rxa_sync_release_helpers() {
    local version=$1 dir file url any=0
    dir=$(mktemp -d "${TMPDIR:-/tmp}/xray-helper-candidates.XXXXXX") || return 1
    for file in fail2ban_manager.sh traffic_blocker.sh file_manager.sh auto_update.sh ssl_update.sh geo_update.sh; do
        [[ -f "${scripts_dir}/${file}" ]] || continue
        any=1
        url=$(shell_release_raw_url "$version" "scripts/${file}")
        if ! download_script_file "$url" "${dir}/${file}"; then
            rm -rf "$dir"
            return 1
        fi
    done
    if ((any)); then
        for file in fail2ban_manager.sh traffic_blocker.sh file_manager.sh auto_update.sh ssl_update.sh geo_update.sh; do
            if [[ -f "${dir}/${file}" ]] && ! mv -f "${dir}/${file}" "${scripts_dir}/${file}"; then
                rm -rf "$dir"
                return 1
            fi
        done
    fi
    rm -rf "$dir"
    # Refresh the optional read-only stats helper together with the release.
    # Failure is non-fatal: readout stays on the previous verified copy.
    xray_stats_script_ensure 1 >/dev/null 2>&1 || true
    return 0
}

rxa_reconcile_release() {
    local version=$1 installed=0 managed_file="${idleleo_dir}/release-managed.version"
    local bundle_tmp bundle expected mode
    rxa_update_title
    rxa_stage_begin 2 "检测 Rill Xray AI 运维助手"
    if rxa_rill_installed; then
        installed=1
        rxa_stage_done 2 "检测 Rill Xray AI 运维助手" "已安装"
    else
        rxa_stage_done 2 "检测 Rill Xray AI 运维助手" "— 未安装"
    fi
    rxa_stage_begin 3 "下载并校验 Rill 更新包"
    if ((installed)); then
        bundle_tmp=$(mktemp -d "${TMPDIR:-/tmp}/xray-rill-release.XXXXXX") || return 1
        bundle="${bundle_tmp}/rill-xray-agent-xray-bundle.tar.gz"
        expected=$(rxa_release_checksum "$version" "rill-xray-agent-xray-bundle.tar.gz")
        if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]] ||
            ! rxa_download_release_asset "$version" "rill-xray-agent-xray-bundle.tar.gz" "$bundle" "$expected"; then
            rm -rf "$bundle_tmp"
            rxa_stage_done 3 "下载并校验 Rill 更新包" "✗ 失败"
            return 1
        fi
        rxa_stage_done 3 "下载并校验 Rill 更新包" "完成"
        rxa_stage_begin 4 "更新 Rill 核心组件"
        if ! rxa_release_bundle_install "$version" --upgrade "$bundle" "$expected"; then
            rm -rf "$bundle_tmp"
            rxa_stage_done 4 "更新 Rill 核心组件" "✗ 失败"
            return 1
        fi
        rm -rf "$bundle_tmp"
        rxa_stage_done 4 "更新 Rill 核心组件" "完成"
        rxa_stage_begin 5 "恢复 AI 工作状态"
        if ! rxa_reload_manager; then
            rxa_stage_done 5 "恢复 AI 工作状态" "✗ 失败"
            return 1
        fi
        mode=$(rxa_get mode 2>/dev/null || true)
        if [[ -z "$mode" ]] || ! rxa_mode_state_matches_target "$mode" ||
            ! rxa_auto_confirmation_is_revoked; then
            rxa_stage_done 5 "恢复 AI 工作状态" "✗ 失败"
            return 1
        fi
        rxa_stage_done 5 "恢复 AI 工作状态" "已确认 ${mode}"
    else
        rxa_stage_done 3 "下载并校验 Rill 更新包" "— 跳过"
        rxa_stage_done 4 "更新 Rill 核心组件" "— 跳过"
        rxa_stage_done 5 "恢复 AI 工作状态" "— 跳过"
    fi
    rxa_stage_begin 6 "运行升级后健康检查"
    if ((installed)) && declare -F rxa_dispatch >/dev/null 2>&1; then
        rxa_dispatch verify >/dev/null 2>&1 || { rxa_stage_done 6 "运行升级后健康检查" "✗ 失败"; return 1; }
    fi
    rxa_stage_done 6 "运行升级后健康检查" "✓"
    mkdir -p "$(dirname "$managed_file")" || return 1
    printf '%s\n' "$version" >"${managed_file}.tmp.$$" || return 1
    mv -f "${managed_file}.tmp.$$" "$managed_file" || return 1
    return 0
}

rxa_reconcile_release_if_needed() {
    local managed_file="${idleleo_dir}/release-managed.version"
    [[ -f "${managed_file}" ]] &&
        [[ "$(cat "${managed_file}" 2>/dev/null)" == "${shell_version}" ]] && return 0
    # This is deliberately called only from the normal mutable startup path.
    # Pure read-only dispatch exits before reaching it.
    # Shell-owned helpers are managed by the Xray Release independently of
    # whether Rill is installed. Rill detection remains inside the Rill stage.
    rxa_sync_release_helpers "${shell_version}" || return 1
    rxa_reconcile_release "${shell_version}"
}

rxa_download_main_candidate() {
    local candidate=${1:-}
    RILL_UPDATE_CANDIDATE_ERROR=""
    [[ -n ${candidate} ]] || { RILL_UPDATE_CANDIDATE_ERROR="path"; return 1; }
    if [[ ! "${shell_online_version:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        RILL_UPDATE_CANDIDATE_ERROR="metadata-version"
        rm -f "${candidate}"
        return 1
    fi
    if release_sha_contract_required "${shell_online_version}" &&
        [[ ! "${shell_release_sha256:-}" =~ ^[0-9a-f]{64}$ ]]; then
        RILL_UPDATE_CANDIDATE_ERROR="metadata-sha"
        rm -f "${candidate}"
        return 1
    fi
    rm -f "${candidate}"
    if ! download_script_file "$(shell_release_asset_url "${shell_online_version}" install.sh)" "${candidate}"; then
        RILL_UPDATE_CANDIDATE_ERROR="download"
        rm -f "${candidate}"
        return 1
    fi
    if [[ -n "${shell_release_sha256:-}" ]]; then
        local candidate_sha
        candidate_sha=$(sha256sum "${candidate}" | awk '{print $1}')
        if [[ "${candidate_sha}" != "${shell_release_sha256}" ]]; then
            RILL_UPDATE_CANDIDATE_ERROR="sha256"
            rm -f "${candidate}"
            return 1
        fi
    fi
    if ! command -v candidate_guard >/dev/null 2>&1 ||
       ! candidate_guard "${candidate}"; then
        if [[ -n "${CORE_CANDIDATE_GUARD_STAGE:-}" ]]; then
            RILL_UPDATE_CANDIDATE_ERROR="core-guard:${CORE_CANDIDATE_GUARD_STAGE}:1"
        else
            RILL_UPDATE_CANDIDATE_ERROR="guard:${RILL_CANDIDATE_GUARD_STAGE:-unknown}:${RILL_CANDIDATE_GUARD_RC:-?}"
        fi
        rm -f "${candidate}"
        return 1
    fi
    return 0
}

rxa_replace_main_candidate() {
    # Replace only after the downloaded candidate passed the semantic guard.
    # The backup remains available until the installed bytes pass the same
    # check, so every update entry has identical rollback behavior.
    local candidate=${1:-} destination=${2:-} backup=""
    RILL_UPDATE_CANDIDATE_ERROR=""
    [[ -f ${candidate} && -n ${destination} ]] || {
        RILL_UPDATE_CANDIDATE_ERROR="path"
        return 1
    }
    if [[ -f ${destination} ]]; then
        backup="${destination}.bak.$$"
        if ! cp -a "${destination}" "${backup}"; then
            RILL_UPDATE_CANDIDATE_ERROR="backup"
            rm -f "${candidate}" "${backup}"
            return 1
        fi
    fi
    if ! mv -f "${candidate}" "${destination}"; then
        RILL_UPDATE_CANDIDATE_ERROR="replace"
        rm -f "${candidate}" "${backup}"
        return 1
    fi
    if ! bash -n "${destination}" 2>/dev/null ||
       ! candidate_guard "${destination}"; then
        if [[ -n "${CORE_CANDIDATE_GUARD_STAGE:-}" ]]; then
            RILL_UPDATE_CANDIDATE_ERROR="core-postcheck:${CORE_CANDIDATE_GUARD_STAGE}:1"
        else
            RILL_UPDATE_CANDIDATE_ERROR="postcheck:${RILL_CANDIDATE_GUARD_STAGE:-unknown}:${RILL_CANDIDATE_GUARD_RC:-?}"
        fi
        if [[ -n ${backup} && -f ${backup} ]]; then
            if ! mv -f "${backup}" "${destination}"; then
                RILL_UPDATE_CANDIDATE_ERROR="rollback"
                return 1
            fi
        elif ! rm -f "${destination}"; then
            RILL_UPDATE_CANDIDATE_ERROR="rollback"
            return 1
        fi
        return 1
    fi
    rm -f "${backup}"
    return 0
}

rxa_log_candidate_failure() {
    local err="${RILL_UPDATE_CANDIDATE_ERROR:-unknown}"
    local kind="${err%%:*}" rest="" stage="" prc=""
    if [[ "${err}" == *:* ]]; then
        rest="${err#*:}"
        stage="${rest%%:*}"
        prc="${rest#*:}"
    fi
    case ${kind} in
        core-guard|core-postcheck)
            log_echo "${Error} ${RedBG} Xray Core $(gettext "候选校验失败, 已阻止脚本更新") ${Font}"
            ;;
        guard)
            log_echo "${Error} ${RedBG} Rill Xray Agent $(gettext "集成校验失败, 已阻止脚本更新") ${Font}"
            ;;
        postcheck)
            log_echo "${Error} ${RedBG} Rill Xray Agent $(gettext "替换后校验失败, 已回滚") ${Font}"
            ;;
        rollback)
            log_echo "${Error} ${RedBG} Rill Xray Agent $(gettext "替换后校验失败, 已阻止启动") ${Font}"
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "脚本更新失败")! ${Font}"
            ;;
    esac
    if [[ "${kind}" == "metadata-version" || "${kind}" == "metadata-sha" ]]; then
        log_echo "${Error} ${RedBG} Shell Release metadata unavailable or invalid; candidate download refused ${Font}"
    fi
    # Diagnostics (P1): report the guard stage and probe rc so a real Bootstrap
    # failure is locatable. No candidate content, secrets, UUIDs, tokens or
    # link data are ever included here.
    if [[ ${kind} == "core-guard" || ${kind} == "core-postcheck" ||
          ${kind} == "guard" || ${kind} == "postcheck" ]]; then
        log_echo "${Info} ${YellowBG} Rill $(gettext "校验详情"): $(gettext "阶段")=${stage:-unknown} rc=${prc:-?} candidate-version=${RILL_CANDIDATE_GUARD_VERSION:-?} $(gettext "当前版本")=${shell_version:-?} $(gettext "来源")=${main_remote_url} ${Font}"
    fi
}

rxa_refresh_main_script() {
    local destination=${1:-} candidate
    candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
    if ! rxa_download_main_candidate "${candidate}"; then
        rxa_log_candidate_failure
        return 1
    fi
    if ! rxa_replace_main_candidate "${candidate}" "${destination}"; then
        rxa_log_candidate_failure
        return 1
    fi
    return 0
}

# Historical template defect (335f4d8c): the generated xhttp location shipped
# with a commented `#client_max_body_size 0;`, so Nginx used its 1m default and
# stream-one request bodies above ~1MB failed with 413. `-u` only refreshes the
# script and its helpers; it never rewrites 00-xray.conf. Tell the operator how
# to fix an existing deployment instead of failing silently.
rxa_warn_legacy_xhttp_limit() {
    [[ "${tls_mode:-}" == "TLS" ]] || return 0
    is_xhttp_mode || return 0
    [[ -r "${nginx_conf}" ]] || return 0
    grep -qE '^[[:space:]]*grpc_pass[[:space:]]+grpc://xray-xhttp-server;' "${nginx_conf}" || return 0
    grep -qE '^[[:space:]]*#[[:space:]]*client_max_body_size[[:space:]]+0;' "${nginx_conf}" || return 0
    log_echo "${Warning} ${YellowBG} $(gettext "检测到旧版 Nginx 模板：xHTTP 上行超过 1MB 会被 Nginx 拒绝 (413)。更新脚本不会重建 Nginx 配置，请重新运行安装脚本重建，或手工在 xHTTP location 放开 client_max_body_size 0;") ${Font}"
}

_update_sh_impl() {
    local downloaded_shell_version _candidate
    _rxa_update_title_shown=0
    set_shell_release_urls "${shell_online_version}"
    ol_version=${shell_online_version}
    echo "${ol_version}" >"${shell_version_tmp}"
    [[ -z ${ol_version} ]] && log_echo "${Error} ${RedBG} $(gettext "检测最新版本失败")! ${Font}" && return 1
    echo "${shell_version}" >>"${shell_version_tmp}"
    newest_version=$(sort -rV "${shell_version_tmp}" | head -1)
    oldest_version=$(sort -V "${shell_version_tmp}" | head -1)
    version_difference="$(version_series_difference "${newest_version}" "${oldest_version}")"
    if [[ ${shell_version} != ${newest_version} ]]; then
        rxa_update_title
        rxa_stage_begin 1 "下载并校验新版主脚本"
        if [[ ${auto_update} != "YES" ]]; then
            echo
            log_echo "${GreenBG} $(gettext "新版本")(${newest_version}) $(gettext "更新内容"): ${Font}"
            log_echo "${Green} $(check_version shell_upgrade_details) ${Font}"
            if [[ ${version_difference} == 1 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "存在新版本, 但版本变化较大, 可能存在不兼容情况, 是否更新") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
            else
                echo
                log_echo "${GreenBG} $(gettext "存在新版本, 是否更新") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
            fi
            update_confirm=""
            if [[ "${update_assume_yes:-off}" == "YES" ]]; then
                if [[ ${version_difference} == 1 && "${update_allow_major:-off}" != "YES" ]]; then
                    # --yes is a same-minor convenience only. A cross-minor
                    # update needs the separate --allow-major switch; in a
                    # terminal the user can still answer the prompt explicitly.
                    if [[ ! -t 0 ]]; then
                        log_echo "${Error} ${RedBG} $(gettext "未升级")：$(gettext "跨 minor 更新需要显式 --allow-major；--yes 仅自动确认同一 minor") ${Font}"
                        return 1
                    fi
                    log_echo "${Warning} ${YellowBG} $(gettext "跨 minor 更新未被 --yes 自动确认；请确认或改用 --allow-major") ${Font}"
                else
                    if [[ ${version_difference} == 1 ]]; then
                        log_echo "${Info} $(gettext "已按 --yes --allow-major 自动确认跨 minor 更新") ${Font}"
                    else
                        log_echo "${Info} $(gettext "已按 --yes 自动确认更新") ${Font}"
                    fi
                    update_confirm="YES"
                fi
            elif [[ ! -t 0 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "未升级")：$(gettext "当前输入不是交互终端；自动化请使用 --yes") ${Font}"
                return 1
            fi
            if [[ -z "${update_confirm}" ]]; then
                if ! read -r update_confirm; then
                    log_echo "${Error} ${RedBG} $(gettext "未升级")：$(gettext "无法读取确认输入") ${Font}"
                    return 1
                fi
            fi
        else
            [[ -z ${ol_version} ]] && echo "$(gettext "检测最新版本失败")!" >>"${log_file}" && return 1
            [[ ${version_difference} == 1 ]] && echo "$(gettext "脚本版本差别过大, 跳过更新")!" >>"${log_file}" && return 1
            update_confirm="YES"
        fi
        case $update_confirm in
        [yY][eE][sS] | [yY])
            if ! rxa_entry_is_go_managed; then
                [[ -L "${idleleo_commend_file}" ]] && rm -f "${idleleo_commend_file}"
            fi
            _candidate="${idleleo_dir}/install.sh.rxa-candidate.$$"
            if ! rxa_download_main_candidate "${_candidate}"; then
                rxa_set_bash_entry
                [[ ${auto_update} == "YES" ]] && echo "$(gettext "脚本更新失败")!" >>"${log_file}"
                [[ ${auto_update} != "YES" ]] && rxa_log_candidate_failure
                return 1
            fi
            downloaded_shell_version=$(
                grep -E '^shell_version=' "${_candidate}" |
                head -n 1 |
                awk -F'=|"' '{print $3}'
            )
            if [[ -z "${downloaded_shell_version}" ||
                  "${downloaded_shell_version}" != "${newest_version}" ]]; then
                rm -f "${_candidate}"
                log_echo "${Error} ${RedBG} $(gettext "下载脚本版本校验失败") ${Font}"
                rxa_set_bash_entry
                return 1
            fi
            if ! rxa_replace_main_candidate "${_candidate}" "${idleleo}"; then
                rxa_set_bash_entry
                rxa_log_candidate_failure
                return 1
            fi
            rxa_set_bash_entry || return 1
            rxa_stage_done 1 "下载并校验新版主脚本" "✓"
            if [[ -f "${xray_install_config_file}" ]]; then
                update_json_config "${xray_install_config_file}" \
                    --arg shell_version "${downloaded_shell_version}" \
                    '.shell_version = $shell_version' || return 1
            fi
            shell_version="${downloaded_shell_version}"
            set_shell_release_urls "${shell_version}"
            if ! rxa_sync_release_helpers "${shell_version}"; then
                log_echo "${Error} ${RedBG} Shell helper 同版本同步失败；主脚本已更新，下次将重试 ${Font}"
                return 1
            fi
            if ! rxa_reconcile_release "${shell_version}"; then
                log_echo "${Error} ${RedBG} 主脚本已更新，但 Rill 同步失败；下次运行将自动重试 Rill 同步 ${Font}"
                return 1
            fi
            # The startup hook ran before install.sh was replaced, and this
            # process still holds the old function definitions. Run the newly
            # installed script's own migration so an update repairs a legacy
            # node without waiting for the next launch. The command is a
            # root-only offline mutation and fails closed (old cron retained).
            if [[ "$(id -u)" == "0" ]] && ! is_relay_role && {
                [[ -n "$(geodata_legacy_cron_lines 2>/dev/null || true)" ]] ||
                    [[ -d "${local_bin}/share/xray" && ! -L "${local_bin}/share/xray" ]]
            }; then
                if bash "${idleleo}" --internal-geodata-migrate-legacy; then
                    log_echo "${OK} ${GreenBG} $(gettext "GeoData 已自动迁移为 Xray 原生刷新") ${Font}"
                else
                    log_echo "${Warning} ${YellowBG} $(gettext "GeoData 自动迁移未完成, 旧刷新任务已保留; 下次启动会自动重试") ${Font}"
                fi
            fi
            rxa_clear_screen
            log_echo "${OK} ${GreenBG} $(gettext "更新") $(gettext "完成") ${Font}"
            rxa_warn_legacy_xhttp_limit
            [[ ${version_difference} == 1 ]] && log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 若服务无法正常运行请卸载后重装")! ${Font}"
            # Phase 03: a manual TTY update may discover the Go bridge. Run the
            # freshly installed script's own offer so this same run is wired
            # through the maintenance version instead of the old functions.
            if [[ "${bridge_manual_invocation:-off}" == "on" ]] && [[ -t 0 ]] &&
                [[ ${auto_update} != "YES" ]] && [[ "${update_assume_yes:-off}" != "YES" ]]; then
                bash "${idleleo}" --internal-bridge-offer
                return 0
            fi
            return 0
            ;;
        *)
            log_echo "${Warning} ${YellowBG} $(gettext "已取消更新，未升级") ${Font}"
            return 0
            ;;
        esac
    else
        if [[ ! -f "${idleleo_dir}/release-managed.version" ||
              "$(cat "${idleleo_dir}/release-managed.version" 2>/dev/null)" != "${shell_version}" ]]; then
            rxa_update_title
        fi
        rxa_stage_done 1 "下载并校验新版主脚本" "✓ 已是 v${shell_version}"
        if [[ ! -f "${idleleo_dir}/release-managed.version" || "$(cat "${idleleo_dir}/release-managed.version" 2>/dev/null)" != "${shell_version}" ]]; then
            rxa_sync_release_helpers "${shell_version}" || return 1
            rxa_reconcile_release "${shell_version}" || return 1
        fi
        rxa_clear_screen
        log_echo "${OK} ${GreenBG} $(gettext "当前已经是最新版本") ${Font}"
        rxa_warn_legacy_xhttp_limit
        if [[ "${bridge_manual_invocation:-off}" == "on" ]] && [[ -t 0 ]] && [[ ${auto_update} != "YES" ]]; then
            bridge_migration_offer || true
        fi
    fi
    return 0

}

update_sh() {
    with_update_lock _update_sh_impl "$@"
}

# Phase 03 bridge discovery. This is the ONLY Bash path that may offer the Go
# migration: an explicit manual check (-u) in a real TTY, never auto_update,
# never --yes, never a pipe. It performs no network request and changes
# nothing unless the operator explicitly answers yes.
bridge_asset_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) printf 'amd64' ;;
        aarch64 | arm64) printf 'arm64' ;;
        *) return 1 ;;
    esac
}

# Fixed production manifest origin. Overridable only for container E2E; the
# default must stay the immutable API copy, never a mutable branch artifact.
bridge_manifest_url() {
    local arch
    arch=$(bridge_asset_arch) || return 1
    printf '%s' "${IDLELEO_BRIDGE_MANIFEST_URL:-https://raw.githubusercontent.com/hello-yunshu/Xray_bash_onekey_api/main/bridge/asset-linux-${arch}.json}"
}

# Fetch and validate the production manifest into the local cache. Failures are
# deliberately silent (the offer then reports "尚未发布"): a missing manifest
# must never block normal Bash operation or leave a partial file behind.
bridge_install_manifest() {
    local manifest="${IDLELEO_BRIDGE_MANIFEST:-/etc/idleleo/bridge/asset.json}"
    local arch url tmpdir rc=0
    [[ -r "${manifest}" ]] && return 0
    arch=$(bridge_asset_arch) || return 1
    url=$(bridge_manifest_url) || return 1
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-bridge-manifest.XXXXXX") || return 1
    if ! curl -fsSL --proto '=https,file' --connect-timeout 10 --max-time 60 \
        -o "${tmpdir}/asset.json" "${url}"; then
        rc=1
    fi
    if [[ ${rc} -eq 0 ]]; then
        python3 - "${tmpdir}/asset.json" "${arch}" <<'PY' || rc=1
import json, re, sys
path, arch = sys.argv[1:3]
doc = json.load(open(path))
if doc.get("schemaVersion") != 1:
    raise SystemExit("schemaVersion")
if doc.get("arch") != arch:
    raise SystemExit("arch mismatch")
for key in ("url", "recoveryUrl"):
    value = doc.get(key) or ""
    if not (value.startswith("https://") or value.startswith("file://")):
        raise SystemExit("%s scheme" % key)
for key in ("sha256", "recoverySha256"):
    if not re.fullmatch(r"[0-9a-f]{64}", doc.get(key) or ""):
        raise SystemExit(key)
PY
    fi
    if [[ ${rc} -ne 0 ]]; then
        rm -rf "${tmpdir}"
        return 0
    fi
    mkdir -p "$(dirname "${manifest}")" || { rm -rf "${tmpdir}"; return 1; }
    chmod 0700 "$(dirname "${manifest}")" 2>/dev/null || true
    if ! cp "${tmpdir}/asset.json" "${manifest}.tmp.$$" ||
        ! chmod 0600 "${manifest}.tmp.$$" ||
        ! mv -f "${manifest}.tmp.$$" "${manifest}"; then
        rm -f "${manifest}.tmp.$$"
        rm -rf "${tmpdir}"
        return 1
    fi
    rm -rf "${tmpdir}"
    return 0
}

# A completed Bridge migration owns /usr/bin/idleleo. Refreshing the Bash
# script (manual -u or the retained auto_update cron) must not re-point the
# entry back to Bash: that would silently undo the migration.
rxa_entry_is_go_managed() {
    local entry="${idleleo_commend_file:-/usr/bin/idleleo}"
    if [[ -L "${entry}" ]] && [[ "$(readlink -f "${entry}" 2>/dev/null)" == "/opt/idleleo/bin/idleleo" ]]; then
        return 0
    fi
    grep -Eq '"state"[[:space:]]*:[[:space:]]*"COMMITTED"' \
        "${IDLELEO_BRIDGE_JOURNAL:-/var/lib/idleleo/bridge/journal.json}" 2>/dev/null
}

rxa_set_bash_entry() {
    if rxa_entry_is_go_managed; then
        return 0
    fi
    ln -sf "${idleleo}" "${idleleo_commend_file}"
}

# A full reinstall (or a wiped install directory) re-runs the bootstrap and
# used to rebuild /usr/bin/idleleo as a Bash symlink. A committed migration
# must survive that: restore the Go entry instead. Return 0 when the entry
# was claimed, 1 when the caller may create the Bash link.
rxa_keep_committed_entry() {
    local go_entry="${IDLELEO_GO_ENTRY:-/opt/idleleo/bin/idleleo}"
    rxa_entry_is_go_managed || return 1
    if [[ -x "${go_entry}" ]]; then
        ln -sfn "${go_entry}" "${idleleo_commend_file}"
        log_echo "${Info} ${GreenBG} $(gettext "检测到已提交的 Go 迁移，保留 Go 入口") ${Font}"
    else
        log_echo "${Warning} ${YellowBG} $(gettext "检测到已提交的 Go 迁移但 Go 入口缺失，未创建 Bash 入口；请运行 idleleo-recover") ${Font}"
    fi
    return 0
}

bridge_migration_offer() {
    local bridge_manifest="${IDLELEO_BRIDGE_MANIFEST:-/etc/idleleo/bridge/asset.json}"
    local go_entry="/opt/idleleo/bin/idleleo"
    local entry_file="${idleleo_commend_file:-/usr/bin/idleleo}"
    [[ "${bridge_manual_invocation:-off}" == "on" ]] || return 0
    [[ "${auto_update:-}" != "YES" ]] || return 0
    [[ "${update_assume_yes:-off}" != "YES" ]] || return 0
    [[ -t 0 ]] || return 0
    if [[ -x "${go_entry}" ]] && [[ "$(readlink -f "${entry_file}" 2>/dev/null)" == "${go_entry}" ]]; then
        return 0
    fi
    # The manifest is a published artifact, not a test fixture: fetch it from the
    # fixed API URL only after every non-interactive guard has passed.
    bridge_install_manifest || true
    if [[ ! -r "${bridge_manifest}" ]]; then
        echo "$(gettext "Go 迁移资产尚未发布，跳过（未下载、未改动")"
        return 0
    fi
    local asset_url="" asset_sha="" rec_url="" rec_sha=""
    asset_url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("url","") or "")' "${bridge_manifest}" 2>/dev/null) || asset_url=""
    asset_sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("sha256","") or "")' "${bridge_manifest}" 2>/dev/null) || asset_sha=""
    rec_url=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("recoveryUrl","") or "")' "${bridge_manifest}" 2>/dev/null) || rec_url=""
    rec_sha=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("recoverySha256","") or "")' "${bridge_manifest}" 2>/dev/null) || rec_sha=""
    if [[ -z "${asset_url}" || -z "${asset_sha}" || -z "${rec_url}" || -z "${rec_sha}" ]]; then
        echo "$(gettext "Go 迁移清单不完整，跳过（未下载、未改动")"
        return 0
    fi
    if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
        if [[ "${IDLELEO_ALLOW_SYSTEM_WRITES:-}" != "I_ACCEPT_CONTAINER_ONLY" ]]; then
            echo "$(gettext "未设置 IDLELEO_ALLOW_SYSTEM_WRITES，拒绝切换；未下载、未改动")"
            return 0
        fi
    else
        # Real host root: the migration must be possible, but it has to leave an
        # auditable record before any asset is downloaded or the entry switches.
        mkdir -p /var/log/idleleo 2>/dev/null || true
        if ! printf '%s mode=host uid=%s pid=%s argv=%q\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(id -u)" "$$" "install.sh bridge-offer" \
            >>/var/log/idleleo/system-writes.log 2>/dev/null; then
            echo "$(gettext "无法写入迁移审计日志，拒绝切换；未下载、未改动")"
            return 0
        fi
        chmod 0600 /var/log/idleleo/system-writes.log 2>/dev/null || true
    fi
    echo "$(gettext "检测到可迁移的 Bash 安装。迁移只切换入口并保留原配置/证书/用户；是否继续") [y/${Red}N${Font}]? "
    local answer=""
    if ! read -r answer; then
        return 0
    fi
    case "${answer}" in
    [yY][eE][sS] | [yY]) ;;
    *)
        echo "$(gettext "已取消 Go 迁移，未下载、未改动")"
        return 0
        ;;
    esac
    local tmpdir=""
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-bridge.XXXXXX") || return 1
    local _rc=0
    if ! curl -fsSL --proto '=https,file' --connect-timeout 10 --max-time 180 -o "${tmpdir}/idleleo" "${asset_url}"; then
        _rc=1
    fi
    if ! curl -fsSL --proto '=https,file' --connect-timeout 10 --max-time 180 -o "${tmpdir}/idleleo-recover" "${rec_url}"; then
        _rc=1
    fi
    if [[ ${_rc} -eq 0 ]] && ! echo "${asset_sha}  ${tmpdir}/idleleo" | sha256sum -c - >/dev/null 2>&1; then
        _rc=1
    fi
    if [[ ${_rc} -eq 0 ]] && ! echo "${rec_sha}  ${tmpdir}/idleleo-recover" | sha256sum -c - >/dev/null 2>&1; then
        _rc=1
    fi
    if [[ ${_rc} -eq 0 ]] && [[ "$(head -c 4 "${tmpdir}/idleleo" 2>/dev/null | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]]; then
        _rc=1
    fi
    if [[ ${_rc} -ne 0 ]]; then
        rm -rf "${tmpdir}"
        echo "$(gettext "Go 候选下载或校验失败，未改动")"
        return 1
    fi
    chmod +x "${tmpdir}/idleleo" "${tmpdir}/idleleo-recover"
    # Full change summary before anything is staged: version, mode, users,
    # certificates, custom fragments, cron takeover, Rill and degradations.
    "${tmpdir}/idleleo" bridge audit --summary || true
    if ! "${tmpdir}/idleleo" bridge prepare --candidate "${tmpdir}/idleleo" --recovery "${tmpdir}/idleleo-recover" --acknowledge-custom --container; then
        "${tmpdir}/idleleo" bridge recover --container >/dev/null 2>&1 || true
        rm -rf "${tmpdir}"
        echo "$(gettext "Go 迁移预检准备失败，未切换")"
        return 1
    fi
    local xray_bin="" nginx_bin=""
    command -v xray >/dev/null 2>&1 && xray_bin="$(command -v xray)"
    command -v nginx >/dev/null 2>&1 && nginx_bin="$(command -v nginx)"
    local validate_args=("bridge" "validate" "--container")
    [[ -n "${xray_bin}" ]] && validate_args+=(--xray "${xray_bin}")
    [[ -n "${nginx_bin}" ]] && validate_args+=(--nginx "${nginx_bin}")
    if ! "${tmpdir}/idleleo" "${validate_args[@]}"; then
        "${tmpdir}/idleleo" bridge recover --container >/dev/null 2>&1 || true
        rm -rf "${tmpdir}"
        echo "$(gettext "xray -test / nginx -t 预检失败，未切换")"
        return 1
    fi
    echo "$(gettext "预检通过。切换后入口为 Go 管理器，旧 Bash 仅保留为恢复备份；是否切换") [y/${Red}N${Font}]? "
    answer=""
    if ! read -r answer; then
        "${tmpdir}/idleleo" bridge recover --container >/dev/null 2>&1 || true
        rm -rf "${tmpdir}"
        return 0
    fi
    case "${answer}" in
    [yY][eE][sS] | [yY]) ;;
    *)
        "${tmpdir}/idleleo" bridge recover --container >/dev/null 2>&1 || true
        rm -rf "${tmpdir}"
        echo "$(gettext "已取消切换，候选已丢弃")"
        return 0
        ;;
    esac
    if ! "${tmpdir}/idleleo" bridge activate --container; then
        "${tmpdir}/idleleo" bridge recover --container >/dev/null 2>&1 || true
        rm -rf "${tmpdir}"
        echo "$(gettext "切换失败，已按恢复流程处理")"
        return 1
    fi
    rm -rf "${tmpdir}"
    echo "$(gettext "Go 迁移已提交；旧 Bash 已保留为 /opt/idleleo/recovery/legacy-install.sh")"
    echo "$(gettext "Go 原生定时任务已接管旧 cron；auto-update 与 cert-renew 为明确降级项（见 schedule status）")"
    /usr/bin/idleleo schedule status 2>/dev/null | sed 's/^/  /' || true
    return 0
}

# The managed script is the authority for the installed Shell version. A stale
# install_config value (e.g. after a failed metadata write or an older API copy)
# must not be used for update decisions; repair it during startup.
sync_shell_version_config_with_actual() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    has_jq_binary || return 0
    local actual recorded
    actual=$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${idleleo}" 2>/dev/null | head -n 1)
    [[ -n "${actual}" ]] || return 0
    recorded=$(jq -r '.shell_version // empty' "${xray_install_config_file}" 2>/dev/null) || return 0
    [[ "${recorded}" == "${actual}" ]] && return 0
    if update_json_config "${xray_install_config_file}" \
        --arg shell_version "${actual}" '.shell_version = $shell_version'; then
        log_echo "${Info} ${Green} $(gettext "已修正") install_config.shell_version: ${recorded:-empty} → ${actual} ${Font}" 2>/dev/null || true
    else
        log_echo "${Warning} ${YellowBG} $(gettext "修正") install_config.shell_version $(gettext "失败，保留原文件") ${Font}" 2>/dev/null || true
    fi
    return 0
}

check_file_integrity() {
    if [[ ! -L "${idleleo_commend_file}" ]] && [[ ! -f "${idleleo}" ]]; then
        check_system
        # P0-2: bootstrap required dependency (bc/jq) failure must hard-stop
        # BEFORE the candidate guard / download path — never masked or folded
        # into a later "guard" failure. Error text names the failing dependency.
        if ! pkg_install "bc,jq"; then
            log_echo "${Error} ${RedBG} bootstrap_dependency_failed: bc,jq ${Font}"
            return 1
        fi
        # Metadata must be loaded before constructing the immutable candidate URL.
        load_shell_release_metadata || return 1
        [[ ! -d "${idleleo_dir}" ]] && mkdir -p "${idleleo_dir}"
        [[ ! -d "${idleleo_dir}/tmp" ]] && mkdir -p "${idleleo_dir}"/tmp
        [[ ! -d "${scripts_dir}" ]] && mkdir -p "${scripts_dir}"
        rxa_refresh_main_script "${idleleo}" || return 1
        judge "$(gettext "下载最新脚本")"
        if ! rxa_keep_committed_entry; then
            ln -sf "${idleleo}" "${idleleo_commend_file}" || return 1
        fi
        clear
        exec "${BASH:-bash}" "${idleleo}" "$@"
    fi
}

read_version() {
    # Load once in the current shell. Calling check_version only through command
    # substitutions would otherwise perform one network request per field because
    # each substitution runs in a subshell and cannot preserve the cache state.
    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "在线版本检测失败, 请稍后再试")! ${Font}" >&2
        return 1
    fi

    local new_shell_online_version
    local new_shell_release_sha256
    local new_xray_online_version
    local new_xray_installer_ref
    local new_xray_installer_sha256
    local new_xray_installer_verified_at
    local new_nginx_build_version
    local new_shell_tested_version
    local new_xray_tested_version
    local new_nginx_build_tested_version

    new_shell_online_version="$(check_version shell_online_version)" || return 1
    new_shell_release_sha256="$(check_version_silent shell_release_sha256 || echo "")"
    if release_sha_contract_required "${new_shell_online_version}" &&
        [[ ! "${new_shell_release_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
        log_echo "${Error} ${RedBG} 3.2.3+ Release 缺少有效 shell_release_sha256，已拒绝更新 ${Font}" >&2
        return 1
    fi
    if [[ -n "${new_shell_release_sha256}" && ! "${new_shell_release_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
        log_echo "${Error} ${RedBG} shell_release_sha256 格式无效，已拒绝更新 ${Font}" >&2
        return 1
    fi
    new_xray_online_version="$(check_version xray_online_version)" || return 1
    new_xray_installer_ref="$(check_version_silent xray_installer_ref || echo "")"
    new_xray_installer_sha256="$(check_version_silent xray_installer_sha256 || echo "")"
    new_xray_installer_verified_at="$(check_version_silent xray_installer_verified_at || echo "")"
    # Candidate qualification may run against an API branch that has not yet
    # landed on API main. Apply its immutable installer inputs before the
    # fail-closed validation; ordinary production reads still require the API
    # metadata to be present and valid.
    [[ -z "${XRAY_CANDIDATE_INSTALLER_REF:-}" ]] || new_xray_installer_ref="${XRAY_CANDIDATE_INSTALLER_REF}"
    [[ -z "${XRAY_CANDIDATE_INSTALLER_SHA256:-}" ]] || new_xray_installer_sha256="${XRAY_CANDIDATE_INSTALLER_SHA256}"
    if [[ ! "${new_xray_installer_ref}" =~ ^[0-9a-f]{40}$ ]] ||
        [[ ! "${new_xray_installer_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
        log_echo "${Error} ${RedBG} Xray-install verified metadata 无效，已拒绝安装或更新 ${Font}" >&2
        return 1
    fi
    new_nginx_build_version="$(check_version nginx_build_online_version)" || return 1
    # Read tested_version (known-good fallback baseline) from API.
    # These fields are optional in the API JSON; missing fields are treated as
    # "no Layer 2 fallback available" and silently become empty strings.
    new_shell_tested_version="$(check_version_silent shell_tested_version || echo "")"
    new_xray_tested_version="$(check_version_silent xray_tested_version || echo "")"
    new_nginx_build_tested_version="$(check_version_silent nginx_build_tested_version || echo "")"

    shell_online_version="${new_shell_online_version}"
    shell_release_sha256="${new_shell_release_sha256}"
    set_shell_release_urls "${shell_online_version}"
    xray_online_version="${new_xray_online_version}"
    xray_installer_ref="${new_xray_installer_ref}"
    xray_installer_sha256="${new_xray_installer_sha256}"
    xray_installer_verified_at="${new_xray_installer_verified_at}"
    # Qualification-only overrides never change API metadata or ordinary user
    # state. They only replace the candidate inputs consumed by the existing
    # production install/update path in CI.
    [[ -z "${XRAY_CANDIDATE_VERSION:-}" ]] || xray_online_version="${XRAY_CANDIDATE_VERSION}"
    [[ -z "${XRAY_CANDIDATE_INSTALLER_REF:-}" ]] || xray_installer_ref="${XRAY_CANDIDATE_INSTALLER_REF}"
    [[ -z "${XRAY_CANDIDATE_INSTALLER_SHA256:-}" ]] || xray_installer_sha256="${XRAY_CANDIDATE_INSTALLER_SHA256}"
    verified_installer_metadata_valid || {
        log_echo "${Error} ${RedBG} Candidate Xray-install metadata 无效，已拒绝 ${Font}" >&2
        return 1
    }
    nginx_build_version="${new_nginx_build_version}"
    shell_tested_version="${new_shell_tested_version}"
    xray_tested_version="${new_xray_tested_version}"
    nginx_build_tested_version="${new_nginx_build_tested_version}"
}

maintain() {
    log_echo "${Error} ${RedBG} $(gettext "该选项暂时无法使用")! ${Font}"
    log_echo "${Error} ${RedBG} $(gettext "$1") ${Font}"
    exit 0
}

list() {
    case $1 in
    '-1' | '--install-tls')
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        ;;
    '-2' | '--install-reality')
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        ;;
    '-3' | '--install-none')
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            ;;
        *) ;;
        esac
        ;;
    '--install-relay')
        node_role="relay"
        tls_mode="None"
        transport_mode="None"
        install_nginx_relay
        ;;
    # The XTLS ONLY profile was removed in stage 02. Stale notes/scripts that
    # still pass the old flag get an explicit answer instead of the main menu.
    '-4' | '--install-xtls')
        log_echo "${Error} ${RedBG} $(gettext "旧版 XTLS 模式 (已取消)") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "中转节点") / Reality: --install-relay / --install-reality ${Font}"
        return 1
        ;;
    '-5' | '--add-upstream')
        nginx_upstream_server_set
        ;;
    '-6' | '--add-servernames')
        nginx_servernames_server_set
        ;;
    '-sg' | '--sni-guard')
        reset_sni_guard_policy
        ;;
    '-au' | '--auto-update')
        auto_update
        ;;
    '-c' | '--clean-logs')
        clean_logs
        ;;
    '-cs' | '--cert-status')
        check_cert_status
        ;;
    '-cu' | '--cert-update')
        cert_update_manuel
        ;;
    '-cau' | '--cert-auto-update')
        acme_cron_update
        ;;
    '-f' | '--set-fail2ban')
        set_fail2ban
        ;;
    '--fail2ban-list')
        set_fail2ban_cli --list
        ;;
    '--fail2ban-unban')
        set_fail2ban_cli --unban "$2" "$3"
        ;;
    '--fail2ban-trust-add')
        set_fail2ban_cli --trust-add "$2" "$3"
        ;;
    '--fail2ban-trust-del')
        set_fail2ban_cli --trust-del "$2" "$3"
        ;;
    '-tb' | '--traffic-blocker')
        set_traffic_blocker
        ;;
    '-h' | '--help')
        show_help
        ;;
    '-l' | '--language')
        set_language
        ;;
    '-n' | '--nginx-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        nginx_update
        ;;
    '-p' | '--port-reset')
        reset_port
        ;;
    '-pt' | '--port-traffic')
        clear
        monitor_traffic_with_iftop
        ;;
    '--stats')
        xray_stats_cli stats "${@:2}"
        ;;
    '--stats-reset')
        xray_stats_cli reset "${@:2}"
        ;;
    '--stats-watch')
        xray_stats_cli watch "${@:2}"
        ;;
    '--purge' | '--uninstall')
        uninstall_all
        ;;
    '-u' | '--update')
        update_assume_yes="off"
        update_allow_major="off"
        bridge_manual_invocation="on"
        local _update_arg
        for _update_arg in "${2:-}" "${3:-}" "${4:-}"; do
            case "${_update_arg}" in
            auto_update) auto_update="YES"; log_file="${log_dir}/auto_update.log" ;;
            --yes|-y) update_assume_yes="YES" ;;
            --allow-major) update_allow_major="YES" ;;
            esac
        done
        update_sh
        ;;
    '--internal-bridge-offer')
        # Kept for internal dispatch compatibility; the early dispatch above is
        # the authoritative entry (zero network before consent).
        bridge_manual_invocation="on"
        bridge_migration_offer
        exit $?
        ;;
    '-s' | '--show')
        clear
        basic_information
        install_link_image
        show_information
        ;;
    '-t' | '--target-reset')
        reset_target
        ;;
    '-tcp' | '--tcp')
        bbr_boost_sh
        ;;
    '-tls' | '--tls')
        tls_type
        ;;
    '-uu' | '--uuid-reset')
        reset_UUID
        ;;
    '-xa' | '--xray-access')
        clear
        show_access_log
        ;;
    '-xe' | '--xray-error')
        clear
        show_error_log
        ;;
    '-x' | '--xray-update')
        [[ $2 == "auto_update" ]] && auto_update="YES" && log_file="${log_dir}/auto_update.log"
        xray_update
        ;;
    *)
        menu
        ;;
    esac
}

show_help() {
    echo "usage: idleleo [OPTION]"
    echo
    echo "OPTION:"
    echo "  -1, --install-tls           $(gettext "安装") Xray (Nginx+ws/gRPC/xHTTP+TLS)"
    echo "  -2, --install-reality       $(gettext "安装") Xray (Nginx+Reality+ws/gRPC/xHTTP)"
    echo "  -3, --install-none          $(gettext "安装") Xray (ws/gRPC/xHTTP ONLY, $(gettext "默认仅监听 127.0.0.1"))"
    echo "  --install-relay             $(gettext "安装中转节点") (Nginx Stream TCP $(gettext "转发"), $(gettext "不安装") Xray)"
    echo "  -5, --add-upstream          $(gettext "变更") Nginx $(gettext "负载均衡配置")"
    echo "  -6, --add-servernames       $(gettext "变更") Nginx serverNames $(gettext "配置")"
    echo "  -sg, --sni-guard            $(gettext "变更") SNI Guard"
    echo "  -au, --auto-update          $(gettext "设置自动更新")"
    echo "  -c, --clean-logs            $(gettext "清除日志文件")"
    echo "  -cs, --cert-status          $(gettext "查看证书状态")"
    echo "  -cu, --cert-update          $(gettext "更新证书有效期")"
    echo "  -cau, --cert-auto-update    $(gettext "设置证书自动更新")"
    echo "  -f, --set-fail2ban          $(gettext "设置 Fail2ban 防暴力破解")"
    echo "      --fail2ban-list         $(gettext "查看 Fail2ban 状态")"
    echo "      --fail2ban-unban <jail> <ip>                $(gettext "快速解封 IP")"
    echo "      --fail2ban-trust-add <jail> <ip-or-cidr>   $(gettext "添加可信 IP/CIDR")"
    echo "      --fail2ban-trust-del <jail> <ip-or-cidr>   $(gettext "移除可信 IP/CIDR")"
    echo "  -tb, --traffic-blocker      $(gettext "设置 Xray 流量阻断")"
    echo "      GEO_REFRESH_ASSUME_YES=1   $(gettext "跳过 GeoData 手动刷新确认 (仅自动化)")"
    echo "  -h, --help                  $(gettext "显示帮助")"
    echo "  -l, --language              $(gettext "修改语言")"
    echo "  -n, --nginx-update          $(gettext "更新") Nginx"
    echo "  -p, --port-reset            $(gettext "变更") port"
    echo "  -pt, --port-traffic         $(gettext "查看") port $(gettext "实时流量")"
    echo "      --stats                 $(gettext "查看 Xray 流量统计") [--json]"
    echo "      --stats-reset           $(gettext "重置 Xray 流量统计") [--yes]"
    echo "      --stats-watch [秒]       $(gettext "实时刷新 Xray 流量统计")"
    echo "  --purge, --uninstall        $(gettext "脚本卸载")"
    echo "      --backup                $(gettext "备份") $(gettext "脚本管理文件")"
    echo "      --restore               $(gettext "恢复") $(gettext "脚本管理文件")"
    echo "      --rill-agent-install    $(gettext "安装或修复 Rill AI 判断引擎")"
    echo "      --rill-agent-status     $(gettext "查看") Rill AI $(gettext "判断引擎状态")"
    echo "      --rill-agent-route-stage $(gettext "切换路由辅助阶段") observe/assist/auto"
    echo "      --rill-agent-auto-status $(gettext "查看自动修改状态")"
    echo "      --rill-agent-auto-confirm $(gettext "确认自动修改授权")"
    echo "      --rill-agent-auto-revoke $(gettext "撤销自动修改授权")"
    echo "  -s, --show                  $(gettext "显示安装信息")"
    echo "  -t, --target-reset          $(gettext "变更") target"
    echo "  -tcp, --tcp                 $(gettext "配置") TCP $(gettext "加速")"
    echo "  -tls, --tls                 $(gettext "修改") TLS $(gettext "配置")"
    echo "  -u, --update [--yes] [--allow-major]"
    echo "                              $(gettext "更新脚本") ($(gettext "自动化请加") --yes；$(gettext "跨 minor 另加") --allow-major)"
    echo "  -uu, --uuid-reset           $(gettext "变更") UUIDv5/$(gettext "映射字符串")"
    echo "  -xa, --xray-access          $(gettext "显示") Xray $(gettext "访问信息")"
    echo "  -xe, --xray-error           $(gettext "显示") Xray $(gettext "错误信息")"
    echo "  -x, --xray-update           $(gettext "更新") Xray"
    exit 0
}

idleleo_commend() {
    if [[ -L "${idleleo_commend_file}" ]] || [[ -f "${idleleo}" ]]; then
        if [[ ! -L "${idleleo_commend_file}" ]]; then
            chmod +x "${idleleo}"
            rxa_keep_committed_entry || ln -sf "${idleleo}" "${idleleo_commend_file}"
        fi
        old_version=$(grep "shell_version=" "${idleleo}" | head -1 | awk -F '=|"' '{print $3}')
        echo "${old_version}" >"${shell_version_tmp}"
        echo "${shell_version}" >>"${shell_version_tmp}"
        oldest_version=$(sort -V "${shell_version_tmp}" | head -1)
        version_difference="$(version_series_difference "${shell_version}" "${oldest_version}")"
        if [[ -z ${old_version} ]]; then
            rxa_refresh_main_script "${idleleo}" || return 1

            judge "$(gettext "下载最新脚本")"
            clear
            exec "${BASH:-bash}" "${idleleo}"
        elif [[ ${shell_version} != ${oldest_version} ]]; then
            echo
            log_echo "${GreenBG} $(gettext "新版本")(${shell_version}) $(gettext "更新内容"): ${Font}"
            log_echo "${Green} $(check_version shell_upgrade_details) ${Font}"
            if [[ ${version_difference} == 1 ]]; then
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 可能存在不兼容情况, 是否继续使用") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
                read -r update_sh_fq
                case $update_sh_fq in
                [yY][eE][sS] | [yY])
                    rxa_refresh_main_script "${idleleo}" || return 1

                    judge "$(gettext "下载最新脚本")"
                    clear
                    log_echo "${Warning} ${YellowBG} $(gettext "脚本版本变化较大, 若服务无法正常运行请卸载后重装")! ${Font}"
                    echo
                    ;;
                *)
                    exec "${BASH:-bash}" "${idleleo}"
                    ;;
                esac
            else
                rxa_refresh_main_script "${idleleo}" || return 1

                echo
                judge "$(gettext "下载最新脚本")"
                clear
                echo
            fi
            exec "${BASH:-bash}" "${idleleo}"
        else
            ol_version=${shell_online_version}
            echo "${ol_version}" >"${shell_version_tmp}"
            [[ -z ${ol_version} ]] && shell_need_update="${Yellow}[$(gettext "检测失败")]!${Font}"
            echo "${shell_version}" >>"${shell_version_tmp}"
            newest_version=$(sort -rV "${shell_version_tmp}" | head -1)
            if [[ ${shell_version} != ${newest_version} ]]; then
                shell_need_update="${Yellow}[$(gettext "有新版")!]${Font}"
                shell_emoji="${Yellow}>_<${Font}"
            else
                shell_need_update="${Green}[$(gettext "最新版")]${Font}"
                shell_emoji="${Green}^O^${Font}"
            fi
            if [[ -f "${xray_install_config_file}" ]]; then
                if [[ -z "$(info_extraction nginx_build_version)" ]] || [[ ! -f "${nginx_dir}/sbin/nginx" ]]; then
                    nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                elif [[ ${nginx_build_version} != $(info_extraction nginx_build_version) ]]; then
                    nginx_need_update="${Green}[$(gettext "有新版")!]${Font}"
                else
                    nginx_need_update="${Green}[$(gettext "最新版")]${Font}"
                fi
                if [[ -f "${xray_install_config_file}" ]] && [[ -f "${xray_conf}" ]] && [[ -f "${xray_bin_dir}/xray" ]]; then
                    if [[ -z "$(info_extraction xray_version)" ]]; then
                        xray_need_update="${Green}[$(gettext "已安装")] ($(gettext "版本未知"))${Font}"
                    elif [[ ${xray_online_version} != $(info_extraction xray_version) ]]; then
                        xray_need_update="${Green}[$(gettext "有新版")!]${Font}"
                    else
                        xray_need_update="${Green}[$(gettext "最新版")]${Font}"
                    fi
                else
                    xray_need_update="${Yellow}[$(gettext "未安装")]${Font}"
                fi
            else
                nginx_need_update="${Green}[$(gettext "未安装")]${Font}"
                xray_need_update="${Yellow}[$(gettext "未安装")]${Font}"
            fi
        fi
    fi
}

check_program() {
    if is_relay_role; then
        if [[ -n $(pgrep nginx) ]]; then
            nginx_status="${Green}$(gettext "运行中")..${Font}"
        else
            nginx_status="${Red}$(gettext "未运行")${Font}"
        fi
        xray_status="${Green}$(gettext "不适用")${Font}"
        return 0
    fi
    if [[ -n $(pgrep nginx) ]]; then
        nginx_status="${Green}$(gettext "运行中")..${Font}"
    elif [[ ${tls_mode} == "None" ]] || [[ ${tls_mode} == "Reality" && ${reality_add_nginx} != "on" ]]; then
        nginx_status="${Green}$(gettext "无需测试")${Font}"
    else
        nginx_status="${Red}$(gettext "未运行")${Font}"
    fi
    if [[ -n $(pgrep xray) ]]; then
        xray_status="${Green}$(gettext "运行中")..${Font}"
    else
        xray_status="${Red}$(gettext "未运行")${Font}"
    fi
}

curl_local_connect() {
    curl -Is -o /dev/null -w '%{http_code}' --max-time 10 "https://$1/$2"
}

curl_local_connect_xhttp() {
    local host="$1"
    local raw_path="$2"
    local probe_path
    local curl_args=(-s -o /dev/null -w '%{http_code}' --max-time 10)

    probe_path="$(format_xhttp_path "${raw_path}")"
    probe_path="${probe_path%/}/xhttp-probe-${RANDOM}"
    if curl --version 2>/dev/null | grep -q 'HTTP2'; then
        curl_args+=(--http2)
    fi
    curl "${curl_args[@]}" "https://${host}${probe_path}"
}

tcp_local_connect() {
    local port="$1"

    [[ ${port} =~ ^[0-9]+$ ]] || return 1
    timeout 3 bash -c ':</dev/tcp/127.0.0.1/$1' _ "${port}" >/dev/null 2>&1
}

xray_inbound_port() {
    local inbound_tag="$1"

    [[ -f "${xray_conf}" ]] || return 1
    jq -r --arg tag "${inbound_tag}" 'first(.inbounds[]? | select(.tag == $tag) | .port) // empty' "${xray_conf}" 2>/dev/null
}

xray_inbound_listen() {
    local inbound_tag="$1"

    [[ -f "${xray_conf}" ]] || return 1
    jq -r --arg tag "${inbound_tag}" 'first(.inbounds[]? | select(.tag == $tag) | .listen) // empty' "${xray_conf}" 2>/dev/null
}

# First listen address of the ws/gRPC/xHTTP inbounds (None/"ONLY" mode).
none_mode_listen_address() {
    local _tag _addr=""
    for _tag in VLESS-ws-in VLESS-gRPC-in VLESS-xhttp-in; do
        _addr=$(xray_inbound_listen "${_tag}")
        [[ -n "${_addr}" ]] && break
    done
    printf '%s' "${_addr}"
}

check_transport_tcp_ports() {
    if is_ws_mode && ! tcp_local_connect "$(info_extraction ws_port)"; then
        return 1
    fi
    if is_grpc_mode && ! tcp_local_connect "$(info_extraction grpc_port)"; then
        return 1
    fi
    if is_xhttp_mode && ! tcp_local_connect "$(info_extraction xhttp_port)"; then
        return 1
    fi
    is_ws_mode || is_grpc_mode || is_xhttp_mode
}

check_reality_tcp_ports() {
    local reality_port

    if [[ ${reality_add_nginx} == "on" ]]; then
        reality_port=$(xray_inbound_port "VLESS-Reality-in")
        tcp_local_connect "$(info_extraction port)" && tcp_local_connect "${reality_port}" || return 1
    else
        tcp_local_connect "$(info_extraction port)" || return 1
    fi
    if [[ ${reality_add_more} == "on" ]]; then
        check_transport_tcp_ports || return 1
    fi
}

check_xray_local_connect() {
    if is_relay_role; then
        _relay_state_load
        relay_status_refresh
        xray_local_connect_status="${relay_local_connect_status}"
        return 0
    fi
    if [[ -f "${xray_install_config_file}" ]]; then
        if [[ ${tls_mode} == "TLS" ]]; then
            xray_local_connect_status="${Yellow}$(gettext "无法连通")${Font}"
        else
            xray_local_connect_status="${Red}$(gettext "无法连通")${Font}"
        fi
        if [[ ${tls_mode} == "TLS" ]]; then
            if [[ ${transport_mode} == "onlyxhttp" ]]; then
                [[ $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "onlyws" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "onlygRPC" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "wsxhttp" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" && $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            elif [[ ${transport_mode} == "wsgRPCxhttp" ]]; then
                [[ $(curl_local_connect "$(info_extraction host)" "$(info_grpc_serviceName)") == "502" && $(curl_local_connect "$(info_extraction host)" "$(info_ws_path)") == "400" && $(curl_local_connect_xhttp "$(info_extraction host)" "$(info_xhttp_path)") == "400" ]] && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
            fi
        elif [[ ${tls_mode} == "Reality" ]]; then
            check_reality_tcp_ports && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        elif [[ ${tls_mode} == "None" ]]; then
            check_transport_tcp_ports && xray_local_connect_status="${Green}$(gettext "本地正常")${Font}"
        fi
    else
        xray_local_connect_status="${Red}$(gettext "未安装")${Font}"
    fi
}

check_online_version_connect() {
    maintain_file_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${shell_release_raw_base}/maintain")

    if [[ ${maintain_file_status} == "200" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "脚本维护中.. 请稍后再试")! ${Font}"
        sleep 0.5
        exit 0
    fi

    if ! load_versions; then
        log_echo "${Error} ${RedBG} $(gettext "无法检测所需依赖的在线版本, 请稍后再试")! ${Font}"
        sleep 0.5
        exit 1
    fi
}

set_language() {
    echo
    log_echo "${GreenBG} 选择语言 / Select Language / انتخاب زبان / Выберите язык ${Font}"
    echo -e "${Green}1.${Font} 中文 (默认)"
    echo -e "${Green}2.${Font} English"
    echo -e "${Green}3.${Font} Français"
    echo -e "${Green}4.${Font} فارسی"
    echo -e "${Green}5.${Font} Русский"
    echo -e "${Green}6.${Font} 한국어"

    local lang_choice
    read_optimize "$(gettext "请输入数字"): " "lang_choice" "NULL" 1 6 "$(gettext "请输入 1 到 6 之间的有效数字")" || return 1

    case $lang_choice in
        1)
            unset LANG
            unset LC_MESSAGES
            unset LANGUAGE
            unset LC_ALL
            rm -f "${idleleo_dir}/language.conf"
            rm -rf "${idleleo_dir}/languages"
            ;;
        2)
            export LANG=en_US.UTF-8 2>/dev/null
            export LC_MESSAGES=en_US.UTF-8 2>/dev/null
            ;;
        3)
            export LANG=fr_FR.UTF-8 2>/dev/null
            export LC_MESSAGES=fr_FR.UTF-8 2>/dev/null
            ;;
        4)
            export LANG=fa_IR.UTF-8 2>/dev/null
            export LC_MESSAGES=fa_IR.UTF-8 2>/dev/null
            ;;
        5)
            export LANG=ru_RU.UTF-8 2>/dev/null
            export LC_MESSAGES=ru_RU.UTF-8 2>/dev/null
            ;;
        6)
            export LANG=ko_KR.UTF-8 2>/dev/null
            export LC_MESSAGES=ko_KR.UTF-8 2>/dev/null
            ;;
        *)
            log_echo "${Error} ${RedBG} $(gettext "无效的选择, 请重试") ${Font}"
            return 1
            ;;
    esac

    if [ "$lang_choice" -ne 1 ]; then

        check_system

        echo "LANG=$LANG" > "${idleleo_dir}/language.conf"
        echo "LC_MESSAGES=$LC_MESSAGES" >> "${idleleo_dir}/language.conf"

        case $ID in
            debian|ubuntu)
                if ! dpkg -s locales-all >/dev/null 2>&1; then
                    # P1-9: locales-all is an OPTIONAL locale enhancement; the
                    # locale-gen step below already tolerates failure.
                    pkg_install "locales-all"
                fi

                if command -v locale-gen >/dev/null 2>&1; then
                     locale-gen "$LANG" 2>/dev/null || true # 忽略可能的错误
                fi
                ;;
            centos|rocky|almalinux)
                local ins_lang_code="${LANG%%_*}"
                if ! rpm -q "glibc-langpack-$ins_lang_code" >/dev/null 2>&1; then
                    # P1-9: glibc-langpack is an OPTIONAL locale enhancement;
                    # localedef below already tolerates failure.
                    pkg_install "glibc-langpack-$ins_lang_code"
                fi
                # 尝试生成 locale (非必需，但可能有帮助)
                if command -v localedef >/dev/null 2>&1 && [ -f "/usr/share/i18n/locales/${LANG%.*}" ]; then
                    localedef -c -i "${LANG%.*}" -f UTF-8 "$LANG" 2>/dev/null || true # 忽略可能的错误
                fi
                ;;
        esac
    fi

    exec "${BASH:-bash}" "${idleleo}"
}

function backup_directories() {
    local timestamp
    timestamp=$(date +"%Y%m%d%H%M%S")
    local backup_name=""
    read_optimize "$(gettext "请输入备份名称") ($(gettext "不需要后缀")): " "backup_name" ""
    # The name becomes part of a root-owned path. Reject path separators and
    # traversal so a typo cannot write outside /etc/idleleo.
    if [[ ! "${backup_name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
        log_echo "${Error} ${RedBG} $(gettext "值为空或超出范围, 请重新输入") ${Font}"
        return 1
    fi
    local backup_filename="xray_bash_${backup_name}_${timestamp}.tar.gz"
    local backup_path="${idleleo_dir}/${backup_filename}"
    local backup_tmp backup_tar_paths=() tar_output old_umask
    local manifest="${idleleo_dir}/.backup_sha256sums.txt"

    # Never silently overwrite an existing archive (same name and same second).
    if [[ -e "${backup_path}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败")：${backup_path} ${Font}"
        return 1
    fi

    # Create outside the tree being archived: the archive itself would otherwise
    # change /etc/idleleo while tar is reading it. Keep the temp file 0600 so no
    # partially written archive is exposed.
    backup_tmp=$(mktemp "${TMPDIR:-/tmp}/xray-backup.XXXXXX") || {
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败")：$(gettext "无法创建临时文件") ${Font}"
        return 1
    }
    chmod 600 "${backup_tmp}" 2>/dev/null || true
    backup_tar_paths=("${idleleo_dir}")
    [[ -d "${nginx_dir}" ]] && backup_tar_paths+=("${nginx_dir}")
    # Service units and the Xray binary live outside idleleo_dir/nginx_dir.
    # "全部文件" must include them, otherwise a restore leaves the old binary
    # or unit pointing at the restored (older) config.
    [[ -f "${xray_bin_dir}/xray" ]] && backup_tar_paths+=("${xray_bin_dir}/xray")
    # Xray's default asset root is /usr/local/share/xray, which this script
    # manages as a symlink into /etc/idleleo/share/xray. Back up the link as
    # well: a restore on a fresh host would otherwise leave the native
    # geodata block in config.json without a resolvable asset directory.
    [[ -L "${local_bin}/share/xray" ]] && backup_tar_paths+=("${local_bin}/share/xray")
    [[ -f "${xray_systemd_file}" ]] && backup_tar_paths+=("${xray_systemd_file}")
    [[ -f "${nginx_systemd_file}" ]] && backup_tar_paths+=("${nginx_systemd_file}")
    # Root crontab spool differs by distro; include whichever exists so the
    # cert-renewal / auto-update tasks survive a manual restore.
    local cron_path
    for cron_path in /var/spool/cron/crontabs/root /var/spool/cron/root; do
        [[ -f "${cron_path}" ]] && backup_tar_paths+=("${cron_path}")
    done
    # ACME account state is needed for future certificate renewals.
    [[ -d /root/.acme.sh ]] && backup_tar_paths+=("/root/.acme.sh")

    # Per-file checksum manifest, inside the archive, using the same
    # sha256sum -c model as the reinstall snapshot. It excludes itself, old
    # archives and /etc/idleleo/backup (previous reinstall snapshots) so the
    # backup does not recursively grow.
    local _manifest_err=0 _file _rel _hash
    : >"${manifest}" || _manifest_err=1
    while IFS= read -r -d '' _file; do
        [[ "${_file}" == "${manifest}" ]] && continue
        _rel="${_file#/}"
        _hash=$(sha256sum "${_file}" 2>/dev/null | awk '{print $1}')
        if [[ -z "${_hash}" ]]; then
            _manifest_err=1
            break
        fi
        printf '%s  %s\n' "${_hash}" "${_rel}" >>"${manifest}" || {
            _manifest_err=1
            break
        }
    done < <(
        find "${backup_tar_paths[@]}" \
            \( -path "${idleleo_dir}/backup" -o -name 'xray_bash_*.tar.gz' \
               -o -name '.backup_sha256sums.txt' \) -prune -o \
            -type f -print0 2>/dev/null
    )
    [[ -s "${manifest}" ]] || _manifest_err=1
    if (( _manifest_err != 0 )); then
        rm -f "${backup_tmp}" "${manifest}"
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败")：$(gettext "完整性清单生成失败") ${Font}"
        return 1
    fi
    chmod 600 "${manifest}" 2>/dev/null || true

    old_umask=$(umask)
    umask 077
    if ! tar_output=$(tar --exclude='xray_bash_*.tar.gz' \
        --exclude="${idleleo_dir}/backup" \
        -czf "${backup_tmp}" "${backup_tar_paths[@]}" 2>&1); then
        umask "${old_umask}"
        rm -f "${backup_tmp}" "${manifest}"
        log_echo "${Green} tar $(gettext "报错信息"): ${Font}"
        echo "${tar_output}"
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败")：tar $(gettext "返回非零") ${Font}"
        return 1
    fi
    chmod 600 "${backup_tmp}" 2>/dev/null || true
    if ! mv -f "${backup_tmp}" "${backup_path}"; then
        umask "${old_umask}"
        rm -f "${backup_tmp}" "${manifest}"
        log_echo "${Error} ${RedBG} $(gettext "备份") $(gettext "失败")：$(gettext "无法写入备份文件") ${Font}"
        return 1
    fi
    rm -f "${manifest}"
    chmod 600 "${backup_path}" 2>/dev/null || true
    umask "${old_umask}"
    log_echo "${OK} ${GreenBG} $(gettext "备份") $(gettext "成功"): ${backup_path} ${Font}"
}

# ---- restore-time GeoData layout self-heal ---------------------------------
# Archives created before the managed asset layout either carry a real
# /usr/local/share/xray directory or no entry at all, while Xray expects the
# symlink into /etc/idleleo/share/xray. Restoring such an archive on a fresh
# host therefore leaves the .dat files in a directory Xray never reads. The
# helpers below repair the three layouts, validate with the restored binary and
# roll back every change when validation fails.

_restore_geo_pair_ok() {
    local dir="$1"
    [[ -f "${dir}/geoip.dat" && ! -L "${dir}/geoip.dat" ]] || return 1
    [[ -f "${dir}/geosite.dat" && ! -L "${dir}/geosite.dat" ]] || return 1
}

# Heal /usr/local/share/xray after an archive overlay.
#
#   1. correct symlink -> do nothing (idempotent re-restore).
#   2. missing path + managed geodata -> create the symlink.
#   3. real directory with geodata -> merge into the managed directory, keep the
#      original tree as a rollback copy and replace it with the symlink.
#
# Merge policy: the target (restored /etc/idleleo/share/xray) wins on every
# same-name collision. The legacy file stays available in the kept backup
# directory, so nothing is destroyed and repeated restores never overwrite
# geodata the host already had.
#
# $2 is an optional legacy tree detached before the overlay (repeat restore of
# an old archive onto an already-healed host); only missing files are merged.
restore_geodata_layout_selfheal() {
    local restore_root="${1:-/}"
    local legacy_source="${2:-}"
    local prefix="" link_target default_dir managed_dir
    [[ "${restore_root}" == "/" ]] || prefix="${restore_root%/}"
    default_dir="${prefix}${local_bin}/share/xray"
    managed_dir="${prefix}/etc/idleleo/share/xray"
    link_target="${prefix}/etc/idleleo/share/xray"

    local xray_bin="${prefix}${xray_bin_dir}/xray"
    local xray_config="${prefix}${xray_conf}"
    local config_snapshot="" backup_dir="" created_link=0 moved_original=0
    local relinked=0 original_link_target="" test_output="" managed_created=0
    local -a copied_files=()

    if [[ -f "${xray_config}" ]]; then
        config_snapshot=$(mktemp "${TMPDIR:-/tmp}/xray-restore-config.XXXXXX" 2>/dev/null) || {
            log_echo "${Error} ${RedBG} $(gettext "恢复前配置快照创建失败") ${Font}"
            return 1
        }
        if ! cp -p "${xray_config}" "${config_snapshot}"; then
            rm -f "${config_snapshot}"
            log_echo "${Error} ${RedBG} $(gettext "恢复前配置快照创建失败") ${Font}"
            return 1
        fi
    fi

    # Bash dynamic scoping keeps the caller's locals visible here; this keeps
    # every failure path on the same rollback sequence.
    _restore_geo_fail() {
        local reason="$1" rollback_ok=1 f
        if [[ "${created_link}" == "1" ]]; then
            rm -f "${default_dir}" || rollback_ok=0
            created_link=0
        fi
        if [[ "${moved_original}" == "1" ]]; then
            if [[ -d "${backup_dir}" && ! -e "${default_dir}" && ! -L "${default_dir}" ]]; then
                mv "${backup_dir}" "${default_dir}" || rollback_ok=0
            else
                rollback_ok=0
            fi
            moved_original=0
        fi
        for f in ${copied_files[@]+"${copied_files[@]}"}; do
            rm -f -- "${f}" || rollback_ok=0
        done
        if [[ "${managed_created}" == "1" && -d "${managed_dir}" ]]; then
            rmdir "${managed_dir}" 2>/dev/null || true
            managed_created=0
        fi
        if [[ "${relinked}" == "1" ]]; then
            if [[ -n "${original_link_target}" ]]; then
                ln -sfn "${original_link_target}" "${default_dir}" || rollback_ok=0
            else
                rm -f "${default_dir}" || rollback_ok=0
            fi
        fi
        if [[ -n "${config_snapshot}" && -f "${config_snapshot}" ]]; then
            cp -p "${config_snapshot}" "${xray_config}" || rollback_ok=0
        fi
        if [[ "${rollback_ok}" == "1" ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "GeoData 自愈失败, 已回滚到恢复前状态"): ${reason} ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "RECOVERY REQUIRED: GeoData 自愈回滚不完整"): ${reason} ${Font}"
        fi
        [[ -z "${config_snapshot}" ]] || rm -f "${config_snapshot}"
        return 1
    }

    _restore_geo_merge() {
        local source_dir="$1" target_dir="$2" entry base
        if [[ ! -d "${target_dir}" ]]; then
            mkdir -p "${target_dir}" || return 1
            [[ "${target_dir}" == "${managed_dir}" ]] && managed_created=1
        fi
        for entry in "${source_dir}"/*; do
            [[ -f "${entry}" && ! -L "${entry}" ]] || continue
            base="${entry##*/}"
            if [[ -e "${target_dir}/${base}" || -L "${target_dir}/${base}" ]]; then
                continue
            fi
            if ! cp -p -- "${entry}" "${target_dir}/${base}"; then
                log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 文件复制失败, 保留原目录"): ${entry} ${Font}"
                return 1
            fi
            copied_files+=("${target_dir}/${base}")
        done
        return 0
    }

    if [[ -L "${default_dir}" ]]; then
        local target
        target=$(readlink "${default_dir}" 2>/dev/null)
        # Relocated test roots cannot resolve the canonical absolute target.
        # Re-point the restored link inside that root; production is unchanged.
        if [[ "${restore_root}" != "/" && "${target}" == "/etc/idleleo/share/xray" ]]; then
            original_link_target="${target}"
            relinked=1
            ln -sfn "${link_target}" "${default_dir}" || {
                relinked=0
                _restore_geo_fail "repoint link"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            }
            target="${link_target}"
        fi
        if [[ "${target}" == "${link_target}" ]] || \
            { [[ -d "${default_dir}" ]] && \
              [[ "$(_geodata_realpath "${default_dir}")" == "$(_geodata_realpath "${managed_dir}")" ]]; }; then
            if [[ -n "${legacy_source}" ]]; then
                if ! _restore_geo_merge "${legacy_source}" "${managed_dir}"; then
                    _restore_geo_fail "merge legacy assets"
                    unset -f _restore_geo_fail _restore_geo_merge
                    return 1
                fi
            fi
        else
            log_echo "${Warning} ${YellowBG} $(gettext "GeoData 软链指向其他目录, 保留现状"): ${target:-<broken>} ${Font}"
            if [[ -n "${legacy_source}" ]]; then
                log_echo "${Warning} ${YellowBG} $(gettext "旧归档 GeoData 文件未合并, 现有软链未被覆盖") ${Font}"
            fi
        fi
    elif [[ -d "${default_dir}" ]]; then
        if _restore_geo_pair_ok "${default_dir}"; then
            if ! _restore_geo_merge "${default_dir}" "${managed_dir}"; then
                _restore_geo_fail "merge legacy assets"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            fi
            if ! _restore_geo_pair_ok "${managed_dir}"; then
                _restore_geo_fail "managed assets incomplete"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            fi
            backup_dir="${default_dir}.restore-backup.$(date +%Y%m%d%H%M%S)"
            [[ -e "${backup_dir}" || -L "${backup_dir}" ]] && backup_dir="${backup_dir}.$$"
            if ! mv "${default_dir}" "${backup_dir}"; then
                _restore_geo_fail "move legacy directory"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            fi
            moved_original=1
            if ! ln -s "${link_target}" "${default_dir}"; then
                _restore_geo_fail "create managed symlink"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            fi
            created_link=1
            log_echo "${OK} ${GreenBG} $(gettext "已将旧 GeoData 目录合并到"): ${managed_dir} ${Font}"
            log_echo "${Info} ${Green} $(gettext "同名文件以目标目录为准, 原目录回退副本保留于"): ${backup_dir} ${Font}"
        else
            log_echo "${Warning} ${YellowBG} $(gettext "旧 GeoData 目录缺少 geoip.dat/geosite.dat, 保留原目录且不建软链"): ${default_dir} ${Font}"
        fi
    elif [[ -e "${default_dir}" ]]; then
        _restore_geo_fail "unsupported asset path"
        unset -f _restore_geo_fail _restore_geo_merge
        return 1
    else
        if _restore_geo_pair_ok "${managed_dir}"; then
            mkdir -p "${default_dir%/*}" || {
                _restore_geo_fail "create asset parent"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            }
            if ! ln -s "${link_target}" "${default_dir}"; then
                _restore_geo_fail "create managed symlink"
                unset -f _restore_geo_fail _restore_geo_merge
                return 1
            fi
            created_link=1
            log_echo "${OK} ${GreenBG} $(gettext "已创建 GeoData 资源目录软链"): ${default_dir} ${Font}"
        else
            log_echo "${Info} ${Green} $(gettext "未找到可用的 GeoData 资源, 跳过软链自愈") ${Font}"
        fi
    fi

    # Validation is part of the heal: a layout that cannot be read by the real
    # binary must not be reported as a successful restore.
    if [[ ! -x "${xray_bin}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "未找到可执行的 Xray, 跳过 GeoData 自愈后自检") ${Font}"
        [[ -z "${config_snapshot}" ]] || rm -f "${config_snapshot}"
        unset -f _restore_geo_fail _restore_geo_merge
        return 0
    fi
    if [[ ! -f "${xray_config}" ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "恢复后缺少 Xray 配置, 跳过 GeoData 自愈后自检") ${Font}"
        [[ -z "${config_snapshot}" ]] || rm -f "${config_snapshot}"
        unset -f _restore_geo_fail _restore_geo_merge
        return 0
    fi
    if ! test_output=$(XRAY_LOCATION_ASSET="${default_dir}" "${xray_bin}" run -test -config "${xray_config}" 2>&1); then
        log_echo "${Error} ${RedBG} $(gettext "GeoData 自愈后 Xray 配置自检失败") ${Font}"
        printf '%s\n' "${test_output}" | tail -n 5 | while IFS= read -r _line; do
            [[ -n "${_line}" ]] && log_echo "  ${_line}"
        done
        _restore_geo_fail "xray -test"
        unset -f _restore_geo_fail _restore_geo_merge
        return 1
    fi
    log_echo "${OK} ${GreenBG} $(gettext "GeoData 自愈后 Xray 自检通过") ${Font}"
    [[ -z "${config_snapshot}" ]] || rm -f "${config_snapshot}"
    unset -f _restore_geo_fail _restore_geo_merge
    return 0
}

function restore_directories() {
    log_echo "${Warning} ${YellowBG} $(gettext "请确保备份文件在目录"): ${idleleo_dir} ${Font}"
    local backup_files=($(ls "${idleleo_dir}"/xray_bash_*.tar.gz 2>/dev/null))

    if [[ ${#backup_files[@]} -eq 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "没有找到备份文件") ${Font}"
        return 1
    fi

    if [[ ${#backup_files[@]} -gt 1 ]]; then
        log_echo "${Warning} ${YellowBG} $(gettext "发现多个备份文件"), $(gettext "将使用最新的文件进行恢复") ${Font}"
    fi

    # Select by the 14-digit timestamp embedded in the name, not by ls order.
    # Different backup names made the previous "last line wins" choice restore
    # an older archive whose name merely sorted later.
    local latest_backup_file="" latest_backup_ts=0 candidate candidate_ts
    for candidate in "${backup_files[@]}"; do
        candidate_ts=$(basename "${candidate}" | sed -n 's/.*_\([0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\)\.tar\.gz$/\1/p')
        if [[ -z "${candidate_ts}" ]]; then
            candidate_ts=$(stat -c '%Y' "${candidate}" 2>/dev/null || echo 0)
        fi
        if (( 10#${candidate_ts} > 10#${latest_backup_ts} )); then
            latest_backup_ts="${candidate_ts}"
            latest_backup_file="${candidate}"
        fi
    done

    log_echo "${Green} $(gettext "找到最新备份文件"): ${latest_backup_file} ${Font}"

    # Validate the whole archive before touching the live tree. A truncated
    # archive used to report 恢复失败 yet still return 0 and could leave a
    # partially extracted /etc/idleleo or /usr/local/nginx.
    if ! tar -tzf "${latest_backup_file}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性校验失败, 拒绝恢复") ${Font}"
        return 1
    fi

    # Capture the listing once. Piping tar directly into grep is unsafe under
    # `set -o pipefail`: grep exits on the first match, tar receives SIGPIPE,
    # and a perfectly valid archive is rejected as "unexpected content".
    local _archive_listing=""
    if ! _archive_listing=$(tar -tzf "${latest_backup_file}" 2>/dev/null); then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性校验失败, 拒绝恢复") ${Font}"
        return 1
    fi
    if ! grep -Eq '^/?(etc/idleleo|usr/local/nginx|usr/local/bin/xray|etc/systemd/system|root/.acme.sh)(/|$)' <<<"${_archive_listing}"; then
        log_echo "${Error} ${RedBG} $(gettext "备份内容不符合预期, 拒绝恢复") ${Font}"
        return 1
    fi

    countdown "$(gettext "恢复备份")!"
    local restore_root="${RESTORE_ROOT:-/}"
    local staging
    staging=$(mktemp -d "${TMPDIR:-/tmp}/xray-restore.XXXXXX") || {
        log_echo "${Error} ${RedBG} $(gettext "恢复") $(gettext "失败") ${Font}"
        return 1
    }

    # Extract to staging first: a corrupt or truncated archive must not touch
    # the live tree, and the checksum manifest is verified before any copy.
    if ! tar -xzf "${latest_backup_file}" -C "${staging}" >/dev/null 2>&1; then
        rm -rf "${staging}"
        log_echo "${Error} ${RedBG} $(gettext "恢复") $(gettext "失败") ${Font}"
        return 1
    fi

    local manifest="${staging}/etc/idleleo/.backup_sha256sums.txt"
    if [[ -f "${manifest}" ]]; then
        if ! ( cd "${staging}" && sha256sum --strict -c "${manifest}" >/dev/null 2>&1 ); then
            rm -rf "${staging}"
            log_echo "${Error} ${RedBG} $(gettext "备份完整性校验失败, 拒绝恢复") ${Font}"
            return 1
        fi
    else
        # Archives created before the manifest existed can only be checked
        # structurally; keep them restorable but make the limitation visible.
        log_echo "${Warning} ${YellowBG} $(gettext "旧备份无完整性清单, 仅做结构校验") ${Font}"
    fi

    # A legacy archive stores /usr/local/share/xray as a real directory. When
    # the host is already healed (the path is the managed symlink), `cp -a`
    # would either fail or write the archived files through the link, silently
    # replacing newer geodata. Detach that tree before the overlay and merge it
    # later with target-wins rules; the self-heal owns the final layout.
    local _legacy_geo_source=""
    local _live_default_geo="${restore_root%/}${local_bin}/share/xray"
    if [[ -d "${staging}/usr/local/share/xray" && ! -L "${staging}/usr/local/share/xray" ]] && \
        [[ -L "${_live_default_geo}" ]]; then
        _legacy_geo_source=$(mktemp -d "${TMPDIR:-/tmp}/xray-restore-geo.XXXXXX" 2>/dev/null) || {
            rm -rf "${staging}"
            log_echo "${Error} ${RedBG} $(gettext "旧 GeoData 目录暂存失败, 拒绝恢复") ${Font}"
            return 1
        }
        if ! mv "${staging}/usr/local/share/xray" "${_legacy_geo_source}/xray"; then
            rm -rf "${staging}" "${_legacy_geo_source}"
            log_echo "${Error} ${RedBG} $(gettext "旧 GeoData 目录暂存失败, 拒绝恢复") ${Font}"
            return 1
        fi
    fi

    if ! cp -a "${staging}/." "${restore_root}/"; then
        rm -rf "${staging}" "${_legacy_geo_source}"
        log_echo "${Error} ${RedBG} $(gettext "恢复") $(gettext "失败") ${Font}"
        return 1
    fi
    rm -f "${restore_root}/etc/idleleo/.backup_sha256sums.txt"
    rm -rf "${staging}"

    # Remove target-mode managed files that were not present in the backup.
    # Only exact script-owned names are removed; user-added .conf files and
    # other custom files are preserved. Legacy archives have no manifest
    # listing, so pruning is skipped and the cross-mode limitation is logged.
    local _manifest_in_archive=0
    if grep -qx 'etc/idleleo/.backup_sha256sums.txt' <<<"${_archive_listing}"; then
        _manifest_in_archive=1
    fi
    if (( _manifest_in_archive == 1 )); then
        local _backed _managed_rel
        _backed=$(tar -xOzf "${latest_backup_file}" etc/idleleo/.backup_sha256sums.txt 2>/dev/null | awk '{print $2}')
        for _managed_rel in \
            "${nginx_conf_dir#/}/00-xray.conf" \
            "${nginx_conf_dir#/}/01-xray-80.conf" \
            "${nginx_conf_dir#/}/02-xray-server.conf" \
            "${nginx_conf_dir#/}/03-isolate.conf" \
            "${nginx_conf_dir#/}/03-decoy.conf" \
            "${relay_stream_conf#/}" \
            "${xray_conf_dir#/}/config.json" \
            "${xray_conf_dir#/}/status_config.json"; do
            if ! grep -qx -- "${_managed_rel}" <<<"${_backed}"; then
                rm -f "${restore_root}/${_managed_rel}" 2>/dev/null || true
            fi
        done
    else
        log_echo "${Warning} ${YellowBG} $(gettext "旧备份未做跨模式清理, 请手动检查残留配置") ${Font}"
    fi

    # Re-harden the restored config. Production uses the existing helper
    # (which also assigns the Nginx worker group); tests restore into a temp
    # root, so the direct 0600 fallback keeps UUID/private material non-root
    # readable only.
    if [[ "${restore_root}" == "/" ]] && declare -F harden_config_permissions >/dev/null 2>&1; then
        harden_config_permissions 2>/dev/null || \
            log_echo "${Warning} ${YellowBG} $(gettext "恢复后权限收紧未完全成功, 请手动检查") ${Font}"
    fi
    chmod 600 "${restore_root}/etc/idleleo/conf/install_config.json" 2>/dev/null || true
    chmod 600 "${restore_root}/etc/idleleo/info/xray_info.inf" 2>/dev/null || true
    chmod 600 "${restore_root}/etc/idleleo/info/xray_info_clash.yaml" 2>/dev/null || true
    local _cert
    for _cert in xray.key xray.crt decoy.key decoy.crt; do
        [[ -f "${restore_root}/etc/idleleo/cert/${_cert}" ]] && \
            chmod 640 "${restore_root}/etc/idleleo/cert/${_cert}" 2>/dev/null || true
    done

    # Repair a legacy asset layout before validating the restored config.
    # A failure rolls the layout and config back; never leave a half-healed tree.
    local _legacy_geo_arg=""
    [[ -n "${_legacy_geo_source}" ]] && _legacy_geo_arg="${_legacy_geo_source}/xray"
    if ! restore_geodata_layout_selfheal "${restore_root}" "${_legacy_geo_arg}"; then
        rm -rf "${_legacy_geo_source}"
        log_echo "${Error} ${RedBG} $(gettext "恢复失败: GeoData 资源目录自愈未通过") ${Font}"
        return 1
    fi
    rm -rf "${_legacy_geo_source}"

    # Reload systemd after restored units/config; do not start services here
    # (installation/uninstall semantics stay unchanged).
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || \
            log_echo "${Warning} ${YellowBG} $(gettext "恢复后 daemon-reload 失败, 请手动检查") ${Font}"
    fi

    # Validate the restored Xray config with the restored binary when possible.
    # Point the asset root at the restored tree: with RESTORE_ROOT the default
    # /usr/local/share/xray would otherwise resolve against the live host.
    local _xray_bin="${restore_root%/}${xray_bin_dir}/xray"
    local _xray_config="${restore_root%/}${xray_conf}"
    local _xray_asset="${restore_root%/}${local_bin}/share/xray"
    if [[ -x "${_xray_bin}" && -f "${_xray_config}" ]]; then
        if ! XRAY_LOCATION_ASSET="${_xray_asset}" "${_xray_bin}" run -test -config "${_xray_config}" >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} $(gettext "恢复后 Xray 配置自检失败") ${Font}"
            return 1
        fi
    fi

    # Report the restored script/config versions. They must agree, and the
    # caller still has to reinstall binaries when required.
    local restored_script_version="" restored_config_version=""
    restored_script_version=$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' "${restore_root}/etc/idleleo/install.sh" 2>/dev/null | head -1)
    restored_config_version=$(jq -r '.shell_version // empty' "${restore_root}/etc/idleleo/conf/install_config.json" 2>/dev/null || true)
    log_echo "${OK} ${GreenBG} $(gettext "恢复") $(gettext "成功") ${Font}"
    if [[ -n "${restored_script_version}" ]]; then
        log_echo "${Info} ${Green} $(gettext "已恢复脚本版本"): ${restored_script_version} ${Font}"
        if [[ -n "${restored_config_version}" && "${restored_config_version}" != "${restored_script_version}" ]]; then
            log_echo "${Warning} ${YellowBG} $(gettext "脚本与配置版本不一致, 请重新执行安装") ${Font}"
        fi
    fi
    return 0
}

# ============================================================
# Reinstall backup / restore — directory snapshot taken before
# reinstall/mode-switch, restored on deploy failure.
# ============================================================

# Backup directory for the current reinstall attempt. Empty when nothing to restore.
_reinstall_backup_dir=""
# Firewall transaction state captured at reconfig start (old) and after
# parameters are determined (new), so a partial change can be reversed.
_reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
_reinstall_firewall_old_families=""
_reinstall_firewall_new_families=""
_reinstall_firewall_changed="no"
# Baseline-rule transaction state: OLD family set from ownership before deploy,
# NEW set is the target family policy. Same no/pending/yes contract as above.
_reinstall_baseline_old_families=""
_reinstall_baseline_new_families=""
_reinstall_baseline_changed="no"
# Baseline-rule pending journal: the exact rules THIS transaction created.
# Updated immediately after each successful baseline_rule add, so even if the
# corrective ownership save also fails the global rollback still knows which
# rules to delete. Cleared once ownership is committed (baseline_sync success)
# or after restore + persistence succeed; retained on any failure so orphans
# stay recoverable.
_reinstall_baseline_pending_added_v4=""
_reinstall_baseline_pending_added_v6=""

# RETURN-trap wrapper: restores the backup once on deploy failure; on restore
# failure returns 2 and retains the backup dir for operator inspection.
reinstall_rollback_on_return() {
    local rc="$1"
    local backup_dir="$2"
    trap - RETURN
    if [[ "${rc}" -ne 0 && -n "${backup_dir}" ]]; then
        if ! reinstall_backup_restore "${backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "部署失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
    else
        _reinstall_backup_dir=""
    fi
    return "${rc}"
}

# Canonical cron marker for the project-managed ACME cert-renewal task.
# Detection, backup, restore, dedup and deletion must ALL match this exact
# script path (fixed-string grep) so a user's own ssl_update.sh or another
# project's ACME job is never detected, backed up, restored or deleted.
acme_cron_match_pattern() {
    printf '%s' "${ssl_update_file}"
}

# Create a timestamped backup of the running config before reinstall
# or mode switch. Echoes the backup directory path on stdout.
# Returns 1 if the backup could not be created.
reinstall_backup_create() {
    local backup_dir
    local _backup_root="${idleleo_dir}/backup"
    # Ensure parent directory exists (fail-closed if it cannot be created).
    if ! mkdir -p "${_backup_root}" 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "备份父目录创建失败, 中止重配置") ${Font}"
        return 1
    fi
    # Use mktemp -d for a unique directory (prevents same-second collisions).
    backup_dir=$(mktemp -d "${_backup_root}/reinstall-$(date +%Y%m%d-%H%M%S)-XXXXXX" 2>/dev/null)
    if [[ -z "${backup_dir}" || ! -d "${backup_dir}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份目录创建失败, 中止重配置") ${Font}"
        return 1
    fi

    local _cp_err=0
    # Fail-closed metadata error flag. Set anywhere below (cron line backup,
    # manifest validation, checksum generation) to abort the whole backup.
    local _meta_err=0

    # Critical files — fail closed if they exist but cannot be copied.
    if [[ -f "${xray_install_config_file}" ]]; then
        cp -a "${xray_install_config_file}" "${backup_dir}/install_config.json" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${xray_conf_dir}" ]]; then
        cp -a "${xray_conf_dir}" "${backup_dir}/xray" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${nginx_conf_dir}" ]]; then
        cp -a "${nginx_conf_dir}" "${backup_dir}/nginx" 2>/dev/null || _cp_err=1
    fi
    # Main nginx.conf (outside the project conf dir).
    local _nginx_main_conf="/usr/local/nginx/conf/nginx.conf"
    if [[ -f "${_nginx_main_conf}" ]]; then
        cp -a "${_nginx_main_conf}" "${backup_dir}/nginx.conf" 2>/dev/null || _cp_err=1
    fi
    if [[ -d "${ssl_chainpath}" ]]; then
        cp -a "${ssl_chainpath}" "${backup_dir}/cert" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${managed_ports_file}" ]]; then
        cp -a "${managed_ports_file}" "${backup_dir}/managed_ports.json" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${xray_systemd_file}" ]]; then
        cp -a "${xray_systemd_file}" "${backup_dir}/xray.service" 2>/dev/null || _cp_err=1
    fi
    if [[ -f "${nginx_systemd_file}" ]]; then
        cp -a "${nginx_systemd_file}" "${backup_dir}/nginx.service" 2>/dev/null || _cp_err=1
    fi
    # Share info files — use the canonical xray_info_file path and Clash YAML.
    if [[ -f "${xray_info_file}" ]]; then
        cp -a "${xray_info_file}" "${backup_dir}/xray_info.inf" 2>/dev/null || _cp_err=1
    fi
    local _clash_yaml="${xray_info_file%.*}_clash.yaml"
    if [[ -f "${_clash_yaml}" ]]; then
        cp -a "${_clash_yaml}" "${backup_dir}/xray_info_clash.yaml" 2>/dev/null || _cp_err=1
    fi

    if [[ ${_cp_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "关键文件备份失败, 中止重配置") ${Font}"
        rm -rf "${backup_dir}"
        return 1
    fi

    # Record pre-reinstall state. Use old_tls_mode (source mode) not tls_mode
    # (target mode) so mode-switch backups record the correct source.
    local _source_mode="${old_tls_mode:-${tls_mode:-}}"
    local _xray_active="no" _nginx_active="no" _xray_enabled="no" _nginx_enabled="no"
    systemctl is-active --quiet xray 2>/dev/null && _xray_active="yes"
    systemctl is-active --quiet nginx 2>/dev/null && _nginx_active="yes"
    systemctl is-enabled --quiet xray 2>/dev/null && _xray_enabled="yes"
    systemctl is-enabled --quiet nginx 2>/dev/null && _nginx_enabled="yes"

    # Snapshot actual managed firewall rules.
    local _fw_snapshot=""
    if command -v iptables >/dev/null 2>&1; then
        _fw_snapshot=$(iptables -S 2>/dev/null | grep -i idleleo || true)
    fi

    # Snapshot ACME/cron state for TLS mode. Detection AND the saved task line
    # must match ONLY the project-managed script path. Whether the project cron
    # exists is decided solely by the user crontab containing the exact project
    # script path — never by the presence of $HOME/.acme.sh/acme.sh (which may
    # be missing or relocated while the project cron still exists). The line
    # backup is fail-closed: a failed or empty write invalidates the whole
    # backup, so an "acme_cron=yes" manifest can never point at a missing/empty
    # cron file.
    local _acme_cron="no"
    local _acme_marker
    _acme_marker=$(acme_cron_match_pattern)
    if [[ ${_source_mode} == "TLS" ]]; then
        if crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
            _acme_cron="yes"
            _meta_err=0
            if ! crontab -l 2>/dev/null | grep -F -- "${_acme_marker}" > "${backup_dir}/acme_cron_line.txt" 2>/dev/null; then
                _meta_err=1
            fi
            [[ -s "${backup_dir}/acme_cron_line.txt" ]] || _meta_err=1
        fi
    fi

    # Record file existence manifest. Use a brace group redirected to file
    # (NOT var=$(...)>file, which writes an empty file — the command
    # substitution captures stdout into the var, leaving the redirection
    # target empty).
    {
        echo "{"
        # NOTE: the $(...) command substitutions must NOT escape the inner
        # quotes (\"...\"). GNU bash 3.2 treats `\"` inside a command
        # substitution as a literal backslash+quote, so the path becomes
        # `\"/path\"` and the -f/-d test always fails. Use plain quotes so the
        # manifest records file existence correctly on all bash versions.
        echo "  \"files\": {"
        echo "    \"install_config.json\": $( [[ -f "${xray_install_config_file}" ]] && echo true || echo false),"
        echo "    \"xray_conf_dir\": $( [[ -d "${xray_conf_dir}" ]] && echo true || echo false),"
        echo "    \"nginx_conf_dir\": $( [[ -d "${nginx_conf_dir}" ]] && echo true || echo false),"
        echo "    \"nginx_main_conf\": $( [[ -f "${_nginx_main_conf}" ]] && echo true || echo false),"
        echo "    \"cert_dir\": $( [[ -d "${ssl_chainpath}" ]] && echo true || echo false),"
        echo "    \"info_dir\": $( [[ -d "${idleleo_dir}/info" ]] && echo true || echo false),"
        echo "    \"conf_dir\": $( [[ -d "${idleleo_conf_dir}" ]] && echo true || echo false),"
        echo "    \"managed_ports.json\": $( [[ -f "${managed_ports_file}" ]] && echo true || echo false),"
        echo "    \"xray.service\": $( [[ -f "${xray_systemd_file}" ]] && echo true || echo false),"
        echo "    \"nginx.service\": $( [[ -f "${nginx_systemd_file}" ]] && echo true || echo false),"
        echo "    \"xray_info.inf\": $( [[ -f "${xray_info_file}" ]] && echo true || echo false),"
        echo "    \"xray_info_clash.yaml\": $( [[ -f "${_clash_yaml}" ]] && echo true || echo false)"
        echo "  },"
        echo "  \"source_tls_mode\": \"${_source_mode}\","
        echo "  \"source_transport_mode\": \"${transport_mode:-}\","
        echo "  \"multi_user\": \"$(detect_multi_user_from_xray_conf)\","
        echo "  \"reality_clients\": $(count_reality_clients_in_xray_conf),"
        echo "  \"uuid_set\": $(extract_uuid_set_from_xray_conf | jq -R . | jq -s .),"
        echo "  \"xray_active\": \"${_xray_active}\","
        echo "  \"nginx_active\": \"${_nginx_active}\","
        echo "  \"xray_enabled\": \"${_xray_enabled}\","
        echo "  \"nginx_enabled\": \"${_nginx_enabled}\","
        echo "  \"acme_cron\": \"${_acme_cron}\","
        echo "  \"fw_snapshot\": $(jq -Rn --arg v "${_fw_snapshot}" '$v' 2>/dev/null || echo '""')"
        echo "}"
    } > "${backup_dir}/pre_reinstall_state.json"

    # Generate SHA256 manifest for integrity verification.
    # Use relative paths so verification does not depend on the original
    # absolute backup_dir path (which may differ if the snapshot is moved).
    #
    # Fail-closed metadata validation: a backup whose state manifest is
    # missing/corrupt, or whose checksum list is missing/empty/incomplete, is
    # useless for restore. Any such failure deletes this incomplete backup and
    # returns 1 so the upper layer stops reconfiguration before any change.
    if ! jq empty "${backup_dir}/pre_reinstall_state.json" >/dev/null 2>&1; then
        _meta_err=1
    fi
    ( cd "${backup_dir}" && find . -type f ! -name "sha256sums.txt" -exec sha256sum {} \; 2>/dev/null ) > "${backup_dir}/sha256sums.txt" || _meta_err=1
    [[ -s "${backup_dir}/sha256sums.txt" ]] || _meta_err=1
    grep -q "pre_reinstall_state.json" "${backup_dir}/sha256sums.txt" 2>/dev/null || _meta_err=1
    if [[ ${_meta_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份元数据校验失败, 中止重配置") ${Font}"
        rm -rf "${backup_dir}"
        return 1
    fi

    echo "${backup_dir}"
}

# Restore a previously created reinstall backup.
# Args: <backup_dir>
# Returns 1 on any critical restore failure. Does NOT output "已恢复" on failure.
reinstall_backup_restore() {
    local backup_dir="$1"
    [[ -z "${backup_dir}" || ! -d "${backup_dir}" ]] && return 1

    log_echo "${Warning} ${YellowBG} $(gettext "部署失败, 正在恢复原配置") ${Font}"

    local _restore_err=0

    # Verify backup integrity via SHA256 before restoring (strict fail-closed).
    # Refuses to restore on: missing manifest, missing file, hash mismatch,
    # sha256sum failure, or unparseable manifest line (--strict).
    if [[ ! -f "${backup_dir}/sha256sums.txt" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性清单缺失, 拒绝恢复") ${Font}"
        return 1
    fi
    if ! ( cd "${backup_dir}" && sha256sum --strict -c sha256sums.txt >/dev/null 2>&1 ); then
        log_echo "${Error} ${RedBG} $(gettext "备份完整性校验失败, 拒绝恢复") ${Font}"
        return 1
    fi

    # Stop all services to avoid races during restoration.
    service_stop 2>/dev/null || true

    # Read the pre-reinstall manifest once. It records which managed paths
    # existed before the deploy, so restore can delete anything the failed
    # deploy created that was not there before (P2 manifest-driven cleanup).
    local _pre_state="${backup_dir}/pre_reinstall_state.json"

    # Whether a managed path existed before the reinstall.
    # Returns "true"/"false". Defaults to "true" (restore, not delete) so an
    # unknown path is never wrongly deleted.
    # NOTE: must NOT use `// true` on the value — jq treats an explicit `false`
    # as falsy, so `false // true` yields `true` and a file recorded as absent
    # would be wrongly restored. Only an ABSENT field/-missing manifest should
    # default to "true".
    _manifest_existed() {
        local key="$1"
        if [[ -f "${_pre_state}" ]]; then
            jq -r --arg k "${key}" \
                'if (has("files") and (.files[$k] == false)) then "false" else "true" end' \
                "${_pre_state}" 2>/dev/null || echo true
        else
            echo true
        fi
    }

    # Restore critical files according to the manifest: paths that existed
    # before are restored from backup; paths that did NOT exist before (created
    # by the failed deploy) are removed. Only script-managed paths are touched.
    if [[ "$(_manifest_existed install_config.json)" == "true" ]]; then
        cp -a "${backup_dir}/install_config.json" "${xray_install_config_file}" 2>/dev/null || _restore_err=1
    else
        # Deleting a path that did not exist before must NOT fail the restore
        # when it (or its parent dir) does not exist — e.g. the failed deploy
        # never created it, or the parent was also removed. Only a real error
        # that leaves the path present should count as a failure.
        rm -f "${xray_install_config_file}" 2>/dev/null || [[ ! -e "${xray_install_config_file}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed xray_conf_dir)" == "true" ]]; then
        rm -rf "${xray_conf_dir}" 2>/dev/null
        cp -a "${backup_dir}/xray" "${xray_conf_dir}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${xray_conf_dir}" 2>/dev/null || [[ ! -e "${xray_conf_dir}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed nginx_conf_dir)" == "true" ]]; then
        rm -rf "${nginx_conf_dir}" 2>/dev/null
        cp -a "${backup_dir}/nginx" "${nginx_conf_dir}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${nginx_conf_dir}" 2>/dev/null || [[ ! -e "${nginx_conf_dir}" ]] || _restore_err=1
    fi
    # Restore/delete main nginx.conf (outside the project conf dir).
    local _nginx_main_conf="/usr/local/nginx/conf/nginx.conf"
    if [[ "$(_manifest_existed nginx_main_conf)" == "true" ]]; then
        cp -a "${backup_dir}/nginx.conf" "${_nginx_main_conf}" 2>/dev/null || _restore_err=1
    else
        rm -f "${_nginx_main_conf}" 2>/dev/null || [[ ! -e "${_nginx_main_conf}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed cert_dir)" == "true" ]]; then
        rm -rf "${ssl_chainpath}" 2>/dev/null
        cp -a "${backup_dir}/cert" "${ssl_chainpath}" 2>/dev/null || _restore_err=1
    else
        rm -rf "${ssl_chainpath}" 2>/dev/null || [[ ! -e "${ssl_chainpath}" ]] || _restore_err=1
    fi
    # Project-owned directory tree created by create_directory that is not
    # separately backed up: idleleo_conf_dir (parent of xray/nginx conf dirs)
    # and idleleo_dir/info (share-info files). Restore the true source state:
    # a dir that did not exist before the failed deploy must be removed.
    if [[ "$(_manifest_existed conf_dir)" != "true" ]]; then
        rm -rf "${idleleo_conf_dir}" 2>/dev/null || [[ ! -e "${idleleo_conf_dir}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed info_dir)" != "true" ]]; then
        rm -rf "${idleleo_dir}/info" 2>/dev/null || [[ ! -e "${idleleo_dir}/info" ]] || _restore_err=1
    fi

    # Firewall transaction rollback: reverse rules changed by this deploy
    # ("yes"/"pending"; "no" = untouched). Family-aware: reverse on the recorded
    # OLD families, not current network_mode, so a failed dual -> ipv4 switch
    # restores the cleaned IPv6 rules.
    #
    # Persistence requirement is captured BEFORE rollback; flags are NOT reset
    # by a successful rollback or a reboot would reload the failed deploy.
    local _restore_persist_required=0
    if [[ "${_reinstall_firewall_changed:-}" == "yes" || "${_reinstall_firewall_changed:-}" == "pending" || \
          "${_reinstall_baseline_changed:-}" == "yes" || "${_reinstall_baseline_changed:-}" == "pending" ]]; then
        _restore_persist_required=1
    fi
    if [[ "${_reinstall_firewall_changed:-}" == "yes" || "${_reinstall_firewall_changed:-}" == "pending" ]]; then
        if ! reconcile_managed_firewall \
            "${_reinstall_firewall_new_ports}" \
            "${_reinstall_firewall_old_ports}" \
            "${_reinstall_firewall_new_families:-}" \
            "${_reinstall_firewall_old_families:-}"; then
            log_echo "${Error} ${RedBG} $(gettext "防火墙规则回滚失败") ${Font}"
            _restore_err=1
        fi
    fi
    # Baseline rollback: baseline_sync(old families) removes gained-family rules
    # and re-ensures the source baseline. Same yes/pending contract.
    if [[ "${_reinstall_baseline_changed:-}" == "yes" || "${_reinstall_baseline_changed:-}" == "pending" ]]; then
        # FIRST reverse this transaction's journal: rules may not be in
        # managed_baseline.list (corrective save may have failed). check-then-
        # remove so an already-cleaned rule is not a false rollback failure.
        local _pend_fail=0 _pbin _pkey _pkeys
        for _pbin in iptables ip6tables; do
            if [[ "${_pbin}" == "iptables" ]]; then
                _pkeys="${_reinstall_baseline_pending_added_v4:-}"
            else
                _pkeys="${_reinstall_baseline_pending_added_v6:-}"
            fi
            for _pkey in ${_pkeys}; do
                if baseline_rule "${_pbin}" "${_pkey}" check; then
                    baseline_rule "${_pbin}" "${_pkey}" remove >/dev/null 2>&1 || _pend_fail=1
                fi
            done
        done
        if [[ ${_pend_fail} -ne 0 ]]; then
            # Orphan persists; FAIL and retain journal + backup (do NOT run
            # baseline_sync, which would clear it on success).
            log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则回滚失败") ${Font}"
            _restore_err=1
        else
            # Journal reversed — reconcile to old family set; on failure the
            # journal is retained (cleanup only runs on success).
            if ! baseline_sync "${_reinstall_baseline_old_families:-}"; then
                log_echo "${Error} ${RedBG} $(gettext "基础防火墙规则回滚失败") ${Font}"
                _restore_err=1
            fi
        fi
    fi
    # Persist restored state for old ∪ new families: stale rules.v4/v6 would
    # reload the failed firewall on reboot, so failure is CRITICAL (never
    # print 已恢复原配置).
    if [[ ${_restore_persist_required} -eq 1 ]]; then
        local _restore_persist_families
        _restore_persist_families=$(firewall_persist_families \
            "${_reinstall_firewall_new_families:-}" \
            "${_reinstall_firewall_old_families:-}")
        if ! firewall_persist_rules "${_restore_persist_families}"; then
            log_echo "${Error} ${RedBG} $(gettext "防火墙持久化恢复未完成, 重启后可能回到失败状态") ${Font}"
            _restore_err=1
        fi
    fi
    # Restore or delete managed_ports.json per the manifest.
    if [[ "$(_manifest_existed managed_ports.json)" == "true" ]]; then
        cp -a "${backup_dir}/managed_ports.json" "${managed_ports_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${managed_ports_file}" 2>/dev/null || [[ ! -e "${managed_ports_file}" ]] || _restore_err=1
    fi

    # Restore/delete per-unit systemd files per the manifest. A unit that did
    # NOT exist on the source system must be removed (the failed deploy created
    # it), and must never be enable/disable/start/stop'd afterwards — systemd
    # fails those commands for a missing unit, which would wrongly turn a
    # correct restore into a reported failure.
    local _xray_unit_existed _nginx_unit_existed
    _xray_unit_existed=$(_manifest_existed xray.service)
    _nginx_unit_existed=$(_manifest_existed nginx.service)
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        cp -a "${backup_dir}/xray.service" "${xray_systemd_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_systemd_file}" 2>/dev/null || [[ ! -e "${xray_systemd_file}" ]] || _restore_err=1
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        cp -a "${backup_dir}/nginx.service" "${nginx_systemd_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${nginx_systemd_file}" 2>/dev/null || [[ ! -e "${nginx_systemd_file}" ]] || _restore_err=1
    fi
    # Restore/delete share info — use canonical xray_info_file path and Clash YAML.
    if [[ "$(_manifest_existed xray_info.inf)" == "true" ]]; then
        cp -a "${backup_dir}/xray_info.inf" "${xray_info_file}" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_info_file}" 2>/dev/null || [[ ! -e "${xray_info_file}" ]] || _restore_err=1
    fi
    if [[ "$(_manifest_existed xray_info_clash.yaml)" == "true" ]]; then
        cp -a "${backup_dir}/xray_info_clash.yaml" "${xray_info_file%.*}_clash.yaml" 2>/dev/null || _restore_err=1
    else
        rm -f "${xray_info_file%.*}_clash.yaml" 2>/dev/null || [[ ! -e "${xray_info_file%.*}_clash.yaml" ]] || _restore_err=1
    fi

    systemctl daemon-reload 2>/dev/null || _restore_err=1

    # Reload config state from restored file.
    info_extraction_all=$(jq -rc . "${xray_install_config_file}" 2>/dev/null || echo "{}")
    declare -F _info_cache_invalidate >/dev/null && _info_cache_invalidate 2>/dev/null || true

    # Restore source mode variables from backup state so service_start/stop
    # below uses the SOURCE mode (not the failed target mode).
    if [[ -f "${_pre_state}" ]]; then
        local _src_mode
        _src_mode=$(jq -r '.source_tls_mode // empty' "${_pre_state}" 2>/dev/null)
        [[ -n "${_src_mode}" ]] && old_tls_mode="${_src_mode}" && tls_mode="${_src_mode}"
        local _src_transport
        _src_transport=$(jq -r '.source_transport_mode // empty' "${_pre_state}" 2>/dev/null)
        [[ -n "${_src_transport}" ]] && transport_mode="${_src_transport}"
    fi

    # Restore service active/enabled state per the pre-reinstall snapshot.
    # Units that did NOT exist on the source system are NEVER
    # enable/disable/start/stop'd — systemd fails those commands for a missing
    # unit, which would wrongly turn a correct restore into a reported failure.
    local _pre_xray_active="no" _pre_nginx_active="no"
    local _pre_xray_enabled="no" _pre_nginx_enabled="no"
    if [[ -f "${_pre_state}" ]]; then
        _pre_xray_active=$(jq -r '.xray_active // "no"' "${_pre_state}" 2>/dev/null)
        _pre_nginx_active=$(jq -r '.nginx_active // "no"' "${_pre_state}" 2>/dev/null)
        _pre_xray_enabled=$(jq -r '.xray_enabled // "no"' "${_pre_state}" 2>/dev/null)
        _pre_nginx_enabled=$(jq -r '.nginx_enabled // "no"' "${_pre_state}" 2>/dev/null)
    fi
    # Enabled state — propagate failures instead of swallowing with || true.
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        if [[ "${_pre_xray_enabled}" == "yes" ]]; then
            systemctl enable xray 2>/dev/null || _restore_err=1
        else
            systemctl disable xray 2>/dev/null || _restore_err=1
        fi
        if [[ "${_pre_xray_active}" == "yes" ]]; then
            systemctl start xray 2>/dev/null || _restore_err=1
        else
            systemctl stop xray 2>/dev/null || _restore_err=1
        fi
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        if [[ "${_pre_nginx_enabled}" == "yes" ]]; then
            systemctl enable nginx 2>/dev/null || _restore_err=1
        else
            systemctl disable nginx 2>/dev/null || _restore_err=1
        fi
        if [[ "${_pre_nginx_active}" == "yes" ]]; then
            systemctl start nginx 2>/dev/null || _restore_err=1
        else
            systemctl stop nginx 2>/dev/null || _restore_err=1
        fi
    fi

    if [[ ${_restore_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "恢复未完全成功, 请手动检查") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
        return 1
    fi

    # Bidirectional verification: active AND enabled states must match the
    # snapshot for units that existed before. Units that did NOT exist before
    # must be gone from systemd entirely — if systemd still sees them as
    # loaded/active/enabled, the restore must fail and report it clearly.
    if [[ "${_xray_unit_existed}" == "true" ]]; then
        if [[ "${_pre_xray_active}" == "yes" ]] && ! systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后未运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_active}" == "no" ]] && systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍在运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_enabled}" == "yes" ]] && ! systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后未启用") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_xray_enabled}" == "no" ]] && systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍启用") ${Font}"
            _restore_err=1
        fi
    else
        if systemctl is-active --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍被 systemd 加载为 active, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
        if systemctl is-enabled --quiet xray 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Xray 服务恢复后仍为 enabled, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
    fi
    if [[ "${_nginx_unit_existed}" == "true" ]]; then
        if [[ "${_pre_nginx_active}" == "yes" ]] && ! systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后未运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_active}" == "no" ]] && systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍在运行") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_enabled}" == "yes" ]] && ! systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后未启用") ${Font}"
            _restore_err=1
        fi
        if [[ "${_pre_nginx_enabled}" == "no" ]] && systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍启用") ${Font}"
            _restore_err=1
        fi
    else
        if systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍被 systemd 加载为 active, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
        if systemctl is-enabled --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务恢复后仍为 enabled, 但原系统无此 unit") ${Font}"
            _restore_err=1
        fi
    fi

    # Restore ACME/cron state if it was recorded as active before reinstall.
    # All detection, dedup and verification below matches the project's exact
    # managed script path so user-owned ssl_update.sh tasks are never touched.
    local _pre_acme_cron="no"
    local _acme_marker
    _acme_marker=$(acme_cron_match_pattern)
    if [[ -f "${_pre_state}" ]]; then
        _pre_acme_cron=$(jq -r '.acme_cron // "no"' "${_pre_state}" 2>/dev/null)
    fi
    if [[ "${_pre_acme_cron}" == "yes" ]]; then
        # Restore via the standard crontab interface (works on Debian, CentOS,
        # Rocky, AlmaLinux alike — no spool path assumptions). Only append if
        # the managed ssl_update.sh line is missing, to avoid duplicates.
        if ! crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
            if [[ -s "${backup_dir}/acme_cron_line.txt" ]]; then
                {
                    crontab -l 2>/dev/null || true
                    cat "${backup_dir}/acme_cron_line.txt" 2>/dev/null
                } | crontab - || _restore_err=1
                # Verify the restore actually took effect.
                if ! crontab -l 2>/dev/null | grep -Fq -- "${_acme_marker}"; then
                    log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务未能恢复, 请手动检查") ${Font}"
                    _restore_err=1
                fi
            else
                log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务未能恢复, 请手动检查") ${Font}"
                _restore_err=1
            fi
        fi
    elif [[ "${_pre_acme_cron}" == "no" ]]; then
        # The source system had NO script-managed ssl_update.sh cron. A failed
        # deploy may have added one — remove only the line matching the exact
        # project path while preserving every other user crontab line, using
        # the standard `crontab -l` / filter / `crontab -` interface (never the
        # spool files). A failed write or a leftover line fails the restore.
        local _cron_before="" _cron_filtered=""
        _cron_before=$(crontab -l 2>/dev/null || true)
        if printf '%s\n' "${_cron_before}" | grep -Fq -- "${_acme_marker}"; then
            # grep -v exits 1 when it drops the LAST line (crontab becomes
            # empty) — that is a successful removal, not a failure.
            _cron_filtered=$(printf '%s\n' "${_cron_before}" | grep -Fv -- "${_acme_marker}" || true)
            if [[ -n "${_cron_filtered}" ]]; then
                printf '%s\n' "${_cron_filtered}" | crontab - 2>/dev/null || _restore_err=1
            else
                # Nothing left: install an empty crontab.
                : | crontab - 2>/dev/null || _restore_err=1
            fi
            if printf '%s\n' "$(crontab -l 2>/dev/null)" | grep -Fq -- "${_acme_marker}"; then
                log_echo "${Warning} ${YellowBG} $(gettext "ACME 定时任务删除后仍存在, 请手动检查") ${Font}"
                _restore_err=1
            fi
        fi
    fi

    if [[ ${_restore_err} -ne 0 ]]; then
        log_echo "${Error} ${RedBG} $(gettext "恢复后验证失败, 请手动检查") ${Font}"
        log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${backup_dir} ${Font}"
        return 1
    fi

    # Rollback succeeded — reset the firewall transaction for the next attempt.
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_old_families=""
    _reinstall_firewall_new_families=""
    _reinstall_firewall_changed="no"
    _reinstall_baseline_old_families=""
    _reinstall_baseline_new_families=""
    _reinstall_baseline_changed="no"
    # Rollback + persistence both succeeded — the pending journal is fully
    # consumed; clear it. (On any earlier failure we return before here, so a
    # failed rollback retains the journal for diagnosis/retry.)
    _reinstall_baseline_pending_added_v4=""
    _reinstall_baseline_pending_added_v6=""

    log_echo "${OK} ${GreenBG} $(gettext "已恢复原配置") ${Font}"
    return 0
}

# Validate the newly deployed config. Returns non-zero if any check fails.
reinstall_validate_deploy() {
    if [[ -f "${xray_conf}" ]] && ! ${xray_bin_dir}/xray run -test -config "${xray_conf}" >/dev/null 2>&1; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 配置测试失败") ${Font}"
        return 1
    fi
    if [[ -x "${nginx_dir}/sbin/nginx" ]] && [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if ! "${nginx_dir}/sbin/nginx" -t >/dev/null 2>&1; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 配置测试失败") ${Font}"
            return 1
        fi
    fi
    if ! systemctl is-active --quiet xray 2>/dev/null; then
        log_echo "${Error} ${RedBG} $(gettext "Xray 服务未运行") ${Font}"
        return 1
    fi
    if [[ -x "${nginx_dir}/sbin/nginx" ]] && [[ ${tls_mode} == "TLS" || ${reality_add_nginx} == "on" ]]; then
        if ! systemctl is-active --quiet nginx 2>/dev/null; then
            log_echo "${Error} ${RedBG} $(gettext "Nginx 服务未运行") ${Font}"
            return 1
        fi
    fi
    return 0
}

# Verify user identity set was preserved across a keep-config reinstall.
# Args: <backup_dir>
# Returns 1 if UUID set changed. Skipped for mode_switch and standard_rebuild
# since those operations legitimately change the user set.
reinstall_verify_preservation() {
    local backup_dir="$1"
    [[ -z "${backup_dir}" || ! -f "${backup_dir}/pre_reinstall_state.json" ]] && return 0

    # Skip preservation check for mode_switch and standard_rebuild — these
    # Operations legitimately change the user set.
    case "${reinstall_operation}" in
        mode_switch|standard_rebuild|clean_install)
            return 0
            ;;
    esac

    # For keep_config: verify UUID set is unchanged.
    local pre_uuids post_uuids
    pre_uuids=$(jq -r '.uuid_set[]?' "${backup_dir}/pre_reinstall_state.json" 2>/dev/null | sort)
    post_uuids=$(extract_uuid_set_from_xray_conf | sort)

    if [[ "${pre_uuids}" != "${post_uuids}" ]]; then
        log_echo "${Error} ${RedBG} $(gettext "用户 UUID 集合发生变化, 将恢复原配置") ${Font}"
        return 1
    fi
    return 0
}

# Final safety gate called at the end of every install_xray_* path.
# Validates the freshly deployed config and verifies user counts were
# preserved across the reinstall. On any failure, restores the backup
# and returns non-zero so the caller can surface the error.
# No-op when no backup was created (fresh install or test mode).
reinstall_finalize() {
    [[ -z "${_reinstall_backup_dir}" ]] && return 0
    if ! reinstall_validate_deploy; then
        if ! reinstall_backup_restore "${_reinstall_backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "最终验证失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${_reinstall_backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
        return 1
    fi
    if ! reinstall_verify_preservation "${_reinstall_backup_dir}"; then
        if ! reinstall_backup_restore "${_reinstall_backup_dir}"; then
            log_echo "${Error} ${RedBG} $(gettext "最终验证失败且自动恢复未完成") ${Font}"
            log_echo "${Warning} ${YellowBG} $(gettext "备份目录保留在"): ${_reinstall_backup_dir} ${Font}"
            return 2
        fi
        _reinstall_backup_dir=""
        return 1
    fi
    _reinstall_backup_dir=""
    # Transaction completed — clear firewall transaction state so a later
    # standalone firewall_set or a subsequent reinstall cannot be polluted by
    # the previous transaction's recorded families/ports.
    _reinstall_firewall_old_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_new_ports='{"tcp":[],"udp":[]}'
    _reinstall_firewall_old_families=""
    _reinstall_firewall_new_families=""
    _reinstall_firewall_changed="no"
    _reinstall_baseline_old_families=""
    _reinstall_baseline_new_families=""
    _reinstall_baseline_changed="no"
    return 0
}

menu_clear() {
    if [[ -t 1 && -n ${TERM:-} && ${TERM} != "dumb" && -z "${NO_COLOR:-}" ]]; then
        clear
    else
        echo
    fi
}

menu_prepare_width() {
    local terminal_columns="" max_box_width=60 size=""

    # Query the controlling terminal first. tmux/detached sessions do not
    # necessarily keep fd 1 a TTY, and `[[ -t 1 ]]` inside a pipeline is false,
    # which previously pinned the box at 60 columns even in a 45-column pane.
    size=$(stty size 2>/dev/null </dev/tty || true)
    terminal_columns=${size#* }
    if ! [[ ${terminal_columns} =~ ^[0-9]+$ ]]; then
        terminal_columns="${COLUMNS:-}"
    fi
    if ! [[ ${terminal_columns} =~ ^[0-9]+$ ]] && command -v tput >/dev/null 2>&1; then
        terminal_columns=$(tput cols 2>/dev/null || true)
    fi
    [[ ${terminal_columns} =~ ^[0-9]+$ ]] || terminal_columns=80

    MENU_BOX_WIDTH=$((terminal_columns - 4))
    ((MENU_BOX_WIDTH > max_box_width)) && MENU_BOX_WIDTH=${max_box_width}
    if ((MENU_BOX_WIDTH < 52)); then
        MENU_BOX_WIDTH=$((terminal_columns - 2))
    fi
    ((MENU_BOX_WIDTH < 20)) && MENU_BOX_WIDTH=20
}

menu_ensure_width() {
    [[ ${MENU_BOX_WIDTH:-} =~ ^[0-9]+$ ]] || menu_prepare_width
}

menu_visible_width() {
    local plain_text visible_width
    plain_text=$(printf '%b' "$1" | sed $'s/\033\\[[0-9;]*m//g')
    if ! visible_width=$(printf '%s' "${plain_text}" | LC_ALL=C.UTF-8 wc -L 2>/dev/null); then
        visible_width=$(printf '%s' "${plain_text}" | wc -L 2>/dev/null)
    fi
    visible_width=${visible_width//[[:space:]]/}
    if [[ ${visible_width} =~ ^[0-9]+$ ]]; then
        printf '%s' "${visible_width}"
    else
        printf '%s' "${#plain_text}"
    fi
}

menu_repeat() {
    local character="$1" count="$2" index
    for ((index = 0; index < count; index++)); do
        printf '%s' "${character}"
    done
}

# East Asian Ambiguous symbols used by the menus render one cell.
menu_char_width() {
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

# Truncate overlong menu text by display width. Colors are dropped for this
# row because slicing ANSI sequences safely is not worth the complexity; the
# surrounding border keeps its colors.
menu_truncate_visible() {
    local text="$1" max="$2" out="" i=0 n w=0 c v step cw ch
    local LC_ALL=C
    text=$(printf '%b' "${text}" | sed $'s/\033\\[[0-9;]*m//g')
    n=${#text}
    while ((i < n)); do
        c=${text:i:1}
        v=$(printf '%d' "'$c" 2>/dev/null) || v=63
        # bash 3.2 reports high bytes as negative signed chars.
        ((v < 0)) && v=$((v + 256))
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
        ch=${text:i:step}
        cw=$(menu_char_width "${ch}" "${step}")
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

menu_title() {
    local title="$1" title_width line_count max
    menu_prepare_width
    # Keep at least one dash after the title: 5 fixed cells + title + 1 dash.
    max=$((MENU_BOX_WIDTH - 6))
    title_width=$(menu_visible_width "${title}")
    if ((title_width > max)); then
        title=$(menu_truncate_visible "${title}" "${max}")
        title_width=$(menu_visible_width "${title}")
    fi
    line_count=$((MENU_BOX_WIDTH - title_width - 5))
    ((line_count < 1)) && line_count=1

    printf '%b╭─ %b%b %b' "${GreenW}" "${Font}" "${title}" "${GreenW}"
    menu_repeat '─' "${line_count}"
    printf '╮%b\n' "${Font}"
}

menu_footer() {
    menu_ensure_width
    printf '%b╰' "${GreenW}"
    menu_repeat '─' "$((MENU_BOX_WIDTH - 2))"
    printf '╯%b\n' "${Font}"
}

menu_divider() {
    local title="$1" title_width line_count max
    menu_ensure_width
    # Keep at least one dash after the title: 5 fixed cells + title + 1 dash.
    max=$((MENU_BOX_WIDTH - 6))
    title_width=$(menu_visible_width "${title}")
    if ((title_width > max)); then
        title=$(menu_truncate_visible "${title}" "${max}")
        title_width=$(menu_visible_width "${title}")
    fi
    line_count=$((MENU_BOX_WIDTH - title_width - 5))
    ((line_count < 1)) && line_count=1

    printf '%b├─ %b%b %b' "${GreenW}" "${Font}" "${title}" "${GreenW}"
    menu_repeat '─' "${line_count}"
    printf '┤%b\n' "${Font}"
}

menu_row() {
    local content="$1" content_width padding max
    menu_ensure_width
    max=$((MENU_BOX_WIDTH - 4))
    content_width=$(menu_visible_width "${content}")
    if ((content_width > max)); then
        content=$(menu_truncate_visible "${content}" "${max}")
        content_width=$(menu_visible_width "${content}")
    fi
    padding=$((MENU_BOX_WIDTH - content_width - 4))
    ((padding < 0)) && padding=0

    printf '%b│%b %b' "${GreenW}" "${Font}" "${content}"
    printf '%*s' "${padding}" ''
    printf '%b │%b\n' "${GreenW}" "${Font}"
}

# Word-wrap a single long label across multiple menu rows. This keeps the
# Rill health sentence inside the box instead of truncating it to one line.
menu_wrapped_row() {
    local text="$1" line="" word candidate candidate_width max
    local -a words=()
    menu_ensure_width
    max=$((MENU_BOX_WIDTH - 4))
    read -ra words <<<"${text}"
    for word in "${words[@]}"; do
        if [[ -z "${line}" ]]; then
            line="${word}"
            continue
        fi
        candidate="${line} ${word}"
        candidate_width=$(menu_visible_width "${candidate}")
        if ((candidate_width <= max)); then
            line="${candidate}"
        else
            menu_row "${line}"
            line="${word}"
        fi
    done
    [[ -n "${line}" ]] && menu_row "${line}"
}

_menu_fields_render() {
    local add_vertical_padding="$1"
    shift
    local field current="" candidate candidate_width max_width
    menu_ensure_width
    max_width=$((MENU_BOX_WIDTH - 4))

    [[ ${add_vertical_padding} == "1" ]] && menu_blank

    for field in "$@"; do
        if [[ -z ${current} ]]; then
            current="${field}"
            continue
        fi
        candidate="${current}  ·  ${field}"
        candidate_width=$(menu_visible_width "${candidate}")
        if ((candidate_width <= max_width)); then
            current="${candidate}"
        else
            menu_row "${current}"
            current="${field}"
        fi
    done
    if [[ -n ${current} ]]; then
        menu_row "${current}"
        [[ ${add_vertical_padding} == "1" ]] && menu_blank
    fi
}

menu_fields() {
    _menu_fields_render 0 "$@"
}

menu_spaced_fields() {
    _menu_fields_render 1 "$@"
}

menu_blank() {
    menu_row ""
}

menu_item() {
    local item
    printf -v item '%b%2s.%b %s' "${Green}" "$1" "${Font}" "$2"
    menu_row "${item}"
}

menu_pause() {
    echo
    read -rp "$(gettext "回到菜单") [Enter] " _ || true
}

menu_read() {
    local target_var="$1"
    local max_value="$2"
    read_optimize "$(gettext "请输入选项"): " "${target_var}" "NULL" 0 "${max_value}" "$(gettext "请输入有效的数字")!"
}

menu_submenu_begin() {
    menu_clear
    menu_title "$1"
    menu_blank
}

menu_action() {
    case $1 in
    0)
        update_sh
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    1)
        xray_update
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    2)
        echo
        log_echo "${Red}[$(gettext "不建议")]${Font} $(gettext "频繁更新 Nginx, 请确认 Nginx 有更新的必要")!"
        countdown "$(gettext "开始更新")!"
        nginx_update
        exec "${BASH:-bash}" "${idleleo}"
        ;;
     3)
        shell_mode="Reality"
        tls_mode="Reality"
        install_xray_reality
        local install_rc=$?
        if [[ ${install_rc} -eq 0 ]]; then
            exec "${BASH:-bash}" "${idleleo}"
        fi
        if [[ ${install_rc} -eq 2 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
        fi
        return "${install_rc}"
        ;;
     4)
        shell_mode="Nginx+ws+TLS"
        tls_mode="TLS"
        install_xray_ws_tls
        local install_rc=$?
        if [[ ${install_rc} -eq 0 ]]; then
            exec "${BASH:-bash}" "${idleleo}"
        fi
        if [[ ${install_rc} -eq 2 ]]; then
            log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
        else
            log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
        fi
        return "${install_rc}"
        ;;
     5)
        echo
        log_echo "${Warning} ${YellowBG} $(gettext "此模式推荐用于负载均衡, 一般情况不推荐使用, 是否安装") [Y/${Red}N${Font}${YellowBG}]? ${Font}"
        read -r wsonly_fq
        case $wsonly_fq in
        [yY][eE][sS] | [yY])
            shell_mode="ws ONLY"
            tls_mode="None"
            install_xray_ws_only
            local install_rc=$?
            if [[ ${install_rc} -eq 0 ]]; then
                exec "${BASH:-bash}" "${idleleo}"
            fi
            if [[ ${install_rc} -eq 2 ]]; then
                log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
            else
                log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
            fi
            return "${install_rc}"
            ;;
        *) ;;
        esac
        ;;
     6)
        menu_install_relay
        ;;
    7)
        reset_UUID
        judge -r "$(gettext "变更") UUIDv5/$(gettext "映射字符串")"
        menu_pause
        ;;
    8)
        reset_port
        judge -r "$(gettext "变更") port"
        menu_pause
        ;;
    9)
        reset_target
        judge -r "$(gettext "变更") target"
        menu_pause
        ;;
    10)
        tls_type
        judge -r "$(gettext "变更") TLS $(gettext "版本")"
        menu_pause
        ;;
    11)
        nginx_upstream_server_set
        menu_pause
        ;;
    12)
        nginx_servernames_server_set
        menu_pause
        ;;
    39)
        reset_sni_guard_policy
        judge -r "$(gettext "变更") SNI Guard"
        menu_pause
        ;;
    13)
        show_user
        menu_pause
        ;;
    14)
        if service_stop; then
            add_user && service_start
        fi
        menu_pause
        ;;
    15)
        if service_stop; then
            remove_user && service_start
        fi
        menu_pause
        ;;
    16)
        clear
        show_access_log
        menu_pause
        ;;
    17)
        clear
        show_error_log
        menu_pause
        ;;
    18)
        clear
        basic_information
        install_link_image
        show_information
        menu_pause
        ;;
    19)
        clear
        monitor_traffic_with_iftop
        menu_pause
        ;;
    20)
        service_restart
        check_program
        check_xray_local_connect
        menu_pause
        ;;
    21)
        if service_start; then
            check_program
            check_xray_local_connect
        else
            log_echo "${Error} ${RedBG} $(gettext "所有服务") $(gettext "启动") $(gettext "失败") ${Font}"
        fi
        menu_pause
        ;;
    22)
        if service_stop; then
            check_program
            check_xray_local_connect
        else
            log_echo "${Error} ${RedBG} $(gettext "所有服务") $(gettext "停止") $(gettext "失败") ${Font}"
        fi
        menu_pause
        ;;
    23)
        if [[ ${tls_mode} == "TLS" ]] || [[ ${reality_add_nginx} == "on" ]]; then
            systemctl status nginx
        fi
        systemctl status xray
        menu_pause
        ;;
    24)
        check_cert_status
        menu_pause
        ;;
    25)
        cert_update_manuel
        menu_pause
        ;;
    26)
        acme_cron_update
        menu_pause
        ;;
    27)
        auto_update
        menu_pause
        ;;
    28)
        clear
        bbr_boost_sh
        menu_pause
        ;;
    29)
        set_fail2ban
        ;;
    30)
        xray_status_add
        menu_pause
        ;;
    40)
        menu_xray_stats
        ;;
    41)
        set_geodata_menu
        ;;
    31)
        set_traffic_blocker
        ;;
    32)
        clean_logs
        menu_pause
        ;;
    33)
        clear
        read -r -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        local superspeed_script="${idleleo_dir}/tmp/superspeed.sh"
        if download_script_file "https://cdn.jsdelivr.net/gh/hello-yunshu/superspeed@master/superspeed.sh" "$superspeed_script"; then
            bash "$superspeed_script"
            rm -f "$superspeed_script"
        else
            log_echo "${Error} ${RedBG} $(gettext "网速测试脚本下载失败") ${Font}"
        fi
        read -r -t 0.1 -n 10000 -d '' _ </dev/tty 2>/dev/null || true
        menu_pause
        ;;
    34)
        backup_directories
        menu_pause
        ;;
    35)
        if confirm_no_answer "$(gettext "将用最新备份覆盖当前配置与程序, 是否继续")"; then
            restore_directories
        fi
        menu_pause
        ;;
    36)
        if confirm_no_answer "$(gettext "将停止并卸载 Xray/Nginx, 是否继续")"; then
            uninstall_all
            exec "${BASH:-bash}" "${idleleo}"
        fi
        ;;
    37)
        if confirm_no_answer "$(gettext "将删除 ACME 证书与证书残留文件, 是否继续")"; then
            delete_tls_key_and_crt
            rm -rf "${ssl_chainpath:?}"/*
        fi
        menu_pause
        ;;
    38)
        exit 0
        ;;
    99)
        set_language
        exec "${BASH:-bash}" "${idleleo}"
        ;;
    esac
}

# Fourth-level menu: choose transport protocol (ws/gRPC/xHTTP).
# Sets transport_mode and returns 0 on success, 1 on "0. return".
menu_choose_transport() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "选择传输协议")"
        menu_item 1 "ws"
        menu_item 2 "gRPC"
        menu_item 3 "xHTTP"
        menu_item 4 "ws+xHTTP"
        menu_item 5 "ws+gRPC+xHTTP"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return 1 ;;
            1) transport_mode="onlyws"; return 0 ;;
            2) transport_mode="onlygRPC"; return 0 ;;
            3) transport_mode="onlyxhttp"; return 0 ;;
            4) transport_mode="wsxhttp"; return 0 ;;
            5) transport_mode="wsgRPCxhttp"; return 0 ;;
        esac
    done
}

# Third-level menu: Reality deployment methods.
menu_install_reality() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "Reality 部署方式")"
        menu_item 1 "Reality + Nginx $(gettext "前置保护")($(gettext "推荐"))"
        menu_item 2 "$(gettext "标准") Reality"
        menu_item 3 "Reality + ws/gRPC/xHTTP"
        menu_item 4 "Reality + ws/gRPC/xHTTP + Nginx"
        menu_item 5 "Reality $(gettext "负载均衡")($(gettext "高级"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return ;;
            1)
                reset_install_wizard_state
                install_profile="reality_nginx"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="reality_standard"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            3)
                reset_install_wizard_state
                install_profile="reality_transport"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            4)
                reset_install_wizard_state
                install_profile="reality_transport_nginx"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            5)
                menu_install_reality_balance_role || continue
                ;;
        esac
    done
}

# Fourth-level menu: Reality load-balancing role selection.
# Primary installs Nginx front-end + upstream; secondary only provides Reality backend.
menu_install_reality_balance_role() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "Reality 负载均衡角色")"
        menu_item 1 "$(gettext "主服务器")($(gettext "安装 Nginx"))"
        menu_item 2 "$(gettext "二级服务器")($(gettext "仅提供 Reality 后端"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return 1 ;;
            1)
                reset_install_wizard_state
                install_profile="reality_balance_primary"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="reality_balance_secondary"
                install_wizard_preset="on"
                apply_install_profile
                install_xray_reality
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
        esac
    done
}

# ws/gRPC/xHTTP ONLY has no transport encryption: default to loopback and let
# the operator explicitly opt into another (trusted, e.g. internal) address.
ws_listen_address_choose() {
    local _listen_custom_fq
    ws_backend_listen_addr="$(ws_backend_listen_default)"
    echo
    log_echo "${Warning} ${YellowBG} $(gettext "此模式没有传输层加密, 仅应用于可信后端链路") ${Font}"
    log_echo "${GreenBG} $(gettext "默认仅监听") $(ws_backend_listen_default), $(gettext "是否需要指定其他监听地址") [y/${Red}N${Font}${GreenBG}]? ${Font}"
    read -r _listen_custom_fq
    case ${_listen_custom_fq:-} in
    [yY][eE][sS] | [yY])
        while true; do
            read_optimize "$(gettext "请输入监听地址") ($(gettext "例如") 10.0.0.2): " "ws_backend_listen_addr" "NULL" || return 1
            if is_valid_listen_address "${ws_backend_listen_addr}"; then
                break
            fi
            log_echo "${Error} ${RedBG} $(gettext "监听地址无效, 请重新输入")! ${Font}"
        done
        ;;
    *) ;;
    esac
    log_echo "${Green} $(gettext "监听地址") (listen): ${ws_backend_listen_addr} ${Font}"
    return 0
}

# Third-level menu: ws/gRPC/xHTTP deployment methods.
menu_install_transport() {
    local menu_num
    while true; do
        menu_submenu_begin "ws/gRPC/xHTTP $(gettext "部署方式")"
        menu_item 1 "Nginx + TLS ($(gettext "推荐"))"
        menu_item 2 "ONLY ($(gettext "无 Nginx、无传输层加密")，$(gettext "仅限可信后端")，$(gettext "高级"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1)
                reset_install_wizard_state
                install_profile="transport_nginx_tls"
                menu_choose_transport || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_ws_tls
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
            2)
                reset_install_wizard_state
                install_profile="transport_only"
                echo
                log_echo "${Warning} ${YellowBG} $(gettext "ONLY 模式没有传输层加密, 主要用于中转、负载均衡后端或已有上层代理的环境") ${Font}"
                log_echo "${GreenBG} $(gettext "是否继续") [Y/${Red}N${Font}${GreenBG}]? ${Font}"
                read -r wsonly_fq
                case ${wsonly_fq:-} in
                    [yY][eE][sS] | [yY]) ;;
                    *) continue ;;
                esac
                menu_choose_transport || continue
                ws_listen_address_choose || continue
                install_wizard_preset="on"
                apply_install_profile
                install_xray_ws_only
                local install_rc=$?
                if [[ ${install_rc} -eq 0 ]]; then
                    exec "${BASH:-bash}" "${idleleo}"
                fi
                if [[ ${install_rc} -eq 2 ]]; then
                    log_echo "${Error} ${RedBG} $(gettext "安装失败且自动恢复失败, 备份已保留, 请手动检查") ${Font}"
                else
                    log_echo "${Error} ${RedBG} $(gettext "安装失败, 原配置已恢复") ${Font}"
                fi
                return "${install_rc}"
                ;;
        esac
    done
}

# Second-level menu: install wizard main (protocol category selection).
menu_install() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "安装向导")"
        menu_item 1 "Reality"
        menu_item 2 "ws/gRPC/xHTTP"
        menu_item 3 "$(gettext "中转节点") ($(gettext "Nginx Stream TCP 转发"))"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_install_reality ;;
            2) menu_install_transport ;;
            3)
                # Propagate the relay install rc so the caller (and the test
                # harness) can distinguish success from a failed install.
                menu_install_relay
                return $?
                ;;
        esac
    done
}

menu_user_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "用户管理")"
        menu_item 1 "$(gettext "查看") Xray $(gettext "用户")"
        menu_item 2 "$(gettext "添加") Xray $(gettext "用户")"
        menu_item 3 "$(gettext "删除") Xray $(gettext "用户")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_action 13 ;;
            2) menu_action 14 ;;
            3) menu_action 15 ;;
        esac
    done
}

menu_connection_config() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "配置变更")"
        menu_item 1 "$(gettext "变更") UUIDv5/$(gettext "映射字符串")"
        menu_item 2 "$(gettext "变更") port"
        menu_item 3 "$(gettext "变更") target"
        menu_item 4 "$(gettext "变更") TLS $(gettext "版本")"
        menu_item 5 "$(gettext "变更") SNI Guard"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 5
        case $menu_num in
            0) return ;;
            1) menu_action 7 ;;
            2) menu_action 8 ;;
            3) menu_action 9 ;;
            4) menu_action 10 ;;
            5) menu_action 39 ;;
        esac
    done
}

menu_nginx_config() {
    local menu_num
    while true; do
        menu_submenu_begin "Nginx $(gettext "配置")"
        menu_item 1 "$(gettext "负载均衡")"
        menu_item 2 "serverNames"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1) menu_action 11 ;;
            2) menu_action 12 ;;
        esac
    done
}

menu_config() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "配置变更")"
        menu_item 1 "$(gettext "用户管理")"
        menu_item 2 "$(gettext "配置变更")"
        menu_item 3 "Nginx $(gettext "配置")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_user_management ;;
            2) menu_connection_config ;;
            3) menu_nginx_config ;;
        esac
    done
}

menu_information() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "查看信息")"
        menu_item 1 "Xray $(gettext "配置信息")"
        menu_item 2 "Xray $(gettext "实时访问日志")"
        menu_item 3 "Xray $(gettext "实时错误日志")"
        menu_item 4 "port $(gettext "实时流量")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 18 ;;
            2) menu_action 16 ;;
            3) menu_action 17 ;;
            4) menu_action 19 ;;
        esac
    done
}

menu_service_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "服务相关")"
        menu_item 1 "$(gettext "重启") $(gettext "所有服务")"
        menu_item 2 "$(gettext "启动") $(gettext "所有服务")"
        menu_item 3 "$(gettext "停止") $(gettext "所有服务")"
        menu_item 4 "$(gettext "查看") $(gettext "所有服务")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 20 ;;
            2) menu_action 21 ;;
            3) menu_action 22 ;;
            4) menu_action 23 ;;
        esac
    done
}

menu_certificate_management() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "证书相关")"
        menu_item 1 "$(gettext "证书状态")"
        menu_item 2 "$(gettext "证书有效期")"
        menu_item 3 "$(gettext "证书自动更新")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 3
        case $menu_num in
            0) return ;;
            1) menu_action 24 ;;
            2) menu_action 25 ;;
            3) menu_action 26 ;;
        esac
    done
}

menu_service_and_certificate() {
    local menu_num
    while true; do
        menu_submenu_begin "Xray / TLS"
        menu_item 1 "$(gettext "服务相关")"
        menu_item 2 "$(gettext "证书相关")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 2
        case $menu_num in
            0) return ;;
            1) menu_service_management ;;
            2) menu_certificate_management ;;
        esac
    done
}

menu_update() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "更新向导")"
        menu_item 1 "$(gettext "更新") $(gettext "脚本")"
        menu_item 2 "$(gettext "更新") Xray"
        menu_item 3 "$(gettext "更新") Nginx"
        menu_item 4 "$(gettext "配置") $(gettext "自动更新")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 0 ;;
            2) menu_action 1 ;;
            3) menu_action 2 ;;
            4) menu_action 27 ;;
        esac
    done
}

menu_xray_stats() {
    local menu_num stats_state listen
    while true; do
        stats_state=$(gettext "未开启")
        if [[ -f "${xray_conf}" ]] && jq -e 'has("stats")' "${xray_conf}" >/dev/null 2>&1; then
            stats_state=$(gettext "已开启")
            listen=$(jq -r '.api.listen // empty' "${xray_conf}" 2>/dev/null) || listen=""
            if [[ -n "${listen}" ]]; then
                stats_state+=" (${listen})"
            else
                stats_state+=" ($(gettext "缺少 api.listen"))"
            fi
        fi
        menu_submenu_begin "Xray $(gettext "流量统计")"
        menu_row "${Green}$(gettext "当前状态"): ${Font}${stats_state}"
        menu_blank
        menu_item 1 "$(gettext "开启/关闭统计")"
        menu_item 2 "$(gettext "查看统计")"
        menu_item 3 "$(gettext "重置统计")"
        menu_item 4 "$(gettext "实时监控")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 30 ;;
            2) xray_stats_cli stats; menu_pause ;;
            3) xray_stats_cli reset; menu_pause ;;
            4) xray_stats_cli watch ;;
        esac
    done
}

menu_tools() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "其他选项")"
        menu_item 1 "TCP $(gettext "加速")"
        menu_item 2 "Fail2ban"
        menu_item 3 "Xray $(gettext "流量统计")"
        menu_item 4 "Xray $(gettext "流量阻断")"
        menu_item 5 "$(gettext "清除") $(gettext "日志文件")"
        menu_item 6 "$(gettext "服务器网速")"
        menu_item 7 "$(gettext "刷新 GeoData")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 7
        case $menu_num in
            0) return ;;
            1) menu_action 28 ;;
            2) menu_action 29 ;;
            3) menu_action 40 ;;
            4) menu_action 31 ;;
            5) menu_action 32 ;;
            6) menu_action 33 ;;
            7) menu_action 41 ;;
        esac
    done
}

menu_backup_and_uninstall() {
    local menu_num
    while true; do
        menu_submenu_begin "$(gettext "备份恢复")"
        menu_item 1 "$(gettext "备份") $(gettext "脚本管理文件")"
        menu_item 2 "$(gettext "恢复") $(gettext "脚本管理文件")"
        menu_item 3 "$(gettext "清空") $(gettext "证书文件")"
        menu_item 4 "$(gettext "卸载") $(gettext "脚本")"
        menu_blank
        menu_item 0 "$(gettext "返回")"
        menu_footer
        menu_read menu_num 4
        case $menu_num in
            0) return ;;
            1) menu_action 34 ;;
            2) menu_action 35 ;;
            3) menu_action 37 ;;
            4) menu_action 36 ;;
        esac
    done
}

menu_main_header() {
    menu_clear
    menu_title "$(gettext "Xray 管理脚本") ${Red}[${shell_version}]${Font} ${shell_emoji}"
    local mode_field="$(gettext "当前模式"): ${shell_mode}"
    local language_field="$(gettext "当前语言"): $(_xray_lang_display)"
    local shell_version_field="$(gettext "脚本"): ${shell_need_update}"
    local xray_version_field="Xray: ${xray_need_update}"
    local nginx_version_field="Nginx: ${nginx_need_update}"
    local xray_status_field="Xray: ${xray_status}"
    local nginx_status_field="Nginx: ${nginx_status}"
    local connect_status_field="$(gettext "连通性"): ${xray_local_connect_status}"
    menu_spaced_fields "${mode_field}" "${language_field}"
    menu_divider "$(gettext "版本检测")"
    menu_fields "${shell_version_field}" "${xray_version_field}" "${nginx_version_field}"
    menu_divider "$(gettext "运行状态")"
    menu_fields "${xray_status_field}" "${nginx_status_field}" "${connect_status_field}"
    rxa_refresh_summary
    menu_divider "$(gettext "Rill Xray AI 运维助手")"
    menu_blank
    menu_wrapped_row "$(rxa_health_label)"
    menu_blank
    # 仅运行中的状态着绿色；关闭、未运行不加颜色。
    if [[ "${RILL_XRAY_AGENT_HEADER_RUNTIME}" == *"$(gettext "运行中")"* ]]; then
        menu_fields \
            "${Green}${RILL_XRAY_AGENT_HEADER_STATE}${Font}" \
            "${Green}${RILL_XRAY_AGENT_HEADER_RUNTIME}${Font}" \
            "${RILL_XRAY_AGENT_HEADER_ROUTE}"
    else
        menu_fields \
            "${RILL_XRAY_AGENT_HEADER_STATE}" \
            "${RILL_XRAY_AGENT_HEADER_RUNTIME}" \
            "${RILL_XRAY_AGENT_HEADER_ROUTE}"
    fi
    menu_footer
    log "${mode_field}  ·  ${language_field}"
    log "${shell_version_field}  ·  ${xray_version_field}  ·  ${nginx_version_field}"
    log "${xray_status_field}  ·  ${nginx_status_field}  ·  ${connect_status_field}"
    echo
    menu_title "$(gettext "Xray 管理菜单")"
    menu_blank
}

menu() {
    local menu_num
    if is_relay_role; then
        menu_relay_main
        return
    fi
    while true; do
        menu_main_header
        menu_item 1 "$(gettext "安装向导")"
        menu_item 2 "$(gettext "配置变更")"
        menu_item 3 "$(gettext "查看信息")"
        menu_item 4 "Xray / TLS"
        menu_item 5 "$(gettext "更新向导")"
        menu_item 6 "$(gettext "其他选项")"
        menu_item 7 "$(gettext "备份恢复")"
        menu_item 8 "$(gettext "修改语言") / Language"
        menu_item 9 "$(gettext "Rill Xray AI 运维助手")"
        menu_blank
        menu_item 0 "$(gettext "退出")"
        menu_footer
        menu_read menu_num 9
        case $menu_num in
            0) exit 0 ;;
            1) menu_install ;;
            2) menu_config ;;
            3) menu_information ;;
            4) menu_service_and_certificate ;;
            5) menu_update ;;
            6) menu_tools ;;
            7) menu_backup_and_uninstall ;;
            8) menu_action 99 ;;
            9) rxa_menu ;;
        esac
    done
}

# P1-5: command classification into three disjoint classes. The old single
# is_offline_safe_command() predicate conflated zero-network, no-package-install,
# read-only and rootless semantics. These helpers make the boundary explicit:
#   PURE_READONLY         -> zero package calls, zero network, zero /etc write,
#                            zero log-file create; runs WITHOUT root.
#   OFFLINE_ROOT_MUTATION -> root-required, local-only: no network, no package
#                            install, but may mutate host state; logging enabled.
#   ONLINE_ROOT_MUTATION  -> everything else (fresh install/update/repair); may
#                            network and install packages.
is_pure_readonly_command() {
    case "${1:-}" in
        -h|--help|-s|--show|--access-log|--error-log|\
        --stats|--stats-watch|\
        --rill-agent-status|--rill-agent-diagnose|--rill-agent-timeline|\
        --rill-agent-auto-status|--rill-integration-self-check)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_offline_root_mutation_command() {
    case "${1:-}" in
        --purge|--uninstall|--service-start|--service-stop|--service-restart|\
        --stats-reset|--backup|--restore|--rill-agent|--rill-agent-safe-disable|--rill-agent-verify|\
        --rill-agent-route-stage|--rill-agent-auto-confirm|--rill-agent-auto-revoke|\
        --rill-agent-fuse-ack|--rill-agent-uninstall|\
        --internal-geodata-migrate-legacy)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Backward-compatible combined predicate (pure readonly OR offline root
# mutation) kept for existing unit tests and read-only dispatchers.
is_offline_safe_command() {
    if is_pure_readonly_command "${1:-}" || is_offline_root_mutation_command "${1:-}"; then
        return 0
    fi
    return 1
}

dispatch_pure_readonly_command() {
    case "${1:-}" in
        -h|--help) show_help ;;
        -s|--show)
            judge_mode
            basic_information
            install_link_image
            show_information
            ;;
        --access-log) show_access_log ;;
        --error-log) show_error_log ;;
        --stats) xray_stats_cli stats "${@:2}" ;;
        --stats-watch) xray_stats_cli watch "${@:2}" ;;
        --rill-agent-status) rxa_dispatch status ;;
        --rill-agent-diagnose) rxa_dispatch diagnose ;;
        --rill-agent-timeline) rxa_dispatch timeline ;;
        --rill-agent-auto-status) rxa_dispatch autoStatus ;;
        --rill-integration-self-check) rxa_integration_self_check ;;
        *) return 1 ;;
    esac
}

dispatch_offline_root_mutation_command() {
    relay_bootstrap_role || true
    case "${1:-}" in
        --purge|--uninstall) uninstall_all ;;
        --service-start) service_start ;;
        --service-stop) service_stop ;;
        --service-restart) service_restart ;;
        --stats-reset) xray_stats_cli reset "${@:2}" ;;
        --backup) backup_directories ;;
        --restore) restore_directories ;;
        --rill-agent) rxa_menu ;;
        --rill-agent-safe-disable) rxa_dispatch mode safe-disabled ;;
        --rill-agent-verify) rxa_dispatch verify ;;
        # P0-8: authority-relevant transitions dispatch to the manager, which
        # routes them through the ROOT execution policy helper (routeStage
        # three-party transaction; auto confirm/revoke and fuse ack bump
        # executionEpoch; autoStatus reports configured/rootAuthoritative/
        # shadow/effective).
        --rill-agent-route-stage) rxa_dispatch routeStage "${2:-}"; shift ;;
        --rill-agent-auto-confirm) rxa_dispatch autoConfirm ;;
        --rill-agent-auto-revoke) rxa_dispatch autoRevoke ;;
        --rill-agent-fuse-ack) rxa_dispatch fuseAck ;;
        --rill-agent-uninstall) rxa_dispatch uninstall ;;
        --internal-geodata-migrate-legacy) geodata_migrate_legacy ;;
        *) return 1 ;;
    esac
}

# Backward-compatible combined dispatch used by existing unit tests.
dispatch_offline_safe_command() {
    if is_pure_readonly_command "${1:-}"; then
        dispatch_pure_readonly_command "$@"
        return $?
    fi
    dispatch_offline_root_mutation_command "$@"
}

harden_config_permissions_if_needed() {
    [[ -f "${xray_install_config_file}" ]] || return 0
    if [[ ${tls_mode} == "Reality" ]]; then
        ensure_reality_sni_guard_defaults || log_echo "${Warning} ${YellowBG} Reality SNI Guard $(gettext "配置修改") $(gettext "失败") ${Font}"
    fi
    harden_config_permissions
}

[[ "${_TEST_MODE:-0}" == "1" ]] && return 0

# Phase 0: pure early dispatch. -h/--help MUST be dispatched before
# init_language, check_file_integrity, version checks, network requests, and
# dependency installation. This ensures `bash install.sh --help` works with
# zero network access, zero package manager calls, zero log-file creation, and
# zero language file downloads — even when gettext is not installed, GitHub is
# unreachable, or the script is not yet installed.
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    --rill-integration-self-check)
        # P1-4: read-only, side-effect-free contract self-check. Dispatched
        # before init_language / check_file_integrity / any network or package
        # call so stdout carries ONLY the JSON contract. Never installs.
        rxa_integration_self_check
        exit 0
        ;;
    --internal-bridge-offer)
        # Phase 03: dispatched before init_language, integrity checks, version
        # checks and dependency installs so the offer path makes zero network
        # requests unless the operator explicitly consents. Credential-free.
        bridge_manual_invocation="on"
        bridge_migration_offer
        exit $?
        ;;
esac

# Phase 1: pure system detection + package-manager selection. Both are
# read-only: init_package_manager selects INS from os-release only (never
# installs, never networks); init_language offline is local-only.
init_package_manager
init_language offline

# Phase 2A: PURE_READONLY — dispatched before the root gate. Zero package
# calls, zero network, zero /etc write, zero log-file create. These commands
# must work as a non-root user with no tooling installed.
if is_pure_readonly_command "${1:-}"; then
    # `-s/--show` reads /etc/idleleo/info/xray_info.inf, which intentionally
    # stays 0600 because it contains UUID/mapping material. The pure-readonly
    # dispatcher runs before the root gate, so name the actual requirement
    # instead of letting a non-root run fail with a raw Permission denied.
    if [[ "${1:-}" == "-s" || "${1:-}" == "--show" ]] && [[ "$(id -u)" -ne 0 ]]; then
        printf '%b\n' "${Error} ${RedBG} $(gettext "读取安装信息需要 root 权限")（$(gettext "信息文件权限为") 0600）${Font}" >&2
        exit 1
    fi
    dispatch_pure_readonly_command "$@"
    exit $?
fi

# Root gate: every mutation command (offline or online) requires root BEFORE
# its first system write, package call, network call, or /etc mutation, so a
# non-root user is rejected up front instead of discovering mid-install.
is_root

# Phase 2B: OFFLINE_ROOT_MUTATION — root-confirmed, local-only (no network, no
# package install). These MUST be dispatched before check_file_integrity, which
# may attempt network downloads, so they work even when GitHub is unreachable.
# Logging is enabled here: mutation commands persist their outcome.
if is_offline_root_mutation_command "${1:-}"; then
    enable_file_logging
    dispatch_offline_root_mutation_command "$@"
    exit $?
fi

# Phase 2C: ONLINE_ROOT_MUTATION — fresh install / update / repair /
# --rill-agent-install (P1-6: the Rill installer is NOT guaranteed
# zero-network; it prefers a local payload but falls back to downloading the
# bootstrap). Validate the OS BEFORE any apt update / dnf makecache / pkg
# install / GitHub curl / mkdir /etc/idleleo, then enable logging, then go
# through the full bootstrap + candidate-guard + config-load path.
validate_supported_system || exit 1
enable_file_logging

# Online language enhancement may now install gettext and refresh translations:
# INS is already defined by init_package_manager above and root is confirmed.
init_language online

check_file_integrity "$@" || exit 1
# Repair a stale install_config shell_version before any update decision. The
# managed script itself is authoritative; never rewrite it from old metadata.
sync_shell_version_config_with_actual || true
judge_mode
check_online_version_connect
read_version || exit 1

harden_config_permissions_if_needed || exit 1
# A stale legacy status_config.json must go even when the user never toggles
# statistics again (audit P2-1).
xray_stats_cleanup_legacy_config || true
# One-time legacy repair on every mutable startup (including -u): old installs
# keep an external geo_update.sh cron and may still use the real
# /usr/local/share/xray directory. No prompt is shown: the hook migrates
# automatically when legacy evidence exists, stays quiet when there is nothing
# to do, and on failure leaves the old cron in place (fail closed).
geodata_migrate_legacy || true
idleleo_commend || exit 1
rxa_reconcile_release_if_needed || {
    log_echo "${Error} ${RedBG} Release reconciliation failed; marker was not committed. It will retry on the next mutable startup. ${Font}" >&2
    exit 1
}
check_program
if [[ ${tls_mode} == "Reality" ]]; then
    ensure_reality_public_key || true
fi
check_xray_local_connect
case "${1:-}" in
    --rill-agent-install) rxa_dispatch install ;;
    *) list "$@" ;;
esac
