#!/usr/bin/env bash
# Pure-function EXTRACT from install.sh at main commit
# 0fa7052e51b9bd7e6ffb46bc86befb006034da3c (v3.3.6).
# Source line anchors: 410-464, 1653-1701, 9190-9192, 9213-9216, 11178-11189.
# This file is a subset snapshot, NOT a substitute for executing full upstream install.sh.
# The live-repository gate in scripts/run_parity.py is required for release.

version_is_numeric() {
    [[ "${1:-}" =~ ^[0-9]+(\.[0-9]+)*$ ]]
}
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
normalize_ip_literal() {
    local input="$1"
    [[ -z "${input}" ]] && return 1
    python3 -c 'import ipaddress, sys
try:
    print(ipaddress.ip_address(sys.argv[1].strip().strip("[]")).compressed)
except Exception:
    sys.exit(1)' "${input}" 2>/dev/null
}
is_ipv6_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}
is_ipv4_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *.* && "${candidate}" != *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}
relay_is_valid_host() {
    local host="${1:-}"
    [[ -n "${host}" && ${#host} -le 253 ]] || return 1
    is_ipv6_literal "${host}" && return 0
    is_ipv4_literal "${host}" && return 0
    [[ "${host}" =~ ^[0-9]+$ ]] && return 1
    [[ "${host}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || return 1
    [[ "${host}" != *".."* ]] || return 1
    [[ "${host}" != *".-"* && "${host}" != *"-."* ]] || return 1
    return 0
}
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
yaml_quote_scalar() {
    local value="$1"
    if is_ipv6_literal "${value}"; then
        echo "'${value}'"
    else
        echo "${value}"
    fi
}
format_xhttp_path() {
    local raw_path="$1"
    echo "/${raw_path#/}"
}
vless_urlquote() {
    [[ $# = 0 ]] && return 1
    python3 -c "import urllib.request,sys;print(urllib.request.quote(sys.argv[1]))" "$1"
}
