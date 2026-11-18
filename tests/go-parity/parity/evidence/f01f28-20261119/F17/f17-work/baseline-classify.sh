set -uo pipefail
normalize_ip_literal() {
    local input="$1"
    [[ -z "${input}" ]] && return 1
    python3 -c 'import ipaddress, sys
try:
    print(ipaddress.ip_address(sys.argv[1].strip().strip("[]")).compressed)
except Exception:
    sys.exit(1)' "${input}" 2>/dev/null
}
is_ipv4_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *.* && "${candidate}" != *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}
is_ipv6_literal() {
    local candidate="$1"
    [[ -z "${candidate}" ]] && return 1
    [[ "${candidate}" == *:* ]] || return 1
    normalize_ip_literal "${candidate}" >/dev/null 2>&1
}
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
input="$1"
classify_resolved_ips "$input"
printf 'v4=%s\n' "$(printf '%b' "$resolved_ipv4s" | sed '/^$/d' | tr '\n' ',')"
printf 'v6=%s\n' "$(printf '%b' "$resolved_ipv6s" | sed '/^$/d' | tr '\n' ',')"
