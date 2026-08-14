#!/usr/bin/env bash
# IPv4/IPv6 dual-stack regression tests:
#   - IPv6 URI authority bracket formatting (vless link)
#   - single-stack domain_check / network capability detection
#   - bad A/AAAA record detection (return code 2)
#   - old-config compatibility (infer/load network_mode)
#   - dual direct-IP link generation
# All network/DNS calls are deterministic mocks; no real IPv6 required.
# SC2154/SC2034: globals (network_mode, ipv4_address, resolved_ipv4s, tls_mode,
# reality_add_more) are written by the functions under test or read by
# install_link_image; shellcheck cannot see the cross-function flow.
# shellcheck disable=SC2154,SC2034

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

PASS=0
FAIL=0
TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT

ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
log_echo() { :; }
gettext() { printf '%s' "$1"; }

# --- mocks ---------------------------------------------------------------
# Deterministic public-IP probe. Override per-test by reassigning these globals.
MOCK_PUBLIC_IPV4="203.0.113.10"
MOCK_PUBLIC_IPV6="2001:db8::10"
get_public_ip() {
    if [[ "$1" == "IPv6" ]]; then
        printf '%s' "${MOCK_PUBLIC_IPV6}"
    else
        printf '%s' "${MOCK_PUBLIC_IPV4}"
    fi
}

# Deterministic DNS resolver. Override per-test by reassigning MOCK_DNS.
MOCK_DNS="203.0.113.10
2001:db8::10"
resolve_domain_ips() {
    printf '%s' "${MOCK_DNS}"
}

# vless_urlquote: keep it a pure function for deterministic tests.
vless_urlquote() {
    local s="$1"
    s=${s//:/%3A}
    s=${s//\//%2F}
    printf '%s' "${s}"
}

# info_extraction / info_* used by generate_vless_link.
MOCK_HOST="v4.example.com"
MOCK_PORT="443"
info_extraction() {
    case "$1" in
        host) printf '%s' "${MOCK_HOST}" ;;
        port) printf '%s' "${MOCK_PORT}" ;;
        serverNames) printf '%s' "${MOCK_HOST}" ;;
        target) printf '%s' 'www.microsoft.com' ;;
        shortIds) printf '%s' 'abcd1234' ;;
        *) printf '%s' '' ;;
    esac
}
info_reality_public_key() { printf '%s' 'REALITYPUBKEY'; }
reality_client_meta() { printf '%s' ''; }
info_ws_path() { printf '%s' 'ws'; }
info_grpc_serviceName() { printf '%s' 'grpc'; }
info_xhttp_path() { printf '%s' 'xhttp'; }
format_xhttp_path() { printf '%s' "${1:-}"; }

# --- IPv6 literal helpers ------------------------------------------------
printf '%s\n' '--- IPv6 / IPv4 literal detection ---'
if is_ipv6_literal "2001:db8::10"; then ok "bare IPv6 literal is detected"; else bad "bare IPv6 literal not detected"; fi
if is_ipv6_literal "[2001:db8::10]"; then ok "bracketed IPv6 literal is detected"; else bad "bracketed IPv6 literal not detected"; fi
if is_ipv6_literal "2001:db8:0:1"; then ok "IPv6 with leading zeros is detected"; else bad "IPv6 with leading zeros not detected"; fi
if ! is_ipv6_literal "203.0.113.10"; then ok "IPv4 is not an IPv6 literal"; else bad "IPv4 treated as IPv6 literal"; fi
if ! is_ipv6_literal ""; then ok "empty string is not an IPv6 literal"; else bad "empty string treated as IPv6 literal"; fi
if is_ipv4_literal "203.0.113.10"; then ok "IPv4 literal is detected"; else bad "IPv4 literal not detected"; fi
if ! is_ipv4_literal "2001:db8::10"; then ok "IPv6 is not an IPv4 literal"; else bad "IPv6 treated as IPv4 literal"; fi

printf '%s\n' '--- format_uri_authority_host ---'
if [[ "$(format_uri_authority_host "2001:db8::10")" == "[2001:db8::10]" ]]; then
    ok "bare IPv6 authority wrapped in brackets"
else
    bad "bare IPv6 authority not wrapped; got '$(format_uri_authority_host "2001:db8::10")'"
fi
if [[ "$(format_uri_authority_host "[2001:db8::10]")" == "[2001:db8::10]" ]]; then
    ok "bracketed IPv6 authority is not double-wrapped"
else
    bad "bracketed IPv6 authority double-wrapped"
fi
if [[ "$(format_uri_authority_host "203.0.113.10")" == "203.0.113.10" ]]; then
    ok "IPv4 authority unchanged"
else
    bad "IPv4 authority was modified"
fi
if [[ "$(format_uri_authority_host "v4.example.com")" == "v4.example.com" ]]; then
    ok "domain authority unchanged"
else
    bad "domain authority was modified"
fi

printf '%s\n' '--- yaml_quote_scalar ---'
if [[ "$(yaml_quote_scalar "2001:db8::10")" == "'2001:db8::10'" ]]; then
    ok "IPv6 literal is single-quoted in YAML"
else
    bad "IPv6 literal not quoted in YAML"
fi
if [[ "$(yaml_quote_scalar "v4.example.com")" == "v4.example.com" ]]; then
    ok "domain is not quoted in YAML"
else
    bad "domain was quoted in YAML"
fi

# --- network capability detection (detect_public_network_capabilities) ---
printf '%s\n' '--- detect_public_network_capabilities ---'
MOCK_PUBLIC_IPV4="203.0.113.10"; MOCK_PUBLIC_IPV6="2001:db8::10"
detect_public_network_capabilities
if [[ "${network_mode}" == "dual" ]]; then ok "dual detected when both families probed"; else bad "dual not detected; mode=${network_mode}"; fi

MOCK_PUBLIC_IPV6=""
detect_public_network_capabilities
if [[ "${network_mode}" == "ipv4" ]]; then ok "ipv4 detected when only v4 probed"; else bad "ipv4 not detected; mode=${network_mode}"; fi

MOCK_PUBLIC_IPV4=""; MOCK_PUBLIC_IPV6="2001:db8::10"
detect_public_network_capabilities
if [[ "${network_mode}" == "ipv6" ]]; then ok "ipv6 detected when only v6 probed"; else bad "ipv6 not detected; mode=${network_mode}"; fi

MOCK_PUBLIC_IPV4=""; MOCK_PUBLIC_IPV6=""
detect_public_network_capabilities
if [[ "${network_mode}" == "none" ]]; then ok "none detected when neither family probed"; else bad "none not detected; mode=${network_mode}"; fi

# --- classify_resolved_ips ---
printf '%s\n' '--- classify_resolved_ips ---'
classify_resolved_ips "203.0.113.10
2001:db8::10
203.0.113.55"
if [[ "${resolved_ipv4s}" == *"203.0.113.10"* && "${resolved_ipv4s}" == *"203.0.113.55"* && \
      ! "${resolved_ipv4s}" == *":"* ]]; then
    ok "IPv4 records classified into resolved_ipv4s"
else
    bad "IPv4 classification wrong; v4s='${resolved_ipv4s}'"
fi
if [[ "${resolved_ipv6s}" == *"2001:db8::10"* && ! "${resolved_ipv6s}" == *"."* ]]; then
    ok "IPv6 records classified into resolved_ipv6s"
else
    bad "IPv6 classification wrong; v6s='${resolved_ipv6s}'"
fi

# --- old-config compatibility (infer_network_mode_from_config) ---
printf '%s\n' '--- infer_network_mode_from_config (old config compat) ---'
if [[ "$(infer_network_mode_from_config "IPv4")" == "ipv4" ]]; then ok "old IPv4 field -> ipv4"; else bad "old IPv4 field inference wrong"; fi
if [[ "$(infer_network_mode_from_config "IPv6")" == "ipv6" ]]; then ok "old IPv6 field -> ipv6"; else bad "old IPv6 field inference wrong"; fi
if [[ "$(infer_network_mode_from_config "manual-host")" == "manual" ]]; then ok "old manual IP field -> manual"; else bad "old manual field inference wrong"; fi

printf '%s\n' '--- load_network_capabilities_from_config (old config compat) ---'
info_extraction() {
    case "$1" in
        network_mode) printf '%s' '' ;;
        ipv4_address) printf '%s' '' ;;
        ipv6_address) printf '%s' '' ;;
        ip_version) printf '%s' 'IPv6' ;;
        *) printf '%s' '' ;;
    esac
}
load_network_capabilities_from_config
if [[ "${network_mode}" == "ipv6" ]]; then ok "old IPv6 config infers network_mode ipv6"; else bad "old IPv6 config inference wrong; mode=${network_mode}"; fi

info_extraction() {
    case "$1" in
        network_mode) printf '%s' 'dual' ;;
        ipv4_address) printf '%s' '203.0.113.10' ;;
        ipv6_address) printf '%s' '2001:db8::10' ;;
        ip_version) printf '%s' 'IPv4' ;;
        *) printf '%s' '' ;;
    esac
}
load_network_capabilities_from_config
if [[ "${network_mode}" == "dual" && "${ipv4_address}" == "203.0.113.10" && "${ipv6_address}" == "2001:db8::10" ]]; then
    ok "new dual fields are loaded directly"
else
    bad "new dual fields not loaded; mode=${network_mode} v4=${ipv4_address} v6=${ipv6_address}"
fi

# --- validate_domain_network_records (A/AAAA qualification) ---
# restore generic info_extraction for these tests
info_extraction() {
    case "$1" in
        host) printf '%s' "${MOCK_HOST}" ;;
        port) printf '%s' "${MOCK_PORT}" ;;
        serverNames) printf '%s' "${MOCK_HOST}" ;;
        target) printf '%s' 'www.microsoft.com' ;;
        shortIds) printf '%s' 'abcd1234' ;;
        *) printf '%s' '' ;;
    esac
}

printf '%s\n' '--- validate_domain_network_records: dual ---'
MOCK_PUBLIC_IPV4="203.0.113.10"; MOCK_PUBLIC_IPV6="2001:db8::10"
MOCK_DNS="203.0.113.10
2001:db8::10"
validate_domain_network_records "dual.example.com"
rc=$?
if [[ ${rc} -eq 0 && "${network_mode}" == "dual" ]]; then ok "dual validated with matching A + AAAA"; else bad "dual validation failed rc=${rc} mode=${network_mode}"; fi

printf '%s\n' '--- validate_domain_network_records: ipv4 single-stack ---'
# Server has no v6; DNS has only a matching A record -> clean ipv4 (rc=0).
MOCK_PUBLIC_IPV6=""
MOCK_DNS="203.0.113.10"
validate_domain_network_records "v4.example.com"
rc=$?
if [[ ${rc} -eq 0 && "${network_mode}" == "ipv4" ]]; then ok "ipv4 validated cleanly when server v6 unavailable and no AAAA present"; else bad "ipv4 validation failed rc=${rc} mode=${network_mode}"; fi

printf '%s\n' '--- validate_domain_network_records: server-no-v6 but AAAA present is bad-AAAA ---'
# Server has no v6 but DNS has a non-matching AAAA -> must be flagged (rc=2).
MOCK_PUBLIC_IPV6=""
MOCK_DNS="203.0.113.10
2001:db8::99"
validate_domain_network_records "v4-with-aaaa.example.com"
rc=$?
if [[ ${rc} -eq 2 && "${network_mode}" == "ipv4" ]]; then ok "non-matching AAAA flagged even when server has no v6"; else bad "orphan AAAA not flagged rc=${rc} mode=${network_mode}"; fi

printf '%s\n' '--- validate_domain_network_records: bad AAAA detection ---'
MOCK_PUBLIC_IPV4="203.0.113.10"; MOCK_PUBLIC_IPV6="2001:db8::10"
MOCK_DNS="203.0.113.10
2001:db8::99"
validate_domain_network_records "bad-aaaa.example.com"
rc=$?
if [[ ${rc} -eq 2 && "${network_mode}" == "ipv4" ]]; then ok "bad AAAA record flagged (rc=2) while v4 validated"; else bad "bad AAAA not flagged rc=${rc} mode=${network_mode}"; fi

printf '%s\n' '--- validate_domain_network_records: bad A detection ---'
MOCK_PUBLIC_IPV4="203.0.113.10"; MOCK_PUBLIC_IPV6="2001:db8::10"
MOCK_DNS="192.0.2.99
2001:db8::10"
validate_domain_network_records "bad-a.example.com"
rc=$?
if [[ ${rc} -eq 2 && "${network_mode}" == "ipv6" ]]; then ok "bad A record flagged (rc=2) while v6 validated"; else bad "bad A not flagged rc=${rc} mode=${network_mode}"; fi

printf '%s\n' '--- validate_domain_network_records: no match fails ---'
MOCK_PUBLIC_IPV4="203.0.113.10"; MOCK_PUBLIC_IPV6="2001:db8::10"
MOCK_DNS="192.0.2.99
2001:db8::99"
validate_domain_network_records "nomatch.example.com"
rc=$?
if [[ ${rc} -eq 1 && "${network_mode}" == "none" ]]; then ok "no matching family fails closed (rc=1)"; else bad "no-match did not fail rc=${rc} mode=${network_mode}"; fi

# --- generate_vless_link: IPv6 authority formatting ---
printf '%s\n' '--- generate_vless_link: IPv6 authority bracket ---'
MOCK_HOST="203.0.113.10"
v4_link=$(generate_vless_link "test-user" "reality")
if [[ "${v4_link}" == *"@203.0.113.10:"* ]]; then ok "IPv4 authority has no brackets"; else bad "IPv4 authority malformed: ${v4_link}"; fi

v6_link=$(generate_vless_link "test-user" "reality" "2001:db8::10")
if [[ "${v6_link}" == *"@[2001:db8::10]:"* ]]; then
    ok "IPv6 authority host is wrapped in brackets"
else
    bad "IPv6 authority host not bracketed: ${v6_link}"
fi
if [[ ! "${v6_link}" == *"@[2001%3Adb8"* ]]; then ok "IPv6 authority colon is not percent-encoded"; else bad "IPv6 authority colon was percent-encoded"; fi

xtls_v6=$(generate_vless_link "test-user" "xtls" "2001:db8::10")
if [[ "${xtls_v6}" == *"@[2001:db8::10]:"* ]]; then ok "XTLS IPv6 authority wrapped"; else bad "XTLS IPv6 authority malformed: ${xtls_v6}"; fi

# --- dual direct-IP link generation in install_link_image ---
# install_link_image emits links; capture stdout and grep. Mock qrencode + info reads.
printf '%s\n' '--- install_link_image: dual direct-IP v6 entry ---'
info_extraction() {
    case "$1" in
        id) printf '%s' 'test-user' ;;
        host) printf '%s' '203.0.113.10' ;;
        port) printf '%s' "${MOCK_PORT}" ;;
        serverNames) printf '%s' 'v4.example.com' ;;
        target) printf '%s' 'www.microsoft.com' ;;
        shortIds) printf '%s' 'abcd1234' ;;
        ws_port) printf '%s' '8888' ;;
        grpc_port) printf '%s' '8888' ;;
        xhttp_port) printf '%s' '8888' ;;
        *) printf '%s' '' ;;
    esac
}
info_reality_public_key() { printf '%s' 'REALITYPUBKEY'; }
reality_client_meta() { printf '%s' ''; }
is_ws_mode() { return 1; }
is_grpc_mode() { return 1; }
is_xhttp_mode() { return 1; }
qrencode() { cat; }   # allow qrencode to be absent; just echo input
ensure_reality_public_key() { return 0; }

network_mode="dual"; ipv6_address="2001:db8::10"; tls_mode="Reality"; reality_add_more="off"
xray_info_file="${TMP_ROOT}/xray_info.inf"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" == *"vless://test-user@[2001:db8::10]:"* ]]; then
    ok "dual Reality emits an IPv6 direct-IP share link"
else
    bad "dual Reality missing IPv6 link; out=${out}"
fi

network_mode="ipv4"; ipv6_address=""; tls_mode="Reality"; reality_add_more="off"
rm -f "${xray_info_file}"
out=$(install_link_image 2>/dev/null; cat "${xray_info_file}" 2>/dev/null)
if [[ "${out}" != *"vless://test-user@[2001:db8::10]:"* ]]; then
    ok "ipv4-only does NOT emit an IPv6 direct-IP link"
else
    bad "ipv4-only incorrectly emitted an IPv6 link"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]