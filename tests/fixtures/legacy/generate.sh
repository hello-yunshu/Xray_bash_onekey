#!/usr/bin/env bash
# Regenerate the synthetic legacy fixtures in this directory.
#
# The templates and field names are taken from the Bash baseline
# (install.sh:9065-9188 config writers, install.sh:11212-11242 relay renderer,
# config/vless_reality.json, config/vless_tls.json).  Values are synthetic:
# documentation IP ranges, invalid example domains and a throwaway x25519 key.
#
# Usage: bash tests/fixtures/legacy/generate.sh [output-directory]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../../.." && pwd)"
OUT="${1:-${HERE}}"

UUID_PRIMARY="11111111-2222-4333-8444-555555555555"
UUID_SECONDARY="66666666-7777-4888-8999-aaaaaaaaaaaa"
# Throwaway pair generated with `xray x25519`; never used on a real host.
REALITY_PRIVATE="oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk"
REALITY_PUBLIC="U_BBVmjjhAmc7fuvx42tI1FqTOTmvjZrvAWsk3yK2Vc"
SHORT_ID="0123456789abcdef"
MANAGED_EMAIL="fixture@example.invalid"

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to regenerate fixtures" >&2
    exit 1
}

mkdir -p "${OUT}"/{reality-direct,reality-nginx,tls-multi,relay,custom-dns-routing,xtls-only}

reality_body() {
    jq \
        --arg id "${UUID_PRIMARY}" \
        --arg email "${MANAGED_EMAIL}" \
        --arg private_key "${REALITY_PRIVATE}" \
        --arg short_id "${SHORT_ID}" \
        --arg target "www.example.invalid:443" \
        '
        .inbounds[0].listen = "0.0.0.0"
        | .inbounds[0].port = 9443
        | .inbounds[0].settings.clients[0].id = $id
        | .inbounds[0].settings.clients[0].email = $email
        | .inbounds[0].streamSettings.realitySettings.target = $target
        | .inbounds[0].streamSettings.realitySettings.serverNames = ["www.example.invalid"]
        | .inbounds[0].streamSettings.realitySettings.privateKey = $private_key
        | .inbounds[0].streamSettings.realitySettings.shortIds = [$short_id]
        | del(.inbounds[0].streamSettings.realitySettings.minClientVer)
        ' "${ROOT}/config/vless_reality.json"
}

reality_body >"${OUT}/reality-direct/xray-config.json"
cp "${OUT}/reality-direct/xray-config.json" "${OUT}/reality-nginx/xray-config.json"
cp "${OUT}/reality-direct/xray-config.json" "${OUT}/custom-dns-routing/xray-config.json"

jq -n \
    --arg uuid "${UUID_PRIMARY}" \
    --arg private_key "${REALITY_PRIVATE}" \
    --arg public_key "${REALITY_PUBLIC}" \
    --arg short_id "${SHORT_ID}" \
    --arg email "${MANAGED_EMAIL}" \
    '{
        shell_mode: "Reality", transport_mode: "None", host: "203.0.113.10",
        ip_version: "IPv4", network_mode: "ipv4", ipv4_address: "203.0.113.10",
        ipv6_address: "", port: 9443, email: $email,
        idc: "fixture-idc", id: $uuid, net: "raw", tls: "Reality",
        target: "www.example.invalid:443", serverNames: "www.example.invalid",
        privateKey: $private_key, publicKey: $public_key, password: $public_key,
        shortIds: $short_id, spiderx_path: "/",
        reality_add_nginx: "off", reality_add_balance: "off",
        reality_balance_role: "", reality_add_more: "off",
        reality_nginx_sni_guard: "off", unknown_sni_policy: "",
        decoy_domain: "", ws_port: "", grpc_port: "", xhttp_port: "",
        ws_path: "", grpc_serviceName: "", xhttp_path: "",
        shell_version: "3.3.4", xray_version: "26.10.31"
    }' >"${OUT}/reality-direct/install_config.json"

jq '. + {
    reality_add_nginx: "on",
    reality_nginx_sni_guard: "on",
    unknown_sni_policy: "reject",
    decoy_domain: "www.example.invalid",
    nginx_build_version: "2026.10.15.7679"
}' "${OUT}/reality-direct/install_config.json" \
    >"${OUT}/reality-nginx/install_config.json"

jq '
    .inbounds[0].listen = "127.0.0.1"
    | .inbounds[0].settings.clients[0].id = "11111111-2222-4333-8444-555555555555"
    | .inbounds[0].settings.clients[0].email = "ws1@example.invalid"
    | .inbounds[0].streamSettings.wsSettings.path = "/fixture-ws"
    | .inbounds[0].settings.clients += [{
        id: "66666666-7777-4888-8999-aaaaaaaaaaaa",
        level: 0,
        email: "ws2@example.invalid"
    }]
    | .inbounds += [{
        port: 10087,
        listen: "127.0.0.1",
        tag: "VLESS-gRPC-in",
        protocol: "VLESS",
        settings: {
            clients: [{id: "11111111-2222-4333-8444-555555555555", level: 0, email: "grpc@example.invalid"}],
            decryption: "none"
        },
        streamSettings: {
            network: "grpc",
            security: "none",
            grpcSettings: {serviceName: "fixture-grpc", multiMode: true, idle_timeout: 20}
        }
    }]
    | .inbounds += [{
        port: 10088,
        listen: "127.0.0.1",
        tag: "VLESS-xhttp-in",
        protocol: "VLESS",
        settings: {
            clients: [{id: "11111111-2222-4333-8444-555555555555", level: 0, email: "xhttp@example.invalid"}],
            decryption: "none"
        },
        streamSettings: {
            network: "xhttp",
            security: "none",
            xhttpSettings: {path: "/fixture-xhttp", mode: "auto"}
        }
    }]
    | .routing.rules[0].inboundTag = ["VLESS-ws-in", "VLESS-gRPC-in", "VLESS-xhttp-in"]
    ' "${ROOT}/config/vless_tls.json" >"${OUT}/tls-multi/xray-config.json"

jq -n \
    --arg uuid "${UUID_PRIMARY}" \
    '{
        shell_mode: "TLS", transport_mode: "wsgRPCxhttp", host: "www.example.invalid",
        ip_version: "IPv4", network_mode: "ipv4", ipv4_address: "203.0.113.10",
        ipv6_address: "", port: 443, ws_port: "10086",
        grpc_port: "10087", xhttp_port: "10088", tls: "TLS",
        email: "fixture@example.invalid", idc: "fixture-idc", id: $uuid,
        net: "ws", path: "/fixture-ws", serviceName: "fixture-grpc",
        xhttp_path: "/fixture-xhttp", shell_version: "3.3.4",
        xray_version: "26.10.31", nginx_build_version: "2026.10.15.7679"
    }' >"${OUT}/tls-multi/install_config.json"

jq '.dns.servers = ["https+local://dns.example.invalid/dns-query", "1.1.1.1", "localhost"]
    | .outbounds += [{protocol: "socks", tag: "custom-out", settings: {servers: [{address: "198.51.100.20", port: 1080}]}}]
    | .routing.rules += [{type: "field", domain: ["custom.example.invalid"], outboundTag: "custom-out"}]
    ' "${OUT}/custom-dns-routing/xray-config.json" >"${OUT}/custom-dns-routing/xray-config.tmp" \
    && mv "${OUT}/custom-dns-routing/xray-config.tmp" "${OUT}/custom-dns-routing/xray-config.json"

jq -n \
    --arg uuid "${UUID_PRIMARY}" \
    '{
        shell_mode: "Reality", transport_mode: "None", host: "203.0.113.10",
        ip_version: "IPv4", network_mode: "ipv4", ipv4_address: "203.0.113.10",
        ipv6_address: "", port: 9443, email: "fixture@example.invalid",
        idc: "fixture-idc", id: $uuid, net: "raw", tls: "Reality",
        target: "www.example.invalid:443", serverNames: "www.example.invalid",
        privateKey: "oD7nlMJVY4oXH5eom_ijOe741Y4WDjpCm6_bzYRCvmk",
        publicKey: "U_BBVmjjhAmc7fuvx42tI1FqTOTmvjZrvAWsk3yK2Vc",
        password: "U_BBVmjjhAmc7fuvx42tI1FqTOTmvjZrvAWsk3yK2Vc",
        shortIds: "0123456789abcdef", spiderx_path: "/",
        reality_add_nginx: "off", reality_add_balance: "off",
        reality_balance_role: "", reality_add_more: "off",
        reality_nginx_sni_guard: "off", unknown_sni_policy: "",
        decoy_domain: "", ws_port: "", grpc_port: "", xhttp_port: "",
        ws_path: "", grpc_serviceName: "", xhttp_path: "",
        shell_version: "3.3.4", xray_version: "26.10.31"
    }' >"${OUT}/custom-dns-routing/install_config.json"

jq -n \
    '{
        role: "relay", shell_mode: "Relay", transport_mode: "None", tls: "None",
        host: "203.0.113.10", ip_version: "IPv4", network_mode: "ipv4",
        ipv4_address: "203.0.113.10", ipv6_address: "",
        relay_backend_host: "198.51.100.20", relay_backend_port: 443,
        relay_listen_port: 8443, relay_listen_addr: "0.0.0.0",
        relay_enabled: "on", shell_version: "3.3.4",
        nginx_build_version: "2026.10.15.7679"
    }' >"${OUT}/relay/install_config.json"

cat >"${OUT}/relay/relay-stream.conf" <<'EOF'
# Managed by Xray_bash_onekey (relay node). Do not edit by hand.
# Rewritten by the installer and the updater; change it from the script menu.
stream {
    server {
        listen 0.0.0.0:8443;
        proxy_pass 198.51.100.20:443;
        proxy_connect_timeout 10s;
        proxy_timeout 720m;
        proxy_socket_keepalive on;
    }
}
EOF

jq -n \
    '{
        shell_mode: "TLS", transport_mode: "None", host: "203.0.113.10",
        ip_version: "IPv4", network_mode: "ipv4", ipv4_address: "203.0.113.10",
        ipv6_address: "", port: 443, tls: "XTLS", email: "fixture@example.invalid",
        idc: "fixture-idc", id: "11111111-2222-4333-8444-555555555555",
        net: "tcp", path: "", serviceName: "", xhttp_path: "",
        shell_version: "2.7.1", xray_version: "1.8.4"
    }' >"${OUT}/xtls-only/install_config.json"

if command -v sha256sum >/dev/null 2>&1; then
    SHA256=(sha256sum)
else
    SHA256=(shasum -a 256)
fi
(cd "${OUT}" && find reality-direct reality-nginx tls-multi relay custom-dns-routing xtls-only \
    -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 "${SHA256[@]}" >SHA256SUMS)

echo "fixtures written under ${OUT}"
