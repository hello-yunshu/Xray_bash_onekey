set -uo pipefail
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
command_available() { [ "${FW_HAS_V6:-0}" = "1" ]; }
for mode in auto ipv4 ipv6 dual manual; do
    printf '%s=%s\n' "$mode" "$(managed_fw_families_for_mode "$mode" | paste -sd, -)"
done
