#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
export _TEST_MODE=1
source "$repo/install.sh" >/dev/null 2>&1 || true
unset _TEST_MODE
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
xray_bin_dir="$tmp"
xray_conf="$tmp/no-config"
cat > "$tmp/xray" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == -version ]] && exit 0
printf 'Xray 26.10.29\n'
# Exceed the pipe buffer so an early reader close reliably causes SIGPIPE.
for ((i=0; i<10000; i++)); do printf 'additional version output %08d\n' "$i"; done
EOF
chmod +x "$tmp/xray"
log_echo() { :; }
gettext() { printf '%s' "$1"; }
systemctl() { return 0; }
info_extraction() { :; }
health_check_xray_update 26.10.29
echo 'PASS: version health check consumes complete output under pipefail'
