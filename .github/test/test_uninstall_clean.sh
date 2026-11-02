#!/usr/bin/env bash
# 3.3.1 H2: real `--purge` must remove the Xray host surface without requiring
# offline installer metadata. Run after a real (mode) installation.
set -uo pipefail

LOG=$(mktemp)
trap 'rm -f "${LOG}"' EXIT
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }
exists() { [[ -e "$1" || -L "$1" ]]; }
active() { systemctl is-active --quiet "$1" 2>/dev/null; }

[[ -f /etc/idleleo/install.sh ]] || { echo 'FATAL: managed install missing'; exit 1; }
role=$(jq -r '.role // "node"' /etc/idleleo/conf/install_config.json 2>/dev/null || echo node)
echo "=== purge role=${role} ==="

set +e
printf 'y\ny\ny\ny\n' | bash /etc/idleleo/install.sh --purge >"${LOG}" 2>&1
rc=$?
set -e
[[ ${rc} -eq 0 ]] && ok "purge exits 0" || bad "purge exits ${rc}"
if grep -Fq 'Xray-install verified metadata is missing or invalid' "${LOG}"; then
    bad "purge still tried to require installer metadata"
else
    ok "purge did not require installer metadata"
fi

if [[ "${role}" == "relay" ]]; then
    exists /usr/local/nginx && bad "relay nginx binary remains" || ok "relay nginx binary removed"
    exists /etc/systemd/system/nginx.service && bad "relay nginx unit remains" || ok "relay nginx unit removed"
    active nginx && bad "relay nginx still active" || ok "relay nginx inactive"
else
    exists /usr/local/bin/xray && bad "Xray binary remains" || ok "Xray binary removed"
    exists /usr/local/etc/xray && bad "/usr/local/etc/xray remains" || ok "/usr/local/etc/xray removed"
    exists /etc/idleleo/conf/xray && bad "managed Xray config dir remains" || ok "managed Xray config dir removed"
    exists /etc/systemd/system/xray.service && bad "Xray unit remains" || ok "Xray unit removed"
    exists /etc/systemd/system/xray@.service && bad "Xray@ unit remains" || ok "Xray@ unit removed"
    active xray && bad "Xray still active" || ok "Xray inactive"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
