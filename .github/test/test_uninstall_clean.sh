#!/usr/bin/env bash
# 3.3.1 H2: real `--purge` must remove the Xray/Nginx host surface without
# requiring offline installer metadata. Run after a real (mode) installation.
#
# PURGE_DROP_BINARY=1 additionally simulates an interrupted/partial uninstall:
# the role binary is deleted before purge (node keeps the main unit, drops
# xray@; relay also loses its Nginx dir/unit). The managed unit/config surface
# must still be removed. This is the case where the old `if [[ -f binary ]]`
# guard left units and /usr/local/etc/xray behind while returning 0.
#
# PURGE_CORRUPT_CONFIG=1 corrupts install_config.json before a node purge.
# Purge must still clean the host and return 0, with only a diagnostic warning
# for the skipped metadata edit.
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

# Real install-success surface: basic_information runs after installation and
# must not persist the UUIDv5 mapping string to install.log.
if [[ -f /etc/idleleo/logs/install.log ]]; then
    if grep -Eq '映射字符串[^:：=]*[:：=][[:space:]]*[A-Za-z0-9]' /etc/idleleo/logs/install.log; then
        bad "install.log contains UUIDv5 mapping-string material"
    else
        ok "install.log contains no UUIDv5 mapping-string material"
    fi
fi
drop_binary=${PURGE_DROP_BINARY:-0}
corrupt_config=${PURGE_CORRUPT_CONFIG:-0}
echo "=== purge role=${role} drop_binary=${drop_binary} corrupt_config=${corrupt_config} ==="

if [[ "${drop_binary}" == "1" ]]; then
    if [[ "${role}" == "relay" ]]; then
        rm -rf /usr/local/nginx
        rm -f /etc/systemd/system/nginx.service
        # Mixed/interrupted host: the relay still carries an old node surface.
        # Purge must remove it instead of returning 0 with Xray bits left.
        mkdir -p /usr/local/etc/xray /usr/local/share/xray
        printf '{"inbounds":[]}' > /usr/local/etc/xray/config.json
        printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/xray
        chmod 755 /usr/local/bin/xray
        cat > /etc/systemd/system/xray.service <<'UNIT'
[Unit]
Description=Xray residue
[Service]
ExecStart=/usr/local/bin/xray run
[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload >/dev/null 2>&1 || true
    else
        # The reported state: the Xray binary is gone (e.g. an interrupted
        # upgrade) but the main unit and managed config still exist. Keep the
        # main unit so purge must disable/stop it, remove both unit files, and
        # run daemon-reload. Drop xray@ to also cover a partially missing unit.
        rm -f /usr/local/bin/xray
        rm -f /etc/systemd/system/xray@.service
    fi
    echo "=== simulated interrupted uninstall: role surface not present ==="
fi

# Corrupting the role document on a relay would make role detection fall back
# to the node path and would not exercise relay_uninstall; node is the intended
# corrupt-metadata fixture. The relay mixed-state fixture above keeps valid JSON.
if [[ "${corrupt_config}" == "1" && "${role}" != "relay" ]]; then
    printf '{not-json' > /etc/idleleo/conf/install_config.json
    echo "=== simulated corrupt install_config.json ==="
fi

# Keep-config=no + delete-scripts=yes: the strongest purge, so a leftover
# /etc/idleleo is unambiguous.
if [[ "${role}" == "relay" ]]; then
    purge_input=$'y\nn\ny\n'
else
    purge_input=$'n\ny\n'
fi

set +e
printf '%s' "${purge_input}" | bash /etc/idleleo/install.sh --purge >"${LOG}" 2>&1
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
    exists /etc/idleleo/conf/nginx && bad "managed relay config dir remains" || ok "managed relay config dir removed"
    # PURGE_DROP_BINARY=1 seeds the mixed node surface above. These must be
    # removed on the real relay path, not left behind with RC=0.
    exists /usr/local/etc/xray && bad "relay purge left /usr/local/etc/xray" || ok "relay purge removed /usr/local/etc/xray"
    exists /usr/local/share/xray && bad "relay purge left /usr/local/share/xray" || ok "relay purge removed /usr/local/share/xray"
    exists /usr/local/bin/xray && bad "relay purge left /usr/local/bin/xray" || ok "relay purge removed /usr/local/bin/xray"
    exists /etc/systemd/system/xray.service && bad "relay purge left Xray unit" || ok "relay purge removed Xray unit"
else
    exists /usr/local/bin/xray && bad "Xray binary remains" || ok "Xray binary removed"
    exists /usr/local/etc/xray && bad "/usr/local/etc/xray remains" || ok "/usr/local/etc/xray removed"
    exists /etc/idleleo/conf/xray && bad "managed Xray config dir remains" || ok "managed Xray config dir removed"
    exists /etc/systemd/system/xray.service && bad "Xray unit remains" || ok "Xray unit removed"
    exists /etc/systemd/system/xray@.service && bad "Xray@ unit remains" || ok "Xray@ unit removed"
    active xray && bad "Xray still active" || ok "Xray inactive"
fi

# The terminal-only tail after removing /etc/idleleo must not make tee print a
# false error (the old log_echo attempted to append to the deleted install.log).
if grep -Fq 'tee: ' "${LOG}"; then
    bad "purge produced a tee error after removing the log directory"
else
    ok "purge produced no tee error"
fi
exists /etc/idleleo && bad "/etc/idleleo remains after a full purge" || ok "/etc/idleleo removed"
if [[ "${corrupt_config}" == "1" && "${role}" != "relay" ]]; then
    if grep -Eq 'Xray 卸载失败|Nginx 卸载失败' "${LOG}"; then
        bad "corrupt install_config turned a completed purge into a failure"
    else
        ok "corrupt install_config did not turn purge into a failure"
    fi
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
