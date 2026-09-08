#!/usr/bin/env bash
# Release reconciliation startup boundary tests.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
export _TEST_MODE=1
# shellcheck source=/dev/null
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true

TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${TMP_ROOT}"' EXIT
idleleo_dir="${TMP_ROOT}/idleleo"
shell_version="3.2.5"
mkdir -p "${idleleo_dir}"

sync_calls=0
reconcile_calls=0
rxa_rill_installed() { return 0; }
rxa_sync_release_helpers() { sync_calls=$((sync_calls + 1)); [[ "$1" == "$shell_version" ]]; }
rxa_reconcile_release() { reconcile_calls=$((reconcile_calls + 1)); [[ "$1" == "$shell_version" ]]; }

if rxa_reconcile_release_if_needed &&
   [[ ${sync_calls} -eq 1 && ${reconcile_calls} -eq 1 ]]; then
    echo 'PASS: missing marker triggers one startup reconciliation'
else
    echo "FAIL: missing marker reconciliation calls sync=${sync_calls} reconcile=${reconcile_calls}"
    exit 1
fi

# The critical migration case: helper sync is required even when Rill is absent.
# Restore the production reconciliation body so this case also proves marker
# commit semantics and the absence of any Rill installation call.
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true
idleleo_dir="${TMP_ROOT}/idleleo"
shell_version="3.2.5"
rm -f "${idleleo_dir}/release-managed.version"
rxa_rill_installed() { return 1; }
install_calls=0
rxa_release_bundle_install() { install_calls=$((install_calls + 1)); return 0; }
sync_calls=0
reconcile_calls=0
rxa_sync_release_helpers() { sync_calls=$((sync_calls + 1)); return 0; }
if rxa_reconcile_release_if_needed >/dev/null 2>&1 &&
   [[ ${sync_calls} -eq 1 && ${install_calls} -eq 0 &&
      -f "${idleleo_dir}/release-managed.version" &&
      "$(cat "${idleleo_dir}/release-managed.version")" == "${shell_version}" ]]; then
    echo 'PASS: missing marker with Rill absent still syncs helpers without auto-install'
else
    echo "FAIL: Rill-absent migration sync=${sync_calls} install=${install_calls}"
    exit 1
fi

# Use call-counting stubs for the marker/retry boundary cases below.
rxa_reconcile_release() { reconcile_calls=$((reconcile_calls + 1)); [[ "$1" == "$shell_version" ]]; }
rxa_sync_release_helpers() { sync_calls=$((sync_calls + 1)); [[ "$1" == "$shell_version" ]]; }
printf '%s\n' "${shell_version}" > "${idleleo_dir}/release-managed.version"
sync_calls=0
reconcile_calls=0
if rxa_reconcile_release_if_needed &&
   [[ ${sync_calls} -eq 0 && ${reconcile_calls} -eq 0 ]]; then
    echo 'PASS: current marker avoids redundant reconciliation'
else
    echo 'FAIL: current marker did not suppress reconciliation'
    exit 1
fi

# A helper sync failure must stop before reconciliation and leave the marker
# absent, so the next mutable startup retries the migration.
rm -f "${idleleo_dir}/release-managed.version"
sync_calls=0
reconcile_calls=0
rxa_sync_release_helpers() { sync_calls=$((sync_calls + 1)); return 1; }
if rxa_reconcile_release_if_needed >/dev/null 2>&1; then
    echo 'FAIL: helper sync failure was reported as success'
    exit 1
elif [[ ${sync_calls} -eq 1 && ${reconcile_calls} -eq 0 && ! -e "${idleleo_dir}/release-managed.version" ]]; then
    echo 'PASS: helper sync failure leaves marker uncommitted'
else
    echo "FAIL: helper failure state sync=${sync_calls} reconcile=${reconcile_calls} marker=$(test -e "${idleleo_dir}/release-managed.version"; echo $?)"
    exit 1
fi

# Stage 4 must be committed before Stage 5 starts, including when manager
# reload fails. This protects the user-facing phase semantics.
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true
idleleo_dir="${TMP_ROOT}/stage-order"
shell_version="3.2.5"
mkdir -p "${idleleo_dir}"
rxa_rill_installed() { return 0; }
rxa_release_checksum() { printf '%064d\n' 0; }
rxa_download_release_asset() { mkdir -p "$(dirname "$3")"; : >"$3"; }
rxa_release_bundle_install() { return 0; }
rxa_reload_manager() { return 1; }
stage_output=$(rxa_reconcile_release "${shell_version}" 2>&1)
stage_rc=$?
stage4_done=$(printf '%s\n' "${stage_output}" | grep -n '\[4/6\].*更新 Rill 核心组件.*完成' | head -1 | cut -d: -f1)
stage5_begin=$(printf '%s\n' "${stage_output}" | grep -n '\[5/6\].*恢复 AI 工作状态.*处理中' | head -1 | cut -d: -f1)
stage5_fail=$(printf '%s\n' "${stage_output}" | grep -n '\[5/6\].*恢复 AI 工作状态.*✗ 失败' | head -1 | cut -d: -f1)
if [[ ${stage_rc} -ne 0 && -n ${stage4_done} && -n ${stage5_begin} && -n ${stage5_fail} &&
      ${stage4_done} -lt ${stage5_begin} && ${stage5_begin} -lt ${stage5_fail} &&
      ! -e "${idleleo_dir}/release-managed.version" ]]; then
    echo 'PASS: Stage 4 completes before Stage 5 reload failure'
else
    echo "FAIL: stage order rc=${stage_rc} stage4=${stage4_done:-missing} stage5_begin=${stage5_begin:-missing} stage5_fail=${stage5_fail:-missing}"
    exit 1
fi

# Restore production Rill detection for the residual-only check.
source "${REPO_DIR}/install.sh" >/dev/null 2>&1 || true
DESTDIR="${TMP_ROOT}/residual"
mkdir -p "${DESTDIR}/etc/rill-xray-agent" "${DESTDIR}/var/lib/rill-xray-agent-runtime"
printf '%s\n' '{"mode":"observe-only"}' > "${DESTDIR}/etc/rill-xray-agent/config.json"
if ! rxa_rill_installed; then
    echo 'PASS: residual-only Rill state remains uninstalled'
else
    echo 'FAIL: residual-only Rill state was treated as installed'
    exit 1
fi
unset DESTDIR

help_output="${TMP_ROOT}/help.out"
if bash "${REPO_DIR}/install.sh" --help >"${help_output}" 2>&1 &&
   ! grep -Fq 'Release reconciliation failed' "${help_output}"; then
    echo 'PASS: readonly help path does not enter reconciliation'
else
    echo 'FAIL: readonly help path entered reconciliation'
    exit 1
fi

echo 'Release reconciliation startup tests passed'
