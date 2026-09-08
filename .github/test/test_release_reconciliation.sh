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
shell_version="3.2.3"
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

rxa_rill_installed() { return 1; }
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
