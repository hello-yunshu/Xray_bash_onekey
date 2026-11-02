#!/usr/bin/env bash
# The release workflow reads the version from install.sh and the CHANGELOG is
# the human-facing record; both must agree before a tag can be created.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${REPO_DIR}"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL: %s\n' "$1"; }

version_count=$(grep -c '^shell_version="[0-9][0-9.]*"$' install.sh || true)
version=$(sed -n 's/^shell_version="\([0-9][0-9.]*\)"$/\1/p' install.sh)
if [[ "${version_count}" == "1" && "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ok "install.sh declares exactly one semantic shell_version (${version})"
else
    bad "install.sh must contain exactly one semantic shell_version (count=${version_count}, value='${version}')"
fi

if grep -Fq "## ${version} " CHANGELOG.md; then
    ok "CHANGELOG.md has an entry for ${version}"
else
    bad "CHANGELOG.md has no '## ${version}' entry"
fi

if grep -Fq "中转节点" README.md; then
    ok "README.md documents the relay role"
else
    bad "README.md does not document the relay role"
fi

if bash -n install.sh; then
    ok "install.sh syntax"
else
    bad "install.sh syntax"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
