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

if grep -Fq "当前版本：" README.md; then
    bad "README.md still contains a shell version banner"
else
    ok "README.md has no shell version banner"
fi

if grep -Eq '^(###|##) 3\.[0-9]+\.[0-9]+' README.md; then
    bad "README.md still contains version-specific upgrade sections"
else
    ok "README.md has no version-specific upgrade sections"
fi

if grep -Eq '\b3\.[0-9]+\.[0-9]+\b' README.md i18n/languages/*/README.md; then
    bad "README files still mention a shell version number"
else
    ok "README files contain no shell version numbers"
fi

if grep -Fq "中转节点" README.md; then
    ok "README.md documents the relay role"
else
    bad "README.md does not document the relay role"
fi

# README is product documentation, not release history. The release version
# lives in install.sh and CHANGELOG.md; the README translation workflow still
# validates structure, glossary use, and Chinese residue for all languages.


if bash -n install.sh; then
    ok "install.sh syntax"
else
    bad "install.sh syntax"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
