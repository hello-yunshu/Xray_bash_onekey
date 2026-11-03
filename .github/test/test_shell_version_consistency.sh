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

if grep -Fq "当前版本：**${version}**" README.md; then
    ok "README.md advertises ${version}"
else
    bad "README.md does not advertise ${version}"
fi

if grep -Fq "Current version: **${version}**" i18n/languages/en/README.md; then
    ok "English README advertises ${version}"
else
    bad "English README does not advertise ${version}"
fi

if grep -Fq "中转节点" README.md; then
    ok "README.md documents the relay role"
else
    bad "README.md does not document the relay role"
fi

# Non-English READMEs are machine-translated now. This shell test keeps the
# hard gate on the canonical English version line; the README translation
# workflow validates all five outputs (structure, version and Chinese
# residue) before it opens a PR. A hard gate here would block version-bump
# PRs until the post-merge translation PR lands.
for lang in fr ru fa ko; do
    if [[ -f "i18n/languages/${lang}/README.md" ]] &&
       grep -Fq "${version}" "i18n/languages/${lang}/README.md"; then
        printf '  NOTE: i18n/languages/%s/README.md advertises %s (validated by the translation workflow)\n' "${lang}" "${version}"
    else
        printf '  NOTE: i18n/languages/%s/README.md does not advertise %s (translation workflow will refresh it)\n' "${lang}" "${version}"
    fi
done

if bash -n install.sh; then
    ok "install.sh syntax"
else
    bad "install.sh syntax"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
