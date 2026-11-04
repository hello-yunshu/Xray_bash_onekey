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

# README is product documentation, not release history; the release version
# lives in install.sh and CHANGELOG.md. These checks reject version narration
# (banners, version headings, upgrade arrows and release-note phrasing), not
# incidental version numbers in examples, CHANGELOG links or placeholders.
# The i18n validator checks structure, glossary and Chinese residue only; it
# does not compare release versions, so this is the single version gate.
README_VERSION_RE='^(#{2,3}[[:space:]]+[vV]?3\.[0-9]+\.[0-9]+([[:space:]]|$)|[[:space:]]*(当前版本|Current[[:space:]]+version|Version[[:space:]]+actuelle|Текущая[[:space:]]+версия|نسخه[[:space:]]+فعلی|현재[[:space:]]+버전)[^0-9]*[vV]?3\.[0-9]+\.[0-9]+|[[:space:]]*(#{2,3}[[:space:]]+)?[vV]?3\.[0-9]+\.[0-9]+[[:space:]]*(→|->)[[:space:]]*[vV]?3\.[0-9]+\.[0-9]+|(^|[^[:alnum:]])(本版本新增|本版修复|This[[:space:]]+release[[:space:]]+adds|This[[:space:]]+version[[:space:]]+adds|Fixed[[:space:]]+in[[:space:]]+this[[:space:]]+release|New[[:space:]]+in[[:space:]]+this[[:space:]]+version))'

readme_narrates_version() {
    grep -Eq "${README_VERSION_RE}" "$1"
}

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

if readme_narrates_version README.md; then
    bad "README.md narrates a shell version"
else
    ok "README.md does not narrate a shell version"
fi

translation_narrates=0
for readme in i18n/languages/*/README.md; do
    if readme_narrates_version "${readme}"; then
        bad "${readme} narrates a shell version"
        translation_narrates=1
    fi
done
if [[ ${translation_narrates} -eq 0 ]]; then
    ok "translated READMEs do not narrate a shell version"
fi

if grep -Fq "中转节点" README.md; then
    ok "README.md documents the relay role"
else
    bad "README.md does not document the relay role"
fi

# Fixture cases prove both halves of the contract: incidental version-like
# text must not block, while real version narration must still fail.
FIXTURE_ROOT=$(mktemp -d)
trap 'rm -rf "${FIXTURE_ROOT}"' EXIT
fixture_index=0
fixture_case() {
    local label=$1 expected=$2 content=$3 file result
    fixture_index=$((fixture_index + 1))
    file="${FIXTURE_ROOT}/case-${fixture_index}.md"
    printf '%s\n' "${content}" >"${file}"
    if readme_narrates_version "${file}"; then
        result=narrate
    else
        result=clean
    fi
    if [[ "${result}" == "${expected}" ]]; then
        ok "fixture ${label}: ${result}"
    else
        bad "fixture ${label}: expected ${expected}, got ${result}"
    fi
}

fixture_case "example version in prose" clean "例如版本 3.3.2 只是示例"
fixture_case "CHANGELOG link without version" clean "[CHANGELOG](https://github.com/hello-yunshu/Xray_bash_onekey/blob/main/CHANGELOG.md)"
fixture_case "CHANGELOG link text with version" clean "[CHANGELOG 3.3.2](https://example.com/changelog)"
fixture_case "release tag placeholder" clean "https://github.com/hello-yunshu/Xray_bash_onekey/releases/tag/v{{version}}"
fixture_case "example version in code span" clean "在代码块中示例：\`v3.3.2\`"
fixture_case "example version in table" clean "| 示例版本 | 3.3.2 |"

fixture_case "Chinese version banner" narrate "当前版本：3.3.2"
fixture_case "English version banner" narrate "Current version: **3.3.2**"
fixture_case "French version banner" narrate "Version actuelle : **3.3.2**"
fixture_case "Russian version banner" narrate "Текущая версия: **3.3.2**"
fixture_case "Persian version banner" narrate "نسخه فعلی: **3.3.2**"
fixture_case "Korean version banner" narrate "현재 버전: **3.3.2**"
fixture_case "version heading" narrate "## 3.3.2"
fixture_case "version upgrade arrow" narrate "### 3.3.1 → 3.3.2"
fixture_case "release-note phrase" narrate "本版本新增：统计读取"

if bash -n install.sh; then
    ok "install.sh syntax"
else
    bad "install.sh syntax"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
