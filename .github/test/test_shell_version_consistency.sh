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

# README is product documentation, not release history. The gate is
# deny-by-default: any `3.x.y` (optional leading v) is version narration
# unless it sits in one of these explicit allowlisted contexts:
#   * fenced code blocks
#   * inline code spans
#   * URL/link targets (target only; visible link text is still scanned)
#   * CHANGELOG link text (e.g. [CHANGELOG 3.3.2](...))
#   * placeholders such as {{version}} (no concrete 3.x.y)
#   * explicit example/sample sentences or table rows
#   * JSON machine-readable fields ("version": "3.3.2")
# HTML comments are deliberately NOT exempt: they still ship in README and can
# become visible or stale. Image badges are NOT exempt either: a version badge
# is a visible release banner even though its URL would be an allowed target.
# The i18n validator checks structure, glossary and Chinese residue only; it
# does not compare release versions, so this test is the single version gate.
README_VERSION_RE='[vV]?3\.[0-9]+\.[0-9]+'
# Release-note wording is narrative even when the sentence contains no number
# (e.g. "本版本新增：统计读取"). This is a small residual phrase check on top of
# the default numeric ban, not the primary gate.
README_RELEASE_NOTE_RE='(^|[^[:alnum:]])(本版本新增|本版修复|This[[:space:]]+release[[:space:]]+adds|This[[:space:]]+version[[:space:]]+adds|Fixed[[:space:]]+in[[:space:]]+this[[:space:]]+release|New[[:space:]]+in[[:space:]]+this[[:space:]]+version)'

readme_narrates_version() {
    local file="$1" line sanitized
    while IFS= read -r line; do
        # A versioned image/badge is visible narration, not an allowed URL.
        if [[ "${line}" =~ !\[.*[vV]?3\.[0-9]+\.[0-9]+ ]]; then
            return 0
        fi
        # Remove inline code and link/raw-URL targets before scanning prose.
        # Link text remains, so [Release 3.3.2](...) is still caught.
        sanitized=$(printf '%s\n' "${line}" | sed -E \
            -e 's/`[^`]*`//g' \
            -e 's#\]\([^)]*\)#](URL)#g' \
            -e 's#https?://[^[:space:]]+#URL#g')
        # JSON machine-readable fields are allowed.
        if [[ "${sanitized}" =~ ^[[:space:]]*\"(shell_)?version\"[[:space:]]*:[[:space:]]*\"[vV]?3\.[0-9]+\.[0-9]+\"[[:space:]]*,?[[:space:]]*$ ]]; then
            continue
        fi
        # Release-note wording is narrative even without a version number.
        if [[ "${sanitized}" =~ ${README_RELEASE_NOTE_RE} ]]; then
            return 0
        fi
        # Explicit example/sample contexts are allowed; bare prose is not.
        if [[ "${sanitized}" =~ (示例|例子|[Ee]xample|[Ss]ample) ]] &&
            [[ "${sanitized}" =~ ${README_VERSION_RE} ]]; then
            continue
        fi
        # CHANGELOG link text may carry its anchor version.
        sanitized=$(printf '%s\n' "${sanitized}" | sed -E \
            -e 's#\[[^]]*CHANGELOG[^]]*[vV]?3\.[0-9]+\.[0-9]+[^]]*\]#[CHANGELOG]#g')
        if [[ "${sanitized}" =~ ${README_VERSION_RE} ]]; then
            return 0
        fi
    done < <(awk '
        /^[[:space:]]*(```|~~~)/ { in_fence = !in_fence; next }
        in_fence { next }
        { print }
    ' "$file")
    return 1
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
fixture_case "JSON machine-readable version field" clean '"version": "3.3.2"'

fixture_case "Chinese version banner" narrate "当前版本：3.3.2"
fixture_case "English version banner" narrate "Current version: **3.3.2**"
fixture_case "French version banner" narrate "Version actuelle : **3.3.2**"
fixture_case "Russian version banner" narrate "Текущая версия: **3.3.2**"
fixture_case "Persian version banner" narrate "نسخه فعلی: **3.3.2**"
fixture_case "Korean version banner" narrate "현재 버전: **3.3.2**"
fixture_case "version heading" narrate "## 3.3.2"
fixture_case "version upgrade arrow" narrate "### 3.3.1 → 3.3.2"
fixture_case "release-note phrase" narrate "本版本新增：统计读取"

# Bypass forms found in the independent recheck. These must be blocked by the
# deny-by-default scan, not just by the old narrow phrase list.
fixture_case "version-number suffix" narrate "版本号 3.3.2（见下）"
fixture_case "Release prefix" narrate "Release 3.3.2"
fixture_case "last-update slash" narrate "last update: 2026-11-04 / 3.3.2"
fixture_case "Fixed in version" narrate "Fixed in 3.3.2"
fixture_case "plain version label" narrate "版本：3.3.2"
fixture_case "Latest version prefix" narrate "Latest version: 3.3.2"
fixture_case "h4 version heading" narrate "#### 3.3.2"
fixture_case "multiline version banner" narrate $'Current version:\n3.3.2'
fixture_case "HTML comment banner" narrate "<!-- 当前版本：3.3.2 -->"
fixture_case "bold bare version" narrate "**3.3.2**"
fixture_case "version badge image" narrate "![version](https://img.shields.io/badge/version-3.3.2-blue)"
fixture_case "bare version line" narrate "3.3.2"
fixture_case "example URL does not allow prose" narrate "Release 3.3.2 https://example.com"

if bash -n install.sh; then
    ok "install.sh syntax"
else
    bad "install.sh syntax"
fi

printf '\nSummary: PASS=%d FAIL=%d\n' "${PASS}" "${FAIL}"
[[ ${FAIL} -eq 0 ]]
