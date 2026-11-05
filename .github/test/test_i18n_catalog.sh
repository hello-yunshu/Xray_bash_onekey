#!/usr/bin/env bash
# color-test-fixture: strips ANSI from captured tmux output for width checks.
# Locale-independent menu catalog regression.
#
# The target images only have C/C.utf8 generated. gettext ignores LANGUAGE
# there, so this test proves install.sh's direct .mo lookup renders English /
# French without en_US.UTF-8 and falls back to English for a missing entry.
# It also proves the [信息]/[错误]/[警告] prefixes are refreshed.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "${HERE}/../.." && pwd)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/idleleo-i18n-test.XXXXXX")
trap 'rm -rf "${TMP_ROOT}"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }

if ! command -v msgunfmt >/dev/null 2>&1 || ! command -v gettext >/dev/null 2>&1; then
    echo "SKIP: gettext/msgunfmt unavailable"
    exit 0
fi

mkdir -p "${TMP_ROOT}/idleleo/languages/en/LC_MESSAGES" \
    "${TMP_ROOT}/idleleo/languages/fr/LC_MESSAGES"
cp "${REPO_DIR}/i18n/languages/en/LC_MESSAGES/xray_install.mo" \
    "${TMP_ROOT}/idleleo/languages/en/LC_MESSAGES/xray_install.mo"
cp "${REPO_DIR}/i18n/languages/fr/LC_MESSAGES/xray_install.mo" \
    "${TMP_ROOT}/idleleo/languages/fr/LC_MESSAGES/xray_install.mo"

export _TEST_MODE=1
# shellcheck disable=SC1090
source "${REPO_DIR}/install.sh"
idleleo_dir="${TMP_ROOT}/idleleo"
TEXTDOMAIN="xray_install"
TEXTDOMAINDIR="${idleleo_dir}/languages"
export TEXTDOMAIN TEXTDOMAINDIR

if locale -a 2>/dev/null | grep -qi 'en_US'; then
    echo "  INFO: en_US locale is generated; the test still checks the direct catalog path"
else
    ok "target image has no en_US locale (only C/C.utf8), as intended"
fi

printf 'LANG=en_US.UTF-8\nLC_MESSAGES=en_US.UTF-8\n' >"${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
[[ "$(gettext "总览")" == "Overview" ]] && ok "English catalog works without en_US locale" || bad "English menu fell back: $(gettext "总览")"
[[ "$(gettext "信息")" == "information" ]] && ok "English msgid lookup works" || bad "English msgid lookup failed"
[[ "${Info}" == *"information"* ]] && ok "Info prefix refreshed to English" || bad "Info prefix is stale: ${Info}"

# Selecting a locale the image does not have must not leak bash setlocale noise.
setlocale_err=$(init_language offline 2>&1 >/dev/null)
if [[ "${setlocale_err}" == *setlocale* ]]; then
    bad "English init leaked a setlocale warning: ${setlocale_err}"
else
    ok "English init emits no setlocale warning"
fi
[[ "$(_xray_lang_display)" == "en_US" ]] && ok "header shows en_US, not an empty/unavailable locale" || bad "header language: $(_xray_lang_display)"

# The actual main menu, not just a single gettext lookup. Initialize the
# runtime status fields normally filled by read_version; the test only renders.
shell_emoji=""; shell_need_update=""; xray_need_update=""; nginx_need_update=""
xray_status=""; nginx_status=""; xray_local_connect_status=""
menu_out=$(printf '0\n' | menu 2>/dev/null || true)
if grep -q 'installation wizard' <<<"${menu_out}" && ! grep -q '安装向导' <<<"${menu_out}"; then
    ok "English main menu has no Chinese menu items"
else
    bad "English main menu is mixed or still Chinese"
fi

# The stats wrapper must pass the menu language through without a gettext probe.
if grep -q '_stats_lang="${_XRAY_UI_LANG:-zh}"' "${REPO_DIR}/install.sh" &&
    ! grep -q '_stats_lang="zh"' "${REPO_DIR}/install.sh"; then
    ok "stats wrapper keeps the menu language (no zh downgrade)"
else
    bad "stats wrapper still downgrades to zh"
fi

printf 'LANG=fr_FR.UTF-8\nLC_MESSAGES=fr_FR.UTF-8\n' >"${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
[[ "$(gettext "总览")" == "Vue d'ensemble" ]] && ok "French catalog works without fr_FR locale" || bad "French menu failed: $(gettext "总览")"
[[ "${Info}" == *"informations"* ]] && ok "Info prefix refreshed to French" || bad "French Info prefix stale: ${Info}"

# A partially translated catalog must fall back per-entry to English, never
# leave a Chinese line inside a French screen.
cat >"${TMP_ROOT}/partial.po" <<'EOF'
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\n"

msgid "信息"
msgstr "informations"

msgid "总览"
msgstr ""
EOF
mkdir -p "${TMP_ROOT}/idleleo/languages/fr/LC_MESSAGES"
msgfmt -o "${TMP_ROOT}/idleleo/languages/fr/LC_MESSAGES/xray_install.mo" \
    "${TMP_ROOT}/partial.po"
printf 'LANG=fr_FR.UTF-8\nLC_MESSAGES=fr_FR.UTF-8\n' >"${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
[[ "$(gettext "总览")" == "Overview" ]] && ok "missing French entry falls back to English" || bad "missing entry fallback: $(gettext "总览")"

# A missing language directory must use the same fallback as the stats helper.
rm -rf "${TMP_ROOT}/idleleo/languages/fr"
printf 'LANG=fr_FR.UTF-8\nLC_MESSAGES=fr_FR.UTF-8\n' >"${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
[[ "$(gettext "总览")" == "Overview" ]] && ok "missing fr directory falls back to English" || bad "missing dir fallback: $(gettext "总览")"

rm -f "${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
[[ "$(gettext "总览")" == "总览" ]] && ok "no language.conf returns Chinese msgid" || bad "Chinese default broken: $(gettext "总览")"
[[ "${Info}" == *"信息"* ]] && ok "Chinese Info prefix restored" || bad "Chinese Info prefix broken: ${Info}"
[[ "$(_xray_lang_display)" == "zh_CN" ]] && ok "header shows zh_CN for the Chinese default" || bad "header language: $(_xray_lang_display)"
menu_zh=$(printf '0\n' | menu 2>/dev/null || true)
if grep -q '安装向导' <<<"${menu_zh}" && ! grep -q 'installation wizard' <<<"${menu_zh}"; then
    ok "Chinese main menu has no English menu items"
else
    bad "Chinese main menu is mixed or still English"
fi

# Real 45-column tmux: the box must shrink instead of wrapping.
if command -v tmux >/dev/null 2>&1; then
    cat >"${TMP_ROOT}/menu-run.sh" <<EOF
#!/usr/bin/env bash
_TEST_MODE=1
source "${REPO_DIR}/install.sh" >/dev/null 2>&1
idleleo_dir="${TMP_ROOT}/idleleo"
printf 'LANG=en_US.UTF-8\nLC_MESSAGES=en_US.UTF-8\n' >"\${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
shell_emoji=""; shell_need_update=""; xray_need_update=""; nginx_need_update=""
xray_status=""; nginx_status=""; xray_local_connect_status=""
printf '0\n' | menu
sleep 10
EOF
    tmux kill-session -t i18n-menu 2>/dev/null || true
    tmux new-session -d -s i18n-menu -x 45 -y 40 "bash '${TMP_ROOT}/menu-run.sh'"
    sleep 8
    tmux capture-pane -pt i18n-menu >"${TMP_ROOT}/menu-45.txt" 2>/dev/null || true
    tmux kill-session -t i18n-menu 2>/dev/null || true
    sed $'s/\033\\[[0-9;]*m//g' "${TMP_ROOT}/menu-45.txt" >"${TMP_ROOT}/menu-45.clean"
    tops=$(grep -c '^╭─.*╮$' "${TMP_ROOT}/menu-45.clean" || true)
    bottoms=$(grep -c '^╰.*╯$' "${TMP_ROOT}/menu-45.clean" || true)
    if [[ "${tops}" -eq 2 && "${bottoms}" -eq 2 ]]; then
        ok "45-column menu borders stay closed"
    else
        bad "45-column menu wrapped (top=${tops} bottom=${bottoms})"
    fi
    WC_LOCALE=$(locale -a 2>/dev/null | grep -ix 'C.utf8' | head -1)
    [[ -n "${WC_LOCALE}" ]] || WC_LOCALE=$(locale -a 2>/dev/null | grep -ix 'C.UTF-8' | head -1)
    [[ -n "${WC_LOCALE}" ]] || WC_LOCALE=C
    menu_width=$(LC_ALL="${WC_LOCALE}" wc -L <"${TMP_ROOT}/menu-45.clean" | tr -d ' ')
    [[ "${menu_width}" -le 45 ]] && ok "45-column menu renders ${menu_width} cols" || bad "45-column menu renders ${menu_width} cols"
else
    echo "  SKIP: tmux unavailable for the 45-column menu check"
fi

printf 'PASS=%s FAIL=%s\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
