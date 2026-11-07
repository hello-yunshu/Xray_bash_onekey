#!/usr/bin/env bash
# color-test-fixture: strips ANSI from captured PTY output for width checks.
# Locale-independent menu catalog regression.
#
# Requires: bash, gettext/msgunfmt, python3 (PTY menu layout assertions).
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
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 required for the PTY menu layout assertions"
    exit 0
fi

for lang in en fr ru ko fa zh_CN; do
    mkdir -p "${TMP_ROOT}/idleleo/languages/${lang}/LC_MESSAGES"
    cp "${REPO_DIR}/i18n/languages/${lang}/LC_MESSAGES/xray_install.mo" \
        "${TMP_ROOT}/idleleo/languages/${lang}/LC_MESSAGES/xray_install.mo"
done

export _TEST_MODE=1
# The test runs with set -u; on a non-Linux dev host /etc/os-release may be
# absent and install.sh would abort mid-source. Restore -u after loading.
set +u
# shellcheck disable=SC1090
source "${REPO_DIR}/install.sh"
set -u
# install.sh pins PATH to the standard system directories; on macOS the
# Homebrew gettext tools live elsewhere. Restore them for this test only.
if [[ -d /opt/homebrew/bin ]]; then
    PATH="${PATH}:/opt/homebrew/bin"
    export PATH
fi
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

# 3.3.5 regression: the new nginx xHTTP warning must resolve in every shipped
# translation instead of falling back to Chinese. The auto-translate run that
# introduced it aborted on upstream quota before writing the catalogs.
xhttp_warning='检测到旧版 Nginx 模板：xHTTP 上行超过 1MB 会被 Nginx 拒绝 (413)。更新脚本不会重建 Nginx 配置，请重新运行安装脚本重建，或手工在 xHTTP location 放开 client_max_body_size 0;'
for entry in "en_US:Legacy Nginx template detected" "fr_FR:Ancien modèle Nginx détecté" \
    "ru_RU:Обнаружен устаревший шаблон Nginx" "ko_KR:이전 Nginx 템플릿이 감지되었습니다" \
    "fa_IR:قالب قدیمی Nginx شناسایی شد"; do
    locale_name=${entry%%:*}
    expected=${entry#*:}
    printf 'LANG=%s\nLC_MESSAGES=%s\n' "${locale_name}.UTF-8" "${locale_name}.UTF-8" >"${idleleo_dir}/language.conf"
    init_language offline >/dev/null 2>&1
    rendered=$(gettext "$xhttp_warning")
    if [[ "$rendered" == "$xhttp_warning" ]]; then
        bad "${locale_name} xHTTP warning still falls back to Chinese"
    elif [[ "$rendered" == *"$expected"* ]]; then
        ok "${locale_name} xHTTP warning translated"
    else
        bad "${locale_name} xHTTP warning unexpected: ${rendered:0:40}"
    fi
done

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
cat >"${TMP_ROOT}/menu-run.sh" <<EOF
#!/usr/bin/env bash
_TEST_MODE=1
source "${REPO_DIR}/install.sh" >/dev/null 2>&1
if [[ -d /opt/homebrew/bin ]]; then PATH="\${PATH}:/opt/homebrew/bin"; export PATH; fi
idleleo_dir="${TMP_ROOT}/idleleo"
printf 'LANG=%s\nLC_MESSAGES=%s\n' "\${MENU_LOCALE:-en_US.UTF-8}" "\${MENU_LOCALE:-en_US.UTF-8}" >"\${idleleo_dir}/language.conf"
init_language offline >/dev/null 2>&1
shell_emoji=""; shell_need_update=""; xray_need_update=""; nginx_need_update=""
xray_status=""; nginx_status=""; xray_local_connect_status=""
printf '0\n' | menu
[[ "\${MENU_HOLD:-0}" == "1" ]] && sleep 10
exit 0
EOF

WC_LOCALE=$(locale -a 2>/dev/null | grep -ix 'C.utf8' | head -1)
[[ -n "${WC_LOCALE}" ]] || WC_LOCALE=$(locale -a 2>/dev/null | grep -ix 'C.UTF-8' | head -1)
[[ -n "${WC_LOCALE}" ]] || WC_LOCALE=C

# Every row inside a menu box must start and end on the border and keep the
# same display width as the box top; a wrapped continuation line has no
# leading border and is counted as an error.
assert_menu_rows_closed() {
    local file="$1" limit="$2" label="$3"
    local line width first_width="" errors=0 rows=0 boxes=0 inside=0
    while IFS= read -r line; do
        if [[ ${inside} -eq 0 ]]; then
            case "${line}" in
                '╭'*'╮')
                    inside=1
                    boxes=$((boxes + 1))
                    rows=$((rows + 1))
                    width=$(LC_ALL="${WC_LOCALE}" wc -L <<<"${line}" | tr -d ' ')
                    [[ -n "${first_width}" ]] || first_width=${width}
                    ((width > limit)) && errors=$((errors + 1))
                    ;;
                '╭'*) errors=$((errors + 1)) ;;
            esac
            continue
        fi
        rows=$((rows + 1))
        case "${line}" in
            '│'*'│'|'├'*'┤') ;;
            '╰'*'╯') inside=0 ;;
            *) errors=$((errors + 1)); continue ;;
        esac
        width=$(LC_ALL="${WC_LOCALE}" wc -L <<<"${line}" | tr -d ' ')
        [[ "${width}" -ne "${first_width}" ]] && errors=$((errors + 1))
        ((width > limit)) && errors=$((errors + 1))
    done <"${file}"
    if [[ ${inside} -eq 0 && ${boxes} -ge 2 && ${errors} -eq 0 ]]; then
        ok "${label}: ${boxes} boxes, ${rows} rows closed at ${first_width}/${limit} cols"
    else
        bad "${label}: boxes=${boxes} rows=${rows} errors=${errors} width=${first_width} limit=${limit}"
    fi
}

if command -v python3 >/dev/null 2>&1; then
    cat >"${TMP_ROOT}/menu-pty.py" <<'PY'
import fcntl
import os
import pty
import struct
import sys
import termios

width, height, script = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
env = dict(os.environ)
env["TERM"] = "xterm-256color"
env.pop("NO_COLOR", None)
if env.get("PTY_NO_COLOR") == "1":
    env["NO_COLOR"] = "1"

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
pid = os.fork()
if pid == 0:
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.dup2(slave, 0)
    os.dup2(slave, 1)
    os.dup2(slave, 2)
    os.close(master)
    os.close(slave)
    os.execvpe("bash", ["bash", script], env)

os.close(slave)
chunks = []
while True:
    try:
        data = os.read(master, 4096)
    except OSError:
        break
    if not data:
        break
    chunks.append(data)
os.close(master)
os.waitpid(pid, 0)
sys.stdout.buffer.write(b"".join(chunks))
PY
    for width in 45 80 100 120; do
        PTY_NO_COLOR=1 python3 "${TMP_ROOT}/menu-pty.py" "${width}" 40 \
            "${TMP_ROOT}/menu-run.sh" >"${TMP_ROOT}/menu-${width}.raw" 2>/dev/null || true
        sed $'s/\033\\[[0-9;?]*[A-Za-z]/ /g' "${TMP_ROOT}/menu-${width}.raw" \
            | tr -d '\r' >"${TMP_ROOT}/menu-${width}.clean"
        assert_menu_rows_closed "${TMP_ROOT}/menu-${width}.clean" "${width}" \
            "${width}-column main menu"
        if grep -q $'\033' "${TMP_ROOT}/menu-${width}.raw"; then
            bad "${width}-column NO_COLOR menu emitted ESC"
        else
            ok "${width}-column NO_COLOR menu emits zero ESC"
        fi
    done
    # Long translated section titles (fr/ru) must be truncated inside the box
    # at 45 columns, not printed at full width with a wrapped continuation.
    for locale in en_US.UTF-8 zh_CN.UTF-8 fr_FR.UTF-8 ru_RU.UTF-8 fa_IR.UTF-8 ko_KR.UTF-8; do
        lang=${locale%%.*}
        MENU_LOCALE="${locale}" PTY_NO_COLOR=1 \
            python3 "${TMP_ROOT}/menu-pty.py" 45 40 "${TMP_ROOT}/menu-run.sh" \
            >"${TMP_ROOT}/menu-${lang}-45.raw" 2>/dev/null || true
        sed $'s/\033\\[[0-9;?]*[A-Za-z]/ /g' "${TMP_ROOT}/menu-${lang}-45.raw" \
            | tr -d '\r' >"${TMP_ROOT}/menu-${lang}-45.clean"
        assert_menu_rows_closed "${TMP_ROOT}/menu-${lang}-45.clean" 45 \
            "${lang} 45-column main menu"
        if grep -q $'\033' "${TMP_ROOT}/menu-${lang}-45.raw"; then
            bad "${lang} 45-column NO_COLOR menu emitted ESC"
        else
            ok "${lang} 45-column NO_COLOR menu emits zero ESC"
        fi
    done
else
    echo "  SKIP: python3 unavailable for the 45/80/100/120-column PTY menu checks"
fi

printf 'PASS=%s FAIL=%s\n' "${PASS}" "${FAIL}"
[[ "${FAIL}" -eq 0 ]]
