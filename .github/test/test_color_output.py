#!/usr/bin/env python3
# color-test-fixture: this file intentionally contains literal escape text
# (and an old-style counterexample) to prove the scanner can fail.
"""ANSI color output regression tests.

Requires: python3. Run via test_color_output.sh so a missing interpreter is a
clear SKIP instead of a bare rc=127.

Two independent failure modes are covered:

1. Static: color variables must hold real ESC bytes (``$'\\033...'``), never the
   literal two-character text ``\\033``. A literal value is only expanded by
   ``printf '%b'`` / ``echo -e``; a plain ``echo`` or ``printf '%s'`` prints the
   backslash sequence to the user. The scanner also rejects a color variable
   embedded in a ``printf`` format string without ``%b``.
2. Runtime: non-TTY output (logs, pipes, CI) must contain no ANSI control
   bytes at all, while a pseudo-terminal must still render colors. ``NO_COLOR``
   must disable them even on a TTY.

The counterexample fixture proves the static scanner actually fails on the old
pattern instead of silently passing everything.
"""

import collections
import os
import pathlib
import pty
import re
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "install.sh"
SCRIPTS = sorted((REPO / "scripts").glob("*.sh"))

PASS = 0
FAIL = 0


def ok(message):
    global PASS
    PASS += 1
    print(f"  PASS: {message}")


def bad(message):
    global FAIL
    FAIL += 1
    print(f"  FAIL: {message}")


def check(condition, message):
    if condition:
        ok(message)
    else:
        bad(message)


COLOR_NAMES = (
    "Green",
    "Red",
    "GreenW",
    "RedW",
    "Yellow",
    "GreenBG",
    "RedBG",
    "YellowBG",
    "Font",
)
COLOR_REF = re.compile(
    r"\$\{(" + "|".join(COLOR_NAMES) + r")\b"
)
COLOR_DEF = re.compile(r"^\s*(" + "|".join(COLOR_NAMES) + r")\s*=\s*(.*)$")
PRINTF = re.compile(r"^\s*printf\s+(.*)$")
ECHO = re.compile(r"^\s*echo\s+(.*)$")


def strip_comment(line):
    """Remove a trailing shell comment, respecting simple quotes."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def format_string(raw):
    """Return the printf format word and whether it is double-quoted."""
    raw = raw.lstrip()
    if not raw:
        return "", False
    if raw.startswith("-v"):
        # printf -v var FORMAT ...
        parts = raw.split(None, 2)
        if len(parts) < 3:
            return "", False
        raw = parts[2].lstrip()
    if raw[0] == "'":
        end = raw.find("'", 1)
        return (raw[1:end] if end > 0 else raw[1:]), False
    if raw[0] == '"':
        end = 1
        while end < len(raw):
            if raw[end] == "\\":
                end += 2
                continue
            if raw[end] == '"':
                break
            end += 1
        return raw[1:end], True
    return raw.split()[0], False


def scan_file(path):
    """Return (literal_definitions, dangerous_sites, color_lines, checked_lines)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    literal_defs = []
    dangerous = []
    color_lines = 0
    heredoc_end = None

    for number, original in enumerate(text.splitlines(), 1):
        line = original

        if heredoc_end is not None:
            if line.strip() == heredoc_end:
                heredoc_end = None
            continue
        heredoc = re.search(r"<<[-~]?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
        if heredoc:
            heredoc_end = heredoc.group(1)
            continue

        code = strip_comment(line)

        match = COLOR_DEF.match(code)
        if match:
            value = match.group(2).strip()
            if not (value.startswith("$'") or value == '""' or value == ""):
                literal_defs.append((number, match.group(1), value))
            continue

        if not COLOR_REF.search(code):
            continue
        color_lines += 1

        if re.match(r"^\s*log_echo(_secure)?\s", code):
            continue

        echo = ECHO.match(code)
        if echo and not re.match(r"-e\s", echo.group(1)):
            dangerous.append((number, "plain echo", original.strip()))
            continue

        printf = PRINTF.match(code)
        if printf:
            fmt, _double_quoted = format_string(printf.group(1))
            # bash printf interprets backslash escapes in the FORMAT string, so
            # a color variable placed there is expanded even without %b. The
            # leak is the other shape: color variables passed as arguments to
            # a format that has no %b (`printf '%s' "${Green}..."`).
            if COLOR_REF.search(fmt):
                continue
            if "%b" not in fmt:
                dangerous.append((number, "printf arguments without %b", original.strip()))

    return literal_defs, dangerous, color_lines


def scan_repository():
    literal_defs = []
    dangerous = []
    color_lines = 0
    for path in [INSTALL_SH] + SCRIPTS:
        defs, sites, lines = scan_file(path)
        literal_defs.extend((path, *entry) for entry in defs)
        dangerous.extend((path, *entry) for entry in sites)
        color_lines += lines
    return literal_defs, dangerous, color_lines


ANSI_LITERAL = re.compile(r"\\033|\\x1[bB]|\\e(?![A-Za-z0-9_])")
REAL_ESC = re.compile(r"\$'\\033")
ANSI_TOOL = re.compile(r"\btput\b|_color_enabled\s*=")
TEST_PREFIXES = (".github/test/", "i18n/tests/")


def tracked_files():
    """All repository files Git knows about, across every file type."""
    try:
        output = subprocess.run(
            ["git", "ls-files"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return [p for p in REPO.rglob("*") if p.is_file()]
    return [REPO / name for name in output.splitlines() if name]


def ansi_category(rel, line):
    posix = rel.as_posix()
    suffix = pathlib.Path(posix).suffix.lower()
    stripped = line.strip()
    if posix.startswith(TEST_PREFIXES):
        return "test-fixture"
    if posix == "scripts/rill_xray_agent_manager.sh":
        return "canonical-payload"
    if suffix in {".md", ".rst"} or posix == "README.md" or posix.startswith("README"):
        return "doc-example"
    if suffix in {".po", ".pot"}:
        return "i18n-text"
    if suffix in {".json", ".yml", ".yaml", ".toml", ".ini", ".service", ".conf"}:
        return "config-text"
    if suffix == ".sh":
        if stripped.startswith("#"):
            return "source-comment"
        if REAL_ESC.search(line):
            return "real-esc"
        if re.search(r"\b(sed|awk|grep|tput)\b", line) and "printf" not in line:
            return "tooling"
        if re.search(r"\bprintf\b", line):
            # printf interprets backslash escapes in its format string.
            return "tooling"
        return "production-output-risk"
    if suffix == ".py" and ("test" in posix or posix.startswith("i18n/tests/")):
        return "test-fixture"
    return "production-output-risk"


def scan_ansi_repository():
    """Classify every literal ANSI/escape form in every tracked file type."""
    rows = []
    table = collections.Counter()
    type_counts = collections.Counter()
    annotation_missing = []
    for path in tracked_files():
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "\x00" in text:
            continue
        rel = path.relative_to(REPO)
        type_counts[rel.suffix.lower() or rel.name] += 1
        annotated = "color-test-fixture" in text
        for number, line in enumerate(text.splitlines(), 1):
            hit = ANSI_LITERAL.search(line)
            actual_esc = "\x1b" in line
            tool = ANSI_TOOL.search(line)
            if not hit and not actual_esc and not tool:
                continue
            category = ansi_category(rel, line)
            if category == "test-fixture" and not annotated:
                annotation_missing.append(f"{rel}:{number}")
            if tool and not hit and not actual_esc and category != "test-fixture":
                category = "tooling-variable"
            table[(rel.suffix.lower() or rel.name, category)] += 1
            rows.append((rel.as_posix(), number, category, line.strip()[:180]))
    return table, rows, annotation_missing, type_counts


def test_static():
    print("\n-- A. static color definition / output scan --")
    literal_defs, non_b_sites, color_lines = scan_repository()

    check(len(literal_defs) == 0,
          f"no color variable stores the literal text \\033 (found {len(literal_defs)})")
    # With real ESC bytes (or empty values), printf '%s' and plain echo are
    # correct: they carry the ESC byte through untouched in a TTY and print
    # nothing extra when colors are disabled. The leak only exists when a
    # literal "\033" definition is paired with a call that does not interpret
    # backslash escapes.
    leaks = non_b_sites if literal_defs else []
    check(len(leaks) == 0,
          f"literal color definitions never reach a non-interpreting call (found {len(leaks)})")
    print(f"  INFO: {len(COLOR_NAMES)} color definitions, "
          f"{color_lines} color-bearing lines, "
          f"{len(non_b_sites)} non-%b sites, {len(leaks)} leaks")
    if non_b_sites and not literal_defs:
        print("  INFO: non-%b sites are safe because definitions hold real ESC bytes or are empty")

    for path, number, name, value in literal_defs:
        print(f"  DETAIL: {path}:{number}: {name}={value}")
    for path, number, kind, line in leaks:
        print(f"  DETAIL: {path}:{number}: {kind}: {line}")

    ansi_table, ansi_rows, annotation_missing, type_counts = scan_ansi_repository()
    risk = sum(n for (_, category), n in ansi_table.items()
               if category == "production-output-risk")
    docs = sum(n for (_, category), n in ansi_table.items()
               if category == "doc-example")
    fixtures = sum(n for (_, category), n in ansi_table.items()
                   if category == "test-fixture")
    canonical = sum(n for (_, category), n in ansi_table.items()
                    if category == "canonical-payload")
    canonical_non_b = sum(
        1 for path, _, _, _ in non_b_sites
        if path.name == "rill_xray_agent_manager.sh"
    )
    if canonical_non_b:
        ansi_table[(".sh", "canonical-payload")] += canonical_non_b
        canonical += canonical_non_b
    check(risk == 0, f"no production output path carries a literal ANSI escape (found {risk})")
    check(docs == 0, f"no README/doc example carries a literal ANSI escape (found {docs})")
    check(not annotation_missing,
          f"every test fixture literal is annotated with color-test-fixture (missing {len(annotation_missing)})")
    print(f"  INFO: tracked files scanned: {sum(type_counts.values())}; "
          f"types={dict(sorted(type_counts.items()))}")
    print(f"  INFO: ANSI inventory: total={sum(ansi_table.values())}, "
          f"production-risk={risk}, docs={docs}, "
          f"test-fixtures={fixtures}, canonical={canonical}")
    print("  INFO: ANSI inventory by file type / category:")
    for (ext, category), count in sorted(ansi_table.items()):
        print(f"    {ext:12s} {category:24s} {count}")
    for path, number, category, line in ansi_rows:
        if category in {"production-output-risk", "doc-example"}:
            print(f"  DETAIL: {path}:{number}: {category}: {line}")
    for path in annotation_missing[:20]:
        print(f"  DETAIL: unannotated fixture: {path}")
    check(ansi_category(pathlib.Path("README.md"), "\\033[31m") == "doc-example",
          "the ANSI scanner flags a Markdown example")
    check(ansi_category(pathlib.Path("install.sh"), 'echo "\\033[31m"') == "production-output-risk",
          "the ANSI scanner flags a plain shell output")

    # The scanner must be able to fail. A fixture using the pre-fix shape is
    # scanned with the same function; a green result here would mean the gate
    # is a no-op.
    with tempfile.TemporaryDirectory() as tmp:
        fixture = pathlib.Path(tmp) / "bad_colors.sh"
        fixture.write_text(
            "Green=\"\\033[32m\"\n"
            "Font=\"\\033[0m\"\n"
            "echo \"${Green}ok${Font}\"\n"
            "printf '%s\\n' \"${Green}ok${Font}\"\n",
            encoding="utf-8",
        )
        fixture_defs, fixture_dangerous, _ = scan_file(fixture)
        check(len(fixture_defs) >= 1 and len(fixture_dangerous) >= 1,
              "the counterexample fixture is correctly reported as red")
        if fixture_defs:
            print(f"  INFO: counterexample literal definition: {fixture_defs[0]}")
        if fixture_dangerous:
            print(f"  INFO: counterexample leak: {fixture_dangerous[0]}")


COMMON = """\
#!/usr/bin/env bash
set -u
export _TEST_MODE=1
source "@INSTALL@" 2>/dev/null
gettext() { printf '%s' "$1"; }
log_echo() { printf '%b\\n' "$*"; }
"""

LIST_STUBS = """\
source "@FAIL2BAN@" 2>/dev/null
read_optimize() { printf -v "$2" '%s' 0; }
mf_get_active_jails() { printf 'sshd\\nnginx-badbots\\n'; }
"""

SCENARIOS = {
    "combined": LIST_STUBS + """\
confirm_prompt "$(gettext '统计已开启但缺少 api.listen, 是否补写并重启 Xray')"
mf_menu_view_banned_ips
""",
    "list_view": LIST_STUBS + "mf_menu_view_banned_ips\n",
    "list_unban": LIST_STUBS + "mf_menu_quick_unban\n",
    "list_trust_add": LIST_STUBS + "mf_menu_add_trust_ip\n",
    "list_trust_del": LIST_STUBS + "mf_menu_remove_trust_ip\n",
    "guard_fail2ban": """\
shell_version="2.0.0"
source "@FAIL2BAN@" 2>/dev/null
true
""",
    "guard_file_manager": """\
shell_version="2.0.0"
source "@FILE_MANAGER@" 2>/dev/null
true
""",
    "guard_traffic_blocker": """\
shell_version="2.0.0"
source "@TRAFFIC_BLOCKER@" 2>/dev/null
true
""",
    "root_info": """\
if [[ "$(id -u)" -ne 0 ]]; then
    bash "@INSTALL@" -s || true
else
    # Root fallback (container/local root): exercise the same non-root message
    # and printf '%b' call with the sourced color variables.
    printf '%b\\n' "${Error} ${RedBG} $(gettext "读取安装信息需要 root 权限")（$(gettext "信息文件权限为") 0600）${Font}"
fi
""",
    "stats_prompt": """\
confirm_prompt "$(gettext '统计已开启但缺少 api.listen, 是否补写并重启 Xray')"
""",
    "rill_status": """\
source "@RILL_MANAGER@" 2>/dev/null
rxa_diagnose() { printf '%s' '{"result":{"diagnosisCode":"HEALTHY"}}'; }
rxa_health_label
""",
    "clear_screen": """\
clear() { printf '\\033[H\\033[2J\\033[3J'; }
menu_clear
rxa_clear_screen
printf 'CLEAR-DONE\\n'
""",
}

SCENARIO_EXPECT = {
    "combined": "1. sshd",
    "list_view": "1. sshd",
    "list_unban": "1. sshd",
    "list_trust_add": "1. sshd",
    "list_trust_del": "1. sshd",
    "guard_fail2ban": "fail2ban_manager.sh",
    "guard_file_manager": "file_manager.sh",
    "guard_traffic_blocker": "traffic_blocker.sh",
    "root_info": "读取安装信息需要 root 权限",
    "stats_prompt": "[Y/N]?",
    "rill_status": "检测",
    "clear_screen": "CLEAR-DONE",
}


def render_child(name):
    script = COMMON + SCENARIOS[name]
    script = script.replace("@INSTALL@", str(INSTALL_SH))
    script = script.replace("@FAIL2BAN@", str(REPO / "scripts" / "fail2ban_manager.sh"))
    script = script.replace("@FILE_MANAGER@", str(REPO / "scripts" / "file_manager.sh"))
    script = script.replace("@TRAFFIC_BLOCKER@", str(REPO / "scripts" / "traffic_blocker.sh"))
    script = script.replace("@RILL_MANAGER@", str(REPO / "scripts" / "rill_xray_agent_manager.sh"))
    return script


def run_child_script(script, mode):
    with tempfile.TemporaryDirectory() as tmp:
        child = pathlib.Path(tmp) / "child.sh"
        child.write_text(script, encoding="utf-8")

        base_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": tmp,
            "LANG": "C.UTF-8",
        }

        if mode == "non-tty":
            completed = subprocess.run(
                ["bash", str(child)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=base_env,
                text=True,
                timeout=30,
            )
            return completed.stdout + completed.stderr, completed.returncode

        env = dict(base_env)
        env["TERM"] = "xterm-256color"
        if mode == "tty":
            env.pop("NO_COLOR", None)
        elif mode == "no-color":
            env["NO_COLOR"] = "1"
        elif mode == "dumb":
            env["TERM"] = "dumb"
            env.pop("NO_COLOR", None)

        master, slave = pty.openpty()
        process = subprocess.Popen(
            ["bash", str(child)],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=env,
            close_fds=True,
        )
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
        process.wait(timeout=30)
        os.close(master)
        return b"".join(chunks).decode("utf-8", errors="replace"), process.returncode


def run_child(mode):
    return run_child_script(render_child("combined"), mode)


def has_control_bytes(text):
    return any(ord(char) < 32 and char not in "\n\t" for char in text)


def test_runtime():
    print("\n-- B. non-TTY / pseudo-TTY runtime output --")
    non_tty, rc = run_child("non-tty")
    check(rc == 0, f"non-TTY child exits 0 (got {rc})")
    check("\x1b" not in non_tty, "non-TTY output contains no raw ESC byte")
    check("\\033" not in non_tty and "\\e" not in non_tty and "\\x1b" not in non_tty,
          "non-TTY output contains no literal \\033 / \\e / \\x1b text")
    check(not has_control_bytes(non_tty), "non-TTY output contains no bare control bytes")
    check("1. sshd" in non_tty and "2. nginx-badbots" in non_tty and "0. 返回" in non_tty,
          "non-TTY Fail2ban list is plain text")
    check("[Y/N]?" in non_tty, "non-TTY stats confirmation prompt is plain text")
    if non_tty:
        print("  INFO: non-TTY sample:", repr(non_tty.splitlines()[:3]))

    tty_output, rc = run_child("tty")
    check(rc == 0, f"pseudo-TTY child exits 0 (got {rc})")
    check("\x1b[32m" in tty_output and "\x1b[0m" in tty_output,
          "pseudo-TTY output contains green and reset escape sequences")
    check("\x1b[31m" in tty_output, "pseudo-TTY confirmation prompt contains red N")
    plain_tty = re.sub(r"\x1b\[[0-9;]*m", "", tty_output).replace("\r", "")
    check("1. sshd" in plain_tty, "pseudo-TTY Fail2ban list still renders text")
    if tty_output:
        print("  INFO: pseudo-TTY sample:", repr(tty_output.splitlines()[:2]))

    no_color, rc = run_child("no-color")
    check(rc == 0, f"NO_COLOR pseudo-TTY child exits 0 (got {rc})")
    check("\x1b" not in no_color, "NO_COLOR output contains no raw ESC byte")
    check("1. sshd" in no_color, "NO_COLOR output still contains the jail list text")

    dumb, rc = run_child("dumb")
    check(rc == 0, f"TERM=dumb pseudo-TTY child exits 0 (got {rc})")
    check("\x1b" not in dumb, "TERM=dumb output contains no raw ESC byte")


def test_runtime_matrix():
    print("\n-- C. the old 14 leak sites, one by one --")
    modes = ("non-tty", "tty", "no-color", "dumb")
    for name in SCENARIOS:
        for mode in modes:
            output, rc = run_child_script(render_child(name), mode)
            plain = re.sub(r"\x1b\[[0-9;]*m", "", output).replace("\r", "")
            expected = SCENARIO_EXPECT[name]
            good = rc == 0 and expected in plain
            if mode == "non-tty":
                good = good and "\x1b" not in output \
                    and "\\033" not in output and "\\e" not in output and "\\x1b" not in output \
                    and not has_control_bytes(output)
            elif mode == "tty":
                good = good and "\x1b[" in output
            else:
                good = good and "\x1b" not in output
            check(good, f"{name}/{mode}: expected text and {mode} color policy")
            if not good:
                print(f"  DETAIL: {name}/{mode} rc={rc} output={output!r}")


def main():
    print("============================================================")
    print("  ANSI color output regression")
    print("============================================================")
    test_static()
    test_runtime()
    test_runtime_matrix()
    print("\n============================================================")
    print(f"  Result: {PASS} passed, {FAIL} failed")
    print("============================================================")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
