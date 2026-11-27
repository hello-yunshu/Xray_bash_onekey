#!/usr/bin/env python3
"""F23 — six-language CLI, TTY and narrow-screen contract.

Preview evidence level: CONTAINER_VERIFIED (config-level: the real Go binary and
the fixed Bash catalogs are executed/read directly; no Xray binary, no systemd,
no root, no network).

The fixture proves the documented language surface byte for byte: zh/en carry
complete Go catalogs, fr/fa/ru/ko accept the code but fall back to English with
exactly one notice, invalid codes are rejected before command dispatch, locale
environment variables do not influence the choice, and the safe persistent
`etc/idleleo/language.conf` preference is honored unless `--lang` overrides it.
It then locks the non-localized TTY behaviour (no TTY error, 45-column menu),
shows the help text has no narrow-screen wrapping, and compares all of that to
the six real Bash `.mo` catalogs.

Differences from the Bash baseline are recorded in `baseline-compare.json`
instead of being claimed as parity: Bash is complete in six languages and
renders a localized 45-column adaptive menu; Go persists language selection
but is complete in two languages and prints an English single-line prompt.
"""
import fcntl
import gettext
import hashlib
import json
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import termios
import time
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture_support import run_fixture  # noqa: E402

SUPPORTED = ["zh", "en", "fr", "fa", "ru", "ko"]
COMPLETE = ["zh", "en"]
FALLBACK = ["fr", "fa", "ru", "ko"]
BASH_LOCALES = ["zh_CN", "en", "fr", "ru", "ko", "fa"]
EXPECT_OVERVIEW = {
    "zh_CN": "总览",
    "en": "Overview",
    "fr": "Vue d'ensemble",
    "ru": "Обзор",
    "ko": "개요",
    "fa": "نمای کلی",
}
EXPECT_INFO = {
    "zh_CN": "信息",
    "en": "information",
    "fr": "informations",
    "ru": "информация",
    "ko": "정보",
    "fa": "اطلاعات",
}
TOP_LEVEL = [
    "version", "language", "status", "show", "config", "change", "xray", "fail2ban",
    "bridge", "metadata", "schedule", "update", "stats", "service", "tcp",
    "speedtest", "rill", "recover", "help",
]
VERSION_RE = re.compile(r"^idleleo \S+ \(go\)\n$")


def notice(lang):
    return (
        f"note: {lang} messages are not translated yet, falling back to English "
        f"(use --lang en to silence this)\n"
    )


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def max_line_width(text):
    best = 0
    for line in text.splitlines():
        width = 0
        for ch in line:
            width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        best = max(best, width)
    return best


def run_pty(f, lang, columns=45, rows=40):
    """Run the menu on a 45-column PTY with stdin/stdout/stderr on the slave."""
    master, slave = pty.openpty()
    cmd = [str(f.go), "--lang", lang]
    env = dict(f.env, TERM="xterm-256color")
    proc = None
    rc = None
    chunks = []
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, columns, 0, 0))
        proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave,
                                env=env, close_fds=True)
        os.close(slave)
        slave = -1
        try:
            os.write(master, b"0\n")
        except OSError:
            pass
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 1.0)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            try:
                data = os.read(master, 4096)
            except OSError:  # Linux reports EIO once the slave is gone.
                break
            if not data:
                break
            chunks.append(data)
        try:
            rc = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait(timeout=5)
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
    out = b"".join(chunks).decode("utf-8", "replace")
    # A PTY translates LF to CRLF; normalize so string assertions see the same
    # text a pipe would carry. ANSI detection is unaffected.
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    f._log(f"$ PTY {columns}x{rows} {' '.join(cmd)} (rc={rc} bytes={len(out)})")
    return rc, out


def main(f):
    f.need(f.bash_repo is not None,
           "F23 requires --bash-repo for the fixed Bash i18n baseline")

    work = f.evidence / "i18n-work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    # ---- 1) Language matrix -------------------------------------------------
    runs = {}
    for lang in SUPPORTED:
        version = f.run([f.go, "--lang", lang, "version"], timeout=30)
        help_text = f.run([f.go, "--lang", lang, "help"], timeout=30)
        runs[lang] = {"version": version, "help": help_text}

    en_version = runs["en"]["version"]
    en_help = runs["en"]["help"]
    zh_help = runs["zh"]["help"]

    for lang in SUPPORTED:
        v = runs[lang]["version"]
        f.check(
            v.rc == 0 and VERSION_RE.fullmatch(v.out or "") and "\x1b" not in (v.out or ""),
            f"{lang} version prints a plain version line",
            f"rc={v.rc} out={v.out!r} err={v.err!r}",
        )
        expected_err = "" if lang in COMPLETE else notice(lang)
        f.check((v.err or "") == expected_err,
                f"{lang} version stderr matches the fallback contract",
                repr(v.err))
        h = runs[lang]["help"]
        f.check(h.rc == 0 and "\x1b" not in (h.out or ""),
                f"{lang} help exits 0 without ANSI escapes",
                f"rc={h.rc} err={h.err!r}")
        f.check((h.err or "") == expected_err,
                f"{lang} help stderr matches the fallback contract",
                repr(h.err))

    for lang in FALLBACK:
        f.check(runs[lang]["version"].out == en_version.out,
                f"{lang} version stdout is byte-identical to en",
                f"len={len(runs[lang]['version'].out or '')}")
        f.check(runs[lang]["help"].out == en_help.out,
                f"{lang} help stdout is byte-identical to en",
                f"len={len(runs[lang]['help'].out or '')}")

    f.check(zh_help.out != en_help.out, "zh and en help differ")
    f.check("用法:" in (zh_help.out or ""), "zh help uses the Chinese usage label")
    f.check("Usage:" in (en_help.out or ""), "en help uses the English usage label")
    missing_zh = [token for token in TOP_LEVEL if token not in (zh_help.out or "")]
    f.check(not missing_zh, "zh help lists every top-level command token",
            ",".join(missing_zh))
    missing_en = [token for token in TOP_LEVEL if token not in (en_help.out or "")]
    f.check(not missing_en, "en help lists every top-level command token",
            ",".join(missing_en))

    invalid_results = {}
    for code in ("de", "ZH", "zh_CN"):
        r = f.run([f.go, "--lang", code, "status"], timeout=30)
        invalid_results[code] = {
            "rc": r.rc,
            "stdoutEqualsEnHelp": r.out == en_help.out,
            "stderr": r.err or "",
        }
        f.check(r.rc == 2 and r.out == en_help.out and (r.err or "") == "",
                f"invalid language {code} is rejected with English help and no notice",
                f"rc={r.rc} outMatches={r.out == en_help.out} err={r.err!r}")

    de_version = f.run([f.go, "--lang", "de", "--version"], timeout=30)
    de_help = f.run([f.go, "--lang", "de", "--help"], timeout=30)
    fr_version = f.run([f.go, "--lang", "fr", "--version"], timeout=30)
    f.check(de_version.rc == 0 and de_version.out == en_version.out
            and (de_version.err or "") == "",
            "pre-validation --lang de --version exits 0 in English",
            f"rc={de_version.rc} err={de_version.err!r}")
    f.check(de_help.rc == 0 and de_help.out == en_help.out
            and (de_help.err or "") == "",
            "pre-validation --lang de --help exits 0 with English help",
            f"rc={de_help.rc} err={de_help.err!r}")
    f.check(fr_version.rc == 0 and fr_version.out == en_version.out
            and (fr_version.err or "") == notice("fr"),
            "pre-validation --lang fr --version still announces the fallback",
            f"rc={fr_version.rc} err={fr_version.err!r}")

    matrix = {
        "supportedLanguages": SUPPORTED,
        "completeCatalogs": COMPLETE,
        "fallbackLanguages": FALLBACK,
        "enVersion": en_version.out,
        "enHelpSha256": sha256_text(en_help.out or ""),
        "languages": {},
        "invalidLanguages": invalid_results,
        "preValidation": {
            "deVersion": {"rc": de_version.rc, "stdout": de_version.out,
                          "stderr": de_version.err or ""},
            "deHelp": {"rc": de_help.rc, "stdoutEqualsEnHelp": de_help.out == en_help.out,
                       "stderr": de_help.err or ""},
            "frVersion": {"rc": fr_version.rc,
                          "stdoutEqualsEnVersion": fr_version.out == en_version.out,
                          "stderr": fr_version.err or ""},
        },
    }
    for lang in SUPPORTED:
        v = runs[lang]["version"]
        h = runs[lang]["help"]
        matrix["languages"][lang] = {
            "version": {
                "rc": v.rc,
                "stdout": v.out,
                "stderr": v.err or "",
                "matchesVersionPattern": bool(VERSION_RE.fullmatch(v.out or "")),
                "hasAnsi": "\x1b" in (v.out or ""),
                "stdoutEqualsEn": v.out == en_version.out,
            },
            "help": {
                "rc": h.rc,
                "stdoutSha256": sha256_text(h.out or ""),
                "stdoutEqualsEn": h.out == en_help.out,
                "stderr": h.err or "",
                "hasAnsi": "\x1b" in (h.out or ""),
            },
        }
    f.write_json("language-matrix.json", matrix)

    # ---- 2) Environment, persistent language.conf, and override precedence --
    env_fr = dict(f.env, LANG="fr_FR.UTF-8", LC_ALL="fr_FR.UTF-8")
    env_help = f.run([f.go, "help"], timeout=30, env=env_fr)
    f.check(env_help.rc == 0, "help succeeds under a French locale environment",
            f"rc={env_help.rc}")
    f.check(env_help.out == zh_help.out,
            "help stays Chinese under a French locale environment",
            f"len={len(env_help.out or '')}")
    f.check((env_help.err or "") == "",
            "help does not announce a fallback for the environment locale",
            repr(env_help.err))

    env_zh = dict(f.env, LANG="zh_CN.UTF-8")
    en_under_zh = f.run([f.go, "--lang", "en", "help"], timeout=30, env=env_zh)
    f.check(en_under_zh.rc == 0, "explicit --lang en help succeeds under a Chinese locale",
            f"rc={en_under_zh.rc}")
    f.check(en_under_zh.out == en_help.out,
            "--lang en wins over the Chinese locale environment",
            f"len={len(en_under_zh.out or '')}")
    f.check((en_under_zh.err or "") == "",
            "--lang en help has an empty stderr under a Chinese locale",
            repr(en_under_zh.err))

    conf_root = work / "language-conf"
    (conf_root / "etc/idleleo").mkdir(parents=True)
    (conf_root / "etc/idleleo/language.conf").write_text(
        "LANG=fr_FR.UTF-8\nLC_MESSAGES=fr_FR.UTF-8\n", encoding="utf-8")
    (conf_root / ".idleleo-phase01-sandbox").write_text(
        "I_ACCEPT_DISPOSABLE_SANDBOX\n", encoding="utf-8")
    conf_help = f.run([f.go, "--root", str(conf_root), "help"], timeout=30)
    f.check(conf_help.rc == 0 and conf_help.out == en_help.out,
            "language.conf selects its allowed persistent locale",
            f"rc={conf_help.rc} len={len(conf_help.out or '')}")
    f.check(conf_help.err == notice("fr"),
            "incomplete persistent locale announces one English fallback",
            repr(conf_help.err))
    explicit_help = f.run([f.go, "--root", str(conf_root), "--lang", "en", "help"], timeout=30)
    f.check(explicit_help.rc == 0 and explicit_help.out == en_help.out
            and (explicit_help.err or "") == "",
            "explicit --lang overrides the persistent preference",
            f"rc={explicit_help.rc} err={explicit_help.err!r}")
    before = f.tree_digest(conf_root)
    conf_status = f.run([f.go, "--root", str(conf_root), "--lang", "en", "status"], timeout=30)
    f.check(conf_status.rc == 3 and "not installed" in (conf_status.err or ""),
            "persistent language reads preserve read-only status behavior",
            f"rc={conf_status.rc} err={conf_status.err!r}")
    f.check(f.tree_digest(conf_root) == before,
            "language reads leave the sandbox tree unchanged")
    set_ko = f.run([f.go, "--root", str(conf_root), "language", "set", "ko"], timeout=30)
    f.check(set_ko.rc == 0 and set_ko.out == "ko\n",
            "language set persists one allowlisted locale in the marked sandbox",
            f"rc={set_ko.rc} out={set_ko.out!r}")
    show_ko = f.run([f.go, "--root", str(conf_root), "language", "show"], timeout=30)
    f.check(show_ko.rc == 0 and show_ko.out == "ko\n",
            "language show reports the persisted preference",
            f"rc={show_ko.rc} out={show_ko.out!r}")

    env_default = dict(f.env)
    env_default.pop("LANG", None)
    env_default.pop("LC_ALL", None)
    default_help = f.run([f.go, "help"], timeout=30, env=env_default)
    f.check(default_help.rc == 0 and default_help.out == zh_help.out
            and (default_help.err or "") == "",
            "default language is Chinese without LANG or LC_ALL",
            f"rc={default_help.rc} err={default_help.err!r}")

    # ---- 3) Exit codes and zero writes -------------------------------------
    empty = work / "empty"
    empty.mkdir()
    empty_status = {}
    for lang in ("zh", "en", "fr", "ko"):
        r = f.run([f.go, "--root", str(empty), "--lang", lang, "status"], timeout=30)
        empty_status[lang] = r
        f.check(r.rc == 3, f"empty-root status exits 3 with --lang {lang}",
                f"rc={r.rc} err={r.err!r}")
    f.check(empty_status["fr"].err == notice("fr") + (empty_status["en"].err or ""),
            "fr status stderr is the en message plus one fallback notice",
            repr(empty_status["fr"].err))

    inspect_rc = {}
    for lang in ("zh", "en", "fr", "ko"):
        r = f.run([f.go, "--root", str(empty), "--lang", lang,
                   "config", "inspect"], timeout=30)
        inspect_rc[lang] = r.rc
        f.check(r.rc != 0, f"empty-root config inspect fails with --lang {lang}",
                f"rc={r.rc}")
    f.check(len(set(inspect_rc.values())) == 1,
            "config inspect exit code does not depend on the language",
            json.dumps(inspect_rc, sort_keys=True))

    bogus = {}
    for lang in ("zh", "en", "fr", "ko"):
        r = f.run([f.go, "--root", str(empty), "--lang", lang, "bogus"], timeout=30)
        bogus[lang] = r
        f.check(r.rc == 2, f"unknown subcommand exits 2 with --lang {lang}",
                f"rc={r.rc}")
    f.check(bogus["fr"].out == bogus["en"].out,
            "unknown subcommand stdout is identical for fr and en",
            f"len={len(bogus['fr'].out or '')}")

    for args in (["status"], ["config", "inspect"], ["help"]):
        before = f.tree_digest(conf_root)
        f.run([f.go, "--root", str(conf_root), *args], timeout=30)
        f.check(f.tree_digest(conf_root) == before,
                f"read-only {' '.join(args)} leaves the prepared root unchanged")

    # ---- 4) No TTY ---------------------------------------------------------
    no_tty_zh = f.run(
        ["bash", "-c", 'exec "$1" --lang zh </dev/null', "_", str(f.go)], timeout=30)
    f.check(no_tty_zh.rc == 2, "no-TTY zh exits 2", f"rc={no_tty_zh.rc}")
    f.check("无 TTY：不进入交互菜单" in (no_tty_zh.err or ""),
            "no-TTY zh uses the localized no_tty message", repr(no_tty_zh.err))
    f.check(no_tty_zh.out == zh_help.out,
            "no-TTY zh prints the Chinese help on stdout",
            f"len={len(no_tty_zh.out or '')}")

    no_tty_fr = f.run(
        ["bash", "-c", 'exec "$1" --lang fr </dev/null', "_", str(f.go)], timeout=30)
    f.check(no_tty_fr.rc == 2, "no-TTY fr exits 2", f"rc={no_tty_fr.rc}")
    f.check(no_tty_fr.out == en_help.out,
            "no-TTY fr prints the English help on stdout",
            f"len={len(no_tty_fr.out or '')}")
    f.check((no_tty_fr.err or "").startswith(notice("fr")),
            "no-TTY fr stderr starts with the fallback notice", repr(no_tty_fr.err))
    f.check("no TTY: interactive menu not entered" in (no_tty_fr.err or ""),
            "no-TTY fr uses the English no_tty message", repr(no_tty_fr.err))

    # ---- 5) 45-column PTY --------------------------------------------------
    tty = {"columns": 45, "rows": 40, "languages": {}}
    for lang in ("zh", "fr"):
        rc, out = run_pty(f, lang)
        tty["languages"][lang] = {
            "rc": rc,
            "containsStatusEntry": "1) status" in out,
            "containsZeroExit": "0) exit" in out,
            "containsFallbackNotice": notice(lang) in out,
            "hasAnsi": "\x1b" in out,
            "output": out,
        }
        f.check(rc == 0, f"{lang} menu exits 0 in a 45-column PTY", f"rc={rc}")
        f.check("1) status" in out,
                f"{lang} menu shows the English status entry", out.strip()[:160])
        f.check("0) exit" in out,
                f"{lang} menu shows the English exit entry", out.strip()[:160])
        f.check("\x1b" not in out, f"{lang} PTY output contains no ANSI escapes")
        if lang == "fr":
            f.check(notice("fr") in out,
                    "fr menu streams the fallback notice", out.strip()[:160])
    f.write_json("tty.json", tty)

    # ---- 6) Narrow-screen help ---------------------------------------------
    zh_width = max_line_width(zh_help.out or "")
    en_width = max_line_width(en_help.out or "")
    f.check(zh_width > 80,
            "zh help is wider than 80 columns (no narrow-screen adaptation)",
            f"max={zh_width}")
    f.check(en_width > 80,
            "en help is wider than 80 columns (no narrow-screen adaptation)",
            f"max={en_width}")

    # ---- 7) Fixed Bash baseline --------------------------------------------
    mo_root = f.bash_repo / "i18n/languages"
    catalogs_present = all(
        (mo_root / locale / "LC_MESSAGES/xray_install.mo").is_file()
        for locale in BASH_LOCALES)
    f.check(catalogs_present, "all six Bash locale catalogs are present")
    bash_catalogs = {}
    for locale in BASH_LOCALES:
        path = mo_root / locale / "LC_MESSAGES/xray_install.mo"
        overview = None
        info = None
        error = ""
        if path.is_file():
            try:
                with open(path, "rb") as fh:
                    translations = gettext.GNUTranslations(fh)
                overview = translations.gettext("总览")
                info = translations.gettext("信息")
            except Exception as exc:  # a broken .mo is a red result, not a skip.
                error = str(exc)
        bash_catalogs[locale] = {"总览": overview, "信息": info, "error": error}
        f.check(overview == EXPECT_OVERVIEW[locale],
                f"Bash {locale} translates 总览", repr(overview))
        f.check(info == EXPECT_INFO[locale],
                f"Bash {locale} translates 信息", repr(info))

    f.write_json("baseline-compare.json", {
        "go": {
            "supportedLanguages": SUPPORTED,
            "completeCatalogs": COMPLETE,
            "fallbackLanguages": FALLBACK,
            "defaultLanguage": "zh",
            "readsEnvironmentLocale": False,
            "readsLanguageConf": True,
            "ttyMenu": "English single-line prompt, not localized",
            "helpWidthAdaptation": False,
            "helpMaxWidth": {"zh": zh_width, "en": en_width},
        },
        "bash": {
            "catalogs": bash_catalogs,
            "catalogsWithTranslations": BASH_LOCALES,
            "sampleEntries": ["总览", "信息"],
            "menuColumns": 45,
            "menuLocalizedAndAdaptive": True,
            "readsLanguageConf": True,
        },
        "differences": [
            "Bash ships complete catalogs for all six languages; Go has complete "
            "catalogs only for zh and en.",
            "Bash falls back to English per missing message (_xray_i18n_setup); Go "
            "falls back for the whole language and prints one notice.",
            "Bash and Go read etc/idleleo/language.conf; Go also offers explicit language show/set commands and --lang overrides the stored default.",
            "Bash renders a localized 45-column adaptive menu box; Go renders an "
            "English single-line prompt with no width adaptation (not aligned).",
            "Bash suppresses ANSI without a TTY or with NO_COLOR; Go never emits "
            "ANSI, which is stricter rather than a parity gap.",
        ],
        "cliQuirks": {
            "--lang de --version": "exit 0 with English output before language validation",
            "--lang de --help": "exit 0 with English help before language validation",
        },
        "helpMaxWidth": {"zh": zh_width, "en": en_width},
        "narrowScreenParity": "not aligned: Go help is a single unwrapped block wider than 80 columns",
        "ttyMenuParity": "not aligned: Go menu prompt stays English and has no 45-column layout",
    })


if __name__ == "__main__":
    sys.exit(run_fixture("F23", main))
