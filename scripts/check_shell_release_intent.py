#!/usr/bin/env python3
"""Decide whether a main-branch push increased the shell release version."""

import re
import subprocess
import sys
from pathlib import Path


ANCHOR = re.compile(r'^shell_version="([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)


def version(text: str) -> tuple[int, int, int]:
    matches = ANCHOR.findall(text)
    if len(matches) != 1:
        raise ValueError("install.sh must contain exactly one valid shell_version")
    return tuple(map(int, matches[0].split(".")))


def main() -> None:
    if len(sys.argv) != 2 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[1]) or set(sys.argv[1]) == {"0"}:
        raise SystemExit("push must have a valid previous commit")
    try:
        previous = subprocess.check_output(
            ["git", "show", f"{sys.argv[1]}:install.sh"], text=True
        )
        old = version(previous)
        new = version(Path("install.sh").read_text())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"cannot determine release intent: {exc}") from exc
    if new < old:
        raise SystemExit("shell_version decreased; automatic release refused")
    print(f"publish={'true' if new > old else 'false'}")


if __name__ == "__main__":
    main()
