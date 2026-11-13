#!/usr/bin/env python3
"""Thin driver for the Go side (idleleo) inside an e2e container.

Usage:
    go_cli.py --container NAME [--timeout 1800] run xray install --mode reality ...
    go_cli.py --container NAME verify-help

`run` executes `/usr/local/bin/idleleo <argv>` via `docker exec` and streams
stdout/stderr unchanged (callers tee them into evidence). Exit code, timeout
and docker errors are surfaced verbatim; nothing is retried here.

`verify-help` checks that the flags the matrix relies on actually exist in
`idleleo --help` / sub-command help, so no matrix argv is used unverified.
"""
import argparse
import subprocess
import sys

IDLELEO = '/usr/local/bin/idleleo'
REQUIRED_FLAGS = {
    'xray install': ['--mode', '--transport', '--cert', '--cert-key',
                     '--nginx-bin', '--container', '--binary'],
    'xray uninstall': ['--keep-config', '--keep-nginx-conf', '--container'],
    'change apply': ['--mode', '--transport', '--container'],
}
HELP_COMMANDS = [
    ['--help'],
    ['xray', 'install', '--help'],
    ['xray', 'uninstall', '--help'],
    ['change', 'apply', '--help'],
]


def run(argv, timeout):
    proc = subprocess.run(argv, capture_output=False, timeout=timeout)
    return proc.returncode


def verify_help(container, timeout):
    problems = []
    help_text = {}
    for command in HELP_COMMANDS:
        key = ' '.join(command[:-1]) if command[:-1] and command[-1] == '--help' else ' '.join(command)
        argv = ['docker', 'exec', container, IDLELEO] + command
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            problems.append('%s: help timed out' % key)
            continue
        text = proc.stdout + proc.stderr
        help_text[key] = text
        if proc.returncode != 0:
            problems.append('%s: help exited %d' % (key, proc.returncode))

    for scope, flags in REQUIRED_FLAGS.items():
        probe = help_text.get(scope, '')
        for flag in flags:
            if flag not in probe:
                problems.append('%s: missing flag %s' % (scope, flag))

    for scope, text in help_text.items():
        print('=== %s ===' % scope)
        print(text.rstrip())

    if problems:
        for problem in problems:
            print('HELP-VERIFY-FAIL: %s' % problem)
        return 1
    print('HELP-VERIFY: PASS')
    return 0


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--container', required=True)
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('mode', choices=['run', 'verify-help'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    if args.mode == 'verify-help':
        return verify_help(args.container, args.timeout)

    command = args.command
    if command and command[0] == '--':
        command = command[1:]
    if not command:
        parser.error('run requires a command')
    return run(['docker', 'exec', args.container, IDLELEO] + command, args.timeout)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
