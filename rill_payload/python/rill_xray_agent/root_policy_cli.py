"""Root-owned execution-policy helper CLI (rill-xray-agent-root-policy, §17).

A one-shot, root-only CLI for operator transitions on the ROOT execution
policy. It deliberately replaces a long-running root socket daemon: the Xray
manager (already running as root) invokes it for auto confirm/revoke, fuse
acknowledge, safe-disable, mode / route-stage transitions, policy reset and
status.

Security contract (§17/§12/§13/§15/§16):
  - accepts only fixed enums (argparse choices); no arbitrary paths, shell or
    service names;
  - every mutating command persists atomically through RootExecutionPolicy;
  - every authorization-relevant transition bumps executionEpoch (§12) so any
    queued ApplyRequest bound to the old epoch becomes stale;
  - every mutating command appends a crash-safe, root-owned audit event and
    rewrites the safe projection the unprivileged Runtime consumes;
  - corruption / unreadability / invalid schema / symlink / bad ownership or
    permissions FAIL CLOSED (RootPolicyIntegrityError) and NEVER reset the
    policy to a fresh default (that would widen the auto window).
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import sys
from pathlib import Path

from .audit import AuditLog
from .root_policy import (
    DEFAULT_EXECUTION_POLICY_PATH,
    DEFAULT_PROJECTION_PATH,
    MODES,
    ROUTE_STAGES,
    RootExecutionPolicy,
    RootPolicyIntegrityError,
)

PROG = 'rill-xray-agent-root-policy'

# command -> (RootExecutionPolicy method, positional args, audit event type)
_MUTATIONS = {
    'confirm-auto': ('set_auto_confirmed', (True,), 'policy.auto_confirm'),
    'revoke-auto': ('set_auto_confirmed', (False,), 'policy.auto_revoke'),
    'safe-disable': ('safe_disable', (), 'policy.safe_disable'),
    'acknowledge-fuse': ('acknowledge_fuse', (True,), 'policy.acknowledge_fuse'),
    'reset': ('reset_policy', (), 'policy.reset'),
}


def _operator_id() -> str:
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except (KeyError, OSError):
        return 'uid:%d' % os.geteuid()


def _audit(policy: RootExecutionPolicy, event_type: str, details: dict) -> dict:
    """Append a crash-safe root-owned audit event (best-effort, reported)."""
    log = AuditLog(policy.root_dir / 'audit')
    return log.append(event_type, actor_type='operator', actor_id=_operator_id(),
                      details=details)


def _emit(out: dict) -> None:
    print(json.dumps(out, sort_keys=True, ensure_ascii=False, indent=2))


def _fail(command: str, code: str, message: str) -> int:
    _emit({'schemaVersion': 1, 'ok': False, 'command': command,
           'error': {'code': code, 'message': str(message)[:400]}})
    return 1


def _mutate(args, command: str, transition=None) -> int:
    method, method_args, event_type = transition or _MUTATIONS[command]
    if args.root_dir == DEFAULT_EXECUTION_POLICY_PATH.parent and os.geteuid() != 0:
        return _fail(command, 'root_required',
                     'mutating root policy requires root; refusing')
    try:
        policy = RootExecutionPolicy(root_dir=args.root_dir)
        before = policy.snapshot()
        # Authorization-relevant transitions fail closed on corruption
        # (RootPolicyIntegrityError) BEFORE any persistent change.
        changed = getattr(policy, method)(*method_args)
        after = policy.snapshot()
    except RootPolicyIntegrityError as exc:
        return _fail(command, 'root_policy_corrupt', exc)
    except (OSError, ValueError) as exc:
        return _fail(command, 'root_policy_io', exc)
    details = {'command': command, 'changed': changed,
               'before': before, 'after': after}
    audit_event = None
    audit_error = None
    try:
        audit_event = _audit(policy, event_type, details)
    except Exception as exc:  # audit capacity / io: report, transition persisted
        audit_error = str(exc)[:200]
    projection_error = None
    try:
        policy.write_projection(args.projection)
    except Exception as exc:  # projection is best-effort; never fails the command
        projection_error = str(exc)[:200]
    _emit({'schemaVersion': 1, 'ok': True, 'command': command, 'changed': changed,
           'auditEventHash': (audit_event or {}).get('eventHash'),
           'auditError': audit_error, 'projectionError': projection_error,
           'policy': after})
    return 0


def _status(args) -> int:
    try:
        policy = RootExecutionPolicy(root_dir=args.root_dir)
    except (OSError, ValueError) as exc:
        return _fail('status', 'root_policy_io', exc)
    _emit({'schemaVersion': 1, 'ok': True, 'command': 'status',
           'policy': policy.snapshot()})
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog=PROG, description=(
        'One-shot root helper for the ROOT execution policy. Refuses arbitrary '
        'paths/shell/service; only fixed transitions; every mutation is atomic, '
        'bumps executionEpoch, audits and refreshes the Runtime projection.'))
    parser.add_argument('--root-dir', type=Path,
                        default=DEFAULT_EXECUTION_POLICY_PATH.parent)
    parser.add_argument('--projection', type=Path, default=DEFAULT_PROJECTION_PATH)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('status', 'confirm-auto', 'revoke-auto', 'safe-disable',
                 'acknowledge-fuse', 'reset'):
        sub.add_parser(name)
    mode = sub.add_parser('mode')
    mode.add_argument('value', choices=sorted(MODES))
    route_stage = sub.add_parser('route-stage')
    route_stage.add_argument('value', choices=sorted(ROUTE_STAGES))
    args = parser.parse_args(argv)

    command = args.command
    if command == 'status':
        return _status(args)
    if command == 'mode':
        return _mutate(args, 'mode', ('set_mode', (args.value,), 'policy.mode'))
    if command == 'route-stage':
        return _mutate(args, 'route-stage',
                       ('set_route_stage', (args.value,), 'policy.route_stage'))
    return _mutate(args, command)


if __name__ == '__main__':
    raise SystemExit(main())
