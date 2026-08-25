from __future__ import annotations
import argparse, json, socket, time, uuid
from pathlib import Path
from .canonical import canonical_bytes

# Semantic capability mapping (0.2): CLI no longer hardcodes route for every
# envelope. Security permissions are unchanged - this only labels intent.
SENTINEL_METHODS = {'status', 'health', 'metrics', 'config', 'snapshot', 'timeline'}
DOCTOR_METHODS = {'diagnose'}
ROUTE_METHODS = {'mode', 'routeStatus', 'routeStage', 'routePlan', 'routeInspect',
                 'routeApprove', 'routeReject', 'routeHistory', 'autoStatus',
                 'autoConfirm', 'autoProduce'}
ROUTE_STAGES = ['observe', 'assist', 'auto']


def _capability(method: str) -> str:
    if method in SENTINEL_METHODS:
        return 'sentinel'
    if method in DOCTOR_METHODS:
        return 'doctor'
    if method in ROUTE_METHODS:
        return 'route'
    return 'route'


def call(socket_path: Path, method: str, body: dict | None = None) -> dict:
    envelope = {'schemaVersion': 3, 'requestId': str(uuid.uuid4()),
                'capability': _capability(method), 'method': method, 'body': body or {}}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(socket_path))
        client.sendall(canonical_bytes(envelope) + b'\n')
        data = b''
        while b'\n' not in data and len(data) <= 1_048_576:
            chunk = client.recv(65_536)
            if not chunk:
                break
            data += chunk
    if not data:
        raise RuntimeError('empty Runtime response')
    return json.loads(data.split(b'\n', 1)[0])


def _rillml_dispatch(args) -> dict:
    """Root-only RillML lifecycle operations.

    Directly operates the ROOT-owned RillML tree (staging/current/rollback)
    via the single authoritative ``RillMLRuntimeManager``; it never goes
    through the Runtime IPC (the unprivileged Runtime is read-only for
    RillML, §P0-16). Requires euid 0; a non-root caller fails closed.
    """
    import os

    if os.name != 'posix' or os.geteuid() != 0:
        return {'schemaVersion': 3, 'requestId': 'local', 'ok': False,
                'error': {'code': 'rootRequired',
                          'message': 'rillml lifecycle operations require root'}}
    from .rillml_artifact import RillMLRuntimeManager, load_expected_release_version
    manager = RillMLRuntimeManager(
        args.rillml_root,
        expected_release_version=load_expected_release_version(),
    )
    try:
        cmd = args.rillml_command
        if cmd == 'status':
            result = manager.status()
        elif cmd == 'resolve':
            result = manager.resolve()
        elif cmd == 'install':
            result = manager.install(probe=args.probe,
                                     allow_downgrade=args.allow_downgrade)
        elif cmd == 'upgrade':
            result = manager.upgrade(probe=args.probe,
                                     allow_downgrade=args.allow_downgrade)
        elif cmd == 'reinstall':
            result = manager.reinstall(probe=args.probe)
        elif cmd == 'rollback':
            result = manager.rollback()
        else:
            raise ValueError(f'unsupported rillml command: {cmd}')
    except Exception as exc:
        return {'schemaVersion': 3, 'requestId': 'local', 'ok': False,
                'error': {'code': getattr(exc, 'code', None) or 'rillmlError',
                          'message': str(exc)[:512]}}
    return {'schemaVersion': 3, 'requestId': 'local', 'ok': True, 'result': result}


FEEDBACK_OUTCOMES = ['resolved', 'not-resolved', 'not-applicable']


def _confirm(response: dict) -> dict:
    if not response.get('ok'):
        raise SystemExit(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return response


def _print_diagnose(result: dict) -> None:
    """Human-readable diagnosis output; never prints secrets."""
    print('Status:', result.get('status'))
    print('Severity:', result.get('severity'))
    print('Confidence:', result.get('confidenceBand'))
    evidence = result.get('evidence') or {}
    print('Evidence: observation', evidence.get('observationStatus'),
          '/ timeline', evidence.get('timelineStatus'))
    print()
    print('Facts:')
    for fact in result.get('facts') or []:
        print('-', fact)
    print()
    print('Assessment:')
    for inference in result.get('inferences') or []:
        print('-', inference)
    print()
    print('Recommendation:')
    for rec in result.get('recommendations') or []:
        print('-', rec.get('code'), f"(priority={rec.get('priority')})")
    if not result.get('recommendations'):
        print('- none')
    print()
    print('Limitations:')
    for limitation in result.get('limitations') or []:
        print('-', limitation)
    if not result.get('limitations'):
        print('- none')
    print()
    print('Automatic execution:')
    print('disabled')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='rill-xray-agent')
    parser.add_argument('--socket', type=Path, default=Path('/run/rill-xray-agent/runtime.sock'))
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--rillml-root', type=Path, default=Path('/var/lib/rill-xray-agent-rillml'))
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('status', 'health', 'metrics', 'config', 'snapshot', 'diagnose',
                 'route-status', 'route-history', 'auto-status', 'rillml-status'):
        sub.add_parser(name)
    mode = sub.add_parser('mode')
    mode.add_argument('value', choices=['normal', 'observe-only', 'safe-disabled'])
    inspect = sub.add_parser('inspect')
    inspect.add_argument('decision_id')
    timeline = sub.add_parser('timeline')
    timeline.add_argument('--limit', type=int, default=50)
    route_stage = sub.add_parser('route-stage')
    route_stage.add_argument('value', choices=ROUTE_STAGES)
    route_plan = sub.add_parser('route-plan')
    route_plan.add_argument('--operations', type=json.loads, default=None)
    route_approve = sub.add_parser('route-approve')
    route_approve.add_argument('recommendation_id')
    route_approve.add_argument('--operations', type=json.loads, default=None)
    route_reject = sub.add_parser('route-reject')
    route_reject.add_argument('recommendation_id')
    route_reject.add_argument('--reason', default='operator-rejected')
    auto_confirm = sub.add_parser('auto-confirm')
    auto_produce = sub.add_parser('auto-produce')
    feedback = sub.add_parser('feedback')
    feedback.add_argument('decision_id')
    feedback.add_argument('--outcome', choices=FEEDBACK_OUTCOMES, required=True)
    feedback.add_argument('--helpful', type=lambda v: v.lower() in ('1', 'true', 'yes'), required=True)
    feedback.add_argument('--diagnosis-correct', dest='diagnosis_correct',
                          type=lambda v: v.lower() in ('1', 'true', 'yes'), required=True)
    rillml = sub.add_parser('rillml')
    rillml_sub = rillml.add_subparsers(dest='rillml_command', required=True)
    rillml_sub.add_parser('status')
    rillml_sub.add_parser('resolve')
    for name in ('install', 'upgrade', 'reinstall'):
        rillml_lifecycle = rillml_sub.add_parser(name)
        rillml_lifecycle.add_argument('--probe', choices=('lightweight', 'handshake'),
                                      default='lightweight')
        rillml_lifecycle.add_argument('--allow-downgrade', action='store_true')
    rillml_sub.add_parser('rollback')
    args = parser.parse_args(argv)

    method = None
    if args.command != 'rillml':
        method = {'status': 'health', 'health': 'health', 'metrics': 'metrics',
                  'config': 'config', 'snapshot': 'snapshot', 'mode': 'mode',
                  'inspect': 'inspect', 'timeline': 'timeline', 'diagnose': 'diagnose',
                  'feedback': 'feedback', 'route-status': 'routeStatus',
                  'route-stage': 'routeStage', 'route-plan': 'routePlan',
                  'route-approve': 'routeApprove', 'route-reject': 'routeReject',
                  'route-history': 'routeHistory', 'auto-status': 'autoStatus',
                  'auto-confirm': 'autoConfirm', 'auto-produce': 'autoProduce',
                  'rillml-status': 'rillmlStatus'}[args.command]
    body = {}
    if args.command == 'mode':
        body = {'mode': args.value}
    elif args.command == 'route-stage':
        body = {'stage': args.value}
    elif args.command == 'route-plan':
        body = {'operations': args.operations or []}
    elif args.command == 'route-approve':
        body = {'recommendationId': args.recommendation_id,
                'operations': args.operations or []}
    elif args.command == 'route-reject':
        body = {'recommendationId': args.recommendation_id,
                'reasonCode': args.reason}
    elif args.command == 'route-history':
        body = {'limit': 50}
    elif args.command == 'inspect':
        body = {'decisionId': args.decision_id}
    elif args.command == 'timeline':
        body = {'limit': args.limit}

    try:
        if args.command == 'feedback':
            # The decision was already registered by the diagnose flow (or the
            # operator knows its diagnosisId); the CLI NEVER fabricates a
            # registration. Canonical decision identity (capability, model
            # generation, created-at) is resolved by the Runtime from the
            # registered decision - the CLI only submits the structured
            # feedback fields.
            response = call(args.socket, 'feedback', {
                'decisionId': args.decision_id,
                'outcome': args.outcome, 'helpful': args.helpful,
                'diagnosisCorrect': args.diagnosis_correct})
            _confirm(response)
            print(json.dumps(response if args.json else response.get('result'),
                             ensure_ascii=False, sort_keys=True, indent=2))
            return 0
        if args.command == 'rillml':
            # Root-only lifecycle: directly operates the RillML tree, never
            # the Runtime IPC (Runtime is read-only for RillML, §P0-16).
            response = _rillml_dispatch(args)
        else:
            response = call(args.socket, method, body)
    except Exception as exc:
        response = {'schemaVersion': 3, 'requestId': 'local', 'ok': False,
                    'error': {'code': 'runtimeUnavailable', 'message': str(exc)[:256]}}
    if not response.get('ok'):
        print(json.dumps(response, ensure_ascii=False, sort_keys=True, indent=2))
        return 1
    result = response.get('result')
    if args.command == 'diagnose' and not args.json:
        _print_diagnose(result)
        return 0
    print(json.dumps(result if args.json else result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
