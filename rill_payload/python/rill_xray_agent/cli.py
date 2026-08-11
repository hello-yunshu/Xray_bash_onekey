from __future__ import annotations
import argparse, json, socket, time, uuid
from pathlib import Path
from .canonical import canonical_bytes

# Semantic capability mapping (0.2): CLI no longer hardcodes route for every
# envelope. Security permissions are unchanged - this only labels intent.
SENTINEL_METHODS = {'status', 'health', 'metrics', 'config', 'snapshot', 'timeline'}
DOCTOR_METHODS = {'diagnose'}
ROUTE_METHODS = {'mode'}


def _capability(method: str) -> str:
    if method in SENTINEL_METHODS:
        return 'sentinel'
    if method in DOCTOR_METHODS:
        return 'doctor'
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
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('status', 'health', 'metrics', 'config', 'snapshot', 'diagnose'):
        sub.add_parser(name)
    mode = sub.add_parser('mode')
    mode.add_argument('value', choices=['normal', 'observe-only', 'safe-disabled'])
    inspect = sub.add_parser('inspect')
    inspect.add_argument('decision_id')
    timeline = sub.add_parser('timeline')
    timeline.add_argument('--limit', type=int, default=50)
    feedback = sub.add_parser('feedback')
    feedback.add_argument('decision_id')
    feedback.add_argument('--outcome', choices=FEEDBACK_OUTCOMES, required=True)
    feedback.add_argument('--helpful', type=lambda v: v.lower() in ('1', 'true', 'yes'), required=True)
    feedback.add_argument('--diagnosis-correct', dest='diagnosis_correct',
                          type=lambda v: v.lower() in ('1', 'true', 'yes'), required=True)
    args = parser.parse_args(argv)

    method = {'status': 'health', 'health': 'health', 'metrics': 'metrics',
              'config': 'config', 'snapshot': 'snapshot', 'mode': 'mode',
              'inspect': 'inspect', 'timeline': 'timeline', 'diagnose': 'diagnose',
              'feedback': 'feedback'}[args.command]
    body = {}
    if args.command == 'mode':
        body = {'mode': args.value}
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