import os, re, shutil, time
from pathlib import Path
from .canonical import atomic_write_bytes, atomic_write_json, digest, file_sha256, read_json
from .errors import TransactionError
from .locking import FileLock

RECOMMENDATION_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
TERMINAL_STATES = {'committed', 'rolledBack', 'rollbackUnverified'}
RECOVERABLE_STATES = {'prepared', 'applying', 'applied', 'verified', 'commit-intent', 'rollback-intent'}
UNVERIFIED_STATE = 'rollbackUnverified'


def fault(point: str):
    """Controllable crash injection at real persistence boundaries.

    Each env var is checked exactly where the corresponding durable write
    happens, so fault tests exercise the production crash path instead of
    hand-rolled state files. Points:
      PREPARED APPLYING MANAGED_MUTATION APPLIED VERIFIED COMMIT_INTENT
      ROLLBACK_INTENT MANAGED_RESTORE GENERATION_RESTORE ROLLBACK_BUNDLE
      RESULT RECEIPT DELIVERY TERMINAL
    """
    if os.environ.get(f'RILL_FAULT_{point}') == '1':
        raise TransactionError(f'fault injected at {point}')


class RootTransaction:
    def __init__(self, root, delivery, generation_file):
        self.root = Path(root)
        self.delivery = Path(delivery)
        self.generation_file = Path(generation_file)
        self.lock = self.root / '.single-flight.lock'

    def generation(self):
        try:
            return int(self.generation_file.read_text().strip())
        except FileNotFoundError:
            return 0

    @staticmethod
    def validated_id(did):
        if not isinstance(did, str) or not RECOMMENDATION_ID_RE.match(did):
            raise TransactionError('invalid recommendationId')
        return did

    @staticmethod
    def work_dir_name(did):
        return digest(did)

    def state(self, w, s, x=None):
        atomic_write_json(w / 'state.json', {'schemaVersion': 1, 'state': s, **(x or {})})

    def _build_bundle(self, w, did, request, old, terminal, outcome):
        body = {'schemaVersion': 2, 'decisionId': did, 'outcome': outcome,
                'observedAtEpochSeconds': int(time.time()), 'configurationGeneration': old,
                'nextConfigurationGeneration': old + 1 if terminal == 'committed' else old}
        result = {**body, 'resultSha256': digest(body)}
        receipt = {'schemaVersion': 1, 'decisionId': did, 'resultSha256': result['resultSha256'],
                   'transactionSha256': digest({'request': request, 'result': result}),
                   'createdAtEpochSeconds': int(time.time())}
        base = {'schemaVersion': 1, 'terminalState': terminal,
                'nextConfigurationGeneration': result['nextConfigurationGeneration'],
                'result': result, 'receipt': receipt,
                'delivery': {'schemaVersion': 1, 'request': request, 'result': result, 'receipt': receipt}}
        return {**base, 'commitSha256': digest(base)}

    def _materialize_artifacts(self, w, b):
        """Write generation, result, receipt and delivery from a validated
        bundle. Each durable artifact boundary is a fault point so crash
        recovery can be tested at every step."""
        atomic_write_bytes(self.generation_file, (str(b['nextConfigurationGeneration']) + '\n').encode(), 0o640)
        atomic_write_json(w / 'result.json', b['result'])
        fault('RESULT')
        atomic_write_json(w / 'receipt.json', b['receipt'])
        fault('RECEIPT')
        self.delivery.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.delivery / 'route-delivery.json', b['delivery'], 0o640)
        fault('DELIVERY')

    def apply(self, request, managed, apply_fn, verify_fn):
        did = self.validated_id(request['recommendationId'])
        w = self.root / self.work_dir_name(did)
        with FileLock(self.lock):
            if (w / 'commit-bundle.json').exists():
                return self.materialize(w)
            w.mkdir(parents=True, exist_ok=True)
            old = self.generation()
            if old != request['configurationGeneration']:
                raise TransactionError('generation mismatch')
            existed = managed.exists()
            backup = w / 'managed.backup'
            if existed and not backup.exists():
                shutil.copy2(managed, backup)
            meta = {'schemaVersion': 1, 'managedExisted': existed,
                    'managedPath': str(managed),
                    'backupSha256': file_sha256(backup) if existed else None,
                    'oldGeneration': old, 'newGeneration': old + 1}
            atomic_write_json(w / 'backup-metadata.json', meta)
            atomic_write_json(w / 'request.json', request)
            self.state(w, 'prepared')
            fault('PREPARED')
            try:
                self.state(w, 'applying')
                fault('APPLYING')
                apply_fn()
                fault('MANAGED_MUTATION')
                self.state(w, 'applied')
                fault('APPLIED')
                if not verify_fn():
                    raise TransactionError('verify failed')
                self.state(w, 'verified')
                fault('VERIFIED')
                self.state(w, 'commit-intent')
                fault('COMMIT_INTENT')
            except Exception as exc:
                return self._rollback(w, managed, backup, existed, old, exc)
            bundle = self._build_bundle(w, did, request, old, 'committed', 'success')
            atomic_write_json(w / 'commit-bundle.json', bundle)
            if os.environ.get('RILL_FAIL_AFTER_COMMIT_BUNDLE') == '1':
                raise TransactionError('fault injected after commit bundle')
            return self.materialize(w)

    def _rollback(self, w, managed, backup, existed, old, exc):
        """Ordered rollback transaction. The rollback commit bundle and all
        durable artifacts (result/receipt/delivery) are written BEFORE the
        terminal rolledBack state, so a crash in the middle is recoverable and
        rolledBack-without-bundle can never look ready."""
        self.state(w, 'rollback-intent')
        fault('ROLLBACK_INTENT')
        try:
            # 1. restore managed from backup
            if existed:
                atomic_write_bytes(managed, backup.read_bytes(), 0o640)
            elif managed.exists():
                managed.unlink()
            fault('MANAGED_RESTORE')
            # 2. restore generation
            atomic_write_bytes(self.generation_file, (str(old) + '\n').encode(), 0o640)
            fault('GENERATION_RESTORE')
            # 3. verify the restore actually converged
            if existed and (not backup.is_file() or file_sha256(managed) != file_sha256(backup)):
                raise TransactionError('restore verification failed')
            # 4. build and persist the rollback commit bundle
            did = read_json(w / 'request.json')['recommendationId']
            bundle = self._build_bundle(w, did, read_json(w / 'request.json'), old, 'rolledBack', 'rolledBack')
            atomic_write_json(w / 'commit-bundle.json', bundle)
            fault('ROLLBACK_BUNDLE')
            # 5. materialize result/receipt/delivery
            self._materialize_artifacts(w, bundle)
            # 6. terminal state written LAST
            self.state(w, 'rolledBack', {'commitSha256': bundle['commitSha256']})
            fault('TERMINAL')
            return {'status': 'rolledBack', 'result': bundle['result'], 'receipt': bundle['receipt']}
        except Exception as rb_exc:
            try:
                self.state(w, 'rollbackUnverified')
            except Exception:
                pass
            raise TransactionError('rollback unverified; recovery will retry') from rb_exc

    def materialize(self, w):
        b = read_json(w / 'commit-bundle.json')
        base = {k: v for k, v in b.items() if k != 'commitSha256'}
        if digest(base) != b['commitSha256']:
            raise TransactionError('commit digest')
        self._materialize_artifacts(w, b)
        self.state(w, b['terminalState'], {'commitSha256': b['commitSha256']})
        fault('TERMINAL')
        return {'status': b['terminalState'], 'result': b['result'], 'receipt': b['receipt']}

    def recover_all(self):
        out = []
        if not self.root.exists():
            return out
        for w in self.root.iterdir():
            if not w.is_dir() or w.is_symlink():
                continue
            name = self._recover_one(w)
            if name:
                out.append(name)
        return out

    def _recover_one(self, w):
        # 1. Bundle already durable: materialize whatever is missing (result,
        #    receipt, delivery, generation, terminal state). Safe for both
        #    committed and rolledBack bundles.
        if (w / 'commit-bundle.json').exists():
            try:
                self.materialize(w)
                return w.name
            except Exception:
                try:
                    self.state(w, 'rollbackUnverified')
                except Exception:
                    pass
                return w.name
        if not (w / 'state.json').is_file():
            return None
        try:
            state = read_json(w / 'state.json')['state']
        except Exception:
            return None
        # 2. Intermediate states, a terminal state without a bundle, or an
        #    unverified rollback: rebuild the full rollback transaction.
        if state in RECOVERABLE_STATES or state in TERMINAL_STATES:
            try:
                self._rollback_recover(w, state)
                return w.name
            except Exception:
                try:
                    self.state(w, 'rollbackUnverified')
                except Exception:
                    pass
                return w.name
        return None

    def _rollback_recover(self, w, state):
        meta = read_json(w / 'backup-metadata.json')
        existed = bool(meta.get('managedExisted'))
        managed = Path(meta.get('managedPath') or w / 'managed.backup')
        backup = w / 'managed.backup'
        did = read_json(w / 'request.json')['recommendationId']
        old = int(meta['oldGeneration'])
        if existed and backup.is_file():
            atomic_write_bytes(managed, backup.read_bytes(), 0o640)
        elif not existed and managed.exists():
            managed.unlink()
        atomic_write_bytes(self.generation_file, (str(old) + '\n').encode(), 0o640)
        if existed and (not backup.is_file() or file_sha256(managed) != file_sha256(backup)):
            raise TransactionError('restore verification failed')
        bundle = self._build_bundle(w, did, read_json(w / 'request.json'), old, 'rolledBack', 'rolledBack')
        atomic_write_json(w / 'commit-bundle.json', bundle)
        self._materialize_artifacts(w, bundle)
        self.state(w, 'rolledBack', {'commitSha256': bundle['commitSha256']})
