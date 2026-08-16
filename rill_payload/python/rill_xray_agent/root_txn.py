import os, pwd, re, shutil, time
from pathlib import Path
from .canonical import atomic_write_bytes, atomic_write_json, digest, file_sha256, read_json
from .errors import TransactionError
from .locking import FileLock

RECOMMENDATION_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
TERMINAL_STATES = {'committed', 'rolledBack', 'rollbackUnverified'}
RECOVERABLE_STATES = {'prepared', 'applying', 'applied', 'verified', 'commit-intent', 'rollback-intent'}
UNVERIFIED_STATE = 'rollbackUnverified'

# Root-owned generation file (§P0-7). Generation participates in root-side
# stale-plan authorization, so its final authority must be a root-only path,
# never the unprivileged Runtime state root. The Runtime service only READS
# it (ReadOnlyPaths=/var/lib/rill-xray-agent-root); only the root oneshot
# (rill-xray-agent-apply) writes it via RootTransaction.
DEFAULT_GENERATION_PATH = Path('/var/lib/rill-xray-agent-root/generation')

# The unprivileged Runtime (User=rill-xray-agent) must be able to READ the
# root-owned generation to observe committed generations. The generation file
# is therefore written 0640 with group rill-xray-agent (install.sh also sets
# the setgid bit on the root dir, so mkstemp+replace inherits the group even
# without the explicit chown; the chown here makes it robust in sandboxes).
RILL_GROUP = 'rill-xray-agent'


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
    def __init__(self, root, delivery, generation_file, restart_fn=None):
        self.root = Path(root)
        self.delivery = Path(delivery)
        self.generation_file = Path(generation_file)
        self.lock = self.root / '.single-flight.lock'
        # Optional host-sync callback (P0-9): after a managed-file mutation the
        # live Xray service must be restarted and verified active. Production
        # wiring (bin/rill-xray-agent-apply) provides a systemctl-based
        # implementation; tests may leave it None (pure file-level txn). It is
        # also invoked on rollback/recovery so the restored config is the one
        # actually running. Returning False means the live convergence failed
        # and the transaction must roll back.
        self.restart_fn = restart_fn

    def generation(self):
        try:
            return int(self.generation_file.read_text().strip())
        except FileNotFoundError:
            return 0

    def _write_generation(self, value):
        """Persist the root-owned generation (§P0-7) as 0640 root:rill-xray-agent
        so the unprivileged Runtime can read committed generations. The root dir
        carries the setgid bit at install time (mkstemp+replace inherits the
        group); the explicit chown keeps the DAC correct even where the dir
        lacks setgid (test sandboxes). Non-root callers (tests) skip the chown."""
        atomic_write_bytes(self.generation_file, (str(value) + '\n').encode(), 0o640)
        if os.geteuid() == 0:
            try:
                gid = pwd.getgrnam(RILL_GROUP).gr_gid
                os.chown(self.generation_file, 0, gid)
            except (KeyError, OSError):
                pass

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
        self._write_generation(b['nextConfigurationGeneration'])
        atomic_write_json(w / 'result.json', b['result'])
        fault('RESULT')
        atomic_write_json(w / 'receipt.json', b['receipt'])
        fault('RECEIPT')
        self.delivery.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.delivery / 'route-delivery.json', b['delivery'], 0o640)
        fault('DELIVERY')

    def apply(self, request, managed, apply_fn, verify_fn,
              restart_fn=None, commit_hook=None, rollback_hook=None):
        did = self.validated_id(request['recommendationId'])
        w = self.root / self.work_dir_name(did)
        restart = restart_fn if restart_fn is not None else self.restart_fn
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
                # P0-9 Phase B: live convergence. The new config is on disk;
                # restart Xray and require it active BEFORE the terminal
                # commit. A failed restart rolls back.
                if restart is not None and not restart():
                    raise TransactionError('live restart failed')
                self.state(w, 'applied')
                fault('APPLIED')
                # P0-9 Phase C: post-restart verification (config sha match +
                # validation) before commit.
                if not verify_fn():
                    raise TransactionError('verify failed')
                self.state(w, 'verified')
                fault('VERIFIED')
                self.state(w, 'commit-intent')
                fault('COMMIT_INTENT')
                # P0-10: the auto ledger record must be durable BEFORE the
                # terminal commit. If it fails, the host is rolled back so no
                # "host changed but no durable ledger record" terminal exists.
                if commit_hook is not None:
                    commit_hook()
            except Exception as exc:
                return self._rollback(w, managed, backup, existed, old, exc,
                                      restart_fn=restart, rollback_hook=rollback_hook)
            bundle = self._build_bundle(w, did, request, old, 'committed', 'success')
            atomic_write_json(w / 'commit-bundle.json', bundle)
            if os.environ.get('RILL_FAIL_AFTER_COMMIT_BUNDLE') == '1':
                raise TransactionError('fault injected after commit bundle')
            return self.materialize(w)

    def _rollback(self, w, managed, backup, existed, old, exc,
                  restart_fn=None, rollback_hook=None):
        """Ordered rollback transaction. The rollback commit bundle and all
        durable artifacts (result/receipt/delivery) are written BEFORE the
        terminal rolledBack state, so a crash in the middle is recoverable and
        rolledBack-without-bundle can never look ready.

        P0-9 Phase E: after the managed config is restored the live Xray
        service is restarted (restart_fn) so the restored config is the one
        actually running; a failed restored-restart marks rollbackUnverified.
        """
        self.state(w, 'rollback-intent')
        fault('ROLLBACK_INTENT')
        try:
            # 1. restore managed from backup
            if existed:
                atomic_write_bytes(managed, backup.read_bytes(), 0o640)
            elif managed.exists():
                managed.unlink()
            fault('MANAGED_RESTORE')
            # 1b. live convergence back to the restored config (P0-9 Phase E).
            if restart_fn is not None and not restart_fn():
                raise TransactionError('restored restart failed')
            # 2. restore generation
            self._write_generation(old)
            fault('GENERATION_RESTORE')
            # 3. verify the restore actually converged
            if existed and (not backup.is_file() or file_sha256(managed) != file_sha256(backup)):
                raise TransactionError('restore verification failed')
            # 3b. P0-10: rollback ledger record before the rollback terminal.
            if rollback_hook is not None:
                rollback_hook()
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

    def scan_recovery_state(self):
        """READ-ONLY scan of the root transaction area for the unprivileged
        Runtime production path.

        Unlike recover_all() this never mutates anything: no generation write,
        no delivery/result/receipt rewrite, no managed-file restore, no state
        file touch and no re-materialization of historical transactions. It
        exists so the Runtime (whose systemd contract keeps the root
        transaction area read-only) can classify each transaction as safe or
        requiring a privileged host-owned recovery.

        Returns a list of per-work-dir reports:
          {workDir, state, commitBundle, result, receipt, safe, recoveryRequired}
        """
        out = []
        if not self.root.exists():
            return out
        for w in sorted(self.root.iterdir()):
            if not w.is_dir() or w.is_symlink():
                continue
            report = {'workDir': w.name}
            state = None
            try:
                state = read_json(w / 'state.json').get('state')
            except Exception:
                state = None
            report['state'] = state
            bundle_ok = (w / 'commit-bundle.json').is_file()
            report['commitBundle'] = bundle_ok
            report['result'] = (w / 'result.json').is_file()
            report['receipt'] = (w / 'receipt.json').is_file()
            report['unsafe'] = False
            if state == 'rollbackUnverified':
                # rollbackUnverified is NEVER a safe terminal state.
                report['safe'] = False
                report['unsafe'] = True
            elif state in TERMINAL_STATES and bundle_ok and report['result'] and report['receipt']:
                report['safe'] = True
            elif state is None:
                # A work dir without a readable state is incomplete/corrupt.
                report['safe'] = False
                report['unsafe'] = True
            else:
                report['safe'] = False
            report['recoveryRequired'] = not report['safe']
            out.append(report)
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
        # P0-9: live convergence back to the restored config after recovery.
        if self.restart_fn is not None and not self.restart_fn():
            raise TransactionError('restored restart failed during recovery')
        self._write_generation(old)
        if existed and (not backup.is_file() or file_sha256(managed) != file_sha256(backup)):
            raise TransactionError('restore verification failed')
        bundle = self._build_bundle(w, did, read_json(w / 'request.json'), old, 'rolledBack', 'rolledBack')
        atomic_write_json(w / 'commit-bundle.json', bundle)
        self._materialize_artifacts(w, bundle)
        self.state(w, 'rolledBack', {'commitSha256': bundle['commitSha256']})
