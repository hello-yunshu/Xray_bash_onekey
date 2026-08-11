import os
import time
from pathlib import Path
from .canonical import atomic_write_json, digest, read_json
from .errors import ContractError, DecisionIdentityConflict, MigrationError, RillError
from .locking import FileLock


class LedgerFullError(ContractError):
    """Closed ledger is at capacity or hit a conflict; failing closed rather
    than silently dropping a tombstone that may still be inside its
    replay-protection window."""


class ClosedLedger:
    """Externalized, bounded closed-decision ledger.

    Tombstones are stored one-per-file under <root>/ as sha256(decisionId).json.
    A tombstone NEVER stores the plaintext decision id, only its hash plus the
    identity/payload hashes, the close timestamp and - since the P1-3 fix - the
    safe, non-sensitive feedback identity metadata (capability,
    modelGeneration) needed to rebuild the canonical feedback projection for
    exact replay after eviction. Raw config, secrets and free text are never
    stored. The ledger has an explicit capacity (entries or bytes) and fails
    closed when full; it never silently drops a tombstone. Corrupted files are
    treated as unsafe on query.

    put()/put_hashed() are idempotent for an identical tombstone (same
    decisionIdHash + identityHash + payloadHash) regardless of the replay
    window, and fail closed on conflict (same decision, differing
    identity/payload/metadata) or on an unsafe existing entry. Tombstones
    written without the optional feedback metadata (legacy) stay valid: the
    hash comparison remains the authoritative identity check.
    """

    def __init__(self, root, max_entries=None, max_bytes=None,
                 replay_protection_seconds=21600):
        self.root = Path(root)
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.replay_protection_seconds = replay_protection_seconds
        self.lock = self.root / '.lock'
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _file_path(root, decision_id_hash):
        return Path(root) / f'{decision_id_hash}.json'

    def _bytes(self):
        total = 0
        for p in self.root.glob('*.json'):
            try:
                total += p.stat().st_size
            except OSError:
                continue
        return total

    def count(self):
        return len(list(self.root.glob('*.json')))

    def entries(self):
        out = {}
        for p in sorted(self.root.glob('*.json')):
            try:
                data = read_json(p)
            except Exception:
                continue
            if data.get('schemaVersion') != 1:
                continue
            out[data.get('decisionIdHash')] = {
                'payloadHash': data.get('payloadHash'),
                'closedAtEpochSeconds': data.get('closedAtEpochSeconds'),
            }
        return out

    def get_hash(self, decision_id_hash):
        p = ClosedLedger._file_path(self.root, decision_id_hash)
        if not p.is_file() or p.is_symlink():
            return None
        try:
            data = read_json(p)
        except Exception:
            return {'corrupt': True, 'decisionIdHash': decision_id_hash}
        if data.get('schemaVersion') != 1 or data.get('decisionIdHash') != decision_id_hash:
            return {'corrupt': True, 'decisionIdHash': decision_id_hash}
        return data

    def get(self, did):
        return self.get_hash(digest(did))

    def put_hashed(self, decision_id_hash, identity_hash, payload_sha, closed_at,
                   capability=None, model_generation=None):
        if os.environ.get('RILL_LEDGER_IO_ERROR') == '1':
            raise LedgerFullError('fault injected: RILL_LEDGER_IO_ERROR')
        with FileLock(self.lock):
            existing_path = ClosedLedger._file_path(self.root, decision_id_hash)
            if existing_path.exists() and not existing_path.is_symlink():
                existing = None
                try:
                    existing = read_json(existing_path)
                except Exception:
                    existing = None
                if existing is not None and existing.get('schemaVersion') == 1:
                    if (existing.get('decisionIdHash') == decision_id_hash
                            and existing.get('identityHash') == identity_hash
                            and existing.get('payloadHash') == payload_sha):
                        # Idempotent success, unaffected by replay window. When
                        # the existing tombstone already carries the feedback
                        # identity metadata, a *differing* capability or
                        # modelGeneration is a conflict, never a silent accept.
                        if (existing.get('capability') is not None
                                and existing.get('capability') != capability):
                            raise LedgerFullError(
                                'tombstone conflict: feedback capability differs')
                        if (existing.get('modelGeneration') is not None
                                and existing.get('modelGeneration') != model_generation):
                            raise LedgerFullError(
                                'tombstone conflict: feedback modelGeneration differs')
                        return True  # idempotent success, unaffected by replay window
                    raise LedgerFullError(
                        'tombstone conflict: same decision, differing identity/payload')
                # Corrupt or unsafe existing entry: never overwrite, fail closed.
                raise LedgerFullError('closed ledger corrupt entry')
            if self.max_entries and self.count() >= self.max_entries:
                raise LedgerFullError('closed ledger at max entries')
            if self.max_bytes and (self._bytes() + 256) > self.max_bytes:
                raise LedgerFullError('closed ledger at max bytes')
            tombstone = {
                'schemaVersion': 1,
                'decisionIdHash': decision_id_hash,
                'identityHash': identity_hash,
                'payloadHash': payload_sha,
                'closedAtEpochSeconds': int(closed_at),
            }
            # P1-3: persist the safe, non-sensitive feedback identity metadata
            # so an evicted Doctor decision can rebuild the canonical feedback
            # projection on exact replay. Never raw config, secrets or text.
            if capability is not None:
                tombstone['capability'] = capability
            if model_generation is not None:
                tombstone['modelGeneration'] = int(model_generation)
            atomic_write_json(existing_path, tombstone)
            return True

    def put(self, did, identity_hash, payload_sha, closed_at):
        return self.put_hashed(digest(did), identity_hash, payload_sha, closed_at)


class RuntimeState:
    def __init__(self, path, max_completed=4096, ledger_dir=None,
                 max_ledger_entries=0, max_ledger_bytes=None,
                 replay_protection_seconds=21600):
        self.path = Path(path)
        self.lock = self.path.with_suffix('.lock')
        self.max_completed = max_completed
        self.ledger = ClosedLedger(
            ledger_dir or (self.path.parent / 'closed-ledger'),
            max_entries=max_ledger_entries,
            max_bytes=max_ledger_bytes,
            replay_protection_seconds=replay_protection_seconds)

    def empty(self):
        return {'schemaVersion': 3, 'mode': 'observe-only', 'routeAssistEnabled': False,
                'pending': {}, 'completed': {}, 'restartCount': 0}

    def load(self):
        if not self.path.exists():
            return self.empty()
        v = read_json(self.path)
        if v.get('schemaVersion') not in {1, 2, 3}:
            raise ContractError('unsupported state')
        if v['schemaVersion'] != 3:
            m = self.empty()
            m.update({k: x for k, x in v.items() if k in m})
            v = m
            self.save(v)
        # Route Assist is a hard invariant: it must never survive load.
        if v.get('routeAssistEnabled'):
            v['routeAssistEnabled'] = False
            self.save(v)
        self._migrate_legacy_closed(v)
        return v

    def _migrate_legacy_closed(self, v):
        """One-shot, fail-closed migration of the pre-ledger in-memory 'closed'
        mirror to the external ledger.

        Each legacy tombstone is externalized through the idempotent ledger.put
        (which also readbacks/compares), and only after that single entry
        succeeds is it removed from the mirror. ANY failure aborts before a
        destructive persist: the legacy entry is retained, no save happens, a
        MigrationError propagates and health becomes recovery-required.
        """
        legacy = v.get('closed')
        if not legacy:
            return
        for did, tomb in list(legacy.items()):
            if not tomb:
                continue
            identity_hash = tomb.get('identityHash')
            payload_sha = tomb.get('payloadHash')
            if not identity_hash or not payload_sha:
                raise MigrationError(f'legacy tombstone missing hashes: {did}')
            closed_at = tomb.get('closedAtEpochSeconds', int(time.time()))
            # Idempotent + readback-compared inside put/put_hashed.
            try:
                self.ledger.put(did, identity_hash, payload_sha, closed_at)
                entry = self.ledger.get(did)
                if not entry:
                    raise MigrationError(f'legacy tombstone not externalized: {did}')
                if entry.get('corrupt'):
                    raise MigrationError(f'legacy tombstone readback corrupt: {did}')
                if entry.get('identityHash') != identity_hash or entry.get('payloadHash') != payload_sha:
                    raise MigrationError(f'legacy tombstone hash mismatch: {did}')
            except (ContractError, OSError) as e:
                # Ledger refused (full/conflict/corrupt/fault), or the readback
                # failed (missing/corrupt/OS error): keep the mirror, fail closed.
                raise MigrationError(
                    f'legacy tombstone not externalized: {did}') from e
            # Success for this single entry only.
            del v['closed'][did]
        v.pop('closed', None)
        self.save(v)

    def save(self, v):
        atomic_write_json(self.path, v)

    def transact(self, fn):
        with FileLock(self.lock):
            s = self.load()
            c = dict(s)
            c['pending'] = dict(s.get('pending') or {})
            c['completed'] = dict(s.get('completed') or {})
            r = fn(c)
            self.save(c)
            return r

    def _tombstone(self, ident, payload_sha, closed_at):
        return {'decisionIdHash': digest(ident['decisionId']), 'identityHash': digest(ident),
                'payloadHash': payload_sha, 'closedAtEpochSeconds': closed_at}

    def ledger_tombstone(self, ident, payload_sha, closed_at):
        return self._tombstone(ident, payload_sha, closed_at)

    def register(self, capability, decision_id, generation, created):
        ident = {'capability': capability, 'decisionId': decision_id,
                 'modelGeneration': generation, 'createdAtEpochSeconds': created}

        def tx(s):
            e = s['pending'].get(decision_id) or s['completed'].get(decision_id)
            if e:
                if e.get('identity') == ident:
                    return {'status': 'idempotent'}
                raise DecisionIdentityConflict('decision ID different identity')
            c = self.ledger.get(decision_id)
            if c:
                if c.get('corrupt'):
                    raise ContractError('closed ledger corrupt')
                if c['identityHash'] == digest(ident):
                    return {'status': 'idempotent'}
                raise DecisionIdentityConflict('decision ID different identity')
            s['pending'][decision_id] = {'identity': ident, 'rootResult': None,
                                         'registeredAtEpochSeconds': int(time.time())}
            return {'status': 'registered'}
        return self.transact(tx)

    def commit_root_result(self, did, result):
        def tx(s):
            p = s['pending'].get(did)
            if not p:
                raise ContractError('unknown pending decision')
            if p.get('rootResult'):
                if digest(p['rootResult']) == digest(result):
                    return {'status': 'idempotent'}
                raise ContractError('conflicting result')
            p['rootResult'] = result
            return {'status': 'committed'}
        return self.transact(tx)