import json, os, socket, time, uuid, threading, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from .audit import AuditLog
from .canonical import atomic_write_json, canonical_bytes, digest, read_json
from .doctor import Doctor
from .errors import EventJournalError
from .event_journal import EventJournal
from .health import health
from .operation import OperationLog
from .payload_policy import sanitize_doctor_feedback, sanitize_payload, sanitize_root_result, sanitize_route_plan_meta, RootResultViolation
from .peer_auth import AccessControl, peer_credentials
from .state import RuntimeState
from .root_txn import RootTransaction
from .release_capabilities import ReleaseCapabilities
from .route_policy import RoutePolicy, evaluate_plan_policy
from .route_history import RouteHistory
from .route_topology import RouteTopologyProjection
from .route_planner import RoutePlanner
from .route_analyzer import RouteAnalyzer, auto_eligible
from .route_contract import AUTO_ROUTE_OPS, overall_risk
from .route_executor import request_digest
from .auto_policy import AutoPolicy
from .root_policy import DEFAULT_PROJECTION_PATH
from .root_txn import DEFAULT_GENERATION_PATH
from .errors import UnknownDecisionError
from .doctor import Doctor

ALLOWED = {'health', 'metrics', 'mode', 'config', 'register', 'rootResult', 'feedback', 'inspect', 'snapshot', 'timeline', 'diagnose', 'routeStatus', 'routeStage', 'routePlan', 'routeApprove', 'routeReject', 'routeHistory', 'autoStatus', 'autoConfirm', 'autoProduce'}
ACCESS_LOG_BYTES = 8 * 1024 * 1024
MAX_FRAME_BYTES = 1048576
DEFAULT_OBSERVATION_PATH = '/var/lib/rill-xray-agent-xray/status/xray-observation.json'
DEFAULT_TIMELINE_DIR = '/var/lib/rill-xray-agent-xray/history'
# §P0-4: the safe route-topology projection produced by the ROOT observer.
# The unprivileged Runtime reads ONLY this secret-free projection (plus
# observation / timeline / root-policy projection); it never reads the raw
# Xray config on the host or the raw host mirror.
DEFAULT_TOPOLOGY_PATH = '/var/lib/rill-xray-agent-xray/status/route-topology.json'
MAX_DIAGNOSE_TIMELINE_EVENTS = 200
OBSERVATION_FRESHNESS_SECONDS = 300


class BoundedQueue:
    """Fail-closed bounded acceptance gate shared by Runtime and Agent.

    The global slot is acquired BEFORE the connection is dispatched to a
    worker, so futures and sockets can never pile up unboundedly. A rejected
    connection is answered with serverBusy and closed immediately.
    """

    def __init__(self, capacity):
        self.capacity = int(capacity)
        self._sem = threading.BoundedSemaphore(self.capacity)
        self.active = 0
        self.rejected = 0
        self._lock = threading.Lock()

    def acquire(self):
        got = self._sem.acquire(blocking=False)
        if got:
            with self._lock:
                self.active += 1
        else:
            with self._lock:
                self.rejected += 1
        return got

    def release(self):
        with self._lock:
            self.active -= 1
        self._sem.release()

    def available(self):
        return max(0, self.capacity - self.active)

    def metrics(self):
        return {'capacity': self.capacity, 'activeConnections': self.active,
                'rejectedConnections': self.rejected, 'availableSlots': self.available()}


class RuntimeService:
    def __init__(self, state_root, txn_root, peer_creds=True, allowed_uids=None,
                 max_concurrency=32, max_completed=4096, ledger_max_entries=0,
                 ledger_max_bytes=None, replay_protection_seconds=21600,
                 default_uid=None, observation_path=None, timeline_dir=None,
                 release_capabilities=None, auto_policy_path=None,
                 route_history_path=None, apply_spool_dir=None,
                 root_policy_projection_path=None, generation_file=None,
                 topology_path=None):
        self.state_root = Path(state_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.txn_root = Path(txn_root)
        self.state = RuntimeState(self.state_root / 'runtime-state.json', max_completed=max_completed,
                                  ledger_dir=self.state_root / 'closed-ledger',
                                  max_ledger_entries=ledger_max_entries,
                                  max_ledger_bytes=ledger_max_bytes,
                                  replay_protection_seconds=replay_protection_seconds)
        self.audit = AuditLog(self.state_root / 'audit')
        self.ops = OperationLog(self.state_root / 'operations', audit=self.audit, ledger=self.state.ledger)
        self.ops_report = self.ops.recover()
        # Safe observation timeline is host-owned and READ-ONLY to the Runtime.
        # The Runtime never appends to the journal; it only reads recent events.
        self.observation_path = Path(observation_path or DEFAULT_OBSERVATION_PATH)
        self.timeline_dir = Path(timeline_dir or DEFAULT_TIMELINE_DIR)
        # §P0-4: the secret-free route-topology projection, root-owned and
        # READ-ONLY to the Runtime (systemd ReadOnlyPaths on the status tree).
        # All topology/risk/ownership facts come from THIS projection; the
        # Runtime never opens the raw Xray config.
        self.topology_path = Path(topology_path or DEFAULT_TOPOLOGY_PATH)
        self.events = EventJournal(self.timeline_dir, read_only=True)
        self.txn = RootTransaction(self.txn_root, self.state_root / 'delivery',
                                   generation_file or DEFAULT_GENERATION_PATH)
        # READ-ONLY: the production Runtime runs with ReadOnlyPaths on the
        # root transaction area and must NEVER materialize, rewrite history
        # or restore root-owned managed files. Privileged recovery is a
        # host-owned helper responsibility; the Runtime only scans.
        self.txn_scan = self.txn.scan_recovery_state()
        self.recovery_required = any(r['recoveryRequired'] for r in self.txn_scan)
        self.recovery = {'unresolved': [r['workDir'] for r in self.txn_scan if r['recoveryRequired']],
                         'scanned': self.txn_scan, 'privilegedRecoveryRequired': self.recovery_required}
        self.delivery_file = self.state_root / 'delivery' / 'route-delivery.json'
        # Fail-closed ACL: explicit allowlist; open access only when the
        # caller explicitly opts in (tests) with allow_open=True semantics.
        self.allowed_uids = set(allowed_uids) if allowed_uids is not None else set()
        if default_uid is not None:
            self.allowed_uids.add(default_uid)
        self.acl = AccessControl(self.allowed_uids)
        # Release capability manifest: root-owned, runtime read-only. Effective
        # route assist / bounded auto availability is decided here, never by a
        # single persisted boolean. Tests inject a temporary object with
        # released=true to exercise the unlocked paths.
        self.release = release_capabilities if release_capabilities is not None else ReleaseCapabilities()
        # Bounded Auto policy: persistent cooldown / rate-limit / fuse state.
        # The Runtime only ever records through the release-gated executor path;
        # shadow evaluation never mutates this state.
        self.auto_policy = AutoPolicy(auto_policy_path or self.state_root / 'auto-policy.json')
        # Bounded, secret-free route plan/approval/reject/auto-status history.
        self.route_history = RouteHistory(route_history_path or self.state_root / 'route-history.jsonl')
        # Root executor apply spool. The Runtime builds an ApplyRequest and
        # writes it here ONLY when the release gate is open and policy allows;
        # the root-owned oneshot consumes it. In the locked production release
        # this is never written (routeApprove fails closed before this point).
        self.apply_spool_dir = Path(apply_spool_dir or '/var/spool/rill-xray-agent-apply')
        # Root-authoritative execution-policy projection (§12/§13/§16):
        # root-writable, runtime-READ-ONLY. The Runtime binds the CURRENT epoch
        # + policy snapshot digest into ApplyRequests and displays live status;
        # it never derives or persists execution authority itself.
        self.root_policy_projection_path = Path(
            root_policy_projection_path or DEFAULT_PROJECTION_PATH)
        self.queue = BoundedQueue(max_concurrency)
        self.sem = self.queue._sem
        self.access_log = self.state_root / 'access-log.jsonl'
        self.pool = ThreadPoolExecutor(max_workers=max_concurrency)
        self._stop = threading.Event()
        self._socket_path = None

    def _log_access(self, creds, method, ok):
        if self.access_log.exists() and self.access_log.stat().st_size > ACCESS_LOG_BYTES:
            self.access_log.rename(self.access_log.with_suffix('.old'))
        line = {'ts': int(time.time()), 'pid': creds[0] if creds else None,
                'uid': creds[1] if creds else None, 'gid': creds[2] if creds else None,
                'method': method, 'ok': ok}
        try:
            with self.access_log.open('a') as f:
                f.write(json.dumps(line, sort_keys=True) + '\n')
                os.fsync(f.fileno())
        except OSError:
            pass

    def _reject(self, c, rid, code, message):
        try:
            c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': rid, 'ok': False,
                                       'error': {'code': code, 'message': message[:256]}}) + b'\n')
        except OSError:
            pass
        finally:
            c.close()

    def _op(self, kind, state_fn, event_type, event_details, actor_type='system', actor_id='runtime'):
        def wrapped(loaded):
            if loaded is None:
                loaded = self.state.empty()
            return state_fn(loaded)
        return self.ops.execute(kind, self.state.path, wrapped, event_type, event_details, actor_type, actor_id)

    def _register_decision(self, decision_id, capability, generation, created,
                           actor_id='runtime'):
        """Unified, idempotent decision registration used by both the public
        `register` method and the diagnose flow. Registration is Runtime
        internal state mutation (never host mutation) and always passes
        through OperationLog -> AuditLog -> RuntimeState -> ClosedLedger."""
        def tx(s):
            ident = {'capability': capability, 'decisionId': decision_id,
                     'modelGeneration': int(generation),
                     'createdAtEpochSeconds': int(created)}
            existing = (s['pending'].get(decision_id) or s['completed'].get(decision_id))
            if existing:
                if existing.get('identity') == ident:
                    return {'status': 'idempotent'}, s
                raise ValueError('decision ID different identity')
            tomb = self.state.ledger.get(decision_id)
            if tomb:
                if tomb.get('corrupt'):
                    raise ValueError('closed ledger corrupt')
                if tomb['identityHash'] == digest(ident):
                    return {'status': 'idempotent'}, s
                raise ValueError('decision ID different identity')
            s['pending'][decision_id] = {'identity': ident, 'rootResult': None,
                                         'registeredAtEpochSeconds': int(time.time())}
            return {'status': 'registered'}, s
        return self._op('register', tx, 'decision.registered',
                        {'decisionId': decision_id}, actor_id=actor_id)

    def handle(self, e, peer_uid=None):
        rid = e.get('requestId') or str(uuid.uuid4())
        m = e.get('method')
        b = e.get('body') or {}
        try:
            if e.get('schemaVersion') != 3 or m not in ALLOWED:
                raise ValueError('invalid envelope/method')
            if m == 'health':
                r = health(self.state_root, self.txn_root, self.audit, self.ops, self.delivery_file)
            elif m == 'metrics':
                s = self.state.load()
                r = {'pending': len(s['pending']), 'completed': len(s['completed']),
                     'closed': self.state.ledger.count(), 'closedLedger': self.state.ledger.count(),
                     'activeOperations': self.ops.pending_count(), 'acl': self.acl.describe(),
                     'queue': self.queue.metrics(),
                     'recoveryRequired': self.recovery_required,
                     'rootTransactionsUnresolved': len(self.recovery['unresolved'])}
            elif m == 'mode':
                mode = b.get('mode')
                if mode not in {'normal', 'observe-only', 'safe-disabled'}:
                    raise ValueError('invalid mode')
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('mode requires privileged peer')

                def tx(s):
                    s['mode'] = mode
                    # Route assist / bounded auto are release-gated derived
                    # capabilities decided by the release manifest + RoutePolicy
                    # at evaluation time, never by this switch. The mode change
                    # must never resurrect an effective enablement; routeStage
                    # (a user preference) is preserved but its effective value
                    # stays observe while the production release gate is locked.
                    s['routeAssistEnabled'] = False
                    s['boundedAutoAllowed'] = False
                    return {'mode': mode, 'routeStage': s.get('routeStage', 'observe')}, s
                r = self._op('mode', tx, 'runtime.mode.changed', {'mode': mode}, actor_id=str(peer_uid))
            elif m == 'config':
                s = self.state.load()
                route = self._route_status(s)
                effective = self._effective_route(route)
                r = {'mode': s['mode'], 'routeStage': s.get('routeStage', 'observe'),
                     'routeAssistEnabled': effective['routeAssistEnabled'],
                     'boundedAutoAllowed': effective['boundedAutoAllowed'],
                     'routeStatus': route}
            elif m == 'register':
                did = b['decisionId']
                r = self._register_decision(
                    did, b['capability'], int(b['modelGeneration']),
                    int(b['createdAtEpochSeconds']), actor_id=str(peer_uid))
            elif m == 'rootResult':
                did = b['decisionId']
                projection = sanitize_root_result(b['result'])

                def tx(s):
                    p = s['pending'].get(did)
                    if not p:
                        raise ValueError('unknown pending decision')
                    if p.get('rootResult'):
                        if json.dumps(p['rootResult'], sort_keys=True) == json.dumps(projection, sort_keys=True):
                            return {'status': 'idempotent'}, s
                        raise ValueError('conflicting result')
                    p['rootResult'] = projection
                    return {'status': 'committed'}, s
                r = self._op('rootResult', tx, 'decision.root_result', {'decisionId': did})
            elif m == 'feedback':
                # P0-2: the state callback must NOT write the external ledger.
                # Eviction decides which tombstones to externalize and returns
                # them as pendingLedgerMutations; the Operation WAL applies them
                # after the intent and state are durable (runtime_state.feedback
                # is used only by the standalone state API, not this path).
                ledger_mutations = []

                def tx(s):
                    p = s['pending'].get(b['decisionId'])
                    c = s['completed'].get(b['decisionId'])
                    t = self.state.ledger.get(b['decisionId'])
                    # 10.2: feedback for a decision that was NEVER registered is
                    # rejected (fake/malicious). But a registered decision that
                    # was already completed or evicted to the closed ledger must
                    # still be replayed idempotently / conflict-detected.
                    if not (p or c or t):
                        raise UnknownDecisionError('feedback unknown decision')
                    # Resolve the canonical identity from the registered decision
                    # whenever possible (pending/completed carry the full
                    # identity). A closed (evicted) decision validates its
                    # replay against the tombstone identity metadata: the
                    # eviction persisted the safe capability/modelGeneration,
                    # so the same feedback produces the same payload hash and
                    # stays idempotent. Legacy tombstones without that metadata
                    # fall back to the client-supplied values as before.
                    if p:
                        ident = p['identity']
                    elif c:
                        ident = c['identity']
                    elif t:
                        ident = {'capability': t.get('capability') or b.get('capability'),
                                 'modelGeneration': t.get('modelGeneration', b.get('modelGeneration'))}
                    else:
                        ident = {'capability': b.get('capability'),
                                 'modelGeneration': b.get('modelGeneration')}
                    # The canonical identity lives with the registered decision:
                    # the client never re-constructs capability/generation.
                    # psha must also stay stable across client variants.
                    canonical = dict(b)
                    canonical['capability'] = ident['capability']
                    canonical['modelGeneration'] = int(ident['modelGeneration'] or 0)
                    psha = digest(canonical)
                    if c:
                        if c['payloadSha256'] == psha:
                            return {'status': 'idempotent', 'accepted': True}, s
                        raise ValueError('conflicting completed feedback')
                    if t:
                        if t.get('corrupt'):
                            raise ValueError('closed ledger corrupt')
                        if t['payloadHash'] == psha:
                            return {'status': 'idempotent', 'accepted': True}, s
                        raise ValueError('conflicting closed feedback')
                    if ident['capability'] == 'route' and not p.get('rootResult'):
                        raise ValueError('feedback before root result')
                    # Doctor feedback keeps its structured fields; generic
                    # payloads are still allowlist-projected.
                    if ident['capability'] == 'doctor':
                        payload_meta = sanitize_doctor_feedback(canonical)
                    else:
                        payload_meta = sanitize_payload(canonical)
                    s['completed'][b['decisionId']] = {'identity': ident, 'payloadMeta': payload_meta,
                                                       'payloadSha256': psha,
                                                       'acceptedAtEpochSeconds': int(time.time())}
                    del s['pending'][b['decisionId']]
                    while len(s['completed']) > self.state.max_completed:
                        evicted = sorted(s['completed'])[0]
                        e = s['completed'].pop(evicted)
                        ledger_mutations.append({
                            'type': 'putClosedDecision',
                            'decisionIdHash': digest(evicted),
                            'identityHash': digest(e['identity']),
                            'payloadHash': e['payloadSha256'],
                            'closedAtEpochSeconds': int(e['acceptedAtEpochSeconds']),
                            # P1-3: persist safe feedback identity metadata so
                            # exact feedback replay stays idempotent even after
                            # the decision is evicted to the closed ledger.
                            'capability': e['identity'].get('capability'),
                            'modelGeneration': e['identity'].get('modelGeneration'),
                        })
                    return {'status': 'accepted', 'accepted': True, 'pendingLedgerMutations': ledger_mutations}, s
                r = self._op('feedback', tx, 'decision.feedback', {'decisionId': b.get('decisionId')})
            elif m == 'inspect':
                s = self.state.load()
                did = b.get('decisionId')
                r = {'pending': s['pending'].get(did), 'completed': s['completed'].get(did),
                     'closed': self.state.ledger.get(did)}
            elif m == 'timeline':
                limit = int(b.get('limit') or 50)
                limit = max(1, min(limit, 200))
                if not self.timeline_dir.is_dir():
                    r = {'available': False, 'integrity': 'missing', 'events': []}
                else:
                    try:
                        events = self.events.read(limit=limit)
                    except EventJournalError:
                        # Never report corruption as an empty history: the
                        # operator must be able to distinguish 'no events'
                        # from 'history unreadable'.
                        r = {'available': False, 'integrity': 'corrupt', 'events': []}
                    else:
                        r = {'available': True, 'integrity': 'valid',
                             'events': [self._project_event(e) for e in events]}
            elif m == 'diagnose':
                # Advisory-only: requires a privileged/operator peer, but never
                # executes anything. Route Assist / bounded auto stay OFF.
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('diagnose requires privileged peer')
                obs = self._read_observation()
                recent = []
                timeline_status = 'missing'
                if self.timeline_dir.is_dir():
                    try:
                        recent = self.events.read(limit=MAX_DIAGNOSE_TIMELINE_EVENTS)
                    except EventJournalError:
                        timeline_status = 'corrupt'
                    else:
                        timeline_status = 'available'
                result = Doctor(observation=obs, events=recent,
                                health=self.health_status(),
                                timeline_status=timeline_status,
                                now=int(time.time())).diagnose()
                # Decision lifecycle: register the advisory doctor decision
                # (Runtime-internal mutation only) BEFORE returning. identity
                # is derived from evidence, so repeated diagnoses with the same
                # evidence are idempotent.
                evidence_epoch = (result.get('evidence') or {}).get(
                    'observationCapturedAtEpochSeconds') or 0
                self._register_decision(
                    result['diagnosisId'], 'doctor', result['engineGeneration'],
                    evidence_epoch, actor_id=str(peer_uid))
                r = result
            elif m == 'snapshot':
                s = self.state.load()
                r = self._snapshot(s)
            elif m == 'routeStatus':
                # Read-only route capability + policy evaluation. Effective
                # enablement comes from the release manifest + RoutePolicy; in
                # the locked production release this reports supported=true /
                # released=false / effectiveStage=observe.
                r = self._route_status()
            elif m == 'routeStage':
                # Set the user's route preference (observe | assist | auto).
                # Setting a preference never enables anything by itself: the
                # effective stage is decided by RoutePolicy against the release
                # gate. Auto additionally requires an explicit confirmation
                # (autoConfirm) before it can ever become effective.
                stage = b.get('stage')
                if stage not in ('observe', 'assist', 'auto'):
                    raise ValueError('invalid route stage')
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('routeStage requires privileged peer')

                def tx(s):
                    s['routeStage'] = stage
                    if stage == 'auto':
                        s['autoConfirmedAtEpochSeconds'] = None
                    return {'routeStage': s['routeStage']}, s
                r = self._op('routeStage', tx, 'route.stage.changed', {'stage': stage},
                             actor_id=str(peer_uid))
                # Surface the effective (release-gated) result, not just the
                # stored preference, so the caller sees the true state.
                r['effective'] = self._route_status()['effectiveStage']
            elif m == 'routePlan':
                # Deterministic shadow planning. Never mutates the host: in the
                # locked release this returns canApply=false /
                # blockedBy=feature_not_released. The plan is recorded in the
                # secret-free route history so shadow evidence accumulates.
                status = self._route_status()
                if not status['canPlan']:
                    raise ValueError('route planning not available')
                topology = self._current_topology()
                # §P0-4: fail closed when the root-owned route-topology
                # projection is unavailable. The Runtime never synthesizes a
                # config hash (that would require reading the raw config it
                # must not see); with no projection no plan gate can be
                # proven, so no plan may be produced.
                if not topology.get('wholeConfigSha256'):
                    err = ValueError('route topology projection unavailable (fail closed)')
                    err.code = 'topology_unavailable'
                    raise err
                planner = RoutePlanner(topology, routing=self._routing_rules())
                plan = planner.plan(operations=b.get('operations') or [])
                meta = sanitize_route_plan_meta(plan)
                try:
                    self.route_history.append({
                        'id': 'plan:' + plan['recommendationId'],
                        'eventType': 'plan', 'createdAtEpochSeconds': plan['createdAtEpochSeconds'],
                        'expiresAtEpochSeconds': plan['expiresAtEpochSeconds'],
                        **meta,
                    })
                except ValueError:
                    pass
                # Policy decides what the plan MAY do (§P0-1): the CONCRETE
                # evaluation derives the plan gates from the actual plan body
                # and the CURRENT root-authoritative state, so a real plan is
                # never deadlocked by a capability-level status that holds no
                # plan. In the locked release this still reports canApply=false
                # with blockedBy=[feature_not_released].
                decision = self._concrete_route_eval(
                    plan, apply_type='manual', operations=plan.get('operations'))
                r = {'plan': plan, 'canApply': decision['canManualApply'],
                     'canAutoApply': decision['canAutoApply'],
                     'shadowWouldApply': decision['shadowWouldApply'],
                     'blockedBy': decision['blockedBy'],
                     'released': status['released'],
                     'effectiveStage': decision['effectiveStage']}
            elif m == 'routeApprove':
                # Full manual-approval contract. In the locked production
                # release this fails closed before any host mutation: the
                # decision is recorded (applied=false, wouldReject=true) and
                # no ApplyRequest ever reaches the root executor spool.
                rid = b.get('recommendationId')
                if not isinstance(rid, str) or not rid:
                    raise ValueError('invalid recommendationId')
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('routeApprove requires privileged peer')
                plan = self._history_plan(rid)
                if plan is None:
                    raise ValueError('unknown recommendation')
                status = self._route_status()
                r = self._route_approve(rid, b.get('operations') or [],
                                        plan, status, peer_uid)
            elif m == 'routeReject':
                # Structured rejection decision recorded in history. Never
                # mutates the host; the plan simply is not applied.
                rid = b.get('recommendationId')
                if not isinstance(rid, str) or not rid:
                    raise ValueError('invalid recommendationId')
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('routeReject requires privileged peer')
                plan = self._history_plan(rid)
                if plan is None:
                    raise ValueError('unknown recommendation')
                self.route_history.append({
                    'id': 'reject:' + rid + ':' + str(uuid.uuid4())[:8],
                    'eventType': 'reject', 'recommendationId': rid,
                    'createdAtEpochSeconds': int(time.time()),
                    'rejectReasonCode': b.get('reasonCode') or 'operator-rejected',
                    'mode': self.state.load()['mode'],
                    'releaseReleased': self.release.is_released('routeAssist'),
                })
                r = {'recommendationId': rid, 'rejected': True}
            elif m == 'routeHistory':
                # Read-only, bounded, secret-free plan/decision history.
                limit = int(b.get('limit') or 50)
                limit = max(1, min(limit, 200))
                r = {'entries': self.route_history.read(limit=limit)}
            elif m == 'autoStatus':
                # Bounded Auto status: release-gated reachability + policy
                # snapshot + wouldAutoApply decision. Read-only.
                r = self._auto_status()
            elif m == 'autoConfirm':
                # Explicit human confirmation of auto intent / fuse reset.
                # This is the ONLY way a stale auto preference can become
                # effective when a future release opens the gate, and the only
                # way to re-arm auto after a rollback fuse.
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('autoConfirm requires privileged peer')
                s = self.state.load()
                stage = s.get('routeStage', 'observe')
                if stage != 'auto':
                    raise ValueError('auto confirm requires routeStage=auto')

                def tx(st):
                    st['autoConfirmedAtEpochSeconds'] = int(time.time())
                    return {'autoConfirmedAtEpochSeconds': st['autoConfirmedAtEpochSeconds']}, st
                r = self._op('autoConfirm', tx, 'auto.confirmed', {'stage': stage},
                             actor_id=str(peer_uid))
                # Also acknowledge an open fuse so auto can be re-armed.
                if self.auto_policy.snapshot().get('fuseOpen'):
                    self.auto_policy.acknowledge_fuse(True)
                r['fuseAcknowledged'] = self.auto_policy.snapshot().get('fuseAcknowledged')
            elif m == 'autoProduce':
                # Real Bounded-Auto producer (§P0-2/§P0-12): Analyzer ->
                # Planner -> auto policy -> ApplyRequest(applyType=auto) ->
                # spool. In the locked release this fails closed
                # (feature_not_released) and never writes the spool.
                if not self.acl.write_permitted(peer_uid):
                    raise ValueError('autoProduce requires privileged peer')
                r = self._auto_produce(peer_uid)
            else:
                r = self.state.load()
            return {'schemaVersion': 3, 'requestId': rid, 'ok': True, 'result': r}
        except Exception as x:
            code = 'contractViolation'
            if isinstance(x, RootResultViolation):
                code = 'rootResultViolation'
            elif getattr(x, 'code', None):
                code = x.code
            return {'schemaVersion': 3, 'requestId': rid, 'ok': False,
                    'error': {'code': code, 'message': str(x)[:512]}}

    def _snapshot(self, s):
        """Safe projection: hashes and counts only, never raw bodies."""
        pending = {}
        for did, v in s['pending'].items():
            pending[did] = {
                'identityHash': digest(v.get('identity')),
                'rootResultPresent': v.get('rootResult') is not None,
                'registeredAtEpochSeconds': v.get('registeredAtEpochSeconds'),
            }
        completed = {}
        for did, v in s['completed'].items():
            completed[did] = {
                'identityHash': digest(v.get('identity')),
                'payloadSha256': v.get('payloadSha256'),
                'acceptedAtEpochSeconds': v.get('acceptedAtEpochSeconds'),
            }
        closed = self.state.ledger.entries()
        route = self._route_status(s)
        effective = self._effective_route(route)
        return {
            'mode': s['mode'],
            'routeStage': s.get('routeStage', 'observe'),
            'routeAssistEnabled': effective['routeAssistEnabled'],
            'boundedAutoAllowed': effective['boundedAutoAllowed'],
            'routeStatus': route,
            'schemaVersion': s['schemaVersion'],
            'restartCount': s['restartCount'],
            'pendingCount': len(s['pending']),
            'completedCount': len(s['completed']),
            'closedCount': len(closed),
            'pending': pending,
            'completed': completed,
            'closed': closed,
            'health': self.health_status(),
        }

    def _observation_status(self):
        obs = self._read_observation()
        if not isinstance(obs, dict):
            return {'present': False, 'fresh': False, 'integrityValid': False}
        captured = obs.get('capturedAtEpochSeconds')
        fresh = (isinstance(captured, int)
                 and 0 <= (int(time.time()) - captured) <= OBSERVATION_FRESHNESS_SECONDS)
        return {'present': True, 'fresh': fresh, 'integrityValid': True}

    def _timeline_status(self):
        if not self.timeline_dir.is_dir():
            return {'integrityValid': False, 'status': 'missing'}
        try:
            self.events.read(limit=1)
        except EventJournalError:
            return {'integrityValid': False, 'status': 'corrupt'}
        return {'integrityValid': True, 'status': 'valid'}

    def _route_status(self, s=None):
        """Unified, read-only route capability + policy evaluation.

        Effective enablement is decided by the release manifest
        (ReleaseCapabilities) and RoutePolicy, never by a single persisted
        boolean. In the production locked release this reports
        supported=true / released=false / effectiveStage=observe, so no host
        mutation is reachable; shadow evaluation is still available.
        """
        s = s or self.state.load()
        obs = self._observation_status()
        tl = self._timeline_status()
        # §P0-2: the capability display prefers the ROOT-owned execution-policy
        # projection (the SAME source the concrete execution path uses); it
        # falls back to Runtime-local state only for legacy / early-boot
        # display. This surface is never an execution authority.
        gates = self._root_policy_gates(need_auto=False)
        if gates is not None:
            mode = gates['mode']
            configured_stage = gates['routeStage']
        else:
            mode = s['mode']
            configured_stage = s.get('routeStage', 'observe')
        policy = RoutePolicy(
            mode=mode,
            configured_stage=configured_stage,
            release_capabilities=self.release,
            health=self.health_status(),
            recovery_required=self.recovery_required,
            observation_fresh=obs['fresh'],
            observation_integrity_valid=obs['integrityValid'],
            timeline_integrity_valid=tl['integrityValid'],
        )
        d = policy.evaluate()
        return {
            'supported': self.release.is_supported('routeAssist') or self.release.is_supported('boundedAuto'),
            'released': self.release.is_released('routeAssist') or self.release.is_released('boundedAuto'),
            'routeAssist': {'supported': self.release.is_supported('routeAssist'),
                            'released': self.release.is_released('routeAssist')},
            'boundedAuto': {'supported': self.release.is_supported('boundedAuto'),
                            'released': self.release.is_released('boundedAuto')},
            'configuredStage': configured_stage,
            'effectiveStage': d['effectiveStage'],
            'canPlan': d['canPlan'],
            'canManualApprove': d['canManualApprove'],
            'canManualApply': d['canManualApply'],
            'canAutoApply': d['canAutoApply'],
            'shadowEnabled': True,
            'shadowWouldApply': d['shadowWouldApply'],
            'blockedBy': d['blockedBy'],
            'mode': mode,
        }

    def _effective_route(self, status=None):
        """Derived, release-gated effective enablement flags (never stored)."""
        status = status if status is not None else self._route_status()
        ra = status['routeAssist']
        ba = status['boundedAuto']
        return {
            'routeAssistEnabled': status['effectiveStage'] in ('assist', 'auto') and ra['released'],
            'boundedAutoAllowed': status['effectiveStage'] == 'auto' and ba['released'],
        }

    def _read_topology(self):
        """Read the root-owned route-topology projection (READ-ONLY, §P0-4).

        The Runtime never reads the raw Xray config; all topology / risk /
        ownership / index facts come from this secret-free projection produced
        by the root observer. read_json rejects symlinks and non-regular
        files. A missing / corrupt / malformed projection returns None so
        callers fail closed (empty topology, no plan gates proven).
        """
        try:
            data = read_json(self.topology_path)
        except (ValueError, OSError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get('rules'), list):
            return None
        return data

    def _empty_topology(self):
        return {'schemaVersion': 2, 'capturedAtEpochSeconds': int(time.time()),
                'configurationGeneration': 0, 'wholeConfigSha256': '',
                'wholeConfigSafeDigest': '', 'routingRulesCount': 0, 'rules': []}

    def _current_topology(self):
        """Return the current safe route-topology projection (§P0-4).

        The projection is produced by the ROOT observer (which alone reads the
        root-owned Xray config) and consumed read-only here. It is returned
        as-is so the planner's topologySha256 binds the same projection the
        analyzer/observer produced. When the projection is unavailable (first
        run, observer not yet fired) returns an empty topology so shadow
        planning fails closed instead of reading raw config.
        """
        proj = self._read_topology()
        if proj is None:
            return self._empty_topology()
        return proj

    def _routing_rules(self):
        """Return the SAFE projected rules dict from the route-topology
        projection (§P0-4). The Runtime never reads the raw config: risk /
        ownership / index precondition evaluation uses the secret-free
        projected rules (selector types + digests), which the route contract
        already understands (see rule_selector_type)."""
        proj = self._read_topology()
        if proj is None:
            return {}
        return {'rules': proj.get('rules') or []}

    def _history_plan(self, recommendation_id):
        """Look up a plan from the route history by recommendationId."""
        if not isinstance(recommendation_id, str) or not recommendation_id:
            return None
        entry = self.route_history.get('plan:' + recommendation_id)
        if entry is None:
            return None
        return entry

    def _read_root_policy(self):
        """Read the root-owned execution-policy projection (READ-ONLY).

        Returns the full projection dict (top level carries schemaVersion and
        policySnapshotDigest; the inner 'policy' object carries the live
        executionEpoch / mode / routeStage), or None on any anomaly (fail
        closed): a missing / corrupt / unsafe projection means the Runtime
        cannot bind a valid execution epoch, so no ApplyRequest may be
        produced. read_json rejects symlinks and non-regular files.
        """
        try:
            data = read_json(self.root_policy_projection_path)
        except (ValueError, OSError):
            return None
        if not isinstance(data, dict):
            return None
        policy = data.get('policy')
        if not isinstance(policy, dict):
            return None
        return data

    def _root_policy_gates(self, need_auto=False):
        """§P0-2: Extract execution gates from the root-owned projection.

        Returns a dict with 'mode', 'routeStage', 'executionEpoch' (and when
        need_auto=True also 'autoConfirmed', 'fusibleOpen', 'rateLimitOk',
        'cooldownOk', plus the raw auto-ledger scalars for display), or None
        when the projection is unavailable / corrupt (fail closed). The
        Runtime MUST use this as the single authority for all execution
        decisions; RuntimeState and Runtime-local AutoPolicy are never the
        final authority.
        """
        data = self._read_root_policy()
        if data is None:
            return None
        policy = data.get('policy')
        if not isinstance(policy, dict):
            return None
        mode = policy.get('mode')
        route_stage = policy.get('routeStage')
        if mode not in ('normal', 'observe-only', 'safe-disabled'):
            return None
        if route_stage not in ('observe', 'assist', 'auto', 'disabled'):
            return None
        epoch = policy.get('executionEpoch')
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            return None
        result = {'mode': mode, 'routeStage': route_stage, 'executionEpoch': epoch}
        if need_auto:
            try:
                auto_confirmed = bool(policy.get('autoConfirmed', False))
                fuse_open = bool(policy.get('fuseOpen', False))
                fuse_ack = bool(policy.get('fuseAcknowledged', False))
                max_per_hour = int(policy.get('maxAutoMutationsPerHour') or 0)
                mutations_last_hour = int(policy.get('autoMutationsLastHour') or 0)
                cooldown = int(policy.get('globalCooldownRemainingSeconds') or 0)
                consec_rollbacks = int(policy.get('consecutiveRollbacks') or 0)
                fuse_limit = int(policy.get('consecutiveRollbackFuseLimit') or 0)
                last_auto = int(policy.get('lastAutoAtEpochSeconds') or 0)
            except (TypeError, ValueError):
                return None
            # Mirrors the root auto ledger: the cap is authoritative and a
            # missing / zero cap fails closed (never widens the window).
            result['autoConfirmed'] = auto_confirmed
            result['fusibleOpen'] = not fuse_open
            result['fuseOpen'] = fuse_open
            result['fuseAcknowledged'] = fuse_ack
            result['rateLimitOk'] = mutations_last_hour < max_per_hour
            result['cooldownOk'] = cooldown <= 0
            result['autoMutationsLastHour'] = mutations_last_hour
            result['maxAutoMutationsPerHour'] = max_per_hour
            result['globalCooldownRemainingSeconds'] = cooldown
            result['consecutiveRollbacks'] = consec_rollbacks
            result['consecutiveRollbackFuseLimit'] = fuse_limit
            result['lastAutoAtEpochSeconds'] = last_auto
        return result

    def _concrete_route_eval(self, plan, apply_type='manual', operations=None):
        """Concrete RoutePlan policy evaluation (§P0-1/§P0-2).

        _route_status() / RoutePolicy.evaluate() are CAPABILITY-level: without
        a concrete plan they must report canManualApply/canAutoApply=False
        (the plan gates are unproven). This method is the CONCRETE evaluation:
        it derives the plan-specific gates (valid / not-expired / generation
        match / config-hash match / execution-epoch match) from the actual
        plan body and the CURRENT root-authoritative state, so a real plan is
        never deadlocked by its own absence. §P0-2: every execution gate is
        sourced EXCLUSIVELY from the root execution-policy projection; a
        missing / corrupt / unsafe projection fails closed with
        root_policy_unavailable. The root executor still re-validates every
        condition against the live root policy and the live managed config
        (§16/§19); a pass here only means "submittable", never final
        permission.
        """
        obs = self._observation_status()
        tl = self._timeline_status()
        # §P0-2: ALL execution gates (mode, routeStage, executionEpoch,
        # autoConfirmed, fuse, rate, cooldown) come EXCLUSIVELY from the ROOT
        # execution-policy projection. RuntimeState and Runtime-local
        # AutoPolicy are never the execution authority; a missing / corrupt /
        # unsafe projection fails closed with root_policy_unavailable.
        gates = self._root_policy_gates(need_auto=True)
        if gates is None:
            return {
                'canPlan': False, 'canManualApprove': False, 'canManualApply': False,
                'canAutoApply': False, 'shadowWouldApply': False,
                'effectiveStage': 'observe', 'blockedBy': ['root_policy_unavailable'],
            }
        # §P0-4: config hash / generation / rules all come from the root-owned
        # route-topology projection (READ-ONLY), never from the raw config.
        proj = self._read_topology()
        if proj is None:
            current_config_sha = ''
            current_generation = 0
            rules = []
        else:
            current_config_sha = (proj.get('wholeConfigSha256')
                                  or proj.get('wholeConfigSafeDigest') or '')
            current_generation = int(proj.get('configurationGeneration') or 0)
            rules = proj.get('rules') or []
        # §19: auto risk/op-allowlist are recomputed from the SAFE projected
        # rules (mirrors the root executor, which recomputes from the live raw
        # rules); never trusted from a request-declared label.
        ops = operations if isinstance(operations, list) else []
        risk_auto_eligible = overall_risk(ops, rules) == 'low'
        auto_allowlisted_op = bool(ops) and all(
            isinstance(o, dict) and o.get('op') in AUTO_ROUTE_OPS for o in ops)
        return evaluate_plan_policy(
            plan, apply_type=apply_type, mode=gates['mode'],
            configured_stage=gates['routeStage'],
            release_capabilities=self.release, health=self.health_status(),
            recovery_required=self.recovery_required,
            observation_fresh=obs['fresh'],
            observation_integrity_valid=obs['integrityValid'],
            timeline_integrity_valid=tl['integrityValid'],
            current_generation=current_generation,
            current_config_sha256=current_config_sha,
            current_execution_epoch=gates['executionEpoch'],
            auto_confirmed=gates['autoConfirmed'],
            risk_auto_eligible=risk_auto_eligible,
            auto_allowlisted_op=auto_allowlisted_op,
            fusible_open=gates['fusibleOpen'],
            rate_limit_ok=gates['rateLimitOk'],
            cooldown_ok=gates['cooldownOk'],
        )

    def _route_approve(self, rid, operations, plan, status, peer_uid):
        """Manual approval contract. Fail-closed when release gate is locked.

        The operator supplies the operations they want to approve. They are
        canonicalized through the SAME typed/allowlisted path as the planner,
        and must reproduce the plan's recorded operationsDigest exactly,
        otherwise the approval is rejected (operations_digest_mismatch). This
        binds the ApplyRequest to the exact plan that was planned.
        """
        now = int(time.time())
        # Canonicalize + digest-bind the supplied operations to the plan.
        try:
            canonical_ops = RoutePlanner.canonicalize_operations(operations)
            ops_ok = digest({'operations': canonical_ops}) == plan.get('operationsDigest')
        except ValueError:
            canonical_ops, ops_ok = [], False
        if not ops_ok:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['operations_digest_mismatch'])
        if isinstance(plan.get('expiresAtEpochSeconds'), int) and now > plan['expiresAtEpochSeconds']:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['plan_expired'])
        # Concrete policy evaluation (§P0-1): the plan-specific gates are
        # derived from the actual plan body + the CURRENT root-authoritative
        # state, so a real plan is never deadlocked by a capability-level
        # status that holds no plan. In the locked production release this
        # still fails closed with feature_not_released before any mutation.
        decision = self._concrete_route_eval(plan, apply_type='manual',
                                             operations=canonical_ops)
        if not decision['canManualApply']:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=decision['blockedBy'])
        # Release gate is open: bind the request to the CURRENT root-owned
        # execution policy (§12/§13). If the root projection is unavailable or
        # unsafe the Runtime fails closed: it cannot produce a validly-bound
        # ApplyRequest. The root executor re-validates epoch + snapshot digest
        # against the live root policy anyway; nothing here is trusted as the
        # final authority.
        root_policy = self._read_root_policy()
        if root_policy is None:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        execution_epoch = root_policy.get('policy', {}).get('executionEpoch')
        if not isinstance(execution_epoch, int) or isinstance(execution_epoch, bool) \
                or execution_epoch < 0:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        policy_snapshot_digest = root_policy.get('policySnapshotDigest')
        if not isinstance(policy_snapshot_digest, str) or not policy_snapshot_digest:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        self._spool_apply_request(rid, plan, canonical_ops, 'manual', decision,
                                  status, execution_epoch, policy_snapshot_digest)
        return self._record_approval(
            rid, now, plan, applied=True, blocked=[], release_gate_open=True)

    def _spool_apply_request(self, rid, plan, canonical_ops, apply_type, decision,
                             status, execution_epoch, policy_snapshot_digest):
        """Build an ApplyRequest bound to the CURRENT root-owned execution
        policy and write it atomically to the apply spool for the root oneshot
        executor. Shared by the manual approval path and the Bounded-Auto
        producer. The root executor re-validates epoch + snapshot digest
        against the live root policy anyway; nothing here is final authority.
        """
        now = int(time.time())
        apply_request = {
            'schemaVersion': 2,
            'recommendationId': rid,
            'createdAtEpochSeconds': now,
            'expiresAtEpochSeconds': now + 300,
            'configurationGeneration': plan.get('configurationGeneration') or 0,
            'executionEpoch': execution_epoch,
            'sourceConfigSha256': plan.get('sourceConfigSha256', ''),
            'planSha256': plan.get('planSha256', ''),
            'recommendationType': plan.get('recommendationType') or 'no-recommendation',
            'semanticFingerprint': (plan.get('semanticFingerprint')
                                    or plan.get('recommendationId') or rid),
            'policySnapshotDigest': policy_snapshot_digest,
            'applyType': apply_type,
            'mode': 'normal',
            'effectiveStage': decision['effectiveStage'],
            'releaseSnapshot': {
                'routeAssist': {'supported': status['routeAssist']['supported'],
                                'released': status['routeAssist']['released']},
                'boundedAuto': {'supported': status['boundedAuto']['supported'],
                                'released': status['boundedAuto']['released']},
            },
            'operations': canonical_ops,
            'requestSha256': '',
        }
        apply_request['requestSha256'] = request_digest(apply_request)
        # Write to the spool directory atomically.
        self.apply_spool_dir.mkdir(parents=True, exist_ok=True)
        spool_path = self.apply_spool_dir / 'apply.json'
        atomic_write_json(spool_path, apply_request, 0o640)
        return apply_request

    def _auto_produce(self, peer_uid):
        """Real Bounded-Auto producer (§P0-2/§P0-12).

        Analyzer -> Planner -> auto policy -> ApplyRequest(applyType=auto) ->
        spool. The Runtime consumes ONLY the root-owned safe route-topology
        projection, which carries the root-authoritative managed-route intent;
        it never reads the raw Xray config and never invents a selector. The
        analyzer classifies, the planner turns the Rill-owned intent into
        typed low-risk ops, and the CONCRETE auto evaluation decides
        submittability. The root executor independently recomputes every
        condition against the live root policy / live config; a pass here only
        means "submittable", never final permission.
        """
        now = int(time.time())
        topology = self._current_topology()
        # §P0-4: fail closed when the root-owned route-topology projection is
        # unavailable. The Runtime never synthesizes a config hash; with no
        # projection no plan gate can be proven, so no auto request may be
        # produced.
        if not topology.get('wholeConfigSha256'):
            err = ValueError('route topology projection unavailable (fail closed)')
            err.code = 'topology_unavailable'
            raise err
        intent = topology.get('managedRouteIntent') or {}
        analyzer = RouteAnalyzer(topology, intent=intent)
        rec = analyzer.analyze()
        rid = rec.get('recommendationId')
        if not auto_eligible(rec):
            return {'recommendationId': rid, 'produced': False, 'applyType': None,
                    'blockedBy': ['auto_not_eligible'],
                    'recommendationType': rec.get('recommendationType'),
                    'reasonCode': rec.get('reasonCode')}
        planner = RoutePlanner(topology, routing=self._routing_rules())
        actionable, reason, ops = planner.operations_from_recommendation(rec)
        if not actionable:
            # §P0-2: never "build an operation to be done". A recommendation
            # that lacks enough safe intent is advisory-only, never a fake
            # auto operation.
            return {'recommendationId': rid, 'produced': False, 'applyType': None,
                    'blockedBy': ['insufficient-safe-intent'],
                    'recommendationType': rec.get('recommendationType'),
                    'reasonCode': reason}
        plan = planner.plan(operations=ops, recommendation=rec)
        rid = plan['recommendationId']
        meta = sanitize_route_plan_meta(plan)
        try:
            self.route_history.append({
                'id': 'plan:' + rid,
                'eventType': 'plan',
                'createdAtEpochSeconds': plan['createdAtEpochSeconds'],
                'expiresAtEpochSeconds': plan['expiresAtEpochSeconds'],
                **meta,
            })
        except ValueError:
            pass
        status = self._route_status()
        decision = self._concrete_route_eval(plan, apply_type='auto',
                                             operations=ops)
        if not decision['canAutoApply']:
            return self._record_approval(rid, now, plan, applied=False,
                                         blocked=decision['blockedBy'])
        root_policy = self._read_root_policy()
        if root_policy is None:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        execution_epoch = root_policy.get('policy', {}).get('executionEpoch')
        if not isinstance(execution_epoch, int) or isinstance(execution_epoch, bool) \
                or execution_epoch < 0:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        policy_snapshot_digest = root_policy.get('policySnapshotDigest')
        if not isinstance(policy_snapshot_digest, str) or not policy_snapshot_digest:
            return self._record_approval(
                rid, now, plan, applied=False, blocked=['root_policy_unavailable'])
        self._spool_apply_request(rid, plan, ops, 'auto', decision, status,
                                  execution_epoch, policy_snapshot_digest)
        return self._record_approval(rid, now, plan, applied=True, blocked=[],
                                     release_gate_open=True)

    def _record_approval(self, rid, now, plan, applied, blocked, release_gate_open=False):
        """Record an approval decision in the secret-free route history and
        return the structured approval response."""
        self.route_history.append({
            'id': 'approve:' + rid + ':' + str(uuid.uuid4())[:8],
            'eventType': 'approve', 'recommendationId': rid,
            'createdAtEpochSeconds': now, 'applied': applied,
            'wouldReject': not applied, 'blockedBy': blocked,
            'mode': self.state.load()['mode'],
            'releaseReleased': self.release.is_released('routeAssist'),
        })
        return {'recommendationId': rid, 'applied': applied,
                'wouldReject': not applied, 'blockedBy': blocked,
                'releaseGateOpen': release_gate_open}

    def _auto_status(self):
        """Bounded Auto status: release-gated reachability + policy snapshot.

        §P0-2: the authoritative auto gating state (autoConfirmed, fuse, rate,
        cooldown) is displayed from the ROOT execution-policy projection.
        Runtime-local AutoPolicy / RuntimeState auto preference are only a
        legacy fallback for early-boot / historical display and never the
        execution authority.
        """
        status = self._route_status()
        gates = self._root_policy_gates(need_auto=True)
        if gates is not None:
            auto_confirmed = gates['autoConfirmed']
            policy_snapshot = {
                'integrity': 'valid',
                'corruptReason': None,
                'fuseOpen': gates['fuseOpen'],
                'fuseAcknowledged': gates['fuseAcknowledged'],
                'consecutiveRollbacks': gates['consecutiveRollbacks'],
                'consecutiveRollbackFuseLimit': gates['consecutiveRollbackFuseLimit'],
                'autoMutationsLastHour': gates['autoMutationsLastHour'],
                'maxAutoMutationsPerHour': gates['maxAutoMutationsPerHour'],
                'globalCooldownRemainingSeconds': gates['globalCooldownRemainingSeconds'],
            }
        else:
            s = self.state.load()
            auto_confirmed = isinstance(s.get('autoConfirmedAtEpochSeconds'), int)
            policy_snapshot = self.auto_policy.snapshot()
        # Determine whether auto is reachable (release gate + configuration).
        ba = status['boundedAuto']
        auto_reachable = (ba['released']
                          and status['configuredStage'] == 'auto'
                          and auto_confirmed)
        # Shadow would-apply decision (never mutates the host).
        if auto_reachable and status['canPlan']:
            allowed, blocked = self.auto_policy.evaluate('shadow')
            would_auto_apply = allowed
            shadow_blocked = blocked
        else:
            would_auto_apply = False
            shadow_blocked = status['blockedBy']
        return {
            'boundedAuto': ba,
            'configuredStage': status['configuredStage'],
            'effectiveStage': status['effectiveStage'],
            'autoConfirmed': auto_confirmed,
            'autoReachable': auto_reachable,
            'wouldAutoApply': would_auto_apply,
            'shadowBlockedBy': shadow_blocked,
            'policyIntegrity': policy_snapshot['integrity'],
            'policyCorruptReason': policy_snapshot['corruptReason'],
            'fuseOpen': policy_snapshot['fuseOpen'],
            'fuseAcknowledged': policy_snapshot['fuseAcknowledged'],
            'consecutiveRollbacks': policy_snapshot['consecutiveRollbacks'],
            'consecutiveRollbackFuseLimit': policy_snapshot['consecutiveRollbackFuseLimit'],
            'autoMutationsLastHour': policy_snapshot['autoMutationsLastHour'],
            'maxAutoMutationsPerHour': policy_snapshot['maxAutoMutationsPerHour'],
            'globalCooldownRemainingSeconds': policy_snapshot['globalCooldownRemainingSeconds'],
        }

    def _project_event(self, e):
        """Project an event to safe scalar fields only (never raw bodies)."""
        return {
            'sequence': e.get('sequence'),
            'eventId': e.get('eventId'),
            'eventType': e.get('eventType'),
            'component': e.get('component'),
            'capturedAtEpochSeconds': e.get('capturedAtEpochSeconds'),
            'facts': e.get('facts') or {},
        }

    def _read_observation(self):
        """Read the latest safe observation (read-only). Missing/symlink -> None."""
        try:
            return read_json(self.observation_path)
        except (ValueError, OSError):
            return None

    def health_status(self):
        try:
            h = health(self.state_root, self.txn_root, self.audit, self.ops, self.delivery_file)
        except Exception:
            h = {'status': 'recovery-required', 'reasons': ['health_unavailable'],
                 'canObserve': True, 'canRecommend': False, 'canApply': False,
                 'rootTransactions': {}}
        if self.recovery_required and h.get('status') != 'recovery-required':
            h = {**h, 'status': 'recovery-required',
                 'reasons': (h.get('reasons') or []) + ['privileged_host_recovery_required'],
                 'canRecommend': False, 'canApply': False}
        elif h.get('status') == 'recovery-required':
            h = {**h, 'canRecommend': False, 'canApply': False}
        return h

    def client(self, c):
        c.settimeout(5)
        creds = peer_credentials(c)
        rid = 'unknown'
        try:
            try:
                d = b''
                while b'\n' not in d and len(d) <= MAX_FRAME_BYTES:
                    x = c.recv(65536)
                    if not x:
                        break
                    d += x
                if len(d) > MAX_FRAME_BYTES:
                    raise ValueError('too large')
                envelope = json.loads(d.split(b'\n', 1)[0])
                rid = envelope.get('requestId') or rid
                if not self.acl.authorize(creds):
                    self._log_access(creds, envelope.get('method'), False)
                    self._reject(c, rid, 'forbiddenPeer', 'peer uid not allowed')
                    return
                out = self.handle(envelope, peer_uid=(creds[1] if creds else None))
                self._log_access(creds, envelope.get('method'), bool(out.get('ok')))
                c.sendall(canonical_bytes(out) + b'\n')
            finally:
                self.queue.release()
        except Exception as x:
            self._log_access(creds, None, False)
            try:
                c.sendall(canonical_bytes({'schemaVersion': 3, 'requestId': rid, 'ok': False,
                                           'error': {'code': 'transportError', 'message': str(x)[:256]}}) + b'\n')
            except Exception:
                pass
        finally:
            c.close()

    def stop(self):
        self._stop.set()
        if self._socket_path:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                    wake.settimeout(.2)
                    wake.connect(str(self._socket_path))
            except Exception:
                pass

    def serve(self, path):
        path = Path(path)
        self._socket_path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.unlink(missing_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(path))
        os.chmod(path, 0o660)
        s.listen(32)
        s.settimeout(1)
        try:
            while not self._stop.is_set():
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                if self._stop.is_set():
                    # Shutdown raced with an accepted connection: close it
                    # rather than stranding it in a cancelled future.
                    c.close()
                    break
                if not self.queue.acquire():
                    self._reject(c, 'unknown', 'serverBusy', 'concurrency limit reached')
                    continue
                try:
                    self.pool.submit(self.client, c)
                except Exception:
                    self.queue.release()
                    c.close()
        finally:
            s.close()
            # Drain every submitted client so no accepted connection is dropped
            # open. client() always closes its socket, so there is no leak; a
            # peer that connects but never sends is bounded by the socket
            # timeout. Never cancel_futures here: a cancelled client future
            # would strand its connection open (Unix socket ResourceWarning).
            self.pool.shutdown(wait=True)
            path.unlink(missing_ok=True)
            self._socket_path = None


def time_now():
    import time
    return int(time.time())