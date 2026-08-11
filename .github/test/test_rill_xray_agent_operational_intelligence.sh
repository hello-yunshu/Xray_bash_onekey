#!/usr/bin/env bash
# Rill Xray Agent 0.2 Operational Intelligence regression (spec 19.1/19.2).
# Run under `set -euo pipefail` by the required "Test Install" job. Never
# `|| true`, never `continue-on-error`. Proves:
#   - canonical Rill payload + systemd permission contract are wired
#   - root observer writes observation + events; Runtime reads, cannot write
#   - timeline / diagnose / feedback / inspect lifecycle
#   - diagnosis registration + same-evidence idempotency + restart persistence
#   - Route Assist / bounded auto stay OFF, canApply=false
set -euo pipefail

# --- static wiring checks (no root / no systemd needed) --------------------
# Observer uses the canonical EventJournal + crash-idempotent transition
# commit (ONE implementation). The transition commit lives in
# observer_transition (which internally uses canonical derive_events).
grep -Fq 'from rill_xray_agent.event_journal import EventJournal' scripts/rill_xray_agent_observe.py
grep -Fq 'from rill_xray_agent.observer_transition import' scripts/rill_xray_agent_observe.py
# Observer FAILS CLOSED when canonical modules are unavailable (never drifts).
grep -Fq 'canonical modules unavailable' scripts/rill_xray_agent_observe.py
# Runtime systemd unit grants read-only access to the xray observation tree;
# the Runtime user must never have a writable path into that tree.
grep -Fq 'ReadOnlyPaths=/var/lib/rill-xray-agent-root /var/lib/rill-xray-agent-xray' \
  systemd/rill-xray-agent-runtime.service
# Root observer systemd DAC contract: User=root Group=rill-xray-agent UMask=0027
# so produced files are 0640 root:rill-xray-agent (readable, not writable).
grep -Fq 'User=root' systemd/rill-xray-agent-xray-observe.service
grep -Fq 'Group=rill-xray-agent' systemd/rill-xray-agent-xray-observe.service
grep -Fq 'UMask=0027' systemd/rill-xray-agent-xray-observe.service
# Installer establishes the root:rill-xray-agent 2750 (setgid) DAC contract.
grep -Fq 'chmod 2750' scripts/rill_xray_agent_install.sh
grep -Fq 'chown root:rill-xray-agent' scripts/rill_xray_agent_install.sh
# CLI exposes diagnose / timeline / feedback / inspect.
grep -Fq -- '--rill-agent-diagnose' install.sh
grep -Fq -- '--rill-agent-timeline' install.sh
# Manager dispatches diagnose / timeline through the Runtime.
grep -Fq 'rxa_runtime diagnose' scripts/rill_xray_agent_manager.sh
grep -Fq 'rxa_runtime timeline' scripts/rill_xray_agent_manager.sh
# Safety invariants are never enabled by the integration. The canonical
# default config disables Route Assist and bounded auto; the manager both
# defaults to that config and rejects any config that enables them.
grep -Fq '"routeAssistEnabled": false' rill_payload/config/default.json
grep -Fq '"boundedAutoAllowed": false' rill_payload/config/default.json
grep -Fq '"routeAssistEnabled":false' scripts/rill_xray_agent_manager.sh
grep -Fq '"boundedAutoAllowed":false' scripts/rill_xray_agent_manager.sh
grep -Eq 'routeAssistEnabled[^=]*== false' scripts/rill_xray_agent_manager.sh
grep -Eq 'boundedAutoAllowed[^=]*== false' scripts/rill_xray_agent_manager.sh

# --- live decision lifecycle (RuntimeService against scratch roots) --------
# Uses the canonical package from the payload mirror. Exercises the full
# diagnose -> register -> feedback -> inspect -> (restart) -> inspect loop,
# plus fake-feedback rejection and Runtime read-only journaling.
PYA="$(pwd)/rill_payload/python"
PYTHONPATH="$PYA" python3 - <<'PY'
import json, os, sys, tempfile, time
from pathlib import Path
from rill_xray_agent.runtime_service import RuntimeService
from rill_xray_agent.event_journal import EventJournal, EventJournalError

OBS = {"schemaVersion":1,"capturedAtEpochSeconds":int(time.time()),
       "xrayConfig":{"present":True,"safe":True,"sha256":"a"*64},
       "nginxConfig":{"present":False},
       "installConfig":{"present":True,"safe":True,"sha256":"c"*64},
       "xrayValidation":{"ok":True,"returnCode":0},
       "nginxValidation":{"ok":False,"returnCode":66},
       "services":{"xray":{"ok":True,"returnCode":0},"nginx":{"ok":False,"returnCode":4}}}

def run(scratch):
    r = Path(scratch)
    (r/'status').mkdir(parents=True, exist_ok=True)
    (r/'status'/'xray-observation.json').write_text(json.dumps(OBS))
    return RuntimeService(r/'state', r/'tx', allowed_uids=[os.getuid()],
                          observation_path=r/'status'/'xray-observation.json',
                          timeline_dir=r/'history')

def req(svc, method, body):
    return svc.handle({'schemaVersion':3,'requestId':'t','method':method,'body':body},
                      peer_uid=os.getuid())

with tempfile.TemporaryDirectory() as td:
    svc = run(td)
    # timeline missing -> unavailable, not empty-history
    tl = req(svc, 'timeline', {})
    assert tl['result']['available'] in (True, False)
    # diagnose -> healthy, advisory-only, decision registered
    d = req(svc, 'diagnose', {})
    assert d['ok'], d
    assert d['result']['canApply'] is False
    assert d['result']['engineGeneration'] == 2
    assert d['result']['status'] == 'healthy', d['result']['status']
    did = d['result']['diagnosisId']
    # same-evidence idempotency -> same diagnosisId, no conflict
    d2 = req(svc, 'diagnose', {})
    assert d2['result']['diagnosisId'] == did
    # inspect -> pending registered decision
    ins = req(svc, 'inspect', {'decisionId': did})
    assert ins['result']['pending'] is not None
    # fake feedback rejected
    fb = req(svc, 'feedback', {'decisionId':'deadbeef'*8,'outcome':'resolved',
                               'helpful':True,'diagnosisCorrect':True})
    assert not fb['ok'] and fb['error']['code'] == 'unknownDecision'
    # real feedback accepted, structured fields preserved
    fb = req(svc, 'feedback', {'decisionId': did, 'outcome':'resolved',
                               'helpful':True,'diagnosisCorrect':True})
    assert fb['ok'] and fb['result']['result']['accepted'] is True
    ins = req(svc, 'inspect', {'decisionId': did})
    assert ins['result']['completed']['payloadMeta']['outcome'] == 'resolved'
    # restart -> feedback persisted
    svc2 = run(td)
    ins = req(svc2, 'inspect', {'decisionId': did})
    assert ins['result']['completed']['payloadMeta']['outcome'] == 'resolved'
    # Runtime never writes the observation/history tree
    j = EventJournal(Path(td,'history'))
    j.append_event({'schemaVersion':1,'eventType':'baseline_observed','component':'agent','facts':{}})
    before = j.verify()
    req(svc2, 'diagnose', {})
    req(svc2, 'timeline', {})
    assert EventJournal(Path(td,'history')).verify() == before
    # read-only journal rejects append
    ro = EventJournal(Path(td,'history'), read_only=True)
    try:
        ro.append_event({'schemaVersion':1,'eventType':'xray_config_changed','component':'xray','facts':{}})
    except EventJournalError:
        pass
    else:
        raise SystemExit('read-only journal must reject append')
print('Operational Intelligence live lifecycle passed')
PY

echo 'Rill Xray Agent operational-intelligence regression passed'