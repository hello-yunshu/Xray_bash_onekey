"""Derive meaningful state-change events from consecutive safe observations.

The timeline never stores full observation snapshots. Instead, consecutive
observations are compared and only *meaningful transitions* are recorded:

    baseline_observed, *_config_changed, *_validation_failed/recovered,
    *_service_down/up, unsafe_path_detected

Facts are restricted to safe scalar metadata (timestamps, hashes, tree
hashes, file sizes/counts, booleans, return codes, component ids). Raw
config bodies, command output, secrets and addresses never appear here.
"""
from .canonical import digest

SCHEMA_VERSION = 1

EVENT_TYPES = {
    'baseline_observed', 'observation_stale',
    'xray_config_changed', 'nginx_config_changed', 'install_config_changed',
    'xray_validation_failed', 'xray_validation_recovered',
    'nginx_validation_failed', 'nginx_validation_recovered',
    'xray_service_down', 'xray_service_up',
    'nginx_service_down', 'nginx_service_up',
    'unsafe_path_detected',
}

COMPONENTS = ('xray', 'nginx', 'install')


def _config_entry(obs, component):
    """Return the safe config summary dict for a component, or {} if absent."""
    key = {'xray': 'xrayConfig', 'nginx': 'nginxConfig', 'install': 'installConfig'}[component]
    value = (obs or {}).get(key) or {}
    return value if isinstance(value, dict) else {}


def config_digest(obs, component):
    """Deterministic safe fingerprint of a component's config summary.

    Only the project-internal hash values and presence/safety booleans are
    mixed in - never the config body.
    """
    entry = _config_entry(obs, component)
    if not entry.get('present'):
        return ''
    if not entry.get('safe'):
        return 'unsafe'
    return entry.get('sha256') or entry.get('treeSha256') or ''


def _validation(obs, component):
    value = (obs or {}).get('xrayValidation' if component == 'xray' else 'nginxValidation')
    return bool((value or {}).get('ok')) if isinstance(value, dict) else None


def _service(obs, component):
    services = (obs or {}).get('services') or {}
    value = services.get(component)
    return bool(value.get('ok')) if isinstance(value, dict) else None


def _unsafe_path(obs):
    for component in COMPONENTS:
        entry = _config_entry(obs, component)
        if entry.get('present') and entry.get('safe') is False:
            return True
    return False


def _event(event_type, component=None, facts=None):
    event = {'schemaVersion': SCHEMA_VERSION, 'eventType': event_type,
             'component': component or 'agent', 'facts': facts or {}}
    return event


def derive_events(previous, current, now=None):
    """Produce a deterministically ordered list of meaningful events.

    `previous` and `current` are safe observation dicts (fields described in
    xray-observation.v1.schema.json). Returns a list of event dicts suitable
    for EventJournal.append_event. An empty list means no meaningful change.
    """
    events = []
    if previous is None:
        events.append(_event('baseline_observed', 'agent',
                             {'firstObservation': True}))
        return events

    # config fingerprint changes
    for component in COMPONENTS:
        prev_d = config_digest(previous, component)
        curr_d = config_digest(current, component)
        if prev_d != curr_d:
            events.append(_event(f'{component}_config_changed', component,
                                 {'previousConfigDigest': prev_d or None,
                                  'currentConfigDigest': curr_d or None}))

    # validation transitions
    for component in ('xray', 'nginx'):
        prev_ok = _validation(previous, component)
        curr_ok = _validation(current, component)
        if prev_ok is not None and curr_ok is not None and prev_ok != curr_ok:
            if curr_ok:
                events.append(_event(f'{component}_validation_recovered', component))
            else:
                events.append(_event(f'{component}_validation_failed', component,
                                     {'returnCode': (current or {}).get(
                                         'xrayValidation' if component == 'xray' else 'nginxValidation', {})
                                      .get('returnCode')}))

    # service transitions
    for component in ('xray', 'nginx'):
        prev_ok = _service(previous, component)
        curr_ok = _service(current, component)
        if prev_ok is not None and curr_ok is not None and prev_ok != curr_ok:
            if curr_ok:
                events.append(_event(f'{component}_service_up', component))
            else:
                events.append(_event(f'{component}_service_down', component))

    # unsafe path
    if _unsafe_path(current):
        events.append(_event('unsafe_path_detected', 'agent', {'unsafe': True}))

    return events


def event_identity(event):
    """Deterministic identity of an event (used for dedup / audit)."""
    return digest({k: event.get(k) for k in ('schemaVersion', 'eventType', 'component', 'facts')})