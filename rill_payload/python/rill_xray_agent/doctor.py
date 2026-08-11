"""Deterministic, audit-friendly Doctor for the Rill Xray Agent 0.2.

The Doctor correlates the latest safe observation with recent safe timeline
events and produces a structured, explainable diagnosis. It is advisory-only:

- facts and inferences are kept separate (never present causation as fact);
- confidence is a coarse band, not a pseudo-precise probability;
- summaries/assessments come from fixed safe templates;
- recommendations are never executed (executionAllowed=false, canApply=false);
- evidence quality is explicit: missing/stale/invalid evidence can never be
  mistaken for proof of health.

Engine identities are bound to the exact evidence instance used: the safe
observation fingerprint + capture time, required validation/service facts,
the eventIds+sequences actually used and the timeline integrity state.
"""
from .canonical import digest

# Observation cadence is 5 minutes (xray-observe.timer), so the default
# freshness threshold is 2x the cadence: timer interval + safety margin.
DEFAULT_OBSERVATION_FRESHNESS_SECONDS = 600
DEFAULT_CORRELATION_WINDOW_SECONDS = 600
DEFAULT_CLOCK_SKEW_SECONDS = 60


class Doctor:
    ENGINE_GENERATION = 2

    # recommendation catalog (advisory only)
    RECOMMENDATIONS = {
        'CHECK_XRAY_VALIDATION': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'XRAY_VALIDATION_FAILED',
        },
        'CHECK_NGINX_VALIDATION': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'NGINX_VALIDATION_FAILED',
        },
        'CHECK_RECENT_XRAY_CHANGE': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'XRAY_VALIDATION_FAILED_AFTER_CHANGE',
        },
        'CHECK_RECENT_NGINX_CHANGE': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'NGINX_VALIDATION_FAILED_AFTER_CHANGE',
        },
        'CHECK_XRAY_SERVICE': {
            'priority': 'medium', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'XRAY_SERVICE_DOWN',
        },
        'CHECK_NGINX_SERVICE': {
            'priority': 'medium', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'NGINX_SERVICE_DOWN',
        },
        'CHECK_HOST_SERVICES': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'BOTH_SERVICES_DOWN',
        },
        'SAFE_INSPECTION': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': True,
            'reversible': False, 'executionAllowed': False,
            'reasonCode': 'UNSAFE_PATH',
        },
        'RUN_RECOVERY': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': True,
            'reversible': False, 'executionAllowed': False,
            'reasonCode': 'RECOVERY_REQUIRED',
        },
    }

    def __init__(self, observation=None, events=None, health=None, now=None,
                 observation_freshness_seconds=DEFAULT_OBSERVATION_FRESHNESS_SECONDS,
                 correlation_window_seconds=DEFAULT_CORRELATION_WINDOW_SECONDS,
                 timeline_status='available'):
        self.observation = observation if isinstance(observation, dict) else None
        self.events = events if isinstance(events, list) else []
        self.health = health if isinstance(health, dict) else {}
        self._clock = now if now is not None else None
        self.observation_freshness_seconds = int(observation_freshness_seconds)
        self.correlation_window_seconds = int(correlation_window_seconds)
        if timeline_status not in ('available', 'missing', 'corrupt'):
            timeline_status = 'available'
        self.timeline_status = timeline_status

    # -- time / evidence quality -----------------------------------------
    def _now(self) -> int:
        if self._clock is not None:
            return int(self._clock)
        import time
        return int(time.time())

    def _captured_at(self):
        o = self.observation
        if not o:
            return None
        value = o.get('capturedAtEpochSeconds')
        return value if isinstance(value, int) and value > 0 else None

    def observation_status(self):
        """fresh / stale / missing / invalid (future timestamp -> invalid)."""
        if self.observation is None:
            return 'missing'
        captured = self._captured_at()
        if captured is None:
            return 'invalid'
        now = self._now()
        if captured > now + DEFAULT_CLOCK_SKEW_SECONDS:
            return 'invalid'
        if now - captured > self.observation_freshness_seconds:
            return 'stale'
        return 'fresh'

    def _evidence_fresh(self):
        """HEALTHY requires the observation to be explicitly fresh."""
        return self.observation_status() == 'fresh'

    # -- input helpers ----------------------------------------------------
    def _events_of_type(self, event_type):
        return [e for e in self.events if e.get('eventType') == event_type]

    def _has(self, component, kind):
        return any(e.get('eventType') == f'{component}_{kind}' for e in self.events)

    def _change_recent(self, component, kind='config_changed'):
        """Temporal correlation: the change event must be at or before the
        observation and inside the correlation window. A raw count-based
        'recent 50 events' heuristic is never acceptable as 'recent'."""
        obs_at = self._captured_at()
        if obs_at is None:
            return False
        for e in self._events_of_type(f'{component}_{kind}'):
            at = e.get('capturedAtEpochSeconds')
            if not isinstance(at, int) or at <= 0:
                continue
            if at <= obs_at and obs_at - at <= self.correlation_window_seconds:
                return True
        return False

    def _config_changed_recently(self, component):
        return self._change_recent(component, 'config_changed')

    def _validation_ok(self, component):
        o = self.observation
        if not o:
            return None
        value = o.get('xrayValidation' if component == 'xray' else 'nginxValidation')
        if not isinstance(value, dict) or value.get('ok') is None:
            return None
        return True if value['ok'] is True else False

    def _service_ok(self, component):
        o = self.observation
        if not o:
            return None
        value = (o.get('services') or {}).get(component)
        if not isinstance(value, dict) or value.get('ok') is None:
            return None
        return True if value['ok'] is True else False

    def _config_present(self, component):
        o = self.observation
        key = {'xray': 'xrayConfig', 'nginx': 'nginxConfig',
               'install': 'installConfig'}[component]
        entry = (o or {}).get(key)
        return bool(isinstance(entry, dict) and entry.get('present') is True)

    # Required components follow the installation contract: a component is
    # required when its configuration tree is present on this host. An
    # intentionally absent component (e.g. Nginx-free single-binary mode) is
    # NOT a missing-evidence failure.
    def _required(self, component):
        return self._config_present(component)

    def _unsafe_path(self):
        o = self.observation or {}
        for key in ('xrayConfig', 'nginxConfig', 'installConfig'):
            entry = o.get(key) or {}
            if entry.get('present') and entry.get('safe') is False:
                return True
        return False

    # -- evidence ----------------------------------------------------------
    def _evidence_digest(self):
        """Deterministic identity of the evidence INSTANCE this diagnosis is
        based on: safe observation fingerprint + capture time, required
        validation/service facts, timeline integrity, and the exact eventIds
        + sequences actually used. Never raw config, secrets or free text."""
        parts = []
        o = self.observation
        if o:
            parts.append('observedAt=' + str(o.get('capturedAtEpochSeconds')))
            for key in ('xrayConfig', 'nginxConfig', 'installConfig'):
                entry = o.get(key) or {}
                for field in ('sha256', 'treeSha256', 'safe', 'present',
                              'files', 'size'):
                    if field in entry:
                        parts.append(f'{key}.{field}={entry[field]}')
            for key in ('xrayValidation', 'nginxValidation'):
                entry = o.get(key) or {}
                for field in ('ok', 'returnCode'):
                    if field in entry:
                        parts.append(f'{key}.{field}={entry[field]}')
            for key in ('xray', 'nginx'):
                entry = (o.get('services') or {}).get(key) or {}
                if 'ok' in entry:
                    parts.append(f'services.{key}.ok={entry["ok"]}')
        parts.append('observationStatus=' + self.observation_status())
        parts.append('timelineStatus=' + self.timeline_status)
        for e in self.events:
            parts.append(f'event:{e.get("eventId")}:{e.get("sequence")}')
        return digest({'evidence': parts})
    # -- outputs -----------------------------------------------------------
    def _newest_event_sequence(self):
        seqs = [e.get('sequence') for e in self.events
                if isinstance(e.get('sequence'), int)]
        return max(seqs) if seqs else None

    def _timeline_limitation(self):
        """Never claim 'no recent change' when the timeline itself is
        unavailable - that would confuse absence of evidence with evidence
        of absence."""
        if self.timeline_status != 'available':
            return ['recent historical correlation unavailable '
                    f'(timeline {self.timeline_status})']
        return []

    def _result(self, status, severity, code, confidence, facts, inferences,
                rec_codes, limitations, summary):
        values = (str(self.ENGINE_GENERATION), self._evidence_digest(), code)
        diagnosis_id = digest(values)
        recommendations = []
        for c in rec_codes:
            if c in self.RECOMMENDATIONS:
                recommendations.append(dict(self.RECOMMENDATIONS[c], code=c))
        evidence = {
            'observationStatus': self.observation_status(),
            'timelineStatus': self.timeline_status,
            'observationCapturedAtEpochSeconds': self._captured_at(),
            'correlationWindowSeconds': self.correlation_window_seconds,
            'newestEventSequence': self._newest_event_sequence(),
        }
        return {
            'schemaVersion': 1,
            'diagnosisId': diagnosis_id,
            'engineGeneration': self.ENGINE_GENERATION,
            'status': status,
            'severity': severity,
            'diagnosisCode': code,
            'confidenceBand': confidence,
            'summary': summary,
            'facts': facts,
            'inferences': inferences,
            'recommendations': recommendations,
            'limitations': limitations,
            'evidence': evidence,
            'evidenceDigest': self._evidence_digest(),
            'canApply': False,
        }

    # -- HEALTHY strict gate ------------------------------------------------
    def _all_required_healthy(self):
        """HEALTHY must be actively proven, never assumed by absence of an
        earlier fault rule. For every currently REQUIRED component the
        required evidence must be explicitly healthy (True, not absent).

        A missing/unknown value is NOT False: unknown evidence can never
        produce HEALTHY.
        """
        if not self._evidence_fresh():
            return False
        if self._unsafe_path():
            return False
        for component in ('xray', 'nginx'):
            if not self._required(component):
                continue
            if self._validation_ok(component) is not True:
                return False
            if self._service_ok(component) is not True:
                return False
        return True

    def _insufficient_list(self):
        """Explain exactly which required evidence is missing/unknown."""
        missing = []
        for component in ('xray', 'nginx'):
            if not self._required(component):
                continue
            if self._validation_ok(component) is None:
                missing.append(f'{component} validation evidence missing')
            if self._service_ok(component) is None:
                missing.append(f'{component} service evidence missing')
        return missing

    # -- rules --------------------------------------------------------------
    def _rule_recovery_required(self):
        if not self.health.get('canRecommend'):
            return self._result(
                'degraded', 'high', 'RECOVERY_REQUIRED', 'high',
                ['Rill internal recovery is required before advisory diagnosis.'],
                ['Recommendations are suppressed until Runtime recovery completes.'],
                ['RUN_RECOVERY'],
                ['Rill internal recovery is required.'],
                'Runtime recovery is required before diagnosis; no advisory action is available.',
            )
        return None

    def _rule_observation_missing(self):
        if self.observation_status() == 'missing':
            return self._result(
                'insufficient-evidence', 'info', 'MISSING_OBSERVATION',
                'insufficient-evidence',
                ['No current safe observation is available.'],
                [],
                [], ['Diagnosis is impossible without a current observation.'],
                'No recent observation is available to diagnose.',
            )
        return None

    def _rule_observation_time_invalid(self):
        if self.observation_status() == 'invalid':
            return self._result(
                'insufficient-evidence', 'info', 'INVALID_OBSERVATION_TIME',
                'insufficient-evidence',
                ['The observation timestamp is missing or in the future.'],
                [],
                [], ['The observation cannot be used as current evidence.'],
                'The observation timestamp is invalid; evidence is insufficient.',
            )
        return None

    def _rule_observation_stale(self):
        if self.observation_status() == 'stale':
            return self._result(
                'insufficient-evidence', 'info', 'STALE_OBSERVATION',
                'insufficient-evidence',
                [f'The observation is older than '
                 f'{self.observation_freshness_seconds}s.'],
                [],
                [], ['A fresh observation is required for diagnosis.'],
                'The observation is stale; evidence is insufficient.',
            )
        return None

    def _rule_unsafe_path(self):
        if self._unsafe_path():
            return self._result(
                'degraded', 'high', 'UNSAFE_PATH', 'high',
                ['An unsafe path was detected in the host configuration tree.'],
                ['The configuration tree is not safe to inspect.'],
                ['SAFE_INSPECTION'],
                ['No actionable recommendation beyond safe host inspection.'],
                'An unsafe path was detected; inspection must be done safely.',
            )
        return None

    def _rule_both_services_down(self):
        # Only required components can contribute to a host-level BOTH_DOWN
        # diagnosis; an intentionally absent component is never counted.
        req = [c for c in ('xray', 'nginx') if self._required(c)]
        if len(req) < 2:
            return None
        x = self._service_ok('xray')
        n = self._service_ok('nginx')
        if x is False and n is False:
            correlated = (self._config_changed_recently('xray')
                          or self._config_changed_recently('nginx'))
            if correlated:
                return self._result(
                    'fault', 'high', 'BOTH_SERVICES_DOWN', 'high',
                    ['Xray and Nginx services are both inactive.',
                     'A recent configuration change is recorded in the window.'],
                    ['The recent configuration change is a likely contributor.'],
                    ['CHECK_HOST_SERVICES'],
                    self._timeline_limitation() +
                    ['Correlation is not proof of cause.'],
                    'Both Xray and Nginx are inactive after a recent configuration change.',
                )
            return self._result(
                'fault', 'high', 'BOTH_SERVICES_DOWN', 'medium',
                ['Xray and Nginx services are both inactive.'],
                ['Without a recent configuration change, a host/system/service-layer issue is likely.'],
                ['CHECK_HOST_SERVICES'],
                self._timeline_limitation(),
                'Both Xray and Nginx are inactive; a host or service-layer issue is likely.',
            )
        return None

    def _validation_failure_result(self, component):
        """Explicit current validation failure. Correlated with a recent
        config change -> confidence high + CHECK_RECENT_*_CHANGE. Without a
        change -> a dedicated NOT-HEALTHY diagnosis with medium confidence
        (never 'no recent change' when the timeline is unavailable)."""
        ok = self._validation_ok(component)
        if ok is not False:
            return None
        recent = self._config_changed_recently(component)
        code = f'{component.upper()}_VALIDATION_FAILED'
        if recent:
            code += '_AFTER_CHANGE'
        facts = [f'{component.capitalize()} validation now fails.']
        inferences = []
        rec = []
        limitations = []
        confidence = 'medium'
        if recent:
            facts.append(
                f'{component.capitalize()} configuration fingerprint changed '
                'within the correlation window.')
            inferences.append(
                f'The recent {component} configuration change is a likely '
                'contributor (correlation, not proven cause).')
            rec = [f'CHECK_RECENT_{component.upper()}_CHANGE']
            limitations = ['Correlation is not proof of cause.']
            confidence = 'high'
        else:
            # 7.5: with an unavailable timeline we must never claim "no recent
            # change" - that confuses absence of evidence with evidence of
            # absence. State only that change evidence is unavailable.
            if self.timeline_status != 'available':
                inferences.append(
                    'Recent configuration-change evidence is unavailable; '
                    'configuration causality cannot be established.')
            else:
                inferences.append(
                    f'No recent configuration change is available to '
                    'establish configuration causality.')
            rec = [f'CHECK_{component.upper()}_VALIDATION']
            limitations = self._timeline_limitation()
        return self._result(
            'degraded', 'high', code, confidence, facts, inferences, rec,
            limitations,
            f'{component.capitalize()} validation is failing; '
            f'configuration causality is {"linked to a recent change" if recent else "not established"}.',
        )

    def _service_failure_result(self, component):
        ok = self._service_ok(component)
        if ok is not False:
            return None
        recent = self._config_changed_recently(component)
        code = f'{component.upper()}_SERVICE_DOWN'
        confidence = 'low'
        facts = [f'{component.capitalize()} service is inactive.']
        inferences = [
            'A service or runtime problem is possible; '
            'configuration causality is not established.']
        rec = [f'CHECK_{component.upper()}_SERVICE']
        limitations = self._timeline_limitation()
        if recent:
            code += '_AFTER_CHANGE'
            confidence = 'high' if self._validation_ok(component) is False else 'medium'
            facts.append(
                f'{component.capitalize()} configuration fingerprint changed '
                'within the correlation window.')
            inferences = [
                f'The recent {component} configuration change is a likely '
                'contributor (correlation, not proven cause).']
            rec = [f'CHECK_RECENT_{component.upper()}_CHANGE']
            limitations = ['Correlation is not proof of cause.']
        return self._result(
            'degraded', 'high', code, confidence, facts, inferences, rec,
            limitations,
            f'{component.capitalize()} service is inactive'
            f'{"; after a recent configuration change" if recent else ""}.',
        )

    def _rule_validation_failure(self):
        for component in ('xray', 'nginx'):
            if not self._required(component):
                continue
            result = self._validation_failure_result(component)
            if result is not None:
                return result
        return None

    def _rule_service_failure(self):
        for component in ('xray', 'nginx'):
            if not self._required(component):
                continue
            result = self._service_failure_result(component)
            if result is not None:
                return result
        return None

    def _rule_config_changed_healthy(self):
        if (self._config_changed_recently('xray')
                or self._config_changed_recently('nginx')
                or self._change_recent('install', 'config_changed')):
            if not self._all_required_healthy():
                return None
            limitations = []
            confidence = 'high'
            if self.timeline_status != 'available':
                limitations = self._timeline_limitation()
                confidence = 'medium'
            return self._result(
                'healthy', 'info', 'CONFIG_CHANGED_HEALTHY', confidence,
                ['A configuration fingerprint changed recently.'],
                ['All validations pass and services are active; no fault is indicated.'],
                [], limitations,
                'Configuration changed but everything is healthy.',
            )
        return None

    def _rule_healthy(self):
        # HEALTHY is a strict gate, not a fallthrough: every piece of required
        # evidence must be explicitly healthy or this rule does not fire.
        if not self._all_required_healthy():
            return None
        limitations = []
        confidence = 'high'
        if self.timeline_status != 'available':
            limitations = self._timeline_limitation()
            confidence = 'medium'
        return self._result(
            'healthy', 'info', 'HEALTHY', confidence,
            ['Validations pass and services are active.'],
            ['No relevant recent failure is indicated.'],
            [], limitations,
            'All observed services are healthy.',
        )

    def _rule_insufficient_evidence(self):
        # Final fallback: never fabricate HEALTHY from incomplete evidence.
        missing_obs = 'No safe observation is available.' if self.observation is None else \
            f'Current observation status: {self.observation_status()}.'
        return self._result(
            'insufficient-evidence', 'info', 'INSUFFICIENT_EVIDENCE',
            'insufficient-evidence',
            [missing_obs] + self._insufficient_list(),
            [],
            [], ['Diagnosis cannot be completed on the available evidence.'],
            'Available evidence is insufficient for a diagnosis.',
        )

    RULES = [
        _rule_recovery_required,
        _rule_observation_missing,
        _rule_observation_time_invalid,
        _rule_observation_stale,
        _rule_unsafe_path,
        _rule_both_services_down,
        _rule_validation_failure,
        _rule_service_failure,
        _rule_config_changed_healthy,
        _rule_healthy,
        _rule_insufficient_evidence,
    ]

    def diagnose(self):
        for rule in Doctor.RULES:
            result = rule(self)
            if result is not None:
                return result
        return self._rule_insufficient_evidence()
