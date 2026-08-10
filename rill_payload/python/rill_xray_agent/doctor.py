"""Deterministic, audit-friendly Doctor for the Rill Xray Agent 0.2.

The Doctor correlates the latest safe observation with recent safe timeline
events and produces a structured, explainable diagnosis. It is advisory-only:

- facts and inferences are kept separate (never present causation as fact);
- confidence is a coarse band, not a pseudo-precise probability;
- summaries/assessments come from fixed safe templates;
- recommendations are never executed (executionAllowed=false, canApply=false).
"""
from .canonical import digest


class Doctor:
    ENGINE_GENERATION = 1

    # recommendation catalog (advisory only)
    RECOMMENDATIONS = {
        'CHECK_RECENT_XRAY_CHANGE': {
            'priority': 'high', 'risk': 'low', 'requiresRoot': False,
            'reversible': True, 'executionAllowed': False,
            'reasonCode': 'XRAY_VALIDATION_FAILED_AFTER_CHANGE',
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

    def __init__(self, observation=None, events=None, health=None):
        self.observation = observation if isinstance(observation, dict) else None
        self.events = events if isinstance(events, list) else []
        self.health = health if isinstance(health, dict) else {}

    # -- input helpers ----------------------------------------------------
    def _has(self, component, kind):
        for e in self.events:
            if e.get('eventType') == f'{component}_{kind}':
                return True
        return False

    def _config_changed(self, component):
        return self._has(component, 'config_changed')

    def _validation_ok(self, component):
        o = self.observation
        if not o:
            return None
        value = o.get('xrayValidation' if component == 'xray' else 'nginxValidation')
        return bool((value or {}).get('ok')) if isinstance(value, dict) else None

    def _service_ok(self, component):
        o = self.observation
        if not o:
            return None
        value = (o.get('services') or {}).get(component)
        return bool(value.get('ok')) if isinstance(value, dict) else None

    def _unsafe_path(self):
        o = self.observation or {}
        for key in ('xrayConfig', 'nginxConfig', 'installConfig'):
            entry = o.get(key) or {}
            if entry.get('present') and entry.get('safe') is False:
                return True
        return False

    def _stale(self, max_age=600):
        o = self.observation
        if not o:
            return False
        captured = o.get('capturedAtEpochSeconds')
        if not isinstance(captured, int):
            return True
        return False  # staleness is evaluated by the caller with a clock

    # -- evidence ----------------------------------------------------------
    def _evidence_digest(self):
        obs_parts = []
        if self.observation:
            for key in ('xrayConfig', 'nginxConfig', 'installConfig'):
                entry = self.observation.get(key) or {}
                for field in ('sha256', 'treeSha256', 'safe', 'present', 'files', 'size'):
                    if field in entry:
                        obs_parts.append(f'{key}.{field}={entry[field]}')
            for key in ('xrayValidation', 'nginxValidation'):
                entry = self.observation.get(key) or {}
                if 'ok' in entry:
                    obs_parts.append(f'{key}.ok={entry["ok"]}')
            for key in ('xray', 'nginx'):
                entry = (self.observation.get('services') or {}).get(key) or {}
                if 'ok' in entry:
                    obs_parts.append(f'services.{key}.ok={entry["ok"]}')
        event_parts = [f'{e.get("eventType")}' for e in self.events]
        return digest({'obs': obs_parts, 'events': event_parts})

    # -- outputs -----------------------------------------------------------
    def _result(self, status, severity, code, confidence, facts, inferences,
                rec_codes, limitations, summary):
        values = (str(self.ENGINE_GENERATION), self._evidence_digest(), code)
        diagnosis_id = digest(values)
        recommendations = []
        for c in rec_codes:
            if c in self.RECOMMENDATIONS:
                recommendations.append(dict(self.RECOMMENDATIONS[c], code=c))
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
            'canApply': False,
        }

    # -- rules ------------------------------------------------------------
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

    def _rule_insufficient_evidence(self):
        if self.observation is None:
            return self._result(
                'insufficient-evidence', 'info', 'MISSING_OBSERVATION',
                'insufficient-evidence',
                ['No current safe observation is available.'],
                [],
                [], ['Diagnosis is impossible without a current observation.'],
                'No recent observation is available to diagnose.',
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
        x = self._service_ok('xray')
        n = self._service_ok('nginx')
        if x is False and n is False:
            changed = self._config_changed('xray') or self._config_changed('nginx')
            if not changed:
                return self._result(
                    'fault', 'high', 'BOTH_SERVICES_DOWN', 'medium',
                    ['Xray and Nginx services are both inactive.'],
                    ['Without a recent configuration change, a host/system/service-layer issue is likely.'],
                    ['CHECK_HOST_SERVICES'],
                    ['Configuration causality is not established without a recent config change.'],
                    'Both Xray and Nginx are inactive; a host or service-layer issue is likely.',
                )
        return None

    def _rule_xray_validation_failed_after_change(self):
        if self._validation_ok('xray') is False and self._config_changed('xray'):
            return self._result(
                'degraded', 'high', 'XRAY_VALIDATION_FAILED_AFTER_CHANGE', 'high',
                ['Xray configuration fingerprint changed recently.',
                 'Xray validation now fails.'],
                ['The recent Xray configuration change is a likely contributor.'],
                ['CHECK_RECENT_XRAY_CHANGE'],
                ['Correlation is not proof of cause.'],
                'Xray validation failed after a recent configuration fingerprint change.',
            )
        return None

    def _rule_xray_service_down_after_change(self):
        if self._service_ok('xray') is False and self._config_changed('xray'):
            conf = 'high' if self._validation_ok('xray') is False else 'medium'
            return self._result(
                'degraded', 'high', 'XRAY_SERVICE_DOWN_AFTER_CHANGE', conf,
                ['Xray configuration fingerprint changed recently.',
                 'Xray service is inactive.'],
                ['The recent Xray configuration change is a likely contributor.'],
                ['CHECK_RECENT_XRAY_CHANGE'],
                ['Correlation is not proof of cause.'],
                'Xray service is inactive after a recent configuration fingerprint change.',
            )
        return None

    def _rule_xray_service_down(self):
        if self._service_ok('xray') is False:
            return self._result(
                'degraded', 'medium', 'XRAY_SERVICE_DOWN', 'low',
                ['Xray service is inactive.'],
                ['A service or runtime problem is possible; configuration causality is not established.'],
                ['CHECK_XRAY_SERVICE'],
                ['No recent configuration change observed.'],
                'Xray service is inactive; a service or runtime problem is possible.',
            )
        return None

    def _rule_nginx_validation_failed_after_change(self):
        if self._validation_ok('nginx') is False and self._config_changed('nginx'):
            return self._result(
                'degraded', 'high', 'NGINX_VALIDATION_FAILED_AFTER_CHANGE', 'high',
                ['Nginx configuration fingerprint changed recently.',
                 'Nginx validation now fails.'],
                ['The recent Nginx configuration change is a likely contributor.'],
                ['CHECK_RECENT_XRAY_CHANGE'],
                ['Correlation is not proof of cause.'],
                'Nginx validation failed after a recent configuration fingerprint change.',
            )
        return None

    def _rule_nginx_service_down_after_change(self):
        if self._service_ok('nginx') is False and self._config_changed('nginx'):
            conf = 'high' if self._validation_ok('nginx') is False else 'medium'
            return self._result(
                'degraded', 'high', 'NGINX_SERVICE_DOWN_AFTER_CHANGE', conf,
                ['Nginx configuration fingerprint changed recently.',
                 'Nginx service is inactive.'],
                ['The recent Nginx configuration change is a likely contributor.'],
                ['CHECK_NGINX_SERVICE'],
                ['Correlation is not proof of cause.'],
                'Nginx service is inactive after a recent configuration fingerprint change.',
            )
        return None

    def _rule_nginx_service_down(self):
        if self._service_ok('nginx') is False:
            return self._result(
                'degraded', 'medium', 'NGINX_SERVICE_DOWN', 'low',
                ['Nginx service is inactive.'],
                ['A service or runtime problem is possible; configuration causality is not established.'],
                ['CHECK_NGINX_SERVICE'],
                ['No recent configuration change observed.'],
                'Nginx service is inactive; a service or runtime problem is possible.',
            )
        return None

    def _rule_config_changed_healthy(self):
        if self._config_changed('xray') or self._config_changed('nginx') or self._config_changed('install'):
            return self._result(
                'healthy', 'info', 'CONFIG_CHANGED_HEALTHY', 'high',
                ['A configuration fingerprint changed recently.'],
                ['All validations pass and services are active; no fault is indicated.'],
                [], ['Informational only; not a fault.'],
                'Configuration changed but everything is healthy.',
            )
        return None

    def _rule_healthy(self):
        return self._result(
            'healthy', 'info', 'HEALTHY', 'high',
            ['Validations pass and services are active.'],
            ['No relevant recent failure is indicated.'],
            [], [], 'All observed services are healthy.',
        )

    RULES = [
        _rule_recovery_required,
        _rule_insufficient_evidence,
        _rule_unsafe_path,
        _rule_both_services_down,
        _rule_xray_validation_failed_after_change,
        _rule_xray_service_down_after_change,
        _rule_xray_service_down,
        _rule_nginx_validation_failed_after_change,
        _rule_nginx_service_down_after_change,
        _rule_nginx_service_down,
        _rule_config_changed_healthy,
        _rule_healthy,
    ]

    def diagnose(self):
        for rule in Doctor.RULES:
            result = rule(self)
            if result is not None:
                return result
        return self._rule_healthy()