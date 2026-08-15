class RoutePolicy:
    def __init__(self, mode, configured_stage, release_capabilities, health,
                 recovery_required, observation_fresh, observation_integrity_valid,
                 timeline_integrity_valid, plan_valid=True, plan_not_expired=True,
                 generation_match=True, config_hash_match=True, fusible_open=True,
                 rate_limit_ok=True, cooldown_ok=True, auto_confirmed=True):
        self.mode = mode
        self.configured_stage = configured_stage
        self.release_capabilities = release_capabilities
        self.health = health
        self.recovery_required = recovery_required
        self.observation_fresh = observation_fresh
        self.observation_integrity_valid = observation_integrity_valid
        self.timeline_integrity_valid = timeline_integrity_valid
        self.plan_valid = plan_valid
        self.plan_not_expired = plan_not_expired
        self.generation_match = generation_match
        self.config_hash_match = config_hash_match
        self.fusible_open = fusible_open
        self.rate_limit_ok = rate_limit_ok
        self.cooldown_ok = cooldown_ok
        self.auto_confirmed = auto_confirmed
        self._decision = None

    def evaluate(self):
        if self._decision is None:
            self._decision = self._compute()
        return self._decision

    def blocked_reasons(self):
        return self.evaluate()['blockedBy']

    def _feature_status(self, feature):
        if not self.release_capabilities.is_supported(feature):
            return 'unsupported'
        if not self.release_capabilities.is_released(feature):
            return 'unreleased'
        return 'released'

    def _compute(self):
        if self.mode == 'safe-disabled':
            return self._result(False, False, False, False, False, 'disabled',
                                ['mode_safe_disabled'])
        if self.mode == 'observe-only':
            return self._result(True, False, False, False, False, 'observe',
                                ['mode_observe_only'])
        return self._compute_normal()

    def _compute_normal(self):
        blocked = []

        health_ready = self.health.get('status') == 'ready'
        if not health_ready:
            blocked.append('health_not_ready')
        if self.recovery_required:
            blocked.append('recovery_required')
        if not self.observation_integrity_valid:
            blocked.append('observation_integrity_invalid')
        if not self.timeline_integrity_valid:
            blocked.append('timeline_integrity_invalid')

        need_route_assist = self.configured_stage in ('assist', 'auto')
        need_bounded_auto = self.configured_stage == 'auto'

        route_assist = self._feature_status('routeAssist')
        bounded_auto = self._feature_status('boundedAuto')

        if need_route_assist and route_assist != 'released':
            blocked.append('feature_not_released' if route_assist == 'unreleased'
                           else 'feature_not_supported')
        if need_bounded_auto and bounded_auto != 'released':
            blocked.append('feature_not_released' if bounded_auto == 'unreleased'
                           else 'feature_not_supported')

        if need_route_assist or need_bounded_auto:
            if not self.plan_valid:
                blocked.append('plan_invalid')
            if not self.plan_not_expired:
                blocked.append('plan_expired')
            if not self.generation_match:
                blocked.append('generation_mismatch')
            if not self.config_hash_match:
                blocked.append('config_hash_mismatch')

        if need_bounded_auto:
            if not self.observation_fresh:
                blocked.append('observation_stale')
            if not self.fusible_open:
                blocked.append('fusible_closed')
            if not self.rate_limit_ok:
                blocked.append('rate_limited')
            if not self.cooldown_ok:
                blocked.append('in_cooldown')
            # Auto requires an explicit human confirmation of auto intent. A
            # stale auto preference (e.g. saved while the feature was locked)
            # must never silently re-enable auto when a future release opens
            # the gate.
            if not self.auto_confirmed:
                blocked.append('auto_requires_confirmation')

        plan_gates_ok = (self.plan_valid and self.plan_not_expired
                         and self.generation_match and self.config_hash_match)
        can_plan = (health_ready and not self.recovery_required
                    and self.observation_integrity_valid
                    and self.timeline_integrity_valid)
        manual_gates_ok = (route_assist == 'released'
                           and self.configured_stage in ('assist', 'auto')
                           and can_plan and plan_gates_ok)
        auto_gates_ok = (bounded_auto == 'released'
                         and self.configured_stage == 'auto'
                         and can_plan and plan_gates_ok
                         and self.observation_fresh
                         and self.fusible_open
                         and self.rate_limit_ok
                         and self.cooldown_ok
                         and self.auto_confirmed)

        can_manual_approve = manual_gates_ok
        can_manual_apply = manual_gates_ok
        can_auto_apply = auto_gates_ok

        if can_auto_apply:
            effective_stage = 'auto'
        elif can_manual_apply:
            effective_stage = 'assist'
        else:
            effective_stage = 'observe'

        any_feature_available = (route_assist != 'unsupported'
                                 or bounded_auto != 'unsupported')
        shadow_would_apply = (not self.recovery_required and health_ready
                              and self.observation_integrity_valid
                              and self.timeline_integrity_valid
                              and any_feature_available)

        return self._result(can_plan, can_manual_approve, can_manual_apply,
                            can_auto_apply, shadow_would_apply, effective_stage,
                            blocked)

    @staticmethod
    def _result(can_plan, can_manual_approve, can_manual_apply, can_auto_apply,
                shadow_would_apply, effective_stage, blocked):
        return {
            'canPlan': can_plan,
            'canManualApprove': can_manual_approve,
            'canManualApply': can_manual_apply,
            'canAutoApply': can_auto_apply,
            'shadowWouldApply': shadow_would_apply,
            'effectiveStage': effective_stage,
            'blockedBy': blocked,
        }
