import time


class RoutePolicy:
    """Fail-closed route execution policy.

    Every safety parameter is REQUIRED or defaults to False. A missing safety
    input (plan validity, generation/hash/epoch match, fuse, rate, cooldown,
    auto confirmation, risk eligibility) can never widen the apply window: the
    default is always "not proven -> blocked". Callers that genuinely hold a
    proven value pass it explicitly.
    """

    def __init__(self, mode, configured_stage, release_capabilities, health,
                 recovery_required, observation_fresh, observation_integrity_valid,
                 timeline_integrity_valid, plan_valid=False, plan_not_expired=False,
                 generation_match=False, config_hash_match=False,
                 execution_epoch_match=False, fusible_open=False,
                 rate_limit_ok=False, cooldown_ok=False, auto_confirmed=False,
                 risk_auto_eligible=False, auto_allowlisted_op=False):
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
        self.execution_epoch_match = execution_epoch_match
        self.fusible_open = fusible_open
        self.rate_limit_ok = rate_limit_ok
        self.cooldown_ok = cooldown_ok
        self.auto_confirmed = auto_confirmed
        self.risk_auto_eligible = risk_auto_eligible
        self.auto_allowlisted_op = auto_allowlisted_op
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
            # Root-side execution authorization: the request must match the
            # CURRENT root execution epoch, never a stale one (§12/§13).
            if not self.execution_epoch_match:
                blocked.append('execution_epoch_mismatch')

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
            # Auto V1 risk/op allowlist: only low-risk, allowlisted
            # operations may ever auto-apply; the root executor re-evaluates
            # this independently (§19).
            if not self.risk_auto_eligible:
                blocked.append('auto_risk_not_eligible')
            if not self.auto_allowlisted_op:
                blocked.append('auto_op_not_allowlisted')

        plan_gates_ok = (self.plan_valid and self.plan_not_expired
                         and self.generation_match and self.config_hash_match
                         and self.execution_epoch_match)
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
                         and self.auto_confirmed
                         and self.risk_auto_eligible
                         and self.auto_allowlisted_op)

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


def evaluate_plan_policy(plan, apply_type, mode, configured_stage,
                         release_capabilities, health, recovery_required,
                         observation_fresh, observation_integrity_valid,
                         timeline_integrity_valid, current_generation,
                         current_config_sha256, current_execution_epoch,
                         auto_confirmed=False, risk_auto_eligible=False,
                         auto_allowlisted_op=False, fusible_open=False,
                         rate_limit_ok=False, cooldown_ok=False, now=None):
    """Concrete RoutePlan policy evaluation (§P0-1).

    RoutePolicy.evaluate() is a CAPABILITY-level evaluation: without a concrete
    plan it cannot (and must not) claim any particular plan may be applied, so
    canManualApply/canAutoApply stay False. This function is the CONCRETE
    evaluation: it computes the plan-specific gates from the actual plan body
    and the CURRENT root-authoritative state and returns the same decision
    shape as RoutePolicy.evaluate():

      plan schema valid (schemaVersion==1 + planSha256 present)
      planSha256 / operations digest are valid (checked by the caller)
      not expired
      current root-owned generation matches
      current live config SHA matches
      current root executionEpoch is valid
      mode / stage matches
      release gate matches
      health ready
      no unresolved recovery
      observation / timeline integrity
      manual / auto-specific gates

    routeApprove() must be authorized by THIS evaluation, never by a global
    capability status. The root executor still independently re-validates every
    key condition against the live root policy / live config (§16); a Runtime
    pass here only means "submittable", never final permission.
    """
    now = int(now if now is not None else time.time())

    # --- plan-specific facts (fail closed) -------------------------------
    plan_valid = (isinstance(plan, dict)
                  and plan.get('schemaVersion') == 1
                  and isinstance(plan.get('planSha256'), str)
                  and bool(plan.get('planSha256')))
    exp = plan.get('expiresAtEpochSeconds') if isinstance(plan, dict) else None
    plan_not_expired = isinstance(exp, int) and now <= exp
    generation_match = (isinstance(plan, dict)
                        and plan.get('configurationGeneration') == current_generation)
    config_hash_match = (isinstance(plan, dict)
                         and isinstance(plan.get('sourceConfigSha256'), str)
                         and bool(plan.get('sourceConfigSha256'))
                         and plan.get('sourceConfigSha256') == current_config_sha256)
    # The CURRENT root execution epoch must be a valid integer (the request
    # binds it; the root executor re-checks the exact value against the live
    # root policy). A missing/unavailable root projection fails closed.
    execution_epoch_match = (isinstance(current_execution_epoch, int)
                             and not isinstance(current_execution_epoch, bool)
                             and current_execution_epoch >= 0)

    policy = RoutePolicy(
        mode=mode,
        configured_stage=configured_stage,
        release_capabilities=release_capabilities,
        health=health,
        recovery_required=recovery_required,
        observation_fresh=observation_fresh,
        observation_integrity_valid=observation_integrity_valid,
        timeline_integrity_valid=timeline_integrity_valid,
        plan_valid=plan_valid,
        plan_not_expired=plan_not_expired,
        generation_match=generation_match,
        config_hash_match=config_hash_match,
        execution_epoch_match=execution_epoch_match,
        fusible_open=fusible_open,
        rate_limit_ok=rate_limit_ok,
        cooldown_ok=cooldown_ok,
        auto_confirmed=auto_confirmed,
        risk_auto_eligible=risk_auto_eligible,
        auto_allowlisted_op=auto_allowlisted_op,
    )
    return policy.evaluate()
