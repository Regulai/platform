"""Shared, current authorization and durable call accounting; no routing policy."""
from copy import deepcopy
from decimal import Decimal
import math
import time

from .models import CompanyEngine, EngineModel, ObfuscationConfig, Profile
from .policy import digest, evaluate_policy
from .masking import mask_identity, valid_masks, mask_cost_bounds, mask_texts
from .routing import actual_cost


class PipelineStop(Exception):
    def __init__(self, code, status='validation_error'):
        self.code, self.status = code, status


def observe_completed_calls(prompt, *, terminal=False):
    """Report persisted metadata once; external observers never receive content."""
    observer = getattr(prompt, '_call_observer', None)
    if observer is None:
        return
    for item in prompt._observer_tokens:
        call, token, observed = item
        if not observed and (terminal or call['status'] != 'started'):
            item[2] = True
            observer.after_call(deepcopy(call), token)


def destination_identity(engine, model):
    return digest([engine.engine.connector_type, engine.engine.base_url, digest(engine.api_key),
        model.model_id, model.context_window, model.max_tokens, model.supports_json, model.supports_vision, getattr(model, 'reasoning', False),
        str(model.input_price), str(model.output_price), model.currency, str(model.price_date)])


class GovernedCalls:
    def __init__(self, actor, prompt, profile, cfg, decision, destinations, rows,
                 masks, history, *, consent_accepted=False, authorize=None, call_context=None):
        self.actor, self.prompt, self.cfg = actor, prompt, cfg
        self.decision, self.destinations, self.rows = decision, destinations, rows
        self.sensitivity, self.consent_accepted = decision.sensitivity, consent_accepted
        self.provider_managed = cfg.limits.provider_managed
        self.deadline = prompt._started + cfg.limits.deadline_seconds
        self.budget = Decimal(cfg.limits.budget) if cfg.limits.budget is not None else None
        self.initial_company_id, self.initial_department_id = profile.company_id, profile.department_id
        self.initial_context = digest([profile.company.system_prompt, profile.department.system_prompt if profile.department else None])
        self.initial_history = digest([(m.role, m.content) for m in history])
        self.identities = {key: destination_identity(engine, model) for key, (engine, model, _) in rows.items()}
        self.mask_identities = {m.pk: mask_identity(m) for m in masks}
        self.jev_identity = digest(profile.company.jev_api_key)
        self.masks, self.authorize = masks, authorize
        self.call_context = call_context or {}
        self.mask_call = None

    def save_decision(self):
        self.prompt.save(update_fields=['decision', 'updated_at'])

    def protect_texts(self, texts, policy_texts):
        mask_bounds = mask_cost_bounds(self.masks, self.cfg.masking.max_call_cost)
        def before_mask(mask, value):
            self.mask_call = self.start_call('obfuscation', f'obfuscation:{mask.pk}', None,
                policy_texts + [('prompts', value)], mask_bounds[mask.pk], {}, transport=mask.backend)
            return self.mask_timeout(mask)

        def after_mask(mask):
            self.complete_call(*self.mask_call, None)

        return mask_texts(texts, self.masks, before_mask, after_mask)

    def mask_timeout(self, mask):
        return 10 if self.provider_managed and mask.backend == 'local' else self.remaining()

    def current_history(self):
        from .chat_service import authorized_history
        return authorized_history(self.actor, self.prompt.conversation)

    def remaining(self):
        if self.provider_managed:
            return None
        seconds = self.deadline - time.monotonic()
        if seconds <= 0:
            raise PipelineStop('deadline_exceeded')
        return min(seconds, self.cfg.limits.call_timeout_seconds)

    def spent_bound(self):
        values = [call.get('cost_exposure_bound', call.get('cost_bound')) for call in self.prompt.decision['calls']]
        if any(value is None for value in values):
            return None
        return sum((Decimal(value) for value in values), Decimal(0))

    def ensure_budget(self, cost, reserve=Decimal(0)):
        if self.budget is not None:
            spent = self.spent_bound()
            if cost is None or spent is None or reserve is None:
                raise PipelineStop('unknown_price')
            if spent + cost + reserve > self.budget:
                raise PipelineStop('budget_exhausted')

    def preflight(self, destination, texts, *, model_pk=None):
        from .chat_service import authorized_history
        self.remaining()
        if self.authorize is not None:
            self.authorize()
        fresh = Profile.objects.select_related('company', 'department', 'user').get(user=self.actor)
        if (not fresh.user.is_active or fresh.company_id != self.initial_company_id or fresh.department_id != self.initial_department_id
                or digest([fresh.company.system_prompt, fresh.department.system_prompt if fresh.department else None]) != self.initial_context):
            raise PipelineStop('authorization_changed')
        self.actor.profile = fresh
        active_masks = list(ObfuscationConfig.objects.filter(company_id=self.initial_company_id, active=True))
        if (not valid_masks(active_masks)
                or {mask.pk: mask_identity(mask) for mask in active_masks} != self.mask_identities):
            raise PipelineStop('authorization_changed')
        if digest([(m.role, m.content) for m in self.current_history()]) != self.initial_history:
            raise PipelineStop('authorization_changed')
        check = evaluate_policy(self.actor, texts, destinations=[destination], sensitivity=self.sensitivity)
        if (check.fingerprint != self.decision.fingerprint or check.status not in ('allow', 'consent_required')
                or destination not in self.destinations or (check.status == 'consent_required' and (
                    not self.consent_accepted or not {r['id'] for r in check.rules}.issubset({r['id'] for r in self.decision.rules})))):
            raise PipelineStop('security_check_failed')
        if destination == 'jev' and digest(fresh.company.jev_api_key) != self.jev_identity:
            raise PipelineStop('authorization_changed')
        if destination.startswith('engine:'):
            linked_id = int(destination.split(':', 1)[1])
            expected = self.rows.get((linked_id, model_pk))
            if expected is None:
                raise PipelineStop('authorization_changed')
            original_engine = expected[0]
            fresh_engine = CompanyEngine.objects.filter(pk=linked_id, company_id=self.initial_company_id,
                active=True).select_related('engine').first()
            fresh_model = EngineModel.objects.filter(pk=model_pk, engine_id=original_engine.engine_id,
                active=True).first()
            if (not fresh_engine or not fresh_model or fresh_engine.engine_id != original_engine.engine_id
                    or destination_identity(fresh_engine, fresh_model) != self.identities[(linked_id, model_pk)]):
                raise PipelineStop('authorization_changed')
        if destination.startswith('obfuscation:'):
            mask_id = int(destination.split(':', 1)[1])
            mask = ObfuscationConfig.objects.filter(pk=mask_id, company_id=self.initial_company_id, active=True).first()
            if not mask or mask_identity(mask) != self.mask_identities[mask_id]:
                raise PipelineStop('authorization_changed')
        return fresh

    def start_call(self, purpose, destination, model, texts, cost_bound, prices, reserve=Decimal(0), *, model_pk=None, transport='http'):
        self.preflight(destination, texts, model_pk=model_pk)
        self.ensure_budget(cost_bound, reserve)
        call = {'purpose': purpose, 'provider': destination, 'model': model, 'status': 'started',
                'cost': None, 'cost_bound': str(cost_bound) if cost_bound is not None else None,
                'price_snapshot': prices, 'currency': 'USD', 'cost_kind': 'unknown', 'transport': transport}
        call.update(self.call_context)
        if transport == 'local':
            call.update(cost='0', cost_kind='configured_zero', cost_scope='api')
        self.prompt.decision['calls'].append(call)
        self.save_decision()
        if self.prompt._call_observer is not None:
            try:
                token = self.prompt._call_observer.before_call(deepcopy(call))
            except Exception:
                call.update(status='not_started', cost='0', cost_kind='not_incurred', cost_exposure_bound='0')
                self.save_decision()
                raise PipelineStop('external_budget_unavailable') from None
            self.prompt._observer_tokens.append([call, token, False])
            try:
                # An external reserve can wait on shared state. Its return is not
                # evidence that company authorization remained unchanged.
                self.preflight(destination, texts, model_pk=model_pk)
            except PipelineStop:
                call.update(status='not_started', cost='0', cost_kind='not_incurred', cost_exposure_bound='0')
                self.save_decision()
                raise
        self.prompt._call_started = time.monotonic()
        return call, self.prompt._call_started

    def complete_call(self, call, started, result):
        call.update(status='completed', duration_ms=round((time.monotonic() - started) * 1000))
        if result is not None:
            cost = actual_cost(call['price_snapshot'], result.input_tokens, result.output_tokens)
            call.update(model_effective=getattr(result, 'model', None) or getattr(result, 'effective_model', None),
                        input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                        cost=str(cost) if cost is not None else None,
                        cost_kind='tariff_estimate' if cost is not None else 'unknown',
                        provider_request_id=getattr(result, 'provider_request_id', None) or getattr(result, 'request_id', None))
            # Retain normalized categories, not arbitrary provider strings or response content.
            call['usage'] = {k: v for k, v in result.usage.items() if isinstance(v, (int, float))
                             and not isinstance(v, bool) and math.isfinite(v) and 0 <= v <= 1_000_000_000}
            gateway = getattr(result, 'provider_metadata', {}).get('gateway', {})
            if 'cost' in gateway:
                call['cost'] = gateway['cost']
                call['cost_kind'] = 'provider_reported'
            if call['cost'] is not None and call['cost_bound'] is not None and Decimal(call['cost']) > Decimal(call['cost_bound']):
                call['cost_exposure_bound'] = call['cost']
                self.save_decision()
                raise PipelineStop('budget_bound_exceeded')
        elif call['purpose'] == 'obfuscation' and call['cost_bound'] is not None and Decimal(call['cost_bound']) == 0:
            call['cost'] = '0'
            call['cost_kind'] = 'configured_zero'
        self.save_decision()
        observe_completed_calls(self.prompt)
        self.remaining()

