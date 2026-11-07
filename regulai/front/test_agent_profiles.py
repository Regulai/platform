"""Synthetic profile/budget tests; SDK transport tests live in test_connectors."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase
from pydantic import ValidationError

from front.agents.capabilities import Limits, limits
from front.agents.inference_options import resolve_inference, options_for_call
from front.agents.service import AgentDenied


class ProfileTests(SimpleTestCase):
    def setup_profile(self, dialect='deepseek', connector='openai_compatible'):
        config = {'dialect': dialect, 'model_id': 'synthetic-model',
            'profiles': ['legacy', 'quick', 'reasoned'], 'thinking_modes': ['off', 'on'],
            'efforts': ['none', 'high'] if dialect == 'openai' else ['high']}
        profile = SimpleNamespace(limits={'inference': config, 'work_profiles': True},
            connection=SimpleNamespace(engine=SimpleNamespace(connector_type=connector)))
        model = SimpleNamespace(model_id='synthetic-model', max_tokens=8192, reasoning=False)
        cfg = SimpleNamespace(limits=SimpleNamespace(provider_managed=True),
            routing=SimpleNamespace(max_output_tokens=6000))
        return profile, model, cfg

    def test_legacy_is_unchanged_and_new_profiles_require_explicit_permission(self):
        profile, model, cfg = self.setup_profile()
        profile.limits = {}
        snapshot = resolve_inference(profile, model, cfg)
        self.assertEqual(snapshot['profile'], 'legacy')
        self.assertIsNone(snapshot['options']['max_output_tokens'])
        self.assertIsNone(options_for_call(snapshot))
        with self.assertRaises(AgentDenied):
            resolve_inference(profile, model, cfg, 'quick')

    def test_reasoned_is_bounded_and_tool_phase_quick_without_mutating_preferences(self):
        profile, model, cfg = self.setup_profile()
        previous = deepcopy(profile.limits)
        snapshot = resolve_inference(profile, model, cfg, 'reasoned')
        self.assertEqual(options_for_call(snapshot)['max_output_tokens'], 6000)
        self.assertEqual(options_for_call(snapshot)['thinking_mode'], 'on')
        self.assertEqual(options_for_call(snapshot, tools=True)['thinking_mode'], 'off')
        self.assertEqual(options_for_call(snapshot, tools=True)['max_output_tokens'], 4096)
        self.assertEqual(previous, profile.limits)
        self.assertTrue(cfg.limits.provider_managed)

    def test_unknown_dialect_changed_model_or_connector_reject_before_transport(self):
        profile, model, cfg = self.setup_profile()
        model.model_id = 'different-model'
        with self.assertRaises(AgentDenied):
            resolve_inference(profile, model, cfg, 'quick')
        model.model_id = 'synthetic-model'
        profile.connection.engine.connector_type = 'openai'
        with self.assertRaises(AgentDenied):
            resolve_inference(profile, model, cfg, 'quick')
        profile.limits['inference']['dialect'] = 'unknown'
        with self.assertRaises(ValidationError):
            resolve_inference(profile, model, cfg, 'quick')

    def test_administrative_minimum_stays_and_effective_task_budget_can_be_lower(self):
        from front.agents.capabilities import resolve_work, execution_limits
        profile, _, _ = self.setup_profile()
        with self.assertRaises(ValidationError):
            Limits(model_calls=3)
        budget, work = resolve_work(profile, {}, 'Capital de España', 'quick')
        self.assertEqual((budget['model_calls'], budget['tool_calls'], budget['run_seconds']), (3, 4, 60))
        self.assertEqual(work['name'], 'text')
        run = SimpleNamespace(job={'limits': budget, 'work_profile': work})
        profile.limits['model_calls'] = 200
        self.assertEqual(execution_limits(run, profile)['model_calls'], 3)

    def test_work_profiles_are_opt_in_and_intent_never_increases_administrative_caps(self):
        from front.agents.capabilities import resolve_work
        profile, _, _ = self.setup_profile()
        profile.limits.update(model_calls=4, tool_calls=8, run_seconds=60, command_seconds=5)
        budget, work = resolve_work(profile, {}, 'Simula Monte Carlo', 'quick')
        self.assertEqual(work['name'], 'calculation')
        self.assertEqual((budget['model_calls'], budget['tool_calls'], budget['command_seconds']), (4, 8, 5))
        profile.limits['work_profiles'] = False
        budget, work = resolve_work(profile, {}, 'Simula Monte Carlo', 'quick')
        self.assertEqual(work['name'], 'legacy')
        self.assertEqual(budget, limits(profile))
        profile.limits['work_profiles'] = True
        self.assertEqual(resolve_work(profile, {'operation': 'download'}, '', 'quick')[1]['name'], 'download')
        self.assertEqual(resolve_work(profile, {'delivery_required': True}, '', 'quick')[1]['name'], 'files')
        self.assertEqual(resolve_work(profile, {'research_required': True}, '', 'quick')[1]['name'], 'research')

    def test_remaining_uses_active_start_and_call_timeout_even_provider_managed(self):
        from front.agents.capabilities import resolve_work, remaining_seconds, call_timeout
        profile, _, _ = self.setup_profile()
        budget, work = resolve_work(profile, {}, 'Capital', 'quick')
        now = datetime(2026, 10, 16, tzinfo=timezone.utc)
        run = SimpleNamespace(job={'limits': budget, 'work_profile': work},
            started_at=now - timedelta(seconds=55), created_at=now - timedelta(minutes=4))
        self.assertEqual(remaining_seconds(run, profile, now=now), 5)
        self.assertEqual(call_timeout(run, profile, configured=30, now=now), 5)
        with self.assertRaises(AgentDenied):
            call_timeout(run, profile, configured=None, now=now + timedelta(seconds=5))
