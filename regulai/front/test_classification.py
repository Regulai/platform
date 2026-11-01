"""Classification contracts using synthetic provider answers only."""
import json
import copy
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.test import SimpleTestCase

from front import test_policy_simulator
from front.policy import AIConfig
from front.classification import decide
from front.models import CompanyEngine, Engine, EngineModel, ObfuscationConfig
from front.test_chat_flow import ChatFixture, mask_response
from front.test_pipeline import PipelineTests


def provider_response(payload):
    return SimpleNamespace(status_code=200, headers={}, close=lambda: None,
        iter_content=lambda **kwargs: iter([json.dumps(payload).encode()]))


def classification_transport(payload):
    def transport(*args, **kwargs):
        url = kwargs.pop('url', None) or args[0]
        return mask_response(url, **kwargs) if url.endswith('/api/mask') else provider_response(payload)
    return transport


def answers():
    return json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))['answers']


class OrdinalClassificationTests(SimpleTestCase):
    def test_tail_mass_selects_lowest_safe_level_at_point_two_boundary(self):
        signals = answers()
        signals['category'].update(choice='public', confidence=0.8,
            probabilities={'public': 0.8, 'internal': 0.0, 'confidential': 0.0,
                'restricted': 0.0, 'unknown': 0.2})
        decision = decide(signals, AIConfig(), 'public')
        self.assertEqual(decision.sensitivity, 'public')
        self.assertIsNone(decision.stop_code)
        signals['category']['probabilities'].update(public=0.7999995, unknown=0.2000005)
        signals['category']['confidence'] = 0.79
        self.assertEqual(decide(signals, AIConfig(), 'public').sensitivity, 'confidential')

    def test_unknown_mass_is_configurable_and_local_floor_never_drops(self):
        signals = answers()
        signals['category'].update(choice='unknown', confidence=1.0,
            probabilities={'public': 0.0, 'internal': 0.0, 'confidential': 0.0,
                'restricted': 0.0, 'unknown': 1.0})
        decision = decide(signals, AIConfig(), 'internal')
        self.assertEqual(decision.sensitivity, 'confidential')
        self.assertEqual(decision.notices, ['classification_ambiguous'])
        cfg = AIConfig.model_validate({'classification_policy': {'unknown_level': 'internal'}})
        self.assertEqual(decide(signals, cfg, 'confidential').sensitivity, 'confidential')
        restricted = decide(signals, cfg, 'restricted')
        self.assertEqual((restricted.sensitivity, restricted.stop_code), ('restricted', 'restricted_content'))

    def test_sensitive_signals_restrict_from_point_two(self):
        for key, sensitivity in (('personal_data', 'confidential'), ('business_confidential', 'confidential'),
                                 ('credentials', 'restricted')):
            with self.subTest(signal=key):
                signals = answers()
                signals[key]['noul'] = 0.2
                decision = decide(signals, AIConfig(), 'internal')
                self.assertEqual(decision.sensitivity, sensitivity)
                self.assertEqual(decision.stop_code, 'restricted_content' if key == 'credentials' else None)
                signals[key]['noul'] = 0.199
                self.assertEqual(decide(signals, AIConfig(), 'internal').sensitivity, 'internal')
        signals = answers()
        signals['personal_data']['noul'] = 0.75
        self.assertEqual(decide(signals, AIConfig(), 'restricted').sensitivity, 'restricted')

    def test_uncertain_task_and_difficulty_use_conservative_defaults_and_plausible_tasks(self):
        signals = answers()
        signals['task'].update(confidence=0.4, choice='summary',
            probabilities={'summary': 0.6, 'document_question': 0.4, 'general': 0.0, 'extraction': 0.0})
        signals['difficulty'].update(confidence=0.5, choice='balanced',
            probabilities={'economy': 0.4, 'balanced': 0.6, 'strong': 0.0})
        signals['ambiguous']['noul'] = 0.2
        signals['insufficient_evidence']['noul'] = 0.2
        decision = decide(signals, AIConfig(), 'internal')
        self.assertEqual((decision.task, decision.difficulty), ('general', 'strong'))
        self.assertEqual(decision.plausible_tasks, ['summary', 'document_question'])
        self.assertEqual(decision.notices, ['task_ambiguous', 'difficulty_ambiguous',
            'clarification_required', 'insufficient_evidence'])
        self.assertIsNone(decision.stop_code)
        cfg = AIConfig.model_validate({'classification_policy': {'on_ambiguity': 'stop'}})
        self.assertEqual(decide(signals, cfg, 'internal').stop_code, 'classification_ambiguous')

    def test_manipulation_has_its_own_block_code(self):
        signals = answers()
        signals['manipulation']['noul'] = 0.2
        decision = decide(signals, AIConfig(), 'internal')
        self.assertEqual((decision.stop_code, decision.stop_status), ('classification_manipulation', 'blocked'))

    def test_incoherent_answers_fail_closed(self):
        original = answers()
        mutations = [
            lambda value: value['category'].update(confidence=0.99),
            lambda value: value['category']['probabilities'].update(public=0.5),
            lambda value: value['task'].update(choice='invalid'),
            lambda value: value['difficulty'].update(confidence=float('nan')),
            lambda value: value['credentials'].update(noul=True),
            lambda value: value['credentials'].update(noul=float('inf')),
            lambda value: value.pop('ambiguous'),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                signals = copy.deepcopy(original)
                mutate(signals)
                decision = decide(signals, AIConfig(), 'internal')
                self.assertEqual((decision.stop_code, decision.stop_status), ('security_check_failed', 'validation_error'))


class ClassificationConfigTests(SimpleTestCase):
    def test_shared_configuration_has_conservative_defaults(self):
        config = AIConfig.model_validate({}).model_dump()
        self.assertEqual(config['classification_policy'], {
            'unknown_level': 'confidential', 'signal_threshold': 0.2,
            'manipulation_threshold': None, 'on_ambiguity': 'warn'})
        self.assertEqual(config['masking'], {'max_call_cost': None})
        self.assertEqual(config['history'], {'max_turns': 20, 'max_bytes': 32768})
        self.assertFalse(config['routing']['allow_cross_engine_fallback'])
        self.assertEqual(config['limits']['call_timeout_seconds'], 30)
        self.assertEqual(config['verification']['min_quote_chars'], 12)
        self.assertEqual(config['verification']['min_quote_words'], 3)

    def test_optional_configuration_is_strict_and_timeouts_are_coherent(self):
        for value in (
            {'history': {'max_turns': '20'}}, {'history': {'max_bytes': -1}},
            {'classification_policy': {'unknown_level': 'unknown'}},
            {'classification_policy': {'signal_threshold': float('nan')}},
            {'classification_policy': {'on_ambiguity': 'ignore'}},
            {'masking': {'max_call_cost': '-1'}}, {'masking': {'max_call_cost': 0}},
            {'limits': {'deadline_seconds': 29, 'call_timeout_seconds': 30}},
            {'limits': {'deadline_seconds': 181}},
            {'limits': {'call_timeout_seconds': True}},
            {'routing': {'allow_cross_engine_fallback': 'false'}},
            {'verification': {'min_quote_chars': 0}}, {'verification': {'min_quote_words': 0}},
            {'classification_policy': {'unexpected': True}},
        ):
            with self.subTest(config=value), self.assertRaises(ValueError):
                AIConfig.model_validate(value)
        self.assertEqual(AIConfig.model_validate({'limits': {
            'deadline_seconds': 180, 'call_timeout_seconds': 180}}).limits.call_timeout_seconds, 180)

    def test_legacy_short_deadline_keeps_configuration_valid(self):
        cfg = AIConfig.model_validate({'limits': {'budget': '0.01', 'deadline_seconds': 5}})
        self.assertEqual(cfg.limits.call_timeout_seconds, 5)

    def test_prices_are_per_million_but_call_bounds_can_be_smaller(self):
        for field in ('input_price', 'output_price'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                AIConfig.model_validate({'jev': {field: '0.000001'}})
        config = AIConfig.model_validate({'jev': {'input_price': '0', 'output_price': '0.0001',
            'max_call_cost': '0.000001'}, 'masking': {'max_call_cost': '0.000001'}})
        self.assertEqual(config.jev.input_price, '0')
        self.assertEqual(config.masking.max_call_cost, '0.000001')

    def test_budgeted_masking_needs_an_explicit_bound(self):
        config = {'limits': {'budget': '1'}, 'destinations': {'internal': ['obfuscation:1']}}
        with self.assertRaises(ValueError):
            AIConfig.model_validate(config)
        config['masking'] = {'max_call_cost': '0'}
        self.assertEqual(AIConfig.model_validate(config).masking.max_call_cost, '0')


class ClassificationSimulatorTests(TestCase):
    setUp = test_policy_simulator.PolicySimulatorTests.setUp
    command = test_policy_simulator.PolicySimulatorTests.command

    def test_real_distribution_is_conservatively_confidential(self):
        self.company.ai_config.update(classification='required',
            destinations={level: ['jev', f'obfuscation:{self.mask.pk}'] for level in ('internal', 'confidential')},
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '0.002'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['category'].update(confidence=0.49, probabilities={
            'public': 0.14, 'internal': 0.59, 'unknown': 0.22,
            'confidential': 0.05, 'restricted': 0.0})
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)) as network:
            result = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(result.status_code, 200)
        comparison = result.context['comparison']
        self.assertEqual(comparison['current']['policy']['status'], 'allow')
        self.assertEqual(comparison['current']['policy']['sensitivity'], 'confidential')
        self.assertEqual(comparison['semantic']['status'], 'completed')
        self.assertEqual(network.call_count, 2)
        self.assertTrue(network.call_args_list[0].kwargs['url'].endswith('/api/mask'))

    def test_active_mask_without_a_bound_is_rejected_before_semantic_calls(self):
        self.company.ai_config.pop('masking')
        self.company.ai_config.update(limits={'budget': '1'})
        self.company.save()
        with patch('requests.sessions.Session.request') as network:
            result = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(result.status_code, 400)
        network.assert_not_called()

    def test_bounded_draft_cannot_authorize_semantics_with_unbounded_active_mask_policy(self):
        self.company.ai_config.pop('masking')
        self.company.ai_config.update(classification='required',
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '1'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        proposed = dict(self.company.ai_config, masking={'max_call_cost': '0'})
        with patch('requests.sessions.Session.request', return_value=test_policy_simulator.jev_response()) as network:
            result = self.client.post(self.url, self.command(mode='semantic', proposed_config=json.dumps(proposed)))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.context['comparison']['semantic']['status'], 'not_authorized')
        self.assertEqual(result.context['comparison']['semantic']['reason_codes'], ['policy_configuration_invalid'])
        network.assert_not_called()

    def test_semantic_simulator_never_sends_unmasked_content_to_jev(self):
        ObfuscationConfig.objects.create(company=self.company, name='Synthetic mask', api_url='https://mask.invalid')
        self.company.ai_config.update(classification='required', masking={'max_call_cost': '0'},
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '1'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        with patch('requests.sessions.Session.request', return_value=test_policy_simulator.jev_response()) as network:
            result = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.context['comparison']['semantic']['status'], 'not_authorized')
        self.assertEqual(result.context['comparison']['semantic']['reason_codes'], ['destination_not_allowed'])
        network.assert_not_called()

    def test_local_classification_ignores_semantic_category_for_routing(self):
        self.company.ai_config.update(classification='local',
            routing={'mode': 'auto'},
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '0.002'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        with patch('requests.sessions.Session.request', side_effect=test_policy_simulator.simulation_transport('restricted')):
            result = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(result.context['comparison']['semantic']['status'], 'blocked')
        self.assertEqual(result.context['comparison']['current']['policy']['sensitivity'], 'internal')
        self.assertEqual(result.context['comparison']['current']['policy']['status'], 'allow')

    def test_credentials_below_choice_threshold_still_block(self):
        self.company.ai_config.update(classification='required',
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '0.002'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['credentials']['noul'] = 0.75
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)) as network:
            result = self.client.post(self.url, self.command(mode='semantic'))
        policy = result.context['comparison']['current']['policy']
        self.assertEqual(policy['sensitivity'], 'restricted')
        self.assertEqual(policy['status'], 'block')
        self.assertEqual(policy['reason_codes'], ['restricted_content'])
        self.assertEqual(network.call_count, 2)
        self.assertTrue(network.call_args_list[0].kwargs['url'].endswith('/api/mask'))

    def route_catalogue(self):
        engine = Engine.objects.create(name='Classification route engine')
        credential = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        cheap = EngineModel.objects.create(engine=engine, name='Cheap', model_id='synthetic-cheap',
            context_window=20_000, max_tokens=2000, input_price='1', output_price='2')
        strong = EngineModel.objects.create(engine=engine, name='Strong', model_id='synthetic-strong',
            context_window=20_000, max_tokens=2000, input_price='10', output_price='20')
        self.company.ai_config.update(classification='required',
            destinations={'internal': ['jev', f'engine:{credential.pk}', f'obfuscation:{self.mask.pk}']},
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '1'}, routing={'candidates': [
                {'company_engine_id': credential.pk, 'model_id': cheap.pk, 'level': 'economy',
                 'quality': {'general': 1.0, 'summary': 0.1, 'document_question': 0.9}},
                {'company_engine_id': credential.pk, 'model_id': strong.pk, 'level': 'strong',
                 'quality': {'general': 0.9, 'summary': 0.9, 'document_question': 0.9}},
            ], 'min_quality': {'economy': 0.8, 'balanced': 0.8, 'strong': 0.8}})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        return credential, cheap, strong

    def test_uncertain_task_routes_by_lowest_quality_among_plausible_tasks(self):
        _, _, strong = self.route_catalogue()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['task'].update(confidence=0.4, choice='summary',
            probabilities={'summary': 0.6, 'document_question': 0.4, 'general': 0.0, 'extraction': 0.0})
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)):
            result = self.client.post(self.url, self.command(mode='semantic'))
        outcome = result.context['comparison']['current']
        self.assertEqual(outcome['task'], 'general')
        self.assertEqual(outcome['plausible_tasks'], ['summary', 'document_question'])
        self.assertEqual(outcome['route']['model'], strong.model_id)

    def test_single_plausible_task_retains_its_quality_requirement(self):
        _, _, strong = self.route_catalogue()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['task'].update(confidence=0.4, choice='summary',
            probabilities={'summary': 1.0, 'document_question': 0.0, 'general': 0.0, 'extraction': 0.0})
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)) as network:
            result = self.client.post(self.url, self.command(mode='semantic'))
        comparison = result.context['comparison']
        self.assertEqual(comparison['semantic']['status'], 'completed')
        for name in ('current', 'proposed'):
            outcome = comparison[name]
            self.assertEqual(outcome['task'], 'general')
            self.assertEqual(outcome['plausible_tasks'], ['summary'])
            self.assertEqual(outcome['route']['model'], strong.model_id)
        self.assertEqual(network.call_count, 2)
        self.assertTrue(network.call_args_list[0].kwargs['url'].endswith('/api/mask'))

    def test_unmeasured_plausible_task_quality_cannot_route_even_at_zero_minimum(self):
        self.route_catalogue()
        self.company.ai_config['routing']['min_quality'] = {'economy': 0.0, 'balanced': 0.0, 'strong': 0.0}
        for candidate in self.company.ai_config['routing']['candidates']:
            candidate['quality'].pop('summary')
        self.company.save()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['task'].update(confidence=0.4, choice='summary',
            probabilities={'summary': 0.6, 'document_question': 0.4, 'general': 0.0, 'extraction': 0.0})
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)):
            result = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(result.context['comparison']['current']['route']['reason_codes'], ['quality_unavailable'])

    def test_incoherent_confidence_fails_closed_in_http_simulation(self):
        self.route_catalogue()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['category']['confidence'] = 0.99
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)):
            result = self.client.post(self.url, self.command(mode='semantic'))
        outcome = result.context['comparison']['current']
        self.assertEqual(outcome['policy']['status'], 'unavailable')
        self.assertEqual(outcome['policy']['allowed_destinations'], [])
        self.assertEqual(outcome['policy']['reason_codes'], ['security_check_failed'])

    def test_manipulation_is_distinct_from_ambiguity_in_http_simulation(self):
        self.route_catalogue()
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['manipulation']['noul'] = 0.75
        with patch('requests.sessions.Session.request', side_effect=classification_transport(payload)):
            result = self.client.post(self.url, self.command(mode='semantic'))
        outcome = result.context['comparison']['current']
        self.assertEqual(outcome['policy']['status'], 'block')
        self.assertEqual(outcome['policy']['reason_codes'], ['classification_manipulation'])

    def test_semantic_classification_never_adds_a_destination(self):
        credential, _, _ = self.route_catalogue()
        self.company.ai_config['destinations'] = {'internal': ['jev', f'obfuscation:{self.mask.pk}'],
            'confidential': ['jev', f'engine:{credential.pk}', f'obfuscation:{self.mask.pk}']}
        self.company.save()
        with patch('requests.sessions.Session.request', side_effect=test_policy_simulator.simulation_transport('confidential')):
            result = self.client.post(self.url, self.command(mode='semantic'))
        outcome = result.context['comparison']['current']
        self.assertEqual(outcome['policy']['allowed_destinations'], ['jev', f'obfuscation:{self.mask.pk}'])
        self.assertEqual(outcome['route']['status'], 'unavailable')
        self.assertEqual(outcome['route']['reason_codes'], ['no_authorized_candidates'])


class ClassificationChatTests(ChatFixture):
    configure = PipelineTests.configure

    def test_single_plausible_task_cannot_borrow_general_quality(self):
        payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
        payload['answers']['task'].update(confidence=0.4, choice='summary',
            probabilities={'summary': 1.0, 'document_question': 0.0, 'general': 0.0, 'extraction': 0.0})
        for quality, minimum in (({'general': 0.9, 'summary': 0.1}, 0.8), ({'general': 0.9}, 0.0)):
            self.configure(verification={'mode': 'local'}, routing={'mode': 'auto', 'candidates': [{
                'company_engine_id': self.credential.pk, 'model_id': self.model.pk,
                'level': 'economy', 'quality': quality}],
                'min_quality': {'economy': minimum, 'balanced': minimum, 'strong': minimum}})
            self.http.side_effect = classification_transport(payload)
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(path=path, quality=quality):
                    self.provider.reset_mock()
                    self.http.reset_mock()
                    response = self.send(path, 'Summarize the synthetic sentence.', auto_route='true')
                    self.provider.assert_not_called()
                    result = response.json()
                    self.assertEqual(result['error_type'], 'quality_unavailable')
                    self.assertEqual(self.http.call_count, 2)
                    self.assertEqual([call['purpose'] for call in result['receipt']['calls']], ['obfuscation', 'classification'])
                    self.assertEqual(result['receipt']['total']['attempts'], 0)

    def test_every_ambiguity_notice_instructs_the_generator_to_clarify_if_needed(self):
        self.configure(verification={'mode': 'local'}, destinations={
            'internal': ['jev', f'engine:{self.credential.pk}'],
            'confidential': ['jev', f'engine:{self.credential.pk}']})
        cases = [
            ('category', 'classification_ambiguous', {'choice': 'internal', 'confidence': 0.49,
                'probabilities': {'public': 0.14, 'internal': 0.59, 'unknown': 0.22,
                    'confidential': 0.05, 'restricted': 0.0}}),
            ('task', 'task_ambiguous', {'choice': 'summary', 'confidence': 0.4,
                'probabilities': {'summary': 1.0, 'document_question': 0.0, 'general': 0.0, 'extraction': 0.0}}),
            ('difficulty', 'difficulty_ambiguous', {'choice': 'economy', 'confidence': 0.4,
                'probabilities': {'economy': 1.0, 'balanced': 0.0, 'strong': 0.0}}),
            ('ambiguous', 'clarification_required', {'noul': 0.2}),
            ('insufficient_evidence', 'insufficient_evidence', {'noul': 0.2}),
        ]
        for key, notice, values in cases:
            payload = json.loads(next(test_policy_simulator.jev_response().iter_content(8192)))
            payload['answers'][key].update(values)
            self.http.side_effect = classification_transport(payload)
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(path=path, notice=notice):
                    self.provider.reset_mock()
                    response = self.send(path, 'Synthetic instruction test')
                    self.assertEqual(response.status_code, 302 if path == '/chat/' else 200)
                    if path != '/chat/':
                        self.assertIn(notice, response.json()['receipt']['notices'])
                    messages = self.provider.call_args.args[0]
                    instruction = '\n'.join(message.content for message in messages if message.role == 'system')
                    self.assertIn('State uncertainty', instruction)
                    self.assertIn('ask for clarification where needed', instruction)
                    self.assertIn('do not invent missing facts', instruction)
