"""Easy/hard routing at the three HTTP entries, with synthetic providers."""
from copy import deepcopy
from decimal import Decimal
import json
from unittest.mock import patch
import httpx

from django.test import SimpleTestCase, override_settings
from pydantic import ValidationError

from front import test_chat_flow, test_pipeline
from front.test_chat_island import bootstrap as island_bootstrap
from front.classification import difficulty_level
from front.models import EngineModel, Prompt
from front.policy import AIConfig
from front.test_local_masking import SCHEDULING_PROMPT, SCHEDULING_ANSWER


class DifficultyValidationTests(SimpleTestCase):
    def test_provider_limits_are_opt_in_and_cannot_claim_a_local_budget_ceiling(self):
        self.assertFalse(AIConfig().limits.provider_managed)
        with self.assertRaises(ValidationError):
            AIConfig(limits={'provider_managed': True, 'budget': '1'})

    def test_visible_cap_is_optional_and_bounded(self):
        self.assertIsNone(AIConfig().routing.max_response_bytes)
        for value in (0, -1, 128001, True, '8000'):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                AIConfig(routing={'max_response_bytes': value})

    def test_default_preserves_quality_and_difficulty_cannot_discard_quality_floor(self):
        self.assertEqual(AIConfig().routing.strategy, 'quality')
        with self.assertRaises(ValidationError):
            AIConfig(routing={'strategy': 'difficulty', 'min_quality': {
                'economy': 0, 'balanced': 0, 'strong': .9}})

    def test_uncertainty_uses_strong_and_malformed_output_is_rejected(self):
        answer = {'difficulty': {'type': 'choice', 'choice': 'easy', 'confidence': .8,
            'probabilities': {'easy': .8, 'hard': .2}}}
        self.assertEqual(difficulty_level(answer, .8), 'economy')
        answer['difficulty']['confidence'] = .79
        self.assertEqual(difficulty_level(answer, .8), 'strong')
        for invalid in (None, {}, {'difficulty': {'choice': 'engine:999'}},
                        {'difficulty': {**answer['difficulty'], 'confidence': float('nan')}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                difficulty_level(invalid, .8)


class DifficultyPipelineTests(test_chat_flow.ChatFixture):
    def setUp(self):
        super().setUp()
        test_pipeline.PipelineTests.configure(self, classification='local')
        self.pro = EngineModel.objects.create(engine=self.engine, name='Pro', model_id='synthetic-pro',
            context_window=32768, max_tokens=4096, supports_json=True,
            input_price=Decimal('3'), output_price=Decimal('6'))
        self.company.ai_config['routing'] = {'mode': 'auto', 'strategy': 'difficulty', 'candidates': [
            {'company_engine_id': self.credential.pk, 'model_id': self.model.pk, 'level': 'economy', 'quality': {}},
            {'company_engine_id': self.credential.pk, 'model_id': self.pro.pk, 'level': 'strong', 'quality': {}}]}
        self.company.save()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'easy'})

    def test_real_masker_preserves_task_and_answer_through_router_sdk_and_history(self):
        self.required_mask.backend = 'local'
        self.required_mask.save()
        self.company.ai_config['verification']['mode'] = 'local'
        self.company.save()
        evaluator = test_pipeline.jev_http(choices={'difficulty': 'hard'})
        def judge(url, **kwargs):
            self.assertFalse(url.endswith('/api/mask'))
            payload = json.loads(kwargs['data'])
            self.assertIn(SCHEDULING_PROMPT, json.dumps(payload, ensure_ascii=False))
            self.assertNotIn('[[REGULAI_', json.dumps(payload))
            return evaluator(url, **kwargs)
        self.http.side_effect = judge
        sent = []
        def respond(request):
            payload = json.loads(request.content)
            sent.append(payload)
            self.assertEqual(payload['model'], self.pro.model_id)
            self.assertEqual(payload['messages'][-1]['content'], SCHEDULING_PROMPT)
            self.assertNotIn('[[REGULAI_', json.dumps(payload))
            return httpx.Response(200, json={'id': 'preserved-task', 'model': payload['model'],
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': SCHEDULING_ANSWER},
                    'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 150, 'completion_tokens': 150, 'total_tokens': 300}})
        with patch('socket.socket.connect', side_effect=AssertionError('Live network forbidden')), patch(
                'front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), patch(
                'openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))):
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(path=path):
                    self.send(path, SCHEDULING_PROMPT, auto_route='true')
                    prompt = Prompt.objects.latest('pk')
                    self.assertEqual(prompt.status, 'completed', prompt.decision)
                    self.assertEqual(prompt.user_message.content, SCHEDULING_PROMPT)
                    self.assertEqual(prompt.response.content, SCHEDULING_ANSWER)
                    self.assertEqual([c['purpose'] for c in prompt.decision['calls']],
                        ['obfuscation', 'difficulty', 'generation', 'obfuscation'])
                    history_path = (path if path.startswith('/api/') else
                        f'/chat/{prompt.conversation_id}/' + ('send/' if path.endswith('send/') else ''))
                    self.send(history_path, SCHEDULING_PROMPT, auto_route='true', conversation_id=prompt.conversation_id)
                    self.assertEqual(Prompt.objects.latest('pk').status, 'completed')
                    self.assertIn(SCHEDULING_ANSWER, [m['content'] for m in sent[-1]['messages']])
        self.assertEqual(len(sent), 6)

    def test_provider_managed_limits_reach_sdk_and_jev_on_all_http_entries(self):
        self.company.ai_config['limits'] = {'provider_managed': True}
        self.company.save()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'hard'})
        clock = [100.0]
        body = 'Respuesta completa. ' * 6000
        captured = []
        def respond(request):
            payload = json.loads(request.content)
            captured.append(payload)
            self.assertNotIn('max_tokens', payload)
            self.assertNotIn('max_completion_tokens', payload)
            self.assertTrue(all(value is None for value in request.extensions['timeout'].values()))
            clock[0] += 10000  # Beyond both the old call and total request deadlines.
            return httpx.Response(200, json={'id': 'provider-defaults', 'model': payload['model'],
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': body}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 100, 'completion_tokens': 10000, 'total_tokens': 10100}})
        with patch('front.chat_service.time.monotonic', side_effect=lambda: clock[0]), patch(
                'front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), patch(
                'openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))):
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                self.http.reset_mock()
                self.send(path, auto_route='true')
                prompt = Prompt.objects.latest('pk')
                self.assertEqual(prompt.status, 'completed', prompt.decision)
                self.assertEqual(prompt.response.content, body)
                limits = prompt.decision['limits']
                self.assertTrue(limits['provider_managed'])
                for name in ('max_output_tokens', 'response_bytes', 'call_timeout_seconds', 'deadline_seconds', 'jev_state_bytes'):
                    self.assertIsNone(limits[name])
                self.assertEqual(prompt.decision['verification']['status'], 'passed')
                generation = next(c for c in prompt.decision['calls'] if c['purpose'] == 'generation')
                self.assertIsNone(generation['cost_bound'])
                self.assertEqual(Decimal(generation['cost']), Decimal('0.0603'))
                judge_calls = [c for c in self.http.call_args_list if c.kwargs.get('data')]
                self.assertEqual(len(judge_calls), 2)
                self.assertTrue(all(c.kwargs['timeout'] is None for c in judge_calls))
                self.assertEqual(json.loads(judge_calls[-1].kwargs['data'])['state']['response'], body)
        self.assertEqual(len(captured), 3)

    def test_provider_limits_do_not_disable_security_or_verification(self):
        self.company.ai_config['limits'] = {'provider_managed': True}
        self.company.save()
        self.assertTrue(island_bootstrap(self.client.get('/chat/'))['models']['provider_limits'])
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            self.assertContains(self.client.get('/chat/'), 'Límites del proveedor')
        self.send('/api/chat/send/', 'SYNTHETIC_SECRET')
        self.provider.assert_not_called()
        self.http.assert_not_called()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'hard'}, failures={'failure_omission': .9})
        rejected = self.send('/api/chat/send/').json()
        self.assertEqual(rejected['error_type'], 'verification_failed')
        self.assertNotIn('assistant_message', rejected)

    def test_local_verification_keeps_difficulty_but_never_calls_final_jev_for_text(self):
        self.company.ai_config['limits'] = {'provider_managed': True}
        self.company.ai_config['verification']['mode'] = 'local'
        self.company.save()
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            for choice, model in (('easy', self.model), ('hard', self.pro)):
                with self.subTest(path=path, choice=choice):
                    self.http.reset_mock()
                    self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': choice}, failures={'failure_contradiction': .99})
                    self.send(path, auto_route='true')
                    prompt = Prompt.objects.latest('pk')
                    self.assertEqual(prompt.status, 'completed', prompt.decision)
                    self.assertEqual(prompt.model_used, model.model_id)
                    self.assertEqual([c['purpose'] for c in prompt.decision['calls']],
                        ['obfuscation', 'difficulty', 'generation', 'obfuscation'])
                    self.assertEqual(prompt.decision['verification']['scope'], 'format_and_completion')
                    judged = [json.loads(c.kwargs['data']) for c in self.http.call_args_list if c.kwargs.get('data')]
                    self.assertEqual(len(judged), 1)
                    self.assertEqual(set(judged[0]['questions']), {'difficulty'})

    def test_easy_and_hard_choose_different_models_on_all_three_entries(self):
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            for choice, model, level in (('easy', self.model, 'economy'), ('hard', self.pro, 'strong')):
                with self.subTest(path=path, choice=choice):
                    self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': choice})
                    self.send(path, auto_route='true')
                    prompt = Prompt.objects.latest('pk')
                    self.assertEqual(prompt.status, 'completed', prompt.decision)
                    self.assertEqual(self.provider.call_args.kwargs['model'], model.model_id)
                    self.assertEqual(prompt.decision['route']['level'], level)
                    self.assertIsNone(prompt.decision['route']['quality'])
                    self.assertEqual(prompt.decision['route']['reason_codes'], ['difficulty_route'])
                    self.assertEqual([c['purpose'] for c in prompt.decision['calls']],
                        ['obfuscation', 'difficulty', 'generation', 'obfuscation', 'verification'])
                    self.assertEqual(prompt.decision['verification']['status'], 'passed')
                    self.assertEqual(prompt.decision['policy']['sensitivity'], 'internal')

    def test_real_sdk_serializes_selected_model_at_network_boundary(self):
        self.engine.connector_type = 'openai_compatible'
        self.engine.base_url = 'https://api.deepseek.com'
        self.engine.save()
        captured = []
        def respond(request):
            payload = json.loads(request.content)
            captured.append(payload)
            self.assertEqual(str(request.url), 'https://api.deepseek.com/chat/completions')
            return httpx.Response(200, json={'id': 'synthetic', 'model': payload['model'],
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'Respuesta de prueba'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 20, 'completion_tokens': 10, 'total_tokens': 30}})
        with patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), patch(
                'openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))):
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                for choice, model in (('easy', self.model), ('hard', self.pro)):
                    self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': choice})
                    self.send(path, auto_route='true')
                    self.assertEqual(Prompt.objects.latest('pk').status, 'completed')
                    self.assertEqual(captured[-1]['model'], model.model_id)
                    self.assertEqual(captured[-1]['max_tokens'], 1000)
            self.assertEqual(len(captured), 6)

    def test_reasoning_budget_is_separate_from_visible_answer_limit(self):
        self.pro.max_tokens = 8192
        self.pro.save()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'hard'})
        captured = []
        def respond(request):
            payload = json.loads(request.content)
            captured.append(payload)
            exhausted = payload['max_tokens'] == 1000
            return httpx.Response(200, json={'id': 'synthetic-reasoning', 'model': payload['model'],
                'choices': [{'index': 0, 'message': {'role': 'assistant',
                    'content': '' if exhausted else 'El tiempo mínimo es 5 horas; con la dependencia adicional, 6 horas.',
                    'reasoning_content': 'SYNTHETIC_PRIVATE_REASONING'},
                    'finish_reason': 'length' if exhausted else 'stop'}],
                'usage': {'prompt_tokens': 100, 'completion_tokens': 1000 if exhausted else 1400,
                    'total_tokens': 1100 if exhausted else 1500}})
        with patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), patch(
                'openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))):
            failed = self.send('/api/chat/send/', 'Calcula y demuestra el horario mínimo con dependencias.').json()
            self.assertEqual(failed['receipt']['verification']['finish_reason'], 'truncated')
            self.assertEqual(failed['status'], 'failed')
            self.assertIn('agotó el límite', failed['error'])
            self.assertNotIn('verification', [c['purpose'] for c in failed['receipt']['calls']])
            self.company.ai_config['routing'].update(max_output_tokens=8192, max_response_bytes=8000)
            self.company.save()
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                self.send(path, 'Calcula y demuestra el horario mínimo con dependencias.', auto_route='true')
                prompt = Prompt.objects.latest('pk')
                self.assertEqual(prompt.status, 'completed', prompt.decision)
                self.assertEqual(captured[-1]['max_tokens'], 8192)
                self.assertEqual(prompt.decision['limits']['response_bytes'], 8000)
                self.assertLess(prompt.decision['limits']['judge_input_bytes_bound'], 98304)
                self.assertEqual(prompt.decision['verification']['status'], 'passed')
                generation = next(c for c in prompt.decision['calls'] if c['purpose'] == 'generation')
                self.assertEqual(generation['output_tokens'], 1400)
                self.assertEqual(Decimal(generation['cost']), Decimal('0.0087'))
                judged = [json.loads(c.kwargs['data']) for c in self.http.call_args_list if c.kwargs.get('data')][-1]
                self.assertNotIn('SYNTHETIC_PRIVATE_REASONING', json.dumps(judged))

    def test_visible_cap_still_blocks_oversize_and_truncated_responses(self):
        self.pro.max_tokens = 8192
        self.pro.save()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'hard'})
        self.company.ai_config['routing'].update(max_output_tokens=8192, max_response_bytes=8000)
        self.company.save()
        from front.connectors import ChatResponse
        for content, finish, error in (('é' * 4000, 'stop', None),
                ('é' * 4000 + 'x', 'stop', 'evaluation_input_too_large'),
                ('', 'length', 'verification_failed')):
            with self.subTest(error=error):
                self.provider.return_value = ChatResponse(content, 1422, self.pro.model_id, finish, 422, 1000)
                result = self.send('/api/chat/send/').json()
                if error:
                    self.assertEqual(result['error_type'], error)
                    self.assertNotIn('assistant_message', result)
                else:
                    self.assertEqual(result['status'], 'completed', result)

    def test_reasoning_tokens_remain_in_cost_reserve_before_any_provider_call(self):
        self.pro.max_tokens = 8192
        self.pro.save()
        self.company.ai_config['routing'].update(max_output_tokens=8192, max_response_bytes=8000)
        self.company.ai_config['limits']['budget'] = '0.03'
        self.company.save()
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['error_type'], 'budget_exhausted', result)
        self.provider.assert_not_called()
        self.http.assert_not_called()

    def test_manual_selection_skips_difficulty_and_respects_model(self):
        self.send('/api/chat/send/', engine_id=self.credential.pk, model_id=self.pro.pk)
        prompt = Prompt.objects.latest('pk')
        self.assertEqual(prompt.status, 'completed', prompt.decision)
        self.assertEqual(self.provider.call_args.kwargs['model'], self.pro.model_id)
        self.assertNotIn('difficulty', [c['purpose'] for c in prompt.decision['calls']])
        self.assertEqual(prompt.decision['route']['mode'], 'manual')

    def test_local_denial_never_contacts_providers(self):
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            self.send(path, 'SYNTHETIC_SECRET', auto_route='true')
            self.assertEqual(Prompt.objects.latest('pk').status, 'blocked')
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_missing_pro_does_not_downgrade_hard_request_to_flash(self):
        self.pro.active = False
        self.pro.save()
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'hard'})
        self.send('/api/chat/send/')
        self.assertEqual(Prompt.objects.latest('pk').decision['error_type'], 'no_authorized_candidates')
        self.provider.assert_not_called()

    def test_unknown_price_or_missing_key_stops_before_any_call(self):
        original = deepcopy(self.company.ai_config)
        self.company.ai_config['jev']['max_call_cost'] = None
        self.company.save()
        self.send('/api/chat/send/')
        self.assertEqual(Prompt.objects.latest('pk').decision['error_type'], 'unknown_price')
        self.company.ai_config = original
        self.company.jev_api_key = ''
        self.company.save()
        self.send('/api/chat/send/')
        self.assertEqual(Prompt.objects.latest('pk').decision['error_type'], 'jev_unavailable')
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_difficulty_cannot_override_policy_changed_during_call(self):
        transport = self.http.side_effect
        def change(*args, **kwargs):
            if kwargs.get('data'):
                self.company.ai_config['revision'] = 99
                self.company.save()
            return transport(*args, **kwargs)
        self.http.side_effect = change
        self.send('/api/chat/send/')
        self.assertEqual(Prompt.objects.latest('pk').decision['error_type'], 'security_check_failed')
        self.provider.assert_not_called()

    def test_malformed_difficulty_stops_generation(self):
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'engine:999'})
        self.send('/api/chat/send/')
        self.assertNotEqual(Prompt.objects.latest('pk').status, 'completed')
        self.provider.assert_not_called()

    def test_failed_verification_still_rejects_response(self):
        self.http.side_effect = test_pipeline.jev_http(choices={'difficulty': 'easy'}, failures={'failure_omission': .9})
        self.send('/api/chat/send/')
        self.assertEqual(Prompt.objects.latest('pk').decision['error_type'], 'verification_failed')
        self.assertEqual(self.provider.call_count, 1)
