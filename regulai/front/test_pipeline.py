"""Shared HTTP pipeline with synthetic provider responses only."""
import json
from types import SimpleNamespace
from unittest.mock import patch
from decimal import Decimal
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from front import test_chat_flow
from front.test_chat_island import bootstrap as island_bootstrap
from front.connectors import ChatResponse, OpenAIConnector
from front.models import CompanyEngine, EngineModel, Message, ObfuscationConfig, Profile, Prompt, Rule

OPENAI_CHAT = OpenAIConnector.chat


def jev_http(choices=None, failures=None):
    choices = choices or {}
    failures = failures or {}
    def post(url, *, data=None, **kwargs):
        if url.endswith('/api/mask'):
            return test_chat_flow.mask_response(url, **kwargs)
        request = json.loads(data)
        answers = {}
        for key, question in request['questions'].items():
            if question['type'] == 'choice':
                chosen = choices.get(key, {'category': 'internal', 'task': 'general', 'difficulty': 'economy'}[key])
                answers[key] = {'type': 'choice', 'choice': chosen, 'confidence': 1.0,
                    'probabilities': {option: float(option == chosen) for option in question['criteria']}}
            else:
                answers[key] = {'type': 'noul', 'noul': float(failures.get(key, 0))}
        payload = json.dumps({'model': request['model'], 'answers': answers,
            'usage': {'input_tokens': 100, 'output_tokens': 20}}).encode()
        return SimpleNamespace(status_code=200, headers={'x-request-id': 'synthetic'},
            iter_content=lambda **kwargs: iter([payload]), close=lambda: None)
    return post


class PipelineTests(test_chat_flow.ChatFixture):
    def test_conversation_judge_scopes_current_turn_without_dropping_history_or_weakening_enforcement(self):
        self.configure(classification='local')
        previous_request = 'Responde solamente con estas dos palabras: Prueba correcta.'
        for entry in ('web', 'api', 'legacy'):
            with self.subTest(entry=entry):
                self.http.side_effect = jev_http()
                self.provider.return_value = ChatResponse('Prueba correcta.', 30, 'synthetic-v1', 'stop', 20, 10)
                first = self.send('/chat/send/', previous_request).json()
                conversation = first['conversation_id']
                path = f'/chat/{conversation}/send/' if entry == 'web' else (
                    '/api/chat/send/' if entry == 'api' else f'/chat/{conversation}/')
                self.http.reset_mock()
                self.provider.return_value = ChatResponse('¡Hola! ¿En qué puedo ayudarte?', 30, 'synthetic-v1', 'stop', 20, 10)
                self.send(path, 'hola', conversation_id=conversation)
                prompt = Prompt.objects.latest('pk')
                self.assertEqual(prompt.status, 'completed')
                self.assertEqual(prompt.decision['history']['sent_turns'], 1)
                judged = [json.loads(call.kwargs['data']) for call in self.http.call_args_list if call.kwargs.get('data')][-1]
                self.assertEqual(judged['state']['request'], 'hola')
                self.assertEqual(judged['state']['context'], [
                    {'role': 'user', 'content': previous_request}, {'role': 'assistant', 'content': 'Prueba correcta.'}])
                self.assertIn('state.request', judged['questions']['failure_omission']['instructions'])
                self.assertIn('one-turn', judged['questions']['failure_omission']['instructions'])
                call = prompt.decision['calls'][-1]
                self.assertEqual(call['question_rubric_version'], 'verification-questions-v2')
                self.assertEqual(call['threshold'], 0.8)
                self.assertEqual(prompt.decision['verification']['mode'], 'enforce')
                self.http.side_effect = jev_http(failures={'failure_omission': 0.47})
                self.provider.return_value = ChatResponse('Prueba correcta.', 30, 'synthetic-v1', 'stop', 20, 10)
                self.send(path, 'hola', conversation_id=conversation)
                rejected = Prompt.objects.latest('pk')
                self.assertEqual(rejected.status, 'failed')
                self.assertEqual(rejected.decision['error_type'], 'verification_failed')
                self.assertEqual(rejected.conversation.messages.filter(role='assistant').count(), 2)

    def test_web_automatic_mode_ignores_stale_manual_session_selection(self):
        self.configure()
        self.company.ai_config['routing'] = {'mode': 'auto', 'candidates': [{
            'company_engine_id': self.credential.pk, 'model_id': self.model.pk,
            'level': 'economy', 'quality': {'general': 1.0}}]}
        self.company.save()
        session = self.client.session
        session['selected_engine_id'] = 99999
        session['selected_model_id'] = 99999
        session.save()
        self.assertTrue(island_bootstrap(self.client.get('/chat/'))['models']['automatic'])
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            self.assertContains(self.client.get('/chat/'), 'Selección automática del modelo')
        result = self.send('/chat/send/', auto_route='true', engine_id=99999, model_id=99999).json()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['receipt']['route']['mode'], 'auto')

    def configure(self, **extra):
        self.model.context_window = 32768
        self.model.supports_json = True
        self.model.input_price = Decimal('1')
        self.model.output_price = Decimal('2')
        self.model.save()
        self.company.jev_api_key = 'synthetic-jev-key'
        self.company.ai_config.update({'classification': 'required',
            'jev': {'input_price': '1', 'output_price': '2', 'max_call_cost': '0.01'},
            'verification': {'mode': 'enforce', 'threshold': 0.8},
            'limits': {'budget': '1'},
            'destinations': {'internal': [f'engine:{self.credential.pk}', 'jev']}, **extra})
        for destinations in self.company.ai_config['destinations'].values():
            if destinations and f'obfuscation:{self.required_mask.pk}' not in destinations:
                destinations.append(f'obfuscation:{self.required_mask.pk}')
        self.company.save()
        self.http.side_effect = jev_http()
        self.provider.return_value = ChatResponse('Correct answer', 30, 'synthetic-v1', 'stop', 20, 10)

    def test_required_classification_never_silently_skips_jev(self):
        self.company.ai_config['classification'] = 'required'
        self.company.save()
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            result = self.send(path).json()
            self.assertNotEqual(result['status'], 'completed')
            self.provider.assert_not_called()

    def test_unknown_capacity_never_sends(self):
        self.model.context_window = None
        self.model.save()
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['error_type'], 'unknown_capacity')
        self.provider.assert_not_called()

    def test_required_classification_and_judge_run_on_all_three_entries(self):
        self.configure()
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                response = self.send(path)
                if path == '/chat/':
                    self.assertEqual(response.status_code, 302)
                    continue
                result = response.json()
                self.assertEqual(result['status'], 'completed', result)
                self.assertEqual(result['receipt']['verification']['status'], 'passed')
                self.assertEqual([c['purpose'] for c in result['receipt']['calls']],
                    ['obfuscation', 'classification', 'generation', 'obfuscation', 'verification'])
                self.assertEqual(Decimal(result['receipt']['total']['cost']), Decimal('0.00032'))

    def test_local_block_makes_no_calls_even_with_required_jev(self):
        self.configure()
        result = self.send('/api/chat/send/', 'SYNTHETIC_SECRET').json()
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['receipt']['total']['cost'], '0')
        self.provider.assert_not_called()
        self.http.assert_not_called()

    def test_classifier_timeout_never_generates_and_cost_is_incomplete(self):
        self.configure()
        import requests
        self.http.side_effect = requests.ReadTimeout()
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['status'], 'outcome_unknown')
        self.assertFalse(result['receipt']['total']['complete'])
        self.assertIsNone(result['receipt']['total']['cost'])
        self.provider.assert_not_called()

    def test_unknown_price_and_judge_reserve_prevent_generation(self):
        self.configure(classification='local')
        self.company.ai_config['jev'].pop('max_call_cost')
        self.company.save()
        self.assertEqual(self.send('/api/chat/send/').json()['error_type'], 'unknown_price')
        self.http.assert_not_called()
        self.provider.assert_not_called()
        self.company.ai_config['jev']['max_call_cost'] = '2'
        self.company.save()
        self.assertEqual(self.send('/api/chat/send/').json()['error_type'], 'budget_exhausted')
        self.provider.assert_not_called()
        self.company.ai_config['jev']['max_call_cost'] = '0.01'
        self.company.ai_config['jev'].pop('input_price')
        self.company.save()
        self.assertEqual(self.send('/api/chat/send/').json()['error_type'], 'unknown_price')
        self.provider.assert_not_called()

    def test_company_reconfiguration_during_classification_stops_generator(self):
        self.configure()
        transport = jev_http()
        def change(*args, **kwargs):
            self.company.ai_config['revision'] = 2
            self.company.save()
            return transport(*args, **kwargs)
        self.http.side_effect = change
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['error_type'], 'security_check_failed')
        self.provider.assert_not_called()

    def test_second_generation_is_verified_and_third_never_starts(self):
        self.configure()
        strong = EngineModel.objects.create(engine=self.engine, name='Strong', model_id='synthetic-strong',
            context_window=32768, input_price=2, output_price=3)
        self.company.ai_config['routing'] = {'mode': 'auto', 'candidates': [
            {'company_engine_id': self.credential.pk, 'model_id': self.model.pk, 'level': 'economy', 'quality': {'general': 0.5}},
            {'company_engine_id': self.credential.pk, 'model_id': strong.pk, 'level': 'strong', 'quality': {'general': 0.9}}]}
        self.company.save()
        self.http.side_effect = jev_http(failures={'failure_contradiction': 1})
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['status'], 'failed', result)
        self.assertEqual(self.provider.call_count, 2)
        self.assertEqual(self.http.call_count, 6)
        self.assertEqual(result['receipt']['verification']['status'], 'failed')
        self.assertNotIn('assistant_message', result)
        self.assertEqual(result['receipt']['total']['attempts'], 2)

    def test_verified_citations_are_resolved_from_current_attachment(self):
        self.configure()
        self.http.side_effect = jev_http(choices={'task': 'document_question'})
        def answer(messages, **kwargs):
            sources = json.loads(messages[-1].content.split('Sources:\n', 1)[1])
            return ChatResponse(json.dumps({'claims': [{'text': 'The code is 42.', 'citations': [
                {'id': sources[0]['id'], 'quote': 'The code is 42.'}]}]}), 30, 'synthetic-v1', 'stop', 20, 10)
        self.provider.side_effect = answer
        result = self.send('/api/chat/send/', 'What is the code?', file=SimpleUploadedFile('code.txt', b'The code is 42.')).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['assistant_message']['content'], 'The code is 42. [1]')
        self.assertEqual(result['evidence']['items'][0]['excerpt'], 'The code is 42.')
        self.assertEqual(result['evidence']['items'][0]['locator'], 'line:1')

    def test_judge_cannot_receive_a_response_blocked_by_yara(self):
        self.configure()
        self.provider.return_value = ChatResponse('SYNTHETIC_SECRET', 30, 'synthetic-v1', 'stop', 20, 10)
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['error_type'], 'security_check_failed')
        self.assertEqual(self.http.call_count, 2)
        self.assertNotIn('assistant_message', result)

    def test_history_mutation_during_classification_prevents_next_egress(self):
        self.configure()
        first = self.send('/api/chat/send/').json()
        self.provider.reset_mock()
        transport = jev_http()
        def change(*args, **kwargs):
            Message.objects.filter(pk=first['assistant_message']['id']).update(content='CHANGED')
            return transport(*args, **kwargs)
        self.http.side_effect = change
        result = self.send('/api/chat/send/', conversation_id=first['conversation_id']).json()
        self.assertEqual(result['error_type'], 'authorization_changed')
        self.provider.assert_not_called()

    def test_advisory_never_delivers_truncated_answer(self):
        self.configure(verification={'mode': 'advisory'})
        self.provider.return_value = ChatResponse('Incomplete', 30, 'synthetic-v1', 'length', 20, 10)
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('assistant_message', result)

    def test_advisory_judge_unavailable_is_visible_and_excluded_from_history(self):
        self.configure(verification={'mode': 'advisory'})
        transport = jev_http()
        def unavailable_judge(url, *, data=None, **kwargs):
            if data and 'failure_omission' in json.loads(data)['questions']:
                import requests
                raise requests.ReadTimeout()
            return transport(url, data=data, **kwargs)
        self.http.side_effect = unavailable_judge
        first = self.send('/api/chat/send/', 'FIRST_UNVERIFIED_INPUT').json()
        self.assertEqual(first['status'], 'completed', first)
        self.assertEqual(first['receipt']['verification']['status'], 'not_verified')
        self.send('/api/chat/send/', 'SECOND_INPUT', conversation_id=first['conversation_id'])
        self.assertNotIn('FIRST_UNVERIFIED_INPUT', str(self.provider.call_args))

    def test_masking_is_authorized_and_logged_per_call(self):
        self.company.ai_config['masking'] = {'max_call_cost': None}
        self.company.save()
        self.http.side_effect = None
        self.http.return_value.json.return_value = {'masked': '["Masked text"]', 'context': {}, 'counters': {}}
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual([call['purpose'] for call in result['receipt']['calls']], ['obfuscation', 'generation', 'obfuscation'])
        self.assertFalse(result['receipt']['total']['complete'])
        self.assertIn('Masked text', str(self.provider.call_args))
        self.assertFalse(self.http.call_args.kwargs['allow_redirects'])

    def test_all_http_entries_reach_the_real_connector_sdk_boundary(self):
        with patch('front.connectors.OpenAIConnector.chat', OPENAI_CHAT), patch('openai.OpenAI') as sdk:
            response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='SDK answer'), finish_reason='stop')],
                model='synthetic-v1', id='synthetic-sdk-id', usage=SimpleNamespace(total_tokens=30,
                    prompt_tokens=20, completion_tokens=10, model_dump=lambda: {'prompt_tokens': 20, 'completion_tokens': 10}))
            sdk.return_value.chat.completions.create.return_value = response
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                result = self.send(path)
                self.assertEqual(result.status_code, 302 if path == '/chat/' else 200)
                payload = sdk.return_value.chat.completions.create.call_args.kwargs
                self.assertEqual(payload['messages'], [{'role': 'user', 'content': 'Hola'}])
                self.assertEqual(sdk.call_args.kwargs['max_retries'], 0)
                self.assertFalse(sdk.call_args.kwargs['http_client'].follow_redirects)
