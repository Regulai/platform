from types import SimpleNamespace
from unittest.mock import Mock, patch
from django.test import SimpleTestCase
from front.connectors import ChatMessage, get_connector
import json
import httpx
from openai import OpenAI


class ConnectorTests(SimpleTestCase):
    def test_anthropic_preserves_both_system_prompts_and_disables_sdk_retries(self):
        with patch('anthropic.Anthropic') as sdk:
            usage = Mock(input_tokens=8, output_tokens=3)
            usage.model_dump.return_value = {'input_tokens': 8, 'output_tokens': 3}
            sdk.return_value.messages.create.return_value = SimpleNamespace(
                content=[SimpleNamespace(text='Hola')], usage=usage, model='synthetic-v1', id='synthetic-id', stop_reason='end_turn')
            connector = get_connector('anthropic', 'synthetic-key')
            result = connector.chat([ChatMessage('system', 'Company'), ChatMessage('system', 'Department'),
                                     ChatMessage('user', 'Hello')], model='synthetic-v1', timeout=4)
            self.assertEqual(sdk.call_args.kwargs['max_retries'], 0)
            self.assertEqual(sdk.return_value.messages.create.call_args.kwargs['system'], 'Company\n\nDepartment')
            self.assertEqual(sdk.return_value.messages.create.call_args.kwargs['timeout'], 4)
            self.assertEqual((result.input_tokens, result.output_tokens, result.tokens_used), (8, 3, 11))

    def test_openai_reports_missing_usage_as_unknown(self):
        with patch('openai.OpenAI') as sdk:
            sdk.return_value.chat.completions.create.return_value = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='Hello'), finish_reason='length')],
                usage=None, model='resolved-alias', id='synthetic-id')
            result = get_connector('openai', 'synthetic-key').chat([ChatMessage('user', 'Hello')], 'alias')
            self.assertEqual(sdk.call_args.kwargs['max_retries'], 0)
            self.assertIsNone(result.input_tokens)
            self.assertEqual(result.model, 'resolved-alias')
            self.assertEqual(result.finish_reason, 'length')

    def test_openai_reasoning_and_json_are_explicit_capabilities(self):
        for connector_type in ('openai', 'openai_compatible'):
            with self.subTest(connector_type=connector_type), patch('openai.OpenAI') as sdk:
                sdk.return_value.chat.completions.create.return_value = SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content='{"claims":[]}'), finish_reason='stop')],
                    usage=None, model='custom-name', id='synthetic-id')
                get_connector(connector_type, 'synthetic-key').chat(
                    [ChatMessage('user', 'Return JSON claims.')], 'custom-name', max_tokens=77,
                    temperature=0.1, supports_json=True, reasoning=True, timeout=4,
                    extra_body={'synthetic_option': 'preserved'})
                payload = sdk.return_value.chat.completions.create.call_args.kwargs
                self.assertEqual(payload.get('response_format'), {'type': 'json_object'})
                self.assertEqual(payload.get('max_completion_tokens'), 77)
                self.assertNotIn('max_tokens', payload)
                self.assertNotIn('temperature', payload)
                self.assertEqual(payload['extra_body'], {'synthetic_option': 'preserved'})
                self.assertEqual(sdk.call_args.kwargs['max_retries'], 0)

    def test_document_temperature_and_json_do_not_depend_on_model_name(self):
        with patch('openai.OpenAI') as sdk:
            sdk.return_value.chat.completions.create.return_value = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='{"claims":[]}'), finish_reason='stop')],
                usage=None, model='o-custom', id='synthetic-id')
            connector = get_connector('openai', 'synthetic-key')
            connector.chat([ChatMessage('user', 'Return JSON claims.')], 'o-custom',
                           max_tokens=88, temperature=0.1, supports_json=True, reasoning=False)
            payload = sdk.return_value.chat.completions.create.call_args.kwargs
            self.assertEqual(payload.get('response_format'), {'type': 'json_object'})
            self.assertEqual((payload['max_tokens'], payload['temperature']), (88, 0.1))
            connector.chat([ChatMessage('user', 'Hello')], 'o-custom', supports_json=False)
            self.assertNotIn('response_format', sdk.return_value.chat.completions.create.call_args.kwargs)

    def test_compatible_provider_missing_finish_reason_cannot_prove_completion(self):
        from front.verification import verify_response
        with patch('openai.OpenAI') as sdk:
            sdk.return_value.chat.completions.create.return_value = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='Hello'), finish_reason=None)],
                usage=None, model='compatible-v1', id='synthetic-id')
            response = get_connector('openai_compatible', 'synthetic-key').chat(
                [ChatMessage('user', 'Hello')], 'compatible-v1')
        self.assertIsNone(response.finish_reason)
        checks = verify_response(response.content, response.finish_reason, require_semantic=False)
        self.assertEqual((checks['local_status'], checks['finish_reason']), ('failed', 'unknown'))

    def test_anthropic_json_capability_requests_the_document_schema(self):
        with patch('anthropic.Anthropic') as sdk:
            sdk.return_value.messages.create.return_value = SimpleNamespace(
                content=[SimpleNamespace(text='{"claims":[]}')], usage=None,
                model='custom-name', id='synthetic-id', stop_reason='end_turn')
            connector = get_connector('anthropic', 'synthetic-key')
            connector.chat([ChatMessage('system', 'Return JSON claims.'), ChatMessage('user', 'Question')],
                           'custom-name', max_tokens=77, temperature=0.1, supports_json=True, reasoning=True)
            payload = sdk.return_value.messages.create.call_args.kwargs
            self.assertIn('output_config', payload)
            self.assertEqual(payload['output_config']['format']['type'], 'json_schema')
            schema = payload['output_config']['format']['schema']
            self.assertEqual(schema['required'], ['claims'])
            self.assertFalse(schema['additionalProperties'])
            claim_schema = schema['properties']['claims']['items']
            self.assertEqual(claim_schema['required'], ['text', 'citations'])
            self.assertEqual(claim_schema['properties']['citations']['items']['required'], ['id', 'quote'])
            self.assertNotIn('temperature', payload)
            self.assertEqual(payload['max_tokens'], 77)
            self.assertNotIn('max_completion_tokens', payload)
            self.assertEqual(sdk.call_args.kwargs['max_retries'], 0)
            connector.chat([ChatMessage('user', 'Hello')], 'custom-name', temperature=0.1)
            payload = sdk.return_value.messages.create.call_args.kwargs
            self.assertNotIn('output_config', payload)
            self.assertEqual(payload['temperature'], 0.1)


class ExplicitProfileHttpTests(SimpleTestCase):
    """Exercise serialization by the installed SDK, without opening a socket."""

    def request(self, dialect, mode, *, connector_type=None, tools=None, effort=None, usage=True, **overrides):
        captured = []
        connector_type = connector_type or {'deepseek': 'openai_compatible', 'openai': 'openai',
            'vercel_gateway': 'vercel_gateway'}[dialect]
        model = 'openai/synthetic-model' if connector_type == 'vercel_gateway' else 'synthetic-model'
        options = {'dialect': dialect, 'model_id': model, 'thinking_mode': mode, 'effort': effort,
            'max_output_tokens': 4096, 'profile_version': 1, 'selection_source': 'user_selected', **overrides}

        def respond(request):
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={'id': 'synthetic-id', 'object': 'chat.completion', 'created': 1,
                'model': model, 'choices': [{'index': 0, 'finish_reason': 'stop', 'message': {
                    'role': 'assistant', 'content': 'Visible answer', 'reasoning_content': 'private-thinking',
                    'reasoning': 'private-thinking', 'reasoning_details': [{'signature': 'private-signature'}]}}],
                **({'usage': {'prompt_tokens': 7, 'completion_tokens': 3, 'total_tokens': 10}} if usage else {})})

        with patch('socket.socket.connect', side_effect=AssertionError('Unmocked network forbidden')):
            connector = get_connector(connector_type, 'synthetic-key')
            connector.client.close()
            with httpx.Client(transport=httpx.MockTransport(respond)) as http:
                connector.client = OpenAI(api_key='synthetic-key', base_url='https://synthetic.invalid/v1',
                    max_retries=0, http_client=http)
                result = connector.chat([ChatMessage('user', 'Question')], model=model,
                    inference_options=options, reasoning=True, tools=tools)
        return captured, result

    def test_deepseek_explicit_off_and_bounded_on_survive_real_sdk_serialization(self):
        for mode, effort in [('off', None), ('on', 'high')]:
            with self.subTest(mode=mode):
                requests, response = self.request('deepseek', mode, effort=effort)
                self.assertEqual(len(requests), 1)
                body = requests[0]
                self.assertEqual(body, {'model': 'synthetic-model', 'messages': [{'role': 'user', 'content': 'Question'}],
                    'max_tokens': 4096, 'thinking': {'type': 'disabled' if mode == 'off' else 'enabled'},
                    **({'reasoning_effort': 'high'} if effort else {})})
                self.assertEqual(response.content, 'Visible answer')
                self.assertNotIn('private', repr(response))
                self.assertEqual(response.inference_options['observed_thinking_mode'], 'unknown')

    def test_openai_maps_none_and_high_without_deepseek_fields(self):
        for mode, effort in [('off', 'none'), ('on', 'high')]:
            with self.subTest(mode=mode):
                requests, _ = self.request('openai', mode, effort=effort)
                self.assertEqual(requests[0], {'model': 'synthetic-model',
                    'messages': [{'role': 'user', 'content': 'Question'}],
                    'max_completion_tokens': 4096, 'reasoning_effort': effort})

    def test_gateway_merges_reasoning_with_pinned_upstream(self):
        for mode, effort in [('off', None), ('on', 'high')]:
            with self.subTest(mode=mode):
                requests, response = self.request('vercel_gateway', mode, effort=effort)
                expected = {'enabled': mode == 'on', 'exclude': True, **({'effort': effort} if effort else {})}
                self.assertEqual(requests[0], {'model': 'openai/synthetic-model',
                    'messages': [{'role': 'user', 'content': 'Question'}], 'max_tokens': 4096,
                    'reasoning': expected, 'providerOptions': {'gateway': {'only': ['openai']}}})
                self.assertEqual(response.inference_options['sent']['providerOptions'], {'gateway': {'only': ['openai']}})

    def test_unavailable_reasoning_tool_continuity_or_dialect_never_opens_transport(self):
        for dialect in ('deepseek', 'openai', 'vercel_gateway'):
            with self.subTest(dialect=dialect), self.assertRaisesRegex(ValueError, 'reasoning_tool_continuity_unavailable'):
                self.request(dialect, 'on', effort='high', tools=[{'type': 'function'}])
        with self.assertRaisesRegex(ValueError, 'inference_dialect_mismatch'):
            self.request('deepseek', 'off', connector_type='openai')

    def test_missing_usage_stays_unknown(self):
        _, response = self.request('deepseek', 'off', usage=False)
        self.assertIsNone(response.input_tokens)
        self.assertIsNone(response.output_tokens)

    def test_gateway_legacy_does_not_accept_arbitrary_fallbacks(self):
        with patch('openai.OpenAI') as sdk:
            sdk.return_value.chat.completions.create.return_value = SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='Hello'), finish_reason='stop')],
                usage=None, model='openai/synthetic', id='synthetic-id')
            get_connector('vercel_gateway', 'synthetic-key').chat([ChatMessage('user', 'Hello')],
                'openai/synthetic', extra_body={'models': ['other/model'],
                    'providerOptions': {'gateway': {'only': ['other']}}})
            self.assertEqual(sdk.return_value.chat.completions.create.call_args.kwargs['extra_body'],
                {'providerOptions': {'gateway': {'only': ['openai']}}})
