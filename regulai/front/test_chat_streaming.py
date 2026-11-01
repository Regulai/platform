"""Incremental web delivery: checked fragments, complete-text boundaries and reattach.

Providers are synthetic. Connector tests use the pinned SDKs over an in-memory
HTTP transport; the live test proves a fragment reaches the HTTP client while
the simulated generation is still blocked.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import random
import threading
import time
import uuid
from unittest.mock import patch

import httpx
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TransactionTestCase, override_settings

from front import chat_streaming, test_chat_flow, test_pipeline
from front.chat_streaming import ChatEvents, _prefix_decidable, delivery_plan, lookup, register, safe_cut
from front.connectors import ChatMessage, ChatResponse, get_connector
from front.governance import PipelineStop
from front.local_masking import mask_local_texts
from front.models import (Company, CompanyEngine, Engine, EngineModel, Message, ObfuscationConfig, Profile,
                          Prompt, Rule, RulesGroup)

INTRO = ('La política de viajes de 2026 fija límites claros para alojamiento, dietas y transporte. '
         'Las reservas se hacen con antelación y los gastos se justifican en treinta días. ')


def parse_sse(body):
    events = []
    for block in body.split('\n\n'):
        data = [line[6:] for line in block.split('\n') if line.startswith('data: ')]
        if data:
            events.append(json.loads('\n'.join(data)))
    return events


def deltas(events):
    return ''.join(event['text'] for event in events if event['type'] == 'delta')


class SafeCutTests(SimpleTestCase):
    pieces = ['hola', 'texto', 'Nombre:', 'nombre', ':', 'Correo:', 'correo de contacto:', 'juan', 'arroba', 'empresa',
              'punto', 'com', 'a@b.co', 'x.y@dominio.es', '+34', '612', '345', '678', 'ES91', '2100', '0418', '4502',
              '12345678Z', 'X1234567L', 'sk-proj-AbCdEf0123456789xyz', 'Bearer', 'tok_abcdefgh12345678', 'password=',
              'hunter2secret', 'api_key:', 'https://user:pass@host.com', '-----BEGIN PRIVATE KEY-----',
              '-----END PRIVATE KEY-----', 'MIIEvQIBADAN', 'Cliente:', 'Ana', 'María', '６１２', '​', '–', '4111', '1111']
    separators = [' ', ' ', ' ', '\n', '\n\n', '\t', '-', '.', ', ']

    def emissions(self, text, step):
        """Mirror StreamGuard: emit only when the safe cut advances."""
        emitted, last = '', 0
        for position in range(1, len(text) + 1, step):
            cut = safe_cut(text[:position])
            if cut <= last:
                continue
            masked = mask_local_texts([text[:cut]])[0]
            self.assertTrue(masked.startswith(emitted), 'shown text was rewritten')
            emitted, last = masked, cut
            yield emitted

    def test_shown_text_is_always_a_prefix_of_the_final_masking(self):
        generator = random.Random(20261014)
        for sample in range(60):
            text = ''.join(generator.choice(self.pieces) + generator.choice(self.separators)
                           for _ in range(generator.randint(40, 120)))
            final = mask_local_texts([text])[0]
            with self.subTest(sample=sample):
                for shown in self.emissions(text, generator.randint(1, 7)):
                    self.assertTrue(final.startswith(shown))

    def test_values_split_across_fragments_are_never_shown_raw(self):
        values = {'juan.perez@empresa-lab.com': 'EMAIL', '612 345 678': 'PHONE', 'ES91 2100 0418 4502 0005 1332': 'ACCOUNT',
                  '4111 1111 1111 1111': 'CARD', '12345678Z': 'ID', 'sk-proj-9f8E7d6C5b4A3z2Y1x0W': 'SECRET',
                  'juan arroba empresa punto com': 'EMAIL', 'Ana María López': 'PERSON'}
        for value, category in values.items():
            label = {'juan arroba empresa punto com': 'Correo: ', 'Ana María López': 'Nombre: '}.get(value, '')
            text = INTRO + label + value + '\nGracias por la consulta. ' + 'Queda a tu disposición. ' * 8
            final = mask_local_texts([text])[0]
            self.assertIn(f'[[REGULAI_{category}]]', final)
            with self.subTest(value=value):
                emitted = list(self.emissions(text, 1))
                self.assertTrue(emitted)  # Something was shown before the end.
                for shown in emitted:
                    # A prefix of the final masking holds either none of the value or its marker.
                    self.assertTrue(final.startswith(shown))
                    self.assertNotIn(value, shown)
                    self.assertNotIn(value.split()[0][:6], shown.replace(INTRO, ''))

    def test_open_private_key_block_and_structured_answers_are_held(self):
        text = INTRO + '\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\n' + 'QWERTY' * 40
        self.assertLessEqual(safe_cut(text), text.index('-----BEGIN'))
        self.assertEqual(safe_cut('{"resumen": "' + 'x ' * 200 + '"'), 0)
        self.assertEqual(safe_cut('  [1, 2, ' + '3, ' * 100), 0)
        self.assertEqual(safe_cut('Respuesta breve.'), 0)


class EligibilityTests(SimpleTestCase):
    def test_only_single_string_conditions_are_decidable_on_partial_text(self):
        from front.ai_connections import BASIC_RULE
        self.assertTrue(_prefix_decidable(BASIC_RULE))
        self.assertTrue(_prefix_decidable('rule a { strings: $s = "x" condition: $s }'))
        self.assertTrue(_prefix_decidable('rule a { strings: $a = "x" $b = "y" condition: $a or $b }'))
        self.assertTrue(_prefix_decidable('rule a { strings: $a = "x" // note\n condition: any of ($a*) }'))
        for condition in ('$a and $b', 'all of them', '#a > 2', 'not $a', 'filesize < 100 and $a',
                          '2 of them', '$a at 0', 'for any i in (1..#a): (@a[i] > 0)'):
            with self.subTest(condition=condition):
                self.assertFalse(_prefix_decidable('rule a { strings: $a = "x" $b = "y" condition: ' + condition + ' }'))
        self.assertFalse(_prefix_decidable('import "pe"\nrule a { strings: $a = "x" condition: $a }'))
        self.assertFalse(_prefix_decidable('global rule a { strings: $a = "x" condition: $a }'))

    def engine(self, connector, base_url=''):
        from types import SimpleNamespace
        return SimpleNamespace(engine=SimpleNamespace(connector_type=connector, base_url=base_url))

    def test_plan_names_the_boundary_that_needs_complete_text(self):
        from types import SimpleNamespace
        local, remote = SimpleNamespace(backend='local'), SimpleNamespace(backend='http')
        rule = SimpleNamespace(applies_to='both', yara_rule='rule a { strings: $s = "x" condition: $s }')
        plan = lambda **kw: delivery_plan(**{'document': None, 'semantic': False, 'masks': [local],
                                             'engine': self.engine('openai'), 'rules': [], **kw})
        self.assertEqual(plan(), ('streamed', None))
        self.assertEqual(plan(engine=self.engine('anthropic')), ('streamed', None))
        self.assertEqual(plan(engine=self.engine('openai_compatible', 'https://api.deepseek.com')), ('streamed', None))
        self.assertEqual(plan(document=object()), ('complete', 'document_citations'))
        self.assertEqual(plan(semantic=True), ('complete', 'response_verification'))
        self.assertEqual(plan(masks=[local, remote]), ('complete', 'remote_masking'))
        for engine in (self.engine('vercel_gateway'), self.engine('openai_compatible', 'https://api.mistral.ai/v1'),
                       self.engine('openai', 'https://proxy.example.invalid/v1')):
            self.assertEqual(plan(engine=engine), ('complete', 'provider_streaming_unverified'))
        strict = SimpleNamespace(applies_to='prompts', yara_rule='rule a { strings: $a = "x" $b = "y" condition: all of them }')
        self.assertEqual(plan(rules=[rule, strict]), ('complete', 'policy_needs_complete_text'))
        self.assertEqual(plan(rules=[rule]), ('complete', 'policy_needs_complete_text'))
        files_only = SimpleNamespace(applies_to='files', yara_rule=strict.yara_rule)
        self.assertEqual(plan(rules=[files_only]), ('streamed', None))
        with override_settings(CHAT_STREAMING_ENABLED=False):
            self.assertEqual(plan(), ('complete', 'streaming_disabled'))


class StreamingConnectorTests(SimpleTestCase):
    def transport(self, handler):
        return patch('openai.DefaultHttpxClient', side_effect=lambda **kwargs:
                     httpx.Client(transport=httpx.MockTransport(handler), **kwargs))

    def test_openai_fragments_arrive_before_the_stream_ends_with_usage(self):
        seen, sent, progress = [], [], []

        def body():
            for index, text in enumerate(['Hola', ', mundo', '.']):
                if index:
                    progress.append(list(seen))  # What the caller had received before this chunk.
                chunk = {'id': 'c1', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'synthetic-effective',
                         'choices': [{'index': 0, 'delta': {'content': text}, 'finish_reason': None}]}
                yield ('data: ' + json.dumps(chunk) + '\n\n').encode()
            yield ('data: ' + json.dumps({'id': 'c1', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'synthetic-effective',
                'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]}) + '\n\n').encode()
            yield ('data: ' + json.dumps({'id': 'c1', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'synthetic-effective',
                'choices': [], 'usage': {'prompt_tokens': 9, 'completion_tokens': 4, 'total_tokens': 13}}) + '\n\n').encode()
            yield b'data: [DONE]\n\n'

        def handler(request):
            sent.append(json.loads(request.content))
            return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=body())

        with patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), self.transport(handler):
            result = get_connector('openai', 'synthetic-key').chat([ChatMessage('user', 'Hola')], 'synthetic-v1',
                                                                   timeout=5, on_delta=seen.append)
        self.assertEqual(seen, ['Hola', ', mundo', '.'])
        self.assertEqual(progress, [['Hola'], ['Hola', ', mundo']])
        self.assertEqual((result.content, result.finish_reason, result.model), ('Hola, mundo.', 'stop', 'synthetic-effective'))
        self.assertEqual((result.input_tokens, result.output_tokens, result.tokens_used), (9, 4, 13))
        self.assertTrue(sent[0]['stream'])
        self.assertEqual(sent[0]['stream_options'], {'include_usage': True})

    def test_a_stop_from_the_checks_closes_the_provider_stream(self):
        produced = []

        def body():
            for index in range(50):
                produced.append(index)
                chunk = {'id': 'c1', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'm',
                         'choices': [{'index': 0, 'delta': {'content': f'parte {index} '}, 'finish_reason': None}]}
                yield ('data: ' + json.dumps(chunk) + '\n\n').encode()

        def stop(text):
            if 'parte 2' in text:
                raise PipelineStop('security_check_failed')

        with patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT), \
                self.transport(lambda request: httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=body())):
            with self.assertRaises(PipelineStop):
                get_connector('openai_compatible', 'k').chat([ChatMessage('user', 'x')], 'm', on_delta=stop)
        self.assertLess(len(produced), 10)

    def test_anthropic_text_events_and_final_usage(self):
        events = [('message_start', {'type': 'message_start', 'message': {'id': 'msg_1', 'type': 'message', 'role': 'assistant',
                       'model': 'synthetic-claude', 'content': [], 'stop_reason': None, 'stop_sequence': None,
                       'usage': {'input_tokens': 11, 'output_tokens': 1}}}),
                  ('content_block_start', {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}}),
                  ('content_block_delta', {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'Buenos '}}),
                  ('content_block_delta', {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'días'}}),
                  ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                  ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None},
                                     'usage': {'output_tokens': 5}}),
                  ('message_stop', {'type': 'message_stop'})]
        payload = ''.join(f'event: {name}\ndata: {json.dumps(data)}\n\n' for name, data in events).encode()
        sent, seen = [], []

        def handler(request):
            sent.append(json.loads(request.content))
            return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=payload)

        with patch('anthropic.DefaultHttpxClient', side_effect=lambda **kwargs:
                   httpx.Client(transport=httpx.MockTransport(handler), **kwargs)):
            result = get_connector('anthropic', 'synthetic-key').chat([ChatMessage('user', 'Hola')], 'synthetic-claude',
                                                                      on_delta=seen.append)
        self.assertEqual(seen, ['Buenos ', 'días'])
        self.assertTrue(sent[0]['stream'])
        self.assertEqual((result.content, result.finish_reason), ('Buenos días', 'end_turn'))
        self.assertEqual((result.input_tokens, result.output_tokens), (11, 5))


@override_settings(CHAT_STREAM_THREADS=False)
class StreamedChatTests(test_chat_flow.ChatFixture):
    answer = (INTRO + 'Para dudas escribe a juan.perez@empresa-lab.com o llama al 612 345 678. '
              'El alojamiento máximo es de 120 € por noche y las dietas de 45 € por día. ' * 3)

    def setUp(self):
        super().setUp()
        # Text streaming is eligible only without an applicable YARA rule.
        Rule.objects.filter(pk=self.rule.pk).update(applies_to='files')
        self.required_mask.backend, self.required_mask.api_url, self.required_mask.language = 'local', '', 'es'
        self.required_mask.save()
        self.http.side_effect = AssertionError('Unexpected external HTTP')
        self.enterContext(patch('front.chat_streaming.EMIT_INTERVAL', 0))
        self.finish, self.hook = 'stop', None
        self.provider.side_effect = self.generate
        chat_streaming._REGISTRY.clear()

    def generate(self, messages, model=None, **kwargs):
        text = self.answer
        pieces = [text[index:index + 7] for index in range(0, len(text), 7)]
        for index, piece in enumerate(pieces):
            if self.hook:
                self.hook(index, piece)
            if kwargs.get('on_delta'):
                kwargs['on_delta'](piece)
        return ChatResponse(text, 30, 'synthetic-v1', self.finish, 20, 10)

    def stream(self, content='Resume la política', path='/chat/send/', **extra):
        response = self.send(path, content, stream='1', **extra)
        self.assertEqual(response['Content-Type'], 'text/event-stream; charset=utf-8')
        return parse_sse(b''.join(response.streaming_content).decode())

    def test_checked_fragments_stream_and_equal_the_saved_answer(self):
        events = self.stream()
        kinds = [event['type'] for event in events]
        self.assertEqual(kinds[:3], ['accepted', 'stage', 'delivery'])
        self.assertEqual(events[1]['stage'], 'protecting')
        self.assertEqual((events[2]['mode'], events[2]['reason']), ('streamed', None))
        self.assertIn('generating', [event.get('stage') for event in events])
        self.assertGreater(kinds.count('delta'), 3)
        self.assertEqual(kinds[-1], 'final')
        self.assertEqual([event['seq'] for event in events], list(range(1, len(events) + 1)))
        final = events[-1]['result']
        self.assertEqual(final['status'], 'completed')
        shown, saved = deltas(events), final['assistant_message']['content']
        self.assertTrue(saved.startswith(shown))
        self.assertGreater(len(shown), len(saved) // 2)
        for value in ('juan.perez@empresa-lab.com', '612 345 678', 'juan.perez', '@empresa-lab'):
            self.assertNotIn(value, json.dumps(events, ensure_ascii=False))
        self.assertIn('[[REGULAI_EMAIL]]', saved)
        self.assertEqual(final['receipt']['delivery'], {'mode': 'streamed', 'reason': None})
        self.assertIn('on_delta', self.provider.call_args.kwargs)
        self.assertEqual(Message.objects.filter(role='assistant').get().content, saved)

    def test_output_rule_requires_complete_text_and_saves_nothing(self):
        Rule.objects.filter(pk=self.rule.pk).update(applies_to='both')
        self.answer = INTRO * 2 + 'El valor interno es SYNTHETIC_SECRET y no debe salir. ' + 'Más texto de cierre. ' * 6
        events = self.stream()
        kinds = [event['type'] for event in events]
        self.assertNotIn('delta', kinds)
        self.assertNotIn('retract', kinds)
        self.assertEqual(events[2]['reason'], 'policy_needs_complete_text')
        self.assertNotIn('SYNTHETIC', deltas(events))
        final = events[-1]['result']
        self.assertEqual((final['status'], final['error_type']), ('validation_error', 'security_check_failed'))
        self.assertNotIn('assistant_message', final)
        self.assertFalse(Message.objects.filter(role='assistant').exists())
        prompt = Prompt.objects.get()
        generation = [call for call in prompt.decision['calls'] if call['purpose'] == 'generation'][0]
        self.assertEqual(generation['status'], 'completed')
        self.assertNotIn('withdrawn', prompt.decision['delivery'])

    def test_incomplete_generation_is_withdrawn_and_explained(self):
        self.finish = 'length'
        events = self.stream()
        self.assertTrue(deltas(events))
        self.assertIn('retract', [event['type'] for event in events])
        final = events[-1]['result']
        self.assertEqual((final['status'], final['error_type']), ('failed', 'verification_failed'))
        self.assertIn('límite de generación', final['error'])
        self.assertFalse(Message.objects.filter(role='assistant').exists())

    def test_user_stop_ends_generation_without_saving_partial_text(self):
        def stop_later(index, piece):
            if index == 30:
                next(iter(chat_streaming._REGISTRY.values())).cancel()
        self.hook = stop_later
        events = self.stream()
        final = events[-1]['result']
        self.assertEqual((final['status'], final['error_type']), ('cancelled', 'cancelled_by_user'))
        self.assertIn('retract', [event['type'] for event in events])
        self.assertFalse(Message.objects.filter(role='assistant').exists())
        call = Prompt.objects.get().decision['calls'][-1]
        self.assertEqual((call['purpose'], call['status']), ('generation', 'cancelled'))

    def test_answers_needing_complete_text_are_delivered_whole_with_their_reason(self):
        with self.subTest('structured answer'):
            self.answer = '{"resumen": "' + 'Pedido confirmado. ' * 20 + '", "importe": 1250}'
            events = self.stream()
            self.assertFalse([event for event in events if event['type'] == 'delta'])
            self.assertIn(('complete', 'structured_answer'),
                          [(event['mode'], event['reason']) for event in events if event['type'] == 'delivery'])
            self.assertEqual(events[-1]['result']['status'], 'completed')
        with self.subTest('remote masking'):
            self.answer = self.__class__.answer
            ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(backend='http', api_url='https://mask.invalid')
            self.http.side_effect = test_chat_flow.mask_response
            events = self.stream()
            self.assertEqual([(e['mode'], e['reason']) for e in events if e['type'] == 'delivery'], [('complete', 'remote_masking')])
            self.assertNotIn('on_delta', self.provider.call_args.kwargs)
            self.assertEqual(events[-1]['result']['status'], 'completed')
            ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(backend='local', api_url='')
            self.http.side_effect = AssertionError('Unexpected external HTTP')
        with self.subTest('rule needs complete text'):
            Rule.objects.filter(pk=self.rule.pk).update(applies_to='both', yara_rule=(
                'rule SyntheticPair { strings: $a = "SYNTHETIC_A" $b = "SYNTHETIC_B" condition: all of them }'))
            events = self.stream()
            self.assertEqual([(e['mode'], e['reason']) for e in events if e['type'] == 'delivery'],
                             [('complete', 'policy_needs_complete_text')])
            self.assertNotIn('on_delta', self.provider.call_args.kwargs)
        with self.subTest('provider without verified streaming usage'):
            Rule.objects.filter(pk=self.rule.pk).update(yara_rule=(
                'rule SyntheticSecret { strings: $s = "SYNTHETIC_SECRET" condition: $s }'))
            Engine.objects.filter(pk=self.engine.pk).update(base_url='https://proxy.example.invalid/v1')
            events = self.stream()
            self.assertEqual([(e['mode'], e['reason']) for e in events if e['type'] == 'delivery'],
                             [('complete', 'provider_streaming_unverified')])
            self.assertNotIn('on_delta', self.provider.call_args.kwargs)

    def test_judged_and_document_requests_show_real_stages_but_no_partial_text(self):
        test_pipeline.PipelineTests.configure(self)
        self.http.side_effect = test_pipeline.jev_http()
        events = self.stream()
        stages = [event['stage'] for event in events if event['type'] == 'stage']
        self.assertEqual(stages, ['protecting', 'classifying', 'generating', 'verifying'])
        self.assertEqual([(e['mode'], e['reason']) for e in events if e['type'] == 'delivery'],
                         [('complete', 'response_verification')])
        self.assertFalse([event for event in events if event['type'] == 'delta'])
        self.assertEqual(events[-1]['result']['status'], 'completed')
        self.answer = json.dumps({'claims': [{'text': 'Plazo acordado.', 'citations': [{'id': 'S1', 'quote': 'El plazo de entrega acordado'}]}]})
        upload = SimpleUploadedFile('acta.txt', b'El plazo de entrega acordado es de diecisiete dias laborables.', content_type='text/plain')
        events = self.stream('¿Qué plazo?', file=upload)
        self.assertIn(('complete', 'document_citations'),
                      [(e['mode'], e['reason']) for e in events if e['type'] == 'delivery'])
        self.assertFalse([event for event in events if event['type'] == 'delta'])

    def test_entries_without_the_stream_flag_keep_their_contract(self):
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                response = self.send(path, 'Hola')
                self.assertNotEqual(response.get('Content-Type'), 'text/event-stream; charset=utf-8')
                self.assertNotIn('on_delta', self.provider.call_args.kwargs)
                self.assertNotIn('delivery', Prompt.objects.order_by('-pk').first().decision)

    def test_entries_without_the_stream_flag_keep_stop_codes_from_the_provider_call(self):
        """A stop raised while the call starts (deadline) keeps its code; no stream state is involved."""
        self.provider.side_effect = PipelineStop('deadline_exceeded')
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                result = self.send(path, 'Hola').json()
                self.assertEqual((result['status'], result['error_type']), ('validation_error', 'deadline_exceeded'))
                call = Prompt.objects.order_by('-pk').first().decision['calls'][-1]
                self.assertEqual((call['purpose'], call['status'], call['cost']), ('generation', 'started', None))

    def test_reattach_replays_and_never_repeats_the_inference(self):
        request_id = str(uuid.uuid4())
        events = self.stream(request_id=request_id)
        calls = self.provider.call_count
        url = f'/chat/requests/{request_id}/stream/'
        replay = parse_sse(b''.join(self.client.get(url, {'after': 3}).streaming_content).decode())
        self.assertEqual(replay, events[3:])
        again = self.stream(request_id=request_id)
        self.assertEqual(again[-1]['result']['assistant_message'], events[-1]['result']['assistant_message'])
        chat_streaming._REGISTRY.clear()  # Another process, or after retention: stored result only.
        stored = parse_sse(b''.join(self.client.get(url).streaming_content).decode())
        self.assertEqual([event['type'] for event in stored], ['final'])
        self.assertEqual(stored[0]['result']['assistant_message'], events[-1]['result']['assistant_message'])
        self.assertEqual(self.provider.call_count, calls)
        other = User.objects.create_user('other-chat-user', password='synthetic-password')
        Profile.objects.create(user=other, company=self.company)
        self.client.force_login(other)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.post(f'/chat/requests/{request_id}/cancel/').status_code, 404)

    def test_stop_endpoint_reaches_only_a_running_request_of_its_owner(self):
        request_id = str(uuid.uuid4())
        self.stream(request_id=request_id)
        url = f'/chat/requests/{request_id}/cancel/'
        self.assertEqual(self.client.post(url).json()['cancelling'], False)
        running = register(ChatEvents(self.user.pk, request_id))
        response = self.client.post(url)
        self.assertEqual((response.status_code, response.json()['cancelling']), (202, True))
        self.assertTrue(running.cancelled())
        self.assertIs(lookup(self.user.pk, request_id), running)


class LiveStreamingTests(TransactionTestCase):
    """Real request thread: a fragment is read before the provider may finish."""

    def setUp(self):
        cache.clear()
        chat_streaming._REGISTRY.clear()
        self.user = User.objects.create_user('live-user', password='synthetic-password')
        company = Company.objects.create(name='Live synthetic')
        Profile.objects.create(user=self.user, company=company)
        engine = Engine.objects.create(name='Live synthetic', connector_type='openai')
        EngineModel.objects.create(engine=engine, name='Synthetic', model_id='synthetic-v1', context_window=32768)
        credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic-key')
        mask = ObfuscationConfig.objects.create(company=company, name='Local', backend='local', language='es')
        company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'masking': {'max_call_cost': '0'},
                             'destinations': {'internal': [f'engine:{credential.pk}', f'obfuscation:{mask.pk}']}}
        company.save()
        group = RulesGroup.objects.create(name='Live security', company=company)
        Rule.objects.create(name='Fake secret', rules_group=group, applies_to='files',
                            yara_rule='rule SyntheticSecret { strings: $s = "SYNTHETIC_SECRET" condition: $s }')
        self.client.force_login(self.user)
        self.release, self.finished = threading.Event(), threading.Event()

    def generate(self, messages, model=None, **kwargs):
        first = INTRO * 3
        for index in range(0, len(first), 9):
            kwargs['on_delta'](first[index:index + 9])
            time.sleep(0.003)
        self.assertTrue(self.release.wait(20), 'the test never released the provider')
        rest = 'Fin del resumen.'
        kwargs['on_delta'](rest)
        self.finished.set()
        return ChatResponse(first + rest, 30, 'synthetic-v1', 'stop', 20, 10)

    def test_first_checked_fragment_reaches_the_client_before_generation_ends(self):
        with patch('front.connectors.OpenAIConnector.chat', side_effect=self.generate), \
                patch('front.chat_streaming.EMIT_INTERVAL', 0.01):
            response = self.client.post('/chat/send/', {'prompt': 'Resume', 'request_id': str(uuid.uuid4()), 'stream': '1'})
            frames, buffer = response.streaming_content, ''
            seen_delta_while_blocked = False
            for raw in frames:
                buffer += raw.decode() if isinstance(raw, bytes) else raw
                if 'event: delta' in buffer and not seen_delta_while_blocked:
                    self.assertFalse(self.finished.is_set())
                    seen_delta_while_blocked = True
                    self.release.set()
                if 'event: final' in buffer:
                    break
            response.close()
        self.assertTrue(seen_delta_while_blocked)
        events = parse_sse(buffer)
        self.assertEqual(events[-1]['result']['status'], 'completed')
        self.assertTrue(events[-1]['result']['assistant_message']['content'].startswith(deltas(events)))
        for thread in threading.enumerate():
            if thread.name.startswith('chat-stream-'):
                thread.join(5)

    @override_settings(CHAT_STREAMING_EXTRA_HOSTS=['127.0.0.1'])
    def test_stop_closes_a_silent_provider_stream_at_once(self):
        """A reasoning model may send nothing for minutes; the stop must not wait for it."""
        closed = threading.Event()

        class SilentProvider(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                text = INTRO * 2
                for index in range(0, len(text), 12):
                    chunk = {'id': 'chatcmpl-silent', 'object': 'chat.completion.chunk', 'created': 0,
                             'model': 'synthetic-v1', 'choices': [{'index': 0, 'delta': {'content': text[index:index + 12]},
                                                                   'finish_reason': None}]}
                    self.wfile.write(b'data: ' + json.dumps(chunk).encode() + b'\n\n')
                    self.wfile.flush()
                for _ in range(150):  # Silent but alive: comments only, for up to 15 s.
                    time.sleep(0.1)
                    try:
                        self.wfile.write(b': thinking\n\n')
                        self.wfile.flush()
                    except OSError:
                        closed.set()
                        return

        server = ThreadingHTTPServer(('127.0.0.1', 0), SilentProvider)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        Engine.objects.update(base_url=f'http://127.0.0.1:{server.server_port}/v1')
        request_id = str(uuid.uuid4())
        with patch('front.chat_streaming.EMIT_INTERVAL', 0.01):
            response = self.client.post('/chat/send/', {'prompt': 'Resume', 'request_id': request_id, 'stream': '1'})
            buffer, stopped_at = '', None
            for raw in response.streaming_content:
                buffer += raw.decode() if isinstance(raw, bytes) else raw
                if 'event: delta' in buffer and stopped_at is None:
                    stopped_at = time.monotonic()
                    self.assertEqual(self.client.post(f'/chat/requests/{request_id}/cancel/').status_code, 202)
                if 'event: final' in buffer:
                    break
            response.close()
        self.assertIsNotNone(stopped_at, buffer[-1200:])
        self.assertLess(time.monotonic() - stopped_at, 5)
        self.assertTrue(closed.wait(5), 'the provider connection stayed open')
        events = parse_sse(buffer)
        final = events[-1]['result']
        self.assertEqual((final['status'], final['error_type']), ('cancelled', 'cancelled_by_user'))
        self.assertIn('retract', [event['type'] for event in events])
        self.assertFalse(Message.objects.filter(role='assistant').exists())
        generation = [call for call in Prompt.objects.get().decision['calls'] if call['purpose'] == 'generation'][0]
        self.assertEqual(generation['status'], 'cancelled')
        self.assertIsNone(generation['cost'])  # Generated tokens may be billed: never shown as zero.
        for thread in threading.enumerate():
            if thread.name.startswith('chat-stream-'):
                thread.join(5)
