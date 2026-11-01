"""P1 E6: real installed SDK, synthetic HTTP, durable PostgreSQL events only."""
from datetime import timedelta
from decimal import Decimal
import json
import io
import socket
import threading
import time
from types import SimpleNamespace
import uuid
from unittest.mock import patch

import httpx
from django.db import connection, connections, transaction
from django.core.management import call_command
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone
from openai import OpenAI

from front.chat_streaming import safe_cut, delivery_plan
from front.connectors import OpenAIConnector, ChatMessage
from front.local_masking import mask_local_texts
from front.models import AgentEvent, AgentExecution, AgentInference, AgentAccessGrant, Rule, RulesGroup
from front.test_agent_inference import AgentFixture
from front.test_agent_work_limits import WorkLimitsFixture
from front.agents.event_store import (append_event, append_events, serialized_event, utf8_frames,
    text_snapshot, compact_expired_text, fetch_event_batch)
from front.agents.streaming import CancellationWatch

REAL_CONNECTION = socket.create_connection


def chunk(delta=None, finish=None, usage=None):
    return ('data: ' + json.dumps({'id': 'synthetic-stream', 'object': 'chat.completion.chunk',
        'created': 1, 'model': 'agent-pinned-v1',
        'choices': [] if usage else [{'index': 0, 'delta': delta or {}, 'finish_reason': finish}],
        **({'usage': usage} if usage else {})}, ensure_ascii=False) + '\n\n').encode()


USAGE = {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120}


class ProviderStreamingTests(SimpleTestCase):
    def connector(self, frames):
        connector = OpenAIConnector('synthetic', 'https://provider.invalid/v1')
        connector.client.close()
        def http(request):
            self.sent = json.loads(request.content)
            return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=iter(frames))
        connector.client = OpenAI(api_key='synthetic', base_url='https://provider.invalid/v1', max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(http)))
        self.addCleanup(connector.client.close)
        return connector

    def test_interleaved_tools_are_returned_only_after_terminal_and_usage(self):
        events, legacy = [], []
        frames = [chunk({'content': 'Trabajo público', 'reasoning_content': 'PRIVATE REASONING',
            'tool_calls': [{'index': 0, 'id': 'call_a', 'type': 'function',
                'function': {'name': 'read_file', 'arguments': '{"file_path":"/work'}},
                {'index': 1, 'id': 'call_b', 'type': 'function',
                 'function': {'name': 'ls', 'arguments': '{"path":"/work'}}]}),
            chunk({'tool_calls': [{'index': 1, 'function': {'arguments': 'space"}'}},
                {'index': 0, 'function': {'arguments': 'space/a.txt"}'}}]}),
            chunk(finish='tool_calls'), chunk(usage=USAGE), b'data: [DONE]\n\n']
        result = self.connector(frames).chat([ChatMessage('user', 'x')], 'agent-pinned-v1',
            tools=[{'type': 'function', 'function': {'name': 'read_file', 'parameters': {'type': 'object'}}}],
            on_event=events.append, on_delta=legacy.append)
        self.assertTrue(self.sent['stream'])
        self.assertEqual(self.sent['stream_options'], {'include_usage': True})
        self.assertEqual([call['id'] for call in result.tool_calls], ['call_a', 'call_b'])
        self.assertEqual(result.tool_calls[0]['args'], {'file_path': '/workspace/a.txt'})
        self.assertEqual((result.input_tokens, result.output_tokens), (100, 20))
        self.assertEqual(legacy, ['Trabajo público'])
        self.assertNotIn('PRIVATE REASONING', repr(events))
        self.assertEqual([event.kind for event in events][-2:], ['finish', 'usage'])

    def test_truncated_invalid_inconsistent_tools_never_return_a_tool(self):
        start = {'tool_calls': [{'index': 0, 'id': 'call_a', 'type': 'function',
            'function': {'name': 'ls', 'arguments': '{"path":"/workspace"}'}}]}
        scenarios = {
            'length': [chunk(start), chunk(finish='length')],
            'eof': [chunk(start)],
            'changed_id': [chunk(start), chunk({'tool_calls': [{'index': 0, 'id': 'different'}]}), chunk(finish='tool_calls')],
            'partial': [chunk({'tool_calls': [{'index': 0, 'id': 'a', 'function': {'name': 'ls', 'arguments': '{'}}]}), chunk(finish='tool_calls')],
            'schema': [chunk({'tool_calls': [{'index': 0, 'id': 'a', 'function': {'name': 'ls', 'arguments': '{"wrong":1}'}}]}), chunk(finish='tool_calls')],
            'extra_after_finish': [chunk(start), chunk(finish='tool_calls'), chunk({'content': 'late'})],
            'duplicate_id': [chunk(start), chunk({'tool_calls': [{'index': 1, 'id': 'call_a'}]}), chunk(finish='tool_calls')],
        }
        for name, frames in scenarios.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.connector(frames).chat([ChatMessage('user', 'x')], 'agent-pinned-v1', on_event=lambda event: None)

    def test_bound_counts_tool_bytes_and_utf8_text(self):
        frames = [chunk({'content': 'á' * 100}), chunk(finish='stop')]
        with self.assertRaisesRegex(ValueError, 'too_large'):
            self.connector(frames).chat([ChatMessage('user', 'x')], 'm', on_event=lambda event: None, stream_max_bytes=128)
        text = 'aá😀e\u0301' * 2000
        parts = list(utf8_frames(text))
        self.assertEqual(''.join(parts), text)
        self.assertTrue(all(len(part.encode()) <= 4096 for part in parts))


class PrefixSecurityTests(SimpleTestCase):
    def test_every_cut_of_detector_patterns_is_a_prefix_of_final_masking(self):
        samples = ['ana@example.com', 'Correo contacto: juan perez arroba empresa punto com',
            '12345678-Z', 'X 1 2 3 4 5 6 7 L', 'ES91 2100 0418 4502 0005 1332',
            '+34 612 345 678', '+1 (212) 555 0198', '4111 1111 1111 1111',
            'sk-proj-' + 'a' * 512, 'ghp_' + 'b' * 255, 'AKIA' + 'A' * 16,
            'eyJ' + 'a' * 30 + '.' + 'b' * 30 + '.' + 'c' * 30,
            'Bearer\n' + 'a' * 300, 'password: ' + 'z' * 300,
            'https://username:password@example.invalid', 'Nombre:\nAna María López',
            'Nombre completo:\n\n' + 'A' * 140 + ' Pérez',
            '-----BEGIN RSA PRIVATE KEY-----\n' + 'a b\n' * 80 + '-----END RSA PRIVATE KEY-----',
            'Correo: ａｎａ＠ｅｘａｍｐｌｅ．ｃｏｍ', '６１２\u200b ３４５ ６７８',
            '{"email":"ana@example.com"}', '["password: secret-value"]']
        for sample in samples:
            text = ('Introducción pública. ' * 6 if not sample.startswith(('{', '[')) else '') + sample + '\n' + 'Texto público final. ' * 10
            final = mask_local_texts([text])[0]
            for end in range(1, len(text) + 1):
                cut = safe_cut(text[:end])
                shown = mask_local_texts([text[:cut]])[0] if cut else ''
                self.assertTrue(final.startswith(shown), (sample[:60], end, cut, shown))

    def test_all_yara_patterns_require_complete_and_detector_change_closes_delivery(self):
        engine = SimpleNamespace(engine=SimpleNamespace(connector_type='openai', base_url=''))
        base = dict(document=None, semantic=False, masks=[SimpleNamespace(backend='local')], engine=engine, rules=[])
        self.assertEqual(delivery_plan(**base), ('streamed', None))
        for pattern in ('"short"', '/a.{1,8000}b/', '/start.*end/'):
            rule = SimpleNamespace(applies_to='both', yara_rule=f'rule r {{ strings: $a={pattern} condition:any of them }}')
            self.assertEqual(delivery_plan(**{**base, 'rules': [rule]}), ('complete', 'policy_needs_complete_text'))
        with patch('front.chat_streaming.detector_metadata', return_value={'patterns_sha256': 'changed'}):
            self.assertEqual(delivery_plan(**base), ('complete', 'detector_stability_unverified'))


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_TEXT_STREAM=True,
                   CHAT_STREAMING_EXTRA_HOSTS=['provider.invalid'])
class DurableAgentStreamTests(AgentFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        AgentAccessGrant.objects.create(user=self.user, company=self.company, profile=self.agent, enabled=True)
        from front.agents.service import _context
        self.execution.conversation = self.conversation
        self.execution.authorization_digest = _context(self.prompt, self.agent.pk)[-1]
        self.execution.save(update_fields=['conversation', 'authorization_digest'])
        self.frames = []
        def connector(*args):
            value = OpenAIConnector(*args[1:])
            value.connector_type = args[0]
            value.client.close()
            def http(request):
                self.requests.append(json.loads(request.content))
                return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=self.body())
            value.client = OpenAI(api_key='synthetic', base_url='https://provider.invalid/v1', max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(http)))
            self.addCleanup(value.client.close)
            return value
        self.enterContext(patch('front.agents.service.get_connector', side_effect=connector))
        self.text = 'Texto público autorizado con acentos y 😀. ' * 12 + 'Correo: ana@example.com\n' + 'Fin público. ' * 12

    def body(self):
        yield chunk({'content': self.text})
        self.before_finish()
        yield chunk(finish='stop')
        yield chunk(usage=USAGE)
        yield b'data: [DONE]\n\n'

    def before_finish(self):
        pass

    def test_text_commits_before_provider_finishes_then_replays_without_a_second_call(self):
        observed = []
        self.before_finish = lambda: observed.extend(AgentEvent.objects.filter(kind='text.delta'))
        request = self.request()
        result = self.infer(request)
        self.assertEqual(result['status'], 'completed', result)
        self.assertTrue(observed, 'No authorized text committed before provider finish')
        self.assertEqual(result, self.infer(request))
        self.assertEqual(len(self.requests), 1)
        rows = list(AgentEvent.objects.filter(kind='text.delta'))
        text = ''.join(row.public_text for row in rows)
        self.assertEqual(text, result['content'])
        self.assertNotIn('ana@example', text)
        offset = 0
        for row in rows:
            self.assertEqual(row.data['offset'], offset)
            offset += len(row.public_text.encode())
            self.assertNotIn('text', row.data)
            self.assertEqual(serialized_event(row)['data']['text'], row.public_text)
        with connection.cursor() as cursor:
            cursor.execute('SELECT public_text FROM front_agentevent WHERE kind=%s', ['text.delta'])
            self.assertTrue(all('Texto público' not in raw[0] for raw in cursor.fetchall()))
        self.prompt.refresh_from_db()
        self.assertEqual(self.prompt.decision['total']['attempts'], 1)
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00014'))
        self.assertEqual(AgentInference.objects.count(), 1)

    def test_complete_policy_has_real_activity_and_no_delta_before_final(self):
        group = RulesGroup.objects.create(name='Complete', company=self.company)
        Rule.objects.create(name='Long pattern', rules_group=group,
            yara_rule='rule Hold { strings: $a = /start.{1,8000}end/ condition: any of them }')
        from front.agents.service import _context
        self.execution.authorization_digest = _context(self.prompt, self.agent.pk)[-1]
        self.execution.save(update_fields=['authorization_digest'])
        observed = []
        self.before_finish = lambda: observed.append(AgentEvent.objects.filter(kind='text.delta').count())
        self.assertEqual(self.infer()['status'], 'completed')
        self.assertEqual(observed, [0])
        self.assertFalse(AgentEvent.objects.filter(kind='text.delta').exists())
        self.assertEqual(AgentEvent.objects.get(kind='inference.started').data['reason'], 'policy_needs_complete_text')

    def test_durable_stop_closes_a_silent_provider_within_one_second(self):
        closed = threading.Event()
        watch = CancellationWatch(self.execution)
        watch.opened(closed.set)
        start = time.monotonic()
        AgentExecution.objects.filter(pk=self.execution.pk).update(status='cancelled')
        self.assertTrue(closed.wait(1), 'Silent stream not closed within 1 s')
        self.assertLessEqual(time.monotonic() - start, 1)
        watch.closed()

    def test_committed_batch_deduplicates_utf8_offsets_and_retention_preserves_snapshot(self):
        text = ('Público 😀' + '\n\t\x01\\\"') * 1000
        rows, offset = [], 0
        for part in utf8_frames(text):
            rows.append({'kind': 'text.delta', 'event_key': f'fixture:{offset}', 'public_text': part,
                'data': {'inference_id': 'fixture', 'message_id': 'fixture', 'offset': offset}})
            offset += len(part.encode())
        first = append_events(self.execution, rows)
        for row in first:
            frame = f'id: {row.pk}\nevent: progress\ndata: {json.dumps(serialized_event(row), ensure_ascii=False)}\n\n'
            self.assertLessEqual(len(frame.encode()), 4096)
        self.assertEqual([row.pk for row in first], [row.pk for row in append_events(self.execution, rows)])
        with self.assertRaisesRegex(ValueError, 'identity_conflict'):
            append_event(self.execution, 'text.delta', event_key=rows[0]['event_key'], public_text='changed')
        AgentEvent.objects.filter(pk__in=[row.pk for row in first]).update(created_at=timezone.now()-timedelta(hours=25))
        output = io.StringIO()
        call_command('purge_agent_data', run_id=[str(self.execution.pk)], stdout=output)
        self.assertIn(str(self.execution.pk), json.loads(output.getvalue())['text_snapshot_runs'])
        self.assertEqual(self.execution.events.filter(kind='text.delta').count(), len(first))
        call_command('purge_agent_data', apply=True, run_id=[str(self.execution.pk)], stdout=io.StringIO())
        self.assertEqual(self.execution.events.filter(kind='text.delta').count(), 0)
        self.assertEqual(compact_expired_text(self.execution), 0)
        snapshot = text_snapshot(self.execution)
        self.assertEqual(snapshot[0]['text'], text)
        self.assertTrue(snapshot[0]['expired'])
        batch = fetch_event_batch(self.user, self.execution.pk, 0)
        self.assertEqual(batch['events'][0]['kind'], 'text.snapshot')
        self.assertTrue(batch['events'][0]['data']['snapshot_required'])
        self.assertNotIn('text', batch['events'][0]['data'])
        self.assertEqual(batch['high_watermark'], batch['events'][-1]['id'])

    def test_post_dispatch_failure_keeps_authorized_partial_unknown_cost_and_no_retry(self):
        def fail():
            raise httpx.ReadError('private exception must not reach UI')
        self.before_finish = fail
        request = self.request()
        result = self.infer(request)
        self.assertEqual(result['status'], 'outcome_unknown')
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(AgentEvent.objects.filter(kind='text.delta').exists())
        self.assertTrue(AgentEvent.objects.get(kind='inference.finished').data['incomplete'])
        self.prompt.refresh_from_db()
        self.assertIsNone(self.prompt.decision['total']['cost'])
        self.assertFalse(self.prompt.decision['total']['complete'])

    def test_silent_sdk_http_stream_closes_on_durable_cancel_without_late_success(self):
        entered, closed, done = threading.Event(), threading.Event(), threading.Event()
        results = []
        class SilentBody(httpx.SyncByteStream):
            def __iter__(body):
                yield chunk({'content': self.text})
                entered.set()
                if not closed.wait(3):
                    raise AssertionError('Provider fixture was never closed')
                raise httpx.ReadError('closed fixture')
            def close(body):
                closed.set()
        def connector(*args):
            value = OpenAIConnector(*args[1:])
            value.connector_type = args[0]
            value.client.close()
            value.client = OpenAI(api_key='synthetic', base_url='https://provider.invalid/v1', max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(lambda request:
                    httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=SilentBody()))))
            self.addCleanup(value.client.close)
            return value
        request = self.request()
        def run():
            try:
                results.append(self.infer(request))
            finally:
                connections.close_all()
                done.set()
        with patch('front.agents.service.get_connector', side_effect=connector):
            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(entered.wait(3), 'Fixture provider did not start')
            from front.agents.jobs import cancel
            start = time.monotonic()
            cancel(self.user, self.execution.pk)
            self.assertTrue(closed.wait(1))
            self.assertLessEqual(time.monotonic()-start, 1)
            self.assertTrue(done.wait(3))
            thread.join(timeout=1)
        self.execution.refresh_from_db()
        self.prompt.refresh_from_db()
        self.assertEqual(self.execution.status, 'cancelled')
        self.assertEqual(self.prompt.status, 'cancelled')
        self.assertEqual(results[0]['status'], 'outcome_unknown')
        self.assertIsNone(self.prompt.decision['total']['cost'])
        self.assertFalse(AgentInference.objects.get().response.get('tool_calls'))

    def test_concurrent_append_commit_and_two_consumers_never_skip_a_lower_cursor(self):
        if connection.vendor != 'postgresql':
            self.skipTest('Row lock interleaving requires PostgreSQL')
        first_ready, release, second_done = threading.Event(), threading.Event(), threading.Event()
        errors, ids = [], []
        def first():
            try:
                with transaction.atomic():
                    row = append_event(self.execution, 'queued', event_key='writer:first')
                    ids.append(row.pk)
                    first_ready.set()
                    release.wait(3)
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()
        def second():
            try:
                first_ready.wait(3)
                ids.append(append_event(self.execution, 'claimed', event_key='writer:second').pk)
                second_done.set()
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()
        a, b = threading.Thread(target=first), threading.Thread(target=second)
        a.start(); b.start()
        self.assertTrue(first_ready.wait(3))
        self.assertFalse(second_done.wait(0.1), 'Second writer committed ahead of first')
        release.set()
        a.join(timeout=3); b.join(timeout=3)
        self.assertFalse(errors)
        self.assertEqual(ids, sorted(ids))
        for _ in range(2):
            first_batch = fetch_event_batch(self.user, self.execution.pk, 0, limit=1)
            second_batch = fetch_event_batch(self.user, self.execution.pk, first_batch['events'][-1]['id'])
            self.assertEqual([event['id'] for event in first_batch['events'] + second_batch['events']], ids)

    def test_byte_and_time_batches_do_not_create_one_event_or_charge_per_token(self):
        self.text = 'á😀 palabra. ' * 1000
        def many():
            for char in self.text:
                yield chunk({'content': char})
            yield chunk(finish='stop')
            yield chunk(usage=USAGE)
        self.body = many
        result = self.infer()
        self.assertEqual(result['status'], 'completed', result)
        rows = list(AgentEvent.objects.filter(kind='text.delta'))
        self.assertEqual(''.join(row.public_text for row in rows), self.text)
        self.assertLess(len(rows), 30)
        self.prompt.refresh_from_db()
        calls = self.prompt.decision['calls']
        self.assertEqual(sum(call['purpose'] == 'generation' for call in calls), 1)
        self.assertLess(sum(call['purpose'] == 'obfuscation' for call in calls), 5)

    def test_late_usage_is_charged_once_without_reviving_a_cancelled_run(self):
        from front.agents.jobs import cancel
        self.before_finish = lambda: cancel(self.user, self.execution.pk)
        # Deliberately model a transport whose close notification loses the race
        # to the usage receipt. Cancellation/real-close is tested separately.
        with patch('front.agents.streaming.CancellationWatch.opened', lambda *_: None):
            result = self.infer()
        self.assertNotEqual(result['status'], 'completed')
        self.execution.refresh_from_db()
        self.prompt.refresh_from_db()
        self.assertEqual(self.execution.status, 'cancelled')
        self.assertEqual(self.prompt.status, 'cancelled')
        # This fixture supplies a complete late usage receipt before the watcher
        # closes. A cancellation cannot turn that receipt into a refund.
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00014'))
        self.assertEqual(sum(c['purpose'] == 'generation' for c in self.prompt.decision['calls']), 1)

    def test_invalid_terminal_tools_preserve_known_usage_without_execution_or_resend(self):
        self.body = lambda: iter([
            chunk({'tool_calls': [{'index': 0, 'id': 'bad-json', 'type': 'function',
                'function': {'name': 'csv_totals', 'arguments': '{'}}]}),
            chunk(finish='tool_calls'), chunk(usage=USAGE), b'data: [DONE]\n\n'])
        request = self.request(tools=['csv_totals'])
        result = self.infer(request)
        self.assertEqual(result['status'], 'rejected', result)
        self.assertEqual(result['code'], 'invalid_provider_tool_calls')
        self.assertFalse(result.get('tool_calls'))
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(self.execution.operations.exists())
        self.prompt.refresh_from_db()
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00014'))
        self.assertTrue(self.prompt.decision['total']['complete'])

    @override_settings(ALLOWED_HOSTS=['127.0.0.1', 'testserver'])
    def test_real_asgi_and_loopback_proxy_flush_before_provider_finishes(self):
        import http.client
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import socket
        import uvicorn
        from django.core.asgi import get_asgi_application
        from django.conf import settings
        waiting, release, finished = threading.Event(), threading.Event(), threading.Event()
        result, errors = [], []
        def barrier():
            waiting.set()
            if not release.wait(6):
                raise AssertionError('Provider barrier was never released')
        self.before_finish = barrier
        self.client.force_login(self.user)
        cookie = f'{settings.SESSION_COOKIE_NAME}={self.client.cookies[settings.SESSION_COOKIE_NAME].value}'
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(get_asgi_application(), log_level='error', lifespan='off'))
        app_thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        class ForwardProxy(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(proxy):
                upstream = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
                try:
                    upstream.request('GET', proxy.path, headers={'Cookie': proxy.headers.get('Cookie', '')})
                    response = upstream.getresponse()
                    proxy.send_response(response.status)
                    for key in ('Content-Type', 'Cache-Control', 'X-Accel-Buffering'):
                        if response.getheader(key):
                            proxy.send_header(key, response.getheader(key))
                    proxy.end_headers()
                    while data := response.read1(4096):
                        proxy.wfile.write(data)
                        proxy.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
                finally:
                    upstream.close()
        proxy = ThreadingHTTPServer(('127.0.0.1', 0), ForwardProxy)
        proxy.daemon_threads = True
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        def infer_in_thread():
            try:
                result.append(self.infer())
            except Exception as error:
                errors.append(error)
            finally:
                connections.close_all()
                finished.set()
        inference_thread = threading.Thread(target=infer_in_thread)
        app_thread.start(); proxy_thread.start(); inference_thread.start()
        try:
            self.assertTrue(waiting.wait(4))
            with httpx.stream('GET', f'http://127.0.0.1:{proxy.server_port}/chat/agent/runs/{self.execution.pk}/events/',
                              headers={'Cookie': cookie}, timeout=5) as response:
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers['x-accel-buffering'], 'no')
                self.assertIn('no-store', response.headers['cache-control'])
                received = None
                for line in response.iter_lines():
                    if line.startswith('data: '):
                        value = json.loads(line[6:])
                        if value.get('kind') == 'text.delta':
                            received = value
                            break
                self.assertIsNotNone(received)
                self.assertTrue(received['data']['text'])
                self.assertNotIn('ana@example', received['data']['text'])
                self.assertFalse(finished.is_set(), 'First SSE text arrived only after provider completion')
                self.assertFalse(release.is_set())
        finally:
            release.set()
            finished.wait(4)
            inference_thread.join(timeout=1)
            AgentExecution.objects.filter(pk=self.execution.pk).update(status='cancelled')
            proxy.shutdown(); proxy.server_close()
            server.should_exit = True
            app_thread.join(timeout=3)
            listener.close()
        self.assertFalse(errors)
        self.assertEqual(result[0]['status'], 'completed', result)


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_TEXT_STREAM=True,
                   CHAT_STREAMING_EXTRA_HOSTS=['provider.invalid'], REGULAY_AGENT_CAPACITY={'provider': 2})
class ThreeEntryStreamingTests(WorkLimitsFixture, TransactionTestCase):
    def test_three_send_entries_and_two_profiles_stream_before_final_without_resending(self):
        from concurrent.futures import ThreadPoolExecutor
        import uvicorn
        from django.conf import settings
        from django.core.asgi import get_asgi_application

        def loopback(address, *args, **kwargs):
            if address[0] not in ('127.0.0.1', 'localhost', '::1'):
                raise AssertionError('External network forbidden')
            return REAL_CONNECTION(address, *args, **kwargs)
        self.enterContext(patch('socket.create_connection', side_effect=loopback))
        entered, release = threading.Event(), threading.Event()
        text = 'Texto público de Madrid con acentos y 😀. ' * 14

        class Body(httpx.SyncByteStream):
            def __iter__(body):
                yield chunk({'content': text, 'reasoning_content': 'PRIVATE_THINKING_SENTINEL'})
                entered.set()
                if not release.wait(8):
                    raise AssertionError('Provider was not released by SSE consumer')
                yield chunk(finish='stop')
                yield chunk(usage=USAGE)
                yield b'data: [DONE]\n\n'

        def connector(*args):
            value = OpenAIConnector(*args[1:])
            value.connector_type = args[0]
            value.client.close()
            def http(request):
                self.requests.append(json.loads(request.content))
                return httpx.Response(200, headers={'content-type': 'text/event-stream'}, stream=Body())
            value.client = OpenAI(api_key='synthetic', base_url='https://provider.invalid/v1', max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(http)))
            self.addCleanup(value.client.close)
            return value
        self.enterContext(patch('front.agents.service.get_connector', side_effect=connector))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0)); listener.listen(128)
        server = uvicorn.Server(uvicorn.Config(get_asgi_application(), log_level='error', lifespan='off'))
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic()+5
        while not server.started and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(server.started)
        cookie = f'{settings.SESSION_COOKIE_NAME}={self.client.cookies[settings.SESSION_COOKIE_NAME].value}'
        try:
            for entry in ('/chat/', '/chat/send/', '/api/chat/send/'):
                for profile in ('quick', 'reasoned'):
                    with self.subTest(entry=entry, profile=profile):
                        identity = uuid.uuid4()
                        run = self.send(entry, profile, identity=identity)
                        self.assertEqual(self.send(entry, profile, identity=identity).pk, run.pk)
                        self.start(run)
                        entered.clear(); release.clear()
                        request = self.request()
                        def infer_http():
                            try:
                                response = self.internal('inference', request)
                                self.assertEqual(response.status_code, 200, response.content)
                                return response.json()
                            finally:
                                connections.close_all()
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            pending = executor.submit(infer_http)
                            try:
                                self.assertTrue(entered.wait(5), pending.result() if pending.done() else 'Provider did not start')
                                with httpx.stream('GET', f'http://127.0.0.1:{listener.getsockname()[1]}/chat/agent/runs/{run.pk}/events/',
                                        headers={'Cookie': cookie}, timeout=5) as response:
                                    self.assertEqual(response.status_code, 200)
                                    received = None
                                    lines = response.iter_lines()
                                    for line in lines:
                                        if line.startswith('data: '):
                                            value = json.loads(line[6:])
                                            if value.get('kind') == 'text.delta':
                                                received = value
                                                break
                                    self.assertIsNotNone(received)
                                    self.assertFalse(pending.done())
                                    self.assertNotIn('PRIVATE_THINKING', json.dumps(received))
                                    release.set()
                                    result = pending.result(5)
                                    self.assertEqual(result['status'], 'completed', result)
                                    calls = len(self.requests)
                                    self.assertEqual(self.internal('inference', request).json(), result)
                                    self.assertEqual(len(self.requests), calls)
                                    self.assertEqual(self.requests[-1]['thinking']['type'], 'disabled' if profile == 'quick' else 'enabled')
                                    self.assertTrue(self.internal('run/complete', {'final_call_id': request['call_id']}).json()['completed'])
                                    tail = '\n'.join(lines)
                                    self.assertIn('event: terminal', tail)
                                self.assertEqual(run.events.filter(kind='inference.started').count(), 1)
                                self.assertEqual(run.events.filter(kind='inference.finished').count(), 1)
                                self.assertEqual(run.events.filter(kind='run.finished').count(), 1)
                            finally:
                                release.set()
            self.assertEqual(len(self.requests), 6)
        finally:
            release.set()
            server.should_exit = True
            thread.join(timeout=5)
            listener.close()
        self.assertFalse(thread.is_alive())
