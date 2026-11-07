"""P0 observations run only against the source frozen by p1_baseline_run.py.

These are observations of the old contract, not permanent assertions that P1
must reject streaming. The SDK/network boundary and ASGI sockets are real;
provider bytes and usage are synthetic and never imply provider quality.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
from threading import Event, Thread
import time
from unittest import skipUnless
from unittest.mock import patch
import uuid

import httpx
from openai import OpenAI
from django.db import close_old_connections
from django.test import SimpleTestCase, TransactionTestCase, override_settings

from front.connectors import ChatMessage, OpenAIConnector
from front.models import AgentEvent, AgentExecution
from front.test_agent_work_limits import WorkLimitsFixture

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = json.loads((ROOT / 'evals/corpora/p1-harness/scenarios.json').read_text(encoding='utf-8'))
FROZEN = os.environ.get('P1_BASELINE_FROZEN') == '1'
REAL_CONNECTION = socket.create_connection


def record(name, value):
    directory = os.environ.get('P1_BASELINE_EVIDENCE')
    if directory:
        target = Path(directory) / (name + '.json')
        target.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def packet(delta=None, *, finish=None, usage=None):
    data = {'id': 'p1-synthetic-completion', 'object': 'chat.completion.chunk', 'created': 1,
            'model': 'synthetic-v1', 'choices': [] if usage else [
                {'index': 0, 'delta': delta or {}, 'finish_reason': finish}]}
    if usage:
        data['usage'] = usage
    return b'data: ' + json.dumps(data).encode() + b'\n\n'


class TextBytes(httpx.SyncByteStream):
    def __init__(self, before_final=None):
        self.before_final = before_final

    def __iter__(self):
        scenario = SCENARIOS['public_text']
        text = scenario['prefix'] * scenario['repeat']
        size = scenario['chunk_characters']
        for offset in range(0, len(text), size):
            yield packet({'content': text[offset:offset + size]})
        if self.before_final:
            self.before_final()
        yield packet(finish='stop')
        yield packet(usage=scenario['usage'])
        yield b'data: [DONE]\n\n'


@skipUnless(FROZEN, 'Historical P0 observation: use p1_baseline_run.py against its frozen source')
class P1SDKBaselineTests(SimpleTestCase):
    def connector(self, handler):
        value = OpenAIConnector('synthetic-key')
        value.client.close()
        value.client = OpenAI(api_key='synthetic-key', base_url='https://provider.invalid/v1', max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)))
        self.addCleanup(value.client.close)
        return value

    def test_public_sdk_chunks_arrive_before_usage_and_final_without_external_network(self):
        seen, before_final = Event(), Event()
        payloads, fragments = [], []

        def finish_barrier():
            self.assertTrue(seen.is_set(), 'No public text was observed before final usage')
            before_final.set()

        def provider(request):
            self.assertEqual(request.url.host, 'provider.invalid')
            payloads.append(json.loads(request.content))
            return httpx.Response(200, stream=TextBytes(finish_barrier), headers={'content-type': 'text/event-stream'})

        def delta(value):
            self.assertFalse(before_final.is_set())
            fragments.append(value)
            seen.set()

        with patch('socket.create_connection', side_effect=AssertionError('External sockets forbidden')):
            result = self.connector(provider).chat([ChatMessage(role='user', content='Madrid')],
                model='synthetic-v1', on_delta=delta)
        self.assertTrue(before_final.is_set())
        self.assertEqual(result.content, ''.join(fragments))
        self.assertEqual(result.tokens_used, 30)
        self.assertEqual(payloads[0]['stream_options'], {'include_usage': True})
        record('sdk-public-text', {'provider': 'synthetic', 'requests': payloads,
            'fragment_count': len(fragments), 'text_before_usage_and_final': True, 'usage': result.usage,
            'first_provider_event_kind': 'text', 'first_authorized_text_ms': None,
            'checkpoint_capture_ms': None, 'checkpoint_transfer_ms': None})

    def test_p0_tools_with_stream_are_rejected_before_http(self):
        requests = []
        connector = self.connector(lambda request: requests.append(request))
        with self.assertRaisesRegex(ValueError, 'does not carry tool calls'):
            connector.chat([ChatMessage(role='user', content='Read two files')], model='synthetic-v1',
                on_delta=lambda value: None, tools=[{'type': 'function', 'function': {
                    'name': 'read_file', 'parameters': {'type': 'object', 'properties': {}}}}])
        self.assertEqual(requests, [])
        record('sdk-tools-baseline', {'status': 'rejected_before_http', 'provider_calls': 0,
            'fixture': SCENARIOS['tool_interleaved'], 'reason': 'P0 connector has no tool streaming contract'})

    def test_local_sdk_overhead_distributions_record_all_twenty_samples(self):
        groups = []
        with patch('socket.create_connection', side_effect=AssertionError('External sockets forbidden')):
            for context in ('short', 'long'):
                for warmth in ('cold', 'warm'):
                    for conversations in (1, 2):
                        count = 2 if context == 'short' else 200
                        messages = [ChatMessage(role='user' if index % 2 == 0 else 'assistant',
                                     content='Texto sintético sin información privada.') for index in range(count)]
                        clients = []
                        samples = []

                        def single(connector):
                            started = time.perf_counter()
                            first = []
                            result = connector.chat(messages, model='synthetic-v1', on_delta=lambda _: first.append(
                                (time.perf_counter() - started) * 1000) if not first else None)
                            self.assertEqual(result.tokens_used, 30)
                            return {'first_provider_public_text_ms': first[0],
                                    'total_ms': (time.perf_counter() - started) * 1000}

                        def provider(request):
                            self.assertEqual(request.url.host, 'provider.invalid')
                            return httpx.Response(200, stream=TextBytes(), headers={'content-type': 'text/event-stream'})

                        for repetition in range(20):
                            if warmth == 'cold' or not clients:
                                for previous in clients:
                                    previous.client.close()
                                clients = [self.connector(provider) for _ in range(conversations)]
                            if conversations == 1:
                                values = [single(clients[0])]
                            else:
                                with ThreadPoolExecutor(max_workers=2) as executor:
                                    values = list(executor.map(single, clients))
                            samples.append({'repetition': repetition + 1, 'conversations': values})
                        totals = sorted(max(row['total_ms'] for row in sample['conversations']) for sample in samples)
                        groups.append({'context': context, 'messages': count, 'warmth': warmth,
                            'concurrent_conversations': conversations, 'sample_count': 20,
                            'median_ms': (totals[9] + totals[10]) / 2, 'p95_ms': totals[18],
                            'max_ms': totals[-1], 'samples': samples})
                        for connector in clients:
                            connector.client.close()
        record('sdk-overhead', {'measurement': 'local SDK parsing overhead with immediate synthetic chunks',
            'provider_latency_ms': None, 'semantic_quality': None, 'groups': groups})


@skipUnless(FROZEN, 'Historical P0 observation: use p1_baseline_run.py against its frozen source')
@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_CAPACITY={'provider': 2})
class P1ASGIBaselineTests(WorkLimitsFixture, TransactionTestCase):
    def test_three_adapters_expose_durable_activity_before_terminal_but_no_agent_text(self):
        import uvicorn
        from regulai.asgi import application

        def loopback_only(address, *args, **kwargs):
            if address[0] not in ('127.0.0.1', 'localhost', '::1'):
                raise AssertionError('External network forbidden')
            return REAL_CONNECTION(address, *args, **kwargs)

        self.enterContext(patch('socket.create_connection', side_effect=loopback_only))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(application, log_level='error', access_log=False, lifespan='off'))
        thread = Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(server.started)
        results = []
        try:
            with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=20,
                    cookies={key: value.value for key, value in self.client.cookies.items()}) as browser:
                for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
                    run = self.send(url)
                    self.start(run)
                    entered, release = Event(), Event()

                    def hold():
                        entered.set()
                        if not release.wait(20):
                            raise AssertionError('ASGI browser never released provider barrier')

                    self.after_request = hold

                    def infer():
                        close_old_connections()
                        try:
                            return self.ask()
                        finally:
                            close_old_connections()

                    with ThreadPoolExecutor(max_workers=1) as executor:
                        pending = executor.submit(infer)
                        self.assertTrue(entered.wait(15))
                        try:
                            with browser.stream('GET', f'/chat/agent/runs/{run.pk}/events/') as response:
                                self.assertEqual(response.status_code, 200)
                                lines = response.iter_lines()
                                before = []
                                for line in lines:
                                    before.append(line)
                                    if line == '':
                                        break
                                self.assertIn('event: progress', before)
                                self.assertFalse(pending.done())
                                self.assertNotIn('event: text_delta', before)
                                self.assertNotIn('Madrid es la capital', '\n'.join(before))
                                durable = list(AgentEvent.objects.filter(execution=run).values('kind', 'data'))
                                self.assertFalse(any(row['kind'] == 'text_delta' for row in durable))
                                release.set()
                                payload, reply = pending.result(15)
                                self.assertEqual(reply['status'], 'completed')
                                self.after_request = None
                                complete = self.internal('run/complete', {'final_call_id': payload['call_id']})
                                self.assertTrue(complete.json()['completed'])
                                after = list(lines)
                                self.assertIn('event: terminal', after)
                                run.refresh_from_db()
                                run.prompt.refresh_from_db()
                                results.append({'entry': url, 'run': str(run.pk), 'status': run.status,
                                    'before_final_frames': before, 'after_final_frames': after,
                                    'model_calls': len(run.prompt.decision.get('calls', [])),
                                    'provider_payload': self.requests[-1],
                                    'first_authorized_text_ms': None, 'agent_text_before_terminal': False})
                        finally:
                            release.set()
        finally:
            server.should_exit = True
            thread.join(10)
            listener.close()
        self.assertFalse(thread.is_alive())
        record('asgi-three-entries', {'provider': 'synthetic HTTP SDK fixture', 'real_asgi_socket': True,
                                     'barrier': 'provider held until browser receives activity', 'runs': results})
