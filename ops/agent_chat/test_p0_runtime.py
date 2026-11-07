"""Pinned SDK runtime boundaries with in-memory HTTP and no external sockets."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

import httpx
from langchain_core.messages import HumanMessage
from deepagents.middleware.summarization import SummarizationMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'regulai'))
from front.agents.adapter import InternalClient, InternalOperationError, RegulayModel, ResultGate
from front.agents.runtime_contract import canonical_digest, compaction_call_id, summary_content
from front.agents.professional_worker import runtime_identity
from front.agents.sandbox_pool import CleanPool
from front.agents.worker import Lease, run_job, run
from front.agents.workspace_backend import WorkspaceSandbox


LIMITS = {'command_seconds': 20, 'output_bytes': 200000, 'file_bytes': 20000000,
    'memory_mb': 1024, 'processes': 64, 'workspace_bytes': 512 * 1024 * 1024,
    'pdf_pages': 20, 'tool_calls': 4, 'model_calls': 3, 'run_seconds': 60}
ENV = {name: '' for name in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
    'DEEPSEEK_API_KEY', 'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY')}


class RuntimeBoundary:
    def __init__(self, *, denied=False, execute=False):
        self.execution = str(uuid.uuid4())
        self.events, self.inferences = [], []
        self.denied, self.execute = denied, execute

    def respond(self, request):
        if request.url.host != 'internal.test':
            raise AssertionError('Unexpected network destination')
        name = request.url.path.removeprefix('/internal/').strip('/')
        payload = json.loads(request.content)
        self.events.append((name, payload))
        if name == 'run/bootstrap':
            value = {'status': 'authorized', 'execution': self.execution, 'input': None,
                'tools': ['execute'], 'sandbox_tools': ['execute'], 'message': 'Capital de España',
                'model_context': {'operation': 'professional'}, 'limits': LIMITS,
                'model_profile': {'max_input_tokens': 12000, 'max_output_tokens': 1024},
                'effective_options': {'max_output_tokens': 1024, 'thinking': 'disabled'}}
            if hasattr(self, 'checkpoint'):
                value['checkpoint'] = self.checkpoint
            if hasattr(self, 'reconcile_final_call_id'):
                value['reconcile_final_call_id'] = self.reconcile_final_call_id
        elif name == 'inference':
            self.inferences.append(payload)
            calls = [{'id': 'execute-1', 'name': 'execute', 'args': {'command': 'echo 42'}}] if self.execute and len(self.inferences) == 1 else []
            value = {'status': 'completed', 'content': '' if calls else 'Madrid.',
                'tool_calls': calls, 'inference': {'call_id': payload['call_id']}}
        elif name == 'authorize-tool':
            if self.denied:
                return httpx.Response(403, json={'code': 'revoked'})
            value = {'status': 'authorized'}
        elif name == 'tool-results':
            value = {'status': 'approved', 'view': '42'}
        elif name == 'run/review-status':
            value = {'status': 'completed', 'pending': False}
        elif name == 'run/complete':
            value = {'status': 'completed', 'completed': True}
        elif name in ('run/checkpoint', 'run/renew'):
            value = {'status': 'completed'}
        else:
            raise AssertionError(name)
        return httpx.Response(200, json=value)


class LazyRuntimeTests(unittest.TestCase):
    def invoke(self, boundary, acquire):
        internal = InternalClient('http://internal.test/internal', 'synthetic', uuid.uuid4(),
            transport=httpx.MockTransport(boundary.respond))
        try:
            with patch.dict(os.environ, ENV), patch('socket.socket.connect', side_effect=AssertionError('Network denied')):
                return run_job(internal, acquire=acquire)
        finally:
            internal.close()

    def test_text_real_graph_has_zero_allocations_and_textual_v2_checkpoint(self):
        boundary, acquire = RuntimeBoundary(), Mock(side_effect=AssertionError('No workspace for text'))
        self.assertEqual(self.invoke(boundary, acquire)['status'], 'completed')
        acquire.assert_not_called()
        checkpoints = [payload for name, payload in boundary.events if name == 'run/checkpoint']
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0]['version'], 2)
        self.assertIsNone(checkpoints[0]['archive'])
        self.assertIsNone(checkpoints[0]['summarization'])
        self.assertEqual(len(boundary.inferences), 1)

    def test_completed_final_reconciliation_never_invokes_model_or_workspace(self):
        boundary, acquire = RuntimeBoundary(), Mock()
        boundary.reconcile_final_call_id = str(uuid.uuid4())
        result = self.invoke(boundary, acquire)
        self.assertTrue(result['reconciled'])
        self.assertFalse(boundary.inferences)
        acquire.assert_not_called()
        self.assertEqual([payload for name, payload in boundary.events if name == 'run/complete'],
            [{'final_call_id': boundary.reconcile_final_call_id}])

    def test_denial_precedes_allocation_in_actual_graph(self):
        boundary, acquire = RuntimeBoundary(denied=True, execute=True), Mock()
        with self.assertRaisesRegex(InternalOperationError, 'revoked'):
            self.invoke(boundary, acquire)
        acquire.assert_not_called()

    def test_authorized_first_command_prepares_once_and_crosses_isolated_runner(self):
        boundary = RuntimeBoundary(execute=True)
        sandbox = Mock(sandbox_id='synthetic-one')
        def command(command, **kwargs):
            boundary.events.append(('sandbox-command', {'command': command, **kwargs}))
            return SimpleNamespace(stdout=json.dumps({'exit_code': 0, 'stdout': '42',
                'stderr': '', 'truncated': False, 'timed_out': False}))
        sandbox.commands.run.side_effect = command
        acquire = Mock(return_value=sandbox)
        with patch.object(WorkspaceSandbox, '_file', return_value=b'synthetic-runtime-and-checkpoint'):
            self.assertEqual(self.invoke(boundary, acquire)['status'], 'completed')
        acquire.assert_called_once()
        names = [name for name, _ in boundary.events]
        self.assertLess(names.index('authorize-tool'), names.index('sandbox-command'))
        commands = [payload for name, payload in boundary.events if name == 'sandbox-command']
        generated = [payload for payload in commands if payload['command'].startswith('python -I /skills/sandbox_runner.py ')]
        self.assertTrue(generated)
        self.assertTrue(all(payload['user'] == 'user' for payload in generated))
        decoded = [json.loads(base64.b64decode(payload['command'].split()[-1].strip("'"))) for payload in generated]
        self.assertIn('echo 42', [payload['command'] for payload in decoded])

    def test_resumed_summary_and_pending_archive_survive_without_materialization(self):
        boundary, acquire = RuntimeBoundary(), Mock(side_effect=AssertionError('Text restore allocated'))
        content = summary_content('Madrid es la capital.')
        boundary.checkpoint = {'version': 2, 'messages': [
            {'type': 'human', 'data': {'content': 'Capital de España'}},
            {'type': 'ai', 'data': {'content': 'Madrid.'}},
            {'type': 'human', 'data': {'content': 'Recuerda esa ciudad'}}],
            'archive': base64.b64encode(b'preserved archive').decode(),
            'runtime_sha256': runtime_identity(), 'workspace_runtime_sha256': 'b' * 64,
            'summarization': {'cutoff_index': 2, 'compaction_call_id': str(uuid.uuid4()),
                'summary_digest': canonical_digest('Madrid es la capital.')},
            '_summarization_event': {'cutoff_index': 2, 'file_path': None, 'summary_message': {
                'type': 'human', 'data': {'content': content, 'additional_kwargs': {'lc_source': 'summarization'}}}}}
        self.assertEqual(self.invoke(boundary, acquire)['status'], 'completed')
        acquire.assert_not_called()
        self.assertEqual([request['purpose'] for request in boundary.inferences], ['generation'])
        self.assertIn(content, [message['content'] for message in boundary.inferences[0]['messages']])
        saved = next(payload for name, payload in boundary.events if name == 'run/checkpoint')
        self.assertEqual(saved['archive'], boundary.checkpoint['archive'])
        self.assertEqual(saved['summarization'], boundary.checkpoint['summarization'])

    def test_lazy_backend_rejects_implicit_offload_and_all_async_bypasses(self):
        prepare = Mock()
        backend = WorkspaceSandbox(limits=LIMITS, lease=SimpleNamespace(check=lambda: None), prepare=prepare)
        self.assertIsNotNone(backend.write('/conversation_history/thread.md', 'private').error)
        self.assertIsNotNone(backend.upload_files([('/workspace/work/x', b'x')])[0].error)
        self.assertIsNotNone(backend.download_files(['/workspace/work/x'])[0].error)
        for operation in [lambda: backend.execute('echo x'), lambda: backend.ls('/workspace'),
                lambda: backend.read('/workspace/work/x'), lambda: backend.glob('*'), lambda: backend.grep('x')]:
            with self.assertRaises(ValueError):
                operation()
        self.assertIsNotNone(backend.edit('/workspace/work/x', 'x', 'y').error)
        with self.assertRaises(ValueError):
            asyncio.run(backend.aexecute('echo bypass'))
        self.assertIsNotNone(asyncio.run(backend.aupload_files([('/workspace/work/x', b'x')]))[0].error)
        prepare.assert_not_called()

    def test_concurrent_authorized_preparation_allocates_once_and_replay_does_not_prepare(self):
        count = []
        def prepare(backend):
            count.append(1)
            backend._sandbox = SimpleNamespace(sandbox_id='one')
        backend = WorkspaceSandbox(limits=LIMITS, lease=SimpleNamespace(check=lambda: None), prepare=prepare)
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: backend.prepare_authorized(), range(2)))
        self.assertEqual(count, [1])
        internal = SimpleNamespace(operation=lambda *_: {'replay': {'view': 'recorded'}})
        gate = ResultGate(internal, Mock(side_effect=AssertionError('Replay allocated')))
        message = gate.wrap_tool_call(SimpleNamespace(tool_call={'id': 'old', 'name': 'execute', 'args': {}}), Mock())
        self.assertEqual(message.tool_call_id, 'old')

    def test_pool_does_not_warm_and_retains_uncertain_destruction(self):
        sandbox = Mock(sandbox_id='one')
        factory = Mock(return_value=sandbox)
        pool = CleanPool(factory)
        factory.assert_not_called()
        self.assertIs(pool.take(), sandbox)
        self.assertIsNone(pool.take())
        sandbox.kill.side_effect = RuntimeError('response lost')
        self.assertFalse(pool.release(sandbox))
        self.assertIsNone(pool.take())
        sandbox.kill.side_effect = None
        self.assertTrue(pool.release(sandbox))
        pool.close()

    def test_pinned_summarizer_retries_same_completed_call_and_cannot_allocate(self):
        execution, requests, effects = str(uuid.uuid4()), [], {}
        def respond(request):
            payload = json.loads(request.content)
            requests.append(payload)
            effects.setdefault(payload['call_id'], {'status': 'completed', 'content': 'Madrid es la capital.',
                'tool_calls': [], 'inference': {'call_id': payload['call_id'], 'purpose': 'compaction'}})
            if len(requests) <= 2:
                raise httpx.ReadError('Both internal responses lost', request=request)
            return httpx.Response(200, json=effects[payload['call_id']])
        internal = InternalClient('http://internal.test/internal', 'synthetic', uuid.uuid4(), transport=httpx.MockTransport(respond))
        internal.configure({'execution': execution, 'effective_options': {'max_output_tokens': 1024}})
        backend = WorkspaceSandbox(limits=LIMITS, lease=SimpleNamespace(check=lambda: None), prepare=Mock())
        middleware = SummarizationMiddleware(model=RegulayModel(internal=internal), backend=backend,
            trigger=('tokens', 50), keep=('messages', 2))
        try:
            with patch('socket.socket.connect', side_effect=AssertionError('Network denied')):
                messages = [HumanMessage(content='Madrid es la capital de España.')]
                self.assertIsNone(middleware._offload_to_backend(backend, messages))
                self.assertEqual(middleware._create_summary(messages), 'Madrid es la capital.')
            self.assertEqual(len(effects), 1)
            self.assertEqual(len(requests), 3)
            self.assertEqual(requests[0]['call_id'], compaction_call_id(execution,
                requests[0]['messages'], internal.effective_options))
            self.assertEqual(len(internal.compactions), 1)
            backend._prepare.assert_not_called()
        finally:
            internal.close()

    def test_dispatcher_completes_other_chat_while_first_is_held_without_shared_client(self):
        hold, second_done, stop = threading.Event(), threading.Event(), threading.Event()
        claims, clients = [], []
        def respond(request):
            payload = json.loads(request.content)
            claims.append(payload)
            if len(claims) > 2:
                return httpx.Response(200, json={'status': 'idle'})
            return httpx.Response(200, json={'status': 'claimed', 'execution': str(uuid.uuid4()),
                'attempt': str(uuid.uuid4()), 'token': 'task-' + str(len(claims))})
        real_client = httpx.Client
        def fake_job(internal, *, acquire, started):
            clients.append(internal)
            with Lease(internal) as lease:
                started(lease)
                if internal.token == 'task-1':
                    self.assertTrue(hold.wait(5))
                else:
                    second_done.set()
            return {'status': 'completed'}
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'worker-token'
            token.write_text('synthetic')
            def client(*args, **kwargs):
                kwargs['transport'] = httpx.MockTransport(respond)
                return real_client(*args, **kwargs)
            failure = []
            def dispatch():
                try:
                    run({'worker_token_file': str(token), 'internal_endpoint': 'http://internal.test/internal',
                         'shutdown_grace_seconds': 1}, stop_event=stop)
                except BaseException as error:
                    failure.append(error)
            with patch('front.agents.worker.httpx.Client', side_effect=client), patch('front.agents.worker.run_job', side_effect=fake_job), \
                    patch('front.agents.worker.create_clean', side_effect=AssertionError('Text allocated VM')):
                thread = threading.Thread(target=dispatch)
                thread.start()
                try:
                    self.assertTrue(second_done.wait(5), failure)
                    self.assertFalse(hold.is_set())
                    self.assertEqual(len(clients), 2)
                    self.assertIsNot(clients[0], clients[1])
                    self.assertIsNot(clients[0].client, clients[1].client)
                finally:
                    hold.set()
                    stop.set()
                    thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failure, [])

    def test_dispatcher_logs_failure_type_without_exception_content_or_tokens(self):
        execution, attempt = str(uuid.uuid4()), str(uuid.uuid4())
        private_message = 'synthetic-private-exception-content'
        request_paths = []
        def respond(request):
            request_paths.append(request.url.path)
            if request.url.path.endswith('/claim/'):
                return httpx.Response(200, json={'status': 'claimed', 'execution': execution,
                    'attempt': attempt, 'token': 'synthetic-secret-task-token'})
            return httpx.Response(200, json={'status': 'completed'})
        real_client = httpx.Client
        def client(*args, **kwargs):
            kwargs['transport'] = httpx.MockTransport(respond)
            return real_client(*args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'worker-token'
            token.write_text('synthetic-secret-worker-token')
            with patch('front.agents.worker.httpx.Client', side_effect=client), \
                    patch('front.agents.worker.run_job', side_effect=FileNotFoundError(private_message)), \
                    patch('front.agents.worker.create_clean', side_effect=AssertionError('Failure allocated VM')), \
                    patch('builtins.print') as output:
                with self.assertRaises(InternalOperationError):
                    run({'worker_token_file': str(token), 'internal_endpoint': 'http://internal.test/internal',
                         'shutdown_grace_seconds': 1}, once=True)
                output.assert_called_once()
                text = output.call_args.args[0]
        record = json.loads(text)
        self.assertEqual(record['execution'], execution)
        self.assertEqual(record['status'], 'failed')
        self.assertEqual(record['error_type'], 'FileNotFoundError')
        self.assertIsNone(record['sandbox_id'])
        self.assertGreaterEqual(record['seconds'], 0)
        for secret in (private_message, 'synthetic-secret-task-token', 'synthetic-secret-worker-token', attempt):
            self.assertNotIn(secret, text)
        self.assertIn('/internal/run/fail/', request_paths)

    def test_registered_sigterm_forces_exit_with_stalled_executor_thread(self):
        # Windows cannot deliver POSIX SIGTERM to Python. Exercise the exact
        # registered callback in a child, with only the 34s clock accelerated.
        program = textwrap.dedent('''
            import json, signal, sys, threading
            from pathlib import Path
            import httpx
            from front.agents import worker
            from unittest.mock import patch
            root = Path(sys.argv[1])
            timer_type, handlers = threading.Timer, {}
            def timer(seconds, callback):
                assert seconds == 34
                return timer_type(.4, callback)
            def job(internal, *, acquire, started):
                lease = worker.Lease(internal)
                lease.sandbox = type('Sandbox', (), {'kill': lambda self: (root / 'killed').write_text('yes')})()
                started(lease)
                timer_type(.02, lambda: handlers[signal.SIGTERM]()).start()
                threading.Event().wait(30)
            def respond(request):
                return httpx.Response(200, json={'status': 'claimed', 'execution': 'one',
                    'attempt': 'attempt', 'token': 'synthetic'})
            client_type = httpx.Client
            def client(*args, **kwargs):
                kwargs['transport'] = httpx.MockTransport(respond)
                return client_type(*args, **kwargs)
            sys.argv = ['worker', '--config', str(root / 'config.json')]
            with patch('front.agents.worker.run_job', side_effect=job), \
                    patch('front.agents.worker.httpx.Client', side_effect=client), \
                    patch('front.agents.worker.threading.Timer', side_effect=timer), \
                    patch('front.agents.worker.signal.signal', side_effect=lambda sig, handler: handlers.update({sig: handler})):
                worker.main()
        ''')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'token').write_text('synthetic')
            (root / 'config.json').write_text(json.dumps({'worker_token_file': str(root / 'token'),
                'internal_endpoint': 'http://internal.test/internal', 'concurrency': 1, 'shutdown_grace_seconds': .05}))
            environment = dict(os.environ, **ENV)
            environment['PYTHONPATH'] = str(Path(__file__).resolve().parents[2] / 'regulai')
            response = subprocess.run([sys.executable, '-c', program, directory], env=environment,
                capture_output=True, text=True, timeout=15)
            self.assertEqual(response.returncode, 143, response.stderr)
            self.assertEqual((root / 'killed').read_text(), 'yes')


if __name__ == '__main__':
    unittest.main()
