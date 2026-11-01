"""Real pinned SDK graph/native tools; internal HTTP and sandbox I/O stay offline."""
import base64
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import httpx
from deepagents.backends.protocol import FileDownloadResponse
from e2b import CommandResult, Sandbox
from langchain_e2b import E2BSandbox

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'regulai'))
from front.agents.adapter import InternalClient, InternalOperationError
from front.agents.worker import run_job


class WorkerBoundary:
    """Script the trusted application's HTTP boundary, not the SDK or its gates."""
    def __init__(self, call, *, denied=False):
        self.call, self.denied = call, denied
        self.events, self.inferences = [], []

    def respond(self, request):
        if request.url.host != 'worker-internal.test' or request.method != 'POST':
            raise AssertionError('Worker attempted another destination')
        if request.headers.get('Authorization') != 'Bearer synthetic-worker-token':
            raise AssertionError('Missing internal authorization')
        name = request.url.path.removeprefix('/internal/').strip('/')
        payload = json.loads(request.content)
        self.events.append((name, payload))
        if name == 'run/bootstrap':
            value = {'status': 'authorized', 'input': None, 'base': None,
                'tools': [self.call['name']], 'message': 'Crea el documento solicitado.',
                'model_context': {'operation': 'create', 'request': {'format': 'docx'}}}
        elif name == 'inference':
            self.inferences.append(payload)
            value = {'status': 'completed', 'content': '' if len(self.inferences) == 1 else 'Listo.',
                'tool_calls': [self.call] if len(self.inferences) == 1 else []}
        elif name == 'authorize-tool':
            if self.denied:
                return httpx.Response(403, json={'status': 'denied'})
            value = {'status': 'authorized'}
        elif name == 'run/local-fields':
            args = payload['args']
            value = {'status': 'authorized', 'title': args['title'],
                'format': args.get('format', 'pptx'), 'narrative': {
                    'title': args['title'], 'language': args['language'],
                    'pages': args['content'], 'references': []}}
        elif name == 'run/candidate':
            value = {'status': 'approved', 'reference': 'private-candidate-reference'}
        elif name == 'run/research':
            value = {'status': 'approved', 'reference': 'private-research-reference'}
        elif name == 'tool-results':
            value = {'status': 'withheld' if payload['failed'] else 'approved',
                'view': {'reference': 'gateway-approved-view'}}
        elif name == 'run/review-status':
            value = {'status': 'completed', 'pending': False}
        elif name in ('run/step', 'run/complete', 'run/renew'):
            value = {'status': 'completed'}
        else:
            raise AssertionError('Unexpected internal operation: ' + name)
        return httpx.Response(200, json=value)


class NativeWorkerTests(unittest.TestCase):
    def run_worker(self, boundary):
        # Debug Sandbox construction performs no E2B allocation. Actual SDK
        # backend, decorators, ToolRuntime injection, graph and ResultGate run.
        sandbox = Sandbox.create(debug=True, api_key='synthetic-worker-only',
            sandbox_url='http://127.0.0.1:1', retries=0)
        sandbox.commands.run = Mock(return_value=CommandResult(
            stdout='private-command-log', stderr='', exit_code=0, error=None))
        sandbox.files.write = Mock()
        backend = E2BSandbox(sandbox=sandbox, workdir='/workspace/work', timeout=90)
        self.sandbox, self.backend = sandbox, backend
        transport = httpx.MockTransport(boundary.respond)
        internal = InternalClient('http://worker-internal.test/internal', 'synthetic-worker-token',
            'synthetic-attempt', transport=transport)
        external = {name: '' for name in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
            'DEEPSEEK_API_KEY', 'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY')}
        external.update(LANGSMITH_TRACING='false', LANGCHAIN_TRACING_V2='false')
        try:
            with (patch.dict(os.environ, external),
                  patch('socket.socket.connect', side_effect=AssertionError('Unexpected network access')),
                  patch('front.agents.worker.E2BSandbox', return_value=backend),
                  patch.object(backend, 'download_files', return_value=[FileDownloadResponse(
                      path='/workspace/work/final/candidate.zip', content=b'synthetic-candidate-bundle')])):
                return run_job(internal, sandbox)
        finally:
            internal.close()

    def test_native_document_and_presentation_accept_content_and_language(self):
        pages = [{'heading': 'Análisis', 'blocks': [{'kind': 'analysis',
            'text': 'Contenido de prueba para comprobar la transferencia completa al procedimiento local.', 'sources': []}]}]
        for name, output in [('build_document', 'docx'), ('build_document', 'pdf'), ('build_presentation', 'pptx')]:
            with self.subTest(tool=name, output=output):
                args = {'input_reference': '', 'title': 'Informe de prueba', 'section': 'Resumen',
                    'content': pages, 'language': 'es'}
                args.update({'template': 'new'} if output == 'pptx' else {'format': output})
                call = {'id': 'native-' + output, 'name': name, 'args': args}
                boundary = WorkerBoundary(call)
                self.assertEqual(self.run_worker(boundary)['status'], 'completed')
                preparations = [p for n, p in boundary.events if n == 'run/local-fields']
                self.assertEqual(preparations, [call])
                candidates = [p for n, p in boundary.events if n == 'run/candidate']
                self.assertEqual(len(candidates), 1)
                self.assertEqual(candidates[0]['call'], call)
                self.assertEqual(base64.b64decode(candidates[0]['document_bundle']), b'synthetic-candidate-bundle')
                commands = [c.args[0] for c in self.sandbox.commands.run.call_args_list]
                extension = 'pptx' if output == 'pptx' else 'docx'
                for phase in ('build', 'render', 'seal'):
                    self.assertTrue(any('/skills/narrative_program.py ' + phase in command
                        and '--extension ' + extension in command for command in commands))
                field_writes = [json.loads(c.args[1]) for c in self.sandbox.files.write.call_args_list
                    if c.args[0].endswith('/fields.json')]
                self.assertEqual(field_writes[-1]['narrative']['pages'], pages)
                self.assertEqual(field_writes[-1]['narrative']['language'], 'es')
                result_payload = next(p for n, p in boundary.events if n == 'tool-results')
                self.assertFalse(result_payload['failed'], result_payload['raw'])
                self.assertIn('private-command-log', json.dumps(result_payload['raw']))
                self.assertEqual(len(boundary.inferences), 2)
                for inference in boundary.inferences:
                    self.assertEqual(inference['tools'], [name])
                followup = json.dumps(boundary.inferences[-1])
                self.assertIn('gateway-approved-view', followup)
                self.assertNotIn('private-command-log', followup)
                self.assertNotIn('private-candidate-reference', followup)
                operations = [n for n, _ in boundary.events]
                self.assertLess(operations.index('authorize-tool'), operations.index('run/local-fields'))
                self.assertLess(operations.index('tool-results'), operations.index('run/complete'))

    def test_native_research_uses_only_trusted_internal_operation_and_result_gate(self):
        call = {'id': 'native-research', 'name': 'research_sources', 'args': {'ids': ['primary-source']}}
        boundary = WorkerBoundary(call)
        self.assertEqual(self.run_worker(boundary)['status'], 'completed')
        result_payload = next(p for n, p in boundary.events if n == 'tool-results')
        self.assertFalse(result_payload['failed'], result_payload['raw'])
        self.assertEqual([p for n, p in boundary.events if n == 'run/research'], [{'call': call}])
        operations = [n for n, _ in boundary.events]
        self.assertLess(operations.index('authorize-tool'), operations.index('run/research'))
        self.assertLess(operations.index('run/research'), operations.index('tool-results'))
        # Only initial sandbox mount is administrative; research runs no command.
        self.assertEqual(self.sandbox.commands.run.call_count, 1)
        self.sandbox.files.write.assert_not_called()
        followup = json.dumps(boundary.inferences[-1])
        self.assertIn('gateway-approved-view', followup)
        self.assertNotIn('private-research-reference', followup)
        self.assertEqual(boundary.inferences[0]['tools'], ['research_sources'])

    def test_denied_native_tool_never_prepares_or_executes_content(self):
        call = {'id': 'denied-document', 'name': 'build_document', 'args': {
            'input_reference': '', 'format': 'docx', 'title': 'Prueba', 'section': 'Resumen',
            'content': [], 'language': 'es'}}
        boundary = WorkerBoundary(call, denied=True)
        with self.assertRaises(InternalOperationError):
            self.run_worker(boundary)
        operations = [n for n, _ in boundary.events]
        self.assertIn('authorize-tool', operations)
        self.assertNotIn('run/local-fields', operations)
        self.assertNotIn('run/candidate', operations)
        self.assertNotIn('run/complete', operations)
        self.assertEqual(self.sandbox.commands.run.call_count, 1)
        self.sandbox.files.write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
