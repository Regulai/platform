"""Real pinned Deep Agents; internal HTTP simulated to inspect every SDK seam."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'regulai'))
from test_probe import simulated_backend
from front.agents.adapter import (InternalClient, InternalOperationError, RegulayModel,
    ResultGate, build_agent)
from front.agents.protocol import TOOL_PARAMETERS
from deepagents.backends.protocol import ReadResult, WriteResult, FileDownloadResponse, FileUploadResponse
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command
from types import SimpleNamespace


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self.replies = []
        self.raw_marker = 'Nombre: Persona Sintetica; synthetic@example.invalid'
        def http(request):
            body = json.loads(request.content)
            name = request.url.path.rstrip('/').split('/')[-1]
            self.seen.append((name, body))
            self.assertEqual(request.headers['authorization'], 'Bearer synthetic-execution-token')
            self.assertEqual(request.headers['x-regulay-attempt'], 'synthetic-attempt')
            if name == 'authorize-tool':
                return httpx.Response(200, json={'status': 'authorized'})
            if name == 'tool-results':
                return httpx.Response(200, json={'status': 'withheld', 'code': 'raw_tool_output_withheld'})
            return httpx.Response(200, json={'status': 'completed', 'content': 'Approved synthetic summary.',
                'tool_calls': self.replies.pop(0) if self.replies else [], 'usage': {}})
        self.client = InternalClient('http://regulay.internal/internal/agents/', 'synthetic-execution-token',
            'synthetic-attempt', transport=httpx.MockTransport(http))
        self.addCleanup(self.client.close)

    def test_all_builtin_outputs_are_gated_before_context(self):
        cases = {
            'write_todos': {'todos': [{'content': 'Synthetic task', 'status': 'pending'}]},
            'ls': {'path': '/workspace/input'}, 'read_file': {'file_path': '/workspace/input/numbers.csv'},
            'write_file': {'file_path': '/workspace/work/a.txt', 'content': 'synthetic'},
            'edit_file': {'file_path': '/workspace/work/a.txt', 'old_string': 'a', 'new_string': 'b'},
            'glob': {'pattern': '*.csv', 'path': '/workspace/input'},
            'grep': {'pattern': 'x', 'path': '/workspace/input'},
            'execute': {'command': 'synthetic-command-never-run'},
        }
        for name, args in cases.items():
            with self.subTest(name=name):
                self.seen.clear()
                self.replies = [[{'id': 'sdk-call', 'name': name, 'args': args}]]
                backend, _ = simulated_backend()
                graph = build_agent(backend, self.client)
                result = graph.invoke({'messages': [HumanMessage(content='Synthetic task')]}, config={'recursion_limit': 12})
                messages = [m for m in result['messages'] if isinstance(m, ToolMessage)]
                self.assertTrue(messages)
                self.assertTrue(all(m.content == '{"code": "raw_tool_output_withheld", "status": "withheld"}' for m in messages))
                self.assertTrue(any(n == 'tool-results' for n, b in self.seen))
                self.assertFalse(any(m.artifact for m in messages))

    def test_errors_metadata_command_and_large_output_never_reach_model(self):
        gate = ResultGate(self.client)
        request = SimpleNamespace(tool_call={'id': 'sdk-call', 'name': 'execute', 'args': {'command': 'synthetic'}})
        raw = [ToolMessage(content=self.raw_marker * 3000, tool_call_id='sdk-call',
                           artifact={'image': self.raw_marker}, response_metadata={'stderr': self.raw_marker}),
               Command(update={'messages': [], 'todos': self.raw_marker, 'private_state': self.raw_marker})]
        for value in raw:
            safe = gate.wrap_tool_call(request, lambda _: value)
            self.assertNotIn(self.raw_marker, safe.content)
            self.assertIsNone(safe.artifact)
        def fail(_):
            raise RuntimeError(self.raw_marker)
        safe = gate.wrap_tool_call(request, fail)
        self.assertNotIn(self.raw_marker, safe.content)
        self.assertIn(self.raw_marker, json.dumps(self.seen[-1][1]['raw']))
        async def afail(_):
            raise RuntimeError(self.raw_marker)
        safe = asyncio.run(gate.awrap_tool_call(request, afail))
        self.assertNotIn(self.raw_marker, safe.content)

    def test_real_sdk_compaction_sync_and_async_uses_internal_operation(self):
        for asynchronous in (False, True):
            self.seen.clear()
            backend, _ = simulated_backend()
            backend.download_files = Mock(side_effect=lambda paths: [
                FileDownloadResponse(path=p, content=None, error='file_not_found') for p in paths])
            backend.upload_files = Mock(side_effect=lambda files: [
                FileUploadResponse(path=p, error=None) for p, _ in files])
            graph = build_agent(backend, self.client, model_profile={'max_input_tokens': 2000})
            history = [m for _ in range(20) for m in (HumanMessage(content='approved synthetic ' * 100), AIMessage(content='noted'))]
            history.append(HumanMessage(content='Summarize progress'))
            with (patch.object(backend, 'write', return_value=WriteResult(path='/conversation_history/test.md')),
                  patch.object(backend, 'read', return_value=ReadResult(error='File not found'))):
                if asynchronous:
                    asyncio.run(graph.ainvoke({'messages': history}, config={'recursion_limit': 12}))
                else:
                    graph.invoke({'messages': history}, config={'recursion_limit': 12})
            purposes = [b['purpose'] for n, b in self.seen if n == 'inference']
            self.assertIn('compaction', purposes)
            self.assertIn('generation', purposes)

    def test_stream_fallback_and_vision_cannot_bypass_adapter(self):
        model = RegulayModel(internal=self.client, cache=False)
        list(model.stream([HumanMessage(content='approved')]))
        self.assertEqual(self.seen[-1][0], 'inference')
        model.invoke([HumanMessage(content=[{'type': 'image_ref', 'reference': '00000000-0000-0000-0000-000000000001'}])])
        self.assertEqual(self.seen[-1][1]['purpose'], 'vision')
        with self.assertRaises(ValueError):
            model.invoke([HumanMessage(content=[{'type': 'image_url', 'image_url': {'url': 'http://external.invalid'}}])])
        with self.assertRaises(InternalOperationError):
            model.invoke([ToolMessage(content='raw', tool_call_id='x', name='execute', artifact={'raw': self.raw_marker})])

    def test_uncertain_and_redirect_responses_do_not_retry_model(self):
        for code, body in [(200, {'status': 'outcome_unknown', 'code': self.raw_marker}), (302, {})]:
            seen = []
            def http(request):
                seen.append(request)
                return httpx.Response(code, json=body, headers={'Location': 'https://external.invalid'})
            client = InternalClient('http://regulay.internal/', 'synthetic', 'attempt', transport=httpx.MockTransport(http))
            try:
                with self.assertRaises(InternalOperationError) as caught:
                    RegulayModel(internal=client, cache=False).invoke([HumanMessage(content='approved')])
                self.assertNotIn(self.raw_marker, str(caught.exception))
                self.assertEqual(len(seen), 1)
            finally:
                client.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
