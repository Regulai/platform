"""Actual pinned graph advertises and invokes opt-in CAS/edit contracts."""
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

import httpx

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'regulai'))
from ops.agent_chat.test_p0_runtime import RuntimeBoundary, ENV
from front.agents.adapter import InternalClient
from front.agents.worker import run_job
from front.agents.workspace_backend import WorkspaceSandbox


class MutationBoundary(RuntimeBoundary):
    def __init__(self, name, args):
        super().__init__()
        self.name, self.args = name, args

    def respond(self, request):
        name = request.url.path.removeprefix('/internal/').strip('/')
        payload = json.loads(request.content)
        if name == 'inference' and not self.inferences:
            self.inferences.append(payload)
            self.events.append((name, payload))
            return httpx.Response(200, json={'status': 'completed', 'content': '', 'tool_calls': [
                {'id': 'mutation-one', 'name': self.name, 'args': self.args}], 'inference': {'call_id': payload['call_id']}})
        response = super().respond(request)
        if name == 'run/bootstrap':
            value = response.json()
            value['tools'] = value['sandbox_tools'] = [self.name]
            return httpx.Response(200, json=value)
        return response


class MutationGraphTests(unittest.TestCase):
    def test_replace_and_edit_reach_authorized_backend_with_expected_digest(self):
        for name, args in [('replace_file', {'file_path': '/workspace/work/file.txt',
                'expected_sha256': 'a' * 64, 'content': 'new content'}),
                ('edit_file', {'file_path': '/workspace/work/file.txt',
                    'expected_sha256': 'a' * 64, 'old_string': 'old', 'new_string': 'new'})]:
            with self.subTest(tool=name):
                boundary = MutationBoundary(name, args)
                internal = InternalClient('http://internal.test/internal', 'synthetic', uuid.uuid4(),
                    transport=httpx.MockTransport(boundary.respond))
                sandbox = Mock(sandbox_id='synthetic-cas')
                sandbox.commands.run.return_value = SimpleNamespace(stdout=json.dumps({
                    'exit_code': 0, 'stdout': '', 'stderr': '', 'truncated': False}))
                acquire = Mock(return_value=sandbox)
                try:
                    with patch.dict(os.environ, ENV), patch.object(WorkspaceSandbox, '_file', return_value=b'synthetic'), \
                            patch.object(WorkspaceSandbox, '_mutate', return_value={
                                'succeeded': True, 'code': 'file_written', 'occurrences': 1}) as mutation:
                        self.assertEqual(run_job(internal, acquire=acquire)['status'], 'completed')
                    acquire.assert_called_once()
                    mutation.assert_called_once()
                    self.assertEqual(mutation.call_args.kwargs['expected_sha256'], 'a' * 64)
                    self.assertEqual(boundary.inferences[0]['tools'], [name])
                    self.assertEqual(len(boundary.inferences), 2)
                    result = next(value for operation, value in boundary.events if operation == 'tool-results')
                    self.assertFalse(result['failed'])
                finally:
                    internal.close()


if __name__ == '__main__':
    unittest.main()
