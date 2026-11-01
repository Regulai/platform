"""Pinned SDK skills discovery/reads through HTTP, with allocation forbidden."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'regulai'))
from ops.agent_chat.test_p0_runtime import RuntimeBoundary, ENV
from front.agents.adapter import InternalClient
from front.agents.skill_backend import SkillBackend, compose
from front.agents.worker import run_job


class SkillsBoundary(RuntimeBoundary):
    def __init__(self, *, automatic=False, documental=False):
        super().__init__()
        self.automatic, self.documental = automatic, documental
        self.content = b'---\nname: design\ndescription: Design HTML\n---\nUNIQUE_BODY\n'
        self.entry = {'installation_id': str(uuid.uuid4()), 'revision_id': str(uuid.uuid4()),
            'folder_sha256': 'a' * 64, 'alias': 'design', 'authorization_version': 1,
            'metadata': {'name': 'design', 'description': 'Design HTML'}, 'compatibility': {},
            'manifest': [{'path': 'SKILL.md', 'bytes': len(self.content), 'sha256': hashlib.sha256(self.content).hexdigest()}],
            'discovery': '---\nname: design\ndescription: Design HTML\n---\n'}
        self.snapshot = {'version': 1, 'digest': 'b' * 64, 'selected': [], 'auto': True, 'catalog': [self.entry]}

    def respond(self, request):
        import httpx
        name = request.url.path.removeprefix('/internal/').strip('/')
        payload = json.loads(request.content)
        if name == 'run/skills':
            self.events.append((name, payload))
            return httpx.Response(200, json={'status': 'completed', **self.snapshot})
        if name == 'run/skill-resource':
            self.events.append((name, payload))
            return httpx.Response(200, json={'status': 'completed', 'files': [
                {'path': item['path'], 'base64': base64.b64encode(self.content).decode(),
                    'sha256': hashlib.sha256(self.content).hexdigest()} for item in payload['files']]})
        if name == 'inference' and self.automatic and not self.inferences:
            self.inferences.append(payload)
            self.events.append((name, payload))
            return httpx.Response(200, json={'status': 'completed', 'content': '',
                'tool_calls': [{'id': 'read-skill', 'name': 'read_file', 'args': {'file_path': '/skills/design/SKILL.md'}}],
                'inference': {'call_id': payload['call_id']}})
        response = super().respond(request)
        if name == 'run/bootstrap':
            value = response.json()
            value['skills'], value['tools'], value['sandbox_tools'] = self.snapshot, ['read_file'], ['read_file']
            if self.documental:
                value['base'] = None
                value['model_context']['operation'] = 'create'
            response = httpx.Response(200, json=value)
        return response


class SkillsRuntimeTests(unittest.TestCase):
    def invoke(self, boundary):
        import httpx
        internal = InternalClient('http://internal.test/internal', 'synthetic', uuid.uuid4(),
            transport=httpx.MockTransport(boundary.respond))
        acquire = Mock(side_effect=AssertionError('Skills read allocated a VM'))
        try:
            with patch.dict(os.environ, ENV), patch('socket.socket.connect', side_effect=AssertionError('Network denied')):
                result = run_job(internal, acquire=acquire)
            acquire.assert_not_called()
            return result
        finally:
            internal.close()

    def test_native_loader_uses_compact_metadata_with_typed_section_and_no_vm(self):
        boundary = SkillsBoundary()
        self.assertEqual(self.invoke(boundary)['status'], 'completed')
        messages = boundary.inferences[0]['messages']
        section = next(message for message in messages if message.get('skill_catalog'))
        self.assertEqual(section['skill_catalog']['digest'], boundary.snapshot['digest'])
        self.assertNotIn('UNIQUE_BODY', json.dumps(messages))
        self.assertFalse(any(name == 'run/skill-resource' for name, _ in boundary.events))
        self.assertEqual(len(boundary.inferences), 1)

    def test_professional_and_documental_automatic_read_use_no_vm(self):
        for documental in (False, True):
            with self.subTest(documental=documental):
                boundary = SkillsBoundary(automatic=True, documental=documental)
                self.assertEqual(self.invoke(boundary)['status'], 'completed')
                self.assertEqual(len(boundary.inferences), 2)
                names = [name for name, _ in boundary.events]
                self.assertLess(names.index('authorize-tool'), names.index('run/skill-resource'))

    def test_backend_paths_writes_async_and_revision_digest(self):
        boundary = SkillsBoundary()
        import httpx
        internal = InternalClient('http://internal.test/internal', 'synthetic', uuid.uuid4(),
            transport=httpx.MockTransport(boundary.respond))
        self.addCleanup(internal.close)
        backend = SkillBackend(internal, boundary.snapshot)
        self.assertIn('UNIQUE_BODY', backend.read('/design/SKILL.md').file_data['content'])
        self.assertIn('UNIQUE_BODY', asyncio.run(backend.aread('/design/SKILL.md')).file_data['content'])
        self.assertIsNotNone(backend.write('/design/SKILL.md', 'changed').error)
        self.assertIsNotNone(asyncio.run(backend.aedit('/design/SKILL.md', 'x', 'y')).error)
        self.assertIsNotNone(backend.download_files(['/design/../SKILL.md'])[0].error)
        self.assertIsNotNone(backend.download_files(['/unknown/SKILL.md'])[0].error)
        self.assertEqual(len(backend.glob('*.md').matches), 1)
        self.assertEqual(len(backend.grep('UNIQUE_BODY').matches), 1)


if __name__ == '__main__':
    unittest.main()
