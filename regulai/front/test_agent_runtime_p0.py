"""Checkpoint v2 authority, receipt reconstruction and v1 compatibility."""
import base64
from datetime import timedelta
from datetime import datetime
import hashlib
import io
import json
import uuid
import zipfile

from django.test import TestCase, override_settings
from django.utils import timezone

from front.models import AgentAccessGrant, AgentExecution, AgentInference, AgentInput
from front.policy import digest
from front.test_agent_inference import AgentFixture
from front.agents import checkpoints
from front.agents.capabilities import GENERAL
from front.agents.service import AgentDenied
from front.agents.runtime_contract import summary_content


@override_settings(REGULAY_AGENT_ENABLED=True, DEBUG=False)
class RuntimeCheckpointTests(AgentFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.professional = True
        self.agent.tools = sorted(GENERAL)
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.client.force_login(self.user)
        response = self.client.post('/chat/send/', {'prompt': 'Calcula la media de 4, 8 y 12 en el chat',
            'mode': 'agent', 'request_id': str(uuid.uuid4())})
        self.assertEqual(response.status_code, 202, response.content)
        self.run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        self.token = 'synthetic-runtime-p0'
        self.run.status, self.run.started_at = 'active', timezone.now()
        self.run.expires_at = timezone.now() + timedelta(seconds=60)
        self.run.token_digest = hashlib.sha256(self.token.encode()).hexdigest()
        self.run.save()

    def payload(self):
        return {'version': 2, 'messages': [{'type': 'human', 'data': {'content': 'Madrid'}}],
            'wire_messages': [{'role': 'user', 'content': 'Madrid'}], 'archive': None,
            'runtime_sha256': 'a' * 64, 'workspace_runtime_sha256': None, 'summarization': None}

    def save(self, payload):
        value = checkpoints.save(self.token, self.run.attempt, payload)
        self.run.refresh_from_db()
        return value

    def compaction(self):
        return AgentInference.objects.create(execution=self.run, call_id=uuid.uuid4(), attempt=self.run.attempt,
            request_digest='b' * 64, status='completed', response={'status': 'completed',
                'content': 'Madrid es la capital.', 'tool_calls': [], 'inference': {'purpose': 'compaction'}})

    def test_text_checkpoint_replay_preserves_one_row_and_null_archive(self):
        payload = self.payload()
        self.save(payload)
        self.save(payload)
        self.assertEqual(AgentInput.objects.filter(execution=self.run, kind='checkpoint').count(), 1)
        self.assertIsNone(checkpoints.load(self.run)['archive'])
        self.assertFalse(self.requests)

    def test_checkpoint_intervals_measure_server_work_and_volume_without_content(self):
        payload = self.payload()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('work/private-file.py', 'PRIVATE_CONTENT')
        payload['archive'] = base64.b64encode(archive.getvalue()).decode()
        payload['workspace_runtime_sha256'] = 'b' * 64
        self.save(payload)
        saved = self.run.events.get(kind='interval', data__category='checkpoint').data
        self.assertEqual(saved['phase'], 'save_server')
        self.assertEqual(saved['archive_bytes'], len(archive.getvalue()))
        self.assertEqual(saved['expanded_bytes'], len(b'PRIVATE_CONTENT'))
        self.assertEqual(saved['file_count'], 1)
        self.assertEqual(saved['message_count'], 1)
        self.assertGreater(saved['serialized_bytes'], saved['archive_bytes'])
        self.assertGreaterEqual(saved['duration_ms'], 0)
        self.assertLessEqual(datetime.fromisoformat(saved['started_at']), datetime.fromisoformat(saved['completed_at']))
        self.assertEqual(datetime.fromisoformat(saved['started_at']).utcoffset(), timedelta(0))
        self.assertNotIn('PRIVATE_CONTENT', json.dumps(saved))
        self.assertNotIn('private-file.py', json.dumps(saved))
        self.assertNotIn('Madrid', json.dumps(saved))
        self.run.status = 'cancelled'
        self.assertTrue(checkpoints.resumable(self.run))
        self.assertEqual(self.run.events.filter(kind='interval', data__category='checkpoint').count(), 1)
        self.run.status = 'active'
        self.run.job['restore_checkpoint'] = True
        self.assertEqual(checkpoints.load(self.run)['archive'], payload['archive'])
        restored = self.run.events.get(kind='interval', data__phase='restore_server').data
        self.assertEqual(restored['archive_bytes'], saved['archive_bytes'])
        self.assertEqual(restored['file_count'], 1)

    def test_serialized_messages_must_equal_the_governed_wire_projection(self):
        payload = self.payload()
        payload['messages'][0]['data']['content'] = 'Forged content'
        with self.assertRaisesRegex(ValueError, 'wire messages changed'):
            self.save(payload)
        self.assertFalse(AgentInput.objects.filter(execution=self.run, kind='checkpoint').exists())

    def test_summary_is_rebuilt_only_from_completed_receipt_without_offload_pointer(self):
        record = self.compaction()
        payload = self.payload()
        payload['summarization'] = {'cutoff_index': 1, 'compaction_call_id': str(record.call_id),
            'summary_digest': digest(record.response['content'])}
        self.save(payload)
        event = checkpoints.load(self.run)['_summarization_event']
        self.assertEqual(event['summary_message']['data']['content'], summary_content(record.response['content']))
        self.assertIsNone(event['file_path'])
        payload['summarization']['summary_digest'] = digest('Arbitrary replacement')
        with self.assertRaisesRegex(AgentDenied, 'compaction_unavailable'):
            self.save(payload)
        self.assertFalse(self.requests)

    def test_missing_compaction_and_cut_inside_tool_pair_are_rejected(self):
        record = self.compaction()
        payload = self.payload()
        with self.assertRaisesRegex(AgentDenied, 'compaction_missing'):
            self.save(payload)
        payload['summarization'] = {'cutoff_index': 1, 'compaction_call_id': str(record.call_id),
            'summary_digest': digest(record.response['content'])}
        payload['wire_messages'] = [{'role': 'assistant', 'content': '',
            'tool_calls': [{'id': 'unfinished', 'name': 'execute', 'args': {'command': 'echo 1'}}]}]
        with self.assertRaisesRegex(ValueError, 'splits tool results'):
            checkpoints._summary(self.run, payload)

    def test_v1_without_summary_remains_readable_but_later_inference_invalidates_watermark(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as output:
            output.writestr('work/new.py', 'print(42)')
        payload = self.payload()
        for field in ('version', 'workspace_runtime_sha256', 'summarization'):
            payload.pop(field)
        payload['archive'] = base64.b64encode(archive.getvalue()).decode()
        self.save(payload)
        self.assertEqual(checkpoints.load(self.run)['archive'], payload['archive'])
        with self.assertRaisesRegex(AgentDenied, 'workspace_missing'):
            self.save(self.payload())
        self.compaction()
        with self.assertRaisesRegex(AgentDenied, 'later_or_uncertain'):
            checkpoints.load(self.run)

    def test_only_completed_final_after_exact_checkpoint_can_be_reconciled(self):
        self.save(self.payload())
        record = AgentInference.objects.create(execution=self.run, call_id=uuid.uuid4(), attempt=self.run.attempt,
            request_digest='d' * 64, status='completed', response={'status': 'completed',
                'content': 'Madrid.', 'tool_calls': [], 'inference': {'purpose': 'generation'}})
        self.assertEqual(checkpoints.completed_final(self.run), str(record.call_id))
        record.status = 'outcome_unknown'
        record.save()
        self.assertIsNone(checkpoints.completed_final(self.run))
        record.status = 'completed'
        record.response['tool_calls'] = [{'id': 'pending', 'name': 'execute', 'args': {'command': 'echo x'}}]
        record.save()
        self.assertIsNone(checkpoints.completed_final(self.run))


