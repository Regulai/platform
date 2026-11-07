"""No-upload creation, immutable generated data and existing publication gate."""
import base64
import copy
import json
import uuid

from django.test import SimpleTestCase, TestCase, override_settings
from front.agents import jobs
from front.agents.excel_contract import mock_source, mock_title, input_rows
from front.agents.service import AgentDenied, infer
from front.agents.data_views import tool_result
from front.models import AgentExecution, AgentInput
from front.test_agent_chat import ChatFixture, candidate_bytes

ROWS = [{'item': 'Producto A', 'amount_cents': 125},
        {'item': 'Producto B', 'amount_cents': 250},
        {'item': 'Producto C', 'amount_cents': 375}]


class MockDataValidationTests(SimpleTestCase):
    def test_bounds_types_and_csv_escaping(self):
        rows = copy.deepcopy(ROWS)
        rows[0]['item'] = 'Coma, comillas " y salto\n=SUM(A1)'
        self.assertEqual(input_rows(mock_source(rows), 'csv')[0], (rows[0]['item'],125))
        for invalid in ([], ROWS[:2], ROWS * 334,
                [dict(row, amount_cents=True) for row in ROWS],
                [dict(row, amount_cents=1.25) for row in ROWS],
                [dict(row, amount_cents=999999999999) for row in ROWS],
                [dict(row, item='') for row in ROWS],
                [dict(row, code='ignored') for row in ROWS]):
            with self.subTest(invalid=str(invalid)[:60]), self.assertRaises(ValueError):
                mock_source(invalid)


@override_settings(REGULAY_AGENT_ENABLED=True)
class MockExcelTests(ChatFixture, TestCase):
    def send(self, **kwargs):
        text = 'Crea un Excel con datos ficticios de ejemplo'
        return super().send(**{'prompt': text, 'content': text, **kwargs})

    def setUp(self):
        super().setUp()
        self.agent.tools.append('create_mock_excel')
        self.agent.save()

    def issue_mock(self, token, attempt, rows=ROWS):
        call = {'id': 'mock-' + uuid.uuid4().hex, 'name': 'create_mock_excel',
            'args': {'title': 'Productos de ejemplo', 'rows': rows}}
        self.reply_calls = [call]
        reply = infer(token, attempt, {'call_id': str(uuid.uuid4()),
            'messages': [{'role': 'user', 'content': 'Crea un Excel con datos ficticios'}],
            'tools': ['create_mock_excel']})
        self.assertEqual(reply['status'], 'completed', reply)
        return reply['tool_calls'][0]

    def test_three_entries_no_upload_replay_and_no_inference_in_request(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            request_id = uuid.uuid4()
            first = self.send(url=url, file=False, request_id=request_id)
            second = self.send(url=url, file=False, request_id=request_id)
            self.assertEqual(first.status_code, 202, first.content)
            self.assertEqual(first.json()['agent']['id'], second.json()['agent']['id'])
            run = AgentExecution.objects.get(pk=first.json()['agent']['id'])
            self.assertEqual(run.job['kind'], 'mock')
            self.assertIsNone(run.job['source'])
            self.assertFalse(AgentInput.objects.filter(execution=run).exists())
        self.assertFalse(self.requests)

    def test_generated_source_is_immutable_verified_and_revisable(self):
        response = self.send(file=False)
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        token, attempt = self.claimed(run)
        grant = jobs.bootstrap(token, attempt, {})
        self.assertIsNone(grant['input'])
        self.assertEqual(grant['tools'], ['create_mock_excel'])
        call = self.issue_mock(token, attempt)
        fields = jobs.local_fields(token, attempt, call)
        self.assertEqual(fields, jobs.local_fields(token, attempt, call))
        self.assertEqual(AgentInput.objects.filter(execution=run).count(), 1)
        self.assertEqual(base64.b64decode(fields['source_base64']), mock_source(ROWS))
        altered = self.issue_mock(token, attempt, [dict(row, amount_cents=500) for row in ROWS])
        with self.assertRaisesRegex(AgentDenied, 'mock_source_immutable'):
            jobs.local_fields(token, attempt, altered)
        data = candidate_bytes(mock_title(call['args']['title']), source=mock_source(ROWS))
        result = jobs.candidate(token, attempt, {'operation_id': str(uuid.uuid4()), 'call': call,
            'base64': base64.b64encode(data).decode()})
        self.assertEqual(result['status'], 'approved', result)
        tool_result(token, attempt, {'call': call, 'raw': {'content': json.dumps({'reference': result['reference']})}})
        jobs.complete(token, attempt, {})
        artifact = run.artifacts.get()
        self.assertEqual(artifact.verification['data_origin'], 'invented_sample_data')
        self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/').content, data)
        revision = self.send(url=f'/chat/{run.conversation_id}/send/', file=False, artifact_id=str(artifact.logical_id),
            base_revision=str(artifact.pk))
        self.assertEqual(revision.status_code, 202, revision.content)

    def test_unissued_cancelled_and_invalid_data_cannot_materialize(self):
        run = AgentExecution.objects.get(pk=self.send(file=False).json()['agent']['id'])
        token, attempt = self.claimed(run)
        call = self.issue_mock(token, attempt)
        forged = copy.deepcopy(call)
        forged['args']['rows'][0]['amount_cents'] = 999
        with self.assertRaisesRegex(AgentDenied, 'unissued_tool_call'):
            jobs.local_fields(token, attempt, forged)
        invalid = self.issue_mock(token, attempt, ROWS[:2])
        with self.assertRaises(ValueError):
            jobs.local_fields(token, attempt, invalid)
        jobs.cancel(self.user, run.pk)
        with self.assertRaises(AgentDenied):
            jobs.local_fields(token, attempt, call)
        self.assertFalse(AgentInput.objects.filter(execution=run).exists())
