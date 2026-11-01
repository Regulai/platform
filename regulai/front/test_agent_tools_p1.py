"""P1 typed tool diagnostics and reference protection; synthetic provider HTTP."""
import json
import uuid

from django.test import TestCase, SimpleTestCase, override_settings

from front.models import AgentToolResult
from front.policy import digest
from front.test_agent_inference import AgentFixture
from front.agents.general_tools import _projection, _output_text
from front.agents.protocol import ToolCall, ToolResultRequest, validate_arguments
from front.agents.service import _context


class ToolProjectionTests(SimpleTestCase):
    def project(self, result, *, failed=False):
        call = ToolCall(id='execution-one', name='execute', args={'command': 'python script.py'})
        request = ToolResultRequest(call=call, raw={'content': json.dumps(result)}, failed=failed)
        return _projection(call, request, 16000)

    def test_exit_code_is_not_transport_success_and_output_is_bounded(self):
        raw = {'exit_code': 2, 'stdout': 'a' * 3000, 'stderr': 'SyntaxError', 'truncated': False}
        view = self.project(raw)
        self.assertFalse(view['succeeded'])
        self.assertEqual(view['exit_code'], 2)
        self.assertEqual(len(view['summary']), 2048)
        self.assertEqual(view['next_offset'], 2048)
        self.assertEqual(view['output_ref'], 'execution-one')
        self.assertEqual(_output_text({'content': json.dumps(raw)}), 'a' * 3000 + '\nSyntaxError')
        self.assertNotIn('stdout', view)

    def test_invalid_json_and_timed_out_results_are_failed(self):
        self.assertEqual(self.project({'stdout': 'looks fine'})['code'], 'invalid_command_result')
        result = {'exit_code': 0, 'stdout': 'partial', 'stderr': '', 'truncated': True, 'timed_out': True}
        self.assertFalse(self.project(result)['succeeded'])
        self.assertTrue(self.project(result)['truncated'])

    def test_summary_limit_is_utf8_bytes_and_pagination_does_not_split_unicode(self):
        for output in ('😀' * 900, 'a' * 2047 + '😀rest', '€' * 900):
            with self.subTest(prefix=output[:2]):
                view = self.project({'exit_code': 0, 'stdout': output, 'stderr': '', 'truncated': False})
                self.assertLessEqual(len(view['summary'].encode('utf-8')), 2048)
                self.assertTrue(view['truncated'])
                self.assertEqual(view['summary'] + output[view['next_offset']:], output)
                self.assertNotIn('\ufffd', view['summary'])

    def test_replace_requires_sha_and_edit_sha_is_optional(self):
        with self.assertRaises(ValueError):
            validate_arguments(ToolCall(id='replace', name='replace_file',
                args={'file_path': '/workspace/work/file', 'content': 'x'}))
        validate_arguments(ToolCall(id='edit', name='edit_file', args={
            'file_path': '/workspace/work/file', 'old_string': 'a', 'new_string': 'b'}))
        with self.assertRaises(ValueError):
            validate_arguments(ToolCall(id='edit', name='edit_file', args={
                'file_path': '/workspace/work/file', 'old_string': 'a', 'new_string': 'b', 'expected_sha256': 'unknown'}))


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_TEXT_STREAM=False)
class TypedReferenceTests(AgentFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.professional, self.agent.tools = True, ['read_output', 'execute']
        self.agent.save()
        self.execution.authorization_digest = _context(self.prompt, self.agent.pk)[-1]
        self.execution.save()
        self.reference = '4111111111111111'
        AgentToolResult.objects.create(execution=self.execution, call_id=self.reference,
            request_digest=digest('fixture receipt'), raw=json.dumps('original command output'),
            view={'status': 'approved', 'output_ref': self.reference})

    def test_issued_argument_keeps_identity_while_same_free_text_is_protected(self):
        self.reply_calls = [{'id': 'read-issued', 'name': 'read_output', 'args': {'call_id': self.reference}}]
        reply = self.infer(self.request(tools=['read_output'], messages=[{
            'role': 'user', 'content': 'Número de tarjeta: ' + self.reference}]))
        self.assertEqual(reply['status'], 'completed', reply)
        self.assertEqual(reply['tool_calls'][0]['args']['call_id'], self.reference)
        self.assertNotIn(self.reference, json.dumps(self.requests[0]['messages']))

    def test_foreign_reference_is_never_preserved_as_a_capability(self):
        self.reply_calls = [{'id': 'foreign', 'name': 'read_output', 'args': {'call_id': '5555555555554444'}}]
        reply = self.infer(self.request(tools=['read_output']))
        self.assertEqual(reply['status'], 'completed', reply)
        self.assertNotEqual(reply['tool_calls'][0]['args']['call_id'], '5555555555554444')
        self.assertFalse(AgentToolResult.objects.filter(execution=self.execution,
            call_id=reply['tool_calls'][0]['args']['call_id']).exists())
