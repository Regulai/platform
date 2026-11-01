"""Selected history is identical at governance and at the simulated SDK wire."""
import base64
from datetime import timedelta
from decimal import Decimal
import json
import uuid

from django.test import TestCase, override_settings
from django.utils import timezone

from front import test_agent_files as fixtures
from front.agents.runtime_contract import compaction_call_id
from front.agents.service import infer
from front.chat_service import authorized_history
from front.models import AgentExecution, AgentInference, AgentInput, Message, Prompt, Response
from front.policy import digest


@override_settings(REGULAY_AGENT_ENABLED=True, DEBUG=False)
class HistoryWindowTests(fixtures.FileFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.conversation.mode = 'agent'
        self.conversation.save(update_fields=['mode'])

    def pair(self, user, answer, *, attachment=None, scope='text_only'):
        first = Message.objects.create(conversation=self.conversation, role='user', content=user,
            file_name='source-secret.txt' if attachment else None, file_size=len(attachment or b''))
        last = Message.objects.create(conversation=self.conversation, role='assistant', content=answer)
        decision = {'history_eligible': True, 'history_digest': digest([user, answer]), 'calls': []}
        if scope:
            decision.update(history_version=2, history_scope=scope)
        prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=self.conversation,
            user_message=first, content=user, status='completed', request_id=uuid.uuid4(), decision=decision,
            file_sha256=digest(attachment.decode()) if attachment else None,
            file_name=first.file_name, file_size=first.file_size)
        Response.objects.create(prompt=prompt, assistant_message=last, content=answer)
        if attachment:
            previous = AgentExecution.objects.create(prompt=prompt, profile=self.agent, conversation=self.conversation,
                token_digest=uuid.uuid4().hex * 2, authorization_digest='a' * 64, status='completed',
                expires_at=timezone.now() + timedelta(days=1), finished_at=timezone.now(), job={'kind': 'professional'})
            AgentInput.objects.create(execution=previous, kind='private_file', path='/workspace/input/source.txt',
                original=base64.b64encode(attachment).decode(), digest=digest(attachment.decode()))
        return prompt

    def start(self, text='Continúa con el tema anterior'):
        response = self.client.post(f'/chat/{self.conversation.pk}/send/', {
            'prompt': text, 'content': text, 'mode': 'agent', 'request_id': str(uuid.uuid4())})
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        self.activate(run)
        return run

    def generation(self, text='Continúa con el tema anterior'):
        result = infer(self.token, self.execution.attempt, {'call_id': str(uuid.uuid4()),
            'messages': [{'role': 'user', 'content': text}], 'tools': []})
        self.assertEqual(result['status'], 'completed', result)
        return [message for message in self.requests[-1]['messages'] if message['role'] != 'system']

    def test_capacity_window_keeps_recent_complete_pairs_and_preflight_uses_same_selection(self):
        # The ordinary history window still contains both pairs. The model's
        # smaller context requires the agent to omit the older pair completely.
        self.agent.tools = ['execute']
        self.agent.save(update_fields=['tools'])
        self.model.context_window = 18000
        self.model.save(update_fields=['context_window'])
        old = self.pair('OLD_USER_' + 'a' * 4000, 'OLD_ASSISTANT_' + 'b' * 4000)
        recent = self.pair('El destino corregido es Madrid, España', 'Conservo Madrid, España como destino')
        self.assertEqual(len(authorized_history(self.user, self.conversation)), 4)
        run = self.start()
        self.assertEqual([pair['prompt_id'] for pair in run.job['history']['pairs']], [recent.pk])
        self.assertEqual(run.job['history']['omitted'], 1)
        wire = self.generation()
        self.assertEqual([(item['role'], item['content']) for item in wire], [
            ('user', recent.content), ('assistant', recent.response.content), ('user', 'Continúa con el tema anterior')])
        self.assertNotIn('OLD_USER_', json.dumps(self.requests[-1]))
        self.assertNotIn('OLD_ASSISTANT_', json.dumps(self.requests[-1]))
        self.assertEqual(Prompt.objects.get(pk=old.pk).status, 'completed')
        self.assertEqual(Message.objects.filter(conversation=self.conversation).count(), 5)

    def test_text_only_attachment_history_sends_text_without_filename_or_original_bytes(self):
        original = b'PRIVATE_ORIGINAL_BYTES_73b41f'
        prior = self.pair('Lee el adjunto para esta conversación', 'El resumen autorizado está listo', attachment=original)
        legacy = self.pair('Legacy attachment must be omitted', 'Legacy assistant must be omitted',
            attachment=b'LEGACY_BYTES_8ef', scope=None)
        self.assertEqual(authorized_history(self.user, self.conversation), [])
        run = self.start('Recuerda únicamente el resumen anterior')
        self.assertEqual([pair['prompt_id'] for pair in run.job['history']['pairs']], [prior.pk])
        self.assertEqual(run.job['history']['omitted'], 1)
        wire = self.generation('Recuerda únicamente el resumen anterior')
        self.assertEqual([item['role'] for item in wire], ['user', 'assistant', 'user'])
        self.assertEqual([item['content'] for item in wire[:2]], [prior.content, prior.response.content])
        serialized = json.dumps(self.requests[-1])
        for excluded in (original.decode(), base64.b64encode(original).decode(), 'source-secret.txt',
                         legacy.content, legacy.response.content, 'LEGACY_BYTES_8ef'):
            self.assertNotIn(excluded, serialized)
        self.assertFalse(any(isinstance(item['content'], list) for item in wire))
        self.assertEqual(AgentInput.objects.filter(execution__prompt=prior, kind='private_file').count(), 1)

    def test_compaction_omits_interturn_prefix_and_stable_uuid_replays_one_http_call_and_cost(self):
        prior = self.pair('PREVIOUS_TURN_ONLY_Madrid', 'PREVIOUS_ANSWER_ONLY_confirmed')
        run = self.start('CURRENT_TURN_ONLY_sumario')
        run.job['worker_protocol'] = 2
        run.save(update_fields=['job'])
        normal = self.generation('CURRENT_TURN_ONLY_sumario')
        self.assertEqual(normal[0]['content'], prior.content)
        messages = [{'role': 'user', 'content': 'COMPACTION_CURRENT_RUN_ONLY'}]
        call_id = compaction_call_id(run.pk, messages, run.job['effective_options'], [])
        self.assertEqual(uuid.UUID(call_id).version, 5)
        self.assertEqual(call_id, compaction_call_id(run.pk, messages, run.job['effective_options'], []))
        request = {'call_id': call_id, 'purpose': 'compaction', 'messages': messages, 'tools': []}
        response = infer(self.token, run.attempt, request)
        self.assertEqual(response['status'], 'completed', response)
        wire = [message for message in self.requests[-1]['messages'] if message['role'] != 'system']
        self.assertEqual([(item['role'], item['content']) for item in wire], [('user', 'COMPACTION_CURRENT_RUN_ONLY')])
        self.assertNotIn(prior.content, json.dumps(self.requests[-1]))
        self.assertNotIn(prior.response.content, json.dumps(self.requests[-1]))
        run.prompt.refresh_from_db()
        cost = Decimal(run.prompt.decision['total']['known_cost'])
        count = len(self.requests)
        repeated = infer(self.token, run.attempt, request)
        self.assertEqual(repeated['content'], response['content'])
        self.assertEqual(len(self.requests), count)
        self.assertEqual(AgentInference.objects.filter(execution=run, call_id=call_id).count(), 1)
        run.prompt.refresh_from_db()
        self.assertEqual(Decimal(run.prompt.decision['total']['known_cost']), cost)
        self.assertEqual(sum(call['purpose'] == 'compaction' for call in run.prompt.decision['calls']), 1)
