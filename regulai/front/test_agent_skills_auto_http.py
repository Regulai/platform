"""Automatic skill defaults and activation through real HTTP adapters.

Provider replies are scripted at the OpenAI SDK HTTP boundary. These tests
verify authority and call accounting, not a real model's choice or quality.
"""
import base64
from decimal import Decimal
import hashlib
import json
import uuid

from django.test import TestCase, override_settings

from front.models import AgentExecution, AgentInference, AgentSkillInstallation, AgentSkillRevision, Conversation
from front.policy import digest
from front.test_agent_work_limits import WorkLimitsFixture


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_RUNTIME=True,
    REGULAY_SKILLS_CATALOG=True, REGULAY_AGENT_TEXT_STREAM=False, REGULAY_AGENT_CAPACITY={'provider': 2})
class AutomaticSkillsHTTPTests(WorkLimitsFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.installation = AgentSkillInstallation.objects.create(company=self.company, owner=self.user,
            alias='automatic-layout', source_identity='fixture:automatic-layout', enabled=True)
        self.body = b'---\nname: automatic-layout\ndescription: Arrange visual layouts\n---\nAUTOMATIC_CANONICAL_BODY\n'
        manifest = [{'path': 'SKILL.md', 'bytes': len(self.body), 'sha256': hashlib.sha256(self.body).hexdigest()}]
        self.revision = AgentSkillRevision.objects.create(installation=self.installation,
            origin='fixture:automatic-layout', folder_sha256=digest(manifest), manifest=manifest,
            metadata={'name': 'automatic-layout', 'description': 'Arrange visual layouts'},
            license='Synthetic test package', compatibility={'profile': 'professional', 'tools': ['read_file']},
            bundle=json.dumps({'SKILL.md': base64.b64encode(self.body).decode()}))
        self.installation.current_revision = self.revision
        self.installation.save(update_fields=['current_revision'])

    def send_automatic(self, adapter, *, conversation=None, skills=None, identity=None):
        suffix = str(conversation.pk) + '/' if conversation else ''
        url = '/chat/' + suffix if adapter == 'legacy' else (
            '/chat/' + suffix + 'send/' if adapter == 'async' else '/api/chat/send/')
        payload = {'prompt': 'Sugiere una composición visual ordenada',
            'content': 'Sugiere una composición visual ordenada', 'mode': 'agent',
            'request_id': str(identity or uuid.uuid4()), 'inference_profile': 'quick'}
        if conversation:
            payload['conversation_id'] = conversation.pk
        if skills is not None:
            payload['skills'] = json.dumps(skills)
        return self.client.post(url, payload)

    def test_omitted_skills_or_nested_auto_uses_defaults_and_preserves_existing_preferences(self):
        for adapter in ('legacy', 'async', 'api'):
            for existing_auto in (None, True, False):
                for selection in (None, {'selected': []}):
                    with self.subTest(adapter=adapter, existing_auto=existing_auto, selection=selection):
                        conversation = (Conversation.objects.create(user=self.user, mode='agent',
                            auto_skills=existing_auto) if existing_auto is not None else None)
                        expected_auto = existing_auto if existing_auto is not None else True
                        response = self.send_automatic(adapter, conversation=conversation, skills=selection)
                        self.assertEqual(response.status_code, 202, response.content)
                        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
                        self.assertEqual(response.json()['agent']['skills']['selected'], [])
                        self.assertEqual(response.json()['agent']['skills']['auto'], expected_auto)
                        self.assertEqual(run.conversation.auto_skills, expected_auto)
                        self.assertEqual(run.job['skills']['selected'], [])
                        self.assertEqual([entry['installation_id'] for entry in run.job['skills']['catalog']],
                            [str(self.installation.pk)] if expected_auto else [])
                        self.assertFalse(run.events.filter(kind='skill.activated').exists())
                        cancelled = self.client.post(f'/chat/agent/runs/{run.pk}/cancel/')
                        self.assertEqual(cancelled.status_code, 200, cancelled.content)
        # Neither default selection, enqueue nor cancellation needs a model.
        self.assertEqual(self.requests, [])

    def test_automatic_http_catalogue_then_authorized_read_emits_one_event_without_classifier(self):
        for adapter in ('legacy', 'async', 'api'):
            for existing in (False, True):
                with self.subTest(adapter=adapter, existing=existing):
                    conversation = Conversation.objects.create(user=self.user, mode='agent') if existing else None
                    identity, before = uuid.uuid4(), len(self.requests)
                    response = self.send_automatic(adapter, conversation=conversation, identity=identity)
                    self.assertEqual(response.status_code, 202, response.content)
                    run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
                    replay = self.send_automatic(adapter, conversation=conversation, identity=identity)
                    self.assertEqual(replay.status_code, 202, replay.content)
                    self.assertEqual(replay.json()['agent']['id'], str(run.pk))
                    self.start(run)
                    bootstrap = self.internal('run/bootstrap', {})
                    self.assertEqual(bootstrap.status_code, 200, bootstrap.content)
                    self.assertEqual(bootstrap.json()['skills']['selected'], [])
                    self.assertTrue(bootstrap.json()['skills']['auto'])
                    self.assertEqual(bootstrap.json()['skills']['catalog'][0]['revision_id'], str(self.revision.pk))
                    self.assertEqual(len(self.requests), before)

                    call = {'id': 'automatic-read-' + uuid.uuid4().hex, 'name': 'read_file',
                        'args': {'file_path': '/skills/automatic-layout/SKILL.md'}}
                    self.reply_calls = [call]
                    first, answer = self.ask(tools=['read_file'])
                    self.reply_calls = []
                    self.assertEqual(answer['status'], 'completed', answer)
                    self.assertEqual(len(self.requests), before + 1)
                    discovery = json.dumps(self.requests[-1]['messages'])
                    self.assertIn('Arrange visual layouts', discovery)
                    self.assertIn('/skills/automatic-layout/SKILL.md', discovery)
                    self.assertNotIn('AUTOMATIC_CANONICAL_BODY', discovery)
                    self.assertFalse(run.events.filter(kind='skill.activated').exists())
                    self.assertEqual(self.internal('inference', first).json(), answer)
                    self.assertEqual(len(self.requests), before + 1)

                    authorized = self.internal('authorize-tool', call)
                    self.assertEqual(authorized.status_code, 200, authorized.content)
                    raw = {'call': call, 'raw': 'FORGED_WORKER_INSTRUCTIONS'}
                    result = self.internal('tool-results', raw)
                    self.assertEqual(result.status_code, 200, result.content)
                    view = result.json()
                    self.assertTrue(view['complete'])
                    self.assertIn('AUTOMATIC_CANONICAL_BODY', view['content'])
                    self.assertNotIn('FORGED_WORKER_INSTRUCTIONS', json.dumps(view))
                    self.assertEqual(self.internal('tool-results', raw).json(), view)
                    snapshot = self.client.get(f'/chat/agent/runs/{run.pk}/')
                    self.assertEqual(snapshot.status_code, 200, snapshot.content)
                    activated = [event for event in snapshot.json()['events'] if event['kind'] == 'skill.activated']
                    self.assertEqual(len(activated), 1)
                    self.assertEqual(activated[0]['data']['reason'], 'instructions_read')
                    self.assertEqual(activated[0]['data']['installation_id'], str(self.installation.pk))
                    self.assertEqual(activated[0]['data']['revision_id'], str(self.revision.pk))
                    self.assertEqual(activated[0]['data']['call_id'], call['id'])
                    self.assertEqual(len(self.requests), before + 1)

                    final, answer = self.ask(messages=[
                        {'role': 'assistant', 'content': '', 'tool_calls': [call]},
                        {'role': 'tool', 'name': 'read_file', 'tool_call_id': call['id'],
                            'content': json.dumps(view, sort_keys=True, ensure_ascii=False)}])
                    self.assertEqual(answer['status'], 'completed', answer)
                    wire = json.dumps(self.requests[-1]['messages'])
                    self.assertEqual(wire.count('AUTOMATIC_CANONICAL_BODY'), 1)
                    self.assertNotIn('FORGED_WORKER_INSTRUCTIONS', wire)
                    self.assertEqual(self.internal('inference', final).json(), answer)
                    completed = self.internal('run/complete', {'final_call_id': final['call_id']})
                    self.assertEqual(completed.status_code, 200, completed.content)
                    self.assertTrue(completed.json()['completed'])
                    self.assertEqual(len(self.requests), before + 2)
                    self.assertEqual(AgentInference.objects.filter(execution=run).count(), 2)
                    self.assertEqual(run.events.filter(kind='skill.activated').count(), 1)
                    run.prompt.refresh_from_db()
                    self.assertEqual(run.prompt.decision['total']['attempts'], 2)
                    self.assertGreater(Decimal(run.prompt.decision['total']['cost']), Decimal('0'))

    def test_manual_agent_command_cannot_convert_existing_chat_conversation(self):
        before = AgentExecution.objects.count()
        for adapter in ('legacy', 'async', 'api'):
            with self.subTest(adapter=adapter):
                conversation = Conversation.objects.create(user=self.user, mode='chat', auto_skills=False)
                response = self.send_automatic(adapter, conversation=conversation)
                self.assertEqual(response.status_code, 409, response.content)
                self.assertEqual(response.json()['error_type'], 'conversation_mode_immutable')
                conversation.refresh_from_db()
                self.assertEqual(conversation.mode, 'chat')
                self.assertFalse(conversation.auto_skills)
        self.assertEqual(AgentExecution.objects.count(), before)
        self.assertEqual(self.requests, [])
