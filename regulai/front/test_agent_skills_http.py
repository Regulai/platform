"""All three send adapters, existing-chat variants, SDK HTTP and recovery."""
import base64
from decimal import Decimal
import hashlib
import json
import uuid

from django.test import TestCase, override_settings

from front.models import AgentArtifact, AgentExecution, AgentInference, AgentSkillInstallation, AgentSkillRevision, Conversation
from front.policy import digest
from front.test_agent_work_limits import WorkLimitsFixture
from front.agents.skill_context import checkpoint_reference


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_RUNTIME=True,
    REGULAY_SKILLS_CATALOG=True, REGULAY_AGENT_TEXT_STREAM=False, REGULAY_AGENT_CAPACITY={'provider': 2})
class SkillsHTTPTests(WorkLimitsFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.installation = AgentSkillInstallation.objects.create(company=self.company, owner=self.user,
            alias='html-layout', source_identity='fixture:http-layout', enabled=True)
        raw = b'---\nname: html-layout\ndescription: HTML layout\n---\nHTTP_CANONICAL_SKILL_BODY\n'
        manifest = [{'path': 'SKILL.md', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}]
        self.revision = AgentSkillRevision.objects.create(installation=self.installation, origin='fixture:http-layout',
            folder_sha256=digest(manifest), manifest=manifest,
            metadata={'name': 'html-layout', 'description': 'HTML layout'}, license='Synthetic test package',
            compatibility={'profile': 'professional', 'tools': ['read_file']},
            bundle=json.dumps({'SKILL.md': base64.b64encode(raw).decode()}))
        self.installation.current_revision = self.revision
        self.installation.save()

    def send_skill(self, url, identity, selection=None, conversation=None, text='Dime la capital de España'):
        payload = {'prompt': text, 'content': text,
            'mode': 'agent', 'request_id': str(identity), 'inference_profile': 'quick'}
        if selection is not None:
            payload['skills'] = json.dumps(selection)
        if conversation is not None:
            payload['conversation_id'] = conversation.pk
        return self.client.post(url, payload)

    def finish(self, payload):
        response = self.internal('run/complete', {'final_call_id': payload['call_id']})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['completed'])

    def test_six_adapter_cases_pin_explicit_body_replay_and_conflicting_selection(self):
        for adapter in ('legacy', 'async', 'api'):
            for existing in (False, True):
                with self.subTest(adapter=adapter, existing=existing):
                    conversation = Conversation.objects.create(user=self.user, mode='agent') if existing else None
                    url = ('/chat/' + (str(conversation.pk) + '/' if conversation else '') if adapter == 'legacy' else
                        '/chat/' + (str(conversation.pk) + '/' if conversation else '') + 'send/' if adapter == 'async'
                        else '/api/chat/send/')
                    identity = uuid.uuid4()
                    selection = {'selected': [str(self.installation.pk), str(self.installation.pk)], 'auto': False}
                    count = len(self.requests)
                    response = self.send_skill(url, identity, selection, conversation)
                    self.assertEqual(response.status_code, 202, response.content)
                    run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
                    self.assertEqual(response.json()['agent']['skills']['selected'], [str(self.installation.pk)])
                    self.assertFalse(run.conversation.auto_skills)
                    replay = self.send_skill(url, identity, {'selected': [str(self.installation.pk)], 'auto': False}, conversation)
                    self.assertEqual(replay.status_code, 202, replay.content)
                    self.assertEqual(replay.json()['agent']['id'], str(run.pk))
                    conflict = self.send_skill(url, identity, {'selected': [], 'auto': False}, conversation)
                    self.assertEqual(conflict.status_code, 409, conflict.content)
                    self.assertEqual(len(self.requests), count)
                    self.start(run)
                    bootstrap = self.internal('run/bootstrap', {}).json()
                    self.assertEqual(bootstrap['skills']['catalog'][0]['revision_id'], str(self.revision.pk))
                    self.assertNotIn('install_packages', bootstrap['tools'])
                    payload, reply = self.ask()
                    self.assertEqual(reply['status'], 'completed', reply)
                    self.assertEqual(json.dumps(self.requests[-1]['messages']).count('HTTP_CANONICAL_SKILL_BODY'), 1)
                    self.assertEqual(self.internal('inference', payload).json(), reply)
                    self.finish(payload)
                    self.assertEqual(len(self.requests), count + 1)
                    self.assertEqual(AgentInference.objects.filter(execution=run).count(), 1)
                    run.prompt.refresh_from_db()
                    self.assertEqual(run.prompt.decision['total']['attempts'], 1)
                    self.assertGreater(Decimal(run.prompt.decision['total']['cost']), Decimal('0'))

    def test_next_turn_consumes_selection_and_keeps_conversation_auto_preference(self):
        response = self.send_skill('/chat/send/', uuid.uuid4(), {'selected': [str(self.installation.pk)], 'auto': False})
        self.assertEqual(response.status_code, 202, response.content)
        first = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        self.start(first)
        payload, _ = self.ask()
        self.finish(payload)
        following = self.send_skill('/chat/' + str(first.conversation_id) + '/send/', uuid.uuid4())
        self.assertEqual(following.status_code, 202, following.content)
        second = AgentExecution.objects.get(pk=following.json()['agent']['id'])
        self.assertEqual(second.job['skills']['selected'], [])
        self.assertFalse(second.job['skills']['auto'])
        self.assertEqual(second.job['skills']['catalog'], [])
        self.start(second)
        payload, reply = self.ask()
        self.assertEqual(reply['status'], 'completed', reply)
        self.assertNotIn('HTTP_CANONICAL_SKILL_BODY', json.dumps(self.requests[-1]['messages']))
        self.finish(payload)

    def test_checkpoint_resume_keeps_skill_revision_and_money_without_replaying_inference(self):
        response = self.send_skill('/api/chat/send/', uuid.uuid4(), {'selected': [str(self.installation.pk)], 'auto': True})
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        self.start(run)
        _, reply = self.ask()
        self.assertEqual(reply['status'], 'completed', reply)
        payload = {'version': 2, 'messages': [{'type': 'human', 'data': {'content': 'Continuar'}}],
            'wire_messages': [{'role': 'user', 'content': 'Continuar'}], 'archive': None,
            'runtime_sha256': 'a' * 64, 'workspace_runtime_sha256': None, 'summarization': None,
            'skills': checkpoint_reference(self.execution)}
        saved = self.internal('run/checkpoint', payload)
        self.assertEqual(saved.status_code, 200, saved.content)
        cancelled = self.client.post('/chat/agent/runs/' + str(run.pk) + '/cancel/')
        self.assertEqual(cancelled.status_code, 200, cancelled.content)
        resumed = self.client.post('/chat/agent/runs/' + str(run.pk) + '/resume/')
        self.assertEqual(resumed.status_code, 200, resumed.content)
        self.assertEqual(len(self.requests), 1)
        self.start(run)
        boot = self.internal('run/bootstrap', {}).json()
        self.assertEqual(boot['checkpoint']['skills'], payload['skills'])
        payload, reply = self.ask()
        self.assertEqual(reply['status'], 'completed', reply)
        self.assertEqual(json.dumps(self.requests[-1]['messages']).count('HTTP_CANONICAL_SKILL_BODY'), 1)
        self.assertEqual(len(self.requests), 2)
        self.finish(payload)
        run.prompt.refresh_from_db()
        self.assertEqual(run.prompt.decision['total']['attempts'], 2)

    def test_old_receipts_replay_when_skill_rollout_and_auto_preference_change(self):
        professional_tools = self.agent.tools
        for professional in (True, False):
            for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
                with self.subTest(professional=professional, url=url):
                    self.agent.professional = professional
                    self.agent.tools = professional_tools if professional else ['build_document']
                    self.agent.save(update_fields=['professional', 'tools'])
                    identity = uuid.uuid4()
                    with override_settings(REGULAY_SKILLS_RUNTIME=False):
                        first = self.send_skill(url, identity, text='Crea un informe Word de Madrid')
                    self.assertEqual(first.status_code, 202, first.content)
                    run = AgentExecution.objects.get(pk=first.json()['agent']['id'])
                    self.assertNotIn('skills', run.job)
                    # A rollout may expose an automatic catalogue. It cannot rewrite a receipt.
                    replay = self.send_skill(url, identity, text='Crea un informe Word de Madrid')
                    self.assertEqual(replay.status_code, 202, replay.content)
                    self.assertEqual(replay.json()['agent']['id'], str(run.pk))
                    changed = self.send_skill(url, identity, {'selected': [str(self.installation.pk)], 'auto': False},
                        text='Crea un informe Word de Madrid')
                    self.assertEqual(changed.status_code, 409, changed.content)
                    AgentExecution.objects.filter(pk=run.pk).update(status='interrupted')
        self.assertEqual(self.requests, [])

    def test_madrid_landing_download_and_color_edit_with_real_curated_skill_on_three_entries(self):
        from front.agents.skill_installation import install
        from front.agents.skill_context import _bytes
        installed = install(self.user, uuid.uuid4(), {'source': 'catalog', 'candidate': 'frontend-design'})
        self.assertEqual(installed['state'], 'installed', installed)
        installation = AgentSkillInstallation.objects.get(pk=installed['installation_id'])
        revision = installation.current_revision
        upstream = _bytes(revision, 'SKILL.md').decode()
        selection = {'selected': [str(installation.pk)], 'auto': False}
        original = b'<!doctype html><html lang="es"><title>Madrid</title><body style="color:red"><h1>Madrid</h1></body></html>'
        changed = original.replace(b'color:red', b'color:blue')

        def endpoint(url, conversation):
            if conversation and url in ('/chat/', '/chat/send/'):
                return '/chat/' + str(conversation.pk) + ('/send/' if url.endswith('send/') else '/')
            return url

        def turn(url, text, conversation=None, raw=None, base=None):
            chosen = selection if raw is not None else {'selected': [], 'auto': False}
            sent = self.send_skill(endpoint(url, conversation), uuid.uuid4(), chosen, conversation, text)
            self.assertEqual(sent.status_code, 202, sent.content)
            run = AgentExecution.objects.get(pk=sent.json()['agent']['id'])
            self.start(run, expected_model_calls=run.job['limits']['model_calls'],
                expected_tool_calls=run.job['limits']['tool_calls'])
            boot = self.internal('run/bootstrap', {}).json()
            if raw is not None:
                self.assertEqual(run.job['skills']['selected'], selection['selected'])
                self.assertEqual(boot['skills']['catalog'][0]['revision_id'], str(revision.pk))
                if base:
                    self.assertEqual(boot['model_context']['base_revision'], str(base.pk))
                    self.assertEqual(base64.b64decode(boot['workspace_inputs'][0]['base64']), original)
                args = {'file_path': '/workspace/output/madrid.html', 'title': 'Madrid'}
                if base:
                    args['base_revision'] = str(base.pk)
                call = {'id': 'publish-' + uuid.uuid4().hex, 'name': 'publish_artifact', 'args': args}
                self.reply_calls = [call]
                _, answer = self.ask(tools=['publish_artifact'], messages=[{'role': 'user', 'content': text}])
                self.reply_calls = []
                self.assertEqual(answer['status'], 'completed', answer)
                wire = json.dumps(self.requests[-1]['messages'], ensure_ascii=False)
                # The normal outbound protection still applies to upstream prose.
                self.assertEqual(wire.count('# Frontend Design'), 1)
                self.assertIn('Approach this as the design lead at a design studio', wire)
                self.assertEqual(hashlib.sha256(_bytes(revision, 'SKILL.md')).hexdigest(),
                    next(item['sha256'] for item in revision.manifest if item['path'] == 'SKILL.md'))
                self.assertIn('Adaptación de regulAI', wire)
                self.assertIn('/workspace/output', wire)
                self.assertNotIn('install_packages', json.dumps(self.requests[-1].get('tools', [])))
                authorization = self.internal('authorize-tool', call)
                self.assertEqual(authorization.status_code, 200, authorization.content)
                published = self.internal('run/publish', {'call': call,
                    'files': {args['file_path']: base64.b64encode(raw).decode()}})
                self.assertEqual(published.status_code, 200, published.content)
                viewed = self.internal('tool-results', {'call': call, 'raw': {'content': 'published'}})
                self.assertEqual(viewed.status_code, 200, viewed.content)
            payload, answer = self.ask(messages=[{'role': 'user', 'content': text}])
            self.assertEqual(answer['status'], 'completed', answer)
            self.finish(payload)
            return run

        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(url=url):
                first = turn(url, 'Hablo de Madrid')
                created = turn(url, 'Crea una landing HTML de Madrid', first.conversation, original)
                artifact = AgentArtifact.objects.get(execution=created, status='verified')
                count = len(self.requests)
                download = self.client.get('/chat/agent/artifacts/' + str(artifact.pk) + '/download/')
                self.assertEqual(download.content, original)
                self.assertIn('madrid.html', download['Content-Disposition'])
                identity = uuid.uuid4()
                for _ in range(2):
                    reissued = self.send_skill(endpoint(url, first.conversation), identity, None,
                        first.conversation, 'Dámelo')
                    self.assertIn(reissued.status_code, (200, 302), reissued.content)
                downloaded = AgentExecution.objects.get(prompt__request_id=identity)
                self.assertEqual(downloaded.status, 'completed')
                self.assertFalse(AgentInference.objects.filter(execution=downloaded).exists())
                self.assertEqual(len(self.requests), count)
                edited = turn(url, 'Cambia sólo el color a azul', first.conversation, changed, artifact)
                updated = AgentArtifact.objects.get(execution=edited, status='verified')
                self.assertEqual(updated.base_id, artifact.pk)
                self.assertEqual(updated.logical_id, artifact.logical_id)
                self.assertEqual(updated.revision, artifact.revision + 1)
                self.assertNotEqual(updated.sha256, artifact.sha256)
                self.assertEqual(self.client.get('/chat/agent/artifacts/' + str(artifact.pk) + '/download/').content, original)
                self.assertEqual(self.client.get('/chat/agent/artifacts/' + str(updated.pk) + '/download/').content, changed)
                self.assertEqual(AgentInference.objects.filter(execution=edited).count(), 2)
