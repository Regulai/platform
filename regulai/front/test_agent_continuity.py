"""Continuity across actual HTTP adapters and the real SDK's simulated wire."""
import json
import uuid
import base64

from django.test import override_settings
from front.models import AgentArtifact, AgentExecution, AgentInference, AgentInput, Message, Response
from front import test_agent_professional as fixtures


@override_settings(REGULAY_AGENT_WORKER_TOKEN='synthetic-p0-worker-token-at-least-32')
class ContinuityTests(fixtures.ProfessionalTests):
    # Inherit the fixture helpers, not the prior delivery's tests.
    def turn(self, url, text, conversation=None, request_id=None, file_bytes=None, before_infer=None, expected='completed'):
        identity = str(request_id or uuid.uuid4())
        payload = {'content': text, 'prompt': text, 'mode': 'agent', 'request_id': identity}
        if conversation:
            payload['conversation_id'] = str(conversation.pk)
            if url == '/chat/':
                url = f'/chat/{conversation.pk}/'
            elif url == '/chat/send/':
                url = f'/chat/{conversation.pk}/send/'
        response = self.client.post(url, payload)
        self.assertIn(response.status_code, (202, 302), response.content)
        run = AgentExecution.objects.get(prompt__request_id=identity)
        claimed = self.client.post('/internal/agents/claim/', json.dumps({
            'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4()), 'worker_protocol': 2}),
            content_type='application/json', HTTP_AUTHORIZATION='Bearer synthetic-p0-worker-token-at-least-32')
        self.assertEqual(claimed.status_code, 200, claimed.content)
        grant = claimed.json()
        self.assertEqual(grant['execution'], str(run.pk))
        headers = {'content_type': 'application/json', 'HTTP_AUTHORIZATION': 'Bearer ' + grant['token'],
                   'HTTP_X_REGULAY_ATTEMPT': grant['attempt']}
        boot = self.client.post('/internal/agents/run/bootstrap/', '{}', **headers)
        self.assertEqual(boot.status_code, 200, boot.content)
        if before_infer:
            before_infer(run, boot.json())
        if file_bytes is not None:
            args = {'file_path': '/workspace/output/madrid.html', 'title': 'Madrid'}
            if run.job.get('base'):
                args['base_revision'] = run.job['base']
            tool = {'id': 'publish-' + uuid.uuid4().hex, 'name': 'publish_artifact', 'args': args}
            self.reply_calls = [tool]
            reply = self.client.post('/internal/agents/inference/', json.dumps({'call_id': str(uuid.uuid4()),
                'messages': [{'role': 'user', 'content': text}], 'tools': ['publish_artifact']}), **headers)
            self.assertEqual(reply.json()['status'], 'completed', reply.content)
            self.reply_calls = []
            authorized = self.client.post('/internal/agents/authorize-tool/', json.dumps(tool), **headers)
            self.assertEqual(authorized.status_code, 200, authorized.content)
            published = self.client.post('/internal/agents/run/publish/', json.dumps({'call': tool,
                'files': {args['file_path']: base64.b64encode(file_bytes).decode()}}), **headers)
            self.assertEqual(published.status_code, 200, published.content)
            result = self.client.post('/internal/agents/tool-results/', json.dumps({'call': tool, 'raw': {'content': 'published'}}), **headers)
            self.assertEqual(result.status_code, 200, result.content)
        call_id = str(uuid.uuid4())
        inferred = self.client.post('/internal/agents/inference/', json.dumps({
            'call_id': call_id, 'messages': [{'role': 'user', 'content': text}]}), **headers)
        if expected == 'denied':
            self.assertEqual(inferred.status_code, 403, inferred.content)
            return run, headers, call_id
        self.assertEqual(inferred.json()['status'], 'completed', inferred.content)
        done = self.client.post('/internal/agents/run/complete/', json.dumps({'final_call_id': call_id}), **headers)
        self.assertEqual(bool(done.json().get('completed')), expected == 'completed', done.content)
        run.refresh_from_db()
        return run, headers, call_id

    def test_history_reaches_sdk_once_in_order_on_three_entries(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            first, _, _ = self.turn(url, 'Hablo de Madrid')
            second, _, _ = self.turn(url, 'Me refería a Madrid, España', first.conversation)
            third, headers, call = self.turn(url, '¿Qué te dije antes?', first.conversation)
            wire = [m for m in self.requests[-1]['messages'] if m['role'] != 'system']
            self.assertEqual([m['role'] for m in wire], ['user', 'assistant', 'user', 'assistant', 'user'])
            self.assertEqual([wire[i]['content'] for i in (0, 2, 4)],
                ['Hablo de Madrid', 'Me refería a Madrid, España', '¿Qué te dije antes?'])
            count = len(self.requests)
            duplicate = self.client.post('/internal/agents/run/complete/', json.dumps({'final_call_id': call}), **headers)
            self.assertTrue(duplicate.json().get('completed'), duplicate.content)
            self.assertEqual(len(self.requests), count)
            self.assertEqual(Response.objects.filter(prompt=third.prompt).count(), 1)
            self.assertEqual(AgentInference.objects.filter(execution=third).count(), 1)

    def test_changed_selected_history_stops_before_network_on_three_entries(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            first, _, _ = self.turn(url, 'Hablo de Madrid')
            count = len(self.requests)
            def tamper(run, boot):
                Message.objects.filter(pk=first.prompt.user_message_id).update(content='changed after selection')
            self.turn(url, '¿Qué te dije antes?', first.conversation, before_infer=tamper, expected='denied')
            self.assertEqual(len(self.requests), count)
            # Release only the synthetic run; no effects were dispatched.
            AgentExecution.objects.filter(status='active', conversation=first.conversation).update(status='interrupted')

    def test_unmarked_history_omitted_and_compaction_does_not_repeat_prefix(self):
        first, _, _ = self.turn('/chat/send/', 'Hablo de Madrid')
        first.prompt.refresh_from_db()
        first.prompt.decision.pop('history_eligible')
        first.prompt.save(update_fields=['decision'])
        second, _, _ = self.turn('/chat/send/', 'Otra pregunta', first.conversation)
        self.assertEqual(second.job['history']['pairs'], [])
        self.assertEqual(second.job['history']['omitted'], 1)
        self.assertEqual([m['content'] for m in self.requests[-1]['messages'] if m['role'] != 'system'], ['Otra pregunta'])
        self.assertEqual(Message.objects.filter(conversation=first.conversation).count(), 4)

    def test_requested_file_cannot_complete_without_publication_and_one_repair(self):
        run, headers, call = self.turn('/chat/send/', 'Crea un HTML de Madrid', expected='missing')
        self.assertEqual(run.status, 'active')
        replay = self.client.post('/internal/agents/run/complete/', json.dumps({'final_call_id': call}), **headers)
        self.assertTrue(replay.json()['repair_allowed'])
        repair_id = str(uuid.uuid4())
        repaired = self.client.post('/internal/agents/inference/', json.dumps({'call_id': repair_id,
            'messages': [{'role': 'user', 'content': 'Repara la entrega'}]}), **headers)
        self.assertEqual(repaired.json()['status'], 'completed', repaired.content)
        failed = self.client.post('/internal/agents/run/complete/', json.dumps({'final_call_id': repair_id}), **headers)
        self.assertEqual(failed.json()['status'], 'failed', failed.content)
        run.refresh_from_db()
        self.assertEqual(run.status, 'failed')
        self.assertFalse(run.prompt.decision.get('history_eligible', False))

    def test_madrid_file_download_reissue_and_edit_across_three_entries(self):
        original = b'<!doctype html><html><body style="color:red">Madrid</body></html>'
        changed = original.replace(b'red', b'blue')
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            first, _, _ = self.turn(url, 'Hablo de Madrid')
            created, _, _ = self.turn(url, 'Crea un HTML de Madrid', first.conversation, file_bytes=original)
            artifact = AgentArtifact.objects.get(execution=created, status='verified')
            download = self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/')
            self.assertEqual(download.status_code, 200, download.content)
            self.assertEqual(download.content, original)
            self.assertEqual(download['Content-Type'], 'application/octet-stream')
            self.assertEqual(download['Content-Length'], str(len(original)))
            self.assertIn('madrid.html', download['Content-Disposition'])
            self.assertEqual(download['Content-Security-Policy'], "sandbox; default-src 'none'")
            count = len(self.requests)
            identity = str(uuid.uuid4())
            endpoint = f'/chat/{first.conversation_id}/' if url == '/chat/' else f'/chat/{first.conversation_id}/send/' if url == '/chat/send/' else url
            payload = {'prompt': 'Dámelo', 'content': 'Dámelo', 'conversation_id': first.conversation_id, 'mode': 'agent', 'request_id': identity}
            for _ in range(2):
                response = self.client.post(endpoint, payload)
                self.assertIn(response.status_code, (200, 302), response.content)
            reissue = AgentExecution.objects.get(prompt__request_id=identity)
            self.assertEqual(reissue.status, 'completed')
            self.assertFalse(AgentInference.objects.filter(execution=reissue).exists())
            self.assertEqual(len(self.requests), count)
            def restored(run, boot):
                refs = boot['workspace_inputs']
                self.assertEqual(len(refs), 1)
                self.assertEqual(base64.b64decode(refs[0]['base64']), original)
                self.assertTrue(run.job['private_data'])
            edited, _, _ = self.turn(url, 'Cambia el color a azul', first.conversation,
                file_bytes=changed, before_infer=restored)
            revision = AgentArtifact.objects.get(execution=edited, status='verified')
            self.assertEqual(revision.base_id, artifact.pk)
            self.assertEqual(revision.logical_id, artifact.logical_id)
            self.assertEqual(revision.revision, artifact.revision + 1)
            self.assertNotEqual(revision.sha256, artifact.sha256)
            self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/').content, original)
            self.assertEqual(self.client.get(f'/chat/agent/artifacts/{revision.pk}/download/').content, changed)


# Do not run inherited ProfessionalTests again through the subclass.
for _name in list(fixtures.ProfessionalTests.__dict__):
    if _name.startswith('test_'):
        setattr(ContinuityTests, _name, None)
