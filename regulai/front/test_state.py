"""Request-state and legacy-data invariants; no live provider traffic."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import timedelta
from threading import Barrier, Event
import uuid
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TransactionTestCase
from django.utils import timezone

from front.connectors import ChatResponse
from front.models import (Company, CompanyEngine, Conversation, Engine, EngineModel,
                          Message, ObfuscationConfig, Profile, Prompt, Response, Rule, RulesGroup)
from front.test_chat_flow import mask_response


class RequestStateTests(TransactionTestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('state-user', password='synthetic')
        self.company = Company.objects.create(name='State synthetic')
        self.profile = Profile.objects.create(user=self.user, company=self.company)
        self.engine = Engine.objects.create(name='State synthetic', connector_type='openai')
        EngineModel.objects.create(engine=self.engine, name='Synthetic', model_id='synthetic-v1', context_window=32768, supports_json=True)
        self.credential = CompanyEngine.objects.create(company=self.company, engine=self.engine,
                                                       api_key='synthetic-key')
        mask = ObfuscationConfig.objects.create(company=self.company, name='State mask', api_url='https://mask.invalid')
        self.company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'masking': {'max_call_cost': '0'},
            'allow_empty_rules': True, 'destinations': {'internal': [f'engine:{self.credential.pk}', f'obfuscation:{mask.pk}']}}
        self.company.save()
        group = RulesGroup.objects.create(name='Consent synthetic', company=self.company)
        self.rule = Rule.objects.create(name='Consent synthetic', rules_group=group, action='consent',
            yara_rule='rule Consent { strings: $s = "CONSENT_MARKER" condition: $s }')
        self.client.force_login(self.user)
        self.provider = self.enterContext(patch('front.connectors.OpenAIConnector.chat',
            return_value=ChatResponse('Synthetic answer', 10, 'synthetic-v1', 'stop')))
        self.enterContext(patch('requests.post', side_effect=mask_response))

    def send(self, content='CONSENT_MARKER', **extra):
        return self.client.post('/api/chat/send/', {'content': content,
            'request_id': str(uuid.uuid4()), **extra})

    def pending(self):
        result = self.send().json()
        self.assertEqual(result['status'], 'pending_consent')
        return {'request_id': result['request_id'], 'consent_token': result['consent_token']}

    def test_confirmation_binds_actor_company_content_policy_and_endpoint(self):
        for mutation in ('actor', 'company', 'content', 'policy', 'endpoint'):
            with self.subTest(mutation=mutation):
                proof = self.pending()
                original_config = dict(self.company.ai_config)
                content = 'CONSENT_MARKER'
                if mutation == 'actor':
                    other = User.objects.create_user('other-state-user')
                    Profile.objects.create(user=other, company=self.company)
                    self.client.force_login(other)
                elif mutation == 'company':
                    other_company = Company.objects.create(name='Other state company')
                    Profile.objects.filter(pk=self.profile.pk).update(company=other_company)
                elif mutation == 'content':
                    content += ' CHANGED'
                elif mutation == 'policy':
                    self.company.ai_config = {**original_config, 'revision': 2}
                    self.company.save()
                else:
                    Engine.objects.filter(pk=self.engine.pk).update(base_url='https://changed.invalid/v1')
                result = self.send(content, **proof)
                self.assertEqual(result.status_code, 409)
                self.provider.assert_not_called()
                self.client.force_login(self.user)
                Profile.objects.filter(pk=self.profile.pk).update(company=self.company)
                self.company.ai_config = original_config
                self.company.save()
                Engine.objects.filter(pk=self.engine.pk).update(base_url='')

    def test_mutated_or_deleted_turn_is_excluded_from_history(self):
        first = self.send('Original authorized content').json()
        conversation_id = first['conversation_id']
        Message.objects.filter(pk=first['user_message']['id']).update(content='TAMPERED_CONTENT')
        second = self.send('Next clean question', conversation_id=conversation_id).json()
        payload = self.provider.call_args.args[0]
        self.assertNotIn('TAMPERED_CONTENT', str(payload))
        self.assertNotIn('Original authorized content', str(payload))
        Message.objects.filter(pk=second['assistant_message']['id']).delete()
        self.send('Another question', conversation_id=conversation_id)
        self.assertEqual(len(self.provider.call_args.args[0]), 1)
        self.assertEqual(Prompt.objects.count(), 3)
        self.assertEqual(Response.objects.count(), 3)

    def test_confirmation_rejects_changed_attachment_but_accepts_same_bytes(self):
        import json
        from front.test_pipeline import jev_http
        self.company.ai_config['destinations']['internal'].append('jev')
        self.company.jev_api_key = 'synthetic-jev'
        self.company.save()
        self.enterContext(patch('requests.post', side_effect=jev_http()))
        def answer(messages, **kwargs):
            sources = json.loads(messages[-1].content.split('Sources:\n', 1)[1])
            return ChatResponse(json.dumps({'claims': [{'text': 'Original document', 'citations': [
                {'id': sources[0]['id'], 'quote': 'Original document'}]}]}), 10, 'synthetic-v1', 'stop')
        self.provider.side_effect = answer
        first = self.send(file=SimpleUploadedFile('original.txt', b'Original document')).json()
        self.assertEqual(first['status'], 'pending_consent')
        proof = {'request_id': first['request_id'], 'consent_token': first['consent_token']}
        changed = self.send(file=SimpleUploadedFile('original.txt', b'Changed document'), **proof)
        self.assertEqual(changed.status_code, 409)
        self.provider.assert_not_called()
        confirmed = self.send(file=SimpleUploadedFile('original.txt', b'Original document'), **proof)
        self.assertEqual(confirmed.json()['status'], 'completed')
        self.assertEqual(confirmed.json()['user_message']['id'], first['user_message']['id'])
        self.assertEqual(Message.objects.filter(role='user').count(), 1)
        self.assertIn('Original document', str(self.provider.call_args.args[0]))

    def test_foreign_conversation_and_credential_never_fall_back_to_own_destination(self):
        other_company = Company.objects.create(name='Foreign destination company')
        other_user = User.objects.create_user('foreign-state-user')
        Profile.objects.create(user=other_user, company=other_company)
        conversation = Conversation.objects.create(user=other_user)
        credential = CompanyEngine.objects.create(company=other_company, engine=self.engine,
                                                   api_key='synthetic-foreign-key')
        for fields in ({'conversation_id': conversation.pk}, {'engine_id': credential.pk}):
            with self.subTest(fields=fields):
                result = self.send('Allowed plain text', **fields)
                self.assertIn(result.status_code, (404, 503))
                self.provider.assert_not_called()

    def test_cancelled_request_and_stale_processing_never_regenerate(self):
        proof = self.pending()
        cancelled = self.send(action='cancel', **proof)
        self.assertEqual(cancelled.json()['status'], 'cancelled')
        replay = self.send(**proof)
        self.assertEqual(replay.json()['status'], 'cancelled')
        for state in ('processing', 'received'):
            proof = self.pending()
            Prompt.objects.filter(request_id=proof['request_id']).update(status=state,
                updated_at=timezone.now() - timedelta(minutes=4))
            self.assertEqual(self.send(**proof).json()['status'], 'outcome_unknown')
            self.assertEqual(self.send(**proof).json()['status'], 'outcome_unknown')
        self.provider.assert_not_called()

    def test_overlapping_confirmation_posts_generate_once_without_open_transaction(self):
        proof = self.pending()
        entered, release = Event(), Event()
        claims = Barrier(2)
        clients = [Client(), Client()]
        for client in clients:
            client.force_login(self.user)

        def provider(*args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            self.assertTrue(connection.get_autocommit())
            entered.set()
            if not release.wait(10):
                raise AssertionError('Concurrent replay did not complete')
            return ChatResponse('Synthetic answer', 10, 'synthetic-v1', 'stop')

        def confirm(client):
            close_old_connections()
            try:
                def synchronize_claim(execute, sql, params, many, context):
                    # Both requests have read pending_consent before either conditional claim.
                    if sql.startswith('UPDATE "front_prompt"') and params[0] == 'processing':
                        claims.wait(timeout=10)
                    return execute(sql, params, many, context)

                with connection.execute_wrapper(synchronize_claim):
                    return client.post('/api/chat/send/', {'content': 'CONSENT_MARKER', **proof})
            finally:
                close_old_connections()

        self.provider.side_effect = provider
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {executor.submit(confirm, client) for client in clients}
            try:
                self.assertTrue(entered.wait(10), 'First request never reached provider')
                done, pending = wait(futures, timeout=10, return_when=FIRST_COMPLETED)
                self.assertEqual(len(done), 1)
                duplicate = done.pop().result()
                self.assertEqual(duplicate.status_code, 202)
                self.assertEqual(duplicate.json()['status'], 'processing')
            finally:
                release.set()
            result = pending.pop().result(timeout=10)
        self.assertEqual(result.json()['status'], 'completed')
        self.assertEqual(self.provider.call_count, 1)
        self.assertEqual(Message.objects.count(), 2)
        self.assertEqual(Response.objects.count(), 1)
        replay = self.send(**proof)
        self.assertEqual(replay.json()['assistant_message'], result.json()['assistant_message'])


class LegacyMigrationTests(TransactionTestCase):
    def test_legacy_rows_keep_distinct_ids_and_remain_unlinked(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0025_message_response_file')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            user = old.get_model('auth', 'User').objects.create(username='legacy-state-user')
            conversation = old.get_model('front', 'Conversation').objects.create(user_id=user.pk,
                                                                               title='Legacy retained')
            prompt_ids, message_ids = [], []
            for index in range(3):
                text = f'Legacy retained content {index}'
                prompt = old.get_model('front', 'Prompt').objects.create(user_id=user.pk,
                    conversation_id=conversation.pk, content=text)
                prompt_ids.append(prompt.pk)
                old.get_model('front', 'Response').objects.create(prompt_id=prompt.pk,
                                                                content=f'Legacy answer {index}')
                message = old.get_model('front', 'Message').objects.create(
                    conversation_id=conversation.pk, role='user', content=text)
                message_ids.append(message.pk)
            MigrationExecutor(connection).migrate(latest)
            prompts = list(Prompt.objects.filter(pk__in=prompt_ids).order_by('pk'))
            self.assertEqual(len(prompts), 3)
            self.assertEqual(len({prompt.request_id for prompt in prompts}), 3)
            for index, prompt in enumerate(prompts):
                self.assertEqual(prompt.status, 'legacy')
                self.assertEqual(prompt.content, f'Legacy retained content {index}')
                self.assertIsNone(prompt.company_id)
                self.assertIsNone(prompt.user_message_id)
                self.assertEqual(prompt.decision, {})
                self.assertEqual(prompt.response.content, f'Legacy answer {index}')
                self.assertIsNone(prompt.response.assistant_message_id)
            self.assertEqual(Message.objects.filter(pk__in=message_ids).count(), 3)
            self.assertEqual(Conversation.objects.get(pk=conversation.pk).title, 'Legacy retained')
        finally:
            MigrationExecutor(connection).migrate(latest)
