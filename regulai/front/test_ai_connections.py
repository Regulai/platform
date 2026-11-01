import importlib
import json
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
from django.apps import apps
from django.contrib.auth.models import User
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from .ai_connections import SERVICES, service_engines
from .test_chat_island import bootstrap as island_bootstrap
from .models import AuditLog, Company, CompanyEngine, Engine, ObfuscationConfig, Profile, Prompt, Role


class ServiceSettingsTests(TestCase):
    def setUp(self):
        importlib.import_module('front.migrations.0034_direct_service_catalog').seed_services(
            apps, SimpleNamespace(connection=connection))
        importlib.import_module('front.migrations.0035_deepseek_service_catalog').seed_deepseek(
            apps, SimpleNamespace(connection=connection))
        self.company = Company.objects.create(name='Gateway account')
        self.other = Company.objects.create(name='Another account', jev_api_key='other-secret')
        self.user = User.objects.create_user('gateway-admin', password='test-password')
        role, _ = Role.objects.get_or_create(name='Admin')
        Profile.objects.create(user=self.user, company=self.company, role=role)
        self.client.force_login(self.user)
        self.url = reverse('front:ai_connections')
        self.keys = {key: f'synthetic-{key}-key' for key, _, _, _, _ in SERVICES}

    def test_save_encrypts_keys_and_is_scoped_without_network_or_policy_changes(self):
        foreign = CompanyEngine.objects.create(company=self.other, engine=service_engines()['claude'], api_key='foreign-secret')
        with patch('httpx.Client.send') as network, patch('requests.post') as jev:
            response = self.client.post(self.url, {**self.keys, 'company_id': self.other.pk})
            self.assertEqual(response.status_code, 302)
            network.assert_not_called()
            jev.assert_not_called()
        self.company.refresh_from_db()
        foreign.refresh_from_db()
        self.assertEqual(self.company.ai_config, {})
        self.assertEqual(self.company.jev_api_key, self.keys['jev'])
        self.assertEqual(foreign.api_key, 'foreign-secret')
        self.assertEqual(CompanyEngine.objects.filter(company=self.company).count(), len(SERVICES) - 1)
        for key, engine in service_engines().items():
            self.assertEqual(CompanyEngine.objects.get(company=self.company, engine=engine).api_key, self.keys[key])
        with connection.cursor() as cursor:
            cursor.execute('SELECT api_key FROM front_companyengine WHERE company_id = %s', [self.company.pk])
            for row in cursor.fetchall():
                self.assertNotIn('synthetic-', row[0])
        page = self.client.get(self.url)
        self.assertContains(page, 'Clave guardada', count=len(SERVICES))
        for value in self.keys.values():
            self.assertNotContains(page, value)
        self.assertIn('no-store', page.headers['Cache-Control'])
        self.assertNotIn('synthetic-', AuditLog.objects.get(action='ai_keys_save').details)

    def test_blank_preserves_override_wins_rotation_reuses_rows_and_remove_preserves_direct(self):
        direct = CompanyEngine.objects.create(company=self.company,
            engine=Engine.objects.create(name='Existing direct'), api_key='keep-direct')
        self.client.post(self.url, {**self.keys, 'jev': 'own-jev-key'})
        ids = list(CompanyEngine.objects.filter(company=self.company).values_list('id', flat=True))
        self.client.post(self.url, {})
        self.company.refresh_from_db()
        self.assertEqual(self.company.jev_api_key, 'own-jev-key')
        self.client.post(self.url, {'claude': 'own-claude-key'})
        self.assertEqual(list(CompanyEngine.objects.filter(company=self.company).values_list('id', flat=True)), ids)
        self.assertEqual(CompanyEngine.objects.get(company=self.company, engine=service_engines()['claude']).api_key, 'own-claude-key')
        self.assertEqual(CompanyEngine.objects.get(company=self.company, engine=service_engines()['gemini']).api_key, self.keys['gemini'])
        self.company.refresh_from_db()
        self.assertEqual(self.company.jev_api_key, 'own-jev-key')
        self.client.post(self.url, {'action': 'remove'})
        self.company.refresh_from_db()
        self.assertEqual(self.company.jev_api_key, '')
        self.assertEqual(CompanyEngine.objects.filter(company=self.company, active=True).count(), 1)
        direct.refresh_from_db()
        self.assertEqual(direct.api_key, 'keep-direct')

    def test_validation_never_echoes_secrets_and_direct_jev_transport_is_preserved(self):
        for value in ('secret with spaces', 'x' * 257, 'secret\nnewline'):
            page = self.client.post(self.url, {'claude': value})
            self.assertEqual(page.status_code, 400)
            self.assertNotContains(page, value, status_code=400)
        self.company.ai_config = {'version': 1, 'jev': {'transport': 'typesafe', 'model': 'jev-1.0.0'}}
        self.company.jev_api_key = 'direct-jev'
        self.company.save()
        self.assertEqual(self.client.post(self.url, {'jev': 'new-key'}).status_code, 400)
        self.assertFalse(CompanyEngine.objects.filter(company=self.company).exists())
        self.client.post(self.url, {'action': 'remove'})
        self.company.refresh_from_db()
        self.assertEqual(self.company.jev_api_key, 'direct-jev')

    def test_permissions_csrf_and_sidebar_for_company_admin_without_superuser(self):
        self.assertFalse(self.user.is_superuser)
        self.assertContains(self.client.get('/chat/'), self.url)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(self.url, {'claude': 'secret'}).status_code, 403)
        Profile.objects.filter(user=self.user).update(role=None)
        for method in (self.client.get, self.client.post):
            self.assertEqual(method(self.url).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)

    def test_service_catalog_cannot_be_repointed_to_another_host(self):
        engine = service_engines()['claude']
        engine.base_url = 'https://elsewhere.invalid'
        engine.save()
        self.assertEqual(self.client.post(self.url, {'claude': 'new-key'}).status_code, 400)
        self.assertFalse(CompanyEngine.objects.filter(company=self.company).exists())

    def test_inactive_credentials_can_be_removed_even_if_catalog_is_unavailable(self):
        self.client.post(self.url, self.keys)
        engine = service_engines()['claude']
        CompanyEngine.objects.filter(company=self.company, engine=engine).update(active=False)
        engine.models.update(active=False)
        self.assertContains(self.client.get(self.url), 'Inactiva')
        self.assertEqual(self.client.post(self.url, {'action': 'remove'}).status_code, 302)
        self.assertTrue(all(not row.api_key for row in CompanyEngine.objects.filter(company=self.company)))

    def test_native_keys_reach_only_their_provider_from_all_three_http_entries(self):
        self.client.post(self.url, self.keys)
        mask = ObfuscationConfig.objects.create(company=self.company, name='Synthetic mask', api_url='https://mask.invalid')
        credentials = CompanyEngine.objects.filter(company=self.company).select_related('engine')
        self.company.ai_config = {'version': 1, 'allow_empty_rules': True, 'local_sensitivity': 'internal',
            'destinations': {'internal': [f'engine:{row.pk}' for row in credentials] + [f'obfuscation:{mask.pk}']},
            'masking': {'max_call_cost': '0'}}
        self.company.save()
        captured = []

        def respond(request):
            body = json.loads(request.content)
            captured.append((request, body))
            if request.url.host == 'api.anthropic.com':
                return httpx.Response(200, json={'id': 'synthetic', 'type': 'message', 'role': 'assistant',
                    'model': body['model'], 'content': [{'type': 'text', 'text': 'Hola'}],
                    'stop_reason': 'end_turn', 'stop_sequence': None,
                    'usage': {'input_tokens': 3, 'output_tokens': 1}})
            return httpx.Response(200, json={'id': 'synthetic', 'model': body['model'],
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'Hola'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 3, 'completion_tokens': 1, 'total_tokens': 4}})

        def masked(url, **kwargs):
            self.assertEqual(url, 'https://mask.invalid/api/mask')
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {'masked': kwargs['json']['text']})

        with patch('openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))), \
             patch('anthropic.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))), \
             patch('requests.post', side_effect=masked):
            for row in credentials:
                for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                    result = self.client.post(path, {'content' if path.startswith('/api/') else 'prompt': 'Hola',
                        'engine_id': row.pk, 'model_id': row.engine.models.get().pk, 'request_id': str(uuid.uuid4())})
                    self.assertEqual(result.status_code, 302 if path == '/chat/' else 200, result.content[:600])
                    self.assertEqual(Prompt.objects.latest('pk').status, 'completed')
                    request, body = captured[-1]
                    suffix = '/v1/messages' if row.engine.connector_type == 'anthropic' else '/chat/completions'
                    self.assertEqual(str(request.url), row.engine.base_url.rstrip('/') + suffix)
                    header = 'x-api-key' if row.engine.connector_type == 'anthropic' else 'authorization'
                    expected = row.api_key if header == 'x-api-key' else f'Bearer {row.api_key}'
                    self.assertEqual(request.headers[header], expected)
                    self.assertNotIn(self.keys['jev'], str(request.headers))
                    self.assertEqual(body['model'], row.engine.default_model)
                    self.assertNotIn('providerOptions', body)
            self.assertEqual(len(captured), 3 * (len(SERVICES) - 1))
        for prompt in Prompt.objects.all():
            for value in self.keys.values():
                self.assertNotIn(value, json.dumps(prompt.decision))
            generation = [call for call in prompt.decision['calls'] if call['purpose'] == 'generation']
            self.assertEqual(len(generation), 1)
            self.assertEqual(generation[0]['cost_kind'], 'unknown')

    def test_old_common_key_is_rejected_and_partial_configuration_never_copies_keys(self):
        self.assertEqual(self.client.post(self.url, {'gateway': 'obsolete-common-key'}).status_code, 400)
        self.assertEqual(self.client.post(self.url, {'gemini': self.keys['gemini']}).status_code, 302)
        self.assertEqual(CompanyEngine.objects.filter(company=self.company).count(), 1)
        self.company.refresh_from_db()
        self.assertEqual(self.company.jev_api_key, '')
        page = self.client.get(self.url)
        self.assertContains(page, 'type="password"', count=len(SERVICES))
        self.assertNotContains(page, 'name="gateway"')

    def test_jev_uses_only_its_own_vercel_key(self):
        from . import jev
        self.client.post(self.url, self.keys)
        self.company.refresh_from_db()
        payload = {'model': 'typesafe-ai/jev', 'answers': {'signal': {'type': 'noul', 'noul': 0}}}
        response = Mock(status_code=200, headers={'x-request-id': 'synthetic'})
        response.iter_content.return_value = [json.dumps(payload).encode()]
        with patch('requests.post', return_value=response) as post:
            jev.evaluate(self.company.jev_api_key, 'typesafe-ai/jev', 'Synthetic',
                {'signal': {'type': 'noul', 'instructions': 'Signal?'}}, transport='vercel')
        self.assertEqual(post.call_args.args, ('https://ai-gateway.vercel.sh/typesafe/v1/systemone',))
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'Bearer ' + self.keys['jev'])
        for key in ('claude', 'gemini', 'mistral', 'openai', 'deepseek'):
            self.assertNotIn(self.keys[key], str(post.call_args))

    def setup_token(self):
        return self.client.get(self.url).context['setup'].get('token', '')

    def test_basic_setup_requires_key_review_and_preserves_existing_configuration(self):
        # The island says it from its bootstrap; the legacy page (rollback) renders it.
        self.assertTrue(island_bootstrap(self.client.get('/chat/'))['setup']['missing'])
        with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
            self.assertContains(self.client.get('/chat/'), 'Falta configurar la IA')
        self.assertEqual(self.setup_token(), '')
        self.client.post(self.url, {'jev': self.keys['jev']})
        self.assertEqual(self.setup_token(), '')
        self.client.post(self.url, {'openai': self.keys['openai']})
        token = self.setup_token()
        self.assertTrue(token)
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic'}).status_code, 400)
        self.client.post(self.url, {'openai': 'rotated-key'})
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        token = self.setup_token()
        with patch('httpx.Client.send') as native, patch('requests.post') as external:
            self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 302)
            native.assert_not_called()
            external.assert_not_called()
        self.company.refresh_from_db()
        self.assertFalse(self.company.ai_config['allow_empty_rules'])
        self.assertEqual(self.company.ai_config['verification']['mode'], 'local')
        self.assertEqual(self.company.obfuscation_configs.get().backend, 'local')
        self.assertEqual(self.company.rules_groups.get().rules.get().action, 'block')
        self.other.refresh_from_db()
        self.assertEqual(self.other.ai_config, {})
        policy = self.company.ai_config
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config, policy)
        self.assertEqual(self.company.obfuscation_configs.count(), 1)
        self.assertNotContains(self.client.get('/chat/'), 'Falta configurar la IA')

    def test_basic_setup_rejects_other_account_review_and_existing_mask(self):
        self.client.post(self.url, {'openai': self.keys['openai']})
        token = self.setup_token()
        Profile.objects.filter(user=self.user).update(company=self.other)
        self.client.post(self.url, {'openai': 'other-key'})
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        self.assertFalse(self.other.obfuscation_configs.exists())
        Profile.objects.filter(user=self.user).update(company=self.company)
        ObfuscationConfig.objects.create(company=self.company, name='Existing mask', api_url='https://existing.invalid')
        self.assertEqual(self.setup_token(), '')
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config, {})

    def test_basic_setup_requires_installed_mask_and_unchanged_provider(self):
        self.client.post(self.url, {'openai': self.keys['openai']})
        token = self.setup_token()
        with patch('front.local_masking.detector_metadata', side_effect=RuntimeError('unavailable')):
            self.assertEqual(self.setup_token(), '')
            self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        engine = service_engines()['openai']
        engine.base_url = 'https://changed.invalid'
        engine.save()
        self.assertEqual(self.client.post(self.url, {'action': 'activate_basic', 'review_token': token}).status_code, 400)
        self.assertFalse(self.company.obfuscation_configs.exists())

    def test_basic_setup_reproduces_failure_then_sends_through_local_mask_on_three_entries(self):
        from .policy import evaluate_policy
        with patch('httpx.Client.send') as network, patch('requests.post') as external:
            self.client.post('/chat/send/', {'prompt': 'j', 'request_id': str(uuid.uuid4())})
            self.assertEqual('policy_configuration_invalid', Prompt.objects.latest('pk').decision['error_type'])
            network.assert_not_called()
            external.assert_not_called()
        self.client.post(self.url, {'openai': self.keys['openai']})
        self.client.post(self.url, {'action': 'activate_basic', 'review_token': self.setup_token()})
        credential = CompanyEngine.objects.get(company=self.company)
        captured = []

        def respond(request):
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={'id': 'synthetic', 'model': credential.engine.default_model,
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'Hola'}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 3, 'completion_tokens': 1, 'total_tokens': 4}})

        with patch('openai.DefaultHttpxClient', side_effect=lambda **kw: httpx.Client(transport=httpx.MockTransport(respond))), \
             patch('requests.post') as external:
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                self.client.post(path, {'content' if path.startswith('/api/') else 'prompt': 'j',
                    'engine_id': credential.pk, 'model_id': credential.engine.models.get().pk, 'request_id': str(uuid.uuid4())})
                self.assertEqual(Prompt.objects.latest('pk').status, 'completed')
                self.assertEqual(captured[-1]['max_tokens'], 1000)
            self.client.post('/chat/send/', {'prompt': 'Mi correo es prueba@example.com',
                'engine_id': credential.pk, 'request_id': str(uuid.uuid4())})
            self.assertEqual(Prompt.objects.latest('pk').status, 'completed')
            self.assertNotIn('prueba@example.com', json.dumps(captured[-1]))
            self.client.post('/chat/send/', {'prompt': 'password=synthetic_secret123', 'request_id': str(uuid.uuid4())})
            self.assertEqual(len(captured), 4)
            self.assertNotEqual(Prompt.objects.latest('pk').status, 'completed')
            external.assert_not_called()
        self.user = User.objects.get(pk=self.user.pk)
        for sensitivity in ('confidential', 'restricted', 'unknown'):
            self.assertEqual(evaluate_policy(self.user, [('prompts', 'j')], sensitivity=sensitivity).status, 'block')
        self.assertEqual(evaluate_policy(self.user, [('prompts', 'j')], destinations=['jev']).status, 'block')
        self.assertEqual(evaluate_policy(self.user, [('prompts', 'j')], destinations=['engine:999999']).status, 'block')


class ServiceMigrationTests(TransactionTestCase):
    def test_forward_and_reverse_preserve_existing_data_and_never_authorize_accounts(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0033_vercel_gateway_catalog')]
        try:
            executor.migrate(old_target)
            company = Company.objects.create(name='Migration account', ai_config={'version': 1}, jev_api_key='existing-jev')
            engine = Engine.objects.create(name='Migration direct', base_url='https://direct.invalid')
            credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='existing-key')
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(len(service_engines()), len(SERVICES) - 1)
            self.assertEqual(CompanyEngine.objects.filter(company=company).count(), 1)
            MigrationExecutor(connection).migrate(old_target)
            credential.refresh_from_db()
            company.refresh_from_db()
            self.assertEqual(credential.api_key, 'existing-key')
            self.assertEqual(company.jev_api_key, 'existing-jev')
            self.assertEqual(company.ai_config, {'version': 1})
        finally:
            MigrationExecutor(connection).migrate(latest)
