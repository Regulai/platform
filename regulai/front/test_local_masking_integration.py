"""Local privacy transformations at the HTTP and provider boundaries."""
import json
import sys
import uuid
from copy import deepcopy
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TransactionTestCase
from django.urls import reverse

from . import test_chat_flow, test_pipeline
from .chat_service import send_chat_message
from .connectors import ChatResponse
from .management.commands.bootstrap_ai_policy import initial_policy
from .masking import mask_cost_bounds, mask_identity, mask_texts, valid_masks
from .models import AuditLog, Company, ObfuscationConfig, Prompt


class LocalMaskingContractTests(SimpleTestCase):
    def config(self, **changes):
        return SimpleNamespace(**dict(dict(pk=1, backend='local', active=True, api_url='',
            detect='both', language='es'), **changes))

    def test_local_backend_is_valid_without_an_external_url(self):
        self.assertTrue(valid_masks([self.config()]))

    def test_backend_change_invalidates_mask_identity(self):
        config = self.config()
        local = mask_identity(config)
        config.backend = 'http'
        self.assertNotEqual(local, mask_identity(config))

    def test_local_backend_never_falls_through_to_http(self):
        config = self.config()
        with patch('front.masking.mask_local_texts', create=True, return_value=['[EMAIL]']) as local, \
                patch('requests.post', side_effect=AssertionError('Network forbidden')) as network:
            self.assertEqual(mask_texts(['private@example.invalid'], [config]), ['[EMAIL]'])
        local.assert_called_once_with(['private@example.invalid'], language='es', timeout=10)
        network.assert_not_called()

    def test_unknown_backend_or_partial_detection_cannot_be_used(self):
        for changes in ({'backend': 'invalid'}, {'detect': 'pii'}, {'detect': 'secrets'}, {'language': 'fr'}):
            with self.subTest(changes=changes):
                self.assertFalse(valid_masks([self.config(**changes)]))

    def test_only_local_requires_zero_and_mixed_chain_bounds_each_backend(self):
        local = self.config()
        for bound in (None, '0.01'):
            with self.subTest(bound=bound), self.assertRaises(ValueError):
                mask_cost_bounds([local], bound)
        self.assertEqual(mask_cost_bounds([local], '0'), {1: Decimal('0')})
        remote = self.config(pk=2, backend='http', api_url='https://mask.invalid')
        self.assertEqual(mask_cost_bounds([local, remote], '0.03'), {1: Decimal('0'), 2: Decimal('0.03')})

    def test_invalid_batch_is_atomic_and_stops_before_following_http(self):
        local = self.config()
        remote = self.config(pk=2, backend='http', api_url='https://mask.invalid')
        for value in (['one'], ['one', 42], {'masked': ['one', 'two']}, 'one\ntwo'):
            with self.subTest(value=value), \
                    patch('front.masking.mask_local_texts', return_value=value), \
                    patch('requests.post') as network:
                with self.assertRaises(ValueError):
                    mask_texts(['original one', 'original two'], [local, remote])
                network.assert_not_called()


class LocalMaskingIntegrationTests(test_chat_flow.ChatFixture):
    configure = test_pipeline.PipelineTests.configure
    original = 'Contacta con Ana García en ana.garcia@example.invalid. DNI 12345678Z.'

    def setUp(self):
        super().setUp()
        self.required_mask.backend = 'local'
        self.required_mask.api_url = ''
        self.required_mask.language = 'es'
        self.required_mask.save()
        self.http.side_effect = AssertionError('Unexpected external HTTP')
        self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Live network forbidden')))

    def openai_transport(self, handler):
        self.enterContext(patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT))
        self.enterContext(patch('openai.DefaultHttpxClient', side_effect=lambda **kwargs:
            httpx.Client(transport=httpx.MockTransport(handler), **kwargs)))

    def answer(self, content):
        return httpx.Response(200, json={'id': 'synthetic-local-mask', 'object': 'chat.completion',
            'created': 0, 'model': 'synthetic-v1',
            'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content}, 'finish_reason': 'stop'}],
            'usage': {'prompt_tokens': 20, 'completion_tokens': 10, 'total_tokens': 30}})

    def assert_masked(self, value):
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        self.assertNotIn('ana.garcia@example.invalid', value)
        self.assertNotIn('12345678Z', value)

    def test_three_http_entries_send_only_real_local_detector_output_to_real_sdk(self):
        sent = []
        def transport(request):
            sent.append(json.loads(request.content))
            self.assert_masked(request.content.decode())
            current = Prompt.objects.get(status='processing').decision['calls']
            self.assertEqual(current[0]['transport'], 'local')
            self.assertEqual(current[-1]['status'], 'started')
            return self.answer('Respuesta segura.')
        self.openai_transport(transport)
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                result = self.send(path, self.original)
                self.assertEqual(result.status_code, 302 if path == '/chat/' else 200)
                prompt = Prompt.objects.latest('pk')
                self.assertEqual(prompt.status, 'completed', prompt.decision)
                self.assert_masked(prompt.user_message.content)
                calls = prompt.decision['calls']
                self.assertEqual([call['transport'] for call in calls], ['local', 'http', 'local'])
                for call in (calls[0], calls[-1]):
                    self.assertEqual((call['cost'], call['cost_bound'], call['cost_kind']), ('0', '0', 'configured_zero'))
                    self.assertEqual(call['cost_scope'], 'api')
        self.assertEqual(len(sent), 3)
        self.http.assert_not_called()

    def test_yara_and_restricted_content_stop_before_local_detector(self):
        with patch('front.masking.mask_local_texts') as detector:
            for content, sensitivity in (('SYNTHETIC_SECRET', 'internal'), (self.original, 'restricted')):
                self.company.ai_config['local_sensitivity'] = sensitivity
                self.company.save()
                for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                    with self.subTest(path=path, sensitivity=sensitivity):
                        self.assertEqual(self.send(path, content).status_code, 403)
                        self.assertEqual(Prompt.objects.latest('pk').decision['calls'], [])
            detector.assert_not_called()
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_local_failures_and_invalid_output_close_all_http_entries_with_known_zero_api_cost(self):
        for failure in (RuntimeError('Detector model unavailable'), TimeoutError('Detector deadline'), ValueError('Invalid batch')):
            with self.subTest(failure=type(failure).__name__), \
                    patch('front.masking.mask_local_texts', side_effect=failure):
                for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                    self.send(path, self.original)
                    prompt = Prompt.objects.latest('pk')
                    self.assertIn(prompt.status, ('failed', 'outcome_unknown'))
                    calls = prompt.decision['calls']
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]['transport'], 'local')
                    self.assertEqual(calls[0]['cost_kind'], 'configured_zero')
                    self.assertEqual(prompt.decision['total']['cost'], '0')
                    self.assertTrue(prompt.decision['total']['complete'])
                    self.assertFalse(hasattr(prompt, 'response'))
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_missing_statistical_model_does_not_block_pattern_masking(self):
        with patch.dict(sys.modules, {'spacy': None, 'xx_ent_wiki_sm': None}):
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(path=path):
                    self.send(path, self.original)
                    prompt = Prompt.objects.latest('pk')
                    self.assertEqual(prompt.status, 'completed', prompt.decision)
                    self.assertEqual(prompt.decision['calls'][0]['transport'], 'local')
                    self.assert_masked(str(self.provider.call_args))
        self.http.assert_not_called()
        self.assertEqual(self.provider.call_count, 3)

    def test_local_only_requires_explicit_zero_before_any_transform(self):
        for bound in (None, '0.01'):
            self.company.ai_config['masking']['max_call_cost'] = bound
            self.company.save()
            with self.subTest(bound=bound), patch('front.masking.mask_local_texts') as detector:
                result = self.send('/api/chat/send/', self.original).json()
                self.assertEqual(result['error_type'], 'policy_configuration_invalid')
                self.assertEqual(result['receipt']['calls'], [])
                detector.assert_not_called()
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def zero_price_generation(self, budget):
        self.model.input_price = self.model.output_price = Decimal(0)
        self.model.save()
        self.company.ai_config['limits'] = {'budget': budget}
        self.company.save()
        self.provider.return_value = ChatResponse('Respuesta segura.', 30, 'synthetic-v1', 'stop', 20, 10)

    def test_zero_api_budget_accepts_local_transforms_and_free_generation(self):
        self.zero_price_generation('0')
        result = self.send('/api/chat/send/', self.original).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(Decimal(result['receipt']['total']['cost']), Decimal(0))
        self.assertEqual([call['transport'] for call in result['receipt']['calls']], ['local', 'http', 'local'])
        self.http.assert_not_called()

    def test_mixed_chain_charges_only_http_steps_and_preserves_remote_uncertainty(self):
        remote = ObfuscationConfig.objects.create(company=self.company, name='Explicit remote step',
            backend='http', api_url='https://mask.invalid', detect='both')
        self.company.ai_config['destinations']['internal'].append(f'obfuscation:{remote.pk}')
        self.company.ai_config['masking']['max_call_cost'] = '0.03'
        self.zero_price_generation('0.06')
        def remote_transport(url, **kwargs):
            self.assert_masked(kwargs['json']['text'])
            return test_chat_flow.mask_response(url, **kwargs)
        self.http.side_effect = remote_transport
        result = self.send('/api/chat/send/', self.original).json()
        self.assertEqual(result['status'], 'completed', result)
        calls = [call for call in result['receipt']['calls'] if call['purpose'] == 'obfuscation']
        self.assertEqual([(call['transport'], call['cost_bound']) for call in calls],
            [('local', '0'), ('http', '0.03'), ('local', '0'), ('http', '0.03')])
        self.assertEqual(sum(Decimal(call['cost_bound']) for call in calls), Decimal('0.06'))
        self.assertIsNone(result['receipt']['total']['cost'])
        self.assertEqual(self.http.call_count, 2)
        self.http.reset_mock()
        self.provider.reset_mock()
        self.company.ai_config['limits']['budget'] = '0.059'
        self.company.save()
        result = self.send('/api/chat/send/', self.original).json()
        self.assertEqual(result['error_type'], 'budget_exhausted')
        self.assertEqual(result['receipt']['calls'], [])
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_backend_change_after_reservation_stops_before_stale_transport_and_is_not_retried(self):
        for initial, purpose in (('local', 'obfuscation'), ('http', 'obfuscation'), ('local', 'generation')):
            with self.subTest(initial=initial, purpose=purpose):
                ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(backend=initial, api_url='https://mask.invalid')
                completed, started = [], []
                def reserve(call):
                    started.append(deepcopy(call))
                    self.assertNotIn('ana.garcia@example.invalid', str(call))
                    if call['purpose'] == purpose:
                        ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(
                            backend='http' if initial == 'local' else 'local')
                    return len(started)
                observer = SimpleNamespace(before_call=reserve, after_call=lambda call, token: completed.append(call))
                command = {'content': self.original, 'request_id': str(uuid.uuid4())}
                result = send_chat_message(self.user, command, call_observer=observer).data
                self.assertEqual(result['error_type'], 'authorization_changed')
                self.assertEqual(completed[-1]['status'], 'not_started')
                self.assertEqual(completed[-1]['cost_kind'], 'not_incurred')
                self.assertEqual(completed[-1]['cost'], '0')
                previous = len(started)
                replay = send_chat_message(self.user, command, call_observer=observer).data
                self.assertEqual(replay['error_type'], 'authorization_changed')
                self.assertEqual(len(started), previous)
                if initial == 'local':
                    self.assertEqual((started[0]['transport'], started[0]['cost'], started[0]['cost_scope']), ('local', '0', 'api'))
                self.http.assert_not_called()
                self.provider.assert_not_called()

    def test_foreign_or_disabled_local_detector_cannot_supply_company_barrier(self):
        other = Company.objects.create(name='Other local privacy company')
        ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(company=other)
        with patch('front.masking.mask_local_texts') as detector:
            result = self.send('/api/chat/send/', self.original).json()
            self.assertEqual(result['error_type'], 'masking_required')
            detector.assert_not_called()
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_backend_switch_invalidates_pending_consent_without_running_detector(self):
        self.rule.action = 'consent'
        self.rule.save()
        request_id = str(uuid.uuid4())
        with patch('front.masking.mask_local_texts') as detector:
            initial = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id).json()
            self.assertEqual(initial['status'], 'pending_consent')
            ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(backend='http', api_url='https://mask.invalid')
            changed = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id,
                consent_token=initial['consent_token']).json()
            self.assertEqual(changed['status'], 'pending_consent')
            self.assertEqual(changed['receipt']['consent_reason'], 'consent_context_changed')
            self.assertEqual(changed['receipt']['calls'], [])
            detector.assert_not_called()
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_semantic_simulation_masks_locally_and_audits_api_zero_before_judge(self):
        self.user.is_superuser = True
        self.user.save()
        self.configure()
        evaluator = test_pipeline.jev_http()
        def judge(url, **kwargs):
            self.assertFalse(url.endswith('/api/mask'))
            self.assert_masked(kwargs['data'])
            local = json.loads(AuditLog.objects.filter(action='policy_simulate').order_by('pk').first().details)['call']
            self.assertEqual((local['transport'], local['status'], local['cost']), ('local', 'completed', '0'))
            return evaluator(url, **kwargs)
        self.http.side_effect = judge
        result = self.client.post(reverse('front:policy_simulator'), {'mode': 'semantic',
            'sample': self.original, 'proposed_config': json.dumps(self.company.ai_config)})
        comparison = result.context['comparison']
        self.assertEqual(comparison['semantic']['status'], 'completed', comparison)
        self.assertEqual([call['transport'] for call in comparison['calls']], ['local', 'http'])
        self.assertEqual(self.http.call_count, 1)
        self.provider.assert_not_called()
        self.assertEqual(Prompt.objects.count(), 0)

    def test_semantic_simulation_detector_failure_never_reaches_judge_and_keeps_api_zero(self):
        self.user.is_superuser = True
        self.user.save()
        self.configure()
        with patch('front.masking.mask_local_texts', side_effect=RuntimeError('Local model unavailable')):
            result = self.client.post(reverse('front:policy_simulator'), {'mode': 'semantic',
                'sample': self.original, 'proposed_config': json.dumps(self.company.ai_config)})
        comparison = result.context['comparison']
        self.assertEqual(comparison['semantic']['reason_codes'], ['masking_failed'])
        self.assertEqual(len(comparison['calls']), 1)
        call = comparison['calls'][0]
        self.assertEqual((call['transport'], call['status'], call['cost'], call['cost_kind']),
            ('local', 'failed', '0', 'configured_zero'))
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_semantic_simulator_backend_replacement_during_local_work_prevents_judge(self):
        from .local_masking import mask_local_texts
        self.user.is_superuser = True
        self.user.save()
        self.configure()
        def replace_backend(texts, **kwargs):
            masked = mask_local_texts(texts, **kwargs)
            ObfuscationConfig.objects.filter(pk=self.required_mask.pk).update(backend='http', api_url='https://changed.invalid')
            return masked
        with patch('front.masking.mask_local_texts', side_effect=replace_backend):
            result = self.client.post(reverse('front:policy_simulator'), {'mode': 'semantic',
                'sample': self.original, 'proposed_config': json.dumps(self.company.ai_config)})
        comparison = result.context['comparison']
        self.assertEqual(comparison['semantic']['reason_codes'], ['authorization_changed'])
        self.assertEqual([(call['transport'], call['cost']) for call in comparison['calls']], [('local', '0')])
        self.http.assert_not_called()
        self.provider.assert_not_called()

    def test_json_citations_survive_real_local_detector_and_real_sdk_transport(self):
        self.configure()
        captured = []
        evaluator = test_pipeline.jev_http(choices={'task': 'document_question'})
        def judge(url, **kwargs):
            self.assertFalse(url.endswith('/api/mask'))
            self.assert_masked(kwargs['data'])
            return evaluator(url, **kwargs)
        self.http.side_effect = judge
        def transport(request):
            self.assert_masked(request.content.decode())
            messages = json.loads(request.content)['messages']
            sources = json.loads(messages[-1]['content'].split('Sources:\n', 1)[1])
            captured.append(sources[0])
            return self.answer(json.dumps({'claims': [{'text': 'El contrato cubre soporte semanal.',
                'citations': [{'id': sources[0]['id'], 'quote': sources[0]['text']}]}]}, ensure_ascii=False))
        self.openai_transport(transport)
        document = 'El contrato de servicio cubre soporte semanal para ana.garcia@example.invalid durante todo el año.'
        result = self.send('/api/chat/send/', 'Resume la cobertura.',
            file=SimpleUploadedFile('contrato.txt', document.encode())).json()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(captured[0]['id'], 'S1')
        self.assertEqual(result['receipt']['verification']['status'], 'passed')
        self.assertEqual(result['evidence']['items'][0]['excerpt'], captured[0]['text'])
        self.assertEqual(result['evidence']['items'][0]['locator'], 'line:1')
        self.assertEqual(self.http.call_count, 2)


class LocalMaskingConfigurationTests(test_chat_flow.ChatFixture):
    def setUp(self):
        super().setUp()
        self.user.is_staff = True
        self.user.save()

    def test_new_ui_defaults_local_and_validates_backend_url_and_language(self):
        url = reverse('front:obfuscation_create')
        page = self.client.get(url)
        self.assertContains(page, '<option value="local" selected>')
        self.assertEqual(ObfuscationConfig.objects.count(), 1)
        data = {'name': 'Company local', 'backend': 'local', 'detect': 'both', 'language': 'es', 'active': 'on'}
        result = self.client.post(url, data)
        self.assertEqual(result.status_code, 302)
        created = ObfuscationConfig.objects.latest('pk')
        self.assertEqual((created.company_id, created.backend, created.api_url), (self.company.pk, 'local', ''))
        for changes, field in (({'backend': 'http'}, 'api_url'), ({'backend': ''}, 'backend'),
                ({'backend': 'local', 'language': 'fr'}, 'language')):
            with self.subTest(changes=changes):
                result = self.client.post(url, dict(data, **changes))
                self.assertEqual(result.status_code, 200)
                self.assertIn(field, result.context['form'].errors)
        self.assertEqual(ObfuscationConfig.objects.count(), 2)
        self.http.assert_not_called()

    def test_existing_http_ui_keeps_backend_and_rejects_missing_url_without_mutating(self):
        url = reverse('front:obfuscation_edit', args=[self.required_mask.pk])
        page = self.client.get(url)
        self.assertContains(page, '<option value="http" selected>')
        result = self.client.post(url, {'name': 'Changed draft', 'backend': 'http', 'api_url': '',
            'detect': 'both', 'language': 'es', 'active': 'on'})
        self.assertContains(result, 'Changed draft')
        self.assertIn('api_url', result.context['form'].errors)
        self.required_mask.refresh_from_db()
        self.assertEqual(self.required_mask.api_url, 'https://mask.invalid')
        self.assertEqual(self.required_mask.backend, 'http')
        other = Company.objects.create(name='Other settings company')
        foreign = ObfuscationConfig.objects.create(company=other, name='Foreign', backend='local')
        self.assertEqual(self.client.get(reverse('front:obfuscation_edit', args=[foreign.pk])).status_code, 404)

    def test_local_bootstrap_draft_has_explicit_zero_without_activation(self):
        self.required_mask.backend, self.required_mask.api_url = 'local', ''
        self.required_mask.save()
        before = deepcopy(self.company.ai_config)
        draft, warnings = initial_policy(self.company)
        self.assertEqual(draft['masking']['max_call_cost'], '0')
        self.assertTrue(any('explicit patterns only' in warning for warning in warnings))
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config, before)
        self.assertEqual(ObfuscationConfig.objects.count(), 1)
        self.http.assert_not_called()


class LocalMaskingMigrationTests(TransactionTestCase):
    def test_downgrade_requires_reauthorization_of_local_masks_and_preserves_http_state(self):
        from .forms import ObfuscationConfigForm
        company = Company.objects.create(name='Local rollback company')
        other = Company.objects.create(name='Other rollback company')
        converted = ObfuscationConfig.objects.create(company=company, name='Former remote', backend='http',
            api_url='https://former-mask.example.invalid', detect='both', active=True)
        form = ObfuscationConfigForm({'name': converted.name, 'backend': 'local', 'api_url': converted.api_url,
            'detect': 'both', 'language': 'es', 'active': 'on'}, instance=converted)
        self.assertTrue(form.is_valid(), form.errors)
        converted = form.save()
        self.assertTrue(converted.active)
        self.assertEqual(converted.api_url, 'https://former-mask.example.invalid')
        blank = ObfuscationConfig.objects.create(company=company, name='New local', backend='local', active=True)
        inactive = ObfuscationConfig.objects.create(company=other, name='Inactive local', backend='local',
            api_url='https://inactive.example.invalid', active=False)
        other_local = ObfuscationConfig.objects.create(company=other, name='Other active local', backend='local',
            api_url='https://other-former.example.invalid', active=True)
        remote = ObfuscationConfig.objects.create(company=other, name='Still remote', backend='http',
            api_url='https://authorized.example.invalid', active=True)
        ObfuscationConfig.objects.create(company=other, name='Inactive remote', backend='http',
            api_url='https://inactive-http.example.invalid', active=False)
        company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
            'masking': {'max_call_cost': '0'}, 'destinations': {'internal': [f'obfuscation:{converted.pk}']}}
        company.save()
        audit = AuditLog.objects.create(company=company, action='historical', details='Preserve original privacy audit')
        fields = ('pk', 'company_id', 'name', 'api_url', 'detect', 'language', 'active', 'created_at')
        before = list(ObfuscationConfig.objects.order_by('pk').values(*fields))
        local_ids = {converted.pk, blank.pk, inactive.pk, other_local.pk}
        expected = [{**row, 'active': False} if row['pk'] in local_ids else row for row in before]
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0031_infer_historical_prompt_company')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            downgraded = old.get_model('front', 'ObfuscationConfig')
            self.assertEqual(list(downgraded.objects.order_by('pk').values(*fields)), expected)
            # The former HTTP endpoint is retained as data, never as authority:
            # old application code finds no active barrier for this local company.
            self.assertFalse(downgraded.objects.filter(company_id=company.pk, active=True).exists())
            self.assertTrue(downgraded.objects.get(pk=remote.pk).active)
            self.assertEqual(old.get_model('front', 'Company').objects.get(pk=company.pk).ai_config, company.ai_config)
            self.assertEqual(old.get_model('front', 'AuditLog').objects.get(pk=audit.pk).details, 'Preserve original privacy audit')
            MigrationExecutor(connection).migrate(old_target)
            self.assertEqual(list(downgraded.objects.order_by('pk').values(*fields)), expected)
            MigrationExecutor(connection).migrate(latest)
            self.assertFalse(ObfuscationConfig.objects.filter(pk__in=local_ids, active=True).exists())
            self.assertTrue(ObfuscationConfig.objects.get(pk=remote.pk).active)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def test_forward_reverse_preserve_remote_configuration_policies_and_audit(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0031_infer_historical_prompt_company')]
        new_target = [('front', '0032_obfuscationconfig_backend')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            company = old.get_model('front', 'Company').objects.create(name='Remote migration', ai_config={'unchanged': 1})
            remote = old.get_model('front', 'ObfuscationConfig').objects.create(company_id=company.pk,
                name='Historical remote', api_url='https://historical.invalid', detect='both', language='es', active=False)
            audit = old.get_model('front', 'AuditLog').objects.create(company_id=company.pk,
                action='historical', details='Original immutable audit')
            executor = MigrationExecutor(connection)
            executor.migrate(new_target)
            upgraded = executor.loader.project_state(new_target).apps.get_model('front', 'ObfuscationConfig')
            row = upgraded.objects.get(pk=remote.pk)
            self.assertEqual((row.backend, row.api_url, row.language, row.active),
                ('http', 'https://historical.invalid', 'es', False))
            MigrationExecutor(connection).migrate(old_target)
            row = old.get_model('front', 'ObfuscationConfig').objects.get(pk=remote.pk)
            self.assertEqual((row.name, row.api_url, row.detect, row.active),
                ('Historical remote', 'https://historical.invalid', 'both', False))
            self.assertEqual(old.get_model('front', 'Company').objects.get(pk=company.pk).ai_config, {'unchanged': 1})
            self.assertEqual(old.get_model('front', 'AuditLog').objects.get(pk=audit.pk).details, 'Original immutable audit')
        finally:
            MigrationExecutor(connection).migrate(latest)
