import json
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import AuditLog, Company, CompanyEngine, Conversation, Engine, EngineModel, Message, ObfuscationConfig, Profile, Prompt, Role


class RegistrationTests(TestCase):
    def setUp(self):
        cache.clear()

    def registration(self, name):
        return {'username': name, 'email': name + '@example.test', 'company_name': name,
            'password': 'Synthetic-password-123', 'password_confirm': 'Synthetic-password-123'}

    def test_public_registration_is_disabled_by_default_and_hidden_at_login(self):
        login = self.client.get(reverse('front:login'))
        self.assertFalse(login.context['allow_registration'])
        self.client.post(reverse('front:signup'), self.registration('disabled'))
        self.assertFalse(User.objects.exists())
        self.assertFalse(Company.objects.exists())

    @override_settings(ALLOW_REGISTRATION=True)
    def test_each_registered_company_admin_manages_only_own_policy_without_platform_privileges(self):
        for name in ('first-company', 'second-company'):
            self.client.logout()
            response = self.client.post(reverse('front:signup'), self.registration(name))
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username=name)
            self.assertFalse(user.is_superuser)
            self.assertTrue(user.is_staff)
            self.assertEqual(user.profile.role.name, 'Admin')
            simulator = self.client.get(reverse('front:policy_simulator'))
            self.assertEqual(simulator.status_code, 200)
            self.assertEqual(simulator.context['company'].name, name)
            self.assertTrue(simulator.context['can_manage_company_policy'])
            self.assertFalse(simulator.context['is_platform_operator'])


class CompanyPolicyPermissionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Company admin policy', ai_config={
            'version': 1, 'allow_empty_rules': True, 'local_sensitivity': 'internal',
            'destinations': {'internal': ['jev']}})
        self.role = Role.objects.create(name='Admin')
        self.admin = User.objects.create_user('company-policy-admin')
        Profile.objects.create(user=self.admin, company=self.company, role=self.role)
        self.client.force_login(self.admin)
        self.url = reverse('front:policy_simulator')
        self.activate = reverse('front:policy_simulator_activate')

    def test_company_admin_compares_and_activates_own_policy_with_audit(self):
        command = {'proposed_config': json.dumps(dict(self.company.ai_config, local_sensitivity='restricted')),
            'sample': 'Synthetic sample'}
        response = self.client.post(self.url, command)
        self.assertEqual(response.status_code, 200)
        command['activation_token'] = response.context['activation_token']
        activated = self.client.post(self.activate, command)
        self.assertEqual(activated.status_code, 200)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config['local_sensitivity'], 'restricted')
        self.assertEqual(AuditLog.objects.get(action='policy_activate').company_id, self.company.pk)

    def test_foreign_destinations_and_revoked_role_cannot_activate(self):
        foreign = Company.objects.create(name='Foreign policy')
        engine = Engine.objects.create(name='Foreign engine')
        linked = CompanyEngine.objects.create(company=foreign, engine=engine, api_key='synthetic')
        proposed = dict(self.company.ai_config, destinations={'internal': [f'engine:{linked.pk}']})
        self.assertEqual(self.client.post(self.url, {'proposed_config': json.dumps(proposed),
            'sample': 'Synthetic'}).status_code, 400)
        Profile.objects.filter(user=self.admin).update(role=None)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.activate, {}).status_code, 403)

    def test_legacy_superuser_with_profile_retains_company_policy_and_missing_profile_is_denied(self):
        bare = User.objects.create_user('bare-superuser', is_superuser=True, is_staff=True)
        Profile.objects.create(user=bare, company=self.company)
        self.client.force_login(bare)
        self.assertEqual(self.client.get(self.url).status_code, 200)
        orphan = User.objects.create_user('orphan-admin', is_superuser=True)
        self.client.force_login(orphan)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.admin.is_active = False
        self.admin.save(update_fields=['is_active'])
        self.client.force_login(self.admin)
        self.assertNotEqual(self.client.get(self.url).status_code, 200)

    def test_explicit_platform_operator_with_profile_can_manage_policy(self):
        self.admin.is_staff = True
        self.admin.is_superuser = True
        self.admin.save(update_fields=['is_superuser', 'is_staff'])
        Profile.objects.filter(user=self.admin).update(role=None)
        with override_settings(PLATFORM_ADMIN_USER_IDS=[self.admin.pk]):
            self.assertEqual(self.client.get(self.url).status_code, 200)


class BootstrapPolicyTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Bootstrap company')
        self.admin = User.objects.create_user('bootstrap-admin')
        Profile.objects.create(user=self.admin, company=self.company, role=Role.objects.create(name='Admin'))
        engine = Engine.objects.create(name='Bootstrap engine')
        self.linked = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        self.model = EngineModel.objects.create(engine=engine, name='Bootstrap model', model_id='bootstrap-model',
            context_window=8192, max_tokens=2048)
        inactive = Engine.objects.create(name='Inactive bootstrap engine')
        CompanyEngine.objects.create(company=self.company, engine=inactive, active=False, api_key='synthetic')
        foreign = Company.objects.create(name='Foreign bootstrap')
        CompanyEngine.objects.create(company=foreign, engine=engine, api_key='synthetic')
        self.client.force_login(self.admin)

    def test_bootstrap_post_generates_company_draft_without_activation_or_network(self):
        with patch('requests.sessions.Session.request') as network:
            response = self.client.post(reverse('front:policy_simulator'), {'action': 'bootstrap', 'mode': 'semantic'})
        self.assertEqual(response.status_code, 200)
        draft = json.loads(response.context['proposed_config'])
        self.assertEqual(draft['local_sensitivity'], 'internal')
        self.assertEqual(draft['destinations']['internal'], [f'engine:{self.linked.pk}'])
        self.assertEqual(draft['destinations']['public'], [f'engine:{self.linked.pk}'])
        self.assertEqual(draft['destinations']['restricted'], [])
        self.assertEqual(draft['destinations']['confidential'], [])
        self.assertTrue(response.context['bootstrap_warnings'])
        self.assertNotIn('activation_token', response.context)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config, {})
        self.assertEqual(AuditLog.objects.count(), 0)
        network.assert_not_called()

    def test_command_outputs_draft_and_dry_run_does_not_write(self):
        for dry_run in (False, True):
            output = StringIO()
            with patch('requests.sessions.Session.request') as network:
                call_command('bootstrap_ai_policy', company=self.company.pk, dry_run=dry_run, stdout=output)
            generated = json.loads(output.getvalue())
            self.assertEqual(generated['proposed_config']['local_sensitivity'], 'internal')
            self.assertTrue(generated['bootstrap_warnings'])
            self.assertEqual(generated['proposed_config']['routing']['candidates'][0]['quality'], {})
            self.company.refresh_from_db()
            self.assertEqual(self.company.ai_config, {})
            self.assertFalse(AuditLog.objects.exists())
            network.assert_not_called()

    def test_bootstrap_draft_requires_comparison_before_audited_activation(self):
        generated = self.client.post(reverse('front:policy_simulator'), {'action': 'bootstrap'})
        command = {'proposed_config': generated.context['proposed_config'], 'sample': 'Synthetic sample'}
        self.assertEqual(self.client.post(reverse('front:policy_simulator_activate'), command).status_code, 409)
        comparison = self.client.post(reverse('front:policy_simulator'), command)
        self.assertEqual(comparison.status_code, 200)
        command['activation_token'] = comparison.context['activation_token']
        self.assertEqual(self.client.post(reverse('front:policy_simulator_activate'), command).status_code, 200)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config['local_sensitivity'], 'internal')
        self.assertEqual(AuditLog.objects.get(action='policy_activate').company_id, self.company.pk)

    def test_missing_prices_with_budget_block_simulation_without_external_calls(self):
        ObfuscationConfig.objects.create(company=self.company, name='Bootstrap mask', api_url='https://mask.invalid')
        generated = self.client.post(reverse('front:policy_simulator'), {'action': 'bootstrap'})
        draft = json.loads(generated.context['proposed_config'])
        draft['allow_empty_rules'] = True
        draft['routing']['candidates'][0]['quality'] = {'general': 0.8}
        draft['limits']['budget'] = '1'
        draft['masking']['max_call_cost'] = '0'
        with patch('requests.sessions.Session.request') as network:
            response = self.client.post(reverse('front:policy_simulator'), {
                'proposed_config': json.dumps(draft), 'sample': 'Synthetic sample'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['comparison']['proposed']['route']['reason_codes'], ['unknown_price'])
        network.assert_not_called()


class HistoricalVisibilityTests(TestCase):
    def setUp(self):
        cache.clear()
        self.first = Company.objects.create(name='History A')
        self.second = Company.objects.create(name='History B')
        self.user = User.objects.create_user('historical-owner', is_staff=True, is_superuser=True)
        self.profile = Profile.objects.create(user=self.user, company=self.first)
        other = User.objects.create_user('historical-other', is_staff=True, is_superuser=True)
        Profile.objects.create(user=other, company=self.second)
        self.legacy = AuditLog.objects.create(user=self.user, action='old', details='Historical A details')
        self.foreign = AuditLog.objects.create(user=other, action='old', details='Historical B details')
        self.captured = AuditLog.objects.create(user=self.user, company=self.first,
            action='new', details='Captured tenant A')
        self.system = AuditLog.objects.create(action='old', details='Historical global system')
        self.client.force_login(self.user)

    def test_web_and_api_show_labeled_legacy_audits_only_for_current_company(self):
        response = self.client.get(reverse('front:auditlogs_list'))
        self.assertEqual({item.pk for item in response.context['logs']}, {self.legacy.pk, self.captured.pk})
        self.assertEqual(response.context['total_logs'], 2)
        self.assertEqual(self.client.get(reverse('front:auditlog_detail', args=[self.legacy.pk])).status_code, 200)
        for item in (self.foreign, self.system):
            self.assertEqual(self.client.get(reverse('front:auditlog_detail', args=[item.pk])).status_code, 404)
        api = self.client.get('/api/audit-logs/')
        self.assertEqual(api.status_code, 200)
        rows = {item['id']: item for item in api.json()['results']}
        self.assertTrue({self.legacy.pk, self.captured.pk}.issubset(rows))
        self.assertFalse({self.foreign.pk, self.system.pk} & rows.keys())
        self.assertTrue(rows[self.legacy.pk]['historical'])
        self.assertFalse(rows[self.captured.pk]['historical'])
        self.legacy.refresh_from_db()
        self.assertEqual(self.legacy.details, 'Historical A details')
        self.assertIsNone(self.legacy.company_id)

    def test_transferred_user_cannot_read_inferred_prompt_conversation_or_file_web_and_api(self):
        conversation = Conversation.objects.create(user=self.user)
        prompt = Prompt.objects.create(user=self.user, company=self.first, historical_company_id=self.first.pk,
            conversation=conversation, content='Inferred historical A prompt', file_name='original.txt')
        message = Message.objects.create(conversation=conversation, role='assistant', content='Old file')
        self.assertEqual(self.client.get(f'/prompts/{prompt.pk}/').status_code, 200)
        self.profile.company = self.second
        self.profile.save(update_fields=['company'])
        for path in (f'/prompts/{prompt.pk}/', f'/chat/{conversation.pk}/', f'/chat/download/{message.pk}/',
                f'/api/conversations/{conversation.pk}/', f'/api/messages/{message.pk}/'):
            self.assertEqual(self.client.get(path).status_code, 404, path)
        self.assertEqual(self.client.get('/api/dashboard/stats/').json()['total_prompts'], 0)
        self.assertNotContains(self.client.get('/prompts/'), 'Inferred historical A prompt')
        self.assertEqual(self.client.get(reverse('front:auditlog_detail', args=[self.captured.pk])).status_code, 404)
        # D5 deliberately infers null audits from the current profile without rewriting them.
        self.assertEqual(self.client.get(reverse('front:auditlog_detail', args=[self.legacy.pk])).status_code, 200)

    def test_historical_visibility_does_not_grant_delete_or_clear_authority(self):
        AuditLog.objects.filter(pk__in=[self.legacy.pk, self.captured.pk]).update(
            timestamp=timezone.now() - timedelta(days=40))
        response = self.client.post(reverse('front:auditlog_delete', args=[self.legacy.pk]))
        self.assertEqual(response.status_code, 404)
        self.client.post(reverse('front:auditlogs_clear'))
        self.legacy.refresh_from_db()
        self.assertEqual(self.legacy.details, 'Historical A details')
        self.assertIsNone(self.legacy.company_id)
        self.assertFalse(AuditLog.objects.filter(pk=self.captured.pk).exists())
