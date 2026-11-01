"""Backend security behavior at HTTP, command and persistent-state interfaces."""
from unittest.mock import patch
import io
from hashlib import sha256
import subprocess
import os
import shutil
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core.checks import run_checks, Tags
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command, CommandError
from django.db import connection
from django.test import TestCase, SimpleTestCase, Client, override_settings
from django.urls import reverse

from front.models import Alert, Company, CompanyEngine, Engine, EngineModel, ObfuscationConfig, Profile, Rule, RulesGroup
from PIL import Image
from cryptography.fernet import Fernet
from front.encryption import encrypt_value, decrypt_value, EncryptionError


class PublicTemplateKeyTests(TestCase):
    def test_original_public_key_fingerprints_remain_blocked(self):
        from front.checks import PUBLIC_KEY_HASHES
        self.assertEqual(PUBLIC_KEY_HASHES, {
            'SECRET_KEY': 'aef52ed18752c7b7f0e97f6e0debb70bee30f70471a454d52d19512602a2a980',
            'ENCRYPTION_KEY': '72766c4f5dfbb6080b34186f85c1127883648d1b07aa512e12382bcc9257b7dd',
        })

    def test_known_public_keys_are_rejected_without_disclosing_values(self):
        from front.checks import PUBLIC_KEY_HASHES
        # Exercise real hashing, settings and rotation without Git history or
        # redistributing the old template secrets in source archives.
        keys = {'SECRET_KEY': 'synthetic-public-template-key-for-tests-only',
                'ENCRYPTION_KEY': Fernet.generate_key().decode()}
        self.enterContext(patch.dict(PUBLIC_KEY_HASHES,
            {name: sha256(key.encode()).hexdigest() for name, key in keys.items()}))
        for name, key in keys.items():
            for option in (name, name + '_FALLBACKS'):
                with self.subTest(setting=option), override_settings(**{option: [key] if option.endswith('_FALLBACKS') else key}):
                    errors = [item for item in run_checks(tags=[Tags.security]) if item.id == 'front.E001']
                    self.assertEqual(len(errors), 1)
                    self.assertTrue(all(key not in str(item) for item in errors))
                    if option == 'ENCRYPTION_KEY':
                        with self.assertRaises(CommandError) as failure:
                            call_command('reencrypt_secrets', stdout=io.StringIO())
                        self.assertIn('rotation target must not be a public template key', str(failure.exception))


class SecretRotationTests(TestCase):
    def test_fallback_decrypts_old_values_and_new_writes_use_primary(self):
        old, new = Fernet.generate_key(), Fernet.generate_key()
        with override_settings(ENCRYPTION_KEY=old, ENCRYPTION_KEY_FALLBACKS=[]):
            previous = encrypt_value('synthetic credential')
        with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[old]):
            self.assertEqual(decrypt_value(previous), 'synthetic credential')
            current = encrypt_value('synthetic fresh credential')
        with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[]):
            self.assertEqual(decrypt_value(current), 'synthetic fresh credential')
            with self.assertRaises(EncryptionError):
                decrypt_value(previous)

    def test_command_rotates_all_encrypted_fields_with_dry_run_and_small_batches(self):
        old, new = Fernet.generate_key(), Fernet.generate_key()
        with override_settings(ENCRYPTION_KEY=old, ENCRYPTION_KEY_FALLBACKS=[]):
            company = Company.objects.create(name='Rotation company', jev_api_key='synthetic jev')
            engine = Engine.objects.create(name='Rotation engine')
            credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic provider')
        with connection.cursor() as cursor:
            cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
            original = cursor.fetchone()[0]
        with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[old]):
            output = io.StringIO()
            call_command('reencrypt_secrets', dry_run=True, batch_size=1, stdout=output)
            with connection.cursor() as cursor:
                cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
                self.assertEqual(cursor.fetchone()[0], original)
            call_command('reencrypt_secrets', batch_size=1, stdout=output)
            self.assertNotIn('synthetic jev', output.getvalue())
            self.assertNotIn('synthetic provider', output.getvalue())
        with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[]):
            company.refresh_from_db()
            credential.refresh_from_db()
            self.assertEqual(company.jev_api_key, 'synthetic jev')
            self.assertEqual(credential.api_key, 'synthetic provider')

    def test_invalid_ciphertext_rolls_back_every_changed_row(self):
        old, new = Fernet.generate_key(), Fernet.generate_key()
        with override_settings(ENCRYPTION_KEY=old, ENCRYPTION_KEY_FALLBACKS=[]):
            company = Company.objects.create(name='Invalid rotation company', jev_api_key='synthetic jev')
            engine = Engine.objects.create(name='Invalid rotation engine')
            credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic provider')
        with connection.cursor() as cursor:
            cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
            original = cursor.fetchone()[0]
            cursor.execute('UPDATE front_companyengine SET api_key=%s WHERE id=%s', ['invalid synthetic ciphertext', credential.pk])
        with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[old]):
            with self.assertRaises(CommandError) as failure:
                call_command('reencrypt_secrets', batch_size=1, stdout=io.StringIO())
            self.assertIn('no changes were saved', str(failure.exception))
            self.assertNotIn('invalid synthetic ciphertext', str(failure.exception))
        with connection.cursor() as cursor:
            cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
            self.assertEqual(cursor.fetchone()[0], original)

    def test_skipped_compare_and_swap_update_aborts_and_rolls_back(self):
        if connection.vendor != 'sqlite':
            self.skipTest('SQLite trigger supplies deterministic concurrent-update boundary.')
        old, new = Fernet.generate_key(), Fernet.generate_key()
        with override_settings(ENCRYPTION_KEY=old, ENCRYPTION_KEY_FALLBACKS=[]):
            company = Company.objects.create(name='Concurrent rotation company', jev_api_key='synthetic jev')
            engine = Engine.objects.create(name='Concurrent rotation engine')
            CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic provider')
        with connection.cursor() as cursor:
            cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
            original = cursor.fetchone()[0]
            cursor.execute('CREATE TRIGGER refuse_rotation BEFORE UPDATE OF api_key ON front_companyengine '
                'BEGIN SELECT RAISE(IGNORE); END;')
        try:
            with override_settings(ENCRYPTION_KEY=new, ENCRYPTION_KEY_FALLBACKS=[old]):
                with self.assertRaises(CommandError) as failure:
                    call_command('reencrypt_secrets', batch_size=1, stdout=io.StringIO())
                self.assertIn('Credentials changed concurrently', str(failure.exception))
            with connection.cursor() as cursor:
                cursor.execute('SELECT jev_api_key FROM front_company WHERE id=%s', [company.pk])
                self.assertEqual(cursor.fetchone()[0], original)
        finally:
            with connection.cursor() as cursor:
                cursor.execute('DROP TRIGGER refuse_rotation')


class LocalBootstrapTests(SimpleTestCase):
    def test_settings_creation_is_restricted_and_existing_file_is_preserved(self):
        source = Path(__file__).resolve().parents[2] / 'scripts/bootstrap_local.py'
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'regulai/regulai').mkdir(parents=True)
            script = root / 'scripts/bootstrap_local.py'
            shutil.copyfile(source, script)
            subprocess.run([sys.executable, str(script)], check=True, capture_output=True)
            created = root / 'regulai/regulai/local_settings.py'
            original = created.read_bytes()
            if os.name == 'nt':
                acl = subprocess.check_output(['icacls', str(created)], text=True)
                self.assertNotIn('(I)', acl)
            else:
                self.assertEqual(created.stat().st_mode & 0o777, 0o600)
            subprocess.run([sys.executable, str(script)], check=True, capture_output=True)
            self.assertTrue(created.read_bytes() == original)


class BackendHardeningTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Security tenant A')
        self.other = Company.objects.create(name='Security tenant B')
        self.staff = User.objects.create_user('security-staff', is_staff=True)
        self.employee = User.objects.create_user('security-employee')
        self.operator = User.objects.create_user('security-operator', is_staff=True, is_superuser=True)
        self.admin = User.objects.create_user('security-admin', is_superuser=True)
        for user in (self.staff, self.employee, self.operator, self.admin):
            Profile.objects.create(user=user, company=self.company)
        self.group = RulesGroup.objects.create(name='Security rules A', company=self.company)
        self.rule = Rule.objects.create(name='LOCAL_SECURITY_RULE', rules_group=self.group,
            yara_rule='rule Local { condition: true }')
        group = RulesGroup.objects.create(name='Security rules B', company=self.other)
        self.foreign_rule = Rule.objects.create(name='FOREIGN_SECURITY_RULE', rules_group=group,
            yara_rule='rule Foreign { condition: true }')
        Alert.objects.create(company=self.company, rule=self.rule, description='LOCAL_ALERT')
        Alert.objects.create(company=self.other, rule=self.foreign_rule, description='FOREIGN_ALERT')
        self.client.force_login(self.staff)

    def test_notifications_show_only_company_alerts_to_security_staff(self):
        response = self.client.get('/chat/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['unresolved_alerts_count'], 1)
        self.assertContains(response, 'LOCAL_SECURITY_RULE')
        self.assertNotContains(response, 'FOREIGN_SECURITY_RULE')

    def test_employee_cannot_read_notifications_even_inside_own_company(self):
        self.client.force_login(self.employee)
        response = self.client.get('/chat/')
        self.assertEqual(response.context['unresolved_alerts_count'], 0)
        self.assertEqual(list(response.context['recent_unresolved_alerts']), [])
        self.assertNotContains(response, 'LOCAL_SECURITY_RULE')

    def test_global_model_mutations_require_post_and_csrf(self):
        engine = Engine.objects.create(name='Security global engine')
        model = EngineModel.objects.create(engine=engine, name='Security model', model_id='security-model')
        self.client.force_login(self.operator)
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.operator)
        with override_settings(PLATFORM_ADMIN_USER_IDS=[self.operator.pk]):
            for action in ('model_toggle', 'model_delete'):
                with self.subTest(action=action):
                    url = reverse('front:' + action, args=[model.pk])
                    self.assertEqual(self.client.get(url).status_code, 405)
                    model.refresh_from_db()
                    self.assertTrue(model.active)
                    self.assertEqual(secure.post(url).status_code, 403)
            toggled = self.client.post(reverse('front:model_toggle', args=[model.pk]))
            self.assertEqual(toggled.status_code, 302)
            model.refresh_from_db()
            self.assertFalse(model.active)
            self.assertEqual(self.client.post(reverse('front:model_delete', args=[model.pk])).status_code, 302)
            self.assertFalse(EngineModel.objects.filter(pk=model.pk).exists())

    def test_obfuscation_toggle_requires_post_csrf_and_company_ownership(self):
        config = ObfuscationConfig.objects.create(company=self.company, name='Synthetic mask',
            api_url='https://mask.invalid', active=True)
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.staff)
        url = reverse('front:obfuscation_toggle', args=[config.pk])
        self.assertEqual(secure.get(url).status_code, 405)
        self.assertEqual(secure.post(url).status_code, 403)
        config.refresh_from_db()
        self.assertTrue(config.active)
        listing = secure.get(reverse('front:obfuscation_list'))
        self.assertContains(listing, f'<form method="post" action="{url}"')
        self.assertContains(listing, 'name="csrfmiddlewaretoken"')
        token = secure.cookies[settings.CSRF_COOKIE_NAME].value
        self.assertEqual(secure.post(url, {'csrfmiddlewaretoken': token}).status_code, 302)
        config.refresh_from_db()
        self.assertFalse(config.active)
        foreign = Company.objects.create(name='Foreign mask company')
        other = ObfuscationConfig.objects.create(company=foreign, name='Other synthetic mask',
            api_url='https://mask.invalid', active=True)
        self.assertEqual(secure.post(reverse('front:obfuscation_toggle', args=[other.pk]),
            {'csrfmiddlewaretoken': token}).status_code, 404)
        other.refresh_from_db()
        self.assertTrue(other.active)

    def test_community_sync_requires_platform_operator_and_post(self):
        self.client.force_login(self.admin)
        url = reverse('front:rules_community_sync')
        with patch('requests.get') as network:
            network.return_value.json.return_value = []
            self.assertEqual(self.client.post(url).status_code, 403)
            network.assert_not_called()
            self.client.force_login(self.operator)
            with override_settings(PLATFORM_ADMIN_USER_IDS=[self.operator.pk]):
                self.assertEqual(self.client.get(url).status_code, 405)
                network.assert_not_called()
                self.assertEqual(self.client.post(url).status_code, 200)
        self.assertEqual(network.call_count, 1)

    def test_yara_includes_are_disabled_for_creation_and_editing(self):
        with TemporaryDirectory() as directory:
            include = Path(directory) / 'synthetic.yar'
            include.write_text('rule Included { condition: true }', encoding='utf-8')
            source = f'include "{include.as_posix()}"\nrule Submitted {{ condition: true }}'
            data = {'name': 'Submitted', 'yara_rule': source, 'rules_group': self.group.pk}
            for url in (reverse('front:rule_create'), reverse('front:rule_edit', args=[self.rule.pk])):
                with self.subTest(url=url):
                    result = self.client.post(url, data)
                    self.assertEqual(result.status_code, 200)
                    self.assertEqual([str(message) for message in get_messages(result.wsgi_request)],
                        ['Invalid YARA rule; compilation failed.'])
            self.rule.refresh_from_db()
            self.assertNotIn('include', self.rule.yara_rule)
            self.assertFalse(Rule.objects.filter(name='Submitted').exists())

    def test_api_avatar_rejects_large_valid_images_and_accepts_small_ones(self):
        self.client.force_login(self.admin)
        profile = self.admin.profile
        image = io.BytesIO()
        Image.new('RGB', (1, 1)).save(image, format='PNG')
        with TemporaryDirectory() as directory, override_settings(MEDIA_ROOT=directory):
            url = reverse('api:profile-detail', args=[profile.pk])
            from rest_framework.test import APIClient
            client = APIClient()
            client.force_login(self.admin)
            rejected = client.patch(url, {'avatar': SimpleUploadedFile('large.png',
                image.getvalue() + b'\0' * (5 * 1024 * 1024), content_type='image/png')}, format='multipart')
            self.assertEqual(rejected.status_code, 400)
            profile.refresh_from_db()
            self.assertFalse(profile.avatar)
            accepted = client.patch(url, {'avatar': SimpleUploadedFile('small.png', image.getvalue(),
                content_type='image/png')}, format='multipart')
            self.assertEqual(accepted.status_code, 200)
            self.assertTrue(accepted.data['avatar'])

    def test_rule_mutations_require_post_and_do_not_modify_on_get(self):
        global_group = RulesGroup.objects.create(name='Global security rules')
        global_rule = Rule.objects.create(name='Global synthetic rule', rules_group=global_group,
            yara_rule='rule Global { condition: true }')
        actions = [('rule_toggle', self.rule.pk), ('rule_community_activate', self.rule.pk),
            ('rule_community_configure', global_rule.pk)]
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.staff)
        self.rule.active = False
        self.rule.save()
        for action, pk in actions:
            with self.subTest(action=action):
                url = reverse('front:' + action, args=[pk])
                self.assertEqual(self.client.get(url).status_code, 405)
                self.rule.refresh_from_db()
                self.assertFalse(self.rule.active)
                self.assertFalse(Rule.objects.filter(rules_group=self.group, name=global_rule.name).exists())
                self.assertEqual(secure.post(url).status_code, 403)

    def test_engine_toggle_and_alert_resolve_require_post(self):
        engine = Engine.objects.create(name='Security company engine')
        credential = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic')
        self.client.force_login(self.admin)
        alert = Alert.objects.get(company=self.company)
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.admin)
        for action, pk in [('engine_toggle', credential.pk), ('alert_resolve', alert.pk)]:
            with self.subTest(action=action):
                url = reverse('front:' + action, args=[pk])
                self.assertEqual(self.client.get(url).status_code, 405)
                self.assertEqual(secure.post(url).status_code, 403)
        credential.refresh_from_db()
        alert.refresh_from_db()
        self.assertTrue(credential.active)
        self.assertFalse(alert.resolved)
        self.assertEqual(self.client.post(reverse('front:engine_toggle', args=[credential.pk])).status_code, 302)
        self.assertEqual(self.client.post(reverse('front:alert_resolve', args=[alert.pk])).status_code, 302)

    def test_alert_unresolve_requires_post_csrf_and_preserves_get_state(self):
        alert = Alert.objects.get(company=self.company)
        alert.resolved = True
        alert.save()
        url = reverse('front:alert_unresolve', args=[alert.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.staff)
        self.assertEqual(secure.post(url).status_code, 403)
        self.assertEqual(self.client.post(url).status_code, 302)
        alert.refresh_from_db()
        self.assertFalse(alert.resolved)
