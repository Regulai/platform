"""P1 package, PostgreSQL lifecycle and account boundaries. No provider or VM."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import io
import json
import stat
from threading import Barrier
import uuid
import zipfile
from unittest.mock import patch

from django.contrib.auth.models import User
from django.db import close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from front.models import (AgentAccessGrant, AgentSkillInstallation, AgentSkillRevision,
    AgentSkillInstallOperation, Profile, Company, AgentInput, Prompt)
from front.agents import skill_installation as install, skills
from front.agents.skill_bundles import SkillError, validate_bundle, revision_files
from front.test_agent_inference import AgentFixture


def bundle(asset=b'first', name='sample-skill', extra=None):
    files = {f'{name}/SKILL.md': (f'---\nname: {name}\ndescription: Synthetic test instructions.\n---\n'
        '# Test\nRead [resource](references/data.txt).\n').encode(), f'{name}/LICENSE.txt': b'MIT synthetic test license',
        f'{name}/references/data.txt': asset, f'{name}/assets/icon.bin': b'\x00\xff'}
    files.update(extra or {})
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, raw in files.items():
            archive.writestr(zipfile.ZipInfo(path, (2026, 10, 16, 0, 0, 0)), raw, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


class BundleTests(SimpleTestCase):
    def test_every_curated_folder_is_complete_and_includes_all_license_notices(self):
        for item in skills.catalogue():
            with self.subTest(candidate=item['id']):
                raw, _ = skills.curated_bundle(item['id'])
                package = validate_bundle(raw)
                self.assertEqual(package['metadata']['name'], item['directory'])
                self.assertTrue(package['license'])
                self.assertTrue(package['attribution'])
                self.assertEqual(package['folder_sha256'], item['folder_sha256'])
                if item['id'] == 'web-design-guidelines':
                    self.assertIn('Business Source License', package['license'])
                    self.assertIn('MIT', package['license'])

    def test_complete_package_resources_and_asset_changes_change_digest(self):
        first, second = validate_bundle(bundle()), validate_bundle(bundle(b'second'))
        self.assertEqual(first['metadata'], second['metadata'])
        self.assertNotEqual(first['folder_sha256'], second['folder_sha256'])
        self.assertEqual(first['files']['assets/icon.bin'], b'\x00\xff')

    def test_hostile_paths_links_duplicates_unicode_zip_bombs_and_yaml(self):
        for path in ('../escape', '/absolute', 'C:/windows', 'x\\y', 'sample-skill/../x',
                     'sample-skill/CON', 'sample-skill/a\x00b'):
            with self.subTest(path=path):
                if '\x00' in path or '\\' in path:  # Windows zipfile normalizes paths before writing.
                    from front.agents.skill_bundles import valid_path
                    with self.assertRaises(SkillError): valid_path(path)
                else:
                    with self.assertRaises(SkillError): validate_bundle(bundle(extra={path: b'x'}))
        for extra in ({'sample-skill/ASSETS/icon.bin': b'x'}, {'sample-skill/bomb': b'x' * 1000000},
                      {'sample-skill/\u212a.txt': b'a', 'sample-skill/K.txt': b'b'}):
            with self.assertRaises(SkillError): validate_bundle(bundle(extra=extra))
        for header in ('name: sample-skill\nname: other', 'name: &x sample-skill\ndescription: *x',
                       'name: !!python/object:builtins.str anything'):
            with self.assertRaises(SkillError):
                validate_bundle(bundle(extra={'sample-skill/SKILL.md': ('---\n' + header + '\n---\nText').encode()}))
        output = io.BytesIO(bundle())
        with zipfile.ZipFile(output, 'a') as archive:
            entry = zipfile.ZipInfo('sample-skill/link')
            entry.create_system, entry.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, '/etc/passwd')
        with self.assertRaises(SkillError): validate_bundle(output.getvalue())


class SkillFixture(AgentFixture):
    def setUp(self):
        super().setUp()
        self.agent.professional, self.agent.tools = True, ['read_file', 'write_file', 'publish_artifact']
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.client.force_login(self.user)

    def install(self, raw=None, key=None, **kwargs):
        return install.install(self.user, key or uuid.uuid4(), {'source': 'zip', **kwargs}, raw=raw or bundle())


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True)
class InstallationTests(SkillFixture, TestCase):
    def test_import_detail_is_account_local_and_keeps_resources_after_update(self):
        result = self.install()
        url = '/skills/installations/' + result['installation_id'] + '/'
        first = self.client.get(url + '?format=json')
        self.assertEqual(first.status_code, 200)
        self.assertIn('assets/icon.bin', [entry['path'] for entry in first.json()['manifest']])
        self.assertEqual(self.client.get(url).status_code, 200)
        changed = install.install(self.user, uuid.uuid4(), {'source': 'zip'}, raw=bundle(b'changed'),
            installation_id=result['installation_id'])
        self.assertEqual(changed['state'], 'installed')
        self.assertNotEqual(first.json()['folder_sha256'], self.client.get(url + '?format=json').json()['folder_sha256'])
        self.assertFalse(self.requests)

    def test_install_replay_full_bytes_update_rollback_and_revocation(self):
        key = uuid.uuid4()
        first = self.install(key=key)
        self.assertEqual(first['state'], 'installed', first)
        self.assertEqual(first, self.install(key=key))
        row = AgentSkillInstallation.objects.get(pk=first['installation_id'])
        self.assertTrue(row.enabled)
        self.assertEqual(revision_files(row.current_revision)['references/data.txt'], b'first')
        old = row.current_revision_id
        changed = install.install(self.user, uuid.uuid4(), {'source': 'zip'}, raw=bundle(b'second'), installation_id=row.pk)
        self.assertEqual(changed['state'], 'installed', changed)
        row.refresh_from_db()
        self.assertEqual(row.previous_revision_id, old)
        version = row.authorization_version
        install.change(self.user, row.pk, 'rollback')
        row.refresh_from_db()
        self.assertEqual(row.current_revision_id, old)
        self.assertEqual(row.authorization_version, version)
        install.change(self.user, row.pk, 'enabled', enabled=False)
        row.refresh_from_db()
        self.assertFalse(row.enabled)
        self.assertEqual(row.authorization_version, version + 1)
        install.change(self.user, row.pk, 'uninstall')
        self.assertEqual(AgentSkillRevision.objects.filter(installation=row).count(), 2)
        self.assertFalse(self.requests)

    def test_catalog_api_and_cross_account_reads_and_changes(self):
        result = self.client.post('/skills/installations/', json.dumps({'source':'catalog',
            'candidate':'frontend-design', 'request_id':str(uuid.uuid4())}), content_type='application/json')
        self.assertEqual(result.status_code, 200, result.content)
        row = AgentSkillInstallation.objects.get(pk=result.json()['installation_id'])
        self.assertIn('Apache', row.current_revision.license)
        self.assertEqual(self.client.get('/skills/?format=json').json()['installations'][0]['id'], str(row.pk))
        for company in (self.company, Company.objects.create(name='Other synthetic')):
            other = User.objects.create_user('other-' + uuid.uuid4().hex)
            Profile.objects.create(user=other, company=company)
            self.client.force_login(other)
            # No grant means no access even within the same company.
            self.assertEqual(self.client.get('/skills/operations/' + result.json()['id'] + '/').status_code, 403)
        self.assertFalse(self.requests)

    def test_failed_validation_has_no_partial_installation_or_model_call(self):
        result = self.install(raw=bundle(extra={'sample-skill/LICENSE.txt': b''}))
        self.assertEqual(result['state'], 'failed')
        self.assertEqual(result['code'], 'license_missing')
        self.assertFalse(AgentSkillInstallation.objects.exists())
        self.assertFalse(self.requests)

    def test_expired_claim_cannot_promote_and_request_conflict(self):
        original = install.validate_bundle
        def expire(*args, **kwargs):
            result = original(*args, **kwargs)
            AgentSkillInstallOperation.objects.update(claim=uuid.uuid4())
            return result
        key = uuid.uuid4()
        with patch.object(install, 'validate_bundle', side_effect=expire):
            result = self.install(key=key)
        self.assertFalse(AgentSkillInstallation.objects.exists())
        with self.assertRaisesMessage(SkillError, 'skill_request_conflict'):
            self.install(key=key, alias='different')
        AgentSkillInstallOperation.objects.update(lease_expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.install(key=key)['state'], 'installed')


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True)
class InstallationConcurrencyTests(SkillFixture, TransactionTestCase):
    def test_duplicate_concurrent_postgres_promotes_one_revision(self):
        self.assertEqual(connection.vendor, 'postgresql')
        barrier, key = Barrier(2), uuid.uuid4()
        def work(_):
            close_old_connections()
            try:
                actor = User.objects.get(pk=self.user.pk)
                barrier.wait(10)
                return install.install(actor, key, {'source':'zip'}, raw=bundle())
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(work, range(2)))
        self.assertEqual(AgentSkillInstallation.objects.count(), 1)
        self.assertEqual(AgentSkillRevision.objects.count(), 1)
        self.assertIn('installed', [r['state'] for r in results])
        self.assertEqual(self.install(key=key)['state'], 'installed')


class SkillMigrationTests(TransactionTestCase):
    def test_additive_p0_migration_keeps_private_inputs_and_grants(self):
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        old = [('front', '0042_agent_artifact_metadata')]
        try:
            executor = MigrationExecutor(connection)
            executor.migrate(old)
            apps = executor.loader.project_state(old).apps
            user = apps.get_model('auth','User').objects.create(username='existing-p1')
            company = apps.get_model('front','Company').objects.create(name='Existing', ai_config={'revision':1})
            conversation = apps.get_model('front','Conversation').objects.create(user_id=user.pk, title='Retained')
            prompt = apps.get_model('front','Prompt').objects.create(user_id=user.pk, company_id=company.pk,
                conversation_id=conversation.pk, content='Retained private text', decision={'total':{'known_cost':'0.031','complete':False}})
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(Prompt.objects.get(pk=prompt.pk).decision['total']['known_cost'], '0.031')
            self.assertFalse(AgentSkillInstallation.objects.exists())
            self.assertFalse(AgentAccessGrant.objects.exists())
            # Rollback is code/flags only: new revision bytes are deliberately not dropped.
        finally:
            MigrationExecutor(connection).migrate(latest)
