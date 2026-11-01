"""Independent adversarial checks of P1 package and installation boundaries."""
from unittest.mock import patch
import io
import json
import socket
import subprocess
import sys
from pathlib import Path
import uuid
import zipfile

import httpx

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, TestCase, TransactionTestCase, override_settings

from front.agents import skill_installation, skills
from front.agents import public_web, skill_sources
from front.agents.service import AgentDenied
from front.models import (AgentAccessGrant, AgentEvent, AgentSkillInstallation, AgentSkillRevision,
    Conversation, Profile)
from front.test_agent_skills_install import SkillFixture, bundle


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True)
class SkillsSecurityTests(SkillFixture, TestCase):
    def test_deactivation_during_validation_prevents_atomic_promotion(self):
        validate = skill_installation.validate_bundle
        def deactivate(*args, **kwargs):
            package = validate(*args, **kwargs)
            User.objects.filter(pk=self.user.pk).update(is_active=False)
            return package
        with patch.object(skill_installation, 'validate_bundle', side_effect=deactivate):
            try:
                result = self.install()
            except AgentDenied:
                result = {'state': 'failed'}
        self.assertNotEqual(result['state'], 'installed', 'An actor deactivated during validation still published a revision')
        self.assertFalse(AgentSkillInstallation.objects.exists())

    def test_imported_executable_outside_scripts_is_not_certified_ready(self):
        for path in ('sample-skill/run.py', 'sample-skill/tools/run.sh'):
            with self.subTest(path=path):
                result = self.install(raw=bundle(name='sample-skill', extra={path: b'import unavailable_package\n'}),
                    alias='case-' + uuid.uuid4().hex)
                self.assertEqual(result['state'], 'installed', result)
                installation = AgentSkillInstallation.objects.get(pk=result['installation_id'])
                availability = skills.availability(self.agent, installation.current_revision.compatibility)
                self.assertFalse(availability['runtime_ready'], 'Executable files outside scripts/ bypassed the unknown-runtime gate')
                self.assertFalse(installation.enabled)

    def test_authorized_other_account_cannot_read_operation_or_mutate_installation(self):
        result = self.install()
        other = User.objects.create_user('same-company-authorized-skill-review')
        Profile.objects.create(user=other, company=self.company)
        AgentAccessGrant.objects.create(company=self.company, user=other, profile=self.agent, enabled=True)
        self.client.force_login(other)
        library = self.client.get('/skills/?format=json')
        self.assertEqual(library.status_code, 200)
        self.assertEqual(library.json()['installations'], [])
        self.assertEqual(self.client.get('/skills/operations/' + result['id'] + '/').status_code, 404)
        self.assertEqual(self.client.post('/skills/installations/' + result['installation_id'] + '/uninstall/').status_code, 404)
        row = AgentSkillInstallation.objects.get(pk=result['installation_id'])
        self.assertIsNone(row.tombstoned_at)
        self.assertTrue(row.enabled)

    def test_csrf_rejects_install_before_creating_any_operation(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post('/skills/installations/', {'source': 'catalog', 'candidate': 'frontend-design',
                                                         'request_id': str(uuid.uuid4())})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AgentSkillInstallation.objects.exists())

    def test_simulation_candidate_is_complete_and_runtime_gated(self):
        result = skill_installation.install(self.user, uuid.uuid4(),
            {'source': 'catalog', 'candidate': 'regulai-simulation'})
        self.assertEqual(result['state'], 'installed', result)
        row = AgentSkillInstallation.objects.get(pk=result['installation_id'])
        self.assertFalse(row.enabled)
        self.assertEqual(row.current_revision.compatibility['runtime'], {'python': '3.12.11', 'numpy': '2.5.3'})
        self.assertEqual(row.current_revision.resolved_commit, '')
        from front.agents.skill_bundles import revision_files
        self.assertIn('scripts/random_walk.py', revision_files(row.current_revision))
        self.agent.tools.append('execute')
        self.agent.save()
        with override_settings(REGULAY_SKILL_RUNTIME_CAPABILITIES={'python': '3.12.11', 'numpy': '2.5.3'}):
            self.assertTrue(skills.availability(self.agent, row.current_revision.compatibility)['available'])

    def github(self, handler, *, dns=None, url='https://github.com/owner/repo/tree/main/skills/sample-skill'):
        self.company.ai_config['destinations']['internal'].append('research:packages')
        self.company.save()
        # An authenticated HTTP request loads a fresh actor after the policy update.
        self.user = User.objects.get(pk=self.user.pk)
        self.wire = []
        def http(request):
            self.wire.append({'method': request.method, 'host': request.headers.get('host'),
                'path': request.url.path, 'headers': dict(request.headers)})
            return handler(request)
        def fetch(url, **kwargs):
            return public_web.fetch(url, transport=httpx.MockTransport(http), **kwargs)
        with patch.object(skill_sources, 'fetch', side_effect=fetch), \
                patch.object(public_web.socket, 'getaddrinfo', return_value=dns or [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]), \
                patch('socket.create_connection', side_effect=AssertionError('External network forbidden')):
            return skill_installation.install(self.user, uuid.uuid4(), {'source': 'github', 'url': url})

    def test_github_resolves_and_pins_commit_without_credentials_or_model_calls(self):
        commit = 'a' * 40
        raw = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(bundle())) as source, zipfile.ZipFile(raw, 'w') as target:
            for name in source.namelist():
                target.writestr('repo-' + commit + '/skills/' + name, source.read(name))
        def provider(request):
            if request.headers['host'] == 'api.github.com':
                return httpx.Response(200, json={'sha': commit})
            self.assertEqual(request.headers['host'], 'codeload.github.com')
            self.assertTrue(request.url.path.endswith('/' + commit))
            return httpx.Response(200, content=raw.getvalue())
        result = self.github(provider)
        self.assertEqual(result['state'], 'installed', result)
        row = AgentSkillInstallation.objects.get(pk=result['installation_id'])
        self.assertEqual(row.current_revision.resolved_commit, commit)
        self.assertIn('/tree/' + commit + '/', row.current_revision.origin)
        self.assertEqual(row.source_identity, 'github:owner/repo/skills/sample-skill')
        self.assertEqual([request['host'] for request in self.wire], ['api.github.com', 'codeload.github.com'])
        for request in self.wire:
            self.assertEqual(request['method'], 'GET')
            self.assertNotIn('authorization', request['headers'])
            self.assertNotIn('cookie', request['headers'])
        self.assertFalse(self.requests)

    def test_github_cross_host_and_private_redirects_stop_before_second_http(self):
        for destination in ('https://example.org/payload.zip', 'http://169.254.169.254/latest/meta-data/'):
            with self.subTest(destination=destination):
                result = self.github(lambda request: httpx.Response(302, headers={'location': destination}))
                self.assertEqual(result['state'], 'failed', result)
                self.assertEqual(len(self.wire), 1)
                self.assertFalse(AgentSkillInstallation.objects.exists())
        self.assertFalse(self.requests)

    def test_github_mixed_public_private_dns_and_credential_url_never_open_http(self):
        forbidden = lambda request: self.fail('Forbidden source reached HTTP')
        result = self.github(forbidden, dns=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))])
        self.assertEqual(result['state'], 'failed', result)
        self.assertEqual(result['code'], 'web_address_denied')
        self.assertEqual(self.wire, [])
        result = self.github(forbidden, url='https://user:password@github.com/owner/repo/tree/main/skills/sample-skill')
        self.assertEqual(result['state'], 'failed', result)
        self.assertEqual(self.wire, [])
        self.assertFalse(self.requests)


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True)
class P0CodeRollbackTests(SkillFixture, TransactionTestCase):
    def test_frozen_p0_reads_and_writes_new_schema_without_dropping_p1_data(self):
        root = Path(__file__).resolve().parents[2]
        if not (root / 'output/p1-20261016/e1/frozen').is_dir():
            self.skipTest('Frozen E1 source must first be prepared and hash-verified with p1_baseline_run.py.')
        self.assertIn(connection.settings_dict['NAME'], ('test_regulai_p1_security', 'test_regulai_p1_integration'))
        result = self.install()
        self.assertEqual(result['state'], 'installed', result)
        revision = AgentSkillRevision.objects.get(pk=result['revision_id'])
        retained = (revision.bundle, revision.folder_sha256, revision.manifest)
        self.conversation.auto_skills = False
        self.conversation.save()
        self.prompt.decision = {'total': {'known_cost': '0.031', 'complete': False}}
        self.prompt.save()
        args = {'database': connection.settings_dict['NAME'], 'user': self.user.pk,
            'prompt': self.prompt.pk, 'asset': str(self.asset.pk), 'input': self.asset.original,
            'conversation': self.conversation.pk, 'execution': str(self.execution.pk)}
        with override_settings(REGULAY_SKILLS_CATALOG=False, REGULAY_SKILLS_RUNTIME=False,
                               REGULAY_AGENT_STREAM=False):
            process = subprocess.run(['rtk', 'proxy', sys.executable,
                str(root / 'ops/agent_chat/p1_p0_rollback_probe.py'), json.dumps(args)],
                cwd=root, capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        receipt = json.loads(process.stdout.strip().splitlines()[-1])
        self.assertTrue(Conversation.objects.get(pk=receipt['conversation_id']).auto_skills)
        event = AgentEvent.objects.get(pk=receipt['event_id'])
        self.assertIsNone(event.public_text)
        self.assertEqual(event.data, {'source': 'frozen_p0'})
        self.conversation.refresh_from_db()
        self.assertFalse(self.conversation.auto_skills)
        revision.refresh_from_db()
        self.assertEqual((revision.bundle, revision.folder_sha256, revision.manifest), retained)
        self.prompt.refresh_from_db()
        self.assertEqual(self.prompt.decision['total'], {'known_cost': '0.031', 'complete': False})
        self.assertFalse(self.requests)
