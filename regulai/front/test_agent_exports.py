"""Real MCP protocol and PostgreSQL ledger; simulated external Drive effects."""
from datetime import timedelta
import json
import hashlib
import uuid
from unittest.mock import patch
from asgiref.sync import async_to_sync
import httpx
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from front.agents import jobs, exports, document_mcp as mcp
from front.agents.service import AgentDenied
from front.models import AgentExport, AgentDocumentConnection, AgentExecution, Profile, Company
from front.test_agent_mcp import DriveFixture
from front.test_agent_chat import ChatFixture


class ExportDriveFixture(DriveFixture):
    def __init__(self):
        super().__init__()
        self.files, self.uploads, self.reservations = {}, 0, 0
        self.timeout_after_write, self.ambiguous_missing = False, False

    def __call__(self, request):
        if request.url.path.endswith('/files/generateIds'):
            self.reservations += 1
            return httpx.Response(200, json={'ids': ['reserved-' + str(self.reservations)]})
        if request.url.path.endswith('/files/export-folder'):
            if self.revoked:
                return httpx.Response(403)
            return httpx.Response(200, json={'id': 'export-folder', 'mimeType': 'application/vnd.google-apps.folder',
                'trashed': False, 'capabilities': {'canAddChildren': True}})
        if request.method == 'POST':
            assert request.url.host == 'www.googleapis.com'
            assert request.url.path == '/upload/drive/v3/files'
            self.uploads += 1
            boundary = request.headers['Content-Type'].split('boundary=')[1].encode()
            parts = request.content.split(b'--' + boundary)
            metadata = json.loads(parts[1].split(b'\r\n\r\n', 1)[1].removesuffix(b'\r\n'))
            content = parts[2].split(b'\r\n\r\n', 1)[1].removesuffix(b'\r\n')
            key = metadata['id']
            if not self.ambiguous_missing:
                assert key not in self.files, 'Duplicate fixture creation'
                self.files[key] = (metadata, content)
            if self.timeout_after_write or self.ambiguous_missing:
                raise httpx.ReadTimeout('Sensitive provider body must never escape', request=request)
            return httpx.Response(200, json={'id': key})
        key = request.url.path.rsplit('/', 1)[-1]
        if key.startswith('reserved-'):
            if key not in self.files:
                return httpx.Response(404)
            metadata, content = self.files[key]
            if request.url.params.get('alt') == 'media':
                return httpx.Response(200, content=content)
            return httpx.Response(200, json={'id': key, 'parents': metadata['parents'],
                'trashed': False, 'appProperties': metadata['appProperties']})
        return super().__call__(request)


class ExportFixture(ChatFixture):
    def setUp(self):
        super().setUp()
        self.agent.tools += ['save_revision']
        self.agent.save()
        self.enterContext(override_settings(REGULAY_AGENT_MCP_ENABLED=True, REGULAY_AGENT_MCP_WRITES_ENABLED=True))
        self.document_connection = AgentDocumentConnection.objects.create(user=self.user, company=self.company,
            enabled=True, write_enabled=True, expires_at=timezone.now() + timedelta(hours=1),
            private_config=json.dumps({'token': 'synthetic-private-token', 'identity': 'person-one',
                'folders': ['folder-one'], 'write_folder': 'export-folder',
                'account_label': 'synthetic@example.invalid', 'folder_label': 'Informes de laboratorio'}))
        self.remote = ExportDriveFixture()
        self.enterContext(patch.object(mcp, 'call', side_effect=lambda private, operation, args:
            async_to_sync(mcp._call)(private, operation, args, transport=httpx.MockTransport(self.remote))))

    def prepared(self, url='/chat/send/'):
        initial = self.queued()
        token, attempt = self.claimed(initial)
        artifact = self.publish(initial, token, attempt, self.issue(initial, token, attempt))
        if url == '/chat/send/':
            url = f'/chat/{initial.conversation_id}/send/'
        elif url == '/chat/':
            url = f'/chat/{initial.conversation_id}/'
        response = self.send(url=url, file=False, conversation=initial.conversation,
            artifact_id=str(artifact.logical_id), base_revision=str(artifact.pk), export_name='informe.xlsx')
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        token, attempt = self.claimed(run)
        call = {'id': 'save-' + uuid.uuid4().hex, 'name': 'save_revision', 'args': {
            'artifact_reference': str(artifact.pk), 'sha256': artifact.sha256, 'name': 'informe.xlsx'}}
        self.reply_calls = [call]
        from front.agents.service import infer
        reply = infer(token, attempt, {'call_id': str(uuid.uuid4()),
            'messages': [{'role': 'user', 'content': 'Guardar revisión'}], 'tools': ['save_revision']})
        self.assertEqual(reply['status'], 'completed', reply)
        exports.propose(token, attempt, call)
        return run, token, attempt, call

    def approve(self, run):
        row = AgentExport.objects.get(execution=run)
        return exports.decide(self.user, row.pk, {'binding': row.binding, 'decision': 'approve'})


@override_settings(REGULAY_AGENT_ENABLED=True)
class ApprovedExportTests(ExportFixture, TestCase):
    def test_three_send_entries_checkpoint_payload_approval_and_duplicate_resume(self):
        for url in ('/chat/send/', '/chat/', '/api/chat/send/'):
            run, token, attempt, call = self.prepared(url)
            data = jobs.bootstrap(token, attempt, {})
            self.assertNotIn('base64', data)
            self.assertNotIn('export-folder', json.dumps(data))
            with self.assertRaises(AgentDenied):
                exports.execute(token, attempt, call)
            self.approve(run)
            self.approve(run)
            first = exports.execute(token, attempt, call)
            self.assertEqual(first['status'], 'approved')
            self.assertEqual(first, exports.execute(token, attempt, call))
            row = AgentExport.objects.get(execution=run)
            self.assertEqual(row.status, 'completed')
            self.assertIsNotNone(row.intent_at)
            self.assertIsNotNone(row.finished_at)
            exports.complete(token, attempt, {})
            run.prompt.refresh_from_db()
            self.assertEqual(run.prompt.decision['verification']['status'], 'passed')
            self.assertEqual(run.prompt.decision['verification']['export_reference'], str(row.pk))
        self.assertEqual(self.remote.uploads, 3)

    def test_timeout_after_effect_reconciles_without_second_creation(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        self.remote.timeout_after_write = True
        result = exports.execute(token, attempt, call)
        self.assertEqual(result['status'], 'withheld')
        self.assertEqual(AgentExport.objects.get(execution=run).status, 'uncertain')
        self.assertEqual(exports.execute(token, attempt, call)['status'], 'approved')
        self.assertEqual(self.remote.uploads, 1)
        self.assertEqual(len(self.remote.files), 1)

    def test_missing_after_ambiguous_timeout_never_blindly_retries(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        self.remote.ambiguous_missing = True
        exports.execute(token, attempt, call)
        for _ in range(3):
            self.assertEqual(exports.execute(token, attempt, call)['status'], 'withheld')
        self.assertEqual(self.remote.uploads, 1)

    def test_changed_bytes_name_scope_or_expiry_invalidates_approval(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        from front.models import AgentArtifact
        original = run.job.copy()
        run.job['export_name'] = 'changed.xlsx'
        run.save()
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        run.job = original
        run.save()
        self.document_connection.version += 1
        self.document_connection.save()
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        self.assertEqual(self.remote.uploads, 0)

    def test_expired_approval_and_tampered_bytes_are_rejected(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        AgentExport.objects.filter(execution=run).update(expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        AgentExport.objects.filter(execution=run).update(expires_at=timezone.now() + timedelta(minutes=1))
        from front.models import AgentArtifact
        AgentArtifact.objects.filter(pk=run.export.artifact_id).update(content='dGFtcGVyZWQ=')
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        self.assertEqual(self.remote.uploads, 0)

    def test_rejection_is_durable_and_cannot_be_reapproved(self):
        run, token, attempt, call = self.prepared()
        row = run.export
        exports.decide(self.user, row.pk, {'binding': row.binding, 'decision': 'reject'})
        with self.assertRaises(AgentDenied):
            self.approve(run)
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        self.assertEqual(self.remote.uploads, 0)

    def test_checkpoint_retention_endpoint_is_executor_only(self):
        run, _, _, _ = self.prepared()
        url = '/internal/agents/checkpoints/'
        self.assertEqual(self.client.post(url, '{}', content_type='application/json').status_code, 403)
        def refs():
            response = self.client.post(url, '{}', content_type='application/json',
                HTTP_AUTHORIZATION='Bearer ' + self.worker_token)
            self.assertEqual(response.status_code, 200)
            return response.json()['keep']
        self.assertIn(str(run.pk), refs())
        run.conversation.delete()
        self.assertNotIn(str(run.pk), refs())

    def test_revocation_cancellation_foreign_actor_and_expiration_stop_effect(self):
        run, token, attempt, call = self.prepared()
        row = AgentExport.objects.get(execution=run)
        from django.contrib.auth.models import User
        other = User.objects.create_user('agent-synthetic-export-other')
        Profile.objects.create(user=other, company=Company.objects.create(name='Other export company'))
        with self.assertRaises(AgentDenied):
            exports.decide(other, row.pk, {'binding': row.binding, 'decision': 'approve'})
        self.approve(run)
        self.remote.revoked = True
        self.assertEqual(exports.execute(token, attempt, call)['status'], 'withheld')
        self.assertEqual(self.remote.uploads, 0)
        jobs.cancel(self.user, run.pk)
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)

    def test_worker_lease_loss_can_only_recover_checkpoint_and_intent(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        self.remote.timeout_after_write = True
        exports.execute(token, attempt, call)
        AgentExecution.objects.filter(pk=run.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        jobs.reap()
        run.refresh_from_db()
        self.assertEqual(run.status, 'queued')
        with self.assertRaises(AgentDenied):
            exports.execute(token, attempt, call)
        token2, attempt2 = self.claimed(run)
        self.assertNotEqual(str(attempt), str(attempt2))
        self.assertEqual(exports.reconcile(token2, attempt2, {})['status'], 'approved')
        exports.complete(token2, attempt2, {})
        self.assertEqual(self.remote.uploads, 1)

    def test_disabling_mode_keeps_authorized_history_and_download(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        artifact = self.publish(run, token, attempt, self.issue(run, token, attempt))
        with override_settings(REGULAY_AGENT_ENABLED=False):
            self.assertEqual(self.send().status_code, 403)
            self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/').status_code, 200)
            self.assertEqual(self.client.get(f'/chat/agent/runs/{run.pk}/').status_code, 200)

    def test_retention_deletes_export_ledger_with_conversation(self):
        run, token, attempt, call = self.prepared()
        self.approve(run)
        exports.execute(token, attempt, call)
        pk = run.export.pk
        run.conversation.delete()
        self.assertFalse(AgentExport.objects.filter(pk=pk).exists())
        self.assertEqual(len(self.remote.files), 1)  # No unauthorized remote deletion.


@override_settings(REGULAY_AGENT_ENABLED=True)
class ExportConcurrencyTests(ExportFixture, TransactionTestCase):
    def test_overlapping_resumes_create_once(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from django.db import close_old_connections
        run, token, attempt, call = self.prepared()
        self.approve(run)
        entered, release = Event(), Event()
        real_call = mcp.call
        def delayed(private, operation, args):
            if operation == 'save_revision':
                entered.set()
                if not release.wait(15):
                    raise AssertionError('Concurrent test release missing')
            return real_call(private, operation, args)
        def execute():
            close_old_connections()
            try:
                return exports.execute(token, attempt, call)
            finally:
                close_old_connections()
        with patch.object(mcp, 'call', side_effect=delayed), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(execute)
            self.assertTrue(entered.wait(15))
            second = pool.submit(execute)
            self.assertEqual(second.result(timeout=15)['status'], 'withheld')
            release.set()
            self.assertEqual(first.result(timeout=15)['status'], 'approved')
        self.assertEqual(self.remote.uploads, 1)
        self.assertEqual(AgentExport.objects.get(execution=run).status, 'completed')


class ApprovedExportMigrationTests(TransactionTestCase):
    def test_0040_preserves_readonly_grant_without_enabling_writes_and_rolls_back(self):
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor
        previous = [('front', '0039_agent_document_connector')]
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        try:
            executor.migrate(previous)
            apps = executor.loader.project_state(previous).apps
            user = apps.get_model('auth','User').objects.create(username='existing-export-migration')
            company = apps.get_model('front','Company').objects.create(name='Keep export migration')
            private = json.dumps({'token':'synthetic-migration-token','identity':'synthetic','folders':['folder']})
            grant = apps.get_model('front','AgentDocumentConnection').objects.create(user_id=user.pk,
                company_id=company.pk,enabled=True,expires_at=timezone.now()+timedelta(hours=1),private_config=private)
            MigrationExecutor(connection).migrate(latest)
            preserved = AgentDocumentConnection.objects.get(pk=grant.pk)
            self.assertFalse(preserved.write_enabled)
            self.assertEqual(preserved.private_config,private)
            self.assertFalse(AgentExport.objects.exists())
            MigrationExecutor(connection).migrate(previous)
            self.assertEqual(apps.get_model('front','AgentDocumentConnection').objects.get(pk=grant.pk).private_config,private)
        finally:
            MigrationExecutor(connection).migrate(latest)
