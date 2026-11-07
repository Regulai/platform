"""Task 50 state/HTTP/data boundaries. Workbook caches here are synthetic fixtures.

The real pandas/LibreOffice/E2B evidence is produced separately by ops/agent_chat.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import io
import json
from threading import Barrier
import uuid
from unittest.mock import patch
import zipfile
import xml.etree.ElementTree as ET
from asgiref.sync import sync_to_async

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings, AsyncClient
from django.utils import timezone
from openpyxl import Workbook

from front.agents import jobs
from front.agents.data_views import tool_result
from front.agents.service import AgentDenied, authenticate, infer
from front.models import AgentArtifact, AgentEvent, AgentExecution, Conversation, Prompt, Profile
from front.test_agent_inference import AgentFixture

CSV = b'item,amount_cents\nNombre: Private Synthetic Marker,125\n<script>alert(1)</script>,250\n=HYPERLINK("invalid"),375\n'


def candidate_bytes(title='Ventas sintéticas', corrupt=False, source=CSV):
    """Simulated cached workbook for boundary tests, never claimed as LO proof."""
    book = Workbook()
    sheet = book.active
    sheet.title = 'Resumen'
    sheet['A1'] = title
    sheet['A1'].data_type = 's'
    sheet.append([])
    for pos, value in {'A3': 'Concepto', 'B3': 'Importe (céntimos)', 'C3': 'Importe (€)'}.items():
        sheet[pos] = value
    from front.agents.excel_contract import input_rows
    for n, (name, amount) in enumerate(input_rows(source, 'csv'), 4):
        sheet.cell(n, 1, name).data_type = 's'
        sheet.cell(n, 2, amount)
        sheet.cell(n, 3, f'=B{n}/100')
    sheet['A7'], sheet['B7'], sheet['C7'] = 'Total', '=SUM(B4:B6)', '=B7/100'
    sheet.column_dimensions['A'].width = 42
    sheet.freeze_panes, sheet.auto_filter.ref = 'A4', 'A3:C6'
    buf = io.BytesIO()
    book.save(buf)
    ns = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
    result = io.BytesIO()
    with zipfile.ZipFile(buf) as source, zipfile.ZipFile(result, 'w', zipfile.ZIP_DEFLATED) as output:
        for item in source.infolist():
            data = source.read(item)
            if item.filename == 'xl/worksheets/sheet1.xml':
                tree = ET.fromstring(data)
                for cell in tree.iter(ns + 'c'):
                    values = {'C4': '1.25', 'C5': '2.5', 'C6': '3.75', 'B7': '999' if corrupt else '750', 'C7': '7.5'}
                    if cell.attrib['r'] in values:
                        cell.find(ns + 'v').text = values[cell.attrib['r']]
                data = ET.tostring(tree)
            output.writestr(item, data)
    return result.getvalue()


class ChatFixture(AgentFixture):
    def setUp(self):
        super().setUp()
        self.user.username = 'agent-synthetic-task50'
        self.user.save()
        self.agent.tools = ['build_excel', 'rename_excel']
        self.agent.save()
        self.worker_token = 'synthetic-task50-worker-key-32-characters'
        self.enterContext(override_settings(DEBUG=True, REGULAY_AGENT_DEVELOPMENT=True,
            REGULAY_AGENT_WORKER_TOKEN=self.worker_token,
            REGULAY_AGENT_DEV_ACCOUNTS={str(self.user.pk): {'company_id': self.company.pk, 'profile_id': self.agent.pk}}))
        self.client.force_login(self.user)

    def send(self, *, url='/chat/send/', request_id=None, conversation=None, file=True, **extra):
        payload = {'prompt': 'Crea el Excel', 'content': 'Crea el Excel', 'mode': 'agent',
            'request_id': str(request_id or uuid.uuid4()), **extra}
        if file:
            payload['file'] = SimpleUploadedFile('synthetic.csv', CSV)
        if conversation:
            payload['conversation_id'] = conversation.pk
        with patch('front.documents.extract_document', side_effect=AssertionError('Normal extractor called')):
            return self.client.post(url, payload)

    def queued(self):
        response = self.send()
        self.assertEqual(response.status_code, 202, response.content)
        return AgentExecution.objects.get(pk=response.json()['agent']['id'])

    def claimed(self, run):
        # Actual claim operation is exercised only against PostgreSQL.
        value = jobs.claim(self.worker_token, {'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4())})
        self.assertEqual(value['status'], 'claimed', value)
        self.assertEqual(value['execution'], str(run.pk))
        run.refresh_from_db()
        return value['token'], run.attempt

    def issue(self, run, token, attempt, title='Ventas sintéticas'):
        call = {'id': 'excel-' + uuid.uuid4().hex, 'name': 'build_excel' if run.job['kind'] == 'build' else 'rename_excel',
            'args': {'title': title, **({'input_reference': run.job['source']} if run.job['kind'] == 'build' else {
                'logical_id': run.job['logical_id'], 'base_revision': run.job['base']})}}
        self.reply_calls = [call]
        reply = infer(token, attempt, {'call_id': str(uuid.uuid4()), 'messages': [{'role': 'user', 'content': 'Crear Excel'}],
                                      'tools': [call['name']]})
        self.assertEqual(reply['status'], 'completed', reply)
        return reply['tool_calls'][0]

    def publish(self, run, token, attempt, call, data=None):
        result = jobs.candidate(token, attempt, {'operation_id': str(uuid.uuid4()), 'call': call,
            'base64': base64.b64encode(data or candidate_bytes()).decode()})
        self.assertEqual(result['status'], 'approved', result)
        tool_result(token, attempt, {'call': call, 'raw': {'content': json.dumps({'reference': result['reference']}),
            'stderr': 'Private Synthetic Raw Marker'}})
        jobs.complete(token, attempt, {})
        return AgentArtifact.objects.get(pk=result['reference'])


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentChatTests(ChatFixture, TestCase):
    def test_three_http_entries_accept_and_replay_without_extracting_or_calling_model(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            request_id = uuid.uuid4()
            first = self.send(url=url, request_id=request_id)
            second = self.send(url=url, request_id=request_id)
            self.assertEqual(first.status_code, 202, first.content)
            self.assertEqual(second.status_code, 202, second.content)
            self.assertEqual(first.json()['agent']['id'], second.json()['agent']['id'])
            run = AgentExecution.objects.get(pk=first.json()['agent']['id'])
            self.assertEqual(run.events.count(), 1)
            Prompt.objects.filter(pk=run.prompt_id).update(updated_at=timezone.now() - timedelta(seconds=500))
            self.assertEqual(self.send(url=url, request_id=request_id).json()['status'], 'accepted')
            run.refresh_from_db()
            self.assertEqual(run.status, 'queued')
        self.assertFalse(self.requests)

    def test_default_and_current_accounts_off_historical_mode_immutable(self):
        with override_settings(REGULAY_AGENT_DEVELOPMENT=False):
            self.assertEqual(self.send().status_code, 403)
        with override_settings(REGULAY_AGENT_DEV_ACCOUNTS={}):
            self.assertEqual(self.send().status_code, 403)
        result = self.send(url=f'/chat/{self.conversation.pk}/send/')
        self.assertEqual(result.status_code, 409)
        self.conversation.refresh_from_db()
        self.assertEqual(self.conversation.mode, 'chat')
        self.assertFalse(self.requests)

    def test_two_tabs_busy_then_revision_stale_and_download_private(self):
        run = self.queued()
        response = self.send(url=f'/chat/{run.conversation_id}/send/')
        self.assertEqual(response.status_code, 409)
        token, attempt = self.claimed(run)
        call = self.issue(run, token, attempt)
        first = self.publish(run, token, attempt, call)
        response = self.send(url=f'/chat/{run.conversation_id}/send/', file=False,
            artifact_id=str(first.logical_id), base_revision=str(first.pk), prompt='Ventas revisadas')
        self.assertEqual(response.status_code, 202, response.content)
        changed = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        token, attempt = self.claimed(changed)
        call = self.issue(changed, token, attempt, 'Ventas revisadas')
        second = self.publish(changed, token, attempt, call, candidate_bytes('Ventas revisadas'))
        self.assertEqual(first.logical_id, second.logical_id)
        self.assertEqual((first.revision, second.revision), (1, 2))
        stale = self.send(url=f'/chat/{run.conversation_id}/send/', file=False,
            artifact_id=str(first.logical_id), base_revision=str(first.pk))
        self.assertEqual(stale.status_code, 409)
        download = self.client.get(f'/chat/agent/artifacts/{second.pk}/download/')
        self.assertEqual(download.content, jobs._bytes(second))
        self.assertEqual(download['Cache-Control'], 'private, no-store')
        state = self.client.get(f'/chat/agent/runs/{changed.pk}/').json()
        self.assertIn('<script>', json.dumps(state))  # User projection is text, not model data.
        self.assertNotIn('Private Synthetic', json.dumps(self.requests))
        from django.contrib.auth.models import User
        outsider = User.objects.create_user('agent-synthetic-outsider')
        Profile.objects.create(user=outsider, company=self.company)
        self.client.force_login(outsider)
        for url in (f'/chat/agent/artifacts/{second.pk}/download/', f'/chat/agent/runs/{changed.pk}/'):
            self.assertEqual(self.client.get(url).status_code, 404)

    def test_cancellation_revocation_expiry_and_old_attempt_block_new_steps_and_publication(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        call = self.issue(run, token, attempt)
        jobs.renew(token, attempt, {})
        jobs.step(token, attempt, {'call': call, 'phase': 'calculate'})
        with self.assertRaises(AgentDenied):
            jobs.step(token, attempt, {'call': call, 'phase': 'calculate'})
        jobs.cancel(self.user, run.pk)
        for op, payload in [(jobs.renew, {}), (jobs.step, {'call': call, 'phase': 'verify'}),
                (jobs.candidate, {'operation_id': str(uuid.uuid4()), 'call': call,
                                  'base64': base64.b64encode(candidate_bytes()).decode()})]:
            with self.assertRaises(AgentDenied):
                op(token, attempt, payload)
        self.assertFalse(run.artifacts.exists())
        next_run = self.queued()
        next_token, next_attempt = self.claimed(next_run)
        AgentExecution.objects.filter(pk=next_run.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(AgentDenied):
            jobs.renew(next_token, next_attempt, {})
        jobs.reap()
        next_run.refresh_from_db()
        self.assertEqual(next_run.status, 'interrupted')
        with self.assertRaises(AgentDenied):
            authenticate(next_token, next_attempt)
        third = self.queued()
        token, attempt = self.claimed(third)
        self.credential.active = False
        self.credential.save()
        with self.assertRaises(AgentDenied):
            jobs.bootstrap(token, attempt, {})
        replay = self.send(request_id=third.prompt.request_id)
        self.assertEqual(replay.status_code, 403)  # Replays also reauthorize after revocation.

    def test_final_bytes_corruption_remains_draft_repair_and_model_view_is_bounded(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        bootstrap = jobs.bootstrap(token, attempt, {})
        self.assertNotIn('Private Synthetic', json.dumps(bootstrap['model_context']))
        self.assertEqual(base64.b64decode(bootstrap['input']['base64']), CSV)
        call = self.issue(run, token, attempt)
        result = jobs.candidate(token, attempt, {'operation_id': str(uuid.uuid4()), 'call': call,
            'base64': base64.b64encode(candidate_bytes(corrupt=True)).decode()})
        self.assertEqual(result['status'], 'withheld')
        self.assertEqual(run.artifacts.get().status, 'draft')
        with self.assertRaises(AgentDenied):
            jobs.complete(token, attempt, {})
        self.assertEqual(self.client.get(f"/chat/agent/artifacts/{result['reference']}/download/").status_code, 404)
        repaired = self.publish(run, token, attempt, call)
        self.assertEqual(run.artifacts.count(), 2)
        AgentArtifact.objects.filter(pk=repaired.pk).update(content=base64.b64encode(candidate_bytes('Tampered')).decode())
        self.assertEqual(self.client.get(f'/chat/agent/artifacts/{repaired.pk}/download/').status_code, 404)

    def test_claim_transport_replay_does_not_renew_and_restart_never_reexecutes(self):
        run = self.queued()
        payload = {'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4())}
        first = jobs.claim(self.worker_token, payload)
        run.refresh_from_db()
        expiry = run.expires_at
        self.assertEqual(first, jobs.claim(self.worker_token, payload))
        run.refresh_from_db()
        self.assertEqual(expiry, run.expires_at)
        # Simulated process death: the replacement worker has no checkpoint and
        # must neither claim nor retry an active attempt with unknown effects.
        self.assertEqual(jobs.claim(self.worker_token, {'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4())})['status'], 'idle')
        AgentExecution.objects.filter(pk=run.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        jobs.reap()
        with self.assertRaises(AgentDenied):
            jobs.claim(self.worker_token, payload)

    def test_input_boundaries_and_formula_text_cannot_become_executable(self):
        from front.agents.excel_contract import input_rows, verify
        invalid = [b'', b'wrong,headers\na,1\n', b'item,amount_cents\na,1.2\n',
                   b'item,amount_cents\na,1000000000000\n', b'x' * 2_000_001,
                   b'item,amount_cents\n' + b'a' * 150000 + b',1\n', b'item,amount_cents\n"unclosed,1']
        for value in invalid:
            with self.subTest(value=value[:30]), self.assertRaises(ValueError):
                input_rows(value, 'csv')
        book = Workbook()
        book.active.append(['item', 'amount_cents'])
        for item, cents in [('A', -125), ('B', 0), ('C', 500)]:
            book.active.append([item, cents])
        data = io.BytesIO()
        book.save(data)
        self.assertEqual(input_rows(data.getvalue(), 'xlsx'), [('A', -125), ('B', 0), ('C', 500)])
        book.active['A2'] = '=HYPERLINK("https://invalid")'
        data = io.BytesIO()
        book.save(data)
        with self.assertRaises(ValueError):
            input_rows(data.getvalue(), 'xlsx')
        # Same visible string as the CSV, but encoded as a formula, is rejected.
        from openpyxl import load_workbook
        output = load_workbook(io.BytesIO(candidate_bytes()))
        output.active['A6'].data_type = 'f'
        data = io.BytesIO()
        output.save(data)
        with self.assertRaises((ValueError, ArithmeticError)):
            verify(data.getvalue(), CSV, 'csv', title='Ventas sintéticas')
        linked = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(candidate_bytes())) as source, zipfile.ZipFile(linked,'w') as output:
            for item in source.infolist():
                raw = source.read(item)
                if item.filename == 'xl/_rels/workbook.xml.rels':
                    raw = raw.replace(b'</Relationships>', b"<Relationship Id='external' Target='https://invalid' TargetMode='External' Type='hyperlink'/></Relationships>")
                output.writestr(item,raw)
        from front.agents.excel_contract import workbook
        with self.assertRaisesMessage(ValueError,'excel_external_link'):
            workbook(linked.getvalue())

    def test_cancellation_during_verification_cannot_publish_candidate(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        call = self.issue(run, token, attempt)
        original = jobs.verify
        def cancel_after_check(*args, **kwargs):
            result = original(*args, **kwargs)
            jobs.cancel(self.user, run.pk)
            return result
        with patch.object(jobs, 'verify', side_effect=cancel_after_check), self.assertRaises(AgentDenied):
            jobs.candidate(token, attempt, {'operation_id': str(uuid.uuid4()), 'call': call,
                'base64': base64.b64encode(candidate_bytes()).decode()})
        self.assertFalse(run.artifacts.exists())

    def test_revision_is_protected_individually_and_conversation_can_be_deleted(self):
        from django.db.models.deletion import RestrictedError
        run = self.queued()
        token, attempt = self.claimed(run)
        artifact = self.publish(run, token, attempt, self.issue(run, token, attempt))
        with self.assertRaises(RestrictedError):
            artifact.source.delete()
        conversation = run.conversation
        conversation.delete()
        self.assertFalse(AgentArtifact.objects.filter(pk=artifact.pk).exists())


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentChatConcurrencyTests(ChatFixture, TransactionTestCase):
    def test_two_workers_claim_once_postgresql(self):
        self.assertEqual(connection.vendor, 'postgresql')
        run = self.queued()
        barrier = Barrier(2)
        def claim():
            close_old_connections()
            try:
                barrier.wait(10)
                return jobs.claim(self.worker_token, {'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4())})
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: claim(), range(2)))
        self.assertEqual(sorted(r['status'] for r in results), ['claimed', 'idle'])
        self.assertEqual(run.events.filter(kind='claimed').count(), 1)

    def test_concurrent_http_duplicate_and_two_tab_writer(self):
        from front.chat_service import send_chat_message
        request_id = uuid.uuid4()
        barrier = Barrier(2)
        def send(conversation=None):
            close_old_connections()
            try:
                from django.contrib.auth.models import User
                actor = User.objects.get(pk=self.user.pk)
                barrier.wait(10)
                return send_chat_message(actor, {'mode': 'agent', 'content': 'Excel',
                    'request_id': str(request_id if conversation is None else uuid.uuid4()),
                    'conversation_id': conversation, 'file': SimpleUploadedFile('synthetic.csv', CSV)})
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: send(), range(2)))
        self.assertTrue(all(result.http_status in (202, 409) for result in results))
        self.assertEqual(Prompt.objects.filter(user=self.user, request_id=request_id).count(), 1)
        run = AgentExecution.objects.get(prompt__request_id=request_id)
        self.assertEqual(Conversation.objects.filter(mode='agent').count(), 1)
        jobs.cancel(self.user, run.pk)
        barrier = Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: send(run.conversation_id), range(2)))
        self.assertEqual(sorted(result.http_status for result in results), [202, 409])
        self.assertEqual(AgentExecution.objects.filter(conversation_id=run.conversation_id, status__in=jobs.LIVE).count(), 1)

    async def test_asgi_sse_disconnect_cursor_cancel_and_reauthorization(self):
        run = await sync_to_async(self.queued)()
        client = AsyncClient()
        client.cookies = self.client.cookies
        url = f'/chat/agent/runs/{run.pk}/events/'
        response = await client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Accel-Buffering'], 'no')
        stream = response.streaming_content.__aiter__()
        first = (await anext(stream)).decode()
        cursor = int(first.split('\n')[0].split(': ')[1])
        await stream.aclose()  # A dropped stream does not cancel or run work.
        await sync_to_async(run.refresh_from_db)()
        self.assertEqual(run.status, 'queued')
        token, attempt = await sync_to_async(self.claimed)(run)
        response = await client.get(url, headers={'Last-Event-ID': str(cursor)})
        stream = response.streaming_content.__aiter__()
        following = (await anext(stream)).decode()
        self.assertNotIn(f'id: {cursor}\n', following)
        self.assertIn('Ejecución iniciada', following)
        self.assertNotIn('Entorno limpio reservado', following)
        await sync_to_async(jobs.cancel)(self.user, run.pk)
        terminal = ''
        for _ in range(5):
            chunk = (await anext(stream)).decode()
            terminal += chunk
            if 'event: terminal' in chunk:
                break
        self.assertIn('cancelled', terminal)
        with self.assertRaises(AgentDenied):
            await sync_to_async(jobs.renew)(token, attempt, {})
        await stream.aclose()
        another = await sync_to_async(self.queued)()
        response = await client.get(f'/chat/agent/runs/{another.pk}/events/')
        stream = response.streaming_content.__aiter__()
        await anext(stream)
        await sync_to_async(type(self.credential).objects.filter(pk=self.credential.pk).update)(active=False)
        revoked = ''
        for _ in range(4):
            chunk = (await anext(stream)).decode()
            revoked += chunk
            if 'event: revoked' in chunk:
                break
        self.assertIn('event: revoked', revoked)
        await stream.aclose()


class AgentChatMigrationTests(TransactionTestCase):
    def test_0037_additive_default_off_and_reversible(self):
        old = [('front', '0036_agent_inference')]
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        try:
            executor = MigrationExecutor(connection)
            executor.migrate(old)
            apps = executor.loader.project_state(old).apps
            user = apps.get_model('auth', 'User').objects.create(username='existing-task50')
            company = apps.get_model('front', 'Company').objects.create(name='Keep', ai_config={'revision': 50})
            conversation = apps.get_model('front', 'Conversation').objects.create(user_id=user.pk, title='Existing')
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(Conversation.objects.get(pk=conversation.pk).mode, 'chat')
            self.assertEqual(apps.get_model('front', 'Company').objects.get(pk=company.pk).ai_config, {'revision': 50})
            MigrationExecutor(connection).migrate(old)
            self.assertEqual(apps.get_model('front', 'Conversation').objects.get(pk=conversation.pk).title, 'Existing')
        finally:
            MigrationExecutor(connection).migrate(latest)
