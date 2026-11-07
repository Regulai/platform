"""Document contracts and publication authority; rendering is tested on real E2B."""
import base64
from datetime import timedelta
import io
import json
from pathlib import Path
import tempfile
import uuid
from unittest.mock import patch
import zipfile

from django.test import TestCase, SimpleTestCase, TransactionTestCase, override_settings
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from front.agents import document_contract as contract, document_jobs, jobs
from front.agents.document_program import build, edit
from front.agents.service import AgentDenied, infer
from front.models import AgentArtifact, AgentExecution
from front.test_agent_chat import ChatFixture, CSV


class DocumentContractTests(SimpleTestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.output = Path(self.folder.name) / 'original.docx'
        self.expected = {'title': 'España: año y acción', 'section': 'Resumen económico con ñ, tildes y 1.250,00 €.'}
        build(contract.TEMPLATE, contract.input_rows(CSV, 'csv'), self.expected, self.output)
        self.raw = self.output.read_bytes()

    def test_template_headers_footers_sections_numbering_styles_and_integer_values(self):
        rows = contract.verify_docx(self.raw, CSV, 'csv', self.expected)
        self.assertEqual(sum(v for _, v in rows), 750)
        a, b = contract.package(self.raw), contract.package(contract.TEMPLATE.read_bytes())
        self.assertTrue(all(a[k] == v for k, v in b.items() if k != 'word/document.xml'))

    def test_title_and_section_edits_change_only_requested_field(self):
        for field, value in [('title', 'Título revisado'), ('section', 'Revisión económica, año 2026: £ y $.')]:
            output = Path(self.folder.name) / (field + '.docx')
            edit(self.output, field, value, output)
            contract.verify_docx(output.read_bytes(), CSV, 'csv', {**self.expected, field: value},
                                 base=self.raw, changed=field)
            with self.assertRaises(ValueError):
                contract.verify_docx(output.read_bytes(), CSV, 'csv', {**self.expected, field: value},
                                     base=self.raw, changed='title' if field == 'section' else 'section')

    def test_legacy_template_revisions_survive_design_upgrade(self):
        build(contract.TEMPLATE.with_name('corporate-v1.docx'), contract.input_rows(CSV, 'csv'), self.expected, self.output)
        previous = self.output.read_bytes()
        changed = Path(self.folder.name)/'legacy-edit.docx'
        edit(self.output, 'title', 'Título anterior revisado', changed)
        contract.verify_docx(changed.read_bytes(), CSV, 'csv', {**self.expected, 'title': 'Título anterior revisado'},
                             base=previous, changed='title')

    def test_long_table_spans_rows_without_changing_template_structure(self):
        source = ('item,amount_cents\n' + '\n'.join(f'Piñón español {n},125' for n in range(65))).encode()
        build(contract.TEMPLATE, contract.input_rows(source, 'csv'), self.expected, self.output)
        self.assertEqual(len(contract.verify_docx(self.output.read_bytes(), source, 'csv', self.expected)), 65)

    def test_malformed_archive_external_relation_and_residue_rejected(self):
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            contract.package(b'not a docx')
        changed = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.raw)) as original, zipfile.ZipFile(changed, 'w') as output:
            for item in original.infolist():
                data = original.read(item)
                if item.filename == 'word/_rels/document.xml.rels':
                    data = data.replace(b'</Relationships>', b"<Relationship Id='external' Target='https://invalid' TargetMode='External' Type='hyperlink'/></Relationships>")
                output.writestr(item, data)
        with self.assertRaisesMessage(ValueError, 'document_external_relationship'):
            contract.package(changed.getvalue())
        for value in ('', '{{TITLE}}', 'a\n', 'x' * 1801):
            with self.assertRaises(ValueError):
                contract.valid_section(value)


@override_settings(REGULAY_AGENT_ENABLED=True)
class DocumentAuthorityTests(ChatFixture, TestCase):
    def send(self, **kwargs):
        text = 'Crea un informe Word con la fuente adjunta'
        return super().send(**{'prompt': text, 'content': text, **kwargs})

    def setUp(self):
        super().setUp()
        self.agent.tools += ['build_document', 'edit_document', 'export_pdf']
        self.agent.save()

    def document(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        call = {'id': 'document-' + uuid.uuid4().hex, 'name': 'build_document', 'args': {
            'input_reference': run.job['source'], 'format': 'docx', 'title': 'España', 'section': 'Resumen sintético.'}}
        self.reply_calls = [call]
        infer(token, attempt, {'call_id': str(uuid.uuid4()), 'messages': [{'role': 'user', 'content': 'DOCX'}],
                              'tools': ['build_document']})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'test.docx'
            build(contract.TEMPLATE, contract.input_rows(CSV, 'csv'), {'title': 'España', 'section': 'Resumen sintético.'}, path)
            raw = path.read_bytes()
        # Deliberately synthetic rendering boundary fixture, not render/visual evidence.
        page = b'synthetic-boundary-page'
        proof = {'sha256': contract.sha256(raw), 'docx_sha256': contract.sha256(raw), 'automated_passed': True, 'rows': 3, 'total_cents': 750,
                 'pages': 1, 'page_sha256': [contract.sha256(page)], 'visual_review': 'required'}
        bundle = json.dumps({'final.docx': base64.b64encode(raw).decode(), 'page-1.png': base64.b64encode(page).decode()})
        payload = {'operation_id': str(uuid.uuid4()), 'call': call, 'document_bundle': base64.b64encode(raw).decode()}
        with patch.object(document_jobs, 'verify_bundle', return_value=(raw, proof, bundle)):
            result = jobs.candidate(token, attempt, payload)
        return run, token, attempt, call, AgentArtifact.objects.get(pk=result['reference']), payload

    def review_payload(self, artifact):
        return {'sha256': artifact.sha256, 'page_sha256': artifact.verification['page_sha256'], 'checks': document_jobs.VISUAL_CHECKS}

    def test_visual_gate_is_real_separate_from_automated_verification_and_worker(self):
        run, token, attempt, call, artifact, payload = self.document()
        self.assertEqual(artifact.status, 'draft')
        self.assertTrue(document_jobs.review_status(token, attempt, {})['pending'])
        with self.assertRaises(AgentDenied):
            jobs.complete(token, attempt, {})
        self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/').status_code, 404)
        self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/pages/1/').status_code, 200)
        from front.agents.data_views import tool_result
        view = tool_result(token, attempt, {'call': call, 'raw': {'content': json.dumps({'reference': str(artifact.pk)})}})
        self.assertEqual(view, {'status': 'withheld', 'code': 'visual_review_required'})
        self.assertNotIn('Private Synthetic', json.dumps(self.requests))
        self.client.logout()
        url = f'/chat/agent/artifacts/{artifact.pk}/review/'
        self.assertEqual(self.client.post(url, self.review_payload(artifact), content_type='application/json',
            HTTP_AUTHORIZATION='Bearer ' + token).status_code, 302)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(url, self.review_payload(artifact), content_type='application/json').status_code, 200)
        jobs.complete(token, attempt, {})
        downloaded = self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/')
        self.assertEqual(contract.sha256(downloaded.content), artifact.sha256)
        self.assertIn('wordprocessingml', downloaded['Content-Type'])

    def test_stale_hash_cancel_expiry_and_revocation_cannot_approve_or_start_steps(self):
        run, token, attempt, call, artifact, payload = self.document()
        wrong = self.review_payload(artifact) | {'sha256': '0' * 64}
        with self.assertRaises(AgentDenied):
            document_jobs.review(self.user, artifact.pk, wrong)
        jobs.cancel(self.user, run.pk)
        with self.assertRaises(AgentDenied):
            document_jobs.review(self.user, artifact.pk, self.review_payload(artifact))
        with self.assertRaises(AgentDenied):
            jobs.step(token, attempt, {'call': call, 'phase': 'render'})
        run, token, attempt, call, artifact, payload = self.document()
        AgentExecution.objects.filter(pk=run.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(AgentDenied):
            document_jobs.review(self.user, artifact.pk, self.review_payload(artifact))
        jobs.reap()
        run, token, attempt, call, artifact, payload = self.document()
        self.credential.active = False
        self.credential.save()
        with self.assertRaises(AgentDenied):
            document_jobs.review(self.user, artifact.pk, self.review_payload(artifact))

    def test_failed_conversion_preserves_draft_and_cannot_fake_qualitative_review(self):
        run, token, attempt, call, artifact, payload = self.document()
        document_jobs.review(self.user, artifact.pk, self.review_payload(artifact))
        failed = jobs.candidate(token, attempt, {**payload, 'operation_id': str(uuid.uuid4()),
            'document_bundle': base64.b64encode(b'failed converter candidate').decode()})
        candidate = AgentArtifact.objects.get(pk=failed['reference'])
        self.assertFalse(candidate.verification['automated_passed'])
        with self.assertRaises(AgentDenied):
            document_jobs.review(self.user, artifact.pk, self.review_payload(artifact))
        self.assertEqual(self.client.get(f'/chat/agent/artifacts/{candidate.pk}/pages/1/').status_code, 404)
        with self.assertRaisesMessage(AgentDenied, 'verified_artifact_required'):
            jobs.complete(token, attempt, {})


@override_settings(REGULAY_AGENT_ENABLED=True)
class DocumentMigrationTests(ChatFixture, TransactionTestCase):
    def test_0038_is_additive_defaults_off_and_reversible(self):
        self.assertEqual(connection.vendor, 'postgresql')
        run = self.queued()
        token, attempt = self.claimed(run)
        artifact = self.publish(run, token, attempt, self.issue(run, token, attempt))
        original = jobs._bytes(artifact)
        receipt = artifact.execution.prompt.decision
        executor = MigrationExecutor(connection)
        # Resolve the actual 0037 name, preserving compatibility with its original label.
        before = [node for node in executor.loader.graph.nodes if node[0] == 'front' and node[1].startswith('0037_')]
        latest = executor.loader.graph.leaf_nodes()
        try:
            executor.migrate(before)
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(AgentArtifact._meta.get_field('format').default, 'xlsx')
            restored = AgentArtifact.objects.get(pk=artifact.pk)
            self.assertEqual(restored.format, 'xlsx')
            self.assertEqual(restored.render_bundle, '')
            self.assertEqual(jobs._bytes(restored), original)
            self.assertEqual(restored.execution.prompt.decision, receipt)
            MigrationExecutor(connection).migrate(before)
        finally:
            MigrationExecutor(connection).migrate(latest)
