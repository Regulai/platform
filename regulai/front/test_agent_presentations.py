"""Final-file contracts plus shared HTTP/lease/publication authority on PostgreSQL."""
import base64
from datetime import timedelta
import io
import json
from pathlib import Path
import uuid
from unittest.mock import patch
import zipfile

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from lxml import etree
from openpyxl import load_workbook

from front.agents import presentation_contract as contract, document_jobs, jobs
from front.agents.data_views import authorize_tool
from front.agents.service import AgentDenied, infer
from front.models import AgentArtifact, AgentExecution
from front.test_agent_chat import ChatFixture

ROOT = Path(__file__).resolve().parents[2]/'evals/reports/task52-powerpoint-20261008/design-v3'
CSV = 'item,amount_cents\nÁrea Norte,125\nPiñón español,250\nRevisión técnica,375\n'.encode()
CONFIG = json.loads((ROOT/'new/fields.json').read_text())
EXPECTED = contract.expected_fields(CONFIG['title'], CONFIG['section'])


def repack(raw, transform):
    stream = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as output:
        for item in source.infolist():
            output.writestr(item, transform(item.filename, source.read(item)))
    return stream.getvalue()


class PresentationContractTests(SimpleTestCase):
    def setUp(self):
        self.raw = (ROOT/'new/final.pptx').read_bytes()

    def test_real_final_corpus_reopens_with_native_data_and_preserves_master(self):
        for name in ('new', 'template', 'long', 'edit'):
            with self.subTest(name=name):
                config = json.loads((ROOT/('new' if name == 'edit' else name)/'fields.json').read_text())
                expected = contract.expected_fields(config['title'], config['section'])
                if name == 'edit':
                    expected[2]['body'] = 'Revisión localizada: análisis de importes de España. Se conserva el resto de la presentación.'
                _, proof, _ = contract.verify_bundle(base64.b64encode((ROOT/name/'candidate.zip').read_bytes()).decode(),
                    CSV, 'csv', expected, base=self.raw if name == 'edit' else None,
                    changed=(3, 'body') if name == 'edit' else None, template=config['template'])
                self.assertEqual(proof['total_cents'], 750)
                self.assertEqual(proof['visual_review'], 'required')

    def test_unrequested_slide_title_or_master_change_rejected(self):
        edited = (ROOT/'edit/final.pptx').read_bytes()
        expected = contract.fields(edited)
        for name, old, new in [('ppt/slides/slide1.xml', b'REGULAY', b'CHANGED'),
                               ('ppt/slideMasters/slideMaster1.xml', b'showMasterSp', b'changedAttribute')]:
            with self.subTest(name=name):
                if old not in contract.package(edited)[name]:
                    old, new = b'</', b' </'
                changed = repack(edited, lambda n, v: v.replace(old, new, 1) if n == name else v)
                with self.assertRaises(Exception):
                    contract.verify_pptx(changed, CSV, 'csv', expected, base=self.raw, changed=(3, 'body'))

    def test_chart_workbook_is_checked_separately_from_chart_cache(self):
        def corrupt(name, value):
            if name.endswith('/data.xlsx'):
                book = load_workbook(io.BytesIO(value))
                book.active['B2'] = 99
                output = io.BytesIO()
                book.save(output)
                return output.getvalue()
            return value
        with self.assertRaisesMessage(ValueError, 'presentation_embedded_data'):
            contract.verify_pptx(repack(self.raw, corrupt), CSV, 'csv', EXPECTED)

    def test_embedded_formula_with_matching_cached_value_is_rejected(self):
        def formula(name, value):
            if name == 'xl/worksheets/sheet1.xml':
                return value.replace(b'<v>1.25</v>', b'<f>1.25</f><v>1.25</v>', 1)
            return value
        changed = repack(self.raw, lambda n, v: repack(v, formula) if n.endswith('/data.xlsx') else v)
        with self.assertRaisesMessage(ValueError, 'presentation_embedded_data'):
            contract.verify_pptx(changed, CSV, 'csv', EXPECTED)

    def test_cover_and_chart_label_must_match_integer_source(self):
        for part in ('ppt/slides/slide1.xml', 'ppt/slides/charts/chart1.xml'):
            changed = repack(self.raw, lambda n, v: v.replace('7,50'.encode(), b'9,99').replace('1,25'.encode(), b'9,99') if n == part else v)
            with self.assertRaises(ValueError):
                contract.verify_pptx(changed, CSV, 'csv', EXPECTED)

    def test_archive_external_links_and_text_limits(self):
        with self.assertRaises(zipfile.BadZipFile):
            contract.package(b'broken pptx')
        changed = repack(self.raw, lambda n, v: v.replace(b'</Relationships>', b'<Relationship Id="x" Target="https://invalid" Type="hyperlink" TargetMode="External"/></Relationships>') if n == '_rels/.rels' else v)
        with self.assertRaisesMessage(ValueError, 'presentation_external_relationship'):
            contract.package(changed)
        for value, field in [('', 'body'), ('x'*341, 'body'), ('x'*71, 'title'), ('{{TITLE}}', 'title')]:
            with self.assertRaises(ValueError):
                contract.valid_text(value, field)
        with self.assertRaises(ValueError):
            contract.source_rows(b'item,amount_cents\n'+b'Long label beyond supported capacity,125\n'*7, 'csv')

    def test_render_hash_and_preview_page_content_bound(self):
        candidate = (ROOT/'new/candidate.zip').read_bytes()
        changed = repack(candidate, lambda n, v: v+b'changed' if n == 'page-1.png' else v)
        with self.assertRaisesMessage(ValueError, 'presentation_render_digest'):
            contract.verify_bundle(base64.b64encode(changed).decode(), CSV, 'csv', EXPECTED)


@override_settings(REGULAY_AGENT_ENABLED=True)
class PresentationAuthorityTests(ChatFixture, TestCase):
    def send(self, **kwargs):
        text = 'Crea una presentación con la fuente adjunta'
        return super().send(**{'prompt': text, 'content': text, **kwargs})

    def setUp(self):
        super().setUp()
        self.agent.tools += ['build_presentation', 'edit_presentation']
        self.agent.save()
        self.enterContext(patch('front.test_agent_chat.CSV', CSV))

    def issue_pptx(self, run, token, attempt, editing=False):
        call = {'id': 'pptx-'+uuid.uuid4().hex, 'name': 'edit_presentation' if editing else 'build_presentation',
            'args': {'logical_id': run.job['logical_id'], 'base_revision': run.job['base'], 'slide': 3, 'field': 'body',
                'value': 'Revisión localizada: análisis de importes de España. Se conserva el resto de la presentación.'} if editing else
                {'input_reference': run.job['source'], 'template': 'new', 'title': CONFIG['title'], 'section': CONFIG['section']}}
        self.reply_calls = [call]
        infer(token, attempt, {'call_id': str(uuid.uuid4()), 'messages': [{'role': 'user', 'content': 'PPTX'}], 'tools': [call['name']]})
        return call

    def submit(self, run, token, attempt, call, fixture='new'):
        data = (ROOT/fixture/'candidate.zip').read_bytes()
        payload = {'operation_id': str(uuid.uuid4()), 'call': call, 'document_bundle': base64.b64encode(data).decode()}
        row = jobs.candidate(token, attempt, payload)
        artifact = AgentArtifact.objects.get(pk=row['reference'])
        self.assertTrue(artifact.verification['automated_passed'])
        return artifact, payload

    def review(self, artifact):
        return document_jobs.review(self.user, artifact.pk, {'sha256': artifact.sha256,
            'page_sha256': artifact.verification['page_sha256'], 'checks': document_jobs.VISUAL_CHECKS})

    def test_three_http_entries_shared_identity_preview_and_download_gate(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            response = self.send(url=url, prompt='PPTX')
            self.assertEqual(response.status_code, 202)
            run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
            token, attempt = self.claimed(run)
            artifact, payload = self.submit(run, token, attempt, self.issue_pptx(run, token, attempt))
            self.assertEqual(self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/').status_code, 404)
            preview = self.client.get(f'/chat/agent/artifacts/{artifact.pk}/pages/1/')
            self.assertEqual(preview.status_code, 200)
            self.assertIn('no-store', preview['Cache-Control'])
            self.assertEqual(jobs.candidate(token, attempt, payload)['reference'], str(artifact.pk))
            self.review(artifact)
            jobs.complete(token, attempt, {})
            download = self.client.get(f'/chat/agent/artifacts/{artifact.pk}/download/')
            self.assertIn('presentationml', download['Content-Type'])
            self.assertEqual(contract.sha256(download.content), artifact.sha256)
            self.assertNotIn('Piñón español', json.dumps(self.requests))

    def test_pptx_second_turn_bootstrap_stale_revisions_and_failed_repair(self):
        run = self.queued()
        token, attempt = self.claimed(run)
        artifact, _ = self.submit(run, token, attempt, self.issue_pptx(run, token, attempt))
        self.review(artifact)
        jobs.complete(token, attempt, {})
        response = self.send(url=f'/chat/{run.conversation_id}/send/', file=False,
            artifact_id=str(artifact.logical_id), base_revision=str(artifact.pk))
        self.assertEqual(response.status_code, 202, response.content)
        edited = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        token, attempt = self.claimed(edited)
        grant = jobs.bootstrap(token, attempt, {})
        self.assertEqual(grant['base_format'], 'pptx')
        self.assertIsNone(grant['base_docx'])
        call = self.issue_pptx(edited, token, attempt, True)
        failed = jobs.candidate(token, attempt, {'operation_id': str(uuid.uuid4()), 'call': call, 'document_bundle': base64.b64encode(b'bad converter output').decode()})
        self.assertEqual(AgentArtifact.objects.get(pk=failed['reference']).status, 'draft')
        repaired, _ = self.submit(edited, token, attempt, call, 'edit')
        self.assertEqual(repaired.logical_id, artifact.logical_id)
        self.assertEqual(repaired.revision, 3)
        self.review(repaired)
        jobs.complete(token, attempt, {})
        self.assertEqual(self.send(url=f'/chat/{run.conversation_id}/send/', file=False,
            artifact_id=str(artifact.logical_id), base_revision=str(artifact.pk)).status_code, 409)

    def test_cancel_expire_and_revocation_prevent_steps_and_delivery(self):
        for failure in ('cancel', 'expire', 'revoke'):
            run = self.queued()
            token, attempt = self.claimed(run)
            call = self.issue_pptx(run, token, attempt)
            artifact, _ = self.submit(run, token, attempt, call)
            if failure == 'cancel':
                jobs.cancel(self.user, run.pk)
            elif failure == 'expire':
                AgentExecution.objects.filter(pk=run.pk).update(expires_at=timezone.now()-timedelta(seconds=1))
            else:
                self.credential.active = False
                self.credential.save()
            with self.assertRaises(AgentDenied):
                self.review(artifact)
            with self.assertRaises(AgentDenied):
                jobs.step(token, attempt, {'call': call, 'phase': 'render'})
            with self.assertRaises(AgentDenied):
                jobs.complete(token, attempt, {})
            if failure == 'expire':
                jobs.reap()
