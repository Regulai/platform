"""Account + explicit skill + real SDK + physical engine; human-readable visual gate."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import LiveServerTestCase, override_settings

from front.agents import document_jobs, jobs, skill_installation
from front.agents.skill_bundles import revision_files
from front.models import AgentAccessGrant, AgentArtifact, AgentExecution, AgentSkillInstallation, ConversationAlias
from front.test_agent_inference import AgentFixture

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'output/p1-20261016/physical/documental'
CSV = b'item,amount_cents\nUno,1000\nDos,2000\nTres,3000\n'


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True, REGULAY_SKILLS_RUNTIME=True,
    REGULAY_AGENT_TEXT_STREAM=False, REGULAY_AGENT_WORKER_TOKEN='synthetic-p1-documental-worker-key-32-characters',
    REGULAY_SKILL_RUNTIME_CAPABILITIES={'documents': 'verified-v1', 'spreadsheets': 'verified-v1', 'presentations': 'verified-v1'})
class DocumentalAcceptance(AgentFixture, LiveServerTestCase):
    def setUp(self):
        super().setUp()
        self.agent.professional = False
        self.agent.tools = ['read_file', 'build_excel', 'build_document', 'build_presentation']
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.client.force_login(self.user)
        EVIDENCE.mkdir(parents=True, exist_ok=True)

    def test_four_curated_skills_with_one_lazy_runtime_each(self):
        records = []
        for fmt, candidate, tabular in (('xlsx', 'excel', False), ('docx', 'docx', False),
                ('pdf', 'pdf', False), ('pptx', 'pptx', False), ('pptx', 'pptx', True)):
            record = self.check_format(fmt, candidate, tabular=tabular)
            records.append(record)
            (EVIDENCE / 'results.json').write_text(json.dumps({'cases': records, 'paid_calls': 0,
                'microvm_verified': False}, ensure_ascii=False, indent=2), encoding='utf-8')

    def check_format(self, fmt, candidate, *, tabular=False):
        installed = skill_installation.install(self.user, uuid.uuid4(), {'source': 'catalog', 'candidate': candidate})
        self.assertEqual(installed['state'], 'installed', installed)
        row = AgentSkillInstallation.objects.get(pk=installed['installation_id'])
        self.assertTrue(row.enabled)
        body = revision_files(row.current_revision)['SKILL.md'].decode()
        prompt = {'xlsx': 'Crea un Excel con los importes del CSV adjunto.',
            'docx': 'Crea un documento Word con los importes del CSV adjunto.',
            'pdf': 'Crea un documento PDF con los importes del CSV adjunto.',
            'pptx': 'Crea una presentaciÃ³n PPTX de una diapositiva con recomendaciones generales.'}[fmt]
        payload = {'mode': 'agent', 'request_id': str(uuid.uuid4()), 'prompt': prompt,
            'skills': json.dumps({'selected': [str(row.pk)], 'auto': False})}
        if tabular:
            payload['prompt'] = 'Crea una presentaciÃ³n PPTX con los importes del CSV adjunto.'
        if fmt != 'pptx' or tabular:
            payload['file'] = SimpleUploadedFile('synthetic.csv', CSV)
        response = self.client.post('/chat/send/', payload)
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        self.assertEqual(run.job['skills']['selected'], [str(row.pk)])
        claim = jobs.claim('synthetic-p1-documental-worker-key-32-characters', {'worker_id': str(uuid.uuid4()),
            'claim_id': str(uuid.uuid4()), 'worker_protocol': 2})
        self.assertEqual(claim['execution'], str(run.pk), claim)
        offset = len(self.requests)
        title = 'VerificaciÃ³n documental'
        if fmt == 'xlsx':
            name, args = 'build_excel', {'input_reference': run.job['source'], 'title': title}
        elif fmt in ('docx', 'pdf'):
            name, args = 'build_document', {'input_reference': run.job['source'], 'format': fmt,
                'title': title, 'section': 'Importes sintÃ©ticos para verificar el documento.'}
        elif tabular:
            name, args = 'build_presentation', {'input_reference': run.job['source'], 'template': 'corporate',
                'title': title, 'section': 'Importes sintÃ©ticos'}
        else:
            name, args = 'build_presentation', {'input_reference': '', 'template': 'new',
                'title': title, 'section': 'Recomendaciones', 'language': 'es', 'content': [
                    {'heading': 'Recomendaciones', 'blocks': [{'kind': 'recommendation',
                        'text': 'Revisar las necesidades del equipo antes de elegir herramientas y conservar una documentaciÃ³n clara de las decisiones tomadas.'}]}]}
        def reply():
            self.reply_calls = [{'id': 'create-' + fmt, 'name': name, 'args': args}] if len(self.requests) == offset + 1 else []
        self.after_request = reply
        folder = EVIDENCE / (fmt + ('-tabular' if tabular else '') + '-' + uuid.uuid4().hex[:8])
        folder.mkdir()
        config = {'endpoint': self.live_server_url + '/internal/agents/', 'token': claim['token'], 'attempt': claim['attempt']}
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        with (folder / 'worker.log').open('w', encoding='utf-8') as log:
            worker = subprocess.Popen(['rtk', 'proxy', str(ROOT / 'ops/agent_probe/.venv/Scripts/python.exe'),
                str(ROOT / 'ops/agent_chat/p1_documental_worker.py')], cwd=ROOT, env=env,
                stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
            worker.stdin.write(json.dumps(config))
            worker.stdin.close()
            reviewed = False
            deadline = time.monotonic() + 240
            try:
                while worker.poll() is None and time.monotonic() < deadline:
                    artifact = AgentArtifact.objects.filter(execution=run).first()
                    if artifact and artifact.status == 'draft' and artifact.verification.get('automated_passed'):
                        if not (folder / 'review.json').exists():
                            parts = json.loads(artifact.render_bundle)
                            for path, content in parts.items():
                                if path.startswith('page-') and path.endswith('.png') or path in ('final.docx', 'final.pptx', 'final.pdf'):
                                    (folder / path).write_bytes(base64.b64decode(content, validate=True))
                            review = {'sha256': artifact.sha256,
                                'page_sha256': artifact.verification['page_sha256'], 'checks': document_jobs.VISUAL_CHECKS}
                            (folder / 'review.json').write_text(json.dumps(review, indent=2), encoding='utf-8')
                            print('VISUAL_REVIEW_READY ' + str(folder), flush=True)
                        approval = folder / 'visual-approved.json'
                        if approval.exists() and not reviewed:
                            review = json.loads((folder / 'review.json').read_text())
                            self.assertEqual(json.loads(approval.read_text()), review)
                            response = self.client.post('/chat/agent/artifacts/' + str(artifact.pk) + '/review/',
                                json.dumps(review), content_type='application/json')
                            self.assertEqual(response.status_code, 200, response.content)
                            reviewed = True
                    time.sleep(.2)
                self.assertIsNotNone(worker.poll(), 'Timed out waiting for real visual inspection or worker completion: ' + str(folder))
            finally:
                if worker.poll() is None:
                    worker.terminate()
                    worker.wait(timeout=10)
        log_text = (folder / 'worker.log').read_text(encoding='utf-8')
        if worker.returncode:
            (folder / 'failure-artifacts.json').write_text(json.dumps(list(
                AgentArtifact.objects.filter(execution=run).values('status', 'verification')), indent=2), encoding='utf-8')
        self.assertEqual(worker.returncode, 0, log_text[-7000:])
        receipt = json.loads(log_text.strip().splitlines()[-1])
        self.assertEqual(receipt['sandbox_allocations'], 1)
        self.assertEqual(len(self.requests) - offset, 2, 'Explicit selection must not add selector inference')
        chunks = []
        for message in self.requests[offset]['messages']:
            content = message.get('content') or ''
            chunks.extend([content] if isinstance(content, str) else [part.get('text', '') for part in content])
        (folder / 'first-provider-messages.json').write_text(json.dumps(self.requests[offset]['messages'], ensure_ascii=False, indent=2), encoding='utf-8')
        # The real provider receives masked text. Resolve only this synthetic
        # conversation's persisted aliases locally to prove the whole canonical
        # body is present exactly once, without bypassing protection on the wire.
        wire_text = '\n'.join(chunks)
        restored_text = wire_text
        aliases = ConversationAlias.objects.filter(company=run.prompt.company,
            user=run.prompt.user, conversation=run.prompt.conversation)
        for alias in aliases:
            restored_text = restored_text.replace(alias.token, alias.original)
        self.assertEqual(restored_text.replace('\r\n', '\n').count(body.replace('\r\n', '\n')), 1)
        self.assertEqual(wire_text.count('Skill autorizada ' + candidate + ' (' + str(row.current_revision_id) + ')'), 1)
        artifact = AgentArtifact.objects.get(execution=run, status='verified')
        self.assertEqual(artifact.format, fmt)
        self.assertTrue(artifact.verification['automated_passed'])
        downloaded = self.client.get('/chat/agent/artifacts/' + str(artifact.pk) + '/download/')
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(hashlib.sha256(downloaded.content).hexdigest(), artifact.sha256)
        (folder / ('download.' + fmt)).write_bytes(downloaded.content)
        self.assertEqual(len(self.requests) - offset, 2)
        run.refresh_from_db()
        self.assertEqual(run.status, 'completed')
        return {'format': fmt, 'candidate': candidate, 'tabular': tabular, 'status': run.status,
            'run': str(run.pk), 'artifact': str(artifact.pk), 'sha256': artifact.sha256,
            'verification': artifact.verification, 'canonical_body_occurrences': 1,
            'canonical_count_scope': 'Complete body after local resolution of this synthetic conversation aliases; protected HTTP payload retained',
            'canonical_body_sha256': hashlib.sha256(body.encode()).hexdigest(),
            'provider_http_requests': 2, 'download_provider_requests': 0, 'visual_reviewed': reviewed,
            'folder': str(folder.relative_to(ROOT)), 'worker': receipt}
