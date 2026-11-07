"""Application HTTP → real SDK → actual namespace/render; model/search simulated."""
import base64
import io
import json
from pathlib import Path
import subprocess
import uuid
from unittest.mock import patch
import httpx
from django.test import LiveServerTestCase, override_settings, tag
from front.test_agent_inference import AgentFixture
from front.models import AgentAccessGrant, AgentExecution
from front.agents import jobs, web_tools
from front.agents.capabilities import GENERAL

@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_WEB_ENABLED=True, DEBUG=False,
    REGULAY_AGENT_WORKER_TOKEN='task56-loopback-worker-credential-for-tests-only')
@tag('namespace_integration')
class ProfessionalHTTPTests(AgentFixture, LiveServerTestCase):
    def test_chat_to_sdk_code_render_artifacts_and_private_download(self):
        root = Path(__file__).resolve().parents[2]
        self.user.username = 'ordinary-existing-account'
        self.user.save()
        self.agent.professional = True
        self.agent.tools = sorted(GENERAL)
        self.agent.search_config = json.dumps({'provider': 'tavily', 'api_key': 'synthetic', 'call_cost_bound': '0.01'})
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user, profile=self.agent, enabled=True)
        self.company.ai_config['destinations']['internal'].append('research:web')
        self.company.save()
        self.client.force_login(self.user)
        response = self.client.post('/chat/send/', {'mode': 'agent', 'request_id': str(uuid.uuid4()),
            'prompt': 'Investiga y crea un informe de consultoría en español de cinco páginas sobre computación cuántica y ciberseguridad en Word y PDF. Incluye además un Excel y un gráfico del dataset público de la prueba; etiqueta sus datos como controlados.'})
        self.assertEqual(response.status_code, 202, response.content)
        run = AgentExecution.objects.get(pk=response.json()['agent']['id'])
        worker_id = str(uuid.uuid4())
        claim = jobs.claim('task56-loopback-worker-credential-for-tests-only', {'worker_id': worker_id,
            'claim_id': str(uuid.uuid4()), 'worker_protocol': 2})
        self.assertEqual(claim['execution'], str(run.pk))
        self.assertEqual(jobs.claim('task56-loopback-worker-credential-for-tests-only',
            {'worker_id': str(uuid.uuid4()), 'claim_id': str(uuid.uuid4()), 'worker_protocol': 2})['status'], 'idle')
        program = (root / 'ops/agent_chat/professional_fixture.py').read_text(encoding='utf-8')
        calls = [
            ('web_search', {'query': 'quantum security primary guidance dataset'}),
            ('web_open', {'url': 'https://dataset.example/context'}),
            ('web_download', {'url': 'https://dataset.example/energy.csv', 'file_path': '/workspace/work/dataset.csv'}),
            ('write_file', {'file_path': '/workspace/work/new_program.py', 'content': program}),
            ('execute', {'command': 'python new_program.py'}),
            ('publish_artifact', {'file_path': '/workspace/output/quantum-v1.docx', 'title': 'Computación cuántica y ciberseguridad'}),
            ('publish_artifact', {'file_path': '/workspace/output/analysis-v1.xlsx', 'title': 'Dataset controlado'}),
            ('publish_artifact', {'file_path': '/workspace/output/chart.png', 'title': 'Demanda controlada'})]
        def next_reply():
            index = len(self.requests) - 1
            self.reply_calls = [{'id': 'acceptance-' + str(index), 'name': calls[index][0], 'args': calls[index][1]}] if index < len(calls) else []
        self.after_request = next_reply
        def web(request):
            if request.url.host == 'api.tavily.com':
                return httpx.Response(200, json={'results': [{'title': 'Controlled source', 'url': 'https://dataset.example/context', 'content': 'Discovery'}]})
            if request.url.path == '/energy.csv':
                return httpx.Response(200, headers={'content-type': 'text/csv'}, content=b'region,load_mwh\nNorth,12\nSouth,18\nEast,24\n')
            return httpx.Response(200, headers={'content-type': 'text/html'}, content=b'<h1>Controlled evidence</h1><p>Quantum migration needs a cryptographic inventory. Acceptance dataset only.</p><a href="/energy.csv">Dataset</a>')
        search = web_tools.search
        with patch('front.agents.public_web.resolve', return_value='93.184.216.34'), \
                patch('front.agents.public_web.httpx.HTTPTransport', return_value=httpx.MockTransport(web)), \
                patch('front.agents.web_tools.search', side_effect=lambda *args, **kwargs: search(*args, **kwargs, transport=httpx.MockTransport(web))):
            python = root / 'ops/agent_probe/.venv/Scripts/python.exe'
            result = subprocess.run(['rtk', 'proxy', str(python), str(root / 'ops/agent_chat/verify_professional_http.py')],
                input=json.dumps({'endpoint': self.live_server_url + '/internal/agents/', 'token': claim['token'],
                    'attempt': claim['attempt'], 'execution': claim['execution'], 'worker_id': worker_id,
                    'worker_token': 'task56-loopback-worker-credential-for-tests-only'}),
                text=True, encoding='utf-8', capture_output=True, timeout=240, cwd=root)
        from front.models import AgentInference
        diagnostic = [{'status': item.status, 'code': item.response.get('code')} for item in AgentInference.objects.filter(execution=run)]
        self.assertEqual(result.returncode, 0, result.stderr[-1500:] + json.dumps(diagnostic))
        run.refresh_from_db()
        self.assertEqual(run.status, 'completed')
        worker_result = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(worker_result['sandbox_allocations'], 1)
        delivered = run.artifacts.filter(status='verified', verification__purpose='deliverable')
        self.assertEqual(delivered.count(), 3)
        doc = delivered.get(format='docx')
        self.assertEqual(run.job['sandbox_reservation']['state'], 'released')
        self.assertEqual(doc.verification['pages'], 5)
        for suffix in ('download/', 'download/?format=pdf', 'pages/5/'):
            downloaded = self.client.get('/chat/agent/artifacts/' + str(doc.pk) + '/' + suffix)
            self.assertEqual(downloaded.status_code, 200, suffix)
            self.assertEqual(downloaded['Cache-Control'], 'private, no-store')
        self.assertIn('54', json.dumps([json.loads(row.protected_view) for row in run.agenttoolresult_set.all()]))
        self.assertEqual(len(self.requests), len(calls) + 1)
        self.assertEqual(len({row.call_id for row in run.agentinference_set.all()}), len(calls) + 1)
        state = self.client.get('/chat/agent/runs/' + str(run.pk) + '/').json()
        self.assertTrue(state['sources'][0]['opened'])
        evidence = root / 'output/p0-e1-e8-20261016/namespace'
        evidence.mkdir(parents=True, exist_ok=True)
        (evidence / 'http-sdk-namespace.json').write_text(json.dumps({'status': run.status, 'http_entry': '/chat/send/',
            'provider': 'HTTP MockTransport; no live model or paid search', 'sandbox': 'actual Linux namespace; E2B transport substitute',
            'worker_protocol': 2, 'sandbox_allocations': worker_result['sandbox_allocations'],
            'inferences': len(self.requests), 'operations': run.operations.count(), 'formats': ['docx', 'pdf', 'xlsx', 'png'],
            'pages': 5, 'sources': len(state['sources']), 'docx_sha256': doc.sha256,
            'pdf_sha256': doc.verification['pdf_sha256']}, indent=2))
