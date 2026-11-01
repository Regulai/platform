"""Actual chat UI with explicitly simulated professional snapshots, loopback only."""
from pathlib import Path
import json
import re
from urllib.parse import urlsplit, parse_qs
import preview_document_ui as base

EVIDENCE = base.ROOT / 'evals/reports/task56-professional-20261014/artifacts'
original_render, original_snapshot, original_run = base.render_page, base.snapshot, base.run_data
original_artifact = base.artifact
base.NOW = '2026-10-14T10:00:00+00:00'
def artifact(scenario, reviewed=True):
    value = original_artifact(scenario, reviewed)
    if scenario == 'deck':
        value['preview'].update(title='Plan de transición', page_count=2)
        value['preview']['pages'] = value['preview']['pages'][:2]
        value['page_sha256'] = value['page_sha256'][:2]
        value['verification_checks']['instructions']['detail'] = 'Escenario simulado: formato PPTX y 2 páginas.'
    return value
base.artifact = artifact
original_template = base.render_to_string
def template(name, context):
    return original_template(name, {**context, 'agent_professional': True})
base.render_to_string = template
def run_data(scenario, status):
    return {**original_run(scenario, status), 'professional': True, 'resumable': status == 'cancelled',
        'resume_url': f'/preview/resume/{scenario}/'}
base.run_data = run_data
def snapshot(scenario):
    value = original_snapshot(scenario)
    value['sources'] = [{'title': 'Evidencia controlada de aceptación', 'url': 'https://www.nist.gov/pqc',
        'final_url': 'https://www.nist.gov/pqc', 'opened': True, 'reading': 'complete',
        'read_ranges': [[0, 240]], 'read_characters': 240, 'characters': 240,
        'retrieved_at': base.NOW, 'snippet': 'Fuente de prueba. No acredita investigación con un modelo vivo.'},
        {'title': 'Resultado descubierto sin lectura', 'url': 'https://www.eia.gov/', 'opened': False}]
    value['operations'] = [{'name': 'execute', 'status': 'completed', 'created_at': base.NOW,
        'details_url': f'/chat/agent/runs/{base.RUN}/operations/1/'}]
    value['infrastructure'] = {'cost': None, 'scope': 'sandbox_and_bandwidth', 'status': 'not_reported'}
    return value
base.snapshot = snapshot
class Handler(base.Handler):
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == f'/chat/agent/runs/{base.RUN}/operations/1/':
            return self.json({'name': 'execute', 'args': {'command': 'python new_program.py'},
                'result': {'stdout': '{"total_mwh":54,"average_mwh":18}', 'exit_code': 0},
                'notice': 'Salida simulada para verificar la interfaz.'})
        match = re.fullmatch(r'/chat/agent/artifacts/([0-9a-f-]+)/(pages/(\d+)|download)/', url.path)
        if match and match[1] in (base.DOC, base.DECK):
            deck = match[1] == base.DECK
            name = 'deck-v2.pptx' if deck else 'quantum-v2.docx'
            if match[3]:
                path = EVIDENCE / ('render-' + name) / ('page-' + match[3] + '.png')
                return self.send(path.read_bytes(), 'image/png') if path.is_file() else self.send(b'', status=404)
            fmt = parse_qs(url.query).get('format', ['pptx' if deck else 'docx'])[0]
            path = EVIDENCE / ('render-' + name) / 'quantum-v2.pdf' if fmt == 'pdf' else EVIDENCE / name
            return self.send(path.read_bytes(), base.mimetypes.guess_type(path.name)[0], download=path.name) if path.is_file() else self.send(b'', status=404)
        return super().do_GET()
    def do_POST(self):
        if self.path.startswith('/preview/resume/'):
            scenario = self.path.strip('/').split('/')[-1]
            base.states[scenario] = 'active'
            return self.json({'run': run_data(scenario, 'active')})
        return super().do_POST()

if __name__ == '__main__':
    server = base.ThreadingHTTPServer(('127.0.0.1', 8766), Handler)
    print('SIMULATED UI: http://127.0.0.1:8766/chat/?state=completed', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
