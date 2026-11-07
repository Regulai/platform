"""Loopback-only visual fixture. No database, accounts, credentials or inference.

Run with the repository Python environment; --port defaults to 8765.
The actual Django chat template, CSS and JavaScript render synthetic snapshots.
Document previews/downloads use the already-rendered task-55 fixture artifacts.
This intentionally does not exercise production authentication or worker behavior.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
from pathlib import Path
import re
import time
from types import SimpleNamespace as NS
from urllib.parse import parse_qs, urlsplit

import django
from django.conf import settings
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.urls import include, path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / 'regulai/front/templates'
STATIC = ROOT / 'regulai/static'
ARTIFACTS = ROOT / 'evals/reports/task55-agent-documents-20261013'
RUN = 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb'
DOC = 'cccccccc-1111-2222-3333-dddddddddddd'
DECK = 'eeeeeeee-1111-2222-3333-ffffffffffff'
NOW = '2026-10-13T17:00:00+00:00'
states = {}


def placeholder(*_args, **_kwargs):
    return HttpResponse('Visual fixture only', status=404)


# Reverse actual template URL tags without importing application settings or views.
routes = {}
for template in ('base.html', 'chat/chat.html'):
    for _, name, args in re.findall(r"""{%\s*url\s+(['"])(.*?)\1([^%]*?)%}""", (TEMPLATES / template).read_text(encoding='utf-8')):
        count = len(args.strip().split())
        routes[name] = max(count, routes.get(name, 0))
urlpatterns = []
for namespace in ('front', 'admin'):
    entries = []
    for qualified, count in routes.items():
        if not qualified.startswith(namespace + ':'):
            continue
        name = qualified.split(':', 1)[1]
        route = 'preview/unused/' + name + '/' + ''.join(f'<str:value{index}>/' for index in range(count))
        entries.append(path(route, placeholder, name=name))
    urlpatterns.append(path('', include((entries, namespace), namespace=namespace)))
settings.configure(
    DEBUG=True, SECRET_KEY='local-ui-fixture-no-session-authority', ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=['127.0.0.1'], INSTALLED_APPS=['django.contrib.staticfiles'],
    DATABASES={}, STATIC_URL='/static/', USE_TZ=True,
    TEMPLATES=[{'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [str(TEMPLATES)], 'APP_DIRS': False}],
)
django.setup()


def receipt():
    calls = []
    for index in range(14):
        calls.append({
            'sequence': index + 1, 'purpose': 'classification' if index == 0 else 'generation',
            'status': 'completed', 'provider_name': 'Proveedor simulado', 'provider': 'synthetic',
            'model_requested': 'modelo-solicitado-de-prueba',
            'model_effective': 'jev-simulado' if index == 0 else f'modelo-efectivo-{index % 2 + 1}',
            'route': {'mode': 'agent_profile', 'destination': 'perfil-sintético', 'connector': 'offline'},
            'fallback': {'status': 'not_used', 'reason': 'agent_profile_pinned'},
            'started_at': NOW, 'duration_ms': 120 + index, 'cost': '0.0001',
            'currency': 'USD', 'cost_kind': 'tariff_estimate',
        })
    return {
        'policy': {'status': 'allowed', 'reason_codes': ['local_policy_allowed']},
        'jev': {'status': 'consulted', 'consulted': True, 'purpose': 'classification', 'consulted_at': NOW,
                'completed_at': NOW, 'decision': {'category': 'ordinary', 'task': 'report', 'difficulty': 'high'},
                'signals': {'difficulty': {'type': 'noul', 'noul': 0.7}}, 'reasons': [], 'recommendations': [],
                'policy': {'source': 'regulay_policy', 'revision': 3, 'classification': 'required', 'threshold': 0.8},
                'applied': {'source': 'regulay_policy', 'sensitivity': 'ordinary', 'task': 'report', 'difficulty': 'high'},
                'effect': 'continue', 'reason_codes': ['synthetic_fixture']},
        'calls': calls, 'total': {'cost': '0.0014', 'currency': 'USD', 'complete': True},
        'verification': {'status': 'partial'},
    }


def run_data(scenario, status):
    return {'id': RUN, 'request_id': RUN, 'status': status, 'status_url': f'/preview/status/{scenario}/',
            'events_url': f'/preview/events/{scenario}/', 'cancel_url': f'/preview/cancel/{scenario}/',
            'limitations': ['Demostración visual simulada. Sin llamadas a proveedores ni gasto real.']}


def artifact(scenario, reviewed=True):
    deck = scenario == 'deck'
    reference, count, fmt = (DECK, 3, 'pptx') if deck else (DOC, 5, 'docx')
    base = f'/chat/agent/artifacts/{reference}/'
    title = 'Computación cuántica y ciberseguridad'
    if scenario == 'overloaded':
        title += ' · ' + 'Evaluación de dependencias y recomendaciones para sistemas críticos ' * 4
    return {'id': reference, 'logical_id': reference, 'revision': 2, 'format': fmt,
            'status': 'verified' if reviewed else 'candidate', 'sha256': 'synthetic-ui-digest',
            'page_sha256': ['synthetic-ui-page'] * count, 'review_checks': ['legibility', 'no_clipping'],
            'review_url': base + 'review/', 'download_url': base + 'download/',
            'downloads': [] if deck else [{'format': 'pdf', 'url': base + 'download/?format=pdf'}],
            'preview': {'title': title, 'page_count': count, 'pages': [base + f'pages/{n}/' for n in range(1, count + 1)]},
            'verification_checks': {
                'integrity': {'status': 'passed', 'detail': 'Escenario simulado: estructura y archivos disponibles.'},
                'instructions': {'status': 'passed', 'detail': f'Escenario simulado: formato {fmt.upper()} y {count} páginas.'},
                'layout': {'status': 'passed' if reviewed else 'not_performed', 'detail': 'Revisión visual simulada registrada.' if reviewed else 'Pendiente de revisar todas las páginas.'},
                'sources': {'status': 'not_performed', 'detail': 'La UI no acredita verificación factual. Consulta el ensayo funcional y sus fuentes.'},
                'security': {'status': 'passed', 'detail': 'Fixture sin datos de clientes, cuentas ni credenciales.'},
            }}


def snapshot(scenario):
    current = states.get(scenario, scenario)
    status = {'active': 'active', 'review': 'active', 'error': 'failed', 'cancelled': 'cancelled'}.get(current, 'completed')
    value = receipt()
    if current in ('active', 'error', 'cancelled'):
        value['calls'] = value['calls'][:1] if current == 'error' else []
        value['total'] = {'cost': None, 'known_cost': None, 'currency': 'USD'}
        value['jev']['status'] = 'failed' if current == 'error' else 'not_consulted'
        value['jev']['consulted_at'] = None
        value['jev']['decision'] = None
        value['jev']['signals'] = {}
    text = {'active': 'Componiendo el informe solicitado. El siguiente paso es renderizar sus cinco páginas.',
            'review': 'Las páginas están listas. Revisa su legibilidad antes de registrar la revisión visual.',
            'error': 'No se pudo completar la ejecución simulada. El coste total no está disponible.',
            'cancelled': 'Ejecución simulada cancelada. No se iniciarán nuevos pasos.'}.get(current,
            'Entregable disponible. Consulta el alcance de cada comprobación.')
    documents = [] if current in ('active', 'error', 'cancelled') else [artifact(scenario, current != 'review')]
    result = {'success': status == 'completed', 'status': status, 'receipt': value}
    if current == 'error':
        result['error'] = 'La investigación está deshabilitada. No se han consultado fuentes. Actívala en la configuración autorizada antes de reintentar.'
    return {'run': run_data(scenario, status), 'result': result,
            'events': [{'id': 1, 'kind': status, 'data': {'text': text}}],
            'artifacts': documents, 'current_revision': documents[0] if documents and current != 'review' else None,
            'export': None, 'export_enabled': False}


def render_page(scenario):
    user = NS(username='Vista previa local', email='offline@example.invalid', is_authenticated=True,
              profile=NS(company=NS(name='Entorno sintético sin base de datos'), avatar=None))
    engine = NS(id=1, display_name='Proveedor simulado', engine=NS(connector_type='openai', provider='Offline', get_connector_type_display='Sin red'))
    model = NS(id=1, name='Modelo de prueba', model_id='synthetic-model', supports_vision=False)
    history = []
    if scenario != 'empty':
        history = [NS(role='user', blocked=False, content='Crea un informe de consultoría de cinco páginas sobre el impacto de la computación cuántica en la ciberseguridad.',
                      request_record=NS(request_id=RUN, status='completed', decision={'policy': {'status': 'allowed'}}))]
    request = NS(user=user, resolver_match=NS(url_name='chat'))
    conversation = None if scenario == 'empty' else NS(id=55, get_title='Informe de ciberseguridad', updated_at=NOW)
    return render_to_string('chat/chat.html', {
        'user': user, 'request': request, 'agent_available': True, 'agent_mode': scenario != 'empty',
        'agent_initial': None if scenario == 'empty' else run_data(scenario, 'active'),
        'conversation': conversation, 'messages': history, 'conversations': [conversation] if conversation else [],
        'available_engines': [engine], 'current_engine': engine, 'available_models': [model], 'current_model': model,
        'csrf_token': 'synthetic-only', 'automatic_routing': False,
    })


class Handler(BaseHTTPRequestHandler):
    def send(self, body, content_type='application/json', status=200, download=None):
        body = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        if download:
            self.send_header('Content-Disposition', f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def json(self, value, status=200):
        self.send(json.dumps(value, ensure_ascii=False), status=status)

    def do_GET(self):
        url = urlsplit(self.path)
        route = url.path
        if route in ('/', '/chat/'):
            scenario = parse_qs(url.query).get('state', ['empty'])[0]
            if scenario not in ('empty', 'active', 'review', 'completed', 'error', 'deck', 'overloaded'):
                return self.json({'error': 'Unknown visual scenario'}, 404)
            states.pop(scenario, None)
            return self.send(render_page(scenario), 'text/html; charset=utf-8')
        if route.startswith('/static/'):
            source = (STATIC / route.removeprefix('/static/')).resolve()
            if not source.is_relative_to(STATIC.resolve()) or not source.is_file():
                return self.send(b'', status=404)
            return self.send(source.read_bytes(), mimetypes.guess_type(source.name)[0] or 'application/octet-stream')
        match = re.fullmatch(r'/preview/status/([a-z]+)/', route)
        if match:
            return self.json(snapshot(match[1]))
        if route.startswith('/preview/events/'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            try:
                for _ in range(60):
                    self.wfile.write(b': local visual fixture heartbeat\n\n')
                    self.wfile.flush()
                    time.sleep(1)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            return
        match = re.fullmatch(r'/chat/agent/artifacts/([0-9a-f-]+)/(pages/(\d+)|download)/', route)
        if match and match[1] in (DOC, DECK):
            group = 'deck' if match[1] == DECK else 'report'
            if match[3]:
                source = ARTIFACTS / group / f'page-{int(match[3])}.png'
                return self.send(source.read_bytes(), 'image/png') if source.is_file() else self.send(b'', status=404)
            fmt = parse_qs(url.query).get('format', ['pptx' if group == 'deck' else 'docx'])[0]
            if fmt not in ('docx', 'pdf', 'pptx'):
                return self.send(b'', status=404)
            source = ARTIFACTS / group / f'final.{fmt}'
            return self.send(source.read_bytes(), mimetypes.guess_type(source.name)[0] or 'application/octet-stream', download=source.name) if source.is_file() else self.send(b'', status=404)
        return self.send(b'', status=404)

    def do_POST(self):
        raw = self.rfile.read(min(int(self.headers.get('Content-Length', 0)), 65536))
        route = urlsplit(self.path).path
        if route.startswith('/preview/cancel/'):
            states[route.strip('/').split('/')[-1]] = 'cancelled'
            return self.json({'status': 'cancelled'})
        if route == f'/chat/agent/artifacts/{DOC}/review/':
            states['review'] = 'completed'
            return self.json({'status': 'reviewed'})
        if route in ('/chat/send/', '/chat/55/send/'):
            states['active'] = 'active'
            return self.json({'success': True, 'status': 'processing', 'conversation_id': 55,
                              'receipt': receipt(), 'agent': run_data('active', 'active')})
        if route == '/chat/agent/documents/search/':
            return self.json({'documents': []})
        return self.json({'error': 'This fixture does not perform this operation'}, 400)

    def log_message(self, pattern, *args):
        print(pattern % args, flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8765)
    arguments = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', arguments.port), Handler)
    print(f'SIMULATED UI ONLY: http://127.0.0.1:{arguments.port}/chat/?state=empty', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
