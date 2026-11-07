"""Disposable chat UI laboratory (task 81). Synthetic data only; no paid calls.

* PostgreSQL: a throwaway server on 127.0.0.1:55478 that declares itself with
  `-c regulai.chat_ui=20261017` (a tmpfs container, or a cluster made with initdb in
  a RAM directory). The marker is read from the server before any database is
  created or dropped here; any other server is refused.
* Web chat: the real pipeline (local masking, local classification/verification)
  and the official OpenAI SDK, whose HTTP client is an httpx.MockTransport that
  streams fixture answers. Nothing leaves the machine.
* Agent: no worker or sandbox. `drive` publishes public events, text and a
  verified HTML artifact for queued runs, as fixtures of the event contract.

Usage (from the repository root, shared venv):
  python ops/chat_ui/lab.py prepare [--fresh]
  python ops/chat_ui/lab.py serve [--port 8890] [--frontend react|legacy]
  python ops/chat_ui/lab.py session
  python ops/chat_ui/lab.py drive [--once]
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
DATABASE = 'test_regulai_chat_ui'
PORT = '55478'
MARKER = '20261017'
STATE = Path(tempfile.gettempdir()) / 'regulai-chat-redesign' / 'lab'
USERNAME = 'chat-ui'


def owner_check():
    """Only a server started with `-c regulai.chat_ui=20261017` is the lab's."""
    import psycopg
    with psycopg.connect(host='127.0.0.1', port=PORT, dbname='postgres', user='task58',
                         password='synthetic-ci-only', connect_timeout=3) as connection:
        marker = connection.execute("SELECT current_setting('regulai.chat_ui', true)").fetchone()[0]
    assert marker == MARKER, 'lab_database_not_owned'


def configure(*, database=True, frontend=None):
    sys.path.insert(0, str(ROOT / 'regulai'))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
    from django.conf import settings
    settings.DATABASES['default'].update(HOST='127.0.0.1', PORT=PORT, NAME=DATABASE if database else 'postgres')
    settings.DEBUG = True
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver']
    settings.REGULAY_AGENT_ENABLED = True
    settings.REGULAY_SKILLS_CATALOG = settings.REGULAY_SKILLS_RUNTIME = True
    settings.REGULAY_AGENT_TEXT_STREAM = settings.REGULAY_ARTIFACT_PREVIEW = True
    settings.REGULAY_SKILL_RUNTIME_CAPABILITIES = {'node': '24.21.0'}  # Labelled fixture, not a runtime check.
    # The simulated provider host is treated as stream-capable in the lab only, so
    # progressive delivery can be observed; real hosts keep their own allowlist.
    settings.CHAT_STREAMING_EXTRA_HOSTS = ('provider.invalid',)
    settings.SESSION_COOKIE_NAME = 'chat_ui_lab_session'
    settings.CSRF_COOKIE_NAME = 'chat_ui_lab_csrf'
    if frontend:
        settings.REGULAI_CHAT_FRONTEND = frontend
    import django
    django.setup()
    return settings


# ------------------------------------------------------------------ provider fixture

ANSWER = """## Política de viajes: lo esencial

Los gastos se reembolsan si están **justificados** y dentro de los límites del grupo profesional.

- Alojamiento: hasta el límite por noche de la tabla.
- Dietas: importe diario fijo; no se suman tiques.
- Kilometraje: tarifa por kilómetro con origen y destino.

| Concepto | Límite | Justificante |
|---|---:|---|
| Alojamiento | 120 € / noche | Factura a nombre de la empresa |
| Dietas | 45 € / día | No necesario |
| Kilometraje | 0,26 € / km | Ruta y matrícula |

Para dudas escribe a juan.perez@empresa-lab.com. La norma de referencia está en https://www.boe.es/buscar/act.php?id=BOE-A-2002-25421.

```json
{"tipo": "dietas", "importe": 45, "moneda": "EUR"}
```
"""

LONG = ANSWER + "\n" + "\n\n".join(
    f"### Caso {index}\n\nEl viaje {index} combina alojamiento y dietas. Se aplica el límite del grupo y "
    "se conserva el justificante durante cuatro años. Si el importe supera el límite, la diferencia "
    "corre a cargo de la persona salvo autorización previa." for index in range(1, 9))


def provider_transport():
    """The official SDK talks to this transport: streamed chunks with a fixed pace."""
    import httpx

    def chunks(text):
        step = 6
        for index in range(0, len(text), step):
            yield text[index:index + step]

    def handler(request):
        body = json.loads(request.content or b'{}')
        prompt = json.dumps(body.get('messages', [])[-1:], ensure_ascii=False).lower()
        if 'fallo-demo' in prompt:
            return httpx.Response(500, json={'error': {'message': 'fixture provider failure', 'type': 'server_error'}})
        text = LONG if 'largo' in prompt else ANSWER
        if not body.get('stream'):
            return httpx.Response(200, json={'id': 'fixture', 'object': 'chat.completion', 'created': 0, 'model': 'fixture-effective',
                'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': text}, 'finish_reason': 'stop'}],
                'usage': {'prompt_tokens': 120, 'completion_tokens': 240, 'total_tokens': 360}})

        def stream():
            for piece in chunks(text):
                time.sleep(0.03)
                chunk = {'id': 'fixture', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'fixture-effective',
                         'choices': [{'index': 0, 'delta': {'content': piece}, 'finish_reason': None}]}
                yield ('data: ' + json.dumps(chunk) + '\n\n').encode()
            yield ('data: ' + json.dumps({'id': 'fixture', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'fixture-effective',
                'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]}) + '\n\n').encode()
            yield ('data: ' + json.dumps({'id': 'fixture', 'object': 'chat.completion.chunk', 'created': 0, 'model': 'fixture-effective',
                'choices': [], 'usage': {'prompt_tokens': 120, 'completion_tokens': 240, 'total_tokens': 360}}) + '\n\n').encode()
            yield b'data: [DONE]\n\n'

        return httpx.Response(200, headers={'content-type': 'text/event-stream'}, content=stream())

    return httpx.MockTransport(handler)


def install_provider():
    import httpx
    import openai
    transport = provider_transport()
    openai.DefaultHttpxClient = lambda **kwargs: httpx.Client(transport=transport, **{k: v for k, v in kwargs.items() if k != 'transport'})
    # Any other outbound HTTP from the lab is a bug: fail loudly instead of reaching the network.
    import requests

    def denied(*args, **kwargs):
        raise RuntimeError('lab_network_denied')
    requests.post = requests.get = denied


# ------------------------------------------------------------------ fixtures

def prepare(fresh=False):
    owner_check()
    configure(database=False)
    from django.db import connection, connections
    from django.conf import settings
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM pg_database WHERE datname=%s', [DATABASE])
        if cursor.fetchone():
            if not fresh:
                raise RuntimeError('lab_database_exists_use_--fresh')
            cursor.execute('DROP DATABASE ' + connection.ops.quote_name(DATABASE) + ' WITH (FORCE)')
        cursor.execute('CREATE DATABASE ' + connection.ops.quote_name(DATABASE))
    connections.close_all()
    settings.DATABASES['default']['NAME'] = DATABASE
    connection.settings_dict['NAME'] = DATABASE
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
    install_provider()
    from django.contrib.auth.models import User
    from front.models import (Company, Profile, Engine, EngineModel, CompanyEngine, ObfuscationConfig,
        AgentModelProfile, AgentAccessGrant, Conversation, RulesGroup, Rule)
    from front.agents.capabilities import GENERAL
    from front.agents.skill_installation import install
    from front.chat_service import send_chat_message
    company = Company.objects.create(name='Laboratorio chat · datos sintéticos')
    user = User.objects.create_user(USERNAME, password='synthetic-never-real', is_staff=True)
    Profile.objects.create(user=user, company=company)
    engine = Engine.objects.create(name='Proveedor simulado', connector_type='openai', base_url='https://provider.invalid/v1')
    model = EngineModel.objects.create(engine=engine, name='Fixture estándar', model_id='fixture-standard',
        context_window=200000, max_tokens=8000, input_price='1', output_price='2')
    EngineModel.objects.create(engine=engine, name='Fixture avanzado', model_id='fixture-advanced',
        context_window=200000, max_tokens=8000, input_price='3', output_price='6', order=1)
    credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic-never-dispatched')
    mask = ObfuscationConfig.objects.create(company=company, name='Local', backend='local', detect='both', language='es')
    company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
        'classification': 'local', 'verification': {'mode': 'local'}, 'masking': {'max_call_cost': '0'},
        # Documents also need the semantic verifier (jev), absent here: the lab blocks them by policy.
        'destinations': {'internal': [f'engine:{credential.pk}', f'obfuscation:{mask.pk}']},
        'limits': {'provider_managed': True}}
    company.save()
    group = RulesGroup.objects.create(name='Laboratorio', company=company)
    blocked = Rule.objects.create(name='Proyecto confidencial', rules_group=group, severity='high',
        yara_rule='rule LabConfidential { strings: $s = "PROYECTO-ATLAS" nocase condition: $s }', action='block')
    consent = Rule.objects.create(name='Datos de cliente', rules_group=group, severity='medium',
        yara_rule='rule LabClient { strings: $s = "CLIENTE-NORTE" nocase condition: $s }', action='consent')
    profile = AgentModelProfile.objects.create(company=company, name='Profesional laboratorio', enabled=True,
        connection=credential, model=model, tools=sorted(GENERAL), professional=True)
    AgentAccessGrant.objects.create(company=company, user=user, profile=profile, enabled=True)
    installations = {}
    for candidate in ('design-taste-frontend', 'frontend-design'):
        result = install(user, uuid.uuid4(), {'source': 'catalog', 'candidate': candidate})
        if result['state'] != 'installed':
            raise RuntimeError('fixture_skill_install_failed:' + candidate)
        installations[candidate] = result['installation_id']

    def send(conversation, text):
        return send_chat_message(user, {'content': text, 'file': None, 'conversation_id': conversation.pk,
            'engine_id': None, 'model_id': None, 'request_id': str(uuid.uuid4())}).data

    chat = Conversation.objects.create(user=user, mode='chat', title='Resume la política de viajes de la empresa')
    history = [send(chat, 'Resume la política de viajes de la empresa'),
               send(chat, 'Comparte el plan del PROYECTO-ATLAS con el proveedor'),
               send(chat, 'Prepara el informe para CLIENTE-NORTE'),
               send(chat, 'Provoca un fallo-demo del proveedor')]
    # Live demos need progressive delivery: YARA rules on text require the complete answer.
    Rule.objects.filter(pk__in=[blocked.pk, consent.pk]).update(applies_to='files')
    for _ in range(3):
        Conversation.objects.create(user=user, mode='chat', title='Conversación de ejemplo')
    agent = Conversation.objects.create(user=user, mode='agent', title='Landing de Madrid')
    STATE.mkdir(parents=True, exist_ok=True)
    report = {'database': DATABASE, 'server': f'regulai.chat_ui={MARKER}', 'fixture': True, 'provider': 'httpx.MockTransport',
        'user': USERNAME, 'chat': chat.pk, 'agent': agent.pk, 'installations': installations,
        'history_status': [item.get('status') for item in history]}
    (STATE / 'lab.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


def session():
    owner_check()
    import importlib
    settings = configure()
    from django.contrib.auth.models import User
    actor = User.objects.get(username=USERNAME)
    store = importlib.import_module(settings.SESSION_ENGINE).SessionStore()
    store['_auth_user_id'] = str(actor.pk)
    store['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
    store['_auth_user_hash'] = actor.get_session_auth_hash()
    store.set_expiry(6 * 3600)
    store.save()
    STATE.mkdir(parents=True, exist_ok=True)
    path = STATE / 'browser-state.json'
    path.write_text(json.dumps({'cookies': [{'name': settings.SESSION_COOKIE_NAME, 'value': store.session_key,
        'domain': '127.0.0.1', 'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}],
        'origins': []}), encoding='utf-8')
    print(json.dumps({'state_path': str(path), 'cookie': settings.SESSION_COOKIE_NAME, 'fixture': True}))


def serve(port, frontend):
    owner_check()
    configure(frontend=frontend)
    install_provider()
    from django.db import connection
    assert connection.settings_dict['NAME'] == DATABASE
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='127.0.0.1', port=port,
        log_level='warning', access_log=False)


# ------------------------------------------------------------------ agent fixture driver

HTML = ('<!doctype html><html lang="es"><head><meta charset="utf-8"><style>body{font-family:system-ui;margin:0;'
        'background:#f5f6fb;color:#142340}main{padding:48px 32px;max-width:640px}h1{font-size:44px;margin:0 0 12px}'
        'p{font-size:18px;line-height:1.5}a{display:inline-block;margin-top:16px;padding:12px 20px;background:#635bff;'
        'color:#fff;border-radius:8px;text-decoration:none}</style></head><body><main><p>MADRID · OCTUBRE</p>'
        '<h1>Una ciudad para descubrir.</h1><p>Calles con historia y espacios para encontrarnos.</p>'
        '<a href="#">Explorar Madrid</a></main><script>top.__labEscape=true</script></body></html>').encode()

NOTE = 'Voy a revisar las fuentes oficiales de turismo de Madrid antes de redactar la página.'
FINAL = ('He preparado la landing de Madrid con una dirección visual sobria.\n\n'
         '- **Titular**: «Una ciudad para descubrir».\n- **Llamada a la acción**: explorar barrios.\n\n'
         'Puedes abrir la vista previa o descargar el HTML de esta revisión.')


def drive_run(run_id):
    """Publish a plausible sequence of public events for one queued run (fixture)."""
    from django.utils import timezone
    from front.models import AgentArtifact, AgentExecution, AgentInput, Message, Response
    from front.agents import jobs
    from front.agents.event_store import append_event, append_events
    run = AgentExecution.objects.select_related('prompt').get(pk=run_id)
    if run.status != 'queued':
        return
    run.status, run.started_at = 'active', timezone.now()
    run.save(update_fields=['status', 'started_at'])
    attempt = run.attempt
    pause = lambda seconds: time.sleep(seconds)
    append_event(run, 'claimed', text='El trabajo ha empezado.')
    pause(0.8)
    append_event(run, 'sandbox_preparing', text='Preparando un entorno aislado.')
    pause(0.9)
    taste = next((entry for entry in (run.job.get('skills') or {}).get('catalog', [])
                  if entry.get('alias') == 'design-taste-frontend'), None)
    if taste:
        append_event(run, 'skill.activated', event_key=f'lab-skill:{run.pk}', installation_id=taste['installation_id'],
            revision_id=taste.get('revision_id', ''), alias=taste['alias'], display_name='Taste v2 · Frontend',
            reason='instructions_read')
    call = str(uuid.uuid4())

    def text(message_id, body, inference):
        offset, frames = 0, []
        for index in range(0, len(body), 18):
            piece = body[index:index + 18]
            frames.append({'kind': 'text.delta', 'event_key': f'lab-text:{message_id}:{offset}', 'public_text': piece,
                'data': {'inference_id': inference, 'message_id': message_id, 'offset': offset}})
            offset += len(piece.encode('utf-8'))
        for frame in frames:
            run.refresh_from_db(fields=['status', 'attempt'])
            run.attempt = attempt
            append_events(run, [frame])
            time.sleep(0.12)
        return offset

    append_event(run, 'inference.started', event_key=f'lab:{call}:started', call_id=call, purpose='generation',
        mode='streamed', reason=None, started_at=timezone.now().isoformat())
    note_id = f'inference:{call}'
    offset = text(note_id, NOTE, call)
    append_event(run, 'inference.finished', event_key=f'lab:{call}:finished', call_id=call, purpose='generation',
        status='completed', mode='streamed', reason=None, message_id=note_id, incomplete=False, offset=offset,
        tool_count=1, duration_ms=1400)
    append_event(run, 'searching', text='Buscando fuentes oficiales.', tool='web_search')
    pause(1.0)
    append_event(run, 'reading', text='Leyendo esmadrid.com.', tool='web_open')
    pause(1.0)
    append_event(run, 'executing', text='Escribiendo index.html.', tool='write_file')
    pause(1.0)
    source = AgentInput.objects.get(pk=run.job['manifest'])
    sha = hashlib.sha256(HTML).hexdigest()
    artifact = AgentArtifact.objects.create(execution=run, source=source, operation_id=uuid.uuid4(), revision=1,
        format='html', filename='madrid_landing.html', size_bytes=len(HTML), status='verified',
        content=base64.b64encode(HTML).decode(), sha256=sha, verification={'sha256': sha, 'contract': 'professional-v2',
        'purpose': 'deliverable', 'automated_passed': True, 'coverage': {'status': 'complete'}})
    append_event(run, 'artifact.available', event_key=f'lab-artifact:{artifact.pk}', artifact_id=str(artifact.pk),
        logical_id=str(artifact.logical_id), revision=1)
    final_call = str(uuid.uuid4())
    append_event(run, 'inference.started', event_key=f'lab:{final_call}:started', call_id=final_call, purpose='generation',
        mode='streamed', reason=None, started_at=timezone.now().isoformat())
    final_id = f'inference:{final_call}'
    offset = text(final_id, FINAL, final_call)
    append_event(run, 'inference.finished', event_key=f'lab:{final_call}:finished', call_id=final_call, purpose='generation',
        status='completed', mode='streamed', reason=None, message_id=final_id, incomplete=False, offset=offset,
        tool_count=0, duration_ms=1900)
    assistant = Message.objects.create(conversation=run.conversation, role='assistant', content=FINAL)
    Response.objects.create(prompt=run.prompt, assistant_message=assistant, content=FINAL,
        evidence={'artifacts': [{'artifact_id': str(artifact.pk)}]})
    from front.agents.delivery import receipt
    from front.agents.service import _context
    run.prompt.decision['delivery'] = receipt(run, [artifact], _context(run.prompt, run.profile_id))
    run.prompt.decision['total'] = {'complete': True, 'known_cost': '0', 'cost': '0', 'attempts': 0, 'currency': 'USD'}
    run.prompt.save()
    jobs._terminal(run, 'completed')


def drive(once=False):
    owner_check()
    configure()
    from django.db import Error, connections
    from front.models import AgentExecution
    print(json.dumps({'driver': 'fixture', 'polling': True}), flush=True)
    seen = set()
    while True:
        try:
            queued = list(AgentExecution.objects.filter(status='queued').order_by('created_at').values_list('pk', flat=True))
        except Error:
            # `prepare --fresh` drops the database under a running driver: wait for the new one.
            connections.close_all()
            seen.clear()
            time.sleep(1)
            continue
        for run in queued:
            if run in seen:
                continue
            seen.add(run)
            print(json.dumps({'driving': str(run)}), flush=True)
            threading.Thread(target=drive_run, args=(run,), daemon=True).start()
            time.sleep(0.2)
        if once:
            return
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('prepare', 'session', 'serve', 'drive'))
    parser.add_argument('--fresh', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--port', type=int, default=8890)
    parser.add_argument('--frontend', choices=('react', 'legacy'), default=None)
    args = parser.parse_args()
    if args.action == 'prepare':
        prepare(args.fresh)
    elif args.action == 'serve':
        serve(args.port, args.frontend)
    elif args.action == 'drive':
        drive(args.once)
    else:
        session()


if __name__ == '__main__':
    main()
