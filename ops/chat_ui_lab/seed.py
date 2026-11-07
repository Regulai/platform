"""Seed the chat UI lab with synthetic accounts, policy, conversations and agent runs.

Lab database only (regulai.ui_lab_settings). Normal chat turns go through the real
send pipeline against the loopback simulator, so receipts are produced by the
application. Agent runs cannot execute here (no worker or sandbox); their recorded
state is written directly and reuses the task-55 rendered fixture documents.

    python ops/chat_ui_lab/seed.py --reset      # simulator must be running first

Synthetic sign-in (lab only): lab-user / lab-pro / lab-admin, password below.
EASY_ADMIN is a deliberately trivial administrator for trying the lab by hand: company
admin, staff and superuser, with the document agent and its own copy of every demo
conversation. Loopback lab database only; never reuse these values anywhere else.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.ui_lab_settings')
LAB_PASSWORD = 'lab-ui-synthetic-2026'
EASY_ADMIN = {'username': 'admin', 'password': 'admin'}  # lab only, see the docstring
FIXTURES = ROOT / 'evals/reports/task55-agent-documents-20261013'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reset', action='store_true')
    arguments = parser.parse_args()
    from django.conf import settings
    database = Path(settings.DATABASES['default']['NAME'])
    if settings.SETTINGS_MODULE != 'regulai.ui_lab_settings' or not database.resolve().is_relative_to(settings.LAB_DIR.resolve()):
        raise SystemExit('Refusing to seed anything but the UI lab database.')
    if arguments.reset and database.exists():
        database.unlink()
    import django
    django.setup()
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
    from front import jev
    jev.ENDPOINT = jev.VERCEL_ENDPOINT = settings.UI_LAB_PROVIDER_URL + '/jev'
    seed(settings)
    print(f'Lab ready: {database}')


def seed(settings):
    from django.contrib.auth.models import User
    from django.utils import timezone
    from front.ai_connections import BASIC_RULE
    from front.models import (Company, CompanyEngine, Engine, EngineModel, ObfuscationConfig, Profile, Role,
                              Rule, RulesGroup, AgentModelProfile, AgentAccessGrant, Conversation, Message)
    from front.agents.capabilities import GENERAL

    company = Company.objects.create(name='Laboratorio UI · sintético', jev_api_key='lab-synthetic-jev')
    admin_role, _ = Role.objects.get_or_create(name='Admin')
    users = {}
    for name, role in (('lab-user', None), ('lab-pro', None), ('lab-admin', admin_role)):
        user = User.objects.create_user(name, f'{name}@lab.invalid', LAB_PASSWORD, first_name=name.split('-')[1].title())
        Profile.objects.create(user=user, company=company, role=role)
        users[name] = user

    provider = settings.UI_LAB_PROVIDER_URL
    engine = Engine.objects.create(name='Proveedor simulado', provider='Laboratorio',
                                   connector_type='openai_compatible', base_url=provider + '/v1')
    fast = EngineModel.objects.create(engine=engine, name='Lab Rápido', model_id='lab-fast', max_tokens=4096,
        context_window=128000, supports_json=True, input_price='0.15', output_price='0.60', order=1,
        price_date=timezone.now().date())
    EngineModel.objects.create(engine=engine, name='Lab Preciso', model_id='lab-precise', max_tokens=4096,
        context_window=128000, supports_json=True, input_price='1.00', output_price='4.00', order=2,
        price_date=timezone.now().date())
    claude = Engine.objects.create(name='Proveedor simulado (Messages)', provider='Laboratorio',
                                   connector_type='anthropic', base_url=provider)
    EngineModel.objects.create(engine=claude, name='Lab Messages', model_id='lab-messages', max_tokens=4096,
        context_window=128000, supports_json=True, input_price='0.80', output_price='4.00', order=1,
        price_date=timezone.now().date())
    connection = CompanyEngine.objects.create(company=company, engine=engine, api_key='lab-synthetic-key')
    second = CompanyEngine.objects.create(company=company, engine=claude, api_key='lab-synthetic-key')
    mask = ObfuscationConfig.objects.create(company=company, name='Privacidad local', backend='local',
                                            detect='both', language='es')
    group = RulesGroup.objects.create(company=company, name='Protección básica del chat')
    Rule.objects.create(rules_group=group, name='Credenciales y claves privadas', yara_rule=BASIC_RULE,
                        severity='critical', action='block', applies_to='both')
    Rule.objects.create(rules_group=group, name='Información confidencial de clientes', severity='medium',
        description='Confirma antes de enviar contenido marcado como confidencial.', action='consent', applies_to='both',
        yara_rule='rule lab_confidencial { strings: $a = "texto confidencial del cliente" nocase condition: $a }')
    destinations = [f'engine:{connection.pk}', f'engine:{second.pk}', f'obfuscation:{mask.pk}', 'jev']
    company.ai_config = {'version': 1, 'local_sensitivity': 'internal',
        'destinations': {'public': destinations, 'internal': destinations, 'confidential': [], 'restricted': [], 'unknown': []},
        'masking': {'max_call_cost': '0'}, 'routing': {'mode': 'manual', 'max_output_tokens': 1000},
        'classification': 'local', 'verification': {'mode': 'local'}}
    company.save()
    for user in users.values():
        Profile.objects.filter(user=user).update(default_engine=connection, default_model=fast)

    documents = AgentModelProfile.objects.create(company=company, name='Documentos (lab)', enabled=True,
        connection=connection, model=fast, tools=['build_document', 'edit_document', 'export_pdf', 'build_presentation',
        'edit_presentation', 'build_excel', 'rename_excel', 'create_mock_excel', 'research_sources', 'save_revision'])
    professional = AgentModelProfile.objects.create(company=company, name='Profesional (lab)', enabled=True,
        connection=connection, model=fast, tools=sorted(GENERAL), professional=True)
    AgentAccessGrant.objects.create(company=company, user=users['lab-user'], profile=documents, enabled=True)
    AgentAccessGrant.objects.create(company=company, user=users['lab-pro'], profile=professional, enabled=True)

    chat_conversations(users['lab-user'])
    legacy = Conversation.objects.create(user=users['lab-user'], title='Conversación antigua (sin registro)')
    Message.objects.create(conversation=legacy, role='user', content='Mensaje anterior a los registros de decisión.')
    Message.objects.create(conversation=legacy, role='assistant', content='Respuesta histórica sin registro validado.')
    agent_runs(users['lab-user'], documents, connection, fast)
    professional_run(users['lab-pro'], professional, connection, fast)

    # Created last so the numbered demo conversations above keep their ids.
    admin = User.objects.create_user(EASY_ADMIN['username'], 'admin@lab.invalid', EASY_ADMIN['password'],
                                     first_name='Admin', is_staff=True, is_superuser=True)
    Profile.objects.create(user=admin, company=company, role=admin_role, default_engine=connection, default_model=fast)
    AgentAccessGrant.objects.create(company=company, user=admin, profile=documents, enabled=True)
    print('Easy administrator account (lab only):')
    chat_conversations(admin)
    agent_runs(admin, documents, connection, fast)


def send(user, text, conversation=None, **extra):
    from front.chat_service import send_chat_message
    command = {'content': text, 'request_id': str(uuid.uuid4()), 'conversation_id': conversation, **extra}
    result = send_chat_message(user, command)
    print(f"  · {result.data.get('status'):<16} {text[:60]}")
    return result.data


def chat_conversations(user):
    from django.core.files.uploadedfile import SimpleUploadedFile
    print('Chat conversations through the real pipeline:')
    first = send(user, 'Resume la política de viajes de 2026 con una tabla de límites')
    conversation = first['conversation_id']
    send(user, 'hola, ¿qué puedes hacer?', conversation)
    send(user, 'Dame el correo del responsable de compras', conversation)
    long = send(user, 'Prepara un informe largo de seguimiento por secciones')
    for index in range(8):
        send(user, f'Continúa con el detalle {index + 1}', long['conversation_id'])
    send(user, 'Mi api_key = sk-proj-ABCDEFGHIJKLMNOPQRSTUV1234 no funciona, ¿qué hago?')
    send(user, 'Revisa este texto confidencial del cliente Norte antes de enviarlo')
    send(user, 'Escribe una respuesta corta sobre la reunión')  # 'corta' -> truncated by provider
    send(user, 'Provoca un error del proveedor')
    upload = SimpleUploadedFile('acta-reunion.txt', ('Acta de la reunión del comité de compras.\n'
        'Se aprueba el presupuesto de 2026 para equipos portátiles.\n'
        'El plazo de entrega acordado es de diecisiete días laborables.\n').encode('utf-8'), content_type='text/plain')
    pending = send(user, '¿Qué plazo de entrega se acordó?', file=upload)
    if pending.get('status') == 'pending_consent' and pending.get('consent_token'):
        upload.seek(0)
        send(user, '¿Qué plazo de entrega se acordó?', None, file=upload,
             request_id=pending['request_id'], consent_token=pending['consent_token'])


def receipt(prompt, connection, model, calls=3, status='completed'):
    from django.utils import timezone
    from front.agents.service import _jev_receipt
    from front.policy import AIConfig
    cfg = AIConfig.model_validate(prompt.company.ai_config)
    now = timezone.now()
    rows = []
    for index in range(calls):
        rows.append({'sequence': index + 1, 'purpose': 'generation', 'status': status if index == calls - 1 else 'completed',
            'provider': f'engine:{connection.pk}', 'provider_name': 'openai_compatible', 'model': model.model_id,
            'model_requested': model.model_id, 'model_effective': model.model_id,
            'route': {'mode': 'agent_profile', 'destination': f'engine:{connection.pk}', 'connector': 'openai_compatible'},
            'fallback': {'status': 'not_used', 'reason': 'agent_profile_pinned'},
            'started_at': (now - timedelta(seconds=40 - index * 9)).isoformat(), 'completed_at': (now - timedelta(seconds=34 - index * 9)).isoformat(),
            'duration_ms': 5200 + index * 700, 'cost': '0.0021', 'currency': 'USD', 'cost_kind': 'tariff_estimate',
            'transport': 'http', 'input_tokens': 2400, 'output_tokens': 610})
    known = sum(float(row['cost']) for row in rows if row['status'] == 'completed')
    return {'schema_version': 1, 'input_digest': '0' * 64, 'calls': rows,
        'policy': {'status': 'allow', 'reason_codes': ['local_policy_allowed'], 'sensitivity': 'internal',
                   'allowed_destinations': [], 'rules': [], 'fingerprint': '', 'source': 'local_policy'},
        'jev': _jev_receipt(prompt.user.profile, cfg),
        'route': {'mode': 'agent_profile', 'company_engine_id': connection.pk, 'model': model.model_id,
                  'reason': 'explicit_agent_profile', 'fallback': 'disabled'},
        'total': {'known_cost': f'{known:.4f}', 'cost': f'{known:.4f}' if status == 'completed' else None,
                  'currency': 'USD', 'complete': status == 'completed', 'attempts': calls}}


def new_run(user, profile, text, status, job, *, minutes_ago=5):
    from django.utils import timezone
    from front.models import AgentExecution, Conversation, Message, Prompt
    from front.agents.service import _context
    conversation = Conversation.objects.create(user=user, mode='agent', title=text[:50])
    message = Message.objects.create(conversation=conversation, role='user', content=text)
    prompt = Prompt.objects.create(user=user, company=user.profile.company, conversation=conversation,
        user_message=message, content=text, status='processing', decision={'schema_version': 1, 'calls': []})
    run = AgentExecution.objects.create(prompt=prompt, profile=profile, token_digest=uuid.uuid4().hex + uuid.uuid4().hex,
        authorization_digest=_context(prompt, profile.pk)[-1], conversation=conversation, status=status,
        expires_at=timezone.now() + timedelta(minutes=55), started_at=timezone.now() - timedelta(minutes=minutes_ago),
        finished_at=None if status in ('queued', 'active') else timezone.now(), job=job)
    Prompt.objects.filter(pk=prompt.pk).update(status={'active': 'processing', 'queued': 'received',
        'interrupted': 'outcome_unknown'}.get(status, status))
    prompt.refresh_from_db()
    return run, prompt, conversation


def events(run, kinds, **data):
    from front.agents.jobs import event
    for kind in kinds:
        event(run, kind, **data)


def document_artifact(run, *, reviewed, revision=1, logical=None, kind='report'):
    from front.models import AgentArtifact, AgentInput
    folder = FIXTURES / kind
    pages = sorted(folder.glob('page-*.png'), key=lambda path: int(path.stem.split('-')[1]))
    fmt = 'docx' if kind == 'report' else 'pptx'
    final = (folder / f'final.{fmt}').read_bytes()
    pdf = (folder / 'final.pdf').read_bytes()
    bundle = {f'final.{fmt}': base64.b64encode(final).decode(), 'final.pdf': base64.b64encode(pdf).decode()}
    hashes = []
    for index, page in enumerate(pages, 1):
        raw = page.read_bytes()
        bundle[f'page-{index}.png'] = base64.b64encode(raw).decode()
        hashes.append(sha(raw))
    narrative = json.loads((FIXTURES / f'{kind}-fields.json').read_text(encoding='utf-8')).get('narrative')
    if narrative:
        raw_narrative = json.dumps(narrative, ensure_ascii=False, sort_keys=True).encode()
        source = AgentInput.objects.create(execution=run, kind='narrative', path=f'/workspace/input/narrative-{uuid.uuid4()}.json',
            original=base64.b64encode(raw_narrative).decode(), digest=sha(raw_narrative))
    else:
        raw_csv = b'item,amount_cents\nA,100\nB,200\nC,300\n'
        source = AgentInput.objects.create(execution=run, kind='csv', path='/workspace/input/source.csv',
            original=base64.b64encode(raw_csv).decode(), digest=sha(raw_csv))
    # Like document_jobs.candidate: the new input is policy text, so the run is re-bound
    # to the re-evaluated authorization (the visual review checks this binding).
    from front.agents.service import _context
    run.authorization_digest = _context(run.prompt, run.profile_id)[-1]
    run.save(update_fields=['authorization_digest'])
    proof = {'sha256': sha(final), 'pages': len(pages), 'page_sha256': hashes, 'automated_passed': True,
             'request_checked': True, 'narrative': bool(narrative), 'source_ids': ['nist-pqc'] if narrative else []}
    if fmt == 'docx':
        proof['pdf_sha256'] = sha(pdf)
    if reviewed:
        proof['visual_review'] = {'reviewer_id': run.prompt.user_id, 'reviewed_at': run.created_at.isoformat(),
                                  'sha256': sha(final), 'checks': ['legibility']}
    return AgentArtifact.objects.create(execution=run, logical_id=logical or uuid.uuid4(), revision=revision,
        source=source, operation_id=uuid.uuid4(), content=base64.b64encode(final).decode(), sha256=sha(final),
        format=fmt, render_bundle=json.dumps(bundle), status='verified' if reviewed else 'draft',
        verification=proof)


def complete(run, prompt, text):
    from django.utils import timezone
    from front.models import Message, Response
    message = Message.objects.create(conversation=run.conversation, role='assistant', content=text)
    Response.objects.create(prompt=prompt, assistant_message=message, content=text, evidence={})
    run.status, run.finished_at = 'completed', timezone.now()
    run.save(update_fields=['status', 'finished_at'])
    prompt.status = 'completed'
    prompt.save(update_fields=['status', 'decision'])


def agent_runs(user, profile, connection, model):
    from front.agents.request_contract import interpret
    print('Agent runs (recorded state, no worker):')
    text = 'Crea un informe de consultoría de cinco páginas en Word y PDF sobre computación cuántica y ciberseguridad'
    request = interpret(text, uploaded=False, base_format=None)
    run, prompt, _ = new_run(user, profile, text, 'active', {'kind': 'create', 'logical_id': str(uuid.uuid4()), 'base': None,
        'source': None, 'request': request})
    prompt.decision = receipt(prompt, connection, model, calls=3)
    events(run, ['queued', 'claimed', 'compose', 'render', 'verify'])
    artifact = document_artifact(run, reviewed=True)
    run.job['logical_id'] = str(artifact.logical_id)
    run.save(update_fields=['job'])
    events(run, ['visual_pending'], reference=str(artifact.pk))
    events(run, ['visual_reviewed'], reference=str(artifact.pk))
    complete(run, prompt, 'Documento disponible. Integridad, paginación y revisión visual registradas. '
             'Consulta las fuentes y los límites de verificación.')
    events(run, ['completed'])
    print('  · completed document run')

    text = 'Prepara una presentación de tres diapositivas con el plan de transición'
    run, prompt, _ = new_run(user, profile, text, 'active', {'kind': 'create', 'logical_id': str(uuid.uuid4()), 'base': None,
        'source': None, 'request': interpret(text, uploaded=False, base_format=None)})
    prompt.decision = receipt(prompt, connection, model, calls=2)
    prompt.save(update_fields=['decision'])
    events(run, ['queued', 'claimed', 'compose', 'render', 'verify'])
    artifact = document_artifact(run, reviewed=False, kind='deck')
    run.job['logical_id'] = str(artifact.logical_id)
    run.save(update_fields=['job'])
    events(run, ['visual_pending'], reference=str(artifact.pk))
    print('  · visual review pending run')

    text = 'Investiga las novedades regulatorias de este mes y crea un informe con fuentes'
    run, prompt, _ = new_run(user, profile, text, 'failed', {'kind': 'create', 'logical_id': str(uuid.uuid4()), 'base': None,
        'source': None, 'request': interpret(text, uploaded=False, base_format=None)})
    prompt.decision = receipt(prompt, connection, model, calls=1, status='failed')
    prompt.decision['error_type'] = 'agent_research_no_sources'
    prompt.status = 'failed'
    prompt.save(update_fields=['decision', 'status'])
    events(run, ['queued', 'claimed', 'failed'])
    print('  · failed run')

    text = 'Redacta un informe de dos páginas sobre la política de teletrabajo'
    run, prompt, _ = new_run(user, profile, text, 'active', {'kind': 'create', 'logical_id': str(uuid.uuid4()), 'base': None,
        'source': None, 'request': interpret(text, uploaded=False, base_format=None)}, minutes_ago=1)
    prompt.decision = receipt(prompt, connection, model, calls=1, status='started')
    prompt.save(update_fields=['decision'])
    events(run, ['queued', 'claimed', 'compose'])
    print(f'  · live run for the simulator: {run.pk}')


def professional_run(user, profile, connection, model):
    from django.utils import timezone
    from front.models import AgentInput, AgentOperation
    from front.policy import digest
    text = 'Investiga el consumo eléctrico de centros de datos en España y calcula la media con un script'
    request = {'formats': ['xlsx'], 'pages': None, 'language': 'es', 'research_required': True}
    run, prompt, _ = new_run(user, profile, text, 'active', {'kind': 'professional', 'logical_id': str(uuid.uuid4()),
        'base': None, 'source': None, 'request': request, 'limits': {}, 'private_data': False})
    prompt.decision = receipt(prompt, connection, model, calls=4)
    for index, (url, title) in enumerate((('https://www.ree.es/es/datos', 'Red Eléctrica · datos de demanda'),
                                          ('https://www.iea.org/reports/electricity-2026', 'IEA · Electricity 2026'))):
        value = {'url': url, 'final_url': url, 'title': title, 'retrieved_at': timezone.now().isoformat(),
                 'publication_date': '2026-09-30', 'updated_at': None, 'sha256': '0' * 64, 'extraction': 'complete',
                 'parts': [{'location': 'p1', 'text': 'Fuente simulada del laboratorio de interfaz. No acredita una lectura real.'}],
                 'read_ranges': [[0, 60]]}
        original = json.dumps(value, ensure_ascii=False)
        AgentInput.objects.create(execution=run, kind='web_source', path=f'web/{index}', original=original, digest=digest(original))
    for call, name in (('c1', 'web_search'), ('c2', 'web_open'), ('c3', 'execute'), ('c4', 'publish_artifact')):
        AgentOperation.objects.create(execution=run, call_id=call, name=name, request_digest='0' * 64,
            request=json.dumps({'id': call, 'name': name, 'args': {'command': 'python media.py'} if name == 'execute' else {}}),
            status='completed', completed_at=timezone.now())
    events(run, ['queued', 'claimed'])
    events(run, ['searching'], call_id='c1', tool='web_search')
    events(run, ['reading'], call_id='c2', tool='web_open')
    events(run, ['executing'], call_id='c3', tool='execute')
    events(run, ['verifying'], call_id='c4', tool='publish_artifact')
    complete(run, prompt, 'He consultado dos fuentes públicas y calculado la media con un script en el entorno aislado.\n\n'
             '| Fuente | Consumo (TWh) |\n| --- | ---: |\n| Red Eléctrica | 6,1 |\n| IEA | 5,8 |\n\n'
             'La media es **5,95 TWh**. Los valores son del laboratorio de interfaz y no proceden de una lectura real.')
    events(run, ['completed'])
    print('  · professional run with sources and operations')


if __name__ == '__main__':
    main()
