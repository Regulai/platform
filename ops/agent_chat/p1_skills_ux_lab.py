"""Owned synthetic Skills UX laboratory; never connects to real credentials.

Run prepare once, then serve. All three generation entries are rejected by the
existing UI-lab middleware. Runtime capability is a labelled fixture, not proof.
"""
import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-skills-ux-20261016'
DATABASE = 'test_regulai_p1_skills_ux'
PG_ID = '7c7f3560096bd5d988e77675855a0e065fdab98e45646195304e9e5c2024dbe1'
BASE = 'http://127.0.0.1:8873'


def owner_check():
    row = json.loads(subprocess.check_output(['rtk', 'proxy', 'docker', 'inspect',
        'regulai-p1-e1-db-20261016']))[0]
    assert row['Id'] == PG_ID and row['State']['Running']
    assert row['Config']['Labels'].get('regulai.p1_e1') == '20261016'
    assert row['HostConfig']['PortBindings']['5432/tcp'] == [
        {'HostIp': '127.0.0.1', 'HostPort': '55468'}]


def configure(*, database=True):
    sys.path.insert(0, str(ROOT / 'regulai'))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
    from django.conf import settings
    settings.DATABASES['default'].update(HOST='127.0.0.1', PORT='55468',
        NAME=DATABASE if database else 'postgres')
    settings.DEBUG = True
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver']
    settings.REGULAY_AGENT_ENABLED = True
    settings.REGULAY_SKILLS_CATALOG = settings.REGULAY_SKILLS_RUNTIME = True
    settings.REGULAY_AGENT_TEXT_STREAM = settings.REGULAY_ARTIFACT_PREVIEW = True
    settings.REGULAY_SKILL_RUNTIME_CAPABILITIES = {'node': '24.21.0'}
    settings.SESSION_COOKIE_NAME = 'p1_skills_ux_synthetic_session'
    settings.CSRF_COOKIE_NAME = 'p1_skills_ux_synthetic_csrf'
    settings.MIDDLEWARE = ['regulai.ui_lab_guard.RejectLabGeneration', *settings.MIDDLEWARE]
    import django
    django.setup()
    return settings


def prepare():
    owner_check()
    configure(database=False)
    from django.db import connection, connections
    from django.conf import settings
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM pg_database WHERE datname=%s', [DATABASE])
        if cursor.fetchone():
            raise RuntimeError('owned_database_already_exists_no_clobber')
        cursor.execute('CREATE DATABASE ' + connection.ops.quote_name(DATABASE))
    connections.close_all()
    settings.DATABASES['default']['NAME'] = DATABASE
    connection.settings_dict['NAME'] = DATABASE
    from django.core.management import call_command
    call_command('migrate', verbosity=0)
    from django.contrib.auth.models import User
    from front.models import (Company, Profile, Engine, EngineModel, CompanyEngine,
        ObfuscationConfig, AgentModelProfile, AgentAccessGrant, Conversation)
    from front.agents.capabilities import GENERAL
    from front.agents.skill_installation import install
    company = Company.objects.create(name='Skills UX · laboratorio sintético')
    user = User.objects.create_user('p1-skills-ux', password='synthetic-never-real')
    Profile.objects.create(user=user, company=company)
    engine = Engine.objects.create(name='Sin proveedor conectado', connector_type='openai',
        base_url='https://provider.invalid/v1')
    model = EngineModel.objects.create(engine=engine, name='Fixture UX', model_id='fixture-ux',
        context_window=200000, max_tokens=8000, input_price='1', output_price='2')
    credential = CompanyEngine.objects.create(company=company, engine=engine,
        api_key='synthetic-never-dispatched')
    mask = ObfuscationConfig.objects.create(company=company, name='Local', backend='local', detect='both')
    company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
        'classification': 'local', 'verification': {'mode': 'local'},
        'masking': {'max_call_cost': '0'}, 'destinations': {'internal': [
            f'engine:{credential.pk}', f'obfuscation:{mask.pk}']}, 'limits': {'provider_managed': True}}
    company.save()
    profile = AgentModelProfile.objects.create(company=company, name='Profesional UX', enabled=True,
        connection=credential, model=model, tools=sorted(GENERAL), professional=True)
    AgentAccessGrant.objects.create(company=company, user=user, profile=profile, enabled=True)
    installations = {}
    for candidate in ('design-taste-frontend', 'frontend-design'):
        result = install(user, uuid.uuid4(), {'source': 'catalog', 'candidate': candidate})
        if result['state'] != 'installed':
            raise RuntimeError('fixture_skill_install_failed:' + candidate)
        installations[candidate] = result
    conversation = Conversation.objects.create(user=user, mode='agent', title='Taste · prueba de interfaz')
    OUT.mkdir(parents=True, exist_ok=True)
    report = {'url': BASE, 'database': DATABASE, 'pg_container': PG_ID,
        'fixture': True, 'runtime_capability_fixture': True, 'provider_requests': 0,
        'generation_blocked': True, 'user_id': user.pk, 'conversation_id': conversation.pk,
        'installations': installations}
    (OUT / 'lab.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


def session():
    owner_check()
    settings = configure()
    from django.contrib.auth.models import User
    actor = User.objects.get(username='p1-skills-ux')
    store = importlib.import_module(settings.SESSION_ENGINE).SessionStore()
    store['_auth_user_id'] = str(actor.pk)
    store['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
    store['_auth_user_hash'] = actor.get_session_auth_hash()
    store.set_expiry(3600)
    store.save()
    private = OUT / 'private'
    private.mkdir(exist_ok=True)
    path = private / 'browser-state.json'
    path.write_text(json.dumps({'cookies': [{'name': settings.SESSION_COOKIE_NAME,
        'value': store.session_key, 'domain': '127.0.0.1', 'path': '/', 'expires': -1,
        'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}], 'origins': []}), encoding='utf-8')
    print(json.dumps({'state_path': str(path), 'fixture': True, 'secret_not_logged': True}))


def serve():
    owner_check()
    configure()
    from django.db import connection
    assert connection.settings_dict['NAME'] == DATABASE
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='127.0.0.1', port=8873,
        log_level='warning', access_log=False)


def chat_fixture():
    owner_check()
    configure()
    from django.contrib.auth.models import User
    from front.models import Conversation
    actor = User.objects.get(username='p1-skills-ux')
    conversation, _ = Conversation.objects.get_or_create(user=actor, mode='chat',
        title='Chat normal · conservar borrador')
    report = json.loads((OUT / 'lab.json').read_text(encoding='utf-8'))
    report['normal_chat_id'] = conversation.pk
    (OUT / 'lab.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'fixture': True, 'normal_chat_id': conversation.pk}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'session', 'serve', 'chat_fixture'))
    args = parser.parse_args()
    globals()[args.action]()


if __name__ == '__main__':
    main()
