"""Synthetic ASGI laboratory only. Actual OpenAI SDK, in-memory HTTP transport.

Never import this module from the application. It refuses non-task50 databases
and non-synthetic users. There is no real provider transport or paid request.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.agent_chat_test_settings'


def prepare(*, database_host='127.0.0.1', database_port='55450', evidence=None):
    import django
    from django.conf import settings
    settings.DATABASES['default']['HOST'] = database_host
    settings.DATABASES['default']['PORT'] = database_port
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '172.30.50.1', 'testserver']
    settings.DEBUG = True
    django.setup()
    from django.core.management import call_command
    from django.contrib.auth.models import User
    from front.models import Company, Profile, Engine, EngineModel, CompanyEngine, ObfuscationConfig, AgentModelProfile
    from front import agents
    from front.agents import service
    from front.connectors import OpenAIConnector
    import httpx
    from openai import OpenAI

    if settings.DATABASES['default']['NAME'] != 'regulai_task50':
        raise RuntimeError('Task50 isolated database required')
    call_command('migrate', interactive=False, verbosity=0)
    if User.objects.exclude(username__startswith='agent-synthetic-').exists():
        raise RuntimeError('Refusing a database containing current accounts')
    user, created = User.objects.get_or_create(username='agent-synthetic-ui')
    if created:
        user.set_password('synthetic-task50-only')
        user.save()
        company = Company.objects.create(name='Task50 synthetic laboratory')
        Profile.objects.create(user=user, company=company)
        engine = Engine.objects.create(name='Task50 synthetic lab', connector_type='openai', base_url='https://provider.invalid/v1')
        model = EngineModel.objects.create(engine=engine, name='Simulated agent', model_id='task50-simulated',
            context_window=200000, max_tokens=8000, input_price='1', output_price='2')
        credential = CompanyEngine.objects.create(company=company, engine=engine, api_key='synthetic-provider-key')
        mask = ObfuscationConfig.objects.create(company=company, name='Local synthetic', backend='local', detect='both')
        company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
            'masking': {'max_call_cost': '0'}, 'destinations': {'internal': [
                f'engine:{credential.pk}', f'obfuscation:{mask.pk}']}, 'limits': {'provider_managed': True}}
        company.save()
        agent = AgentModelProfile.objects.create(company=company, name='Task50 synthetic', enabled=True,
            connection=credential, model=model, tools=['build_excel', 'rename_excel', 'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'])
    else:
        company = user.profile.company
        agent = AgentModelProfile.objects.get(company=company, name='Task50 synthetic')
        agent.tools = ['build_excel', 'rename_excel', 'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation']
        agent.save(update_fields=['tools'])
    settings.REGULAY_AGENT_ENABLED = True
    settings.REGULAY_AGENT_DEVELOPMENT = True
    settings.REGULAY_AGENT_DEV_ACCOUNTS = {str(user.pk): {'company_id': company.pk, 'profile_id': agent.pk}}
    settings.REGULAY_AGENT_WORKER_TOKEN = 'synthetic-task50-worker-key-32-characters'
    requests = []

    def respond(request):
        payload = json.loads(request.content)
        requests.append(payload)
        if evidence:
            Path(evidence).write_text(json.dumps(requests, ensure_ascii=False, indent=2), encoding='utf-8')
        messages = payload['messages']
        if any('SYNTHETIC_PAUSE' in str(message.get('content')) for message in messages):
            time.sleep(10)  # Deterministic process-death/cancellation window; simulated transport only.
        resources = next(m['content'] for m in messages if isinstance(m['content'], str)
            and m['content'].startswith('Referencias autorizadas del servidor: '))
        context = json.loads(resources.split(': ', 1)[1])
        tool_messages = [m for m in messages if m['role'] == 'tool']
        last_result = json.loads(tool_messages[-1]['content']) if tool_messages else {}
        success = last_result.get('status') == 'approved' or last_result.get('code') == 'visual_review_required'
        call = None
        if context['operation'] == 'export' and not tool_messages:
            call = {'id': 'save-' + uuid.uuid4().hex, 'type': 'function', 'function': {
                'name': 'save_revision', 'arguments': json.dumps({k: context[k] for k in ('artifact_reference', 'sha256', 'name')})}}
        if context['operation'] != 'export' and not success and len(tool_messages) < 2:
            name = 'rename_excel' if context['operation'] == 'rename' else 'build_excel'
            title = 'Ventas revisadas' if name == 'rename_excel' else 'Ventas sintéticas'
            args = {'title': title, **({'logical_id': context['logical_id'], 'base_revision': context['base_revision']}
                if name == 'rename_excel' else {'input_reference': context['input_reference']})}
            instruction = next((m['content'] for m in messages if m['role'] == 'user' and
                not m['content'].startswith('Referencias autorizadas del servidor: ')), '').lower()
            identity = {'logical_id': context['logical_id'], 'base_revision': context['base_revision']}
            if context.get('base_format') == 'pptx':
                name = 'edit_presentation'
                body = 'diapositiva' in instruction or 'sección' in instruction
                args = {**identity, 'slide': 3 if body else 1, 'field': 'body' if body else 'title',
                        'value': 'Revisión localizada: análisis de importes de España. Se conserva el resto de la presentación.' if body else 'Informe económico revisado'}
            elif 'pptx' in instruction or 'powerpoint' in instruction or 'presentación' in instruction:
                name, args = 'build_presentation', {'input_reference': context['input_reference'],
                    'template': 'corporate' if 'plantilla' in instruction else 'new', 'title': 'Informe económico de España',
                    'section': ('El análisis reúne los importes de las áreas de trabajo en España. Cada concepto mantiene su nombre original y su valor en euros. La revisión técnica debe contrastar el detalle con el archivo de origen antes de utilizar el total. Se conservan las tildes, la ñ y los símbolos monetarios: €, £ y $.'
                        if 'largo' in instruction else 'Los importes corresponden a tres conceptos del archivo de origen. La tabla conserva el detalle y el gráfico permite comparar su distribución.')}
            elif context.get('base_format') in ('docx', 'pdf'):
                if 'pdf' in instruction and context['base_format'] == 'docx':
                    name, args = 'export_pdf', identity
                else:
                    field = 'section' if 'resumen' in instruction or 'sección' in instruction else 'title'
                    name, args = 'edit_document', {**identity, 'field': field,
                        'value': 'Resumen revisado: análisis económico de España, año 2026.' if field == 'section' else 'Informe técnico revisado'}
            elif 'docx' in instruction or 'informe' in instruction or 'pdf' in instruction:
                name, args = 'build_document', {'input_reference': context['input_reference'],
                    'format': 'pdf' if 'pdf' in instruction else 'docx', 'title': 'Informe económico de España',
                    'section': 'Análisis de importes en euros. Año 2026; revisión técnica con tildes, ñ y símbolos: €, £ y $.'}
            call = {'id': 'synthetic-' + uuid.uuid4().hex, 'type': 'function',
                    'function': {'name': name, 'arguments': json.dumps(args)}}
        message = {'role': 'assistant', 'content': None if call else 'El servidor conserva el resultado de la comprobación.'}
        if call:
            message['tool_calls'] = [call]
        return httpx.Response(200, json={'id': 'synthetic-provider-result', 'object': 'chat.completion', 'created': 1,
            'model': 'task50-simulated', 'choices': [{'index': 0, 'message': message, 'finish_reason': 'tool_calls' if call else 'stop'}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120}})

    def connector(*args):
        result = OpenAIConnector(*args[1:])
        result.client.close()
        result.client = OpenAI(api_key='synthetic-provider-key', base_url='https://provider.invalid/v1',
            max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=False))
        return result
    service.get_connector = connector
    return user.pk


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8500)
    parser.add_argument('--database-port', default='55450')
    parser.add_argument('--evidence')
    args = parser.parse_args()
    user_id = prepare(database_port=args.database_port, evidence=args.evidence)
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    print(json.dumps({'synthetic_user_id': user_id, 'model_transport': 'httpx.MockTransport', 'paid_calls': 0}), flush=True)
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host=args.host, port=args.port, access_log=False)


if __name__ == '__main__':
    main()
