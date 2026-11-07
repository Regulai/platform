"""Disposable P0 evaluation app. Real provider, mandatory local protection, USD cap.

Private input stays inside the installation VM. This module never imports the
installation settings or writes to its database. No provider response is mocked.
"""
from contextvars import ContextVar
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

PRIVATE = Path('/run/private')
STATE = Path('/eval-state')
CONTEXT = ContextVar('p0_eval_request', default=None)
LOG_LOCK = threading.Lock()


def configure():
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    from django.conf import settings
    config = json.loads((PRIVATE / 'eval.json').read_text())
    if (config['database']['name'] != 'p0_eval'
            or config['database']['host'] != 'p0-eval-db20261016'):
        raise RuntimeError('Only the disposable evaluation database is authorized')
    budget = Decimal(config['budget_usd'])
    if not budget.is_finite() or not 0 < budget <= 5:
        raise RuntimeError('The evaluation budget must be positive and at most USD 5')
    database = config['database']
    settings.DATABASES = {'default': {'ENGINE': 'django.db.backends.postgresql',
        **{key.upper(): value for key, value in database.items()}}}
    settings.SECRET_KEY = config['secret_key']
    settings.ENCRYPTION_KEY = config['encryption_key']
    settings.SECRET_KEY_FALLBACKS = settings.ENCRYPTION_KEY_FALLBACKS = []
    settings.DEBUG = False
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver'] + config.get('allowed_hosts', [])
    settings.SESSION_COOKIE_NAME = 'p0_eval_session'
    settings.CSRF_COOKIE_NAME = 'p0_eval_csrf'
    settings.PASSWORD_HASHERS = ['django.contrib.auth.hashers.PBKDF2PasswordHasher']
    settings.PLATFORM_ADMIN_USER_IDS = ()
    settings.REGULAY_AGENT_ENABLED = True
    settings.REGULAY_AGENT_DEVELOPMENT = False
    settings.REGULAY_AGENT_WEB_ENABLED = True
    settings.REGULAY_AGENT_BROWSER_ENABLED = False
    settings.REGULAY_AGENT_PACKAGES_ENABLED = True
    settings.REGULAY_AGENT_WORKER_TOKEN = config['worker_token']
    settings.REGULAY_AGENT_CAPACITY = {'active_global': 1, 'active_company': 1, 'sandbox': 1, 'provider': 1}
    settings.MIDDLEWARE = ['ops.agent_chat.p0_eval_app.EvaluationContext', *settings.MIDDLEWARE]
    import django
    django.setup()
    return config


class EvaluationContext:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        identity = None
        if request.path == '/internal/agents/inference/':
            try:
                from front.models import AgentExecution
                run = AgentExecution.objects.select_related('prompt').get(
                    attempt=uuid.UUID(request.headers['X-Regulay-Attempt']))
                payload = json.loads(request.body)
                identity = {'execution_id': str(run.pk), 'conversation_id': str(run.conversation_id),
                    'call_id': str(uuid.UUID(payload['call_id'])), 'phase': payload.get('purpose', 'generation')}
            except (ValueError, KeyError, AgentExecution.DoesNotExist):
                pass  # The ordinary authentication boundary still rejects the request.
        reset = CONTEXT.set(identity)
        try:
            return self.get_response(request)
        finally:
            CONTEXT.reset(reset)


def seed(config):
    from django.core.management import call_command
    from django.contrib.auth.models import User
    from django.db import transaction
    from front.models import (AgentAccessGrant, AgentModelProfile, Company, CompanyEngine,
        Engine, EngineModel, ObfuscationConfig, Profile)
    source = json.loads((PRIVATE / 'connection.json').read_text())
    if (source['format'] != 'p0-evaluation-connection-v1'
            or source['engine']['connector_type'] != 'openai_compatible'
            or source['model']['model_id'] != 'deepseek-flash'
            or source['engine']['base_url'].rstrip('/') not in ('https://api.deepseek.com', 'https://api.deepseek.com/v1')):
        raise RuntimeError('Only the authorized DeepSeek evaluation connection is permitted')
    if (type(source['model']['context_window']) is not int or source['model']['context_window'] < 8192
            or type(source['model']['max_tokens']) is not int or source['model']['max_tokens'] < 1):
        raise RuntimeError('The evaluation model requires explicit positive context and output limits')
    call_command('migrate', interactive=False, verbosity=0)
    if (STATE / 'initialized.json').exists():
        initialized = json.loads((STATE / 'initialized.json').read_text())
        if not AgentModelProfile.objects.filter(pk=initialized['profile_id'],
                company_id=initialized['company_id'], enabled=True,
                agentaccessgrant__user_id=initialized['user_id'],
                agentaccessgrant__user__username=config['eval_username'],
                agentaccessgrant__enabled=True).exists():
            raise RuntimeError('Existing evaluation identity differs; refusing restart.')
        return source  # Restart serving the same DB and budget; never reset them.
    if User.objects.exists():
        raise RuntimeError('The evaluation database must contain no accounts.')
    with transaction.atomic():
        user = User.objects.create_user(config.get('eval_username', 'p0-evaluation-20261016'),
            password=config['eval_password'])
        company = Company.objects.create(name='P0 synthetic evaluation 20261016')
        Profile.objects.create(user=user, company=company)
        engine = Engine.objects.create(**{**source['engine'], 'name': 'P0 authorized live DeepSeek'})
        fields = {key: source['model'][key] for key in ('model_id', 'context_window', 'max_tokens', 'reasoning')}
        model = EngineModel.objects.create(engine=engine, name='P0 DeepSeek Flash', **fields,
            input_price=Decimal('0.30'), output_price=Decimal('1.20'), currency='USD',
            price_date='2026-10-16', supports_vision=False)
        credential = CompanyEngine.objects.create(company=company, engine=engine, api_key=source['api_key'])
        mask = ObfuscationConfig.objects.create(company=company, name='Required local mask', backend='local', detect='both')
        company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
            'masking': {'max_call_cost': '0'}, 'routing': {'max_output_tokens': 8192},
            'destinations': {'internal': [f'engine:{credential.pk}', f'obfuscation:{mask.pk}',
                'research:web', 'research:packages']},
            'limits': {'provider_managed': True, 'call_timeout_seconds': 60, 'deadline_seconds': 180}}
        company.save(update_fields=['ai_config'])
        from front.agents.capabilities import GENERAL
        profile = AgentModelProfile.objects.create(company=company, name='P0 bounded live evaluation',
            enabled=True, connection=credential, model=model, professional=True, tools=sorted(GENERAL),
            limits={'work_profiles': True, 'inference': {'dialect': 'deepseek', 'model_id': model.model_id,
                'profiles': ['legacy', 'quick', 'reasoned'], 'thinking_modes': ['off', 'on'], 'efforts': ['high']}})
        AgentAccessGrant.objects.create(company=company, user=user, profile=profile, enabled=True)
    (STATE / 'initialized.json').write_text(json.dumps({'user_id': user.pk, 'company_id': company.pk,
        'profile_id': profile.pk, 'model': model.model_id, 'context_window': model.context_window,
        'max_output': model.max_tokens, 'budget_usd': config['budget_usd'],
        'price_policy': 'Conservative peak, uncached USD: 0.30 input / 1.20 output per million.',
        'price_source': 'https://api-docs.deepseek.com/quick_start/pricing/',
        'controls': 'Synthetic policy, mandatory real local mask and normal grants. No paid Jev/search.',
        'source_control_metadata': source.get('controls', {})}, indent=2))
    return source


class MeteredTransport(httpx.BaseTransport):
    def __init__(self, guard, model, context_window):
        self.guard, self.model, self.context_window = guard, model, context_window
        self.transport = httpx.HTTPTransport(retries=0, trust_env=False)

    def close(self):
        self.transport.close()

    def handle_request(self, request):
        context = CONTEXT.get()
        if context is None or request.url.host != 'api.deepseek.com' or request.method != 'POST':
            raise RuntimeError('Paid request outside the evaluation inference boundary')
        body = json.loads(request.content)
        output_cap = body.get('max_tokens')
        if (body.get('model') != self.model or type(output_cap) is not int or not 1 <= output_cap <= 8192
                or not request.url.path.endswith('/chat/completions') or body.get('stream')):
            raise RuntimeError('Unsupported or unbounded evaluation provider request')
        # Reserve the entire advertised input context. Subtracting the requested
        # output cap would assume the provider allocates unused output tokens.
        reservation = self.guard.reserve(context['phase'], self.model, self.context_window,
            output_cap, Decimal('0.30'), Decimal('1.20'), {**context, 'request_bytes': len(request.content)})
        started = time.monotonic()
        event = {'started_utc': datetime.now(timezone.utc).isoformat(), **context,
            'reservation_id': reservation, 'request_sha256': hashlib.sha256(request.content).hexdigest(),
            'request_bytes': len(request.content), 'messages': len(body.get('messages', [])),
            'message_roles': [item.get('role') for item in body.get('messages', [])],
            'historical_tool_calls': sum(len(item.get('tool_calls') or []) for item in body.get('messages', [])),
            'has_tools_parameter': 'tools' in body,
            'tools_offered': [item['function']['name'] for item in body.get('tools', [])],
            'thinking': body.get('thinking'), 'reasoning_effort': body.get('reasoning_effort'),
            'max_tokens': output_cap}
        settlement_started = False
        try:
            response = self.transport.handle_request(request)
            raw = response.read()
            data = json.loads(raw)
            usage = data.get('usage') if isinstance(data, dict) else None
            usage = usage if isinstance(usage, dict) else {}
            prompt, completion = usage.get('prompt_tokens'), usage.get('completion_tokens')
            if response.status_code != 200 or type(prompt) is not int or type(completion) is not int:
                error = data.get('error', {}) if isinstance(data, dict) else {}
                message = str(error.get('message', '')) if isinstance(error, dict) else ''
                # Record diagnostic classes, never arbitrary provider messages
                # which could contain submitted data or an echoed credential.
                categories = {'reasoning_content': 'reasoning_content_required',
                    'last message': 'last_message_invalid', 'reasoning_effort': 'reasoning_effort_invalid',
                    'max_tokens': 'max_tokens_invalid', 'tool_call': 'tool_protocol_invalid'}
                event['provider_error_category'] = next((value for key, value in categories.items()
                    if key in message.casefold()), 'unclassified_http_error')
                event['error_response_sha256'] = hashlib.sha256(raw).hexdigest()
                settlement_started = True
                self.guard.settle(reservation)
                event.update(status='unknown', http_status=response.status_code)
            else:
                settlement_started = True
                self.guard.settle(reservation, input_tokens=prompt, output_tokens=completion,
                    duration_ms=round((time.monotonic() - started) * 1000))
                choices = data.get('choices')
                choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
                message = choice.get('message')
                message = message if isinstance(message, dict) else {}
                tool_calls = message.get('tool_calls')
                tool_calls = tool_calls if isinstance(tool_calls, list) else []
                content = message.get('content')
                event.update(status='completed', http_status=response.status_code,
                    input_tokens=prompt, output_tokens=completion, model_effective=data.get('model'),
                    finish_reason=choice.get('finish_reason'),
                    tool_names=[call['function'].get('name') for call in tool_calls
                        if isinstance(call, dict) and isinstance(call.get('function'), dict)],
                    output_characters=len(content) if isinstance(content, str) else 0)
            return response
        except Exception as error:
            # A breach is already persisted by BudgetGuard. Likewise, a later
            # parsing failure must not replace a known cost with unknown usage.
            if not settlement_started:
                self.guard.settle(reservation)
            event.update(status='failed_after_settlement' if settlement_started else 'unknown',
                error_type=type(error).__name__)
            raise
        finally:
            event['duration_ms'] = round((time.monotonic() - started) * 1000)
            with LOG_LOCK:
                with (STATE / 'provider.jsonl').open('a', encoding='utf-8') as output:
                    output.write(json.dumps(event, ensure_ascii=False) + '\n')


def install_meter(config, source):
    from openai import OpenAI
    from front.agents import service
    from ops.agent_chat.p0_eval_budget import BudgetGuard
    guard = BudgetGuard(STATE / 'budget.json', limit=Decimal(config['budget_usd']))
    original = service.get_connector
    def connector(kind, key, base_url):
        if kind != 'openai_compatible' or base_url.rstrip('/') not in ('https://api.deepseek.com', 'https://api.deepseek.com/v1'):
            raise RuntimeError('Evaluation destination mismatch')
        result = original(kind, key, base_url)
        result.client.close()
        result.client = OpenAI(api_key=key, base_url=base_url, max_retries=0,
            http_client=httpx.Client(transport=MeteredTransport(guard, source['model']['model_id'],
                source['model']['context_window']), follow_redirects=False, trust_env=False))
        return result
    service.get_connector = connector


def main():
    config = configure()
    source = seed(config)
    install_meter(config, source)
    import uvicorn
    from django.core.asgi import get_asgi_application
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
    uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='0.0.0.0', port=31068, access_log=False)


if __name__ == '__main__':
    # Keep the middleware import and __main__ on the same ContextVar/module.
    import sys
    sys.modules['ops.agent_chat.p0_eval_app'] = sys.modules[__name__]
    main()
