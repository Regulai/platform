"""Explicit offline demo process; ordinary startup never installs these fixtures."""
from contextlib import contextmanager
from datetime import date
from decimal import Decimal
import json
from pathlib import Path
from threading import local
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from front.models import Company, CompanyEngine, Engine, EngineModel, ObfuscationConfig, Profile, Rule, RulesGroup
from .evaluate_ai import OfflineProviders, ROOT, load_bank, policy_config


DEMO_USERNAME = 'community-demo'
DEMO_PASSWORD = 'community-demo-only'
DEMO_CREDENTIAL = 'synthetic-offline-credential'
DEMO_DATABASE = ROOT / 'regulai' / 'community-demo.sqlite3'


def require_demo_database(*, allow_memory=False):
    database = connection.settings_dict
    name = str(database['NAME'])
    memory = name == ':memory:' or (name.startswith('file:') and parse_qs(urlsplit(name).query).get('mode') == ['memory'])
    if (not getattr(settings, 'DEMO_MODE', False)
            or database['ENGINE'] != 'django.db.backends.sqlite3'
            or not ((allow_memory and memory) or Path(name).resolve() == DEMO_DATABASE.resolve())):
        raise CommandError('Use --settings=regulai.demo_settings with the dedicated community-demo.sqlite3 database.')
    primary = ROOT / 'regulai' / 'db.sqlite3'
    if not memory and (DEMO_DATABASE.is_symlink() or (
            DEMO_DATABASE.exists() and primary.exists() and DEMO_DATABASE.samefile(primary))):
        raise CommandError('The demo database must be a separate regular file, not an alias of an existing database.')


def seed_demo():
    """Seed only synthetic identities; an unexpected existing value is preserved."""
    require_demo_database(allow_memory=True)
    manifest, _, _, _ = load_bank(ROOT / 'evals' / 'manifest.json')
    with transaction.atomic():
        actor, created = User.objects.get_or_create(username=DEMO_USERNAME)
        if created:
            actor.set_password(DEMO_PASSWORD)
            actor.save(update_fields=['password'])
        if (not actor.check_password(DEMO_PASSWORD) or not actor.is_active
                or actor.is_staff or actor.is_superuser):
            raise CommandError('Existing demo user differs from the public synthetic identity; it was not changed.')
        company, created = Company.objects.get_or_create(name='Community offline demo',
                                                        defaults={'jev_api_key': DEMO_CREDENTIAL})
        if company.jev_api_key != DEMO_CREDENTIAL or company.system_prompt:
            raise CommandError('Existing demo company differs from the synthetic fixture; it was not changed.')
        engine, _ = Engine.objects.get_or_create(name='Community offline demo provider',
                                                defaults={'provider': 'synthetic', 'connector_type': 'openai'})
        if engine.provider != 'synthetic' or engine.connector_type != 'openai' or engine.base_url:
            raise CommandError('Existing demo provider differs from the synthetic fixture; it was not changed.')
        models = {}
        for level in ('economy', 'strong'):
            fields = {'name': f'Synthetic {level}', 'active': True, 'max_tokens': manifest['limits']['max_output_tokens'],
                      'context_window': manifest['context_window'], 'supports_json': True,
                      'input_price': Decimal(manifest['prices_per_million'][level]['input']),
                      'output_price': Decimal(manifest['prices_per_million'][level]['output']),
                      'currency': manifest['currency'], 'price_date': date.fromisoformat(manifest['price_date'])}
            model, _ = EngineModel.objects.get_or_create(engine=engine, model_id=manifest['model_versions'][level], defaults=fields)
            if any(getattr(model, key) != value for key, value in fields.items()):
                raise CommandError('Existing demo model differs from the frozen fixture; it was not changed.')
            models[level] = model
        credential, _ = CompanyEngine.objects.get_or_create(company=company, engine=engine,
                                                            defaults={'api_key': DEMO_CREDENTIAL})
        if credential.api_key != DEMO_CREDENTIAL or not credential.active:
            raise CommandError('Existing demo credential differs from the synthetic fixture; it was not changed.')
        if CompanyEngine.objects.filter(company=company).exclude(pk=credential.pk).exists():
            raise CommandError('Unexpected demo credentials exist; no records were changed.')
        mask, _ = ObfuscationConfig.objects.get_or_create(company=company, name='Local CPU mask',
            defaults={'backend': 'local', 'api_url': '', 'active': True})
        if not mask.active or mask.backend != 'local' or mask.api_url or mask.detect != 'both' or mask.language:
            raise CommandError('Existing demo mask differs from the frozen fixture; it was not changed.')
        if ObfuscationConfig.objects.filter(company=company).count() != 1:
            raise CommandError('Unexpected demo masks exist; no records were changed.')
        policy = policy_config({}, 'router', manifest, credential, models, mask)
        if created:
            company.ai_config = policy
            company.save(update_fields=['ai_config'])
        elif company.ai_config != policy:
            raise CommandError('Existing demo policy differs from the frozen fixture; it was not changed.')
        profile, _ = Profile.objects.get_or_create(user=actor, defaults={
            'company': company, 'default_engine': credential, 'default_model': models['economy']})
        if (profile.company_id != company.pk or profile.department_id is not None
                or profile.default_engine_id not in (None, credential.pk)
                or profile.default_model_id not in (None, *(model.pk for model in models.values()))):
            raise CommandError('Existing demo profile differs from the synthetic fixture; it was not changed.')
        group, _ = RulesGroup.objects.get_or_create(company=company, name='Synthetic demo policy')
        if group.user_id is not None:
            raise CommandError('Existing demo rule group is not the company fixture; it was not changed.')
        for name, marker, action in [('Synthetic secret', 'SYNTHETIC_SECRET', 'block'),
                                     ('Synthetic consent', 'SYNTHETIC_CONSENT', 'consent')]:
            source = f'rule synthetic_{action} {{ strings: $a = "{marker}" condition: $a }}'
            rule, _ = Rule.objects.get_or_create(rules_group=group, name=name, defaults={'yara_rule': source, 'action': action})
            if rule.yara_rule != source or rule.action != action or not rule.active or rule.applies_to != 'both':
                raise CommandError('Existing demo rule differs from the synthetic fixture; it was not changed.')
        if Rule.objects.filter(rules_group__company=company).count() != 2:
            raise CommandError('Unexpected demo rules exist; no records were changed.')
    return actor


class DemoProviders:
    def __init__(self):
        self.manifest, cases, _, _ = load_bank(ROOT / 'evals' / 'manifest.json')
        self.cases = {case['id']: case for case in cases}
        self.state = local()
        self.events = []

    def post(self, url, *, data=None, **kwargs):
        mask_payload = kwargs.pop('json', None)
        if mask_payload is not None:
            provider = OfflineProviders({}, self.manifest)
            response = provider.post(url, json=mask_payload, **kwargs)
            self.events.append(provider.events[-1])
            return response
        payload = json.loads(data)
        if 'category' in payload['questions']:
            sources = payload['state'].get('sources', [])
            if sources and any('cuesta 10 euros.' in source['text'] for source in sources):
                case = self.cases['document-contradiction']
            elif sources:
                case = {**self.cases['document-missing-answer'], 'id': 'demo-unknown-document'}
            else:
                case = self.cases['simple-es']
            self.state.provider = OfflineProviders(case, self.manifest)
        provider = getattr(self.state, 'provider', None)
        if provider is None:
            raise RuntimeError('Demo classification must precede provider calls.')
        response = provider.post(url, data=data, **kwargs)
        self.events.append(provider.events[-1])
        return response

    def generate(self, messages, model, **kwargs):
        provider = getattr(self.state, 'provider', None)
        if provider is None:
            raise RuntimeError('Demo classification must precede generation.')
        response = provider.generate(messages, model, **kwargs)
        self.events.append(provider.events[-1])
        return response


@contextmanager
def offline_demo():
    require_demo_database(allow_memory=True)
    providers = DemoProviders()
    with patch('front.chat_service.get_connector', return_value=SimpleNamespace(chat=providers.generate)), \
            patch('front.jev.requests.post', side_effect=providers.post), \
            patch('requests.sessions.Session.request', side_effect=RuntimeError('Offline demo blocks outbound HTTP')), \
            patch('socket.socket.connect', side_effect=RuntimeError('Offline demo blocks outbound connections')):
        yield providers


class Command(BaseCommand):
    help = 'Run the isolated synthetic demo on 127.0.0.1; no provider network access.'

    def add_arguments(self, parser):
        parser.add_argument('--port', type=int, default=8001)
        parser.add_argument('--seed-only', action='store_true')

    def handle(self, *args, **options):
        require_demo_database()
        if not 1 <= options['port'] <= 65535:
            raise CommandError('Choose a port from 1 to 65535.')
        call_command('migrate', interactive=False, verbosity=0)
        seed_demo()
        self.stdout.write(f'DEMO OFFLINE — fallo simulado. Login: {DEMO_USERNAME} / {DEMO_PASSWORD}')
        if options['seed_only']:
            return
        with offline_demo():
            call_command('runserver', addrport=f"127.0.0.1:{options['port']}", use_reloader=False, use_threading=True)
