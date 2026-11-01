"""Synthetic operations exercised in the internal Docker lab, never user databases."""
import argparse
from datetime import date, timedelta
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
from threading import Thread

sys.path.insert(0, '/app/regulai')
import django
django.setup()
from django.conf import settings
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connection
from django.utils import timezone
from front.models import (Company, CompanyEngine, Conversation, Department, Engine, EngineModel,
                          Message, ObfuscationConfig, Profile, Prompt, Role, Rule, RulesGroup)

LAB = Path('/lab')
PASSWORD = 'Synthetic-lab-only-2026!'


def require_lab():
    if (settings.SETTINGS_MODULE != 'regulai.pilot_lab_settings'
            or connection.vendor != 'postgresql'
            or connection.settings_dict['HOST'] != 'db'
            or connection.settings_dict['NAME'] not in ('regulai_lab', 'regulai_restored')):
        raise CommandError('This command only operates on the isolated synthetic PostgreSQL lab.')


def seed():
    require_lab()
    if Company.objects.exists() or User.objects.exists():
        raise CommandError('Refusing to seed a nonempty laboratory database.')
    accounts, private_files = [], []
    admin_role = Role.objects.create(name='admin')
    for label in ('alpha', 'beta'):
        company = Company.objects.create(name='Synthetic pilot ' + label,
            system_prompt='Only synthetic laboratory tasks.', jev_api_key='synthetic-jev-' + label)
        department = Department.objects.create(company=company, name='Synthetic team')
        engine = Engine.objects.create(name='Synthetic engine ' + label,
            connector_type='openai_compatible', base_url='http://provider:8080/v1')
        model = EngineModel.objects.create(engine=engine, name='Synthetic v1', model_id='synthetic-v1',
            context_window=32768, max_tokens=256, supports_json=True,
            input_price='1', output_price='1', currency='USD', price_date=date(2026, 10, 3))
        credential = CompanyEngine.objects.create(company=company, engine=engine,
            api_key='synthetic-engine-' + label)
        mask = ObfuscationConfig.objects.create(company=company, name='Local CPU mask ' + label,
            backend='local', api_url='', detect='both')
        destinations = [f'engine:{credential.pk}', f'obfuscation:{mask.pk}']
        company.ai_config = {'version': 1, 'local_sensitivity': 'internal',
            'destinations': {level: destinations for level in ('public', 'internal', 'confidential')},
            'masking': {'max_call_cost': '0'}, 'limits': {'budget': '0.5'},
            'routing': {'candidates': [{'company_engine_id': credential.pk, 'model_id': model.pk,
                'level': 'economy', 'quality': {'general': 0.5}}], 'max_output_tokens': 256}}
        company.full_clean()
        company.save()
        group = RulesGroup.objects.create(company=company, name='Synthetic lab rules')
        Rule.objects.create(rules_group=group, name='Synthetic mandatory block',
            yara_rule='rule LabBlock { strings: $s = "SYNTHETIC_BLOCK" condition: $s }', action='block')
        Rule.objects.create(rules_group=group, name='Synthetic consent',
            yara_rule='rule LabConsent { strings: $s = "LAB_CONSENT" condition: $s }', action='consent')
        for kind in ('user', 'admin'):
            actor = User.objects.create_user(f'lab-{label}-{kind}', password=PASSWORD,
                is_staff=kind == 'admin')
            Profile.objects.create(user=actor, company=company, department=department,
                role=admin_role if kind == 'admin' else None,
                default_engine=credential, default_model=model)
            accounts.append({'username': actor.username, 'company_id': company.pk,
                             'engine_id': credential.pk, 'model_id': model.pk})
        actor = User.objects.get(username=f'lab-{label}-user')
        conversation = Conversation.objects.create(user=actor, title='Synthetic private file')
        message = Message.objects.create(conversation=conversation, role='assistant', content='Synthetic file')
        message.response_file.save(label + '.txt', ContentFile(('Synthetic private ' + label).encode()))
        private_files.append({'username': actor.username, 'message_id': message.pk,
                              'file_name': message.response_file.name})
        Prompt.objects.create(user=actor, company=company, conversation=conversation,
            content='Synthetic private file fixture', status='legacy')
    (LAB / 'accounts.json').write_text(json.dumps(accounts, indent=2), encoding='utf-8')
    (LAB / 'lab-files.json').write_text(json.dumps(private_files), encoding='utf-8')
    from front.local_masking import detector_metadata
    print(json.dumps({'companies': 2, 'accounts': 4, 'engines': 2, 'masks': 2, 'real_provider_calls': 0,
                      'local_masking': detector_metadata()}))


def snapshot():
    require_lab()
    # Hash all rows including raw ciphertext, never return their content.
    tables = {}
    with connection.cursor() as cursor:
        for table in sorted(connection.introspection.table_names()):
            cursor.execute(f'SELECT * FROM {connection.ops.quote_name(table)}')
            rows = sorted(json.dumps(row, default=str, sort_keys=True) for row in cursor.fetchall())
            tables[table] = {'count': len(rows), 'sha256': sha256('\n'.join(rows).encode()).hexdigest()}
    media = {str(path.relative_to(settings.MEDIA_ROOT)): sha256(path.read_bytes()).hexdigest()
             for path in sorted(Path(settings.MEDIA_ROOT).rglob('*')) if path.is_file()}
    assert all(row.jev_api_key == 'synthetic-jev-' + row.name.rsplit(' ', 1)[1]
               for row in Company.objects.all())
    assert all(row.api_key.startswith('synthetic-engine-') for row in CompanyEngine.objects.all())
    print(json.dumps({'tables': tables, 'media': media, 'credentials_readable': True}, sort_keys=True))


def expire(identity):
    require_lab()
    row = Prompt.objects.get(request_id=identity, status='processing')
    assert row.user.username.startswith('lab-')
    Prompt.objects.filter(pk=row.pk).update(updated_at=timezone.now() - timedelta(seconds=241))
    print(json.dumps({'expired_synthetic_processing_request': str(identity)}))


def concurrent_rotation():
    require_lab()
    from cryptography.fernet import Fernet
    from django.test import override_settings
    from front.encryption import encrypt_value
    before = list(Company.objects.order_by('pk').values_list('pk', 'name'))
    target = before[0][0]
    errors, touched = [], []
    replacement = encrypt_value('synthetic-concurrent-writer')

    def writer():
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute('UPDATE front_company SET jev_api_key=%s WHERE id=%s', [replacement, target])
        except BaseException as error:
            errors.append(type(error).__name__)
        finally:
            close_old_connections()

    def interleave(execute, sql, params, many, context):
        if many and sql.startswith('UPDATE "front_company"') and not touched:
            touched.append(True)
            thread = Thread(target=writer)
            thread.start()
            thread.join(10)
            assert not thread.is_alive() and not errors
        return execute(sql, params, many, context)

    with connection.cursor() as cursor:
        cursor.execute('SELECT id, jev_api_key FROM front_company ORDER BY id')
        raw_before = dict(cursor.fetchall())
    with override_settings(ENCRYPTION_KEY=Fernet.generate_key().decode(),
                           ENCRYPTION_KEY_FALLBACKS=[settings.ENCRYPTION_KEY]):
        with connection.execute_wrapper(interleave):
            try:
                call_command('reencrypt_secrets', stdout=io.StringIO())
            except CommandError as error:
                assert 'concurrently' in str(error)
            else:
                raise AssertionError('Concurrent writer must abort the complete rotation.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT id, jev_api_key FROM front_company ORDER BY id')
        raw_after = dict(cursor.fetchall())
        assert raw_after[target] == replacement
        assert all(raw_after[pk] == value for pk, value in raw_before.items() if pk != target)
        cursor.execute('UPDATE front_company SET jev_api_key=%s WHERE id=%s', [raw_before[target], target])
    print(json.dumps({'postgresql_real_concurrent_writer': True, 'rotation_aborted_atomically': True,
                      'writer_preserved': True, 'synthetic_fixture_restored': True}))


parser = argparse.ArgumentParser()
parser.add_argument('action', choices=['seed', 'snapshot', 'expire', 'rotation-conflict'])
parser.add_argument('--request-id')
options = parser.parse_args()
{'seed': seed, 'snapshot': snapshot, 'expire': lambda: expire(options.request_id),
 'rotation-conflict': concurrent_rotation}[options.action]()
