"""Bridge existing destination-matched credentials into the isolated, authorized pilot process.

No credential values enter command arguments, artifacts or stdout. The user database
is opened through a separate SQLite mode=ro connection and is never migrated.
"""
import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = HERE / 'manifest.json'
AUTHORIZATION = HERE / 'authorization.approved.json'
EVIDENCE = ROOT / 'evals/reports/adversarial-real-20261003-01'
GATEWAY = 'https://ai-gateway.vercel.sh/typesafe/v1/systemone'


def credentials_readonly():
    sys.path.insert(0, str(ROOT / 'regulai'))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.settings'
    import django
    django.setup()
    from django.conf import settings
    from django.db import connections
    from front.models import CompanyEngine
    config = copy.deepcopy(settings.DATABASES['default'])
    if config['ENGINE'] != 'django.db.backends.sqlite3':
        raise RuntimeError('This reviewed bridge supports an existing local SQLite configuration only.')
    database = Path(config['NAME']).resolve()
    if not database.is_file():
        raise RuntimeError('Existing configuration database is missing; nothing will be created.')
    before = sha256(database.read_bytes()).hexdigest()
    config['NAME'] = database.as_uri() + '?mode=ro'
    config['OPTIONS'] = {**config.get('OPTIONS', {}), 'uri': True}
    alias = 'pilot_credentials_readonly'
    connections.databases[alias] = config
    try:
        rows = CompanyEngine.objects.using(alias).filter(active=True,
            engine__base_url__in=['https://api.deepseek.com', 'https://api.deepseek.com/v1']).values_list(
                'api_key', 'company__jev_api_key', 'company__ai_config')
        pairs = [(generator, judge) for generator, judge, policy in rows
                 if generator and judge and isinstance(policy, dict)
                 and isinstance(policy.get('jev', {}), dict)
                 and policy.get('jev', {}).get('transport', 'vercel') == 'vercel']
        if len(pairs) != 1:
            raise RuntimeError('Exactly one same-company DeepSeek/Gateway credential pair is required.')
        return pairs[0], database, before
    finally:
        connections[alias].close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    flags = parser.add_mutually_exclusive_group(required=True)
    flags.add_argument('--preflight', action='store_true')
    flags.add_argument('--real', action='store_true')
    options = parser.parse_args()
    approval = json.loads(AUTHORIZATION.read_text(encoding='utf-8'))
    if approval.get('approved') is not True or approval.get('status') != 'approved' or not approval.get('extends'):
        raise RuntimeError('Explicit new scope approval is required before accessing existing credentials.')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    label = 'live' if options.real else 'preflight'
    if (EVIDENCE / (label + '-result.json')).exists():
        raise RuntimeError('This execution already has evidence; do not overwrite or retry automatically.')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    if (manifest['judge_transport'] != 'vercel' or manifest['model_versions']['judge'] != 'typesafe-ai/jev'
            or manifest['destinations'] != {'generation': 'https://api.deepseek.com', 'judge': GATEWAY}
            or manifest['masking']['backend'] != 'local' or manifest['maximum_usd'] != '1.00'):
        raise RuntimeError('Credential destination or approved scope mismatch.')
    manifest_hash = sha256(MANIFEST.read_bytes()).hexdigest()
    approval_hash = sha256(AUTHORIZATION.read_bytes()).hexdigest()
    if options.real:
        prior = json.loads((EVIDENCE / 'preflight-result.json').read_text(encoding='utf-8'))
        if (not prior['ready_for_real'] or prior['manifest_sha256'] != manifest_hash
                or prior['authorization_sha256'] != approval_hash):
            raise RuntimeError('An unchanged successful preflight is required.')
    pair, database, before = credentials_readonly()
    environment = dict(os.environ)
    environment['DJANGO_SETTINGS_MODULE'] = 'regulai.test_settings'
    environment['REGULAI_EVAL_GENERATOR_KEY'], environment['REGULAI_EVAL_JEV_KEY'] = pair
    output = EVIDENCE / 'live-run-01' if options.real else EVIDENCE / 'must-not-exist'
    command = ['rtk', 'proxy', sys.executable, 'regulai/manage.py', 'smoke_ai',
        '--settings=regulai.test_settings', '--manifest', str(MANIFEST), '--authorization', str(AUTHORIZATION),
        '--output', str(output), *(['--real', '--max-usd', '1.00'] if options.real else ['--preflight'])]
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, encoding='utf-8', errors='replace')
    del environment
    redacted = False
    logs = {}
    for stream, text in (('stdout', result.stdout), ('stderr', result.stderr)):
        for secret in pair:
            if secret in text:
                redacted = True
                text = text.replace(secret, '[REDACTED_CREDENTIAL]')
        path = EVIDENCE / f'{label}.{stream}.log'
        with path.open('x', encoding='utf-8') as handle:
            handle.write(text)
        logs[path.name] = sha256(path.read_bytes()).hexdigest()
    ready = json.loads(result.stdout).get('ready_for_real') if options.preflight and result.returncode == 0 else None
    record = {'command': command, 'exit_code': result.returncode, 'started_utc': started,
        'finished_utc': datetime.now(timezone.utc).isoformat(), 'ready_for_real': ready,
        'manifest_sha256': manifest_hash, 'authorization_sha256': approval_hash,
        'script_sha256': sha256(Path(__file__).read_bytes()).hexdigest(), 'logs': logs,
        'credential_values_redacted_from_unexpected_logs': redacted,
        'source_database_open_mode': 'ro', 'source_database_unchanged': sha256(database.read_bytes()).hexdigest() == before,
        'source_database_sha256_before': before, 'source_database_sha256_after': sha256(database.read_bytes()).hexdigest(),
        'user_database_migrated': False, 'execution_database': 'isolated memory in child process'}
    with (EVIDENCE / (label + '-result.json')).open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(record, indent=2) + '\n')
    print(json.dumps({key: record[key] for key in ('exit_code', 'ready_for_real', 'source_database_unchanged',
        'credential_values_redacted_from_unexpected_logs')}))
    return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Exception text/locals can contain secrets from third-party libraries.
        print(json.dumps({'bridge_failed': type(error).__name__, 'credential_values_emitted': False}))
        raise SystemExit(1)
