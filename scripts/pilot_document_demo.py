"""Start a new, loopback-only offline document pilot without touching existing DBs.

Run from the repository with .venv Python. --workspace must not exist and must
be below this repository's .claude directory. Every run gets fresh synthetic
records. Uses production Django views and the existing demo transport fixtures.
"""
import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8766)
    options = parser.parse_args()
    workspace = options.workspace.resolve()
    if not workspace.is_relative_to((ROOT / '.claude').resolve()) or workspace.exists():
        parser.error('--workspace must be a NEW directory within the repository .claude directory')
    if not 1 <= options.port <= 65535:
        parser.error('--port must be from 1 to 65535')
    workspace.mkdir(parents=True)
    database = workspace / 'pilot.sqlite3'
    sys.path.insert(0, str(ROOT / 'regulai'))
    from django.conf import settings
    from regulai import test_settings
    values = {key: getattr(test_settings, key) for key in dir(test_settings) if key.isupper()}
    values.update(
        DEBUG=True, DEMO_MODE=True,
        DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': database}},
        MEDIA_ROOT=workspace / 'media', ALLOW_REGISTRATION=False,
        SESSION_COOKIE_NAME='pilot_document_session', CSRF_COOKIE_NAME='pilot_document_csrf',
        SESSION_COOKIE_SECURE=False, CSRF_COOKIE_SECURE=False, SECURE_SSL_REDIRECT=False,
        CORS_ALLOW_ALL_ORIGINS=False,
        CORS_ALLOWED_ORIGINS=[f'http://127.0.0.1:{options.port}'],
    )
    values['TEMPLATES'] = deepcopy(values['TEMPLATES'])
    values['TEMPLATES'][0]['OPTIONS']['context_processors'].append('regulai.demo_settings.demo_context')
    settings.configure(**values)
    import django
    django.setup()
    from django.core.management import call_command
    from front.management.commands import run_demo
    # Scope the strict existing demo guard to this newly created pilot directory.
    # No seed/migration is ever run against the pre-existing Community demo DB.
    with patch.object(run_demo, 'DEMO_DATABASE', database):
        call_command('migrate', interactive=False, verbosity=0)
        run_demo.seed_demo()
        metadata = {
            'schema_version': 1, 'created_at_utc': datetime.now(timezone.utc).isoformat(),
            'database': str(database), 'listen': f'127.0.0.1:{options.port}',
            'mode': 'offline synthetic transport; outbound HTTP and sockets blocked',
            'sources': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [
                'scripts/pilot_document_demo.py', 'regulai/front/management/commands/run_demo.py',
                'regulai/front/management/commands/evaluate_ai.py', 'regulai/front/chat_service.py',
                'regulai/front/documents.py', 'regulai/front/templates/chat/chat.html',
                'regulai/front/masking.py', 'regulai/front/local_masking.py']},
        }
        (workspace / 'run.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
        print(f'OFFLINE SYNTHETIC PILOT at http://127.0.0.1:{options.port}/login/', flush=True)
        print(f'Public demo credentials: {run_demo.DEMO_USERNAME} / {run_demo.DEMO_PASSWORD}', flush=True)
        print(f'New isolated database: {database}', flush=True)
        with run_demo.offline_demo():
            call_command('runserver', addrport=f'127.0.0.1:{options.port}', use_reloader=False, use_threading=True)


if __name__ == '__main__':
    main()
