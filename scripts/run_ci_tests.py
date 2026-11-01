"""Run each test module in a fresh process with its required database backend.

Agent ledger/concurrency tests require PostgreSQL. Legacy offline evaluation
and demo safety tests deliberately refuse anything except in-memory SQLite.
The namespace integration lab is explicit; setup.py verifies real E2B itself.
"""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
requested = set(sys.argv[1:])
for app in ('front', 'api'):
    for module in sorted((root / 'regulai' / app).glob('test*.py')):
        if requested and f'{app}.{module.stem}' not in requested:
            continue
        settings = 'regulai.ci_settings' if module.stem.startswith('test_agent') else 'regulai.test_settings'
        print(f'Checking {app}.{module.stem} ({settings})', flush=True)
        result = subprocess.run([sys.executable, str(root / 'regulai/manage.py'), 'test',
            f'{app}.{module.stem}', '--settings=' + settings, '--noinput',
            '--exclude-tag=namespace_integration', '--exclude-tag=capacity_benchmark'], cwd=root)
        if result.returncode:
            raise SystemExit(result.returncode)
