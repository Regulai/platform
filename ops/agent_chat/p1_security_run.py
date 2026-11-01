"""Run the independent skills review on its own isolated PostgreSQL test DB."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if os.environ.get('P1_SECURITY_CAPTURE') != '1':
    evidence = ROOT / 'output/p1-20261016/e8'
    evidence.mkdir(parents=True, exist_ok=True)
    stamp = time.time_ns()
    log = evidence / f'security-{stamp}.log'
    started = time.monotonic()
    env = dict(os.environ, P1_SECURITY_CAPTURE='1', PYTHONIOENCODING='utf-8')
    with log.open('w', encoding='utf-8') as stream:
        result = subprocess.run(['rtk', 'proxy', sys.executable, __file__, *sys.argv[1:]],
            cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    receipt = {'exit_code': result.returncode, 'duration_seconds': round(time.monotonic() - started, 3),
        'log': str(log), 'tests': sys.argv[1:] or ['front.test_agent_skills_security'],
        'database': 'test_regulai_p1_security', 'provider_calls': 0,
        'sources': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [ROOT / 'regulai/front/test_agent_skills_security.py',
                ROOT / 'regulai/front/agents/skills.py', ROOT / 'regulai/front/agents/skill_installation.py',
                ROOT / 'regulai/front/migrations/0043_p1_skills_and_events.py']}}
    (evidence / f'security-{stamp}.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))
    raise SystemExit(result.returncode)
sys.path.insert(0, str(ROOT / 'regulai'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
from django.conf import settings
settings.DATABASES['default']['PORT'] = '55468'
settings.DATABASES['default']['TEST']['NAME'] = 'test_regulai_p1_security'
assert settings.DATABASES['default']['HOST'] == '127.0.0.1'
import django
django.setup()
from django.core.management import call_command
call_command('test', *(sys.argv[1:] or ['front.test_agent_skills_security']), interactive=False, verbosity=2)
