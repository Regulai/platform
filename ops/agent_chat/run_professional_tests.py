"""Run reproducible application regressions on the explicitly isolated cluster."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[2]
LABELS = ['professional', 'professional_http', 'chat', 'inference', 'documents', 'presentations',
    'reports', 'research', 'mock_excel', 'transparency', 'frontend']
command = ['rtk', 'proxy', sys.executable, str(ROOT / 'regulai/manage.py'), 'test',
    *['front.test_agent_' + name for name in LABELS],
    '--settings=regulai.agent_professional_test_settings', '--noinput', '--verbosity=1']
started = datetime.now(timezone.utc).isoformat()
result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace')
folder = ROOT / 'evals/reports/task56-professional-20261014'
folder.mkdir(parents=True, exist_ok=True)
(folder / 'application-tests.log').write_text(result.stdout + result.stderr, encoding='utf-8')
match = re.search(r'Ran (\d+) tests in ([\d.]+)s', result.stderr)
report = {'started_at': started, 'finished_at': datetime.now(timezone.utc).isoformat(),
    'command': command, 'exit_code': result.returncode, 'database': 'isolated PostgreSQL 18.6 on loopback 55456',
    'tests': int(match[1]) if match else None, 'seconds': float(match[2]) if match else None,
    'provider_boundary': 'simulated HTTP; no paid model/search calls'}
(folder / 'application-tests.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
if result.returncode:
    print((result.stdout + result.stderr)[-16000:])
sys.exit(result.returncode)
