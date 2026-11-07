"""Record real Linux/SDK regressions; models and E2B transport remain fixtures."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
command = ['rtk', 'proxy', sys.executable, '-m', 'unittest',
    'ops.agent_chat.test_professional_runtime', 'ops.agent_chat.test_runtime',
    'ops.agent_chat.test_worker', '-v']
started = datetime.now(timezone.utc).isoformat()
result = subprocess.run(command, cwd=root, capture_output=True, text=True, encoding='utf-8', errors='replace')
folder = root / 'evals/reports/task56-professional-20261014'
folder.mkdir(parents=True, exist_ok=True)
(folder / 'runtime-tests.log').write_text(result.stdout + result.stderr, encoding='utf-8')
match = re.search(r'Ran (\d+) tests in ([\d.]+)s', result.stderr)
report = {'started_at': started, 'finished_at': datetime.now(timezone.utc).isoformat(),
    'command': command, 'exit_code': result.returncode,
    'tests': int(match[1]) if match else None, 'seconds': float(match[2]) if match else None,
    'real': ['Linux namespaces', 'Python', 'Node', 'offline pip/npm installs', 'LibreOffice/Poppler', 'Chromium', 'Deep Agents SDK'],
    'simulated': ['model responses', 'search responses', 'E2B administrative transport'],
    'not_run': ['paid models', 'paid search', 'new E2B image build or deployment']}
(folder / 'runtime-tests.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
if result.returncode:
    print((result.stdout + result.stderr)[-16000:])
sys.exit(result.returncode)
