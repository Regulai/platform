"""Capture the isolated E4 documental acceptance; review every emitted PNG before approval."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/physical/documental'
OUT.mkdir(parents=True, exist_ok=True)
stamp = time.time_ns()
log = OUT / f'test-{stamp}.log'
started = time.monotonic()
with log.open('w', encoding='utf-8') as stream:
    result = subprocess.run(['rtk', 'proxy', sys.executable, '-m', 'ops.agent_chat.p1_test',
        '--database', 'test_regulai_p1_documental', 'ops.agent_chat.p1_documental_acceptance'],
        cwd=ROOT, env=dict(os.environ, PYTHONIOENCODING='utf-8'), stdout=stream, stderr=subprocess.STDOUT)
receipt = {'exit_code': result.returncode, 'duration_seconds': time.monotonic() - started,
    'log': str(log), 'database': 'test_regulai_p1_documental', 'provider': 'httpx.MockTransport',
    'paid_calls': 0, 'microvm_verified': False}
(OUT / f'test-{stamp}.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt))
raise SystemExit(result.returncode)
