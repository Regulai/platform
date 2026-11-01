"""Collect allowlisted synthetic PPTX evaluation evidence."""
import io
from pathlib import Path
import subprocess
import sys
import tarfile

case = sys.argv[1]
sources = {'officecli': '/home/probe/task52-eval/evidence/officecli',
           'presentation-runs': '/home/probe/task50/evidence-live/presentation-runs',
           'http-regression': '/home/probe/task50/evidence-live/task52-regression',
           'design-v2': '/home/probe/task52-eval/evidence/design-v2',
           'design-v3': '/home/probe/task52-eval/evidence/design-v3',
           'chart-comparison': '/home/probe/task52-eval/evidence/chart-comparison',
           'officecli-final': '/home/probe/task52-eval/evidence/officecli-final',
           'officecli-repaired': '/home/probe/task52-eval/evidence/officecli-repaired'}
if case not in sources:
    raise ValueError('Unknown evidence')
output = Path(__file__).resolve().parents[2] / 'evals/reports/task52-powerpoint-20261008' / sys.argv[2]
command = ['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'ssh', '-i', '/vm/id_ed25519',
    '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/vm/known_hosts', '-p', '2222', 'probe@127.0.0.1',
    'tar', '-C', sources[case], '-cf', '-', '.']
result = subprocess.run(command, capture_output=True, check=True)
output.mkdir(parents=True, exist_ok=False)
with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
    archive.extractall(output, filter='data')
print(output)
