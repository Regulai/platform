"""Collect only synthetic task-51 evaluation evidence from the existing VM."""
import io
from pathlib import Path
import subprocess
import tarfile
import sys

root = Path(__file__).resolve().parents[2]
case = sys.argv[1] if len(sys.argv) > 1 else 'branddocs-linux'
sources = {'branddocs-linux': '/home/probe/task51-eval/evidence/branddocs',
           'document-runs': '/home/probe/task50/evidence-live/document-runs',
           'http-regression': '/home/probe/task50/evidence-live/task51-regression',
           'first-docx-draft': '/home/probe/task50/evidence-live/first-docx-draft'}
if case not in sources:
    raise ValueError('Unknown synthetic evidence')
output = root / 'evals/reports/task51-word-pdf-20261008' / case
command = ['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'ssh', '-i', '/vm/id_ed25519',
    '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/vm/known_hosts', '-p', '2222', 'probe@127.0.0.1',
    'tar', '-C', sources[case], '-cf', '-', '.']
result = subprocess.run(command, capture_output=True, check=True)
output.mkdir(parents=True, exist_ok=False)
with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
    archive.extractall(output, filter='data')
print(output)
