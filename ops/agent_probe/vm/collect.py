"""Retrieve only the two non-secret evidence files from our disposable VM."""
import argparse
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('guest_directory')
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if not re.fullmatch(r'/home/probe/task48/evidence(?:-\d{8}T\d{6})?', args.guest_directory):
    parser.error('Expected a task 48 evidence directory, never a credential directory')
args.output.mkdir(parents=True, exist_ok=False)
for name in ('report.json', 'commands.log'):
    result = subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm',
        'ssh', '-i', '/vm/id_ed25519', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=/vm/known_hosts', '-p', '2222', 'probe@127.0.0.1',
        'sudo', 'cat', args.guest_directory + '/' + name], capture_output=True, check=True)
    (args.output / name).write_bytes(result.stdout)
report = json.loads((args.output / 'report.json').read_text())
print(json.dumps({'output': str(args.output), 'passed': report.get('passed', False),
    'trials': [{k: trial[k] for k in ('mode', 'sandbox_id', 'preparation_seconds', 'assignment_seconds',
                                     'contract', 'sandbox_denials')}
               for trial in report.get('live', {}).get('trials', [])]}, indent=2))
