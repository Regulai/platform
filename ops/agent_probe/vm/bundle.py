"""Copy an explicit allowlist of probe source, never the repository or secrets."""
import io
from pathlib import Path
import subprocess
import tarfile

root = Path(__file__).resolve().parents[3]
files = [
    'regulai/front/agents/__init__.py', 'regulai/front/agents/integration_probe.py',
    'regulai/front/agents/probe_csv.py', 'ops/agent_probe/requirements.txt',
    'ops/agent_probe/test_probe.py', 'ops/agent_probe/runtime_checks.py',
    'ops/agent_probe/run_e2b.py', 'ops/agent_probe/input/numbers.csv',
    'ops/agent_probe/Dockerfile.executor', 'ops/agent_probe/Dockerfile.sandbox',
    'ops/agent_probe/.dockerignore', 'ops/agent_probe/vm/live_lab.py',
]
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w') as archive:
    for path in files:
        archive.add(root / path, arcname=path, recursive=False)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
                'sh', '-c', 'cat > /tmp/task48-source.tar'], input=buffer.getvalue(), check=True)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'scp',
                '-i', '/vm/id_ed25519', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=/vm/known_hosts', '-P', '2222',
                '/tmp/task48-source.tar', 'probe@127.0.0.1:/home/probe/task48-source.tar'], check=True)
print(f'{len(files)} probe files copied to the disposable VM')
