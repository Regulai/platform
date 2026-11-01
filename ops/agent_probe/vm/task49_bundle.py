"""Transfer task49 network probe files only, never private application modules."""
import io
from pathlib import Path
import subprocess
import tarfile

root = Path(__file__).resolve().parents[3]
files = ['regulai/front/agents/adapter.py', 'regulai/front/agents/protocol.py',
    'ops/agent_probe/network_governed.py', 'ops/agent_probe/vm/task49_network.py']
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w') as archive:
    for name in files:
        archive.add(root / name, arcname=name, recursive=False)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
    'sh', '-c', 'cat > /tmp/task49-source.tar'], input=buffer.getvalue(), check=True)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'scp',
    '-i', '/vm/id_ed25519', '-o', 'UserKnownHostsFile=/vm/known_hosts', '-P', '2222',
    '/tmp/task49-source.tar', 'probe@127.0.0.1:/home/probe/task49-source.tar'], check=True)
