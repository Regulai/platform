"""Pinned OfficeCLI binary/license and synthetic evaluation files only."""
import io
from pathlib import Path
import subprocess
import tarfile

root = Path(__file__).resolve().parents[2]
files = [p for p in (root / '.task52-officecli-source').rglob('*') if p.is_file()]
files += [p for p in (root / 'ops/agent_chat').glob('*pptx*') if p.is_file()]
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w') as archive:
    for path in files:
        archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
    'sh', '-c', 'cat > /tmp/task52-evaluation.tar'], input=buffer.getvalue(), check=True)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'scp', '-i', '/vm/id_ed25519',
    '-o', 'UserKnownHostsFile=/vm/known_hosts', '-P', '2222', '/tmp/task52-evaluation.tar',
    'probe@127.0.0.1:/home/probe/task52-evaluation.tar'], check=True)
print(f'Transferred {len(files)} OfficeCLI evaluation files')
