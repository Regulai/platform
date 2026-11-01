"""Transfer only pinned upstream evaluation code and synthetic fixture builders."""
import io
from pathlib import Path
import subprocess
import tarfile

root = Path(__file__).resolve().parents[2]
files = [p for p in (root / '.task51-branddocs-source').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
files += [root / 'ops/agent_chat' / p for p in ('document_fixture.py', 'evaluate_branddocs.py', 'Dockerfile.docx-evaluation')]
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w') as archive:
    for path in files:
        archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
    'sh', '-c', 'cat > /tmp/task51-evaluation.tar'], input=buffer.getvalue(), check=True)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'scp', '-i', '/vm/id_ed25519',
    '-o', 'UserKnownHostsFile=/vm/known_hosts', '-P', '2222', '/tmp/task51-evaluation.tar',
    'probe@127.0.0.1:/home/probe/task51-evaluation.tar'], check=True)
print(f'Transferred {len(files)} evaluation files')
