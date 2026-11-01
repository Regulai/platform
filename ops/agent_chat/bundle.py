"""Allowlisted source transfer to the disposable 48 VM; no .env, DB or secrets."""
import io
from pathlib import Path
import subprocess
import tarfile

root = Path(__file__).resolve().parents[2]
files = [p for folder in ('regulai/front', 'regulai/api', 'regulai/regulai', 'ops/agent_chat')
    for p in (root / folder).rglob('*') if p.is_file() and p.suffix in ('.py', '.html', '.md', '.txt', '.in', '.sh', '.docx', '.pptx')
    and '__pycache__' not in p.parts and p.name != 'local_settings.py']
files += [root / 'regulai/manage.py', root / 'ops/agent_chat/Dockerfile.web', root / 'ops/agent_chat/Dockerfile.executor',
          root / 'ops/agent_chat/Dockerfile.spreadsheet',
          root / 'regulai/static/js/agent-chat.js']
files += [p for p in (root / 'regulai/static').rglob('*') if p.is_file() and p.suffix.lower() in
          ('.js', '.css', '.svg', '.png', '.jpg', '.woff', '.woff2', '.ttf', '.ico')
          and p != root / 'regulai/static/js/agent-chat.js']
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode='w') as archive:
    for path in files:
        archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
    'sh', '-c', 'cat > /tmp/task50-source.tar'], input=buffer.getvalue(), check=True)
subprocess.run(['rtk', 'proxy', 'docker', 'exec', 'regulay-task48-e2bvm', 'scp', '-i', '/vm/id_ed25519',
    '-o', 'UserKnownHostsFile=/vm/known_hosts', '-P', '2222', '/tmp/task50-source.tar',
    'probe@127.0.0.1:/home/probe/task50-source.tar'], check=True)
print(f'Transferred {len(files)} source files, without local settings or data')
