"""Infrastructure provisioning inside the dedicated Linux VM. No mock runtime."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request

ROOT = Path('/opt/regulai')
SOURCE = ROOT / 'source'
PRIVATE = ROOT / 'private'
WORKER = ROOT / 'worker'
POSTGRES = 'postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24'
WEB = 'regulai-v2-web:local'
EXECUTOR = 'regulai-v2-worker:local'
SANDBOX = 'regulai-v2-sandbox:local'


def run(*args, capture=False, **kwargs):
    return subprocess.run(args, check=True, capture_output=capture, text=True, **kwargs)


def docker(*args, **kwargs):
    return run('docker', *args, **kwargs)


def exists(kind, name):
    return subprocess.run(['docker', kind, 'inspect', name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def secret_file(path, content, uid=1000):
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
        os.chown(path, uid, uid)


def web_command(*command, writable=False):
    return docker('run', '--rm', '--network', 'host', '--user', '1000:1000', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000',
        '--mount', f'type=bind,src={PRIVATE},dst=/run/private' + ('' if writable else ',readonly'),
        WEB, *command)


def main():
    if os.geteuid() != 0 or not (SOURCE / 'ops/setup/server.py').exists():
        raise SystemExit('Run through setup.py inside the installer VM.')
    for directory in (PRIVATE, WORKER, ROOT / 'checkpoints'):
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, 1000, 1000)
    imported = PRIVATE / 'import.json'
    data = json.loads(imported.read_text()) if imported.exists() else None
    if not (PRIVATE / 'server.json').exists():
        if not data or data.get('format') != 'regulai-private-install-v1':
            raise RuntimeError('A real private installation profile is required.')
        config = dict(database_password=secrets.token_urlsafe(36), secret_key=secrets.token_urlsafe(48),
                      encryption_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
                      worker_token=secrets.token_urlsafe(48), admin_id=data['admin_id'])
        secret_file(PRIVATE / 'server.json', json.dumps(config))
    config = json.loads((PRIVATE / 'server.json').read_text())
    secret_file(PRIVATE / 'postgres-password', config['database_password'], uid=999)
    secret_file(WORKER / 'token', config['worker_token'])
    if not (WORKER / 'e2b-key').exists():
        key = docker('compose', '--project-directory', '/home/probe/e2b', 'exec', '-T',
                     '--interactive=false', 'ready', 'cat', '/run/e2b/team-api-key', capture=True).stdout.strip()
        secret_file(WORKER / 'e2b-key', key)
    worker_config = {'api_url': 'http://172.30.58.1:3000', 'sandbox_url': 'http://172.30.58.1:3002',
                     'api_key_file': '/run/task50/e2b-key', 'template': 'regulai-v2-professional',
                     'internal_endpoint': 'http://172.30.58.1:31058/internal/agents/',
                     'worker_token_file': '/run/task50/token'}
    secret_file(WORKER / 'config.json', json.dumps(worker_config))
    for image, filename in ((WEB, 'web'), (EXECUTOR, 'executor'), (SANDBOX, 'spreadsheet')):
        print('Building ' + image, flush=True)
        docker('build', '-t', image, '-f', 'ops/agent_chat/Dockerfile.' + filename, '.', cwd=SOURCE)
    if not exists('network', 'regulai-v2-exec'):
        docker('network', 'create', '--internal', '--ipv6', '--subnet', '172.30.58.0/24',
               '--subnet', 'fd58:58::/64', '--opt', 'com.docker.network.bridge.name=br-regulai-v2', 'regulai-v2-exec')
    run('bash', str(SOURCE / 'ops/setup/network.sh'))
    if not exists('container', 'regulai-v2-postgres'):
        docker('run', '-d', '--name', 'regulai-v2-postgres', '--label', 'regulai.install=v2',
               '-p', '127.0.0.1:55452:5432', '-e', 'POSTGRES_USER=regulai', '-e', 'POSTGRES_DB=regulai',
               '-e', 'POSTGRES_PASSWORD_FILE=/run/secrets/password',
               '--mount', f'type=bind,src={PRIVATE}/postgres-password,dst=/run/secrets/password,readonly',
               '--mount', 'type=volume,src=regulai-v2-postgres,dst=/var/lib/postgresql/data', POSTGRES)
    docker('start', 'regulai-v2-postgres')
    for _ in range(60):
        ready = subprocess.run(['docker', 'exec', 'regulai-v2-postgres', 'pg_isready', '-U', 'regulai'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ready.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('PostgreSQL did not become ready.')
    web_command('python', 'ops/setup/database.py', writable=True)
    if imported.exists():
        imported.unlink()  # Secrets are now encrypted with this installation's key.
    if not (ROOT / 'template-built').exists():
        docker('save', SANDBOX, '-o', str(ROOT / 'sandbox.tar'))
        registry = subprocess.Popen(['python3', str(SOURCE / 'ops/agent_chat/local_image.py'), str(ROOT / 'sandbox.tar')])
        try:
            for _ in range(180):
                try:
                    with urllib.request.urlopen('http://127.0.0.1:5000/v2/', timeout=2):
                        break
                except OSError:
                    time.sleep(1)
            else:
                raise RuntimeError('Local template image registry unavailable.')
            build = dict(worker_config, api_url='http://127.0.0.1:3000', sandbox_url='http://127.0.0.1:3002',
                         image='localhost:5000/task50-sheet@sha256:' + (ROOT / 'image-manifest.sha256').read_text().strip())
            secret_file(WORKER / 'template.json', json.dumps(build))
            docker('run', '--rm', '--network', 'host', '--mount', f'type=bind,src={WORKER},dst=/run/task50,readonly',
                   EXECUTOR, 'python', '/app/ops/agent_chat/build_template.py', '/run/task50/template.json')
            (ROOT / 'template-built').write_text('regulai-v2-professional\n')
        finally:
            registry.terminate()
            registry.wait(timeout=15)
    # Containers are created once. Normal starts never replace a database or reset users.
    flags = ['--label', 'regulai.install=v2', '--user', '1000:1000', '--read-only',
             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
             '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000']
    if not exists('container', 'regulai-v2-web'):
        docker('run', '-d', '--name', 'regulai-v2-web', '--network', 'host', *flags,
               '--mount', f'type=bind,src={PRIVATE},dst=/run/private,readonly', WEB)
    if not exists('container', 'regulai-v2-worker'):
        docker('create', '--name', 'regulai-v2-worker', '--network', 'regulai-v2-exec', *flags,
               '--dns', '127.0.0.1', '--memory', '1024m', '--cpus', '1', '--pids-limit', '128',
               '--mount', f'type=bind,src={WORKER},dst=/run/task50,readonly',
               '--mount', f'type=bind,src={ROOT}/checkpoints,dst=/state', EXECUTOR)
    print('Application installed. Startup will verify login and a real isolated microVM.', flush=True)


if __name__ == '__main__':
    main()
