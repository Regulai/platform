"""Prepare/start/clean up the owned P0 evaluation inside the existing Linux VM.

The source installation and its services are never replaced or restarted.
--prepare starts only a new PostgreSQL; application and worker remain stopped.
--sync-code updates only owned source/SDK files while web and worker are stopped.
--start requires the prepared guarded application. --cleanup preserves the
evaluation database volume and evidence, but removes copied provider/E2B keys.
All credentials stay in private files inside the VM.
"""
import argparse
import base64
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time

PREFIX = 'p0-eval-20261016'
BASE = Path('/opt/regulai-p0-eval-20261016')
LABEL = 'regulai.p0_evaluation'
DB = 'p0-eval-db20261016'
WEB, WORKER = PREFIX + '-web', PREFIX + '-worker'
DB_NET, OUT_NET, VOLUME = PREFIX + '-database', PREFIX + '-out', PREFIX + '-postgres'
EXEC_NET = 'regulai-v2-exec'
SDK_FILES = ('adapter.py', 'protocol.py', 'runtime_contract.py', 'worker.py', 'sandbox_pool.py',
             'professional_worker.py', 'workspace_backend.py', 'browser_worker.py', 'spreadsheet_program.py',
             'sandbox_runner.py', 'checkpoint_runner.py')


def run(*args, capture=False, check=True, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=check, capture_output=capture,
                          text=True, **kwargs)


def docker(*args, **kwargs):
    return run('docker', *args, **kwargs)


def inspect(kind, name, *, owned=True):
    result = docker(kind, 'inspect', name, capture=True, check=False)
    if result.returncode:
        return None
    value = json.loads(result.stdout)[0]
    labels = value.get('Labels') if kind in ('network', 'volume') else value['Config'].get('Labels')
    if owned and (labels or {}).get(LABEL) != PREFIX:
        raise RuntimeError('Resource is not owned by this evaluation: ' + name)
    return value


def private_file(path, content, *, uid=1000):
    if path.exists() or path.is_symlink():
        raise RuntimeError('Refusing to replace private evaluation file: ' + path.name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content)
    os.chown(path, uid, uid)


def checked_base():
    if BASE.resolve() != BASE or BASE.is_symlink() or not BASE.is_dir():
        raise RuntimeError('Evaluation directory is absent or redirected.')
    if (BASE / 'owner.json').read_text(encoding='utf-8') != json.dumps({'owner': PREFIX}):
        raise RuntimeError('Evaluation directory ownership marker differs.')


def common_flags():
    return ['--label', LABEL + '=' + PREFIX, '--user', '1000:1000', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000']


def mount(source, target, *, readonly=True):
    return ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')]


def executor_address(network):
    ranges = [ipaddress.ip_network(item['Subnet']) for item in network['IPAM']['Config']
              if item.get('Subnet') and ipaddress.ip_network(item['Subnet']).version == 4]
    if len(ranges) != 1 or ranges[0].num_addresses > 65536:
        raise RuntimeError('Unexpected executor network address range.')
    occupied = {item.get('IPv4Address', '').split('/')[0]
                for item in network.get('Containers', {}).values()}
    occupied.update(item.get('Gateway') for item in network['IPAM']['Config'])
    for address in reversed(list(ranges[0].hosts())):
        if str(address) not in occupied:
            return str(address)
    raise RuntimeError('Executor network has no free address for the evaluation.')


def prepare():
    checked_base()
    for name in (WEB, WORKER):
        current = inspect('container', name)
        if current:
            raise RuntimeError('Evaluation containers already prepared; use --start or --cleanup: ' + name)
    source, private, state, worker = (BASE / name for name in ('source', 'private', 'state', 'worker'))
    for folder in (private, state, worker):
        if folder.is_symlink() or folder.resolve().parent != BASE:
            raise RuntimeError('Refusing redirected evaluation directory: ' + folder.name)
        folder.mkdir(mode=0o700, exist_ok=True)
        os.chmod(folder, 0o700)
        os.chown(folder, 1000, 1000)
    if not (private / 'eval.json').exists():
        config = {
            'database': {'name': 'p0_eval', 'user': 'p0_eval', 'password': secrets.token_urlsafe(36),
                         'host': DB, 'port': '5432'},
            'secret_key': secrets.token_urlsafe(48),
            'encryption_key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            'worker_token': secrets.token_urlsafe(48), 'budget_usd': '5.00', 'source_profile_id': 1,
            'eval_username': 'p0-evaluation-20261016', 'eval_password': secrets.token_urlsafe(32),
            'port': 31068,
        }
        private_file(private / 'eval.json', json.dumps(config))
    config = json.loads((private / 'eval.json').read_text(encoding='utf-8'))
    # A separate uid-999 readable file avoids granting PostgreSQL access to the
    # app encryption key or provider connection. Only this file is mounted.
    if not (BASE / 'database-password').exists():
        private_file(BASE / 'database-password', config['database']['password'], uid=999)
    if not (private / 'connection.json').exists():
        docker('run', '--rm', '--network', 'host', *common_flags(),
               *mount('/opt/regulai/private', '/run/private'),
               *mount(private, '/eval-private', readonly=False),
               *mount(source / 'ops/agent_chat/p0_eval_export.py', '/export.py'),
               'regulai-v2-web:local', 'python', '/export.py', '--profile-id', str(config['source_profile_id']))
    if not (worker / 'token').exists():
        private_file(worker / 'token', config['worker_token'])
    if not (worker / 'e2b-key').exists():
        private_file(worker / 'e2b-key', Path('/opt/regulai/worker/e2b-key').read_text(encoding='utf-8'))
    for name, internal in ((DB_NET, True), (OUT_NET, False)):
        if not inspect('network', name):
            docker('network', 'create', '--label', LABEL + '=' + PREFIX,
                   *(['--internal'] if internal else []), name)
    executor_network = inspect('network', EXEC_NET, owned=False)
    if not executor_network:
        raise RuntimeError('Existing restricted E2B executor network is unavailable.')
    address = executor_address(executor_network)
    config['allowed_hosts'] = ['127.0.0.1', 'localhost', WEB, address]
    # No reader exists yet. Preserve the mode/owner of the private file.
    (private / 'eval.json').write_text(json.dumps(config), encoding='utf-8')
    if not inspect('volume', VOLUME):
        docker('volume', 'create', '--label', LABEL + '=' + PREFIX, VOLUME)
    if not inspect('container', DB):
        docker('create', '--name', DB, '--label', LABEL + '=' + PREFIX, '--network', DB_NET,
               '--memory', '256m', '--cpus', '0.5', '-e', 'POSTGRES_USER=p0_eval',
               '-e', 'POSTGRES_DB=p0_eval', '-e', 'POSTGRES_PASSWORD_FILE=/run/secrets/password',
               *mount(BASE / 'database-password', '/run/secrets/password'),
               '--mount', f'type=volume,src={VOLUME},dst=/var/lib/postgresql/data', 'postgres:17-alpine')
    docker('start', DB)
    for _ in range(40):
        if docker('exec', DB, 'pg_isready', '-U', 'p0_eval', capture=True, check=False).returncode == 0:
            break
        time.sleep(.5)
    else:
        raise RuntimeError('Isolated PostgreSQL did not become ready.')
    docker('create', '--name', WEB, '--network', OUT_NET, *common_flags(),
           '--memory', '768m', '--cpus', '1', '--pids-limit', '128',
           *mount(private, '/run/private'), *mount(state, '/eval-state', readonly=False),
           *mount(source / 'regulai', '/app/regulai'), *mount(source / 'ops', '/app/ops'),
           *mount(source / 'evals', '/app/evals'),
           'regulai-v2-web:local', 'python', '/app/ops/agent_chat/p0_eval_app.py')
    docker('network', 'connect', DB_NET, WEB)
    docker('network', 'connect', '--ip', address, EXEC_NET, WEB)
    original = json.loads(Path('/opt/regulai/worker/config.json').read_text(encoding='utf-8'))
    worker_config = {key: original[key] for key in ('api_url', 'sandbox_url', 'template')}
    worker_config.update(api_key_file='/run/task50/e2b-key', worker_token_file='/run/task50/token',
                         internal_endpoint=f'http://{address}:31068/internal/agents/', concurrency=1)
    if not (worker / 'config.json').exists():
        private_file(worker / 'config.json', json.dumps(worker_config))
    sdk = BASE / 'sdk/regulai/front/agents'
    sdk.mkdir(parents=True, exist_ok=True)
    for name in SDK_FILES:
        shutil.copyfile(source / 'regulai/front/agents' / name, sdk / name)
    shutil.copytree(source / 'regulai/front/agents/runtime', sdk / 'runtime', dirs_exist_ok=True)
    docker('create', '--name', WORKER, '--network', EXEC_NET, *common_flags(),
           '--stop-timeout', '35', '--dns', '127.0.0.1', '--memory', '768m', '--cpus', '1',
           '--pids-limit', '128', *mount(worker, '/run/task50'),
           *mount(state, '/state', readonly=False), *mount(sdk, '/app/regulai/front/agents'),
           'regulai-v2-worker:local', 'python', '-m', 'front.agents.worker', '--config', '/run/task50/config.json')
    print(json.dumps({'prepared': True, 'database_started': True, 'application_started': False,
                      'worker_started': False, 'source': str(source), 'state': str(state)}))


def start():
    checked_base()
    for name in (DB, WEB, WORKER):
        if not inspect('container', name):
            raise RuntimeError('Run --prepare first; missing resource: ' + name)
    docker('start', DB, WEB)
    probe = "import urllib.request;urllib.request.urlopen('http://127.0.0.1:31068/login/',timeout=2)"
    for _ in range(90):
        if docker('exec', WEB, 'python', '-c', probe, capture=True, check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Evaluation web is not ready; worker was not started. Inspect its sanitized log.')
    # Refresh the numeric address after start, so restricted worker DNS is not
    # needed for the application endpoint.
    address = inspect('container', WEB)['NetworkSettings']['Networks'][EXEC_NET]['IPAddress']
    if not address:
        raise RuntimeError('Evaluation web has no executor-network address.')
    target = BASE / 'worker/config.json'
    cfg = json.loads(target.read_text(encoding='utf-8'))
    cfg['internal_endpoint'] = f'http://{address}:31068/internal/agents/'
    target.write_text(json.dumps(cfg), encoding='utf-8')
    docker('start', WORKER)
    print(json.dumps({'started': True, 'web': WEB, 'worker': WORKER, 'port': 31068}))


def sync_code():
    checked_base()
    for name in (WEB, WORKER):
        current = inspect('container', name)
        if current and current['State']['Running']:
            raise RuntimeError('Stop the evaluation container before syncing source: ' + name)
    source = BASE / 'source/regulai/front/agents'
    sdk = BASE / 'sdk/regulai/front/agents'
    if sdk.is_symlink() or not sdk.resolve().is_relative_to(BASE):
        raise RuntimeError('Refusing redirected SDK evaluation directory.')
    sdk.mkdir(parents=True, exist_ok=True)
    for name in SDK_FILES:
        shutil.copyfile(source / name, sdk / name)
    shutil.copytree(source / 'runtime', sdk / 'runtime', dirs_exist_ok=True)
    print(json.dumps({'source_synchronized': True, 'services_restarted': False,
                      'database_unchanged': True, 'source': str(BASE / 'source')}))


def cleanup():
    checked_base()
    # Retain synthetic conversations/receipts without retaining a usable
    # provider credential encrypted in that database after the lab closes.
    current_db = inspect('container', DB)
    if current_db and current_db['State']['Running']:
        sql = "DO $$ BEGIN IF to_regclass('public.front_companyengine') IS NOT NULL THEN UPDATE front_companyengine SET api_key='', active=FALSE; END IF; END $$;"
        # Stop model dispatch first; no new call may race credential removal.
        current_worker = inspect('container', WORKER)
        if current_worker and current_worker['State']['Running']:
            docker('stop', '-t', '35', WORKER)
        docker('exec', DB, 'psql', '-U', 'p0_eval', '-d', 'p0_eval', '-v', 'ON_ERROR_STOP=1', '-c', sql)
    for name in (WORKER, WEB, DB):
        current = inspect('container', name)
        if current:
            if current['State']['Running']:
                docker('stop', '-t', '35' if name == WORKER else '15', name)
            docker('rm', name)
    for name in (DB_NET, OUT_NET):
        if inspect('network', name):
            docker('network', 'rm', name)
    for path in (BASE / 'private/connection.json', BASE / 'worker/e2b-key'):
        if path.is_symlink() or path.parent.resolve() not in (BASE / 'private', BASE / 'worker'):
            raise RuntimeError('Refusing cleanup of redirected private path.')
        path.unlink(missing_ok=True)
    print(json.dumps({'cleaned': True, 'retained_database_volume': VOLUME,
                      'retained_evidence': str(BASE / 'state'), 'provider_and_e2b_copies_removed': True}))


def bundle(root, destination):
    excluded = {'__pycache__', 'media', 'staticfiles', '.runtime', '.checkpoints', 'local_settings.py'}
    folders = ('regulai', 'ops/agent_chat', 'ops/agent_probe', 'ops/setup',
               'evals/corpora/p0-conversations-20261016')
    with tarfile.open(destination, 'w:gz') as archive:
        for folder in folders:
            source = root / folder
            if not source.is_dir():
                raise RuntimeError('Required evaluation source is absent: ' + folder)
            for path in sorted(source.rglob('*')):
                relative = path.relative_to(root)
                if (not path.is_file() or path.is_symlink() or any(part in excluded or part.startswith('.') for part in relative.parts)
                        or path.suffix in {'.sqlite3', '.pyc', '.key', '.pem', '.dump'} or 'private' in path.name.lower()):
                    continue
                archive.add(path, arcname=relative.as_posix())


def host(action):
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location('p0_installer', root / 'setup.py')
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    ssh = ['rtk', 'proxy', *installer.SSH]
    if action in ('prepare', 'sync-code'):
        with tempfile.TemporaryDirectory(prefix='regulai-p0-source-') as temporary:
            archive = Path(temporary) / 'source.tar.gz'
            bundle(root, archive)
            # Validate the exact owned path before creating it or transferring
            # source. Never extract into the installation's source directory.
            bootstrap = "action=" + repr(action) + "\n" + """import json,pathlib,subprocess
p=pathlib.Path('/opt/regulai-p0-eval-20261016')
assert not p.is_symlink() and p.resolve()==p
marker=json.dumps({'owner':'p0-eval-20261016'})
if p.exists():
 assert (p/'owner.json').read_text()==marker
 for name in ['p0-eval-20261016-web','p0-eval-20261016-worker']:
  r=subprocess.run(['docker','inspect',name],capture_output=True,text=True)
  if r.returncode==0:
   info=json.loads(r.stdout)[0]
   assert action=='sync-code', 'Evaluation already prepared; use --sync-code with stopped services'
   assert info['Config'].get('Labels',{}).get('regulai.p0_evaluation')=='p0-eval-20261016'
   assert not info['State']['Running'], 'Stop the evaluation container before syncing source'
else:
 assert action=='prepare', 'Evaluation is not prepared'
 p.mkdir(mode=0o755)
 (p/'owner.json').write_text(marker)
(p/'source').mkdir(exist_ok=True)
assert not (p/'source').is_symlink() and (p/'source').resolve()==p/'source'
"""
            subprocess.run([*ssh, 'sudo python3 -c ' + shlex.quote(bootstrap)], check=True)
            with archive.open('rb') as stream:
                subprocess.run([*ssh, 'sudo tar -xzf - -C ' + (BASE / 'source').as_posix()], stdin=stream, check=True)
    remote = f'sudo python3 {BASE.as_posix()}/source/ops/agent_chat/p0_eval_environment.py --remote-action {action}'
    subprocess.run([*ssh, remote], check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    choices = parser.add_mutually_exclusive_group(required=True)
    for action in ('prepare', 'start', 'cleanup', 'sync-code'):
        choices.add_argument('--' + action, action='store_const', const=action, dest='action')
    choices.add_argument('--remote-action', choices=('prepare', 'start', 'cleanup', 'sync-code'))
    args = parser.parse_args()
    if args.remote_action:
        if os.geteuid() != 0:
            raise SystemExit('The remote action requires the dedicated VM administrator.')
        {'prepare': prepare, 'start': start, 'cleanup': cleanup, 'sync-code': sync_code}[args.remote_action]()
    else:
        host(args.action)
