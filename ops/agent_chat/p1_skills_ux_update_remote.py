"""Guest side of the pinned local v2 web-only UX update; not a general deployer."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request

IDENTITY = 'p1-20261016-skills-ux-a1'
WEB = 'regulai-v2-web'
WORKER = 'regulai-v2-worker'
POSTGRES = 'regulai-v2-postgres'
STAGE = Path('/opt/regulai/updates') / IDENTITY
RUNTIME = Path('/opt/regulai/updates/p1-20261016-taste-a2')
NAMES = (WEB, WORKER, POSTGRES)
ALLOWED_PREFIXES = ('regulai/front/templates/', 'regulai/static/js/', 'regulai/static/css/')
ALLOWED_PYTHON = {'regulai/front/agents/skills.py', 'regulai/front/agents/skill_views.py',
    'regulai/front/chat_page.py', 'regulai/front/context_processors.py'}
ALLOWED_CATALOG = 'regulai/front/agents/runtime/skill_catalog.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def current_web(expected_id):
    row = inspect(WEB)
    if row['Id'] != expected_id:
        raise RuntimeError('web_name_identity_changed')
    return row


def canonical_mounts(mounts):
    if len({row['Destination'] for row in mounts}) != len(mounts):
        raise RuntimeError('duplicate_mount_destination')
    return sorted(mounts, key=lambda row: row['Destination'])


def canonical_container(row):
    return {**row, 'mounts': canonical_mounts(row['mounts'])}


def config_digest(rows):
    paths = [Path('/opt/regulai/private/server.json'), Path('/opt/regulai/private/postgres-password')]
    mount = [m for m in rows[WORKER]['Mounts'] if m['Destination'] == '/run/task50']
    if len(mount) != 1 or mount[0]['RW']:
        raise RuntimeError('active_worker_config_mount_changed')
    paths.extend(Path(mount[0]['Source']) / name for name in ('config.json', 'token', 'e2b-key'))
    paths.extend(RUNTIME / 'runtime' / name for name in ('runtime.json', 'p1_activation_remote.py'))
    values = {}
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('active_private_configuration_not_regular')
        values[str(path)] = digest(path.read_bytes())
    return digest(json.dumps(values, sort_keys=True).encode())


def stable_workers(before):
    for name in (WORKER, POSTGRES):
        after = inspect(name)
        if (original_identity({name: after}) != original_identity({name: before[name]})
                or not after['State']['Running'] or after['State']['StartedAt'] != before[name]['State']['StartedAt']
                or after['RestartCount'] != before[name]['RestartCount']):
            raise RuntimeError('untouched_service_identity_or_lifetime_changed:' + name)


def candidate_source(image):
    code = '''import hashlib,json
from pathlib import Path
result={}
for directory in ('regulai','ops/agent_chat','ops/setup'):
 for path in (Path('/app')/directory).rglob('*'):
  if not path.is_file() or path.suffix in ('.pyc','.sqlite','.sqlite3','.db','.dump','.pem','.key'): continue
  if path.name=='local_settings.py' or path.name.startswith('.env') or any(x in path.parts for x in ('__pycache__','.runtime','private','media','node_modules','.venv','staticfiles')): continue
  raw=path.read_bytes()
  if path.suffix in ('.py','.js','.mjs','.cjs','.ts','.css','.scss','.html','.json','.md','.txt','.in','.sh','.yaml','.yml') or path.name.startswith(('Dockerfile','LICENSE','NOTICE')): raw=raw.replace(b'\\r\\n',b'\\n')
  result[path.relative_to('/app').as_posix()]=hashlib.sha256(raw).hexdigest()
print(json.dumps(result))
'''
    return json.loads(docker('run', '--rm', '-i', '--network', 'none', '--user', '1000:1000',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        image, 'python', '-', data=code.encode()))


def gate(state, original=True):
    rows = {name: inspect(name) for name in NAMES}
    if original and original_identity(rows) != state['original_identity']:
        raise RuntimeError('live_container_changed_since_prepare')
    if not original and (rows[WEB]['Id'] != state['candidate_id']
            or original_identity({WEB: rows[WEB]}) != state['candidate_identity']
            or rows[WEB]['State']['StartedAt'] != state['candidate_started_at']):
        raise RuntimeError('candidate_web_identity_or_lifetime_changed')
    if config_digest(rows) != state['configuration_digest']:
        raise RuntimeError('active_configuration_changed_since_prepare')
    if original and source_manifest() != read_json(STAGE / 'before-source.json'):
        raise RuntimeError('live_source_changed_since_prepare')
    if json.loads(docker('image', 'inspect', state['image']))[0]['Id'] != state['image_id']:
        raise RuntimeError('candidate_tag_changed_since_prepare')
    stable_workers(read_json(STAGE / 'original-containers.json'))
    return require_idle(current=True)


def prepare(payload):
    rows = {name: inspect(name) for name in NAMES}
    baseline = payload['baseline']
    for name in NAMES:
        if canonical_container(safe_container(rows[name])) != canonical_container(baseline['containers'][name]):
            raise RuntimeError('recon_container_identity_changed')
    source = source_manifest()
    if source != baseline['source_hashes']:
        raise RuntimeError('recon_live_source_changed')
    require_idle(current=True)
    if STAGE.exists():
        raise RuntimeError('ux_stage_already_exists')
    STAGE.mkdir(mode=0o700)
    private_json(STAGE / 'original-containers.json', rows)
    private_json(STAGE / 'before-source.json', source)
    files = {path: base64.b64decode(value, validate=True) for path, value in payload['files'].items()}
    if not files or set(files) != set(payload['hashes']) or sum(map(len, files.values())) > 5 * 1024 * 1024:
        raise RuntimeError('invalid_source_manifest')
    build = STAGE / 'build'
    build.mkdir(mode=0o700)
    for path, data in files.items():
        relative = Path(path)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in path or ':' in path
                or not (path in ALLOWED_PYTHON or path == ALLOWED_CATALOG or path.startswith(ALLOWED_PREFIXES)
                    and relative.suffix in {'.html', '.js', '.css'})
                or digest(data) != payload['hashes'][path]):
            raise RuntimeError('unsafe_ux_source')
        target = build / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    image = 'regulai-v2-web:' + IDENTITY
    import subprocess
    if subprocess.run(['docker', 'image', 'inspect', image], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode == 0:
        raise RuntimeError('candidate_image_tag_already_exists')
    base = rows[WEB]['Image']
    # FROM uses the already present immutable base; COPY is the only operation.
    dockerfile = ['FROM ' + base, 'LABEL regulai.skills_ux=' + IDENTITY]
    dockerfile.extend('COPY ' + json.dumps([path, '/app/' + path]) for path in sorted(files))
    (build / 'Dockerfile').write_text('\n'.join(dockerfile) + '\n')
    with (STAGE / 'build.log').open('wb') as log:
        os.chmod(log.name, 0o600)
        # Classic builder accepts an immutable local config ID in FROM. This
        # process-only flag does not alter Docker's daemon or other projects.
        result = subprocess.run(['docker', 'build', '--network=none', '--pull=false',
            '-t', image, str(build)], stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, 'DOCKER_BUILDKIT': '0'}, timeout=120)
        if result.returncode:
            raise RuntimeError('immutable_local_base_build_failed')
    image_id = json.loads(docker('image', 'inspect', image))[0]['Id']
    if candidate_source(image_id) != source | payload['hashes']:
        raise RuntimeError('unexpected_candidate_source_delta')
    before = web_exec('fingerprint', current=True, payload={})
    candidate = web_exec('fingerprint', stage=RUNTIME, image=image, database='regulai', payload=before)
    equal_fingerprints(before, candidate)
    candidate_metadata = require_idle(stage=RUNTIME, image=image, database='regulai')
    current_metadata = require_idle(current=True)
    if candidate_metadata != current_metadata:
        raise RuntimeError('candidate_configuration_or_migrations_differ')
    stable_workers(rows)
    state = {'phase': 'prepared', 'identity': IDENTITY, 'source_commit': payload['commit'],
        'hashes': payload['hashes'], 'original_identity': original_identity(rows),
        'configuration_digest': config_digest(rows), 'image': image, 'image_id': image_id,
        'metadata': current_metadata, 'provider_requests': 0, 'migrations_executed': 0,
        'dependencies_built': False, 'worker_or_template_changed': False,
        'prepare_data_unchanged': True, 'updater_sha256': REQUEST['source_sha256'],
        'helper_sha256': digest(REQUEST['helper'].encode())}
    private_json(STAGE / 'state.json', state)
    return state


def create_web(original, state):
    payload = copy.deepcopy(original['Config'])
    payload.pop('Hostname', None)
    payload.pop('Domainname', None)
    payload['Image'] = state['image_id']
    payload['HostConfig'] = copy.deepcopy(original['HostConfig'])
    payload['Labels'] = {**(payload.get('Labels') or {}), 'regulai.skills_ux': IDENTITY}
    connection = DockerConnection('localhost')
    try:
        connection.request('POST', '/v1.47/containers/create?name=' + urllib.parse.quote(WEB),
            body=json.dumps(payload), headers={'Content-Type': 'application/json'})
        response = connection.getresponse()
        response_body = response.read()
        if response.status != 201:
            raise RuntimeError('ux_web_create_failed')
        state['candidate_id'] = json.loads(response_body)['Id']
        private_json(STAGE / 'state.json', state)
        row = current_web(state['candidate_id'])
        actual_config = copy.deepcopy(row['Config'])
        actual_config.pop('Hostname', None)
        actual_config.pop('Domainname', None)
        expected_config = {key: value for key, value in payload.items() if key != 'HostConfig'}
        if (row['Image'] != state['image_id'] or actual_config != expected_config
                or row['HostConfig'] != original['HostConfig']
                or canonical_mounts(row['Mounts']) != canonical_mounts(original['Mounts'])):
            raise RuntimeError('created_web_configuration_or_mounts_changed')
        state['candidate_identity'] = original_identity({WEB: row})
        private_json(STAGE / 'state.json', state)
    finally:
        connection.close()


def stop_gracefully(expected_id):
    row = current_web(expected_id)
    if row['HostConfig']['RestartPolicy']['Name'] != 'no':
        raise RuntimeError('manual_graceful_stop_requires_no_restart_policy')
    docker('kill', '--signal=TERM', expected_id)
    for _ in range(60):
        row = inspect(expected_id)
        if not row['State']['Running']:
            if row['State']['ExitCode'] != 0:
                raise RuntimeError('web_not_cleanly_stopped')
            return
        time.sleep(0.5)
    raise RuntimeError('web_graceful_stop_pending_no_kill_sent')


def health(expected_id):
    for attempt in range(30):
        current_web(expected_id)
        try:
            with urllib.request.urlopen('http://127.0.0.1:31058/static/js/skills.js', timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            if attempt == 29:
                raise RuntimeError('web_health_readiness_timeout')
            time.sleep(0.5)
    for sample in range(6):
        row = current_web(expected_id)
        if not row['State']['Running'] or row['RestartCount']:
            raise RuntimeError('updated_web_failed_or_restarted')
        with urllib.request.urlopen('http://127.0.0.1:31058/static/js/skills.js', timeout=3) as response:
            if response.status != 200:
                raise RuntimeError('updated_web_asset_health_failed')
        if sample < 5:
            time.sleep(2)


def rollback(state):
    original = read_json(STAGE / 'original-containers.json')[WEB]
    import subprocess
    present = subprocess.run(['docker', 'inspect', WEB], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode == 0
    if present:
        current = inspect(WEB)
        if current['Id'] == original['Id']:
            if current['State']['Running'] and state['phase'] == 'stopping_web':
                # Do not pretend a pending graceful stop was cancelled. Wait for
                # this exact original; never SIGKILL or touch its worker.
                for _ in range(60):
                    current = current_web(original['Id'])
                    if not current['State']['Running']:
                        break
                    time.sleep(0.5)
                else:
                    raise RuntimeError('original_web_still_finishing_graceful_stop')
            if not current['State']['Running']:
                docker('start', original['Id'])
            health(original['Id'])
            stable_workers(read_json(STAGE / 'original-containers.json'))
            state['phase'] = 'rolled_back'
            private_json(STAGE / 'state.json', state)
            return state
        if (current['Id'] != state.get('candidate_id')
                or (current['Config'].get('Labels') or {}).get('regulai.skills_ux') != IDENTITY):
            raise RuntimeError('rollback_web_identity_mismatch')
        require_idle(stage=RUNTIME, image=original['Image'], database='regulai')
        if current['State']['Running']:
            stop_gracefully(current['Id'])
        current_web(current['Id'])
        docker('rename', current['Id'], WEB + '-failed-' + IDENTITY)
    retained = WEB + '-before-' + IDENTITY
    if inspect(retained)['Id'] != original['Id']:
        raise RuntimeError('retained_original_identity_mismatch')
    docker('rename', original['Id'], WEB)
    current_web(original['Id'])
    docker('start', original['Id'])
    health(original['Id'])
    stable_workers(read_json(STAGE / 'original-containers.json'))
    state['phase'] = 'rolled_back'
    private_json(STAGE / 'state.json', state)
    return state


def apply():
    state = read_json(STAGE / 'state.json')
    if (state['phase'] != 'prepared' or state['updater_sha256'] != REQUEST['source_sha256']
            or state['helper_sha256'] != digest(REQUEST['helper'].encode())):
        raise RuntimeError('same_prepared_updater_required')
    gate(state)
    originals = read_json(STAGE / 'original-containers.json')
    state['phase'] = 'stopping_web'
    private_json(STAGE / 'state.json', state)
    try:
        stop_gracefully(originals[WEB]['Id'])
        # Worker is deliberately never stopped. A racing accepted run aborts the
        # switch and brings back the same web; its execution keeps its worker.
        require_idle(stage=RUNTIME, image=originals[WEB]['Image'], database='regulai')
        before = web_exec('fingerprint', stage=RUNTIME, image=originals[WEB]['Image'],
            database='regulai', payload={})
        private_json(STAGE / 'before-apply-data.json', before)
        current_web(originals[WEB]['Id'])
        docker('rename', originals[WEB]['Id'], WEB + '-before-' + IDENTITY)
        state['phase'] = 'retained_original'
        private_json(STAGE / 'state.json', state)
        create_web(originals[WEB], state)
        current_web(state['candidate_id'])
        docker('start', state['candidate_id'])
        state['candidate_started_at'] = current_web(state['candidate_id'])['State']['StartedAt']
        private_json(STAGE / 'state.json', state)
        health(state['candidate_id'])
        expected = read_json(STAGE / 'before-source.json') | state['hashes']
        if source_manifest() != expected:
            raise RuntimeError('unexpected_deployed_source_delta')
        after = web_exec('fingerprint', current=True, payload=before)
        equal_fingerprints(before, after)
        final = gate(state, original=False)
        if final != state['metadata']:
            raise RuntimeError('metadata_changed_during_web_only_update')
        state.update(phase='applied', apply_data_unchanged=True, web=safe_container(inspect(WEB)),
            worker_unchanged=True, postgres_unchanged=True, health_seconds=10, metadata=final)
        private_json(STAGE / 'state.json', state)
        return state
    except Exception:
        rollback(state)
        raise


def main():
    if os.geteuid() != 0 or REQUEST['identity'] != IDENTITY:
        raise RuntimeError('owned_guest_root_required')
    helper = {'__name__': 'ux_activation_helpers', '_ACTIVATION_SOURCE': REQUEST['helper']}
    exec(compile(REQUEST['helper'], 'activation_helpers.py', 'exec'), helper)
    for name in ('inspect', 'safe_container', 'original_identity', 'private_json', 'read_json',
            'source_manifest', 'web_exec', 'require_idle', 'equal_fingerprints', 'docker', 'command',
            'DockerConnection'):
        globals()[name] = helper[name]
    action = REQUEST['action']
    # Serialize only this own update; an unrelated operation is never locked.
    import fcntl
    lock_path = STAGE.parent / (IDENTITY + '.lock')
    with lock_path.open('w') as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            if action == 'prepare':
                value = prepare(REQUEST['payload'])
            elif action == 'apply':
                value = apply()
            elif action == 'rollback':
                value = rollback(read_json(STAGE / 'state.json'))
            elif action == 'inspect':
                value = read_json(STAGE / 'state.json')
            else:
                raise RuntimeError('unknown_web_ux_action')
            print(json.dumps(value))
        except Exception as error:
            # No raw exception args/config: retain the precise guard label only.
            failure_path = STAGE / 'failure.json' if STAGE.is_dir() else STAGE.parent / (IDENTITY + '-preparation-failure.json')
            private_json(failure_path, {'action': action,
                'error_type': type(error).__name__, 'guard': str(error) if isinstance(error, RuntimeError) else 'private_traceback_suppressed'})
            raise


if __name__ == '__main__':
    main()
