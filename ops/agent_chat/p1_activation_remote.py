"""Staged upgrade of the existing, owned v2 installation. Never initializes users.

Run only through p1_activate_local.py. Public output is metadata; dumps, original
Docker configuration and build logs stay in a mode-0700 VM directory. Prepare
does not stop services. Apply is a separate explicit operation. Database restore
is deliberately absent from rollback: the migrations are additive.
"""
import argparse
import copy
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path('/opt/regulai')
NAMES = ('regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres')
ALLOWED_MIGRATIONS = {('front', '0042_agent_artifact_metadata'), ('front', '0043_p1_skills_and_events')}
TEXT_SUFFIXES = {'.py', '.js', '.mjs', '.cjs', '.ts', '.css', '.scss', '.html', '.json', '.md', '.txt', '.in', '.sh', '.yaml', '.yml'}
CAPABILITY = {'node': '24.21.0'}
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def module_source():
    return globals().get('_ACTIVATION_SOURCE') or Path(__file__).read_text(encoding='utf-8')


def checked_id(value):
    if not re.fullmatch(r'p1-[a-z0-9][a-z0-9-]{5,45}', value):
        raise ValueError('invalid_activation_id')
    return value


def stage_path(identity):
    target = (ROOT / 'updates' / checked_id(identity)).resolve()
    if target.parent != (ROOT / 'updates').resolve():
        raise ValueError('stage_outside_updates')
    return target


def private_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def command(args, *, data=None, output=None, timeout=None):
    result = subprocess.run(args, input=data, stdout=output or subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        # Do not expose arguments, provider configuration or subprocess logs.
        raise RuntimeError('local_command_failed:' + Path(args[0]).name + ':' + str(result.returncode))
    return result.stdout if output is None else b''


def docker(*args, **kwargs):
    return command(['docker', *args], **kwargs)


def inspect(name):
    row = json.loads(docker('inspect', name))[0]
    if (row.get('Config', {}).get('Labels') or {}).get('regulai.install') != 'v2':
        raise RuntimeError('container_ownership_mismatch:' + name)
    return row


def original_identity(rows):
    return {name: hashlib.sha256(json.dumps({key: row[key] for key in
        ('Id', 'Image', 'Config', 'HostConfig')}, sort_keys=True).encode()).hexdigest()
        for name, row in rows.items()}


def safe_container(row):
    return {'id': row['Id'], 'image_id': row['Image'], 'image': row['Config']['Image'],
        'running': row['State']['Running'], 'network': row['HostConfig']['NetworkMode'],
        'mounts': [{key: mount.get(key) for key in ('Type', 'Source', 'Destination', 'RW')}
                   for mount in row['Mounts']]}


def _configure(database=None):
    runpy.run_path('/app/ops/setup/server.py', run_name='activation_configuration')
    from django.conf import settings
    from django.db import connections
    if database:
        if database != 'regulai' and not re.fullmatch(r'regulai_p1_[a-z0-9_]{5,45}', database):
            raise RuntimeError('database_scope_denied')
        connections.close_all()
        settings.DATABASES['default']['NAME'] = database
        connections['default'].settings_dict['NAME'] = database
    runtime = Path('/run/p1/runtime.json')
    if runtime.exists():
        proof = read_json(runtime)
        if proof.get('verified'):
            if proof.get('capabilities') != CAPABILITY:
                raise RuntimeError('runtime_capability_mismatch')
            settings.REGULAY_SKILL_RUNTIME_CAPABILITIES = {
                **getattr(settings, 'REGULAY_SKILL_RUNTIME_CAPABILITIES', {}), **CAPABILITY}
    return settings


def inside_web(action, database=None):
    settings = _configure(database)
    from django.db import connection
    if action == 'serve':
        import uvicorn
        from django.core.asgi import get_asgi_application
        from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler
        uvicorn.run(ASGIStaticFilesHandler(get_asgi_application()), host='0.0.0.0', port=31058, access_log=False)
        return
    if action == 'metadata':
        with connection.cursor() as cur:
            cur.execute('SELECT name FROM django_migrations WHERE app = %s ORDER BY name', ['front'])
            migrations = [row[0] for row in cur.fetchall()]
            cur.execute("SELECT status, count(*) FROM front_agentexecution WHERE status IN ('queued','active','outcome_unknown') GROUP BY status")
            live = dict(cur.fetchall())
            historical = "e.status IN ('cancelled','completed','interrupted','failed') AND e.expires_at < now() AND e.finished_at IS NOT NULL"
            cur.execute('SELECT count(*) FROM front_agentexecution e WHERE active_call IS NOT NULL AND NOT (' + historical + ')')
            active_calls = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM front_agentinference i JOIN front_agentexecution e ON e.id=i.execution_id WHERE i.status IN ('received','processing') AND NOT (" + historical + ')')
            pending_inferences = cur.fetchone()[0]
            cur.execute("SELECT e.status,count(*) FROM front_agentexecution e WHERE active_call IS NOT NULL AND (" + historical + ') GROUP BY e.status')
            historical_markers = dict(cur.fetchall())
            cur.execute("SELECT count(*) FROM front_agentinference WHERE response->'_capacity'->>'state' IN ('reserved','active','uncertain')")
            provider_occupied = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM front_agentexecution WHERE job->'sandbox_reservation'->>'state' IN ('reserved','active','uncertain')")
            sandbox_occupied = cur.fetchone()[0]
        return {'migrations': migrations[-4:], 'live': live, 'active_calls': active_calls,
            'pending_inferences': pending_inferences,
            'historical_terminal_markers_preserved': historical_markers,
            'provider_occupied': provider_occupied, 'sandbox_occupied': sandbox_occupied,
            'database': {'engine': connection.settings_dict['ENGINE'], 'host': connection.settings_dict['HOST'],
                         'port': connection.settings_dict['PORT'], 'basename': connection.settings_dict['NAME']},
            'flags': {key: getattr(settings, key, None) for key in ('REGULAY_AGENT_ENABLED',
                'REGULAY_SKILLS_CATALOG', 'REGULAY_SKILLS_RUNTIME', 'REGULAY_AGENT_TEXT_STREAM',
                'REGULAY_ARTIFACT_PREVIEW', 'REGULAY_SKILL_RUNTIME_CAPABILITIES')}}
    if action == 'fingerprint':
        requested = json.load(sys.stdin)
        columns = requested.get('columns')
        quote = connection.ops.quote_name
        with connection.cursor() as cur:
            if columns is None:
                cur.execute("SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND table_name <> 'django_migrations' ORDER BY table_name, ordinal_position")
                columns = {}
                for table, column in cur.fetchall():
                    columns.setdefault(table, []).append(column)
            tables = {}
            for table, names in sorted(columns.items()):
                # Hash rows inside PostgreSQL; no clear business values leave it.
                fields = ','.join(quote(name) for name in names)
                cur.execute('SELECT md5(row(' + fields + ')::text) FROM ' + quote(table) + ' ORDER BY 1')
                hashed, count = hashlib.sha256(), 0
                while batch := cur.fetchmany(1000):
                    for row in batch:
                        hashed.update(row[0].encode() + b'\n')
                        count += 1
                tables[table] = {'count': count, 'sha256': hashed.hexdigest()}
            cur.execute("SELECT sequencename, last_value FROM pg_sequences WHERE schemaname='public' AND sequencename <> 'django_migrations_id_seq' ORDER BY sequencename")
            sequences = dict(cur.fetchall())
        previous_sequences = requested.get('sequences')
        if previous_sequences is not None:
            sequences = {key: sequences.get(key) for key in previous_sequences}
        return {'columns': columns, 'tables': tables, 'sequences': sequences}
    if action == 'migrate':
        from django.db.migrations.executor import MigrationExecutor
        executor = MigrationExecutor(connection)
        target = [('front', '0043_p1_skills_and_events')]
        plan = executor.migration_plan(target)
        if any(backwards or (migration.app_label, migration.name) not in ALLOWED_MIGRATIONS
               for migration, backwards in plan):
            raise RuntimeError('migration_plan_outside_authorized_additive_pair')
        executor.migrate(target)
        return {'applied': [migration.name for migration, _ in plan]}
    if action == 'install':
        from django.contrib.auth import get_user_model
        from front.agents.skill_installation import install
        from front.agents.skills import candidate, installation_view, actor_profile
        from front.models import AgentSkillInstallation
        request = json.load(sys.stdin)
        actor = get_user_model().objects.get(pk=settings.PLATFORM_ADMIN_USER_IDS[0], is_active=True)
        entry = candidate('design-taste-frontend')
        existing = AgentSkillInstallation.objects.filter(owner=actor,
            source_identity=entry['source_identity'], tombstoned_at__isnull=True).first()
        if existing:
            _, profile = actor_profile(actor)
            value = installation_view(existing, profile)
            if not value['enabled'] or not value['availability']['available']:
                raise RuntimeError('existing_taste_installation_unavailable')
            return {'state': 'installed', 'installation_id': str(existing.pk), 'reused': True}
        identity = uuid.uuid5(uuid.NAMESPACE_URL, 'regulai-v2:design-taste-frontend:' + request['activation_id'])
        result = install(actor, identity, {'source': 'catalog', 'candidate': 'design-taste-frontend'})
        if result.get('state') != 'installed':
            raise RuntimeError('taste_installation_failed:' + result.get('code', 'unknown'))
        row = AgentSkillInstallation.objects.get(pk=result['installation_id'], owner=actor)
        _, profile = actor_profile(actor)
        view = installation_view(row, profile)
        if not view['enabled'] or not view['availability']['available']:
            raise RuntimeError('new_taste_installation_unavailable')
        return result
    raise RuntimeError('unknown_inside_action')


def web_exec(action, *, stage=None, image=None, database=None, payload=None, current=False):
    args = ['python', '/run/p1/p1_activation_remote.py', '--inside-web', action]
    if database:
        args += ['--database', database]
    body = json.dumps(payload or {}).encode()
    if current:
        # The existing container has no activation module. Execute an in-memory
        # copy, retaining its normal private configuration without copying keys.
        script = module_source() + '\n'
        script = script.replace("if __name__ == '__main__':\n    main()", '')
        script += '\nvalue=inside_web(' + repr(action) + ',' + repr(database) + ')\nprint(json.dumps(value))\n'
        if payload is not None:
            script = 'import sys,io\nsys.stdin=io.StringIO(' + repr(json.dumps(payload)) + ')\n' + script
        raw = docker('exec', '-i', 'regulai-v2-web', 'python', '-', data=script.encode())
    else:
        raw = docker('run', '--rm', '-i', '--network', 'host', '--user', '1000:1000', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000',
            '--mount', 'type=bind,src=/opt/regulai/private,dst=/run/private,readonly',
            '--mount', f'type=bind,src={stage}/runtime,dst=/run/p1,readonly', image, *args, data=body)
    return json.loads(raw)


def require_idle(**kwargs):
    result = web_exec('metadata', **kwargs)
    if (result['live'] or result['active_calls'] or result['pending_inferences']
            or result['provider_occupied'] or result['sandbox_occupied']):
        raise RuntimeError('live_or_uncertain_runs_present')
    return result


def private_configuration_digest():
    # Detect concurrent rotation/config changes without emitting names or values.
    result = hashlib.sha256()
    for relative in ('private/server.json', 'private/postgres-password',
                     'worker/config.json', 'worker/token', 'worker/e2b-key'):
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('private_configuration_must_be_regular_files')
        result.update(relative.encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def source_manifest():
    script = '''import hashlib,json
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
    return json.loads(docker('exec', '-i', 'regulai-v2-web', 'python', '-', data=script.encode()))


def snapshot_backup(stage, name):
    path = stage / (name + '.dump')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        docker('exec', 'regulai-v2-postgres', 'pg_dump', '-U', 'regulai', '-d', 'regulai',
               '--format=custom', '--no-owner', '--no-acl', output=stream)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if not path.stat().st_size:
        raise RuntimeError('empty_database_backup')
    return {'file': path.name, 'sha256': digest, 'bytes': path.stat().st_size}


def equal_fingerprints(before, after):
    if before != after:
        changed = sorted(key for key in set(before['tables']) | set(after['tables'])
                         if before['tables'].get(key) != after['tables'].get(key))
        raise RuntimeError('migration_changed_existing_data:' + ','.join(changed))


def extract_candidate(stage, raw):
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise RuntimeError('source_archive_limit')
    package = stage / 'candidate.tar'
    package.write_bytes(raw)
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        if len(members) > 5000:
            raise RuntimeError('source_archive_file_limit')
        for item in members:
            relative = PurePosixPath(item.name)
            if (relative.is_absolute() or '..' in relative.parts or not item.isfile()
                    or '\\' in item.name or ':' in item.name or str(relative) != item.name
                    or item.name in files or not item.name
                    or item.name != 'activation-manifest.json' and not (
                        item.name == '.dockerignore' or item.name.startswith(('regulai/', 'ops/agent_chat/', 'ops/agent_probe/', 'ops/setup/')))
                    or relative.name == 'local_settings.py' or relative.name.startswith('.env')
                    or relative.suffix in {'.sqlite', '.sqlite3', '.db', '.dump', '.pem', '.key'}
                    or any(part in {'.git', '.venv', '__pycache__', '.runtime', 'private', 'media', 'node_modules'} for part in relative.parts)):
                raise RuntimeError('unsafe_source_archive')
            total += item.size
            if item.size > 20 * 1024 * 1024 or total > MAX_ARCHIVE_BYTES:
                raise RuntimeError('source_archive_expansion_limit')
            files[item.name] = (archive.extractfile(item).read(), item.mode & 0o777)
    manifest = json.loads(files['activation-manifest.json'][0])
    if set(files) != set(manifest['source_sha256']) | {'activation-manifest.json'}:
        raise RuntimeError('source_manifest_coverage_mismatch')
    for relative, expected in manifest['source_sha256'].items():
        if hashlib.sha256(files[relative][0]).hexdigest() != expected:
            raise RuntimeError('candidate_source_digest_changed')
    for relative, (content, mode) in files.items():
        destination = stage / 'source' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        os.chmod(destination, mode)
    return manifest


def build_images(stage, identity):
    images = {kind: f'regulai-v2-{kind}:{identity}' for kind in ('web', 'worker', 'sandbox')}
    for kind, filename in (('web', 'web'), ('worker', 'executor'), ('sandbox', 'spreadsheet')):
        if subprocess.run(['docker', 'image', 'inspect', images[kind]], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError('candidate_image_tag_already_exists')
        with (stage / ('build-' + kind + '.log')).open('wb') as log:
            result = subprocess.run(['docker', 'build', '-t', images[kind], '-f',
                'ops/agent_chat/Dockerfile.' + filename, '.'], cwd=stage / 'source', stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError('candidate_build_failed:' + kind)
    return images


def prepare_worker_directory(stage, identity):
    original = ROOT / 'worker'
    target = stage / 'worker'
    target.mkdir(mode=0o700)
    for name in ('config.json', 'token', 'e2b-key'):
        path = original / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('worker_configuration_must_be_regular_files')
        shutil.copyfile(path, target / name)
    config = read_json(target / 'config.json')
    from urllib.parse import urlsplit
    for key in ('api_url', 'sandbox_url'):
        if urlsplit(config[key]).hostname != '172.30.58.1':
            raise RuntimeError('unexpected_self_hosted_control_endpoint')
    config['template'] = 'regulai-' + identity
    if config.get('api_key_file') != '/run/task50/e2b-key' or config.get('worker_token_file') != '/run/task50/token':
        raise RuntimeError('unexpected_worker_credential_paths')
    private_json(target / 'config.json', config)
    for path in [target, *target.rglob('*')]:
        os.chown(path, 1000, 1000)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    return config


def verify_template(stage, images, config):
    # Unique alias/image: never rebuild the old template or mutable image tag.
    with socket.socket() as port_check:
        port_check.bind(('127.0.0.1', 5000))
    docker('save', images['sandbox'], '-o', str(stage / 'sandbox.tar'))
    with (stage / 'registry.log').open('wb') as log:
        registry = subprocess.Popen(['python3', str(stage / 'source/ops/agent_chat/local_image.py'),
            str(stage / 'sandbox.tar')], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(180):
                if registry.poll() is not None:
                    raise RuntimeError('local_registry_failed')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:5000/v2/', timeout=1):
                        if (stage / 'image-manifest.sha256').exists():
                            break
                except OSError:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError('local_registry_not_ready')
            build = dict(config, api_url='http://127.0.0.1:3000', sandbox_url='http://127.0.0.1:3002',
                image='localhost:5000/task50-sheet@sha256:' + (stage / 'image-manifest.sha256').read_text().strip())
            private_json(stage / 'worker/template.json', build)
            os.chown(stage / 'worker/template.json', 1000, 1000)
            with (stage / 'template-build.log').open('wb') as output:
                docker('run', '--rm', '--network', 'host', '--mount',
                    f'type=bind,src={stage}/worker,dst=/run/task50,readonly', images['worker'],
                    'python', '/app/ops/agent_chat/build_template.py', '/run/task50/template.json', output=output)
        finally:
            registry.terminate()
            registry.wait(timeout=15)
    # Same SDK and namespace backend as ordinary professional execution. No LLM.
    code = '''import base64,hashlib,json
from pathlib import Path
from types import SimpleNamespace
from front.agents.sandbox_pool import create_clean
from front.agents.skill_backend import SkillBackend
from front.agents.workspace_backend import WorkspaceSandbox
config=json.loads(Path('/run/task50/config.json').read_text())
sandbox=create_clean(config)
try:
 backend=WorkspaceSandbox(sandbox=sandbox,lease=SimpleNamespace(check=lambda:None),limits={'command_seconds':30,'memory_mb':1024,'processes':64,'file_bytes':20000000,'output_bytes':1048576})
 result=backend.execute("node --version && test ! -e /run && test \\\"$(id -u)\\\" = 1000 && python -c \\\"import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(('1.1.1.1',443)) != 0\\\"",timeout=15)
 value=json.loads(result.output)
 if result.exit_code or value['stdout'].strip()!='v24.21.0': raise RuntimeError('target_node_or_isolation_failed')
 helper=sandbox.files.read('/skills/workspace_mutation.py',format='bytes')
 assert not backend.write('/workspace/work/cas.txt','before').error
 assert backend.replace('/workspace/work/cas.txt','0'*64,'incorrect')['code']=='hash_conflict'
 assert backend.replace('/workspace/work/cas.txt',hashlib.sha256(b'before').hexdigest(),'after')['succeeded']
 root=Path('/app/regulai/front/agents/runtime/skills/design-taste-frontend')
 files={path.relative_to(root).as_posix():path.read_bytes() for path in root.rglob('*') if path.is_file()}
 manifest=[{'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for path,raw in sorted(files.items())]
 entry={'alias':'design-taste-frontend','installation_id':'00000000-0000-4000-8000-000000000001','revision_id':'00000000-0000-4000-8000-000000000002','manifest':manifest}
 class CandidateFiles:
  def operation(self,name,payload):
   if name=='run/skills': return {'digest':'candidate-public-files','catalog':[entry]}
   assert name=='run/skill-resource'
   return {'files':[{'path':item['path'],'base64':base64.b64encode(files[item['path'].removeprefix('/skills/design-taste-frontend/')]).decode(),'sha256':hashlib.sha256(files[item['path'].removeprefix('/skills/design-taste-frontend/')]).hexdigest()} for item in payload['files']]}
 skills=SkillBackend(CandidateFiles(),{'digest':'candidate-public-files'})
 skills.materialize({'name':'execute','args':{'command':'node /skills/design-taste-frontend/scripts/draw.mjs'}},sandbox)
 sandbox.files.write('/workspace/work/probe.cjs',Path('/run/p1/p1_activation_probe.cjs').read_bytes())
 result=backend.execute('node /workspace/work/probe.cjs',timeout=30)
 value=json.loads(result.output)
 if result.exit_code: raise RuntimeError('target_taste_probe_failed')
 taste=json.loads(value['stdout'])
 if not taste['all_passed']: raise RuntimeError('target_taste_probe_failed')
 print(json.dumps({'verified':True,'capabilities':{'node':'24.21.0'},'helper_sha256':hashlib.sha256(helper).hexdigest(),'mutation_cas':True,'uid':1000,'run_hidden':True,'egress_blocked':True,'provider_requests':0,'template':config['template'],'taste':taste,'skill_transport':'immutable candidate file fixture; actual SDK materialization and E2B execution'}))
finally:
 sandbox.kill()
'''
    proof = json.loads(docker('run', '--rm', '-i', '--network', 'regulai-v2-exec', '--user', '1000:1000',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--dns', '127.0.0.1',
        '--memory', '1024m', '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000',
        '--mount', f'type=bind,src={stage}/worker,dst=/run/task50,readonly',
        '--mount', f'type=bind,src={stage}/runtime,dst=/run/p1,readonly', images['worker'],
        'python', '-', data=code.encode()))
    expected = hashlib.sha256((stage / 'source/regulai/front/agents/workspace_mutation.py').read_bytes()).hexdigest()
    if proof['helper_sha256'] != expected or proof['capabilities'] != CAPABILITY:
        raise RuntimeError('target_runtime_identity_mismatch')
    return proof


def prepare(identity, raw):
    stage = stage_path(identity)
    rows = {name: inspect(name) for name in NAMES}
    metadata = require_idle(current=True)
    stage.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = extract_candidate(stage, raw)
    live_sources = source_manifest()
    if any(value not in manifest['accepted_live_hashes'].get(path, []) for path, value in live_sources.items()):
        raise RuntimeError('deployed_source_has_unintegrated_changes')
    private_json(stage / 'original-containers.json', rows)
    private_json(stage / 'original-source-hashes.json', live_sources)
    private_json(stage / 'original-configuration.json', {'digest': private_configuration_digest()})
    runtime = stage / 'runtime'
    runtime.mkdir(mode=0o755)
    (runtime / 'p1_activation_remote.py').write_text(module_source(), encoding='utf-8')
    shutil.copyfile(stage / 'source/ops/agent_chat/p1_activation_probe.cjs', runtime / 'p1_activation_probe.cjs')
    os.chmod(runtime / 'p1_activation_probe.cjs', 0o444)
    os.chmod(runtime / 'p1_activation_remote.py', 0o444)
    private_json(runtime / 'runtime.json', {'verified': False, 'capabilities': {}})
    os.chmod(runtime / 'runtime.json', 0o444)
    backup = snapshot_backup(stage, 'before-prepare')
    images = build_images(stage, identity)
    clone = 'regulai_' + identity.replace('-', '_')
    docker('exec', 'regulai-v2-postgres', 'createdb', '-U', 'regulai', clone)
    with (stage / backup['file']).open('rb') as stream:
        result = subprocess.run(['docker', 'exec', '-i', 'regulai-v2-postgres', 'pg_restore',
            '-U', 'regulai', '--no-owner', '--no-acl', '-d', clone], stdin=stream,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('isolated_restore_failed')
    parameters = {'stage': stage, 'image': images['web'], 'database': clone}
    before = web_exec('fingerprint', payload={}, **parameters)
    migration = web_exec('migrate', **parameters)
    after = web_exec('fingerprint', payload=before, **parameters)
    equal_fingerprints(before, after)
    private_json(stage / 'clone-invariants.json', before)
    config = prepare_worker_directory(stage, identity)
    proof = verify_template(stage, images, config)
    private_json(runtime / 'runtime.json', proof)
    os.chmod(runtime / 'runtime.json', 0o444)
    # Exercise installation on the migrated copy before touching the real account.
    installation = web_exec('install', payload={'activation_id': identity}, **parameters)
    state = {'identity': identity, 'phase': 'prepared', 'source_commit': manifest['source_commit'],
        'source_manifest_sha256': hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
        'original_identity': original_identity(rows), 'images': images,
        'image_ids': {kind: json.loads(docker('image', 'inspect', tag))[0]['Id'] for kind, tag in images.items()},
        'clone_database': clone,
        'backup': backup, 'migration': migration, 'runtime': proof, 'clone_installation': installation,
        'provider_requests': 0, 'original_metadata': metadata}
    private_json(stage / 'state.json', state)
    return state


class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect('/var/run/docker.sock')


def create_replacement(name, original, image, stage, worker=False):
    # Docker API keeps any existing secret environment values out of argv/logs.
    payload = copy.deepcopy(original['Config'])
    payload.pop('Hostname', None)
    payload.pop('Domainname', None)
    payload['Image'] = image
    host = copy.deepcopy(original['HostConfig'])
    if worker:
        source = str(ROOT / 'worker')
        replacement = str(stage / 'worker')
        replaced = 0
        for mount in host.get('Mounts', []):
            if mount.get('Target') == '/run/task50':
                if mount.get('Source') != source:
                    raise RuntimeError('unexpected_worker_secret_mount')
                mount['Source'] = replacement
                replaced += 1
        replaced += sum(value.startswith(source + ':/run/task50:') for value in host.get('Binds') or [])
        host['Binds'] = [value.replace(source + ':', replacement + ':', 1)
                         if value.startswith(source + ':') else value for value in host.get('Binds') or []]
        if replaced != 1:
            raise RuntimeError('exactly_one_worker_secret_mount_required')
    else:
        payload['Cmd'] = ['python', '/run/p1/p1_activation_remote.py', '--inside-web', 'serve']
        host.setdefault('Mounts', []).append({'Type': 'bind', 'Source': str(stage / 'runtime'),
            'Target': '/run/p1', 'ReadOnly': True})
    payload['HostConfig'] = host
    payload['Labels'] = {**(payload.get('Labels') or {}), 'regulai.activation': stage.name}
    connection = DockerConnection('localhost')
    try:
        connection.request('POST', '/v1.47/containers/create?name=' + urllib.parse.quote(name),
            body=json.dumps(payload), headers={'Content-Type': 'application/json'})
        result = connection.getresponse()
        result.read()
        if result.status != 201:
            raise RuntimeError('replacement_container_create_failed:' + name)
    finally:
        connection.close()


def verify_started_services(stage):
    # A successful `docker start` does not prove that the worker stayed alive.
    for sample in range(6):
        rows = {name: inspect(name) for name in NAMES[:2]}
        if any(not row['State']['Running'] or row['State']['ExitCode'] != 0
               or row.get('RestartCount', 0) for row in rows.values()):
            for name in NAMES[:2]:
                with (stage / (name + '-startup.log')).open('wb') as output:
                    os.chmod(output.name, 0o600)
                    result = subprocess.run(['docker', 'logs', '--tail', '100', name],
                        stdout=output, stderr=subprocess.STDOUT)
            raise RuntimeError('candidate_service_exited_or_restarted')
        # Authentication GETs share the existing 5/minute login limit. Probe a
        # versioned application asset; the separate metadata gate checks Django
        # and PostgreSQL without consuming login attempts or writing audit rows.
        with urllib.request.urlopen('http://127.0.0.1:31058/static/js/skills.js', timeout=2) as response:
            if response.status != 200:
                raise RuntimeError('candidate_web_health_failed')
        if sample < 5:
            time.sleep(2)
    return {'stable_seconds': 10, 'worker_running': True, 'web_running': True,
            'web_http_status': 200, 'provider_requests': 0}


def apply(identity):
    stage = stage_path(identity)
    state = read_json(stage / 'state.json')
    if state['phase'] != 'prepared' or not state['runtime']['verified']:
        raise RuntimeError('prepared_candidate_required')
    rows = {name: inspect(name) for name in NAMES}
    if original_identity(rows) != state['original_identity']:
        raise RuntimeError('live_container_changed_since_prepare')
    if {kind: json.loads(docker('image', 'inspect', tag))[0]['Id']
            for kind, tag in state['images'].items()} != state['image_ids']:
        raise RuntimeError('prepared_image_tag_changed')
    if source_manifest() != read_json(stage / 'original-source-hashes.json'):
        raise RuntimeError('live_source_changed_since_prepare')
    if private_configuration_digest() != read_json(stage / 'original-configuration.json')['digest']:
        raise RuntimeError('private_configuration_changed_since_prepare')
    require_idle(current=True)
    state['phase'] = 'stopping'
    private_json(stage / 'state.json', state)
    docker('stop', 'regulai-v2-worker', 'regulai-v2-web')
    state['phase'] = 'stopped'
    private_json(stage / 'state.json', state)
    old = {'stage': stage, 'image': rows['regulai-v2-web']['Image'], 'database': 'regulai'}
    # Closing the web admission boundary precedes the second queue check.
    require_idle(**old)
    state['apply_backup'] = snapshot_backup(stage, 'before-apply')
    before = web_exec('fingerprint', payload={}, **old)
    private_json(stage / 'real-before-invariants.json', before)
    new = {'stage': stage, 'image': state['images']['web'], 'database': 'regulai'}
    state['real_migration'] = web_exec('migrate', **new)
    after = web_exec('fingerprint', payload=before, **new)
    equal_fingerprints(before, after)
    state['phase'] = 'migrated'
    private_json(stage / 'state.json', state)
    for name in NAMES[:2]:
        docker('rename', name, name + '-before-' + identity)
    create_replacement(NAMES[0], rows[NAMES[0]], state['images']['web'], stage)
    create_replacement(NAMES[1], rows[NAMES[1]], state['images']['worker'], stage, worker=True)
    # Install through the server's account/grant/license/revision authority.
    state['installation'] = web_exec('install', payload={'activation_id': identity}, **new)
    require_idle(**new)
    docker('start', NAMES[0])
    for _ in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:31058/static/js/skills.js', timeout=2) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(1)
    else:
        raise RuntimeError('candidate_web_unavailable_worker_remains_stopped')
    require_idle(**new)
    docker('start', NAMES[1])
    state['startup_verification'] = verify_started_services(stage)
    state['applier_sha256'] = hashlib.sha256(module_source().encode()).hexdigest()
    state['phase'] = 'applied'
    state['final_metadata'] = web_exec('metadata', **new)
    private_json(stage / 'state.json', state)
    return state


def rollback(identity):
    stage = stage_path(identity)
    state = read_json(stage / 'state.json')
    if state['phase'] not in ('stopping', 'stopped', 'migrated', 'applied'):
        raise RuntimeError('activation_has_not_changed_live_services')
    rows = read_json(stage / 'original-containers.json')
    parameters = {'stage': stage, 'image': state['images']['web'], 'database': 'regulai'}
    require_idle(**parameters)
    for name in NAMES[:2]:
        original_name = name + '-before-' + identity
        found = subprocess.run(['docker', 'inspect', original_name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL).returncode == 0
        if found:
            if inspect(original_name)['Id'] != rows[name]['Id']:
                raise RuntimeError('rollback_original_identity_changed')
            current_exists = subprocess.run(['docker', 'inspect', name], stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL).returncode == 0
            if current_exists:
                current = inspect(name)
                if (current['Config'].get('Labels') or {}).get('regulai.activation') != identity:
                    raise RuntimeError('rollback_replacement_ownership_mismatch')
                docker('stop', name)
                docker('rename', name, name + '-failed-' + identity)
            docker('rename', original_name, name)
        elif inspect(name)['Id'] != rows[name]['Id']:
            raise RuntimeError('rollback_original_container_missing')
    require_idle(stage=stage, image=rows[NAMES[0]]['Image'], database='regulai')
    for name in NAMES[:2]:
        if rows[name]['State']['Running']:
            docker('start', name)
    state['phase'] = 'rolled_back_schema_retained'
    private_json(stage / 'state.json', state)
    return state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', nargs='?', choices=('inspect', 'prepare', 'apply', 'rollback'))
    parser.add_argument('--identity')
    parser.add_argument('--database')
    parser.add_argument('--inside-web', choices=('serve', 'metadata', 'fingerprint', 'migrate', 'install'))
    args = parser.parse_args()
    if args.inside_web:
        value = inside_web(args.inside_web, args.database)
        if value is not None:
            print(json.dumps(value))
        return
    if os.geteuid() != 0:
        raise RuntimeError('dedicated_vm_root_required')
    if args.action == 'inspect':
        rows = {name: inspect(name) for name in NAMES}
        value = {'containers': {name: safe_container(row) for name, row in rows.items()},
            'metadata': web_exec('metadata', current=True), 'source_hashes': source_manifest()}
    elif args.action == 'prepare':
        value = prepare(checked_id(args.identity), sys.stdin.buffer.read(MAX_ARCHIVE_BYTES + 1))
    elif args.action == 'apply':
        value = apply(checked_id(args.identity))
    elif args.action == 'rollback':
        value = rollback(checked_id(args.identity))
    else:
        raise RuntimeError('action_required')
    print(json.dumps(value, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
