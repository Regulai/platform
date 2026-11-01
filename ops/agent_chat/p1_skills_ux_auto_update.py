"""Second UX delta: COPY-only image, precreated candidate, coordinated idle switch.

Reuse audited functions as libraries, never their old main/apply entrypoints or
old operation identities. No worker build, migrations, skill edits or provider.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time

IDENTITY = 'p1-20261017-skills-auto-a1'
BASE_WEB = 'a7a0f96e517ed1d21f3a9557b3514aa50375d684d1d6f7350950998860317833'
BASE_IMAGE = 'sha256:90dbc4a31a505ac9e0db16fc45dc10254502f4b7f5085eed4c750d8e12b73376'
WORKER_ID = '4db24e54101297114ab2a036fd16c20a0683b749f66b6aa7b3bb00ff5886fb36'
PG_ID = '35e8237a55f11d8690114b0a96da8405fd9b5a05dda116003ad230f015785b34'
TUNNEL_PID = 48888
WEB, WORKER, PG = 'regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres'
STAGE = Path('/opt/regulai/updates') / IDENTITY
FILES = frozenset(('regulai/front/agents/skills.py', 'regulai/front/agents/skill_context.py',
    'regulai/static/js/skills.js', 'regulai/static/js/agent-chat.js',
    'regulai/static/css/chat.css', 'regulai/front/templates/chat/chat.html',
    'regulai/front/templates/skills/library.html'))
HELPERS = ('p1_activation_remote.py', 'p1_skills_ux_update_remote.py', 'p1_skills_ux_finish_update.py')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity(row):
    return digest(json.dumps({'Id': row['Id'], 'Image': row['Image'], 'Config': row['Config'],
        'HostConfig': co['canonical_host'](row['HostConfig']),
        'Mounts': ux['canonical_mounts'](row['Mounts'])}, sort_keys=True).encode())


def candidate_check(previous, original):
    row = helper['inspect'](previous['candidate_id'])
    if (row['Id'] != previous['candidate_id'] or row['Image'] != previous['image_id'] or row['State']['Running']
            or row['State']['Status'] != 'created' or row['Name'] != '/' + WEB + '-candidate-' + IDENTITY):
        raise RuntimeError('exact_precreated_candidate_required')
    expected = copy.deepcopy(original['Config'])
    expected['Image'] = previous['image_id']
    expected['Labels'] = {**expected['Labels'], 'regulai.skills_ux': IDENTITY}
    actual = copy.deepcopy(row['Config'])
    for value in (expected, actual):
        value.pop('Hostname', None); value.pop('Domainname', None)
    if (actual != expected or co['canonical_host'](row['HostConfig']) != co['canonical_host'](original['HostConfig'])
            or ux['canonical_mounts'](row['Mounts']) != ux['canonical_mounts'](original['Mounts'])):
        raise RuntimeError('precreated_candidate_config_or_mounts_changed')
    return row


def original_rows():
    rows = {name: co['named'](name, expected) for name, expected in
        ((WEB, BASE_WEB), (WORKER, WORKER_ID), (PG, PG_ID))}
    if rows[WEB]['Image'] != BASE_IMAGE or any(not row['State']['Running'] for row in rows.values()):
        raise RuntimeError('expected_ux1_services_required')
    return rows


def recon():
    rows = original_rows()
    source = helper['source_manifest']()
    if source != ux['candidate_source'](BASE_IMAGE):
        raise RuntimeError('live_source_differs_from_immutable_ux1_image')
    return {'containers': {name: helper['safe_container'](row) for name, row in rows.items()},
        'source_hashes': source, 'metadata': helper['require_idle'](current=True),
        'configuration_digest': ux['config_digest'](rows), 'provider_requests': 0}


def prepare():
    payload = REQUEST['payload']
    if set(payload['files']) != FILES:
        raise RuntimeError('exact_seven_auto_ux_files_required')
    rows = original_rows()
    if (ux['config_digest'](rows) != payload['baseline']['configuration_digest']
            or helper['require_idle'](current=True) != payload['baseline']['metadata']):
        raise RuntimeError('recon_private_config_or_metadata_changed')
    co['guest_ingress_clear']()
    previous = ux['prepare'](payload)
    originals = helper['read_json'](STAGE / 'original-containers.json')
    config = copy.deepcopy(originals[WEB]['Config'])
    config.pop('Hostname', None); config.pop('Domainname', None)
    config.update(Image=previous['image_id'], HostConfig=copy.deepcopy(originals[WEB]['HostConfig']))
    config['Labels'] = {**config['Labels'], 'regulai.skills_ux': IDENTITY}
    connection = helper['DockerConnection']('localhost')
    try:
        connection.request('POST', '/v1.47/containers/create?name=' + WEB + '-candidate-' + IDENTITY,
            body=json.dumps(config), headers={'Content-Type': 'application/json'})
        response = connection.getresponse(); body = response.read()
        if response.status != 201: raise RuntimeError('auto_candidate_create_failed')
        previous['candidate_id'] = json.loads(body)['Id']
        helper['private_json'](STAGE / 'state.json', previous)
    finally:
        connection.close()
    candidate = candidate_check(previous, originals[WEB])
    co.update(CANDIDATE=previous['candidate_id'], IMAGE=previous['image_id'])
    rows = original_rows()
    if any(identity(row) != identity(originals[name]) or row['State']['StartedAt'] != originals[name]['State']['StartedAt']
            for name, row in rows.items()): raise RuntimeError('services_changed_during_prepare')
    if (helper['source_manifest']() != payload['baseline']['source_hashes']
            or helper['require_idle'](current=True) != previous['metadata']):
        raise RuntimeError('source_or_idle_changed_during_prepare')
    state = {'phase': 'prepared', 'source_commit': previous['source_commit'],
        'candidate_id': previous['candidate_id'], 'image_id': previous['image_id'],
        'identities': {name: identity(row) for name, row in rows.items()},
        'container_ids': {name: row['Id'] for name, row in rows.items()},
        'started_at': {name: row['State']['StartedAt'] for name, row in rows.items()},
        'restart_counts': {name: row['RestartCount'] for name, row in rows.items()},
        'candidate_identity': identity(candidate), 'configuration_digest': ux['config_digest'](rows),
        'metadata': previous['metadata'], 'updater_sha256': REQUEST['sha256'],
        'source_helpers_sha256': REQUEST['helper_hash'], 'provider_requests': 0,
        'migrations_executed': 0, 'dependencies_built': False, 'prepare_data_unchanged': True,
        'candidate_prevalidated_before_maintenance': True, 'hashes': previous['hashes']}
    helper['private_json'](STAGE / co['STATE'], state)
    return state


def guest():
    import fcntl
    if os.geteuid() != 0: raise RuntimeError('guest_root_required')
    global helper, ux, co
    helper, ux, co = ({'__name__': 'auto_library_' + str(i)} for i in range(3))
    helper['_ACTIVATION_SOURCE'] = REQUEST['sources'][0]
    for namespace, source in zip((helper, ux, co), REQUEST['sources']):
        exec(compile(source, 'frozen_library.py', 'exec'), namespace)
    for key in ('inspect', 'safe_container', 'original_identity', 'private_json', 'read_json',
            'source_manifest', 'web_exec', 'require_idle', 'equal_fingerprints', 'docker', 'command', 'DockerConnection'):
        ux[key] = helper[key]
    ux.update(IDENTITY=IDENTITY, STAGE=STAGE, ALLOWED_PYTHON=FILES & {'regulai/front/agents/skills.py',
        'regulai/front/agents/skill_context.py'}, REQUEST={'source_sha256': REQUEST['sha256'], 'helper': REQUEST['sources'][0]})
    co.update(STAGE=STAGE, TUNNEL_PID=TUNNEL_PID, helper=helper, ux=ux,
        inspect=helper['inspect'], docker=helper['docker'], read=helper['read_json'],
        write=helper['private_json'], REQUEST=REQUEST, identity=identity, candidate_check=candidate_check)
    with (STAGE.parent / (IDENTITY + '.lock')).open('w') as lock:
        os.chmod(lock.name, 0o600); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = REQUEST['action']
        try:
            if action == 'recon': value = recon()
            elif action == 'prepare': value = prepare()
            else:
                state = helper['read_json'](STAGE / co['STATE'])
                co.update(CANDIDATE=state['candidate_id'], IMAGE=state['image_id'])
                if action == 'apply': value = co['apply']()
                elif action == 'verify-terminal': value = co['terminal_check']()
                else: raise RuntimeError('unknown_auto_action')
            print(json.dumps(value))
        except Exception as error:
            target = STAGE / 'failure.json' if STAGE.exists() else STAGE.parent / (IDENTITY + '-failure.json')
            helper['private_json'](target, {'action': action, 'error_type': type(error).__name__,
                'guard': str(error) if isinstance(error, RuntimeError) else 'private_error_suppressed'})
            raise


def snapshot():
    code = "$connections=@(Get-NetTCPConnection -LocalPort 8800 -ErrorAction SilentlyContinue | ForEach-Object { @{address=$_.LocalAddress;port=$_.LocalPort;state=[string]$_.State;pid=$_.OwningProcess} }); $listener=@($connections | Where-Object { $_.state -eq 'Listen' }); $process=$null; if ($listener.Count -eq 1) { $process=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$listener[0].pid) }; @{connections=$connections;pid=$process.ProcessId;command=$process.CommandLine} | ConvertTo-Json -Compress -Depth 5"
    return json.loads(subprocess.check_output(['rtk', 'proxy', 'powershell', '-NoProfile', '-Command', code]))


def local():
    import signal
    import p1_activate_local as activation
    import p1_skills_ux_finish_update as guards
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('recon', 'prepare', 'apply'))
    parser.add_argument('--source-ref'); args = parser.parse_args()
    activation.owner_check(); root = activation.ROOT
    out = root / 'output/p1-skills-ux-20261016/auto'; out.mkdir(exist_ok=True)
    source = Path(__file__).read_text(encoding='utf-8')
    sources = [(root / 'ops/agent_chat' / path).read_text(encoding='utf-8') for path in HELPERS]
    request = {'action': args.action, 'sha256': digest(source.encode()), 'sources': sources,
        'helper_hash': digest(''.join(sources).encode()), 'ingress': snapshot()}
    guards.validate_ingress(request['ingress'], expected_pid=TUNNEL_PID)
    outer = json.loads(subprocess.check_output(['rtk', 'proxy', 'docker', 'inspect', activation.VM]))[0]
    if outer['HostConfig']['PortBindings'] or outer['NetworkSettings']['Ports']:
        raise RuntimeError('unexpected_published_ingress')
    if args.action == 'prepare':
        if not args.source_ref: parser.error('--source-ref is required for prepare')
        commit = activation.git('rev-parse', '--verify', args.source_ref + '^{commit}').decode().strip()
        files = {path: activation.git('show', commit + ':' + path) for path in sorted(FILES)}
        for path, data in files.items():
            if data != (root/path).read_bytes().replace(b'\r\n', b'\n'):
                raise RuntimeError('working_source_changed_since_commit:' + path)
        request['payload'] = {'commit': commit, 'files': {path: base64.b64encode(data).decode() for path,data in files.items()},
            'hashes': {path:digest(data) for path,data in files.items()},
            'baseline': json.loads((out/'recon.json').read_text(encoding='utf-8'))}
    loader = "import sys,json; h=json.loads(sys.stdin.buffer.readline()); exec(compile(sys.stdin.buffer.read().decode(),'auto_update.py','exec'),{'__name__':'__main__','REQUEST':h})"
    def remote(value, timeout=240):
        return subprocess.run([*activation.SSH, 'sudo python3 -c ' + shlex.quote(loader)],
            input=json.dumps(value).encode()+b'\n'+source.encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout)
    closed, result = False, None
    try:
        if args.action == 'apply':
            guards.validate_ingress(snapshot(), expected_pid=TUNNEL_PID)
            os.kill(TUNNEL_PID, signal.SIGTERM); closed = True
            for _ in range(20):
                if not snapshot()['connections']: break
                time.sleep(.1)
            else: raise RuntimeError('host_ingress_not_closed')
            request['ingress_closed'] = True
        result = remote(request)
        if not result.returncode:
            value = json.loads(result.stdout)
            (out/(args.action+'.json')).write_text(json.dumps(value,indent=2),encoding='utf-8')
    finally:
        if closed:
            if result is None:
                (out/'tunnel-pending.json').write_text(json.dumps({'closed':True,'reason':'guest_completion_unknown'}),encoding='utf-8')
                raise RuntimeError('guest_completion_unknown_tunnel_left_closed')
            terminal = remote({**request,'action':'verify-terminal'},timeout=40)
            if terminal.returncode:
                (out/'tunnel-pending.json').write_text(json.dumps({'closed':True,'reason':'terminal_services_unverified'}),encoding='utf-8')
                raise RuntimeError('terminal_services_unverified_tunnel_left_closed')
            verified = json.loads(terminal.stdout)
            if not verified.get('safe_to_reopen_owned_tunnel'): raise RuntimeError('terminal_receipt_denies_reopen')
            (out/'terminal.json').write_text(json.dumps(verified,indent=2),encoding='utf-8')
            if snapshot()['connections']: raise RuntimeError('foreign_listener_prevents_reopen')
            # File sinks plus Popen avoid waiting on inherited handles of the
            # hidden long-running tunnel. Its actual listener is verified below.
            reopen = "Start-Process -FilePath 'rtk' -ArgumentList @('proxy','C:/Users/javi/AppData/Local/Programs/Python/Python314/python.exe','ops/agent_chat/p1_activate_local.py','tunnel','--port','8800') -WorkingDirectory 'C:/Users/javi/Documents/Codex/regulai-platform' -WindowStyle Hidden -RedirectStandardOutput '" + (out/'tunnel.log').as_posix() + "' -RedirectStandardError '" + (out/'tunnel-error.log').as_posix() + "' | Out-Null"
            with (out/'launcher.log').open('wb') as stream:
                launcher = subprocess.Popen(['rtk','proxy','powershell','-NoProfile','-Command',reopen],
                    stdout=stream,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(40):
                current = snapshot()
                if current['connections']:
                    guards.validate_ingress(current,expected_pid=None,idle=False); break
                time.sleep(.2)
            else: raise RuntimeError('owned_tunnel_reopen_failed')
            import urllib.request
            with urllib.request.urlopen('http://127.0.0.1:8800/static/js/skills.js',timeout=5) as response:
                if response.status != 200: raise RuntimeError('reopened_tunnel_health_failed')
            (out/'tunnel-restored.json').write_text(json.dumps({'pid':current['pid'], 'port':8800,
                'loopback':True,'same_command':True,'hidden':True,'http_status':200,
                'launcher_pid':launcher.pid},indent=2),encoding='utf-8')
    if result.returncode: raise RuntimeError('auto_'+args.action+'_failed:exit='+str(result.returncode))
    public = value if args.action != 'recon' else {key:value[key] for key in ('containers','metadata','configuration_digest','provider_requests')}
    print(json.dumps(public,indent=2))


if __name__ == '__main__':
    guest() if 'REQUEST' in globals() else local()
