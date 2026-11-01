"""Finish the already built UX candidate with coordinated idle-worker maintenance.

Preflight is read-only apart from its own receipt. Apply is a distinct action.
Original failed-attempt receipts, images, schema and skill bytes are retained.
"""
import copy
import hashlib
import json
from pathlib import Path
import time

WEB, WORKER, PG = 'regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres'
STAGE = Path('/opt/regulai/updates/p1-20261016-skills-ux-a1')
CANDIDATE = 'a7a0f96e517ed1d21f3a9557b3514aa50375d684d1d6f7350950998860317833'
IMAGE = 'sha256:90dbc4a31a505ac9e0db16fc45dc10254502f4b7f5085eed4c750d8e12b73376'
STATE = 'coordinated-state.json'
TUNNEL_PID = 29644
TUNNEL_COMMAND = '"C:\\Users\\javi\\AppData\\Local\\Programs\\Python\\Python314\\python.exe" ops/agent_chat/p1_activate_local.py tunnel --port 8800'


def canonical_host(host):
    result = copy.deepcopy(host)
    if 'OomKillDisable' not in result:
        raise RuntimeError('missing_oom_kill_disable_setting')
    value = result.get('OomKillDisable')
    if value is not None and type(value) is not bool:
        raise RuntimeError('invalid_oom_kill_disable_type')
    result['OomKillDisable'] = False if value is None else value
    return result


def validate_ingress(snapshot, expected_pid=TUNNEL_PID, idle=True):
    import shlex
    def tokens(command):
        values = shlex.split(command or '', posix=False)
        if values:
            values[0] = values[0].strip('"').replace('\\', '/').casefold()
        return values
    listeners = [row for row in snapshot['connections'] if row['state'] == 'Listen']
    if (tokens(snapshot['command']) != tokens(TUNNEL_COMMAND) or expected_pid is not None and snapshot['pid'] != expected_pid
            or idle and len(snapshot['connections']) != 1 or len(listeners) != 1 or listeners[0] != {
                'address': '127.0.0.1', 'port': 8800, 'state': 'Listen', 'pid': snapshot['pid']}):
        raise RuntimeError('owned_idle_tunnel_required')


def guest_ingress_clear():
    worker = inspect(WORKER)
    peers = {net['IPAddress'] for net in worker['NetworkSettings']['Networks'].values()}
    lines = helper['command'](['ss', '-Htn', 'state', 'established', '( sport = :31058 )']).decode().splitlines()
    for line in lines:
        peer = line.split()[-1].rsplit(':', 1)[0]
        if peer not in peers:
            raise RuntimeError('user_connection_still_present_on_guest_web')


def identity(row):
    return hashlib.sha256(json.dumps({'Id': row['Id'], 'Image': row['Image'],
        'Config': row['Config'], 'HostConfig': canonical_host(row['HostConfig'])}, sort_keys=True).encode()).hexdigest()


def named(name, expected_id):
    row = inspect(name)
    if row['Id'] != expected_id:
        raise RuntimeError('container_name_identity_changed:' + name)
    return row


def clean_stop(name, expected_id):
    row = named(name, expected_id)
    if row['HostConfig']['RestartPolicy']['Name'] != 'no':
        raise RuntimeError('unexpected_restart_policy')
    docker('kill', '--signal=TERM', expected_id)
    for _ in range(60):
        row = inspect(expected_id)
        if not row['State']['Running']:
            if row['State']['ExitCode'] != 0:
                raise RuntimeError('service_did_not_stop_cleanly:' + name)
            return
        time.sleep(0.5)
    raise RuntimeError('graceful_stop_pending_no_kill:' + name)


def candidate_check(previous, original):
    row = inspect(CANDIDATE)
    if (row['Image'] != IMAGE or row['State']['Running'] or row['State']['Status'] != 'created'
            or row['Name'] != '/' + WEB + '-failed-' + previous['identity']
            or row['Config']['Labels'].get('regulai.skills_ux') != previous['identity']):
        raise RuntimeError('exact_unstarted_candidate_required')
    expected = copy.deepcopy(original['Config'])
    expected['Image'] = IMAGE
    expected['Labels'] = {**expected['Labels'], 'regulai.skills_ux': previous['identity']}
    actual = copy.deepcopy(row['Config'])
    for data in (expected, actual):
        data.pop('Hostname', None); data.pop('Domainname', None)
    if (actual != expected or canonical_host(row['HostConfig']) != canonical_host(original['HostConfig'])
            or ux['canonical_mounts'](row['Mounts']) != ux['canonical_mounts'](original['Mounts'])):
        raise RuntimeError('candidate_configuration_changed')
    return row


def preflight():
    validate_ingress(REQUEST['ingress'])
    guest_ingress_clear()
    previous = read(STAGE / 'state.json')
    if previous['phase'] != 'retained_original' or previous['candidate_id'] != CANDIDATE or previous['image_id'] != IMAGE:
        raise RuntimeError('exact_failed_attempt_required')
    original = read(STAGE / 'original-containers.json')
    rows = {name: named(name, original[name]['Id']) for name in (WEB, WORKER, PG)}
    if any(not row['State']['Running'] or identity(row) != identity(original[name]) for name, row in rows.items()):
        raise RuntimeError('restored_original_configuration_required')
    recovered = REQUEST['recovery']
    if rows[WORKER]['State']['StartedAt'] != recovered['new_started_at'] or recovered['worker_id'] != rows[WORKER]['Id']:
        raise RuntimeError('exact_recovered_worker_required')
    metadata = helper['require_idle'](current=True)
    if metadata != previous['metadata'] or helper['source_manifest']() != read(STAGE / 'before-source.json'):
        raise RuntimeError('restored_original_metadata_or_source_changed')
    candidate = candidate_check(previous, rows[WEB])
    if ux['candidate_source'](IMAGE) != read(STAGE / 'before-source.json') | previous['hashes']:
        raise RuntimeError('candidate_source_changed')
    fingerprint = helper['web_exec']('fingerprint', current=True, payload=read(STAGE / 'before-apply-data.json'))
    helper['equal_fingerprints'](read(STAGE / 'before-apply-data.json'), fingerprint)
    if (STAGE / STATE).exists():
        prior = read(STAGE / STATE)
        if (prior['phase'] != 'prepared' or prior['candidate_id'] != CANDIDATE
                or prior['identities'] != {name: identity(row) for name, row in rows.items()}):
            raise RuntimeError('coordinated_receipt_already_executed_or_changed')
        archive = STAGE / ('coordinated-preflight-' + prior['updater_sha256'][:12] + '.json')
        if archive.exists(): raise RuntimeError('preflight_archive_already_exists')
        (STAGE / STATE).rename(archive)
    state = {'phase': 'prepared', 'source_commit': previous['source_commit'], 'candidate_id': CANDIDATE,
        'image_id': IMAGE, 'identities': {name: identity(row) for name, row in rows.items()},
        'container_ids': {name: row['Id'] for name, row in rows.items()},
        'started_at': {name: row['State']['StartedAt'] for name, row in rows.items()},
        'restart_counts': {name: row['RestartCount'] for name, row in rows.items()},
        'candidate_identity': identity(candidate), 'configuration_digest': ux['config_digest'](rows),
        'metadata': metadata, 'updater_sha256': REQUEST['sha256'], 'source_helpers_sha256': REQUEST['helper_hash'],
        'provider_requests': 0, 'migrations_executed': 0, 'dependencies_built': False,
        'preflight_data_unchanged': True, 'candidate_prevalidated_before_maintenance': True}
    write(STAGE / STATE, state)
    return state


def gate(state):
    if not REQUEST.get('ingress_closed'):
        raise RuntimeError('owned_ingress_must_be_closed')
    guest_ingress_clear()
    rows = {name: named(name, state['container_ids'][name]) for name in (WEB, WORKER, PG)}
    for name, row in rows.items():
        if (identity(row) != state['identities'][name] or not row['State']['Running']
                or row['State']['StartedAt'] != state['started_at'][name] or row['RestartCount'] != state['restart_counts'][name]):
            raise RuntimeError('service_changed_since_preflight:' + name)
    if ux['config_digest'](rows) != state['configuration_digest']:
        raise RuntimeError('private_configuration_changed')
    if identity(candidate_check(read(STAGE / 'state.json'), rows[WEB])) != state['candidate_identity']:
        raise RuntimeError('candidate_changed_since_preflight')
    if helper['source_manifest']() != read(STAGE / 'before-source.json') or helper['require_idle'](current=True) != state['metadata']:
        raise RuntimeError('source_or_idle_gate_changed')


def finish_services(state, expected_web, expected_source):
    ux['health'](expected_web)
    if helper['source_manifest']() != expected_source:
        raise RuntimeError('served_source_changed')
    worker = named(WORKER, state['container_ids'][WORKER])
    if not worker['State']['Running']:
        if worker['State']['ExitCode'] != 0:
            raise RuntimeError('worker_stop_not_clean')
        helper['require_idle'](current=True)
        docker('start', worker['Id'])
    started = inspect(worker['Id'])['State']['StartedAt']
    for sample in range(6):
        worker = named(WORKER, worker['Id']); pg = named(PG, state['container_ids'][PG])
        if (not worker['State']['Running'] or worker['State']['StartedAt'] != started
                or identity(worker) != state['identities'][WORKER] or worker['RestartCount'] != state['restart_counts'][WORKER]
                or identity(pg) != state['identities'][PG] or not pg['State']['Running']
                or pg['State']['StartedAt'] != state['started_at'][PG] or pg['RestartCount'] != state['restart_counts'][PG]):
            raise RuntimeError('restored_services_not_stable')
        if sample < 5: time.sleep(2)
    state['worker_new_started_at'] = started


def restore_original_web(state):
    import subprocess
    exists = subprocess.run(['docker', 'inspect', WEB], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode == 0
    if exists:
        web = inspect(WEB)
        if web['Id'] == CANDIDATE:
            if web['State']['Running']: clean_stop(WEB, CANDIDATE)
            docker('rename', CANDIDATE, WEB + '-failed-coordinated-' + ux['IDENTITY'])
        elif web['Id'] != state['container_ids'][WEB]:
            raise RuntimeError('concurrent_web_prevents_recovery')
        else:
            if not web['State']['Running']: docker('start', web['Id'])
            return
    retained = named(WEB + '-before-' + ux['IDENTITY'], state['container_ids'][WEB])
    if identity(retained) != state['identities'][WEB]:
        raise RuntimeError('retained_original_configuration_changed')
    docker('rename', retained['Id'], WEB)
    named(WEB, retained['Id']); docker('start', retained['Id'])


def terminal_check():
    # Called under the same nonblocking flock: an ongoing guest operation cannot
    # be mistaken for a completed failure after the local SSH caller times out.
    import urllib.request
    state = read(STAGE / STATE)
    if state['phase'] not in ('prepared', 'applied', 'rolled_back'):
        raise RuntimeError('maintenance_result_not_terminal')
    web_id = CANDIDATE if state['phase'] == 'applied' else state['container_ids'][WEB]
    expected = state['candidate_identity'] if state['phase'] == 'applied' else state['identities'][WEB]
    web = named(WEB, web_id); worker = named(WORKER, state['container_ids'][WORKER]); pg = named(PG, state['container_ids'][PG])
    if (identity(web) != expected or identity(worker) != state['identities'][WORKER]
            or identity(pg) != state['identities'][PG] or pg['State']['StartedAt'] != state['started_at'][PG]
            or any(not row['State']['Running'] or row['State']['ExitCode'] != 0 for row in (web, worker, pg))):
        raise RuntimeError('terminal_service_identity_or_health_failed')
    if ux['config_digest']({WEB: web, WORKER: worker, PG: pg}) != state['configuration_digest']:
        raise RuntimeError('terminal_private_configuration_changed')
    with urllib.request.urlopen('http://127.0.0.1:31058/static/js/skills.js', timeout=3) as response:
        if response.status != 200: raise RuntimeError('terminal_web_unavailable')
    if helper['require_idle'](current=True) != state['metadata']:
        raise RuntimeError('terminal_metadata_changed')
    return {'phase': state['phase'], 'guest_lock_free': True, 'services_healthy': True,
        'identities_verified': True, 'safe_to_reopen_owned_tunnel': True}


def apply():
    state = read(STAGE / STATE)
    if state['phase'] != 'prepared' or state['updater_sha256'] != REQUEST['sha256'] or state['source_helpers_sha256'] != REQUEST['helper_hash']:
        raise RuntimeError('same_preflight_code_required')
    gate(state)
    expected_source = read(STAGE / 'before-source.json')
    before = helper['web_exec']('fingerprint', current=True, payload={})
    write(STAGE / 'coordinated-before-data.json', before)
    state['phase'] = 'stopping_idle_worker'; write(STAGE / STATE, state)
    try:
        guest_ingress_clear()
        clean_stop(WORKER, state['container_ids'][WORKER])
        helper['require_idle'](current=True)
        clean_stop(WEB, state['container_ids'][WEB])
        helper['require_idle'](stage=ux['RUNTIME'], image=IMAGE, database='regulai')
        named(WEB, state['container_ids'][WEB])
        docker('rename', state['container_ids'][WEB], WEB + '-before-' + ux['IDENTITY'])
        docker('rename', CANDIDATE, WEB)
        named(WEB, CANDIDATE); docker('start', CANDIDATE)
        state['phase'] = 'candidate_web_started'; write(STAGE / STATE, state)
        finish_services(state, CANDIDATE, expected_source | read(STAGE / 'state.json')['hashes'])
        if identity(inspect(CANDIDATE)) != state['candidate_identity']:
            raise RuntimeError('started_candidate_configuration_changed')
        helper['equal_fingerprints'](before, helper['web_exec']('fingerprint', current=True, payload=before))
        if helper['require_idle'](current=True) != state['metadata']:
            raise RuntimeError('final_metadata_changed')
        state.update(phase='applied', data_and_money_unchanged=True, worker_same_container_image_configuration=True,
            postgres_lifetime_unchanged=True, worker_clean_maintenance_restart=True,
            candidate_poststart_identity=identity(inspect(CANDIDATE)), ingress_closed_during_maintenance=True)
        write(STAGE / STATE, state)
        return state
    except Exception as error:
        state['failed_phase'] = state['phase']; state['failure_type'] = type(error).__name__
        state['failure_guard'] = str(error) if isinstance(error, RuntimeError) else 'private_error_suppressed'
        write(STAGE / STATE, state)
        worker = named(WORKER, state['container_ids'][WORKER])
        if worker['State']['Running']:
            helper['require_idle'](stage=ux['RUNTIME'], image=IMAGE, database='regulai')
            clean_stop(WORKER, worker['Id'])
        restore_original_web(state)
        finish_services(state, state['container_ids'][WEB], expected_source)
        helper['equal_fingerprints'](before, helper['web_exec']('fingerprint', current=True, payload=before))
        state['phase'] = 'rolled_back'; write(STAGE / STATE, state)
        raise


def guest():
    import os, fcntl
    if os.geteuid() != 0: raise RuntimeError('guest_root_required')
    global helper, ux, inspect, docker, read, write
    helper = {'__name__': 'ux_helpers', '_ACTIVATION_SOURCE': REQUEST['helper']}
    exec(compile(REQUEST['helper'], 'helper.py', 'exec'), helper)
    ux = {'__name__': 'ux_first_attempt'}
    exec(compile(REQUEST['ux'], 'ux.py', 'exec'), ux)
    for key in ('inspect', 'docker', 'read_json', 'private_json', 'original_identity', 'safe_container'):
        ux[key] = helper[key]
    inspect, docker, read, write = helper['inspect'], helper['docker'], helper['read_json'], helper['private_json']
    with (STAGE / 'coordinated.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = REQUEST['action']
        print(json.dumps(preflight() if action == 'preflight' else terminal_check() if action == 'verify-terminal' else apply()))


def local():
    import argparse, subprocess, os, signal
    import p1_activate_local as activation
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'apply'))
    args = parser.parse_args(); activation.owner_check()
    root = activation.ROOT; out = root / 'output/p1-skills-ux-20261016'
    source = Path(__file__).read_text(encoding='utf-8')
    helper_source = (root / 'ops/agent_chat/p1_activation_remote.py').read_text(encoding='utf-8')
    ux_source = (root / 'ops/agent_chat/p1_skills_ux_update_remote.py').read_text(encoding='utf-8')
    request = {'action': args.action, 'sha256': hashlib.sha256(source.encode()).hexdigest(),
        'helper': helper_source, 'ux': ux_source, 'helper_hash': hashlib.sha256((helper_source + ux_source).encode()).hexdigest(),
        'recovery': json.loads((out / 'worker-recovery.json').read_text(encoding='utf-8'))}
    outer = json.loads(subprocess.check_output(['rtk', 'proxy', 'docker', 'inspect', activation.VM]))[0]
    if outer['HostConfig']['PortBindings'] or outer['NetworkSettings']['Ports']:
        raise RuntimeError('unexpected_published_ingress')
    def snapshot():
        code = "$connections=@(Get-NetTCPConnection -LocalPort 8800 -ErrorAction SilentlyContinue | ForEach-Object { @{address=$_.LocalAddress;port=$_.LocalPort;state=[string]$_.State;pid=$_.OwningProcess} }); $listener=@($connections | Where-Object { $_.state -eq 'Listen' }); $process=$null; if ($listener.Count -eq 1) { $process=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$listener[0].pid) }; @{connections=$connections;pid=$process.ProcessId;command=$process.CommandLine} | ConvertTo-Json -Compress -Depth 5"
        return json.loads(subprocess.check_output(['rtk', 'proxy', 'powershell', '-NoProfile', '-Command', code]))
    request['ingress'] = snapshot(); validate_ingress(request['ingress'])
    loader = "import sys,json; h=json.loads(sys.stdin.buffer.readline()); exec(compile(sys.stdin.buffer.read().decode(),'coordinated.py','exec'),{'__name__':'__main__','REQUEST':h})"
    import shlex
    closed = False
    result = None
    try:
        if args.action == 'apply':
            validate_ingress(snapshot())
            os.kill(TUNNEL_PID, signal.SIGTERM); closed = True
            for _ in range(20):
                if not snapshot()['connections']: break
                time.sleep(0.1)
            else: raise RuntimeError('host_ingress_not_closed')
            request['ingress_closed'] = True
        result = subprocess.run([*activation.SSH, 'sudo python3 -c ' + shlex.quote(loader)],
            input=json.dumps(request).encode() + b'\n' + source.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
    finally:
        if closed:
            if result is None:
                (out / 'tunnel-pending.json').write_text(json.dumps({'closed': True,
                    'reason': 'guest_completion_unknown_do_not_reopen_during_maintenance'}), encoding='utf-8')
                raise RuntimeError('guest_completion_unknown_owned_tunnel_left_closed')
            terminal_request = {**request, 'action': 'verify-terminal'}
            try:
                terminal = subprocess.run([*activation.SSH, 'sudo python3 -c ' + shlex.quote(loader)],
                    input=json.dumps(terminal_request).encode() + b'\n' + source.encode(),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            except subprocess.TimeoutExpired:
                (out / 'tunnel-pending.json').write_text(json.dumps({'closed': True,
                    'reason': 'terminal_verification_timed_out'}), encoding='utf-8')
                raise RuntimeError('terminal_verification_timeout_owned_tunnel_left_closed')
            if terminal.returncode:
                (out / 'tunnel-pending.json').write_text(json.dumps({'closed': True,
                    'reason': 'guest_lock_or_terminal_health_not_verified'}), encoding='utf-8')
                raise RuntimeError('terminal_health_unverified_owned_tunnel_left_closed')
            terminal_value = json.loads(terminal.stdout)
            if not terminal_value.get('safe_to_reopen_owned_tunnel'):
                raise RuntimeError('terminal_receipt_denies_reopen')
            (out / 'coordinated-terminal.json').write_text(json.dumps(terminal_value, indent=2), encoding='utf-8')
            if snapshot()['connections']:
                raise RuntimeError('foreign_listener_prevents_tunnel_reopen')
            reopen = "Start-Process -FilePath 'rtk' -ArgumentList @('proxy','C:/Users/javi/AppData/Local/Programs/Python/Python314/python.exe','ops/agent_chat/p1_activate_local.py','tunnel','--port','8800') -WorkingDirectory 'C:/Users/javi/Documents/Codex/regulai-platform' -WindowStyle Hidden -RedirectStandardOutput 'C:/Users/javi/Documents/Codex/regulai-platform/output/p1-skills-ux-20261016/tunnel.log' -RedirectStandardError 'C:/Users/javi/Documents/Codex/regulai-platform/output/p1-skills-ux-20261016/tunnel-error.log' | Out-Null"
            subprocess.run(['rtk', 'proxy', 'powershell', '-NoProfile', '-Command', reopen], check=True)
            for _ in range(30):
                current = snapshot()
                if current['connections']:
                    validate_ingress(current, expected_pid=None, idle=False)
                    break
                time.sleep(0.2)
            else: raise RuntimeError('owned_tunnel_reopen_failed')
            (out / 'tunnel-restored.json').write_text(json.dumps({'pid': current['pid'], 'loopback': True,
                'port': 8800, 'same_command': True, 'hidden': True}, indent=2), encoding='utf-8')
    if result.returncode: raise RuntimeError('coordinated_ux_' + args.action + '_failed:' + str(result.returncode))
    value = json.loads(result.stdout)
    (out / ('coordinated-' + args.action + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    guest() if 'REQUEST' in globals() else local()
