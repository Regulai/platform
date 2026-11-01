"""One-incident graceful stop for the owned v2 guest before its APF recovery.

Executed inside the guest with the reviewed public inventory in _EXPECTED.
No daemon, disk, container, credential or database is recreated by this script.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

STAGE = Path('/opt/regulai/updates/p1-20261016-taste-a1')


def emit(value):
    print(json.dumps(value), flush=True)


def checkpoint(value):
    path = STAGE / 'graceful-stop-receipt.json'
    with path.open('w') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def inspect(expected):
    result = subprocess.run(['docker', 'inspect', expected['id']],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if result.returncode:
        raise RuntimeError('original_container_inspection_failed')
    row = json.loads(result.stdout)[0]
    labels = row['Config'].get('Labels') or {}
    if (row['Id'] != expected['id'] or row['Name'] != expected['name']
            or not (labels.get('regulai.install') == 'v2'
                    or labels.get('com.docker.compose.project') == 'e2b')):
        raise RuntimeError('container_identity_or_ownership_changed')
    return row


def process_identity(row):
    pid = row['State']['Pid']
    path = Path('/proc') / str(pid)
    if not pid or not path.exists():
        return None
    fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
    if row['Id'] not in (path / 'cgroup').read_text():
        raise RuntimeError('container_pid_cgroup_mismatch')
    return {'pid': pid, 'start_ticks': fields[19], 'state': fields[0]}


def require_idle(postgres):
    row = inspect(postgres)
    identity = process_identity(row)
    if identity is None:
        raise RuntimeError('postgres_process_required_for_idle_check')
    sql = """SELECT json_build_object(
      'live',(SELECT count(*) FROM front_agentexecution WHERE status IN ('queued','active','outcome_unknown')),
      'provider',(SELECT count(*) FROM front_agentinference WHERE response->'_capacity'->>'state' IN ('reserved','active','uncertain')),
      'sandbox',(SELECT count(*) FROM front_agentexecution WHERE job->'sandbox_reservation'->>'state' IN ('reserved','active','uncertain')))
    """
    result = subprocess.run(['nsenter', '--target', str(identity['pid']), '--mount', '--net',
        '--root', '--wd', '--', '/usr/local/bin/psql', '-XAt', '-U', 'regulai', '-d', 'regulai', '-c', sql],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    if result.returncode or any(json.loads(result.stdout).values()):
        raise RuntimeError('idle_recovery_boundary_not_satisfied')


def actual_processes(identity):
    found = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            if identity in (path / 'cgroup').read_text():
                fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
                if fields[0] != 'Z':
                    found.append(int(path.name))
        except FileNotFoundError:
            pass
    return found


def stop_one(expected, receipt, *, postgres_confirmation=None):
    row = inspect(expected)
    original = process_identity(row)
    if not row['State']['Running'] or original is None:
        raise RuntimeError('original_process_changed_before_graceful_stop')
    name = row['Name'].lstrip('/')
    is_postgres = name in ('regulai-v2-postgres', 'e2b-postgres-1')
    log = Path(row['LogPath'])
    if not log.resolve().is_relative_to(Path('/var/lib/docker/containers') / row['Id']):
        raise RuntimeError('unexpected_container_log_path')
    start_offset = log.stat().st_size
    receipt['phase'] = 'stopping:' + name
    checkpoint(receipt)
    descriptor = os.pidfd_open(original['pid'])
    try:
        fresh = process_identity(row)
        if fresh is None or any(fresh[key] != original[key] for key in ('pid', 'start_ticks')):
            raise RuntimeError('container_pid_starttime_changed')
        use_interrupt = is_postgres or name == 'e2b-ready-1'
        signal.pidfd_send_signal(descriptor, signal.SIGINT if use_interrupt else signal.SIGTERM)
    finally:
        os.close(descriptor)
    for _ in range(45):
        current = process_identity(row)
        if (current is None or current['state'] == 'Z') and not actual_processes(row['Id']):
            break
        if current is not None and current['start_ticks'] != original['start_ticks']:
            raise RuntimeError('container_pid_reused_during_stop')
        time.sleep(1)
    else:
        raise RuntimeError('graceful_stop_timeout:' + name)
    if actual_processes(row['Id']):
        raise RuntimeError('container_has_remaining_or_restarted_processes:' + name)
    if is_postgres:
        if postgres_confirmation is not None:
            postgres_confirmation()
        else:
            with log.open('rb') as stream:
                stream.seek(start_offset)
                raw = stream.read(1024 * 1024)
            if b'database system is shut down' not in raw:
                raise RuntimeError('postgres_clean_shutdown_not_confirmed:' + name)
    value = {'name': name, 'id': row['Id'], 'pid': original['pid'],
             'start_ticks': original['start_ticks'], 'graceful': True,
             'postgres_clean_shutdown': is_postgres}
    if is_postgres and postgres_confirmation is not None:
        value['postgres_confirmation'] = 'pg_controldata:shut down'
    receipt['stopped'].append(value)
    checkpoint(receipt)
    emit(value)


def main(expected, *, inspect_only=False):
    if os.geteuid() != 0 or not STAGE.is_dir():
        raise RuntimeError('owned_guest_stage_required')
    rows = {value['name'].lstrip('/'): value for value in expected['containers'] if value['running']}
    observed = []
    for path in Path('/var/lib/docker/containers').glob('*/config.v2.json'):
        value = json.loads(path.read_text())
        if (value.get('State') or {}).get('Running'):
            observed.append(value['ID'])
    if set(observed) != {value['id'] for value in rows.values()}:
        raise RuntimeError('running_container_inventory_changed')
    for value in rows.values():
        row = inspect(value)
        if not row['State']['Running'] or process_identity(row) is None:
            raise RuntimeError('original_running_process_missing')
    emit({'validated_running_containers': len(rows), 'inspect_only': inspect_only})
    if inspect_only:
        return
    if not (STAGE / 'recovery-before-invariants.json').is_file() or not (STAGE / 'before-daemon-recovery.dump').is_file():
        raise RuntimeError('fresh_backup_and_fingerprint_required')
    require_idle(rows['regulai-v2-postgres'])
    receipt = {'phase': 'validated', 'stopped': [], 'forced_kills': 0}
    checkpoint(receipt)
    order = ['regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres']
    databases = ('e2b-redis-1', 'e2b-clickhouse-1', 'e2b-postgres-1')
    order += sorted(name for name in rows if name not in order and name not in databases)
    order += [name for name in databases if name in rows]
    for name in order:
        stop_one(rows[name], receipt)
        if name == 'regulai-v2-web':
            require_idle(rows['regulai-v2-postgres'])
    subprocess.run(['sync'], check=True, timeout=30)
    receipt['phase'] = 'clean_stopped_synced'
    checkpoint(receipt)
    subprocess.run(['sync'], check=True, timeout=30)
    emit({'phase': receipt['phase'], 'stopped': len(receipt['stopped']), 'forced_kills': 0})


def resume_control_stop(expected):
    """Only the independently reviewed APF exception, never a generic skip."""
    receipt = json.loads((STAGE / 'graceful-stop-receipt.json').read_text())
    if receipt['phase'] not in ('stopping:e2b-orchestrator-1', 'stopping:e2b-ready-1'):
        raise RuntimeError('reviewed_recovery_phase_required')
    if receipt['phase'] == 'stopping:e2b-ready-1':
        receipt['readiness_sidecar'] = {'term_timeout_seconds': 45, 'graceful_signal': 'SIGINT'}
    rows = {value['name'].lstrip('/'): value for value in expected['containers'] if value['running']}
    for value in receipt['stopped']:
        row = inspect(rows[value['name']])
        if row['Id'] != value['id'] or actual_processes(row['Id']):
            raise RuntimeError('previously_stopped_container_restarted')
    identity = '42212da4fd328f68c0167a6452499ac36ac1ac72b64c760f2d6bff94a1753a97'
    row = inspect(rows['e2b-orchestrator-1'])
    if row['Id'] != identity or row['State']['Pid'] != 2053 or set(actual_processes(identity)) != {2053, 2366}:
        raise RuntimeError('orchestrator_exception_identity_changed')
    task = Path('/proc/2366/task/6042')
    fields = (task / 'stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] != 'D' or (task / 'wchan').read_text().strip() != 'kvm_async_pf_task_wait_schedule':
        raise RuntimeError('orchestrator_kernel_exception_no_longer_matches')
    for value in rows.values():
        if inspect(value)['HostConfig']['RestartPolicy']['Name'] != 'no':
            raise RuntimeError('automatic_restart_must_be_disabled')
    receipt['exceptions'] = [{'name': 'e2b-orchestrator-1', 'id': identity,
        'pid': 2053, 'blocked_pid': 2366, 'blocked_tid': 6042,
        'reason': 'kernel_async_page_fault_uninterruptible', 'term_timeout_seconds': 45,
        'forced_kill': False}]
    checkpoint(receipt)
    emit({'orchestrator_kernel_exception_verified': True})
    for name in ('e2b-ready-1', 'e2b-vector-1', 'e2b-redis-1', 'e2b-clickhouse-1', 'e2b-postgres-1'):
        stop_one(rows[name], receipt)
    for value in rows.values():
        if value['id'] != identity and actual_processes(value['id']):
            raise RuntimeError('container_restarted_before_sync')
    subprocess.run(['sync'], check=True, timeout=30)
    receipt['phase'] = 'clean_databases_stopped_synced_with_kernel_exception'
    checkpoint(receipt)
    subprocess.run(['sync'], check=True, timeout=30)
    emit({'phase': receipt['phase'], 'stopped': len(receipt['stopped']),
          'kernel_exceptions': len(receipt['exceptions']), 'forced_kills': 0})


if __name__ == '__main__':
    try:
        if globals().get('_RESUME_CONTROL'):
            resume_control_stop(_EXPECTED)
        else:
            main(_EXPECTED, inspect_only=_INSPECT_ONLY)
    except Exception as error:
        code = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        emit({'error': code})
        raise SystemExit(1)
