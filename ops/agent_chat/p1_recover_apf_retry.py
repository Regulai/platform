"""Owned-guest APF mitigation and second graceful stop; no image rebuilds.

The caller injects the already reviewed recovery library and current inventory.
This one-incident script never repairs databases or deletes container metadata.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess

ROOT = Path('/opt/regulai/updates/p1-20261016-taste-a2')
STAGE = ROOT / 'recovery-apf-2'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_json(path, value):
    with path.open('w') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def inspect_disk(expected):
    folder = Path('/var/lib/docker/containers') / expected['id']
    row = json.loads((folder / 'config.v2.json').read_text())
    row['Id'] = row['ID']
    row['HostConfig'] = json.loads((folder / 'hostconfig.json').read_text())
    labels = row['Config'].get('Labels') or {}
    if (row['Id'] != expected['id'] or row['Name'] != expected['name']
            or not (labels.get('regulai.install') == 'v2'
                    or labels.get('com.docker.compose.project') == 'e2b')):
        raise RuntimeError('recovery_container_identity_changed')
    return row


class DockerHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(2)
        self.sock.connect('/var/run/docker.sock')


def main(expected, lib):
    if os.geteuid() != 0 or not ROOT.is_dir():
        raise RuntimeError('owned_stage_required')
    STAGE.mkdir(mode=0o700, exist_ok=False)
    lib['STAGE'] = STAGE
    lib['inspect'] = inspect_disk
    rows = {r['name'].lstrip('/'): r for r in expected['containers'] if r['running']}
    if len(rows) != 13:
        raise RuntimeError('original_running_inventory_changed')
    lib['require_idle'](rows['regulai-v2-postgres'])
    receipt = {'phase': 'backups', 'stopped': [], 'forced_kills': 0}
    lib['checkpoint'](receipt)
    for name, filename in (('regulai-v2-postgres', 'application.dump'),
                           ('e2b-postgres-1', 'control.sql')):
        row = inspect_disk(rows[name])
        process = lib['process_identity'](row)
        env = dict(v.split('=', 1) for v in row['Config']['Env'])
        executable = 'pg_dump' if name == 'regulai-v2-postgres' else 'pg_dumpall'
        args = ['nsenter', '--target', str(process['pid']), '--mount', '--net',
                '--root', '--wd', '--', '/usr/local/bin/' + executable,
                '-U', env['POSTGRES_USER']]
        if executable == 'pg_dump':
            args += ['-d', 'regulai', '--format=custom', '--no-owner', '--no-acl']
        path = STAGE / filename
        with path.open('xb') as output:
            os.chmod(path, 0o600)
            result = subprocess.run(args, stdout=output, stderr=subprocess.PIPE, timeout=45)
            output.flush()
            os.fsync(output.fileno())
        if result.returncode or not path.stat().st_size:
            raise RuntimeError('fresh_postgres_backup_failed')
        receipt.setdefault('backups', {})[name] = {'bytes': path.stat().st_size, 'sha256': sha(path)}
    dropin = Path('/etc/default/grub.d/99-regulai-no-kvmapf.cfg')
    if dropin.exists():
        raise RuntimeError('owned_apf_dropin_already_exists')
    sources = [Path('/etc/default/grub'), *Path('/etc/default/grub.d').glob('*.cfg'),
               Path('/boot/grub/grub.cfg')]
    receipt['grub_before'] = []
    for index, path in enumerate(sources):
        target = STAGE / ('grub-before-' + str(index))
        shutil.copyfile(path, target)
        os.chmod(target, 0o600)
        receipt['grub_before'].append({'path': str(path), 'sha256': sha(path),
                                     'mode': path.stat().st_mode & 0o777})
    loader = Path('/usr/sbin/grub-mkconfig').read_text()
    if ('sysconfdir="/etc"' not in loader
            or 'for x in ${sysconfdir}/default/grub.d/*.cfg' not in loader):
        raise RuntimeError('grub_dropin_loader_not_confirmed')
    dropin.write_text('GRUB_CMDLINE_LINUX="${GRUB_CMDLINE_LINUX} no-kvmapf"\n')
    os.chmod(dropin, 0o644)
    with (STAGE / 'update-grub.log').open('wb') as log:
        os.chmod(STAGE / 'update-grub.log', 0o600)
        result = subprocess.run(['update-grub'], stdout=log, stderr=subprocess.STDOUT, timeout=30)
    if result.returncode:
        raise RuntimeError('update_grub_failed')
    grub = Path('/boot/grub/grub.cfg')
    lines = [line.strip() for line in grub.read_text().splitlines()
             if line.strip().startswith(('linux ', 'linux\t'))]
    if not lines or any(line.split().count('no-kvmapf') != 1 for line in lines):
        raise RuntimeError('generated_kernel_argument_not_confirmed')
    if shutil.which('grub-script-check'):
        subprocess.run(['grub-script-check', str(grub)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)
    receipt['grub_after'] = {'path': str(grub), 'sha256': sha(grub),
                            'mode': grub.stat().st_mode & 0o777,
                            'linux_entries_with_single_token': len(lines),
                            'dropin_sha256': sha(dropin), 'update_grub_exit': 0}
    lib['checkpoint'](receipt)
    lib['emit']({'phase': 'apf_boot_mitigation_prepared', 'kernel_entries': len(lines),
                 'backups': receipt['backups'], 'grub_after': receipt['grub_after']})
    policies = {}
    for value in rows.values():
        row = inspect_disk(value)
        policy = row['HostConfig']['RestartPolicy']
        policies[row['Id']] = {'name': row['Name'], 'restart': policy}
    private_json(STAGE / 'restart-policies-original.json', policies)
    for value in rows.values():
        row = inspect_disk(value)
        if row['HostConfig']['RestartPolicy']['Name'] != 'no':
            client = DockerHTTP('localhost')
            try:
                client.request('POST', '/v1.41/containers/' + row['Id'] + '/update',
                    json.dumps({'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}}),
                    {'Content-Type': 'application/json'})
                response = client.getresponse()
                response.read()
            except TimeoutError:
                pass  # Verify persisted configuration, never infer success.
            finally:
                client.close()
            if inspect_disk(value)['HostConfig']['RestartPolicy']['Name'] != 'no':
                raise RuntimeError('automatic_restart_disable_not_persisted')
    order = ['regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres',
             'e2b-api-1', 'e2b-client-proxy-1', 'e2b-dashboard-1',
             'e2b-dashboard-api-1', 'e2b-ready-1', 'e2b-vector-1',
             'e2b-orchestrator-1', 'e2b-redis-1', 'e2b-clickhouse-1', 'e2b-postgres-1']
    for name in order:
        lib['stop_one'](rows[name], receipt)
        if name == 'regulai-v2-web':
            lib['require_idle'](rows['regulai-v2-postgres'])
    for value in rows.values():
        if lib['actual_processes'](value['id']):
            raise RuntimeError('original_process_restarted')
    subprocess.run(['sync'], check=True, timeout=30)
    receipt['phase'] = 'apf_mitigated_all_services_stopped_synced'
    lib['checkpoint'](receipt)
    subprocess.run(['sync'], check=True, timeout=30)
    lib['emit']({'phase': receipt['phase'], 'stopped': len(receipt['stopped']),
                 'postgres_clean': [v['name'] for v in receipt['stopped']
                                    if v['postgres_clean_shutdown']],
                 'forced_kills': 0, 'sync_completed': True})


def continue_with_paused_daemon(expected, lib):
    """Docker logging pauses too: use PostgreSQL's own offline control reader."""
    lib['STAGE'] = STAGE
    lib['inspect'] = inspect_disk
    receipt = json.loads((STAGE / 'graceful-stop-receipt.json').read_text())
    if receipt['phase'] not in ('backups', 'stopping:e2b-vector-1') or not receipt.get('grub_after'):
        raise RuntimeError('reviewed_pre_stop_phase_required')
    pid = int(Path('/run/docker.pid').read_text())
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    if (proc / 'exe').resolve() != Path('/usr/bin/dockerd') or 'docker.service' not in (proc / 'cgroup').read_text():
        raise RuntimeError('guest_dockerd_identity_mismatch')
    descriptor = os.pidfd_open(pid)
    try:
        if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[19] != fields[19]:
            raise RuntimeError('guest_dockerd_process_reused')
        signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
    finally:
        os.close(descriptor)
    import time
    time.sleep(0.2)
    if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
        raise RuntimeError('guest_dockerd_not_paused')
    receipt['paused_guest_dockerd'] = {'pid': pid, 'start_ticks': fields[19],
                                       'signal': 'SIGSTOP', 'reason': 'prevent_automatic_restart'}
    lib['checkpoint'](receipt)
    lib['emit']({'phase': 'guest_dockerd_paused', 'pid': pid})
    rows = {r['name'].lstrip('/'): r for r in expected['containers'] if r['running']}
    for stopped in receipt['stopped']:
        if lib['actual_processes'](stopped['id']):
            raise RuntimeError('previously_stopped_container_restarted')
    if receipt['phase'] == 'stopping:e2b-vector-1':
        vector = rows['e2b-vector-1']
        if lib['actual_processes'](vector['id']):
            raise RuntimeError('vector_graceful_shutdown_still_pending')
        receipt['stopped'].append({'name': 'e2b-vector-1', 'id': vector['id'],
            'pid': vector['pid'], 'graceful': True, 'postgres_clean_shutdown': False,
            'observation': 'Exited after initial 45-second TERM observation; no further signal'})
        lib['checkpoint'](receipt)
        lib['emit']({'name': 'e2b-vector-1', 'graceful': True, 'late_exit_confirmed': True})
    else:
        lib['require_idle'](rows['regulai-v2-postgres'])
    order = ['regulai-v2-web', 'regulai-v2-worker', 'regulai-v2-postgres',
             'e2b-api-1', 'e2b-client-proxy-1', 'e2b-dashboard-1',
             'e2b-dashboard-api-1', 'e2b-ready-1', 'e2b-vector-1',
             'e2b-orchestrator-1', 'e2b-redis-1', 'e2b-clickhouse-1', 'e2b-postgres-1']
    for name in order:
        if any(value['name'] == name for value in receipt['stopped']):
            continue
        row = inspect_disk(rows[name])
        confirmation = None
        if name in ('regulai-v2-postgres', 'e2b-postgres-1'):
            env = dict(v.split('=', 1) for v in row['Config']['Env'])
            # This read-only helper retains the original mount namespace after
            # postmaster exits. Its process is outside the container's cgroup.
            program = ('i=0; while [ "$i" -lt 40 ]; do '
                'result=$(/usr/local/bin/pg_controldata "$1") || exit 2; '
                'case "$result" in *"Database cluster state:               shut down"*) '
                'printf "%s\\n" "$result"; exit 0;; esac; '
                'sleep 1; i=$((i+1)); done; exit 3')
            checker = subprocess.Popen(['nsenter', '--target', str(row['State']['Pid']),
                '--mount', '--net', '--root', '--wd', '--', '/bin/sh', '-c', program,
                'pg_control_check', env['PGDATA']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            def confirmation(checker=checker, name=name):
                out, err = checker.communicate(timeout=45)
                target = STAGE / (name + '-pg-controldata.txt')
                target.write_bytes(out)
                os.chmod(target, 0o600)
                if checker.returncode or b'Database cluster state:               shut down' not in out:
                    raise RuntimeError('offline_postgres_clean_shutdown_not_confirmed:' + name)
        lib['stop_one'](rows[name], receipt, postgres_confirmation=confirmation)
        if name == 'regulai-v2-web':
            lib['require_idle'](rows['regulai-v2-postgres'])
        if (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0] not in ('T', 't'):
            raise RuntimeError('guest_dockerd_resumed_during_shutdown')
    for value in rows.values():
        if lib['actual_processes'](value['id']):
            raise RuntimeError('original_process_restarted')
    subprocess.run(['sync'], check=True, timeout=30)
    receipt['phase'] = 'apf_mitigated_all_services_stopped_synced'
    lib['checkpoint'](receipt)
    subprocess.run(['sync'], check=True, timeout=30)
    lib['emit']({'phase': receipt['phase'], 'stopped': len(receipt['stopped']),
                 'postgres_clean': [v['name'] for v in receipt['stopped']
                                    if v['postgres_clean_shutdown']],
                 'forced_kills': 0, 'sync_completed': True})


if __name__ == '__main__':
    try:
        if globals().get('_CONTINUE_WITH_PAUSED_DAEMON'):
            continue_with_paused_daemon(_EXPECTED, _LIB)
        else:
            main(_EXPECTED, _LIB)
    except Exception as error:
        print(json.dumps({'error': str(error) if isinstance(error, RuntimeError)
                          else type(error).__name__}), flush=True)
        raise SystemExit(1)
