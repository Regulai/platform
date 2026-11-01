"""Incident-only ClickHouse recovery copy; does not claim a clean shutdown.

Run as root in the identified v2 guest after the approved SIGSTOP. All file
names, contents and configuration remain in its private activation stage.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile

STAGE = Path('/opt/regulai/updates/p1-20261016-taste-a1')
IDENTITY = 'e0b4ae763f6f562aec8caec3f1fed8f0325c95c37ba510ddc0b249eef1a8edec'
ROOTS = {
    'data': Path('/var/lib/docker/volumes/e2b_clickhouse/_data'),
    'config': Path('/proc/1990/root/etc/clickhouse-server'),
    'logs': Path('/proc/1990/root/var/log/clickhouse-server'),
}


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def manifest():
    result = {}
    for label, root in ROOTS.items():
        for base, dirs, files in os.walk(root, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(base) / name
                info = path.lstat()
                key = label + '/' + path.relative_to(root).as_posix()
                row = {'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid,
                       'size': info.st_size, 'mtime_ns': info.st_mtime_ns,
                       'inode': info.st_ino, 'nlink': info.st_nlink}
                if stat.S_ISREG(info.st_mode):
                    row['sha256'] = digest(path)
                elif stat.S_ISLNK(info.st_mode):
                    row['target'] = os.readlink(path)
                elif not stat.S_ISDIR(info.st_mode):
                    raise RuntimeError('unexpected_clickhouse_special_file')
                result[key] = row
    return result


def private_json(name, value):
    path = STAGE / name
    with path.open('x') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def main():
    row = json.loads(subprocess.check_output(['docker', 'inspect', IDENTITY], timeout=5))[0]
    if (row['Id'] != IDENTITY or row['Name'] != '/e2b-clickhouse-1'
            or row['State']['Pid'] != 1990
            or row['Config']['Labels']['com.docker.compose.project'] != 'e2b'
            or row['HostConfig']['RestartPolicy']['Name'] != 'no'
            or IDENTITY not in Path('/proc/1990/cgroup').read_text()):
        raise RuntimeError('clickhouse_identity_changed')
    if Path('/proc/1990/stat').read_text().rsplit(')', 1)[1].split()[19] != '1168':
        raise RuntimeError('clickhouse_process_reused')
    states = {}
    for task in Path('/proc/1990/task').iterdir():
        state = (task / 'stat').read_text().rsplit(')', 1)[1].split()[0]
        states[state] = states.get(state, 0) + 1
    if set(states) - {'T', 't', 'D'} or states.get('D') != 1:
        raise RuntimeError('clickhouse_not_stopped_except_known_kernel_thread')
    blocked = Path('/proc/1990/task/3785')
    if (blocked / 'wchan').read_text().strip() != 'kvm_async_pf_task_wait_schedule':
        raise RuntimeError('clickhouse_kernel_exception_changed')
    subprocess.run(['sync'], check=True, timeout=30)
    before = manifest()
    before_path = private_json('clickhouse-files-before.json', before)
    print(json.dumps({'phase': 'clickhouse_manifest_before', 'entries': len(before)}), flush=True)
    archive = STAGE / 'clickhouse-crash-recovery.tar'
    with archive.open('xb') as stream:
        os.chmod(archive, 0o600)
        with tarfile.open(fileobj=stream, mode='w', dereference=False) as tar:
            for label, path in ROOTS.items():
                tar.add(path, arcname=label)
        stream.flush()
        os.fsync(stream.fileno())
    after = manifest()
    private_json('clickhouse-files-after.json', after)
    if before != after:
        raise RuntimeError('clickhouse_files_changed_during_recovery_copy')
    checked = 0
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if len(members) != len(before) + len(ROOTS):
            raise RuntimeError('clickhouse_archive_coverage_mismatch')
        for member in members:
            if member.name in ROOTS:
                continue
            original = before[member.name]
            if member.isfile() or member.islnk():
                content = tar.extractfile(member)
                value = hashlib.sha256()
                for chunk in iter(lambda: content.read(1024 * 1024), b''):
                    value.update(chunk)
                if value.hexdigest() != original['sha256']:
                    raise RuntimeError('clickhouse_archive_hash_mismatch')
                checked += 1
            elif member.issym() and member.linkname != original['target']:
                raise RuntimeError('clickhouse_archive_symlink_mismatch')
            if (member.uid, member.gid, member.mode) != (
                    original['uid'], original['gid'], stat.S_IMODE(original['mode'])):
                raise RuntimeError('clickhouse_archive_metadata_mismatch')
    receipt = {'phase': 'clickhouse_crash_recovery_copy_verified', 'clean_shutdown': False,
               'queries_available': False, 'thread_states': states, 'files_verified': checked,
               'manifest_sha256': digest(before_path), 'archive_sha256': digest(archive),
               'archive_bytes': archive.stat().st_size, 'before_after_identical': True,
               'image': row['Image'], 'id': IDENTITY,
               'limitations': ['No pre-shutdown row count available',
                               'Unflushed memory cannot be proven preserved']}
    private_json('clickhouse-recovery-copy-receipt.json', receipt)
    subprocess.run(['sync'], check=True, timeout=30)
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'error': str(error) if isinstance(error, RuntimeError)
                          else type(error).__name__}), flush=True)
        raise SystemExit(1)
