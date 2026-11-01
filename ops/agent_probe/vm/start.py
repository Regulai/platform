"""Start/reuse only our labelled disposable E2B host, without host bind mounts."""
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
NAME = 'regulay-task48-e2bvm'
VOLUME = NAME + '-state'
IMAGE = 'regulay-task48-vm:local'


def docker(*args, check=True):
    result = subprocess.run(['rtk', 'proxy', 'docker', *args], capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=600)
    if check and result.returncode:
        raise RuntimeError(result.stderr)
    return result


def main():
    existing = docker('container', 'inspect', NAME, check=False)
    if existing.returncode == 0:
        item = json.loads(existing.stdout)[0]
        if item['Config']['Labels'].get('regulay.task') != '48':
            raise RuntimeError('Name belongs to a different container; refusing to modify it')
        if not item['State']['Running']:
            docker('start', NAME)
        print('Reusing the task 48 VM; wait for SSH, then run provision.sh')
        return
    print('Building VM launcher', flush=True)
    docker('build', '-t', IMAGE, str(HERE))
    group = docker('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                   '--device', '/dev/kvm', IMAGE, 'stat', '-c', '%g', '/dev/kvm').stdout.strip()
    if not group.isdigit():
        raise RuntimeError('Could not determine the KVM device group')
    volume = docker('volume', 'inspect', VOLUME, check=False)
    if volume.returncode == 0:
        if (json.loads(volume.stdout)[0].get('Labels') or {}).get('regulay.task') != '48':
            raise RuntimeError('Volume is not owned by this probe')
    else:
        docker('volume', 'create', '--label', 'regulay.task=48', VOLUME)
    docker('run', '-d', '--name', NAME, '--label', 'regulay.task=48', '--read-only',
           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '1000:1000',
           '--group-add', group, '--device', '/dev/kvm', '--memory', '9g', '--cpus', '4',
           '--pids-limit', '256', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,uid=1000,gid=1000',
           '--mount', f'type=volume,src={VOLUME},dst=/vm', IMAGE)
    print('VM starting; wait for cloud-init, then run provision.sh')


if __name__ == '__main__':
    main()
