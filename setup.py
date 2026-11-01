#!/usr/bin/env python3
"""Local real-agent installer: Python stdlib + Docker, no RTK/uv/Node required."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
NAME = 'regulai-v2-vm'
VOLUME = 'regulai-v2-state'
IMAGE = 'regulai-v2-vm:local'
LABEL = 'regulai.install'
SSH = ['docker', 'exec', '-i', NAME, 'ssh', '-i', '/vm/id_ed25519', '-o', 'BatchMode=yes',
       '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=/vm/known_hosts',
       '-o', 'ConnectTimeout=5', '-p', '2222', 'probe@127.0.0.1']


def command(args, *, capture=False, check=True, **kwargs):
    result = subprocess.run(args, check=False, capture_output=capture, **kwargs)
    if check and result.returncode:
        if capture and result.stderr:
            print(result.stderr.decode(errors='replace'), file=sys.stderr)
        raise RuntimeError('Command failed: ' + ' '.join(args[:4]))
    return result


def inspect(kind, name):
    result = command(['docker', kind, 'inspect', name], capture=True, check=False)
    if result.returncode:
        return None
    value = json.loads(result.stdout)[0]
    labels = value.get('Labels') if kind == 'volume' else value['Config'].get('Labels')
    if (labels or {}).get(LABEL) != 'v2':
        raise RuntimeError(f'{name} belongs to another installation; refusing to overwrite it.')
    return value


def doctor():
    if sys.version_info < (3, 11):
        raise RuntimeError('Install Python 3.11 or newer.')
    if not shutil.which('docker'):
        raise RuntimeError('Install and start Docker Desktop (Windows/WSL2) or Docker Engine (Linux).')
    result = command(['docker', 'info', '--format', '{{json .}}'], capture=True)
    info = json.loads(result.stdout)
    if info['OSType'] != 'linux' or info['Architecture'] not in ('x86_64', 'amd64'):
        raise RuntimeError('This executor requires Linux x86-64 containers and nested KVM. ARM/Mac is not supported locally.')
    if info['MemTotal'] < 10 * 1024**3:
        raise RuntimeError('Assign at least 10 GiB RAM to Docker (16 GiB physical RAM recommended).')
    print('Docker Linux/x86-64 and RAM verified. KVM will be checked before installing.', flush=True)


def boot(create=False):
    current = inspect('container', NAME)
    if current is None:
        if not create:
            raise RuntimeError('Not installed. Run setup.py install --private-profile PATH first.')
        command(['docker', 'build', '-t', IMAGE, '-f', 'ops/setup/Dockerfile.vm', '.'], cwd=ROOT)
        result = command(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                          '--device', '/dev/kvm', IMAGE, 'stat', '-c', '%g', '/dev/kvm'], capture=True)
        group = result.stdout.decode().strip()
        if not group.isdigit():
            raise RuntimeError('KVM is unavailable. Enable CPU virtualization and WSL2 nested virtualization.')
        if inspect('volume', VOLUME) is None:
            command(['docker', 'volume', 'create', '--label', LABEL + '=v2', VOLUME])
        command(['docker', 'run', '-d', '--name', NAME, '--label', LABEL + '=v2', '--read-only',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '1000:1000',
                 '--group-add', group, '--device', '/dev/kvm', '--memory', '9g', '--cpus', '4',
                 '--pids-limit', '256', '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m,uid=1000,gid=1000',
                 '--mount', f'type=volume,src={VOLUME},dst=/vm', '-e', 'REGULAI_DISK_SIZE=96G', IMAGE])
    elif not current['State']['Running']:
        command(['docker', 'start', NAME])
    for attempt in range(180):
        ready = command([*SSH, 'true'], capture=True, check=False)
        if ready.returncode == 0:
            return
        if attempt % 15 == 0:
            print('Waiting for the private VM (first boot downloads verified Ubuntu)...', flush=True)
        time.sleep(3)
    raise RuntimeError('VM did not start. Inspect: docker logs regulai-v2-vm. Check KVM and free disk space.')


def remote(script):
    logs = ROOT / '.regulai-setup'
    logs.mkdir(exist_ok=True)
    log = logs / 'install.log'
    with log.open('ab') as stream:
        process = subprocess.Popen([*SSH, 'sudo', 'bash', '-se'], stdin=subprocess.PIPE,
                                   stdout=stream, stderr=subprocess.STDOUT)
        process.stdin.write(script.encode('utf-8'))
        process.stdin.close()
        while True:
            try:
                code = process.wait(timeout=30)
                break
            except subprocess.TimeoutExpired:
                print(f'Working... details: {log}', flush=True)
    if code:
        raise RuntimeError(f'VM setup failed. See {log}; fix the reported prerequisite and rerun the same command.')


def bundle(destination):
    """Allowlisted source roots, excluding all machine-specific data/secrets."""
    excluded = {'__pycache__', 'media', 'staticfiles', '.runtime', '.checkpoints', 'local_settings.py'}
    with tarfile.open(destination, 'w:gz') as archive:
        for folder in ('regulai', 'ops/agent_chat', 'ops/agent_probe', 'ops/setup'):
            for path in sorted((ROOT / folder).rglob('*')):
                relative = path.relative_to(ROOT)
                if (not path.is_file() or path.is_symlink() or any(p in excluded or p.startswith('.') for p in relative.parts)
                        or path.suffix in {'.sqlite3', '.pyc', '.key', '.pem', '.dump'}
                        or 'private' in path.name.lower()):
                    continue
                archive.add(path, arcname=relative.as_posix())
        archive.add(ROOT / '.dockerignore', arcname='.dockerignore')


def install(profile):
    if profile is not None:
        data = json.loads(profile.read_text(encoding='utf-8'))
        if data.get('format') != 'regulai-private-install-v1' or not data.get('objects'):
            raise RuntimeError('Invalid private profile; no simulated credentials will be substituted.')
    else:
        raise RuntimeError('Provide your private account/API profile with --private-profile PATH.')
    boot(create=True)
    print('Installing the private E2B backend...', flush=True)
    remote((ROOT / 'ops/setup/provision.sh').read_text(encoding='utf-8'))
    remote('mkdir -p /opt/regulai/source /opt/regulai/private\nchown 1000:1000 /opt/regulai/private\nchmod 700 /opt/regulai/private\n')
    with tempfile.TemporaryDirectory(prefix='regulai-install-') as directory:
        archive = Path(directory) / 'source.tar.gz'
        bundle(archive)
        with archive.open('rb') as stream:
            command([*SSH, 'sudo tar -xzf - -C /opt/regulai/source'], stdin=stream)
    # No credential in argv, environment, build context or logs. stdin only.
    command([*SSH, 'sudo sh -c \'umask 077; cat > /opt/regulai/private/import.json; chown 1000:1000 /opt/regulai/private/import.json\''],
            input=profile.read_bytes())
    print('Building application/worker/sandbox and importing the real profile...', flush=True)
    remote('cd /opt/regulai/source\npython3 -u ops/setup/install.py\n')


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        process = subprocess.Popen([*SSH[:-1], '-W', '127.0.0.1:31058', SSH[-1]], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def upload():
            try:
                while data := self.request.recv(65536):
                    process.stdin.write(data)
                    process.stdin.flush()
            except (OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        thread = threading.Thread(target=upload, daemon=True)
        thread.start()
        try:
            while data := process.stdout.read1(65536):
                self.request.sendall(data)
        except OSError:
            pass
        finally:
            process.terminate()
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=2)
            process.wait(timeout=10)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('doctor', 'install', 'start', 'stop', 'status'), nargs='?', default='install')
    parser.add_argument('--private-profile', type=Path)
    parser.add_argument('--port', type=int, default=8800)
    parser.add_argument('--no-tunnel', action='store_true', help='For automated installation checks only.')
    args = parser.parse_args()
    doctor()
    if args.action == 'doctor':
        return
    if args.action == 'stop':
        info = inspect('container', NAME)
        if info and info['State']['Running']:
            remote('docker stop -t 30 regulai-v2-worker regulai-v2-web regulai-v2-postgres\nsync\n')
            command(['docker', 'stop', '-t', '30', NAME])
        return
    if args.action == 'status':
        info = inspect('container', NAME)
        print('VM: ' + ('running' if info and info['State']['Running'] else 'stopped/not installed'))
        if info and info['State']['Running']:
            command([*SSH, "sudo docker ps --filter label=regulai.install=v2 --format '{{.Names}}: {{.Status}}'"])
        return
    if not args.no_tunnel:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', args.port))
    if args.action == 'install':
        profile = args.private_profile or ROOT / 'regulai-private.json'
        if not profile.is_file():
            raise RuntimeError('Private profile missing: copy regulai-private.json beside setup.py or use --private-profile PATH.')
        install(profile.resolve())
    else:
        boot()
    print('Checking web, PostgreSQL and real microVM rendering...', flush=True)
    remote('bash /opt/regulai/source/ops/setup/start.sh\n')
    if args.no_tunnel:
        return
    # Only loopback is exposed; admin/admin must never be published to a LAN.
    with Server(('127.0.0.1', args.port), Tunnel) as server:
        print(f'READY: http://127.0.0.1:{args.port}/login/ — initial login admin / admin.', flush=True)
        print('Keep this window open. Ctrl+C closes local access; setup.py stop stops the VM.', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nLocal access closed. Data remains in the Docker volume.')
    except (RuntimeError, OSError, ValueError) as error:
        print('SETUP FAILED: ' + str(error), file=sys.stderr)
        sys.exit(1)
