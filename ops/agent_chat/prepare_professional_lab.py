"""Linux-only disposable lab preparation; never loads application credentials.

Requires uv, bubblewrap, LibreOffice, Poppler and PostgreSQL 18 already installed.
The selected action touches only /tmp/regulay-task56-20261014 and tool caches.
"""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

ROOT = Path('/tmp/regulay-task56-20261014')
REPO = Path(__file__).resolve().parents[2]
PG = Path('/usr/lib/postgresql/18/bin')
NODE_SHA = 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6'


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def prepare_runtime():
    uv = Path.home() / '.local/bin/uv'
    for name in ('bwrap', 'libreoffice', 'pdftoppm'):
        if not shutil.which(name):
            raise RuntimeError('Install the documented Linux prerequisite: ' + name)
    if not uv.is_file():
        raise RuntimeError('Install uv in ~/.local/bin before preparing the lab.')
    run(uv, 'python', 'install', '3.12.13')
    source = Path(run(uv, 'python', 'find', '3.12.13', capture_output=True, text=True).stdout.strip()).resolve().parent.parent
    environment, runtime = ROOT / 'venv', ROOT / 'runtime'
    if not environment.exists():
        run(uv, 'venv', '--python', source / 'bin/python3.12', environment)
    run(uv, 'pip', 'sync', '--python', environment / 'bin/python', '--require-hashes',
        REPO / 'ops/agent_chat/requirements.txt')
    if not runtime.exists():
        shutil.copytree(source, runtime, symlinks=True)
    shutil.copytree(environment / 'lib/python3.12/site-packages', runtime / 'lib/python3.12/site-packages', dirs_exist_ok=True)
    archive = ROOT / 'node.tar.xz'
    if not archive.exists():
        with urlopen('https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz', timeout=60) as source:
            archive.write_bytes(source.read(40000000))
    if hashlib.sha256(archive.read_bytes()).hexdigest() != NODE_SHA:
        raise RuntimeError('Node archive digest mismatch; no extraction performed.')
    with tarfile.open(archive) as source:
        source.extractall(ROOT / 'node', filter='data')
    shutil.copytree(ROOT / 'node/node-v24.21.0-linux-x64', runtime, dirs_exist_ok=True, symlinks=True)
    run(environment / 'bin/python', '-m', 'playwright', 'install', 'chromium')
    print('Prepared lab runtime:', runtime)


def postgres(action):
    directory = ROOT / 'postgres'
    if action == 'start-postgres':
        if not directory.exists():
            run(PG / 'initdb', '-D', directory, '-U', 'task56', '--auth=trust')
            with (directory / 'postgresql.conf').open('a') as output:
                output.write("\nlisten_addresses='127.0.0.1'\nport=55456\nunix_socket_directories='" + str(ROOT) + "'\n")
        if subprocess.run([str(PG / 'pg_ctl'), '-D', str(directory), 'status'], capture_output=True).returncode:
            run(PG / 'pg_ctl', '-D', directory, '-l', ROOT / 'postgres.log', 'start')
    elif directory.exists():
        run(PG / 'pg_ctl', '-D', directory, 'stop', '-m', 'fast')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare-runtime', 'start-postgres', 'stop-postgres'))
    args = parser.parse_args()
    if Path('/tmp').resolve() != ROOT.parent or ROOT.is_symlink():
        raise RuntimeError('The lab requires its dedicated Linux temporary directory.')
    ROOT.mkdir(exist_ok=True)
    if args.action == 'prepare-runtime':
        prepare_runtime()
    else:
        postgres(args.action)
