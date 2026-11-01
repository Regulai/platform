"""Create only the owned, local WSL runtime used by offline physical P1 tests."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/physical'
IMAGE = 'regulai-p1-physical-runtime:20261016'
CONTAINER = 'regulai-p1-physical-export-20261016'
LINUX = '/tmp/regulai-p1-physical-20261016'


def run(*command, **kwargs):
    return subprocess.run(['rtk', 'proxy', *map(str, command)], check=True, **kwargs)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    requirements = (ROOT / 'ops/agent_chat/requirements.txt').read_text(encoding='utf-8')
    chosen = {'numpy', 'python-docx', 'python-pptx', 'openpyxl', 'lxml', 'pypdf', 'pillow', 'et-xmlfile', 'typing-extensions', 'xlsxwriter'}
    blocks = re.split(r'(?=^[a-zA-Z0-9][a-zA-Z0-9_.-]*==)', requirements, flags=re.M)
    selected = [block for block in blocks if block.split('==', 1)[0].lower() in chosen]
    assert len(selected) == len(chosen), 'Pinned dependency block missing'
    (OUT / 'requirements.txt').write_text(''.join(selected), encoding='utf-8')
    (OUT / 'Dockerfile').write_text('FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f\n'
        'COPY requirements.txt /tmp/requirements.txt\n'
        'RUN pip install --no-deps --require-hashes --no-cache-dir -r /tmp/requirements.txt && pip check\n', encoding='utf-8')
    with (OUT / 'build.log').open('w', encoding='utf-8') as log:
        run('docker', 'build', '--tag', IMAGE, '--label', 'regulai.p1_physical=20261016', str(OUT), stdout=log, stderr=subprocess.STDOUT)
    run('docker', 'create', '--name', CONTAINER, '--label', 'regulai.p1_physical=20261016', '--network', 'none', IMAGE, 'true')
    try:
        with (OUT / 'runtime.tar').open('wb') as output:
            run('docker', 'cp', CONTAINER + ':/usr/local/.', '-', stdout=output)
    finally:
        inspected = json.loads(run('docker', 'inspect', CONTAINER, capture_output=True, text=True).stdout)[0]
        assert inspected['Config']['Labels']['regulai.p1_physical'] == '20261016'
        run('docker', 'rm', CONTAINER)
    prepare = "import pathlib; p=pathlib.Path('/tmp/regulai-p1-physical-20261016'); p.mkdir(exist_ok=False); (p/'runtime').mkdir(); (p/'owner').write_text('regulai-p1-physical-20261016')"
    run('wsl', '-d', 'Ubuntu', '--', 'python3', '-c', prepare)
    archive = OUT / 'runtime.tar'
    linux_archive = '/mnt/' + archive.drive[0].lower() + archive.as_posix()[2:]
    run('wsl', '-d', 'Ubuntu', '--', 'tar', '-xf', linux_archive, '-C', LINUX + '/runtime')
    run('wsl', '-d', 'Ubuntu', '--', 'bwrap', '--unshare-all', '--ro-bind', '/usr', '/usr',
        '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
        '--ro-bind', LINUX + '/runtime', '/usr/local', '--proc', '/proc', '--dev', '/dev',
        '/usr/local/bin/python', '-c', 'import numpy,sys; print(sys.version); print(numpy.__version__)')
    (OUT / 'environment.json').write_text(json.dumps({'image': IMAGE, 'runtime': LINUX + '/runtime',
        'provider_calls': 0, 'e2b_calls': 0, 'source': 'local Python image plus existing hash-pinned runtime dependencies'}) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
