"""Add the repository-pinned spreadsheet dependencies to a new owned test image."""
import json
import hashlib
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/physical/documental-runtime'
IMAGE = 'regulai-p1-documental-runtime:20261016'
CONTAINER = 'regulai-p1-documental-export-20261016'
LINUX = '/tmp/regulai-p1-documental-20261016'


def run(*args, **kwargs):
    return subprocess.run(['rtk', 'proxy', *map(str, args)], check=True, **kwargs)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    if '--officecli' in sys.argv:
        import httpx
        target = OUT / 'officecli-linux-x64'
        expected = '1a5da5cb7e9d995db7a6560beb7466760c79617648f72e65f4ce55897c407f67'
        if not target.exists():
            with httpx.stream('GET', 'https://github.com/iOfficeAI/OfficeCLI/releases/download/v1.0.155/officecli-linux-x64',
                    follow_redirects=True, timeout=60) as response, target.open('xb') as output:
                response.raise_for_status()
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > 60_000_000:
                        raise ValueError('Pinned OfficeCLI binary exceeds expected maximum')
                    output.write(chunk)
        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected
        linux_target = '/mnt/' + target.drive[0].lower() + target.as_posix()[2:]
        install = "import pathlib,shutil,sys; b=pathlib.Path('/tmp/regulai-p1-documental-20261016'); assert b.resolve()==b and not b.is_symlink() and (b/'owner').read_text()=='regulai-p1-documental-20261016'; p=b/'runtime/bin/officecli'; assert not p.exists(); shutil.copyfile(sys.argv[1],p); p.chmod(0o555)"
        run('wsl', '-d', 'Ubuntu', '--', 'python3', '-c', install, linux_target)
        (OUT / 'officecli.json').write_text(json.dumps({'version': '1.0.155', 'sha256': expected,
            'bytes': target.stat().st_size, 'source': 'existing Dockerfile.spreadsheet pinned release',
            'paid_calls': 0}, indent=2))
        return
    blocks = re.split(r'(?=^[a-zA-Z0-9][a-zA-Z0-9_.-]*==)',
        (ROOT / 'ops/agent_chat/requirements.txt').read_text(), flags=re.M)
    packages = {'pandas', 'python-dateutil', 'pytz', 'six', 'tzdata'}
    chosen = [block for block in blocks if block.split('==')[0] in packages]
    assert len(chosen) == len(packages)
    (OUT / 'requirements.txt').write_text(''.join(chosen), encoding='utf-8')
    (OUT / 'Dockerfile').write_text('FROM regulai-p1-physical-runtime:20261016\n'
        'COPY requirements.txt /tmp/documental-requirements.txt\n'
        'RUN pip install --no-deps --require-hashes --no-cache-dir -r /tmp/documental-requirements.txt && pip check\n')
    with (OUT / 'build.log').open('w') as log:
        run('docker', 'build', '--tag', IMAGE, '--label', 'regulai.p1_documental=20261016', str(OUT), stdout=log, stderr=subprocess.STDOUT)
    run('docker', 'create', '--name', CONTAINER, '--label', 'regulai.p1_documental=20261016', '--network', 'none', IMAGE, 'true')
    try:
        with (OUT / 'runtime.tar').open('wb') as output:
            run('docker', 'cp', CONTAINER + ':/usr/local/.', '-', stdout=output)
    finally:
        info = json.loads(run('docker', 'inspect', CONTAINER, text=True, capture_output=True).stdout)[0]
        assert info['Config']['Labels']['regulai.p1_documental'] == '20261016'
        run('docker', 'rm', CONTAINER)
    run('wsl', '-d', 'Ubuntu', '--', 'python3', '-c',
        "import pathlib; p=pathlib.Path('/tmp/regulai-p1-documental-20261016'); p.mkdir(exist_ok=False); (p/'runtime').mkdir(); (p/'owner').write_text('regulai-p1-documental-20261016')")
    archive = OUT / 'runtime.tar'
    linux_archive = '/mnt/' + archive.drive[0].lower() + archive.as_posix()[2:]
    run('wsl', '-d', 'Ubuntu', '--', 'tar', '-xf', linux_archive, '-C', LINUX + '/runtime')
    (OUT / 'environment.json').write_text(json.dumps({'image': IMAGE, 'runtime': LINUX + '/runtime',
        'packages': sorted(packages), 'paid_calls': 0, 'provider_calls': 0, 'microvm_verified': False}, indent=2))


if __name__ == '__main__':
    main()
