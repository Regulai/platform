"""Preserve the five local Community gates in a new evidence directory."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    output = Path(options.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manage = [sys.executable, 'regulai/manage.py']
    commands = [
        ('check', [*manage, 'check', '--settings=regulai.test_settings']),
        ('front-api', [*manage, 'test', 'front', 'api', '--settings=regulai.test_settings']),
        ('migrations', [*manage, 'makemigrations', '--check', '--dry-run', '--settings=regulai.test_settings']),
        ('offline', [*manage, 'evaluate_ai', '--settings=regulai.test_settings', '--output', str(output / 'offline')]),
        ('dependencies', ['uv', 'tool', 'run', '--from', 'pip-audit==2.10.1', 'pip-audit', '-r', 'requirements.txt']),
        ('postgres-dependencies', ['uv', 'tool', 'run', '--from', 'pip-audit==2.10.1', 'pip-audit', '-r', 'ops/pilot/requirements.txt']),
    ]
    revision = subprocess.run(['rtk', 'proxy', 'git', 'rev-parse', 'HEAD'], cwd=ROOT,
        capture_output=True, encoding='utf-8', check=True).stdout.strip()
    files = subprocess.run(['rtk', 'proxy', 'git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        cwd=ROOT, capture_output=True, encoding='utf-8', check=True).stdout.splitlines()
    hashes = {rel: sha256((ROOT / rel).read_bytes()).hexdigest() for rel in files
        if (rel.startswith(('regulai/', 'scripts/', 'ops/')) or rel == 'requirements.txt')
        and (ROOT / rel).is_file() and Path(rel).name != 'local_settings.py'
        and Path(rel).suffix in ('.py', '.txt', '.html', '.js', '.json', '.conf')}
    manifest = {'revision': revision, 'started_utc': datetime.now(timezone.utc).isoformat(),
                'source_sha256': hashes, 'commands': [], 'remote_ci_executed': False}
    for name, arguments in commands:
        started = time.monotonic()
        result = subprocess.run(['rtk', 'proxy', *arguments], cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        log = output / (name + '.log')
        log.write_text(result.stdout, encoding='utf-8')
        manifest['commands'].append({'gate': name, 'command': ['rtk', 'proxy', *arguments],
            'exit_code': result.returncode, 'seconds': round(time.monotonic() - started, 3),
            'log': log.name, 'sha256': sha256(log.read_bytes()).hexdigest()})
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        print(f'{name}: exit {result.returncode}', flush=True)
    manifest['source_unchanged'] = all((ROOT / rel).is_file()
        and sha256((ROOT / rel).read_bytes()).hexdigest() == value for rel, value in hashes.items())
    manifest['passed'] = manifest['source_unchanged'] and all(row['exit_code'] == 0 for row in manifest['commands'])
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return 0 if manifest['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
