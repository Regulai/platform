"""Freeze the effective P0 source, without credentials or private data.

Run before editing P1. The source archive allows fixtures to execute against
the measured checkout while other agents continue work in the main tree.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SUFFIXES = {'.py', '.md', '.txt', '.in', '.html', '.css', '.js', '.mjs', '.json', '.sh', '.yml', '.yaml', '.toml', '.svg'}
EXCLUDED = {'__pycache__', 'node_modules', '.venv', 'media', 'staticfiles', '.runtime', '.checkpoints'}
ROOTS = ('regulai/front', 'regulai/api', 'regulai/regulai', 'regulai/static',
         'ops/agent_chat', 'scripts', 'evals/corpora/p0-conversations-20261016')
PACKAGES = ('Django', 'djangorestframework', 'openai', 'anthropic', 'httpx', 'mcp',
            'deepagents', 'langgraph', 'langchain', 'langchain-core', 'langchain-e2b', 'numpy', 'psycopg', 'psycopg2-binary')


def git(*args):
    return subprocess.run(['rtk', 'proxy', 'git', *args], cwd=ROOT, text=True,
                          capture_output=True, check=True, encoding='utf-8').stdout.strip()


def versions(python):
    source = ('import importlib.metadata as m,json,platform; '
              f'names={PACKAGES!r}; '
              'installed={d.metadata["Name"].lower():d.version for d in m.distributions()}; '
              'print(json.dumps({"python":platform.python_version(),"packages":{n:installed.get(n.lower()) for n in names}}))')
    result = subprocess.run(['rtk', 'proxy', str(python), '-c', source], text=True,
                            capture_output=True, check=True, encoding='utf-8')
    return json.loads(result.stdout)


def source_paths():
    paths = set()
    for folder in ROOTS:
        for path in (ROOT / folder).rglob('*'):
            rel = path.relative_to(ROOT)
            if (not path.is_file() or path.is_symlink() or any(p in EXCLUDED for p in rel.parts)
                    or path.suffix.lower() not in SUFFIXES or path.name == 'local_settings.py'
                    or path.name.startswith('.env') or 'secret' in path.name.lower()):
                continue
            paths.add(path)
    paths.update(ROOT / item for item in ('regulai/manage.py', 'requirements.txt', 'AGENTS.md'))
    paths.update((ROOT / 'docs/plan-blackhat/tareas').glob('6[02567]-p0-*.md'))
    return sorted(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='output/p1-20261016/e1')
    args = parser.parse_args()
    destination = (ROOT / args.output).resolve()
    if not destination.is_relative_to(ROOT / 'output'):
        raise SystemExit('Evidence must remain inside workspace output/.')
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / 'p0-manifest.json'
    if target.exists():
        raise SystemExit('Refusing to overwrite an existing baseline.')
    files = []
    archive_path = destination / 'p0-source.zip'
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in source_paths():
            data = path.read_bytes()
            relative = path.relative_to(ROOT).as_posix()
            archive.writestr(relative, data)
            files.append({'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    manifest = {
        'schema': 1, 'captured_at_utc': datetime.now(timezone.utc).isoformat(),
        'head': git('rev-parse', 'HEAD'), 'branch': git('branch', '--show-current'),
        'status': git('status', '--short', '--untracked-files=normal').splitlines(),
        'host': {'platform': platform.platform(), 'processor': platform.processor()},
        'environments': {'application': versions(ROOT / '.venv/Scripts/python.exe'),
                         'worker': versions(ROOT / 'ops/agent_probe/.venv/Scripts/python.exe')},
        'files': files, 'archive_sha256': hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        'configuration': {'synthetic': True, 'provider_network': 'httpx.MockTransport only',
                          'selection': 'legacy unless fixture explicitly selects quick/reasoned',
                          'work_profiles': 'fixture-specific, recorded in test assertions',
                          'effective_options': 'captured by existing SDK HTTP boundary tests'},
        'excluded': ['.env', 'local_settings.py', 'private root PDFs', 'media', 'databases', 'private output', 'credentials'],
    }
    target.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'manifest': str(target), 'source_files': len(files), 'archive_sha256': manifest['archive_sha256']}))


if __name__ == '__main__':
    main()
