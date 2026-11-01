"""Prepare/apply an explicit, immutable web-only local UX update.

This does not build dependencies, touch worker/template, run migrations, install
skills, or send provider requests. Prepare does not change the running web.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

import p1_activate_local as activation

ROOT = activation.ROOT
OUT = ROOT / 'output/p1-skills-ux-20261016'
IDENTITY = 'p1-20261016-skills-ux-a1'
ALLOWED_PREFIXES = ('regulai/front/templates/', 'regulai/static/js/', 'regulai/static/css/')
ALLOWED_PYTHON = {'regulai/front/agents/skills.py', 'regulai/front/agents/skill_views.py',
    'regulai/front/chat_page.py', 'regulai/front/context_processors.py'}
ALLOWED_CATALOG = 'regulai/front/agents/runtime/skill_catalog.json'


def allowed(path):
    return activation.safe_source(path) and (path in ALLOWED_PYTHON or path == ALLOWED_CATALOG or
        path.startswith(ALLOWED_PREFIXES) and Path(path).suffix in {'.html', '.js', '.css'})


def bundle(reference, paths):
    commit = activation.git('rev-parse', '--verify', reference + '^{commit}').decode().strip()
    if not paths or len(set(paths)) != len(paths) or any(not allowed(path) for path in paths):
        raise RuntimeError('explicit_unique_ux_files_required')
    files = {path: activation.git('show', commit + ':' + path) for path in paths}
    if sum(map(len, files.values())) > 5 * 1024 * 1024:
        raise RuntimeError('ux_source_limit')
    for path, data in files.items():
        if data != (ROOT / path).read_bytes().replace(b'\r\n', b'\n'):
            raise RuntimeError('working_source_changed_since_commit:' + path)
    baseline = json.loads((OUT / 'initial-instance.json').read_text(encoding='utf-8'))
    return {'commit': commit, 'files': {path: base64.b64encode(data).decode()
        for path, data in files.items()}, 'hashes': {path: hashlib.sha256(data).hexdigest()
        for path, data in files.items()}, 'baseline': baseline}


def remote(action, payload=None):
    activation.owner_check()
    source = (ROOT / 'ops/agent_chat/p1_skills_ux_update_remote.py').read_text(encoding='utf-8')
    helper = (ROOT / 'ops/agent_chat/p1_activation_remote.py').read_text(encoding='utf-8')
    request = {'action': action, 'identity': IDENTITY, 'payload': payload,
        'helper': helper, 'source_sha256': hashlib.sha256(source.encode()).hexdigest()}
    loader = "import sys,json; request=json.loads(sys.stdin.buffer.readline()); source=sys.stdin.buffer.read().decode(); exec(compile(source,'ux_update.py','exec'),{'__name__':'__main__','REQUEST':request})"
    result = subprocess.run([*activation.SSH, 'sudo python3 -c ' + shlex.quote(loader)],
        input=json.dumps(request).encode() + b'\n' + source.encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if result.returncode:
        # Private config or tracebacks never leave the dedicated VM.
        raise RuntimeError('web_only_ux_' + action + '_failed:exit=' + str(result.returncode))
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'apply', 'rollback', 'inspect'))
    parser.add_argument('--source-ref')
    parser.add_argument('--file', action='append', default=[])
    args = parser.parse_args()
    if args.action == 'prepare' and not args.source_ref:
        parser.error('--source-ref is required for prepare')
    value = remote(args.action, bundle(args.source_ref, args.file) if args.action == 'prepare' else None)
    OUT.mkdir(exist_ok=True)
    (OUT / ('web-' + args.action + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    main()
