"""Prepare a review branch without changing the shared HEAD, index or worktree.

The prerequisite commit records safe frozen P0 sources, explicitly separate from
P1. Only the approved path inventory is overlaid. Run --prepare, review its diff,
then --commit. Never pushes, checks out, resets, stashes or deletes user files.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/e8'
BRANCH = 'refs/heads/codex/p1-skills-streaming-20261016'
BASE_HEAD = 'a16d03984c0a97f400e21093f81eda04a5222c2b'
ENV = {**os.environ, 'GIT_INDEX_FILE': str(OUT / 'p1-review.index')}


def git(*args, raw=None, env=ENV):
    result = subprocess.run(['rtk', 'proxy', 'git', *args], cwd=ROOT, env=env,
        input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8', errors='replace'))
    return result.stdout.decode('utf-8').strip()


def exact_bytes(path):
    return '/runtime/skills/' in path or Path(path).suffix.lower() in {'.log', '.zip', '.png', '.pdf', '.docx', '.xlsx', '.pptx'}


def content(path):
    raw = (ROOT / path).read_bytes()
    return raw if exact_bytes(path) else raw.replace(b'\r\n', b'\n')


def overlay(files):
    changes = []
    existing = {line.split('\t', 1)[1]: line.split()[0:3] for line in git('ls-files', '--stage').splitlines()}
    for path, raw in sorted(files.items()):
        if not exact_bytes(path):
            raw = raw.replace(b'\r\n', b'\n')
        oid = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        previous = existing.get(path)
        if previous and previous[1] == oid:
            continue
        mode = previous[0] if previous else '100644'
        written = git('hash-object', '-w', '--stdin', raw=raw)
        if written != oid:
            raise RuntimeError('blob_identity_changed')
        changes.append(f'{mode} {oid}\t{path}\n')
    if changes:
        git('update-index', '--index-info', raw=''.join(changes).encode())
    return git('write-tree')


def group(path):
    name = Path(path).name
    if path.startswith('output/p1-20261016/e1/'):
        return 1
    if path.startswith('output/'):
        return 8
    if path.startswith('docs/plan-blackhat/tareas/'):
        return int(name[:2]) - 67
    if name in {'p1_baseline_manifest.py','p1_baseline_run.py','p1_test.py','test_agent_p1_baseline.py',
                'plan-p1-skills-streaming-20261016.md'} or path.startswith('evals/corpora/p1-harness/'):
        return 1
    if ('/runtime/skills/' in path or name in {'skill_catalog.json','skill_bundles.py','skill_installation.py',
            'skill_sources.py','skills.py','records.py','models.py','event_store.py','0043_p1_skills_and_events.py',
            'requirements.txt','web-requirements.in','web-requirements.txt','test_agent_skills_install.py',
            'p1_vendor_sources.py'}):
        return 2
    if ('/templates/skills/' in path or name in {'skill_views.py','skills.js','chat.css','context_processors.py','nav_items.html'}):
        return 3
    if name in {'skill_backend.py','skill_context.py','adapter.py','worker.py',
            'data_views.py','protocol.py','request_contract.py','test_agent_skills_runtime.py','test_p1_skills_runtime.py'}:
        return 4
    if name in {'general_tools.py','workspace_mutation.py','workspace_backend.py','checkpoints.py','capabilities.py','professional_worker.py',
            'test_agent_tools_p1.py','test_p1_tools_runtime.py','test_p1_simulation.py','test_professional_runtime.py',
            'p1_physical_environment.py','p1_physical_verify.py','Dockerfile.executor','Dockerfile.spreadsheet'}:
        return 5
    if name in {'connectors.py','chat_streaming.py','service.py','streaming.py','purge_agent_data.py',
            'test_agent_streaming.py','test_chat_streaming.py','p1_sdk_compare.py'}:
        return 6
    if name in {'artifact_preview.py','agent-chat.js','chat.js','chat-markdown.js','artifact-viewer.js','artifacts.css','test_agent_preview.py','test_frontend_chat.py'}:
        return 7
    return 8  # Shared admission/routes and final evidence are wired after their modules exist.


def prepare():
    if git('rev-parse', 'HEAD') != BASE_HEAD or git('diff', '--cached', '--name-only', env=os.environ):
        raise RuntimeError('shared_head_or_index_changed_review_again')
    inventory = json.loads((OUT/'p1-paths-review.json').read_text(encoding='utf-8'))
    archive = ROOT/'output/p1-20261016/e1/p0-source.zip'
    if hashlib.sha256(archive.read_bytes()).hexdigest() != inventory['frozen_archive_sha256']:
        raise RuntimeError('frozen_source_changed')
    git('read-tree', BASE_HEAD)
    with zipfile.ZipFile(archive) as z:
        baseline = {p:z.read(p) for p in z.namelist() if p != 'ops/agent_chat/p1_baseline_manifest.py'}
    # This extensionless file was not in E1's source filter. Owners independently
    # confirmed these two lines are P1; the remaining dirty content belongs to P0.
    docker = 'ops/agent_chat/Dockerfile.executor'
    baseline[docker] = b'\n'.join(line for line in content(docker).split(b'\n')
        if b'COPY ' not in line or not any(name in line for name in (b'workspace_mutation.py', b'skill_backend.py')))
    base_tree = overlay(baseline)
    paths = {row['path'] for key in ('changed_since_frozen','new_p1_source_files') for row in inventory[key]}
    paths.update({'ops/agent_chat/p1_baseline_manifest.py', docker, 'ops/agent_chat/Dockerfile.spreadsheet',
        'docs/plan-blackhat/plan-p1-skills-streaming-20261016.md', 'regulai/front/test_frontend_chat.py'})
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'ops/agent_chat').glob('p1_*.py'))
    # Deliberate synthetic evidence only. Never sweep the output directory:
    # the UI session cookie, runtime tar, temporary indexes and private PDFs stay out.
    for folder, patterns in {
        'output/p1-20261016/e1': ['*.json', '*.log', 'report.md', 'p0-source.zip'],
        'output/p1-20261016/e4': ['*.log'],
        'output/p1-20261016/e5': ['*.json', '*.log', '*.md'],
        'output/p1-20261016/e8': ['acceptance.md', 'reproduction.md', 'runtime-review.md',
            'publication-review.md', 'cleanup.json',
            'security-report.md', 'visual-review.md', 'p1-paths-review.json', 'integration.log', 'final-focused.log',
            'browser-metrics.json', 'stream-browser-latency.json', 'accepted-browser-latency.json',
            'artifact-browser-latency*.json', 'sdk-comparison.json',
            'sdk-overhead.json', 'security-*.json', 'security-*.log'],
        'output/p1-20261016/physical': ['report.md', 'environment.json', 'verification.json',
            'mutations.json', 'documents.json', 'cleanup.json', 'Dockerfile', 'requirements.txt'],
        'output/p1-20261016/physical/documental': ['*.json', '*.log', '*.md'],
        'output/p1-20261016/physical/documental-runtime': ['environment.json', 'officecli.json',
            'build.log', 'Dockerfile', 'requirements.txt'],
        'output/playwright': ['p1-library-*.png', 'p1-chat-*.png', 'p1-preview-final-*.png',
            'p1-code-*.png', 'p1-manual-scroll-snapshot.png'],
        'output': ['p1-scroll-and-stream-regression-final.log', 'p1-scroll-final.log',
            'p1-counter-hydration.log', 'p1-final-snapshot-permissions.log',
            'p1-final-snapshot-revocation.log'],
    }.items():
        for pattern in patterns:
            paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/folder).glob(pattern))
    paths.add('output/p1-20261016/e6-e7-verification.md')
    documental = ROOT/'output/p1-20261016/physical/documental'
    if (documental/'results.json').exists():
        verified = json.loads((documental/'results.json').read_text(encoding='utf-8'))
        for case in verified['cases']:
            folder = (ROOT/case['folder']).resolve()
            if case['status'] != 'completed' or not folder.is_relative_to(documental.resolve()):
                raise RuntimeError('document_evidence_not_verified')
            for pattern in ('final.*', 'download.*', 'page-*.png', 'first-provider-messages.json',
                    'review.json', 'visual-approved.json', 'worker.log'):
                paths.update(p.relative_to(ROOT).as_posix() for p in folder.glob(pattern))
    titles = ['Freeze the effective P0 baseline for reproducible P1 checks',
        'Install complete account skills with immutable authorized revisions',
        'Add the skills library, package review and per-message selection',
        'Load canonical skill context lazily without starting a sandbox',
        'Make workspace mutations atomic and tool results reliable',
        'Stream authorized agent text with durable events and exact usage',
        'Render incremental replies and isolate static artifact previews',
        'Wire P1 admission and record integrated acceptance evidence']
    groups, manifests = [], []
    for number in range(1,9):
        selected = sorted(path for path in paths if group(path) == number)
        values = {path:content(path) for path in selected}
        tree = overlay(values)
        groups.append({'delivery':f'E{number}', 'title':titles[number-1], 'tree':tree, 'paths':selected})
        manifests.extend({'path':path,'sha256':hashlib.sha256(raw).hexdigest()} for path,raw in values.items())
    plan = {'base_head':BASE_HEAD,'branch':BRANCH,'prerequisite_tree':base_tree,'groups':groups,
        'normalized_source_manifest':sorted(manifests,key=lambda row:row['path']),
        'notes':['HEAD, shared index and worktree remain untouched.',
            'Prerequisite commit records existing safe P0 sources, not P1 work.',
            'Executor prerequisite reconstructed by ownership; not part of the E1 archive hash.',
            'Source text line endings normalized to LF; skill packages, raw logs and binary evidence preserve exact bytes.',
            'Only listed synthetic evidence is included; private PDFs, UI cookies and runtime archives are not swept into Git.']}
    (OUT/'commit-plan.json').write_text(json.dumps(plan,indent=2),encoding='utf-8')
    diff = git('diff', '--stat', base_tree, groups[-1]['tree'])
    (OUT/'review-diff.patch').write_text(git('diff', '--binary', base_tree, groups[-1]['tree'])+'\n',encoding='utf-8')
    print(diff)


def commit():
    plan = json.loads((OUT/'commit-plan.json').read_text(encoding='utf-8'))
    for row in plan['normalized_source_manifest']:
        if hashlib.sha256(content(row['path'])).hexdigest() != row['sha256']:
            raise RuntimeError('source_changed_since_review: '+row['path'])
    if git('rev-parse','HEAD') != BASE_HEAD or git('diff','--cached','--name-only',env=os.environ):
        raise RuntimeError('shared_head_or_index_changed')
    parent = git('commit-tree', plan['prerequisite_tree'], '-p', BASE_HEAD,
        raw=b'Record safe effective P0 prerequisites without changing the shared worktree\n')
    commits = [{'delivery':'prerequisite','commit':parent}]
    for entry in plan['groups']:
        parent = git('commit-tree',entry['tree'],'-p',parent,raw=(entry['title']+'\n').encode())
        commits.append({'delivery':entry['delivery'],'commit':parent,'title':entry['title']})
    # Creating a fresh ref only; a pre-existing branch fails instead of overwriting it.
    git('update-ref',BRANCH,parent,'0'*40)
    (OUT/'commits.json').write_text(json.dumps(commits,indent=2),encoding='utf-8')
    print(json.dumps({'branch':BRANCH,'commits':commits},indent=2))


if __name__ == '__main__':
    if sys.argv[1:] == ['--prepare']: prepare()
    elif sys.argv[1:] == ['--commit']: commit()
    else: raise SystemExit('Use --prepare, inspect output/p1-20261016/e8/review-diff.patch, then --commit')
