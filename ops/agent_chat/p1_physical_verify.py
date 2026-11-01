"""Offline physical checks: Linux bwrap and production runners, no E2B/provider."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/tmp/regulai-p1-physical-20261016')


def linux_main():
    assert BASE.resolve() == BASE and not BASE.is_symlink()
    assert (BASE / 'owner').read_text() == 'regulai-p1-physical-20261016'
    fixture = BASE / ('run-' + uuid.uuid4().hex)
    fixture.mkdir()
    for path in ('skills', 'workspace/input', 'workspace/work', 'workspace/output', 'tmp'):
        (fixture / path).mkdir(parents=True, exist_ok=True)
    source = ROOT / 'regulai/front/agents'
    for name in ('sandbox_runner.py', 'workspace_mutation.py', 'checkpoint_runner.py', 'document_program.py'):
        shutil.copyfile(source / name, fixture / 'skills' / name)
    shutil.copytree(source / 'runtime/skills/regulai-simulation', fixture / 'skills/regulai-simulation',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    template = source / 'runtime/templates/corporate.docx'
    if template.exists():
        shutil.copyfile(template, fixture / 'skills/corporate.docx')
    limits = {'command_seconds': 40, 'output_bytes': 200000, 'file_bytes': 20000000,
              'memory_mb': 1024, 'processes': 64, 'workspace_bytes': 512 * 1024 * 1024}
    outer = ['bwrap', '--unshare-all', '--die-with-parent', '--ro-bind', '/usr', '/usr',
             '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
             '--ro-bind', '/etc', '/etc', '--ro-bind', str(BASE / 'runtime'), '/usr/local',
             '--proc', '/proc', '--dev', '/dev', '--bind', str(fixture / 'tmp'), '/tmp',
             '--bind', str(fixture / 'workspace'), '/workspace', '--ro-bind', str(fixture / 'skills'), '/skills',
             '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin', '--setenv', 'SYNTHETIC_HOST_SECRET', 'must-not-reach-command']
    checks = []

    def execute(command, timeout=30):
        payload = base64.b64encode(json.dumps({'command': command, 'limits': limits, 'timeout': timeout}).encode()).decode()
        result = subprocess.run([*outer, '/usr/local/bin/python', '/skills/sandbox_runner.py', payload],
                                capture_output=True, text=True, timeout=timeout + 10)
        if result.returncode:
            raise AssertionError(result.stderr[-3000:])
        return json.loads(result.stdout)

    def expect(name, command, predicate=lambda value: value['exit_code'] == 0, timeout=30):
        result = execute(command, timeout)
        passed = bool(predicate(result))
        checks.append({'name': name, 'passed': passed, 'runner': result})
        if not passed:
            raise AssertionError(json.dumps(checks[-1]))
        return result

    def mutation(action, content, expected=None, path='/workspace/work/cas.txt'):
        value = {'action': action, 'path': path, 'content': base64.b64encode(content).decode(), 'limit': 200000}
        if expected:
            value['expected_sha256'] = expected
        encoded = base64.b64encode(json.dumps(value).encode()).decode()
        result = execute('python -I /skills/workspace_mutation.py ' + encoded)
        assert result['exit_code'] == 0, result
        return json.loads(result['stdout'])

    try:
        if '--documents-only' in sys.argv:
            (fixture / 'workspace/work/data.csv').write_text('item,amount_cents\nUno,1000\nDos,2000\nTres,3000\n')
            (fixture / 'workspace/work/fields.json').write_text(json.dumps({'title': 'Informe original', 'section': 'Sección que se conserva.'}))
            (fixture / 'workspace/work/edit.json').write_text(json.dumps({'field': 'title', 'value': 'Título editado'}))
            expect('document_build', 'python /skills/document_program.py build --source /workspace/work/data.csv --fields /workspace/work/fields.json --template /skills/corporate.docx --output /workspace/output/doc')
            expect('document_edit_title', 'python /skills/document_program.py edit --source /workspace/output/doc/final.docx --fields /workspace/work/edit.json --output /workspace/output/edited')
            compare = "from pathlib import Path; from zipfile import ZipFile; from docx import Document; a=Path('/workspace/output/doc/final.docx'); b=Path('/workspace/output/edited/final.docx'); za=ZipFile(a); zb=ZipFile(b); assert za.namelist()==zb.namelist(); changed=[n for n in za.namelist() if za.read(n)!=zb.read(n)]; assert changed==['word/document.xml'],changed; da=Document(a); db=Document(b); pa=[p.text for p in da.paragraphs]; pb=[p.text for p in db.paragraphs]; assert sum(x!=y for x,y in zip(pa,pb))==1; assert 'Título editado' in '\\n'.join(pb); assert [[c.text for c in r.cells] for r in da.tables[0].rows]==[[c.text for c in r.cells] for r in db.tables[0].rows]; print('title changed; other paragraphs, tables and package members retained')"
            expect('document_edit_preserves_other_content', 'python -c ' + shlex.quote(compare))
            expect('document_render_all_pages', 'python /skills/document_program.py render --output /workspace/output/edited', timeout=40)
            expect('document_seal_reopens_docx_pdf_png', 'python /skills/document_program.py seal --output /workspace/output/edited')
            destination = ROOT / 'output/p1-20261016/physical/documents'
            destination.mkdir(parents=True, exist_ok=True)
            for name in ('final.docx', 'final.pdf', 'render.json', *[path.name for path in
                    sorted((fixture / 'workspace/output/edited').glob('page-*.png'))]):
                shutil.copyfile(fixture / 'workspace/output/edited' / name, destination / name)
            print(json.dumps({'kind': 'actual document engines in Linux production sandbox runner',
                'checks': checks, 'provider_calls': 0, 'e2b_calls': 0, 'microvm_verified': False,
                'document_program_sha256': hashlib.sha256((fixture / 'skills/document_program.py').read_bytes()).hexdigest(),
                'render_manifest': json.loads((destination / 'render.json').read_text())}))
            return
        if '--mutations-only' in sys.argv:
            first = mutation('create', b'base')
            assert first['succeeded']
            with ThreadPoolExecutor(max_workers=2) as pool:
                race = list(pool.map(lambda content: mutation('replace', content, first['sha256']), (b'one', b'two')))
            assert sorted(item['succeeded'] for item in race) == [False, True], race
            checks.append({'name': 'physical_cas_race', 'passed': True, 'results': race})
            (fixture / 'workspace/work/link').symlink_to('/workspace/work/cas.txt')
            (fixture / 'workspace/work/parent-link').symlink_to('/workspace/output', target_is_directory=True)
            for path in ('/workspace/work/link', '/workspace/work/parent-link/file',
                         '/workspace/work/.regulay-write-lock', '/workspace/work/.regulay-write-synthetic',
                         '/workspace/work/.mutation-synthetic'):
                denied = mutation('create', b'must-not-write', path=path)
                assert not denied['succeeded'], denied
                checks.append({'name': 'denied:' + path, 'passed': True, 'result': denied})
            print(json.dumps({'kind': 'actual Linux mutation helper after reserved-path fix',
                'checks': checks, 'provider_calls': 0, 'e2b_calls': 0,
                'workspace_mutation_sha256': hashlib.sha256((fixture / 'skills/workspace_mutation.py').read_bytes()).hexdigest()}))
            return
        isolation = "import os,socket; assert not os.path.exists('/mnt/c'); assert not os.path.exists('/var/run/docker.sock'); assert not os.path.exists('/etc/passwd'); assert not os.environ.get('SYNTHETIC_HOST_SECRET'); failures=[]\nfor host in ['127.0.0.1','169.254.169.254','1.1.1.1']:\n try: socket.create_connection((host,80),timeout=.2)\n except OSError: failures.append(host)\nassert len(failures)==3; print('isolated')"
        expect('namespace_network_environment_hidden', 'python -c ' + shlex.quote(isolation))
        expect('skills_mount_read_only', 'python -c ' + shlex.quote(
            "from pathlib import Path; p=Path('/skills/regulai-simulation/SKILL.md'); assert p.read_text(); p.write_text('tamper')"),
            lambda value: value['exit_code'] != 0 and 'Read-only file system' in value['stderr'])
        spec = {'dimensions': [2, 3], 'seed': 20261016, 'walkers': 2000, 'steps': 2000}
        (fixture / 'workspace/work/spec.json').write_text(json.dumps(spec))
        expect('simulation_run', 'python /skills/regulai-simulation/scripts/random_walk.py run --spec /workspace/work/spec.json --out /workspace/work/result.json')
        expect('simulation_check', 'python /skills/regulai-simulation/scripts/random_walk.py check /workspace/work/result.json')
        simulation = json.loads((fixture / 'workspace/work/result.json').read_text())
        assert [row['horizons'][0]['returned_walkers'] for row in simulation['results']] == [1401, 651]
        created = mutation('create', b'original')
        assert created['succeeded'], created
        first_hash = created['sha256']
        with ThreadPoolExecutor(max_workers=2) as pool:
            race = list(pool.map(lambda content: mutation('replace', content, first_hash), (b'first', b'second')))
        assert sorted(item['succeeded'] for item in race) == [False, True], race
        assert next(item for item in race if not item['succeeded'])['code'] == 'hash_conflict', race
        checks.append({'name': 'physical_compare_and_swap_race', 'passed': True, 'results': race})
        before = (fixture / 'workspace/work/cas.txt').read_bytes()
        exists = mutation('create', b'overwrite')
        assert exists['code'] == 'file_exists' and (fixture / 'workspace/work/cas.txt').read_bytes() == before
        checks.append({'name': 'exclusive_create_preserves_existing', 'passed': True, 'result': exists})
        (fixture / 'workspace/work/link.txt').symlink_to('/workspace/work/cas.txt')
        denied = mutation('replace', b'escape', path='/workspace/work/link.txt', expected=hashlib.sha256(before).hexdigest())
        assert not denied['succeeded'], denied
        (fixture / 'workspace/work/dirlink').symlink_to('/workspace/output', target_is_directory=True)
        component = mutation('create', b'escape', path='/workspace/work/dirlink/out.txt')
        assert not component['succeeded'], component
        assert not (fixture / 'workspace/output/out.txt').exists()
        assert (fixture / 'workspace/work/cas.txt').read_bytes() == before
        checks.append({'name': 'physical_symlinks_leaf_and_parent_denied', 'passed': True, 'results': [denied, component]})
        (fixture / 'workspace/work/link.txt').unlink()
        (fixture / 'workspace/work/dirlink').unlink()
        expect('output_is_bounded', 'python -c "print(\'x\'*300000)"', lambda value: value['truncated'])
        expect('timeout_kills_process_tree', "sh -c 'sleep 3; touch /workspace/output/late' & sleep 8",
               lambda value: value['timed_out'] and value['exit_code'] == 124, timeout=1)
        expect('no_late_child_effect', 'sleep 3; test ! -e /workspace/output/late')
        capture = expect('checkpoint_capture_compress', 'python /skills/checkpoint_runner.py save 536870912 20000000')
        capture_stats = json.loads(capture['stdout'])
        archive = fixture / 'workspace/work/.regulay-checkpoint.zip'
        started = time.monotonic()
        raw = archive.read_bytes()
        transfer_ms = (time.monotonic() - started) * 1000
        checks.append({'name': 'checkpoint_local_transfer', 'passed': True, 'bytes': len(raw),
                       'capture_and_compression_runner_ms': capture['duration_ms'],
                       'local_filesystem_read_ms': transfer_ms, 'server_transfer_ms': None,
                       'volume': capture_stats})
        report = {'kind': 'actual Linux namespaces and production subprocess runner',
                  'python': '3.12.11', 'numpy': '2.5.3', 'provider_calls': 0, 'e2b_calls': 0,
                  'microvm_verified': False, 'checks': checks, 'simulation': simulation,
                  'source_hashes': {name: hashlib.sha256((fixture / 'skills' / name).read_bytes()).hexdigest()
                    for name in ('sandbox_runner.py', 'workspace_mutation.py', 'checkpoint_runner.py')},
                  'limits': limits}
        print(json.dumps(report))
    except Exception:
        print(json.dumps({'status': 'failed', 'checks': checks, 'fixture': str(fixture)}))
        raise
    finally:
        assert fixture.resolve().parent == BASE and fixture.name.startswith('run-')
        shutil.rmtree(fixture)


def main():
    if '--linux' in sys.argv:
        linux_main()
        return
    path = Path(__file__).resolve()
    linux = '/mnt/' + path.drive[0].lower() + path.as_posix()[2:]
    output = ROOT / 'output/p1-20261016/physical'
    output.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(['rtk', 'proxy', 'wsl', '-d', 'Ubuntu', '--', 'python3', linux, '--linux', *sys.argv[1:]],
                            capture_output=True, text=True, encoding='utf-8')
    label = 'documents' if '--documents-only' in sys.argv else 'mutations' if '--mutations-only' in sys.argv else 'verification'
    (output / (label + '.log')).write_text(result.stderr, encoding='utf-8')
    (output / (label + '.json')).write_text(result.stdout, encoding='utf-8')
    print(json.dumps({'exit_code': result.returncode, 'report': str(output / (label + '.json'))}))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
