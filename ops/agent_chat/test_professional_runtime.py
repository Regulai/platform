"""Actual Linux namespaces/commands, installed SDK; no model or E2B API calls.

Run with the executor SDK environment on Windows + WSL. The E2B transport is
replaced by subprocesses; generated commands still use the production runner.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'regulai'))
from front.agents.workspace_backend import WorkspaceSandbox
from front.agents.adapter import build_agent
from langchain_core.messages import HumanMessage


class LinuxTransport:
    sandbox_id = 'actual-wsl-namespace-not-e2b'
    def __init__(self, root):
        self.root, self.commands, self.files = root, self, self
        self.linux = '/mnt/' + root.drive[0].lower() + root.as_posix()[2:]
        self.runtime = os.environ.get('REGULAY_TEST_RUNTIME', '/tmp/regulay-task56-20261014/runtime')
        for name in ('input', 'work', 'output'):
            (root / 'workspace' / name).mkdir(parents=True)
        (root / 'skills').mkdir()
        (root / 'tmp').mkdir()
        for name in ('sandbox_runner.py', 'checkpoint_runner.py', 'browser_runner.py', 'artifact_render.py', 'workspace_mutation.py'):
            (root / 'skills' / name).write_bytes((REPO / 'regulai/front/agents' / name).read_bytes())
        (root / 'skills/runtime-versions.txt').write_text('Actual WSL test: Python 3.12.13, Node 24.21.0; dependency hashes in repository')
        (root / 'skills/browser_chromium.sh').write_bytes((REPO / 'ops/agent_chat/browser_chromium.sh').read_bytes())
        (root / 'skills/chromium-path').write_text('/opt/ms-playwright/chromium-1248/chrome-linux64/chrome')

    def write(self, path, content, **kwargs):
        if not path.startswith('/tmp/regulay-browser-') or '..' in path:
            raise ValueError('Fixture inbox path denied')
        target = self.root / 'tmp' / path.removeprefix('/tmp/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)

    def run(self, command, *, timeout=30, **kwargs):
        script = self.root / 'skills/invoke.sh'
        script.write_text(command + '\n', encoding='utf-8', newline='\n')
        args = ['wsl', '-d', 'Ubuntu', '--', 'bwrap', '--unshare-all', '--die-with-parent',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/etc', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--bind', self.linux + '/tmp', '/tmp',
            '--ro-bind', os.environ.get('REGULAY_TEST_BROWSER_CACHE', '/home/javi/.cache/ms-playwright'), '/opt/ms-playwright',
            '--ro-bind', self.runtime, '/usr/local', '--bind', self.linux + '/workspace', '/workspace',
            '--ro-bind', self.linux + '/skills', '/skills', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
            '/bin/sh', '/skills/invoke.sh']
        if kwargs.get('on_stdout'):
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace') as process:
                lines, errors, stderr = [], [], []
                def reader():
                    try:
                        for line in process.stdout:
                            lines.append(line)
                            kwargs['on_stdout'](line)
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=reader)
                thread.start()
                def read_errors():
                    for line in process.stderr:
                        stderr.append(line)
                errthread = threading.Thread(target=read_errors)
                errthread.start()
                try:
                    process.wait(timeout=timeout + 5)
                except subprocess.TimeoutExpired as error:
                    raise RuntimeError('Browser fixture timeout. STDERR: ' + ''.join(stderr) + ' STDOUT: ' + ''.join(lines)) from error
                finally:
                    if process.poll() is None:
                        process.kill()
                    thread.join(timeout=5)
                    errthread.join(timeout=5)
                if errors:
                    raise errors[0]
                result = SimpleNamespace(returncode=process.returncode, stdout=''.join(lines), stderr=''.join(stderr))
        else:
            result = subprocess.run(args, capture_output=True, timeout=timeout + 5, encoding='utf-8', errors='replace')
        if result.returncode:
            raise RuntimeError(result.stderr[-7000:])
        return SimpleNamespace(stdout=result.stdout, stderr=result.stderr, exit_code=result.returncode)


class RealWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='regulay-task56-', dir=REPO / '.claude')
        def cleanup():
            # Linux symlinks on the shared NTFS checkout must be removed by
            # Linux. Verify this exact newly-created test root before removal.
            root = Path(self.temp.name).resolve()
            if root.parent != (REPO / '.claude').resolve() or not root.name.startswith('regulay-task56-'):
                raise ValueError('Unexpected test cleanup path')
            linux = '/mnt/' + root.drive[0].lower() + root.as_posix()[2:]
            subprocess.run(['wsl', '-d', 'Ubuntu', '--', 'python3', '-c',
                'import shutil,sys; shutil.rmtree(sys.argv[1])', linux], check=True)
            self.temp.cleanup()
        self.addCleanup(cleanup)
        self.transport = LinuxTransport(Path(self.temp.name))
        self.budget = {'command_seconds': 45, 'output_bytes': 200000, 'file_bytes': 20000000,
            'memory_mb': 1024, 'processes': 64, 'workspace_bytes': 512 * 1024 * 1024}
        self.backend = WorkspaceSandbox(sandbox=self.transport, limits=self.budget, lease=SimpleNamespace(check=lambda: None))

    def execute(self, command, **kwargs):
        return json.loads(self.backend.execute(command, **kwargs).output)

    def test_generated_python_error_repair_node_shell_and_native_file_tools(self):
        path = '/workspace/work/fresh.py'
        self.assertIsNone(self.backend.write(path, 'print(missing_name)\n').error)
        failed = self.execute('python fresh.py')
        self.assertNotEqual(failed['exit_code'], 0)
        self.assertIn('NameError', failed['stderr'])
        self.assertIsNone(self.backend.edit(path, 'missing_name', 'sum([7, 13, 22])').error)
        self.assertIn('42', self.execute('python fresh.py')['stdout'])
        node = self.execute("node -e 'console.log([7,13,22].reduce((a,b)=>a+b,0))'")
        self.assertEqual(node['exit_code'], 0, node)
        self.assertIn('42', node['stdout'])
        self.assertIn('fresh.py', str(self.backend.ls('/workspace/work')))
        self.assertIn('fresh.py', str(self.backend.glob('*.py', '/workspace/work')))
        self.assertIn('sum', str(self.backend.read(path)))
        self.assertIn('sum', str(self.backend.grep('sum', '/workspace/work')))

    def test_chunked_megabyte_transfer_and_symlink_escape(self):
        content = bytes(range(256)) * 4097
        path = '/workspace/work/subdir/data.bin'
        self.assertIsNone(self.backend.upload_files([(path, content)])[0].error)
        self.assertEqual(self.backend.download_files([path])[0].content, content)
        text_path = '/workspace/work/large.txt'
        text = ('0123456789' * 40000) + 'unique replacement marker'
        self.assertIsNone(self.backend.upload_files([(text_path, text.encode())])[0].error)
        self.assertIsNone(self.backend.edit(text_path, 'unique replacement marker', 'updated').error)
        self.assertEqual(self.backend._file(text_path), text.replace('unique replacement marker', 'updated').encode())
        self.execute('ln -s /etc/passwd /workspace/output/escape')
        self.assertIsNotNone(self.backend.download_files(['/workspace/output/escape'])[0].error)

    def test_network_host_secrets_output_timeout_and_child_cancellation(self):
        code = '''import os,socket
assert not os.path.exists('/mnt/c')
assert not os.path.exists('/var/run/docker.sock')
assert not os.path.exists('/etc/passwd')
assert not os.environ.get('SYNTHETIC_HOST_SECRET')
for host in ['127.0.0.1','169.254.169.254','1.1.1.1']:
 try: socket.create_connection((host,80),timeout=.2)
 except OSError: pass
 else: raise RuntimeError('network escape')
print('isolated')'''
        outcome = self.execute('python -c ' + shlex.quote(code))
        self.assertEqual(outcome['exit_code'], 0, outcome)
        self.assertTrue(self.execute("python -c \"print('x'*300000)\"")['truncated'])
        timeout = self.execute("sh -c 'sleep 3; touch /workspace/output/late' & sleep 10", timeout=1)
        self.assertTrue(timeout['timed_out'])
        self.assertEqual(self.execute('sleep 3; test ! -e /workspace/output/late')['exit_code'], 0)

    def test_real_deepagents_tool_result_error_repair_roundtrip(self):
        backend, observed = self.backend, []
        commands = ['python -c "print(unknown_value)"', 'python -c "print(sum([7,13,22]))"']
        class Boundary:
            def operation(self, name, payload):
                observed.append((name, payload))
                if name == 'inference':
                    index = sum(n == 'inference' for n, _ in observed) - 1
                    return {'status': 'completed', 'content': '' if index < 2 else '42',
                        'tool_calls': [{'id': 'command-' + str(index), 'name': 'execute', 'args': {'command': commands[index]}}] if index < 2 else []}
                if name == 'authorize-tool':
                    return {'status': 'authorized'}
                if name == 'tool-results':
                    return {'status': 'approved', 'output': payload['raw'].get('content', str(payload['raw'])) if isinstance(payload['raw'], dict) else payload['raw']}
                raise AssertionError(name)
        result = build_agent(backend, Boundary(), allowed_tools=['execute'],
            model_profile={'max_input_tokens': 200000, 'max_output_tokens': 8000}).invoke({'messages': [HumanMessage(content='Compute a fresh sum')]})
        self.assertEqual(result['messages'][-1].content, '42')
        inferences = [payload for name, payload in observed if name == 'inference']
        self.assertIn('NameError', json.dumps(inferences[1]))
        self.assertIn('42', json.dumps(inferences[2]))
        self.assertTrue(all(p['tools'] == ['execute'] for p in inferences))

    def test_new_registry_packages_install_offline_and_execute(self):
        directory = REPO / '.claude/task56-downloads'
        manifests = json.loads((directory / 'manifest.json').read_text())
        for group in manifests:
            for item in group['manifest']:
                raw = (directory / item['filename']).read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item['sha256'])
                self.assertIsNone(self.backend.upload_files([('/workspace/work/.packages/' + item['filename'], raw)])[0].error)
        requirements = 'humanize==4.13.0 --hash=sha256:' + manifests[0]['manifest'][0]['sha256']
        self.backend.upload_files([('/workspace/work/.packages/requirements.lock', requirements.encode())])
        installed = self.execute('python -m venv --system-site-packages /workspace/work/.venv && '
            '/workspace/work/.venv/bin/python -m pip install --no-index --no-deps --require-hashes '
            '--find-links /workspace/work/.packages -r /workspace/work/.packages/requirements.lock && '
            '/workspace/work/.venv/bin/python -m pip check')
        self.assertEqual(installed['exit_code'], 0, installed)
        self.assertIn('1.2 million', self.execute('python -c "import humanize; print(humanize.intword(1200000))"')['stdout'])
        npm = self.execute('npm cache add --offline --ignore-scripts /workspace/work/.packages/is-number-7.0.0.tgz && '
            'npm install --offline --ignore-scripts --no-audit --no-fund --prefix /workspace/work /workspace/work/.packages/is-number-7.0.0.tgz && '
            'node -e "console.log(require(\'is-number\')(42))"')
        if npm['exit_code']:
            npm['install_log'] = self.execute('tail -80 /workspace/work/.home/.npm/_logs/*debug*')['stdout']
        self.assertEqual(npm['exit_code'], 0, npm)
        self.assertIn('true', npm['stdout'])

    def test_checkpoint_restores_actual_files_into_a_new_namespace(self):
        self.backend.write('/workspace/work/saved.py', 'print(42)')
        self.assertEqual(self.execute('mkdir -p env/bin env/lib/empty && '
            'ln -s /usr/local/bin/python env/bin/python && ln -s lib env/lib64')['exit_code'], 0)
        saved = self.execute('python -I /skills/checkpoint_runner.py save 100000000')
        self.assertEqual(saved['exit_code'], 0, saved)
        archive = self.backend.download_files(['/workspace/work/.regulay-checkpoint.zip'])[0].content
        other = WorkspaceSandbox(sandbox=LinuxTransport(Path(self.temp.name) / 'second'), limits=self.budget,
            lease=SimpleNamespace(check=lambda: None))
        self.assertIsNone(other.upload_files([('/workspace/work/.regulay-checkpoint.zip', archive)])[0].error)
        restored = json.loads(other.execute('python -I /skills/checkpoint_runner.py restore 100000000 && '
            'env/bin/python saved.py && test -d env/lib64/empty').output)
        self.assertEqual(restored['exit_code'], 0, restored)
        self.assertIn('42', restored['stdout'])

    def test_documents_render_edit_and_preserve_other_parts(self):
        import zipfile
        import io
        self.backend.upload_files([('/workspace/work/dataset.csv', b'region,load_mwh\nNorth,12\nSouth,18\nEast,24\n'),
            ('/workspace/work/new_program.py', (REPO / 'ops/agent_chat/professional_fixture.py').read_bytes())])
        result = self.execute('python new_program.py')
        self.assertEqual(result['exit_code'], 0, result)
        self.assertIn('54', result['stdout'])
        evidence = REPO / 'output/p0-e1-e8-20261016/namespace/artifacts'
        evidence.mkdir(parents=True, exist_ok=True)
        for name in ('quantum-v1.docx', 'quantum-v2.docx', 'analysis-v1.xlsx', 'analysis-v2.xlsx',
                'deck-v1.pptx', 'deck-v2.pptx', 'chart.png', 'analysis.json'):
            raw = self.backend._file('/workspace/output/' + name)
            (evidence / name).write_bytes(raw)
        for kind, part in [('docx', 'word/document.xml'), ('xlsx', 'xl/worksheets/sheet2.xml'), ('pptx', 'ppt/slides/slide2.xml')]:
            prefix = {'docx': 'quantum', 'xlsx': 'analysis', 'pptx': 'deck'}[kind]
            with zipfile.ZipFile(evidence / (prefix + '-v1.' + kind)) as first, zipfile.ZipFile(evidence / (prefix + '-v2.' + kind)) as second:
                changed = [name for name in first.namelist() if first.read(name) != second.read(name)]
                self.assertEqual(changed, [part])
        for name, count in [('quantum-v1.docx', 5), ('quantum-v2.docx', 5), ('deck-v2.pptx', 2)]:
            target = '/workspace/output/render-' + name
            result = self.execute('python -I /skills/artifact_render.py /workspace/output/' + name + ' ' + target + ' 10')
            self.assertEqual(result['exit_code'], 0, result)
            rendered = json.loads(result['stdout'])
            self.assertEqual(rendered['pages'], count)
            rendered_files = [rendered['pdf_path'], *rendered['page_paths']]
            destination = evidence / ('render-' + name)
            destination.mkdir(exist_ok=True)
            for path in rendered_files:
                (destination / Path(path).name).write_bytes(self.backend._file(path))
            (destination / 'render.json').write_text(json.dumps(rendered))
            inspected = self.execute('python -c ' + shlex.quote('from pypdf import PdfReader; '
                + 'assert all(p.extract_text().strip() for p in PdfReader(' + repr(rendered['pdf_path']) + ').pages)'))
            self.assertEqual(inspected['exit_code'], 0, inspected)

    def test_javascript_browser_loads_every_resource_through_broker(self):
        from front.agents.browser_worker import browse
        requests, submitted = [], []
        class Broker:
            def operation(self, name, payload):
                if name == 'run/browser-fetch':
                    requests.append(payload['url'])
                    body = (b'<html><h1 id="value">Waiting</h1><script>fetch("https://new.example/series").then(r=>r.json()).then(v=>document.getElementById("value").textContent=v.answer);new WebSocket("wss://data.example/socket");</script></html>'
                        if payload['url'].endswith('/page') else b'{"answer":"JavaScript rendered 42"}')
                    return {'status': 'completed', 'succeeded': True, 'url': payload['url'], 'final_url': payload['url'],
                        'media_type': 'text/html' if payload['url'].endswith('/page') else 'application/json',
                        'body': base64.b64encode(body).decode()}
                submitted.append(payload)
                return {'status': 'completed'}
        browse(Broker(), self.transport, SimpleNamespace(check=lambda: None),
            {'id': 'js-page', 'name': 'web_browse', 'args': {'url': 'https://new.example/page'}}, {'web_seconds': 10})
        self.assertIn('https://new.example/series', requests)
        self.assertIn('JavaScript rendered 42', submitted[0]['html'])
        self.assertFalse(any(url.startswith('wss:') for url in requests))
        self.assertIn('websocket_unavailable', submitted[0]['limitations'])


if __name__ == '__main__':
    unittest.main()
