"""Real document SDK worker with a disposable local bwrap transport, not E2B."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'regulai')]
from front.agents.adapter import InternalClient
from front.agents.worker import run_job

config = json.loads(sys.stdin.read())
runtime = '/tmp/regulai-p1-documental-20261016/runtime'
temp = tempfile.TemporaryDirectory(prefix='p1-documental-', dir=ROOT / 'output/p1-20261016/physical')
folder = Path(temp.name).resolve()
assert folder.parent == (ROOT / 'output/p1-20261016/physical').resolve()
linux = '/mnt/' + folder.drive[0].lower() + folder.as_posix()[2:]
events = []
allocations = 0
limits = {'command_seconds': 90, 'output_bytes': 200000, 'file_bytes': 20000000,
          'memory_mb': 1024, 'processes': 64, 'workspace_bytes': 536870912}


class Transport:
    sandbox_id = 'p1-documental-bwrap-not-e2b'
    input_ready = False
    def __init__(self):
        self.commands = self.files = self
        for name in ('skills', 'workspace/input', 'workspace/work', 'workspace/output', 'tmp'):
            (folder / name).mkdir(parents=True, exist_ok=True)
        source = ROOT / 'regulai/front/agents'
        for name in ('sandbox_runner.py', 'document_program.py', 'spreadsheet_program.py',
                     'presentation_program.py', 'narrative_program.py'):
            shutil.copyfile(source / name, folder / 'skills' / name)
        for name in ('corporate.docx', 'corporate.pptx'):
            shutil.copyfile(source / 'runtime/templates' / name, folder / 'skills' / name)

    def path(self, value):
        if not value.startswith('/workspace/') or '..' in value.split('/'):
            raise ValueError('Only the fixture workspace is accessible')
        result = folder / value.lstrip('/')
        if not result.resolve().is_relative_to(folder):
            raise ValueError('Fixture path escape')
        return result

    def write(self, path, content, **kwargs):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.input_ready and path.startswith('/workspace/input/'):
            raise PermissionError('Input is read-only after preparation')
        target.write_bytes(content.encode() if isinstance(content, str) else content)

    def get_info(self, path):
        import e2b
        target = self.path(path)
        if not target.exists():
            raise e2b.FileNotFoundException(path)
        return SimpleNamespace(type=e2b.FileType.DIR if target.is_dir() else e2b.FileType.FILE)

    def read(self, path, **kwargs):
        return self.path(path).read_bytes()

    def run(self, command, *, timeout=90, **kwargs):
        if kwargs.get('user') == 'root':
            assert command.endswith('mount -o remount,bind,ro /workspace/input'), command
            self.input_ready = True
            # Every following command gets the actual read-only bind below.
            events.append({'event': 'input_readonly'})
            return SimpleNamespace(stdout='', stderr='', exit_code=0)
        payload = base64.b64encode(json.dumps({'command': command, 'limits': limits,
            'timeout': min(timeout, 90)}).encode()).decode()
        args = ['rtk', 'proxy', 'wsl', '-d', 'Ubuntu', '--', 'bwrap', '--unshare-all', '--die-with-parent',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/etc', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--ro-bind', runtime, '/usr/local', '--bind', linux + '/tmp', '/tmp',
            '--bind', linux + '/workspace', '/workspace', '--ro-bind', linux + '/skills', '/skills',
            '--ro-bind', linux + '/workspace/input', '/workspace/input',
            '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
            '/usr/local/bin/python', '/skills/sandbox_runner.py', payload]
        process = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', timeout=timeout + 15)
        if process.returncode:
            raise RuntimeError(process.stderr[-2000:])
        value = json.loads(process.stdout)
        events.append({'event': 'command', 'sha256': hashlib.sha256(command.encode()).hexdigest(),
            'exit_code': value['exit_code'], 'timed_out': value['timed_out'],
            'stderr': value['stderr'][-1500:] if value['exit_code'] else ''})
        return SimpleNamespace(stdout=value['stdout'], stderr=value['stderr'], exit_code=value['exit_code'])

    def set_timeout(self, value):
        pass

    def kill(self):
        pass


class ObservedInternal(InternalClient):
    def operation(self, name, payload):
        result = super().operation(name, payload)
        events.append({'event': name, 'call': payload.get('name'), 'status': result.get('status')})
        return result


internal = ObservedInternal(config['endpoint'], config['token'], config['attempt'])
def acquire(lease):
    global allocations
    allocations += 1
    assert allocations == 1
    assert any(event['event'] == 'authorize-tool' for event in events), events
    events.append({'event': 'acquire', 'count': allocations})
    return Transport()

try:
    result = run_job(internal, acquire=acquire)
    print(json.dumps({'result': result, 'sandbox_allocations': allocations, 'events': events,
        'provider': 'HTTP MockTransport in application', 'sandbox': 'actual Linux namespaces; E2B transport substitute',
        'microvm_verified': False, 'paid_calls': 0}))
except BaseException:
    print(json.dumps({'sandbox_allocations': allocations, 'events': events}), flush=True)
    raise
finally:
    internal.close()
    assert folder.is_relative_to((ROOT / 'output/p1-20261016/physical').resolve())
    temp.cleanup()
