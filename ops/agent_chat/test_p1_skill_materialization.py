"""Real Linux mount regression; opt in with --docker (no network or cloud VM)."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'regulai'))
from front.agents.skill_backend import SkillBackend


class Resources:
    def __init__(self):
        self.files = {'design': {'SKILL.md': b'Design instructions',
            'scripts/run.py': b'print("skill executed")\n', 'assets/data.bin': b'\x00\xff\x80\x01'},
            'second': {'SKILL.md': b'Second instructions'}}
        self.catalog = [{'alias': alias, 'installation_id': str(uuid.uuid4()),
            'revision_id': str(uuid.uuid4()), 'manifest': [{'path': path,
                'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for path, raw in files.items()]} for alias, files in self.files.items()]
        self.snapshot = {'digest': 'synthetic', 'catalog': self.catalog}
        self.calls = []

    def operation(self, name, payload):
        self.calls.append(name)
        if name == 'run/skills':
            return self.snapshot
        result = []
        for requested in payload['files']:
            _, _, alias, relative = requested['path'].split('/', 3)
            raw = self.files[alias][relative]
            result.append({'path': requested['path'], 'base64': base64.b64encode(raw).decode(),
                'sha256': hashlib.sha256(raw).hexdigest()})
        return {'files': result}


def docker(*args, check=True, input=None):
    try:
        return subprocess.run(['rtk', 'proxy', 'docker', *args], check=check, input=input,
            capture_output=True, text=True, encoding='utf-8', timeout=30)
    except subprocess.CalledProcessError as error:
        error.add_note(error.stderr)
        raise


class LinuxSandbox:
    """SDK-shaped adapter; commands and files really cross the container boundary."""
    def __init__(self):
        self.name = 'regulai-p1-skill-mount-' + uuid.uuid4().hex
        docker('run', '--pull=never', '--rm', '-d', '--network', 'none',
            '--cap-add', 'SYS_ADMIN', '--security-opt', 'apparmor=unconfined',
            '--label', 'regulai.p1-skill-mount=test', '--name', self.name,
            'python:3.12.11-slim', 'sleep', '600')
        self.commands = SimpleNamespace(run=self.run)
        self.files = SimpleNamespace(write=self.write)
        self.fail_write = False
        self.fail_publish = False
        self.fail_after_publish = False
        self.fail_view_after_publish = False
        self.fail_cleanup = False
        self.root_commands = []
        self.run('mkdir -p /skills; printf trusted-runtime > /skills/runtime.py; touch /skills/reserved; '
            'chmod -R a-w /skills; mount --bind /skills /skills; '
            'mount -o remount,bind,ro /skills', user='root', timeout=10)

    def run(self, command, *, user='root', timeout=10):
        if user == 'root':
            self.root_commands.append(command)
        publish = 'mount --bind ' in command and command.rstrip().endswith(' /skills/design')
        if publish and self.fail_publish:
            self.fail_publish = False
            raise RuntimeError('Injected publication failure')
        if self.fail_cleanup and 'umount --' in command:
            raise RuntimeError('Injected unmount failure')
        monitored = command + ' && python -c "import os; assert os.statvfs(\'/skills\').f_flag & os.ST_RDONLY"'
        result = docker('exec', '--user', '0' if user == 'root' else '1000:1000',
            self.name, 'sh', '-c', monitored)
        if publish and self.fail_after_publish:
            self.fail_after_publish = False
            raise RuntimeError('Injected lost publication acknowledgement')
        if self.fail_view_after_publish and command.endswith(' /skills'):
            self.fail_view_after_publish = False
            raise RuntimeError('Injected lost view acknowledgement')
        return SimpleNamespace(stdout=result.stdout, stderr=result.stderr, exit_code=result.returncode)

    def write(self, path, content, *, user):
        if self.fail_write:
            self.fail_write -= 1
            if not self.fail_write:
                raise RuntimeError('Injected transfer failure')
        code = 'import base64,pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(sys.stdin.buffer.read()))'
        docker('exec', '-i', '--user', '0', self.name, 'python', '-c', code, path,
            input=base64.b64encode(content).decode())

    def close(self):
        docker('rm', '--force', self.name)


class SkillMaterializationMountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('REGULAY_LOCAL_MOUNT_TEST') != '1':
            raise unittest.SkipTest('Opt-in Linux mount test: pass --docker; never creates a cloud VM')

    def setUp(self):
        self.internal = Resources()
        self.backend = SkillBackend(self.internal, self.internal.snapshot)
        self.sandbox = LinuxSandbox()
        self.addCleanup(self.sandbox.close)

    def materialize(self, alias='design'):
        self.backend.materialize({'name': 'execute', 'args': {'command':
            'python /skills/' + alias + '/scripts/run.py'}}, self.sandbox)

    def assert_read_only(self):
        code = '''import errno,os
for p in ['/skills/new', '/skills/design/new', '/skills/design/SKILL.md']:
 try: fd=os.open(p,os.O_WRONLY|os.O_CREAT,0o600)
 except OSError as e: assert e.errno in (errno.EROFS,errno.EACCES), (p,e)
 else: os.close(fd); raise AssertionError(p+' writable')
'''
        encoded = base64.b64encode(code.encode()).decode()
        for user in ('root', 'user'):
            self.sandbox.run("python -c \"import base64; exec(base64.b64decode('" + encoded + "'))\"", user=user)

    def test_just_in_time_publish_preserves_runtime_and_never_unseals_skills(self):
        self.materialize()
        self.assertEqual(self.sandbox.run('python /skills/design/scripts/run.py', user='user').stdout.strip(), 'skill executed')
        self.assertEqual(self.sandbox.run('cat /skills/runtime.py', user='user').stdout, 'trusted-runtime')
        self.sandbox.run('python -c "from pathlib import Path; '
            'assert Path(\'/skills/design/assets/data.bin\').read_bytes() == bytes([0,255,128,1])"', user='user')
        self.assert_read_only()
        self.sandbox.run('test ! -e /skills/second/SKILL.md; ! test -r /root/.regulay-skills-*', user='user')
        self.materialize('second')
        self.assertEqual(self.sandbox.run('cat /skills/second/SKILL.md', user='user').stdout, 'Second instructions')
        self.assert_read_only()
        count = len(self.sandbox.root_commands)
        self.materialize()
        self.assertEqual(count, len(self.sandbox.root_commands))
        self.assertEqual(len(self.backend.materialized), 2)
        self.assertFalse(any('remount,bind,rw' in command for command in self.sandbox.root_commands))
        self.assertEqual(sum('cp -a /skills/.' in command for command in self.sandbox.root_commands), 1)

    def test_root_assignment_uses_canonical_alias_boundary(self):
        for command in ('cat /skills/design-extra/SKILL.md', 'cat /else/skills/design/SKILL.md'):
            self.backend.materialize({'name': 'execute', 'args': {'command': command}}, self.sandbox)
        self.assertFalse(self.backend.materialized)
        self.assertNotIn('run/skill-resource', self.internal.calls)
        command = 'SKILL_ROOT=/skills/design; python "$SKILL_ROOT/scripts/run.py"'
        self.backend.materialize({'name': 'execute', 'args': {'command': command}}, self.sandbox)
        self.assertEqual(self.sandbox.run(command, user='user').stdout.strip(), 'skill executed')
        self.assertEqual(len(self.backend.materialized), 1)
        self.assert_read_only()

    def test_alias_cannot_replace_platform_file_and_private_view_is_cleaned(self):
        self.internal.catalog[0]['alias'] = 'reserved'
        self.internal.files['reserved'] = self.internal.files.pop('design')
        with self.assertRaises(subprocess.CalledProcessError):
            self.materialize('reserved')
        self.assertFalse(self.backend.materialized)
        self.assertIsNone(self.backend._skill_view)
        self.sandbox.run('test -f /skills/reserved; test -r /skills/runtime.py; '
            'test -z "$(find /root -maxdepth 1 -name .regulay-skills-\\* -print -quit)"')

    def test_lost_view_ack_restores_original_tree_and_cleans_stage(self):
        self.sandbox.fail_view_after_publish = True
        with self.assertRaisesRegex(RuntimeError, 'view acknowledgement'):
            self.materialize()
        self.assertFalse(self.backend.materialized)
        self.assertIsNone(self.backend._skill_view)
        self.sandbox.run('test ! -e /skills/design; test -r /skills/runtime.py; '
            'test -z "$(find /root -maxdepth 1 -name .regulay-skills-\\* -print -quit)"')
        self.materialize()
        self.assert_read_only()

    def test_failed_rollback_blocks_further_materialization_and_stays_read_only(self):
        self.sandbox.fail_after_publish = self.sandbox.fail_cleanup = True
        with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
            self.materialize()
        self.assertFalse(self.backend.materialized)
        self.assert_read_only()
        with self.assertRaisesRegex(RuntimeError, 'unavailable after mount cleanup failure'):
            self.materialize()

    def test_failed_transfer_cleans_private_bytes_and_can_retry(self):
        self.sandbox.fail_write = 2
        with self.assertRaisesRegex(RuntimeError, 'transfer'):
            self.materialize()
        self.assertFalse(self.backend.materialized)
        self.sandbox.run('test ! -e /skills/design/SKILL.md; '
            'test -z "$(find /root -path \"*/bundle-*/*\" -type f -print -quit)"')
        self.materialize()
        self.assert_read_only()

    def test_lost_publication_ack_rolls_back_only_our_mount_then_retries(self):
        self.sandbox.fail_after_publish = True
        with self.assertRaisesRegex(RuntimeError, 'acknowledgement'):
            self.materialize()
        self.assertFalse(self.backend.materialized)
        self.sandbox.run('test ! -e /skills/design/SKILL.md; test -r /skills/runtime.py; '
            'test -z "$(find /root -path \"*/bundle-*/*\" -type f -print -quit)"')
        self.materialize()
        self.assert_read_only()

    def test_failed_publication_is_not_materialized_and_can_retry(self):
        self.sandbox.fail_publish = True
        with self.assertRaisesRegex(RuntimeError, 'publication'):
            self.materialize()
        self.assertFalse(self.backend.materialized)
        self.sandbox.run('test ! -e /skills/design/SKILL.md; test -r /skills/runtime.py')
        self.materialize()
        self.assert_read_only()


class SkillMaterializationValidationTests(unittest.TestCase):
    def setUp(self):
        self.internal = Resources()
        self.backend = SkillBackend(self.internal, self.internal.snapshot)
        def no_workspace(*args, **kwargs):
            raise AssertionError('Unvalidated skill touched the workspace')
        self.sandbox = SimpleNamespace(commands=SimpleNamespace(run=no_workspace),
            files=SimpleNamespace(write=no_workspace))

    def invoke(self):
        self.backend.materialize({'name': 'execute', 'args': {
            'command': 'python /skills/design/scripts/run.py'}}, self.sandbox)

    def test_non_execute_operation_has_no_catalog_or_workspace_effect(self):
        self.backend.materialize({'name': 'read_file', 'args': {
            'file_path': '/skills/design/SKILL.md'}}, self.sandbox)
        self.assertEqual(self.internal.calls, [])

    def test_pinned_manifest_digest_is_checked_before_writing(self):
        self.internal.catalog[0]['manifest'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'materialization unavailable'):
            self.invoke()
        self.assertFalse(self.backend.materialized)

    def test_unsafe_aliases_and_manifest_paths_are_denied_before_writing(self):
        entry = self.internal.catalog[0]
        original = entry['alias']
        for alias in ('../escape', 'name;id', 'name/child', 'UPPER', 'x' * 65):
            entry['alias'] = alias
            with self.subTest(alias=alias), self.assertRaisesRegex(ValueError, 'alias denied'):
                self.invoke()
        entry['alias'] = original
        for path in ('../outside', '/absolute', 'scripts//run.py', 'scripts\\run.py', 'scripts/./run.py'):
            entry['manifest'][0]['path'] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'path denied'):
                self.invoke()
        self.assertNotIn('run/skill-resource', self.internal.calls)


if __name__ == '__main__':
    if '--docker' in sys.argv:
        sys.argv.remove('--docker')
        os.environ['REGULAY_LOCAL_MOUNT_TEST'] = '1'
    unittest.main()
