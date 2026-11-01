"""Host-side regression checks; no Docker, credentials or model calls needed."""
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[2] / 'setup.py')
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_stop_already_stopped_vm_does_not_attempt_ssh(self):
        with patch.object(sys, 'argv', ['setup.py', 'stop']), \
                patch.object(installer, 'doctor'), \
                patch.object(installer, 'inspect', return_value={'State': {'Running': False}}), \
                patch.object(installer, 'remote') as remote, \
                patch.object(installer, 'command') as command:
            installer.main()
        remote.assert_not_called()
        command.assert_not_called()

    def test_status_displays_running_services_in_terminal(self):
        with patch.object(sys, 'argv', ['setup.py', 'status']), \
                patch.object(installer, 'doctor'), \
                patch.object(installer, 'inspect', return_value={'State': {'Running': True}}), \
                patch.object(installer, 'remote') as remote, \
                patch.object(installer, 'command') as command:
            installer.main()
        remote.assert_not_called()
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0][:len(installer.SSH)], installer.SSH)
        self.assertIn('docker ps', command.call_args.args[0][-1])
        self.assertFalse(command.call_args.kwargs.get('capture', False))

    def test_bundle_excludes_secrets_and_database(self):
        with tempfile.TemporaryDirectory(prefix='RegulAI path with spaces ') as directory:
            root = Path(directory)
            for relative in ('regulai/regulai/settings.py', 'regulai/regulai/local_settings.py',
                             'regulai/db.sqlite3', 'regulai/media/upload.txt',
                             'ops/agent_chat/.runtime/config.json', 'ops/setup/server.py',
                             'ops/setup/regulai-private.json', '.dockerignore'):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('sensitive' if 'private' in relative else 'test')
            destination = root / 'source.tar.gz'
            with patch.object(installer, 'ROOT', root):
                installer.bundle(destination)
            with tarfile.open(destination) as archive:
                self.assertEqual(set(archive.getnames()), {
                    'regulai/regulai/settings.py', 'ops/setup/server.py', '.dockerignore'})

    def test_refuses_unowned_container(self):
        result = type('Result', (), {'returncode': 0, 'stdout': b'[{"Config":{"Labels":{}}}]'})()
        with patch.object(installer, 'command', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'another installation'):
                installer.inspect('container', 'regulai-v2-vm')

    def test_invalid_profile_never_starts_vm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private.json'
            path.write_text('{"format":"demo","objects":[]}')
            with patch.object(installer, 'boot') as boot:
                with self.assertRaisesRegex(RuntimeError, 'Invalid private profile'):
                    installer.install(path)
                boot.assert_not_called()


if __name__ == '__main__':
    unittest.main()
