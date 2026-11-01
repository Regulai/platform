"""Offline activation guards. No Docker, PostgreSQL, providers or live services."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remote = load('p1_activation_remote')
local = load('p1_activate_local')


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as stream:
        for name, content in entries:
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(content), 0o644
            stream.addfile(entry, io.BytesIO(content))
    return output.getvalue()


class ActivationGuards(unittest.TestCase):
    def test_source_and_identity_boundaries(self):
        for path in ('regulai/front/agents/skills.py', 'ops/agent_chat/Dockerfile.executor',
                     'regulai/front/agents/runtime/skills/taste/scripts/draw.mjs'):
            self.assertTrue(local.safe_source(path))
        for path in ('/etc/passwd', '../secret', 'regulai/../outside', 'regulai/.env',
                     'regulai/regulai/local_settings.py', 'regulai/local.sqlite3',
                     'ops/agent_chat/.runtime/token', 'ops/setup/private/server.json'):
            self.assertFalse(local.safe_source(path))
        self.assertEqual(remote.checked_id('p1-20261016-activation'), 'p1-20261016-activation')
        with self.assertRaises(ValueError):
            remote.checked_id('../source')

    def test_manifest_exact_coverage_and_hashes_before_extract(self):
        content = b'value = 1\r\n'
        name = 'regulai/front/example.py'
        manifest = {'source_sha256': {name: hashlib.sha256(content).hexdigest()}}
        good = [(name, content), ('activation-manifest.json', json.dumps(manifest).encode())]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(remote.extract_candidate(root, archive(good)), manifest)
            self.assertEqual((root / 'source' / name).read_bytes(), content)
        cases = [good + [(name, content)], good + [('regulai/extra.py', b'unknown')],
                 good[:1], [(name, b'changed'), good[1]],
                 [('../outside.py', content), good[1]]]
        for entries in cases:
            with self.subTest(entries=[x[0] for x in entries]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises((RuntimeError, KeyError)):
                    remote.extract_candidate(root, archive(entries))
                self.assertFalse((root / 'source').exists())

    def test_archive_raw_limit_and_binary_identity(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(remote, 'MAX_ARCHIVE_BYTES', 5):
            with self.assertRaisesRegex(RuntimeError, 'source_archive_limit'):
                remote.extract_candidate(Path(directory), b'123456')
        self.assertNotEqual(local.normalized_hash('regulai/image.png', b'\r\n'),
                            local.normalized_hash('regulai/image.png', b'\n'))
        self.assertEqual(local.normalized_hash('ops/agent_chat/Dockerfile.executor', b'\r\n'),
                         local.normalized_hash('ops/agent_chat/Dockerfile.executor', b'\n'))

    def test_in_memory_loader_does_not_read_a_fake_file(self):
        with patch.dict(remote.__dict__, {'_ACTIVATION_SOURCE': 'trusted source', '__file__': '/missing'}):
            self.assertEqual(remote.module_source(), 'trusted source')

    def test_idle_gate_includes_pending_inferences_without_live_run(self):
        for field in ('live', 'active_calls', 'pending_inferences', 'provider_occupied', 'sandbox_occupied'):
            value = {'live': {}, 'active_calls': 0, 'pending_inferences': 0,
                     'provider_occupied': 0, 'sandbox_occupied': 0}
            value[field] = {'active': 1} if field == 'live' else 1
            with patch.object(remote, 'web_exec', return_value=value):
                with self.assertRaisesRegex(RuntimeError, 'live_or_uncertain_runs_present'):
                    remote.require_idle(current=True)

    def test_expired_terminal_markers_are_reported_without_reconciliation(self):
        value = {'live': {}, 'active_calls': 0, 'pending_inferences': 0,
                 'provider_occupied': 0, 'sandbox_occupied': 0,
                 'historical_terminal_markers_preserved': {'interrupted': 1}}
        with patch.object(remote, 'web_exec', return_value=value) as called:
            self.assertEqual(remote.require_idle(current=True), value)
        called.assert_called_once_with('metadata', current=True)

    def test_fingerprints_detect_money_row_or_sequence_changes(self):
        before = {'columns': {'front_prompt': ['id', 'decision']},
            'tables': {'front_prompt': {'count': 3, 'sha256': 'receipt-before'}},
            'sequences': {'front_prompt_id_seq': 3}}
        remote.equal_fingerprints(before, copy.deepcopy(before))
        for location in ('tables', 'sequences'):
            after = copy.deepcopy(before)
            after[location] = {}
            with self.assertRaisesRegex(RuntimeError, 'migration_changed_existing_data'):
                remote.equal_fingerprints(before, after)

    def test_replacement_preserves_configuration_and_changes_only_worker_mount(self):
        original = {'Config': {'Hostname': 'old-id', 'Env': ['PRIVATE=not-logged'], 'Image': 'old',
            'User': '1000:1000', 'Cmd': ['python', '-m', 'front.agents.worker'],
            'Labels': {'regulai.install': 'v2'}}, 'HostConfig': {'NetworkMode': 'regulai-v2-exec',
            'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'Memory': 1073741824,
            'Mounts': [{'Type': 'bind', 'Source': '/opt/regulai/worker', 'Target': '/run/task50', 'ReadOnly': True},
                       {'Type': 'bind', 'Source': '/opt/regulai/checkpoints', 'Target': '/state', 'ReadOnly': False}]}}
        frozen = copy.deepcopy(original)
        connection = SimpleNamespace(request=lambda *args, **kwargs: calls.append((args, kwargs)),
            getresponse=lambda: SimpleNamespace(status=201, read=lambda: b'{}'), close=lambda: None)
        calls = []
        with patch.object(remote, 'DockerConnection', return_value=connection), \
             patch.object(remote, 'ROOT', PurePosixPath('/opt/regulai')):
            remote.create_replacement('regulai-v2-worker', original, 'new-id', PurePosixPath('/opt/regulai/updates/p1-test-123'), worker=True)
        body = json.loads(calls[0][1]['body'])
        self.assertEqual(original, frozen)
        self.assertEqual(body['Env'], original['Config']['Env'])
        self.assertEqual(body['HostConfig']['NetworkMode'], 'regulai-v2-exec')
        self.assertTrue(body['HostConfig']['ReadonlyRootfs'])
        self.assertEqual(body['HostConfig']['Mounts'][0]['Source'], '/opt/regulai/updates/p1-test-123/worker')
        self.assertEqual(body['HostConfig']['Mounts'][1], original['HostConfig']['Mounts'][1])

    def test_partial_rollback_restores_original_when_replacement_is_absent(self):
        identity = 'p1-test-123'
        state = {'phase': 'migrated', 'images': {'web': 'new-web'}}
        originals = {name: {'Id': name + '-original', 'Image': 'old-web', 'State': {'Running': True}}
                     for name in remote.NAMES[:2]}
        calls = []
        def exists(args, **kwargs):
            return SimpleNamespace(returncode=0 if '-before-' in args[-1] else 1)
        def inspection(name):
            return originals[name.split('-before-')[0]]
        with patch.object(remote, 'read_json', side_effect=[state, originals]), \
             patch.object(remote.subprocess, 'run', side_effect=exists), \
             patch.object(remote, 'inspect', side_effect=inspection), \
             patch.object(remote, 'require_idle'), patch.object(remote, 'private_json'), \
             patch.object(remote, 'docker', side_effect=lambda *args: calls.append(args)):
            remote.rollback(identity)
        self.assertIn(('rename', 'regulai-v2-web-before-' + identity, 'regulai-v2-web'), calls)
        self.assertIn(('rename', 'regulai-v2-worker-before-' + identity, 'regulai-v2-worker'), calls)
        self.assertFalse(any(call[0] == 'stop' for call in calls))
        self.assertEqual(state['phase'], 'rolled_back_schema_retained')

    def test_partial_stop_can_restore_original_containers(self):
        state = {'phase': 'stopping', 'images': {'web': 'new-web'}}
        originals = {name: {'Id': name + '-original', 'Image': 'old-web', 'State': {'Running': True}}
                     for name in remote.NAMES[:2]}
        calls = []
        with patch.object(remote, 'read_json', side_effect=[state, originals]), \
             patch.object(remote.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), \
             patch.object(remote, 'inspect', side_effect=lambda name: originals[name]), \
             patch.object(remote, 'require_idle'), patch.object(remote, 'private_json'), \
             patch.object(remote, 'docker', side_effect=lambda *args: calls.append(args)):
            remote.rollback('p1-test-123')
        self.assertEqual(calls, [('start', name) for name in remote.NAMES[:2]])
        self.assertEqual(state['phase'], 'rolled_back_schema_retained')

    def test_started_services_must_remain_running_and_http_healthy(self):
        from unittest.mock import MagicMock
        response = MagicMock()
        response.__enter__.return_value.status = 200
        running = {'State': {'Running': True, 'ExitCode': 0}, 'RestartCount': 0}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(remote, 'inspect', return_value=running) as inspected, \
             patch.object(remote.urllib.request, 'urlopen', return_value=response) as http_get, \
             patch.object(remote.time, 'sleep') as sleeping:
            value = remote.verify_started_services(Path(directory))
        self.assertEqual(value['stable_seconds'], 10)
        self.assertEqual(inspected.call_count, 12)
        self.assertEqual(sleeping.call_count, 5)
        self.assertEqual(http_get.call_count, 6)
        self.assertTrue(all(call.args[0] == 'http://127.0.0.1:31058/static/js/skills.js'
                            for call in http_get.call_args_list))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(remote, 'inspect', return_value={'State': {'Running': False, 'ExitCode': 1}}), \
             patch.object(remote.subprocess, 'run'):
            with self.assertRaisesRegex(RuntimeError, 'candidate_service_exited_or_restarted'):
                remote.verify_started_services(Path(directory))


if __name__ == '__main__':
    unittest.main()
