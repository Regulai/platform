"""Guard regressions for the local web-only updater; no Docker/SSH operations."""
import hashlib
import unittest
from unittest.mock import Mock, patch

import p1_skills_ux_update as local
import p1_skills_ux_update_remote as remote
import p1_skills_ux_finish_update as coordinated


class WebOnlyGuardTests(unittest.TestCase):
    def test_oom_default_only_normalizes_none_to_false(self):
        self.assertEqual(coordinated.canonical_host({'OomKillDisable': None}),
                         coordinated.canonical_host({'OomKillDisable': False}))
        self.assertNotEqual(coordinated.canonical_host({'OomKillDisable': True}),
                            coordinated.canonical_host({'OomKillDisable': False}))
        for value in (0, 1, '', 'false'):
            with self.assertRaisesRegex(RuntimeError, 'invalid_oom'):
                coordinated.canonical_host({'OomKillDisable': value})
        with self.assertRaisesRegex(RuntimeError, 'missing_oom'):
            coordinated.canonical_host({})

    def test_ingress_guard_rejects_foreign_pid_command_and_active_clients(self):
        value = {'command': coordinated.TUNNEL_COMMAND, 'pid': coordinated.TUNNEL_PID,
            'connections': [{'address': '127.0.0.1', 'port': 8800, 'state': 'Listen', 'pid': coordinated.TUNNEL_PID}]}
        coordinated.validate_ingress(value)
        for changed in ({**value, 'pid': 99}, {**value, 'command': value['command'] + ' --unexpected'},
                        {**value, 'connections': value['connections'] + [{'state': 'Established'}]}):
            with self.assertRaisesRegex(RuntimeError, 'owned_idle_tunnel_required'):
                coordinated.validate_ingress(changed)
        coordinated.validate_ingress({**value, 'connections': value['connections'] + [{'state': 'Established'}]}, idle=False)

    def test_nonterminal_maintenance_cannot_reopen_ingress(self):
        with patch.multiple(coordinated, create=True, read=Mock(return_value={'phase': 'candidate_web_started'})):
            with self.assertRaisesRegex(RuntimeError, 'maintenance_result_not_terminal'):
                coordinated.terminal_check()

    def test_rename_gap_restores_exact_retained_original(self):
        state = {'container_ids': {coordinated.WEB: 'original'}, 'identities': {coordinated.WEB: 'hash'}}
        calls = Mock(); retained = {'Id': 'original'}
        with patch('subprocess.run', return_value=Mock(returncode=1)), patch.multiple(coordinated,
                create=True, docker=calls, named=Mock(return_value=retained),
                identity=Mock(return_value='hash'), ux={'IDENTITY': remote.IDENTITY}):
            coordinated.restore_original_web(state)
        self.assertEqual([call.args for call in calls.call_args_list],
                         [('rename', 'original', coordinated.WEB), ('start', 'original')])

    def test_mount_order_is_not_configuration_but_rw_change_is(self):
        mounts = [{'Destination': '/a', 'Source': '/source/a', 'RW': False},
                  {'Destination': '/b', 'Source': '/source/b', 'RW': True}]
        self.assertEqual(remote.canonical_mounts(mounts), remote.canonical_mounts(mounts[::-1]))
        changed = [{**mounts[0], 'RW': True}, mounts[1]]
        self.assertNotEqual(remote.canonical_mounts(mounts), remote.canonical_mounts(changed))
        with self.assertRaisesRegex(RuntimeError, 'duplicate_mount_destination'):
            remote.canonical_mounts([mounts[0], mounts[0]])

    def test_foreign_web_with_same_label_is_not_rolled_back(self):
        original = {'Id': 'original', 'Image': 'original-image'}
        foreign = {'Id': 'foreign', 'Config': {'Labels': {'regulai.skills_ux': remote.IDENTITY}}}
        calls = Mock()
        with patch.multiple(remote, create=True, read_json=Mock(return_value={remote.WEB: original}),
                inspect=Mock(return_value=foreign), docker=calls), patch('subprocess.run', return_value=Mock(returncode=0)):
            with self.assertRaisesRegex(RuntimeError, 'rollback_web_identity_mismatch'):
                remote.rollback({'candidate_id': 'our-candidate'})
        calls.assert_not_called()

    def test_changed_web_name_prevents_signal(self):
        calls = Mock()
        with patch.multiple(remote, create=True, inspect=Mock(return_value={'Id': 'concurrent-web'}), docker=calls):
            with self.assertRaisesRegex(RuntimeError, 'web_name_identity_changed'):
                remote.stop_gracefully('expected-web')
        calls.assert_not_called()

    def test_allowlist_excludes_runtime_secrets_migrations_and_workers(self):
        for path in ('regulai/front/agents/runtime/skills/design-taste-frontend/SKILL.md',
                     'regulai/front/migrations/0044_change.py', 'ops/agent_chat/start_worker.sh',
                     'regulai/regulai/settings.py', 'regulai/front/templates/../models.py',
                     'regulai/local_settings.py', 'regulai/static/js/secret.env'):
            self.assertFalse(local.allowed(path), path)
        self.assertTrue(local.allowed('regulai/static/js/skills.js'))
        self.assertTrue(local.allowed('regulai/front/agents/skill_views.py'))
        self.assertTrue(local.allowed('regulai/front/agents/runtime/skill_catalog.json'))

    def configured(self):
        helper = 'approved helper'
        request = {'helper': helper, 'source_sha256': 'source'}
        state = {'phase': 'prepared', 'updater_sha256': 'source',
                 'helper_sha256': hashlib.sha256(helper.encode()).hexdigest(),
                 'image': 'candidate', 'image_id': 'candidate-id', 'hashes': {'ui': 'new'},
                 'candidate_id': 'candidate-container',
                 'metadata': {'live': {}}, 'original_identity': {}}
        original = {'Image': 'original-id', 'Id': 'original-container'}
        fingerprint = {'tables': {'synthetic': {'count': 1, 'sha256': 'unchanged'}}}
        def read(path):
            return {'state.json': state, 'original-containers.json': {remote.WEB: original},
                    'before-source.json': {'ui': 'old'}}[path.name]
        mocks = {'REQUEST': request, 'read_json': Mock(side_effect=read),
                 'private_json': Mock(), 'gate': Mock(return_value=state['metadata']),
                 'stop_gracefully': Mock(), 'require_idle': Mock(),
                 'web_exec': Mock(return_value=fingerprint), 'docker': Mock(),
                 'create_web': Mock(), 'health': Mock(), 'source_manifest': Mock(return_value={'ui': 'new'}),
                 'current_web': Mock(return_value={'State': {'StartedAt': 'now'}}),
                 'equal_fingerprints': Mock(), 'inspect': Mock(), 'safe_container': Mock(return_value={}),
                 'rollback': Mock()}
        return state, mocks

    def test_active_run_gate_never_stops_the_web(self):
        state, mocks = self.configured()
        mocks['gate'].side_effect = RuntimeError('live_or_uncertain_runs_present')
        with patch.multiple(remote, create=True, **mocks):
            with self.assertRaisesRegex(RuntimeError, 'live_or_uncertain'):
                remote.apply()
        mocks['stop_gracefully'].assert_not_called()
        mocks['docker'].assert_not_called()
        mocks['rollback'].assert_not_called()
        self.assertEqual(state['phase'], 'prepared')

    def test_racing_run_aborts_before_rename_without_touching_worker(self):
        state, mocks = self.configured()
        mocks['require_idle'].side_effect = RuntimeError('live_or_uncertain_runs_present')
        with patch.multiple(remote, create=True, **mocks):
            with self.assertRaisesRegex(RuntimeError, 'live_or_uncertain'):
                remote.apply()
        mocks['stop_gracefully'].assert_called_once_with('original-container')
        mocks['docker'].assert_not_called()
        mocks['create_web'].assert_not_called()
        mocks['rollback'].assert_called_once_with(state)

    def test_changed_updater_or_helper_never_mutates(self):
        for field in ('updater_sha256', 'helper_sha256'):
            state, mocks = self.configured()
            state[field] = 'changed'
            with patch.multiple(remote, create=True, **mocks):
                with self.assertRaisesRegex(RuntimeError, 'same_prepared_updater_required'):
                    remote.apply()
            mocks['gate'].assert_not_called()
            mocks['stop_gracefully'].assert_not_called()

    def test_source_mismatch_after_start_uses_rollback(self):
        state, mocks = self.configured()
        mocks['source_manifest'].return_value = {'ui': 'unreviewed'}
        response = Mock()
        response.__enter__ = Mock(return_value=Mock(status=200))
        response.__exit__ = Mock(return_value=False)
        with patch.multiple(remote, create=True, **mocks), patch.object(remote.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(RuntimeError, 'unexpected_deployed_source_delta'):
                remote.apply()
        mocks['rollback'].assert_called_once_with(state)
        self.assertTrue(all(remote.WORKER not in call.args and remote.POSTGRES not in call.args
            for call in mocks['docker'].call_args_list))

    def test_success_only_stops_and_starts_web(self):
        state, mocks = self.configured()
        response = Mock()
        response.__enter__ = Mock(return_value=Mock(status=200))
        response.__exit__ = Mock(return_value=False)
        with patch.multiple(remote, create=True, **mocks), patch.object(remote.urllib.request, 'urlopen', return_value=response):
            result = remote.apply()
        self.assertEqual(result['phase'], 'applied')
        mocks['stop_gracefully'].assert_called_once_with('original-container')
        self.assertEqual([call.args for call in mocks['docker'].call_args_list], [
            ('rename', 'original-container', remote.WEB + '-before-' + remote.IDENTITY), ('start', 'candidate-container')])
        mocks['rollback'].assert_not_called()


if __name__ == '__main__':
    unittest.main()
