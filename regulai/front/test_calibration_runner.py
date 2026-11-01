"""Admission limits of the single synthetic paid executor; no real transport."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

PATH = Path(__file__).resolve().parents[2] / 'scripts/run_calibration_campaign.py'
SPEC = importlib.util.spec_from_file_location('calibration_runner_under_test', PATH)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class CalibrationRunnerTests(SimpleTestCase):
    def test_transport_guard_rechecks_revocation_after_client_construction(self):
        from unittest.mock import Mock
        authorize = Mock(side_effect=ValueError('Authorization revoked'))
        guard = runner.make_guard({'campaign_frozen_files': {}}, [], authorize=authorize)
        body = {'model': 'deepseek-flash', 'max_tokens': 512, 'thinking': {'type': 'disabled'},
                'messages': [{'role': 'user', 'content': 'public'}]}
        with self.assertRaisesRegex(ValueError, 'revoked'):
            guard({'purpose': 'generation', 'body_utf8': json.dumps(body)})
        authorize.assert_called_once_with()

    def test_frozen_sample_resolves_only_reviewed_ids_and_provider_input(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory, patch.object(runner, 'CAMPAIGN', Path(directory)):
            corpus = Path(directory) / 'corpus'
            (corpus / 'development').mkdir(parents=True)
            selection = corpus / 'development/real_sample.json'
            selection.write_text(json.dumps({'smoke_case_ids': ['one']}))
            (corpus / 'manifest.json').write_text(json.dumps({'partitions': {
                'development': {'file': 'development/cases.jsonl'}}}))
            case = {'id': 'one', 'provider_reviewed': True, 'oracle': {'kind': 'exact', 'expected_answer': 'private-reference'}}
            api = SimpleNamespace(verify_integrity=lambda: {'ok': True}, load_partition=lambda split: [case],
                provider_input=lambda item: {'prompt': 'public-question', 'history': [], 'instructions': '',
                                            'documents': [{'text': 'public-document'}]})
            with patch.object(runner, 'module', return_value=api):
                sample, frozen = runner.reviewed_sample(selection, 'smoke')
                self.assertEqual(sample['cases'][0]['prompt'], 'public-question')
                self.assertEqual(sample['cases'][0]['document'], 'public-document')
                self.assertEqual(sample['cases'][0]['oracle'], case['oracle'])
                self.assertEqual(len(frozen), 4)
                case['provider_reviewed'] = False
                with self.assertRaisesRegex(ValueError, 'review'):
                    runner.reviewed_sample(selection, 'smoke')
                api.verify_integrity = lambda: {'ok': False}
                with self.assertRaisesRegex(ValueError, 'integrity'):
                    runner.reviewed_sample(selection, 'smoke')

    def test_boundary_rejects_unicode_escaped_sensitive_value_and_extra_generation(self):
        manifest = {'campaign_frozen_files': {}}
        guard = runner.make_guard(manifest, ['personañ@example.invalid'])
        body = {'model': 'deepseek-flash', 'max_tokens': 512, 'thinking': {'type': 'disabled'},
                'messages': [{'role': 'user', 'content': 'personañ@example.invalid'}]}
        with self.assertRaisesRegex(ValueError, 'sensitive'):
            guard({'purpose': 'generation', 'body_utf8': json.dumps(body, ensure_ascii=True)})
        body['messages'][0]['content'] = 'Dato público.'
        guard({'purpose': 'generation', 'body_utf8': json.dumps(body)})
        for key, value in (('max_tokens', 513), ('thinking', {'type': 'enabled'}), ('model', 'unapproved-model')):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'limit/options'):
                guard({'purpose': 'generation', 'body_utf8': json.dumps({**body, key: value})})
        body['messages'][0]['content'] = 'a' * 8001
        with self.assertRaisesRegex(ValueError, 'limit/options'):
            guard({'purpose': 'generation', 'body_utf8': json.dumps(body)})

    def test_complete_batch_must_fit_without_spending_confirmation_reserve(self):
        manifest = {'campaign_phase': 'development', 'maximum_additional_exposure_usd': '.308'}
        ledger = SimpleNamespace(snapshot=lambda: {'budget_exposure_usd': '.8'})
        with self.assertRaisesRegex(ValueError, 'confirmation'):
            runner.phase_check(ledger, manifest)
        ledger.snapshot = lambda: {'budget_exposure_usd': '.1'}
        runner.phase_check(ledger, manifest)

    def test_pinned_source_change_prevents_transport(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory, patch.object(runner, 'ROOT', Path(directory)):
            source = Path(directory) / 'source.py'
            source.write_text('approved')
            manifest = {'campaign_frozen_files': {'source.py': runner.sha(source)}}
            runner.frozen_check(manifest)
            source.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'changed'):
                runner.frozen_check(manifest)
