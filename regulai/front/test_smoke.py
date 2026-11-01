"""Exercise the real-mode harness through actual service/connectors and fake HTTP only."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx
import requests
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from . import evaluation
from .evaluation_budget import EvaluationBudget
from .models import Company


class SmokeHarness:
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.manifest_path = self.root / 'manifest.json'
        self.approval_path = self.root / 'approval.json'
        self.ledger_path = self.root / 'budget.sqlite3'
        self.enterContext(patch.object(evaluation, 'LEDGER_PATH', self.ledger_path))
        self.enterContext(patch.dict(os.environ, {'REGULAI_EVAL_GENERATOR_KEY': 'synthetic-key', 'REGULAI_EVAL_JEV_KEY': 'synthetic-key'}))
        source = evaluation.PILOT_MANIFEST.parent
        shutil.copyfile(source / 'rubric.md', self.root / 'rubric.md')
        self.manifest = evaluation.read_json(evaluation.PILOT_MANIFEST)
        self.manifest.update(masking={'backend': 'http'},
            destinations={**self.manifest['destinations'], 'mask': 'https://mask.testing.example'},
            mask_contract_review='Synthetic test transport only; no live approval', price_date=datetime.now(timezone.utc).date().isoformat(),
            source_sha256=evaluation.source_hashes(), runtime_versions=evaluation.runtime_versions())
        self.manifest['call_caps_usd']['obfuscation'] = '.01'
        self.case = next(json.loads(line) for line in (source / 'cases.jsonl').read_text(encoding='utf-8').splitlines()
                         if json.loads(line)['id'] == 'arithmetic')
        (self.root / 'cases.jsonl').write_text(json.dumps(self.case) + '\n', encoding='utf-8')
        self.manifest['dataset_sha256'] = evaluation.digest((self.root / 'cases.jsonl').read_bytes())
        self.manifest['human_rubric_sha256'] = evaluation.digest((self.root / 'rubric.md').read_bytes())
        self.approval = {'status': 'approved', 'approved_by': 'synthetic test fixture',
            'approval_reference': 'TEST ONLY; never a product authorization', 'authorization_id': self.manifest['authorization_id'],
            'valid_from': (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            'valid_until': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            'maximum_usd': '1.00', 'data_scope': 'versioned_synthetic_cases_only',
            'destinations': self.manifest['destinations'], 'pricing_reviewed_on': self.manifest['price_date'],
            'mask_contract_reviewed': True, 'mutable_alias_acknowledged': True, 'reserved_evaluation': True}
        self.approval['actions'] = self.manifest['actions']
        self.save_approval()
        self.events = []
        self.generation_payloads = []
        self.judge_payloads = []
        self.fault = None
        self.after_transport = None
        self.http = self.enterContext(patch('requests.sessions.Session.request', side_effect=self.requests_transport))
        self.sdk = self.enterContext(patch('httpx.Client.send', side_effect=self.sdk_transport))
        self.socket = self.enterContext(patch('socket.socket.connect', side_effect=AssertionError('Tests forbid network')))

    def save_approval(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding='utf-8')
        self.approval['manifest_sha256s'] = [evaluation.digest(self.manifest_path.read_bytes())]
        self.approval_path.write_text(json.dumps(self.approval), encoding='utf-8')

    def assert_reserved(self, purpose):
        with closing(sqlite3.connect(self.ledger_path)) as db:
            row = db.execute('SELECT purpose,status FROM calls ORDER BY rowid DESC LIMIT 1').fetchone()
        self.assertEqual(row, (purpose, 'started'))
        self.events.append(purpose)

    def requests_transport(self, method, url, **kwargs):
        if url == 'https://mask.testing.example/api/mask':
            self.assert_reserved('obfuscation')
            payload = {'masked': kwargs['json']['text']}
        else:
            self.assertEqual(url, 'https://api.typesafe.ai/v1/systemone')
            body = json.loads(kwargs['data'])
            self.judge_payloads.append(body)
            purpose = 'classification' if 'category' in body['questions'] else 'verification'
            self.assert_reserved(purpose)
            answers = {}
            for key, question in body['questions'].items():
                if question['type'] == 'choice':
                    chosen = {'category': 'public', 'task': 'general', 'difficulty': 'economy'}[key]
                    answers[key] = {'type': 'choice', 'choice': chosen, 'confidence': 1.0,
                                    'probabilities': {value: float(value == chosen) for value in question['criteria']}}
                else:
                    answers[key] = {'type': 'noul', 'noul': 0.0}
            payload = {'model': body['model'], 'answers': answers, 'usage': {'input_tokens': 50, 'output_tokens': 10}}
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        if self.fault == 'mask-http-error' and self.events[-1] == 'obfuscation':
            response.status_code = 503
        if self.fault == 'malformed-judge' and self.events[-1] == 'classification':
            response._content = b'{invalid-json'
        if self.after_transport:
            self.after_transport()
        return response

    def sdk_transport(self, request, **kwargs):
        self.assertEqual(str(request.url), 'https://api.deepseek.com/chat/completions')
        self.assert_reserved('generation')
        body = json.loads(request.content)
        self.generation_payloads.append(body)
        self.assertEqual(body['thinking'], {'type': 'disabled'})
        self.assertEqual(body['max_tokens'], 512)
        if self.fault == 'generation-timeout':
            raise httpx.ReadTimeout('Synthetic timeout', request=request)
        model = 'unapproved-new-model' if self.fault == 'model-drift' else body['model']
        return httpx.Response(200, request=request, json={'id': 'synthetic-response', 'object': 'chat.completion',
            'created': 1, 'model': model, 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': '4'}, 'finish_reason': 'stop'}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 1, 'total_tokens': 101}})

    def run_smoke(self, name='run', command='smoke_ai', **changes):
        options = {'manifest': str(self.manifest_path), 'authorization': str(self.approval_path),
                   'real': True, 'max_usd': '1.00', 'output': str(self.root / name), 'stdout': StringIO()}
        call_command(command, **{**options, **changes})

    def ledger(self):
        return EvaluationBudget(self.ledger_path, '1.00', authorization_id=self.approval['authorization_id'],
                                authorization_digest=evaluation.digest(self.approval)).snapshot()

    def use_local_mask(self):
        self.manifest['masking'] = evaluation.local_masking_manifest()
        self.manifest['destinations'].pop('mask')
        self.manifest.pop('mask_contract_review', None)
        self.manifest['call_caps_usd']['obfuscation'] = '0'
        self.approval['destinations'] = self.manifest['destinations']
        self.approval['masking'] = self.manifest['masking']
        self.save_approval()


class SmokeIsolationTests(SmokeHarness, TestCase):
    def test_local_detector_hides_original_at_both_http_boundaries_and_reserves_zero_api_cost(self):
        self.use_local_mask()
        original_email = 'evaluation.person@example.net'
        self.case['input'] = 'Devuelve 4. Correo de contacto: ' + original_email
        (self.root / 'cases.jsonl').write_text(json.dumps(self.case) + '\n', encoding='utf-8')
        self.manifest['dataset_sha256'] = evaluation.digest((self.root / 'cases.jsonl').read_bytes())
        self.save_approval()
        self.run_smoke('local')
        self.assertEqual(self.events.count('generation'), 3)
        self.assertEqual(self.events.count('classification'), 3)
        self.assertEqual(self.events.count('verification'), 3)
        self.assertNotIn('obfuscation', self.events)
        self.assertTrue(self.generation_payloads and self.judge_payloads)
        for payload in self.generation_payloads + self.judge_payloads:
            self.assertNotIn(original_email, json.dumps(payload))
        snapshot = self.ledger()
        local = [call for call in snapshot['calls'] if call['metadata']['transport'] == 'local']
        self.assertEqual(len(local), 6)
        for call in local:
            self.assertEqual((call['purpose'], call['reserved'], call['cost'], call['status']),
                             ('obfuscation', '0', '0', 'completed'))
            self.assertEqual(call['metadata']['cost_kind'], 'configured_zero')
            self.assertEqual(call['metadata']['cost_scope'], 'api')
        summaries = json.loads((self.root / 'local' / 'summary.json').read_text(encoding='utf-8'))
        aggregate = [row for row in summaries if row['split'] == 'all']
        self.assertEqual(sum(row['provider_calls'] for row in aggregate), 9)
        self.assertEqual(sum(row['local_transformations'] for row in aggregate), 6)
        self.assertTrue(all(row['calls_by_purpose']['obfuscation'] == 0 and row['local_api_cost_usd'] == '0' for row in aggregate))
        self.socket.assert_not_called()

    def test_failed_local_detector_has_zero_api_cost_and_no_external_fallback(self):
        self.use_local_mask()
        with patch('front.masking.mask_local_texts', side_effect=RuntimeError('Synthetic unavailable local model')):
            with self.assertRaises(CommandError):
                self.run_smoke('local-failed')
        snapshot = self.ledger()
        self.assertEqual(len(snapshot['calls']), 1)
        call = snapshot['calls'][0]
        self.assertEqual((call['reserved'], call['cost'], call['metadata']['transport'], call['metadata']['cost_kind']),
                         ('0', '0', 'local', 'configured_zero'))
        self.assertEqual(snapshot['budget_exposure_usd'], '0')
        self.http.assert_not_called()
        self.sdk.assert_not_called()
        self.socket.assert_not_called()

    def test_local_model_drift_or_missing_runtime_blocks_before_database_or_transport(self):
        self.use_local_mask()
        before = Company.objects.count()
        for result in ({**self.manifest['masking'], 'model_files_sha256': 'changed'}, RuntimeError('missing model')):
            with self.subTest(result=result), patch.object(evaluation, 'local_masking_manifest',
                    **({'side_effect': result} if isinstance(result, Exception) else {'return_value': result})):
                with self.assertRaises(CommandError):
                    self.run_smoke('local-drift')
        self.assertEqual(Company.objects.count(), before)
        self.assertFalse(self.ledger_path.exists())
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_unsettled_local_computation_keeps_unknown_outcome_but_known_zero_api_cost(self):
        self.use_local_mask()
        ledger = EvaluationBudget(self.ledger_path, '1.00')
        observer = evaluation.LedgerObserver(ledger, self.manifest, {'obfuscation': 'obfuscation:1'},
            case_id='synthetic-interruption', configuration='router')
        observer.before_call({'purpose': 'obfuscation', 'provider': 'obfuscation:1', 'model': None,
                              'transport': 'local', 'cost_bound': '0', 'cost_scope': 'api'})
        observer.finish()
        snapshot = ledger.snapshot()
        call = snapshot['calls'][0]
        self.assertEqual((call['status'], call['cost'], call['metadata']['cost_kind']),
                         ('outcome_unknown', '0', 'configured_zero'))
        self.assertEqual(snapshot['budget_exposure_usd'], '0')
        self.assertEqual(observer.stop_reason, 'unsettled_provider_call')
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_local_approval_revoked_during_reservation_preserves_sec1_before_detector(self):
        self.use_local_mask()
        reserve = EvaluationBudget.reserve
        def revoke_after_reserve(ledger, purpose, maximum, **kwargs):
            token = reserve(ledger, purpose, maximum, **kwargs)
            self.approval_path.write_text(json.dumps({**self.approval, 'status': 'revoked'}), encoding='utf-8')
            return token
        with patch.object(EvaluationBudget, 'reserve', revoke_after_reserve), patch('front.masking.mask_local_texts') as detector:
            with self.assertRaises(CommandError):
                self.run_smoke('local-revoked')
        call = self.ledger()['calls'][0]
        self.assertEqual((call['status'], call['cost'], call['metadata']['cost_kind']), ('not_started', '0', 'not_incurred'))
        detector.assert_not_called()
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_real_commands_share_ledger_and_reserve_all_transports(self):
        self.run_smoke()
        first = self.ledger()
        self.assertEqual(len(first['calls']), 15)
        self.assertEqual(set(self.events), {'obfuscation', 'classification', 'generation', 'verification'})
        self.run_smoke('evaluate', command='evaluate_ai')
        self.assertEqual(len(self.ledger()['calls']), 30)
        self.assertGreater(Decimal(self.ledger()['budget_exposure_usd']), Decimal(first['budget_exposure_usd']))
        self.assertFalse(self.ledger_path.with_suffix('.lock').exists())
        self.socket.assert_not_called()
        row = json.loads((self.root / 'run' / 'results.jsonl').read_text(encoding='utf-8').splitlines()[0])
        self.assertIsNone(row['human_review'])
        self.assertEqual(row['generation_responses'][0]['content'], '4')
        self.assertTrue(self.generation_payloads)
        self.assertEqual({body['temperature'] for body in self.generation_payloads},
                         {self.manifest['generation_options']['temperature']})

    def test_document_temperature_matches_the_frozen_manifest_at_sdk_transport(self):
        source = evaluation.PILOT_MANIFEST.parent
        self.case = next(json.loads(line) for line in (source / 'cases.jsonl').read_text(encoding='utf-8').splitlines()
                         if line.strip() and json.loads(line)['id'] == 'document-success')
        (self.root / 'cases.jsonl').write_text(json.dumps(self.case) + '\n', encoding='utf-8')
        self.manifest['dataset_sha256'] = evaluation.digest((self.root / 'cases.jsonl').read_bytes())
        self.save_approval()
        self.run_smoke()
        self.assertTrue(self.generation_payloads)
        options = self.manifest['generation_options']
        self.assertEqual({body['temperature'] for body in self.generation_payloads},
                         {options.get('document_temperature', options['temperature'])})
        self.socket.assert_not_called()

    def test_pending_or_expired_permission_has_no_database_or_network_effect(self):
        before = Company.objects.count()
        for status, until in [('pending', self.approval['valid_until']),
                              ('approved', (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())]:
            self.approval.update(status=status, valid_until=until)
            self.save_approval()
            with self.assertRaises(CommandError):
                self.run_smoke()
        self.assertEqual(Company.objects.count(), before)
        self.assertFalse(self.ledger_path.exists())
        self.assertFalse((self.root / 'run').exists())
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_existing_lock_is_preserved_before_any_database_write(self):
        lock = self.ledger_path.with_suffix('.lock')
        lock.write_text('Prior interrupted run', encoding='utf-8')
        before = Company.objects.count()
        with self.assertRaises(CommandError):
            self.run_smoke()
        self.assertEqual(Company.objects.count(), before)
        self.assertEqual(lock.read_text(encoding='utf-8'), 'Prior interrupted run')
        self.http.assert_not_called()
        self.assertFalse((self.root / 'run').exists())

    def test_authorization_revoked_during_mask_prevents_classifier(self):
        def revoke():
            changed = {**self.approval, 'status': 'revoked'}
            self.approval_path.write_text(json.dumps(changed), encoding='utf-8')
        self.after_transport = revoke
        with self.assertRaises(CommandError):
            self.run_smoke()
        self.assertEqual(self.events, ['obfuscation'])
        self.assertEqual(len(self.ledger()['calls']), 1)
        self.assertFalse(self.ledger_path.with_suffix('.lock').exists())
        self.assertTrue((self.root / 'run' / 'report.md').exists())

    def test_authorization_changed_during_reservation_prevents_each_transport(self):
        reserve = EvaluationBudget.reserve
        prefixes = {
            'obfuscation': [],
            'classification': ['obfuscation'],
            'generation': ['obfuscation', 'classification'],
            'verification': ['obfuscation', 'classification', 'generation', 'obfuscation'],
        }
        for change in ('revoked', 'expired'):
            for purpose, expected in prefixes.items():
                with self.subTest(change=change, purpose=purpose):
                    self.save_approval()
                    self.events = []
                    before = len(self.ledger()['calls']) if self.ledger_path.exists() else 0

                    def reserve_then_change(ledger, call_purpose, maximum, **kwargs):
                        token = reserve(ledger, call_purpose, maximum, **kwargs)
                        if call_purpose == purpose:
                            changed = {**self.approval}
                            if change == 'revoked':
                                changed['status'] = 'revoked'
                            else:
                                changed['valid_until'] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                            self.approval_path.write_text(json.dumps(changed), encoding='utf-8')
                        return token

                    with patch.object(EvaluationBudget, 'reserve', reserve_then_change):
                        with self.assertRaises(CommandError):
                            self.run_smoke(f'reserve-{change}-{purpose}')
                    self.assertEqual(self.events, expected)
                    calls = self.ledger()['calls'][before:]
                    self.assertEqual(len(calls), len(expected) + 1)
                    self.assertEqual(calls[-1]['purpose'], purpose)
                    self.assertEqual(calls[-1]['status'], 'not_started')
                    self.assertEqual(calls[-1]['cost'], '0')
                    self.assertEqual(calls[-1]['metadata']['cost_kind'], 'not_incurred')
                    self.assertGreater(Decimal(calls[-1]['reserved']), 0)
                    self.socket.assert_not_called()

    def test_failed_revocation_settlement_retains_unknown_reservation_without_transport(self):
        reserve, complete = EvaluationBudget.reserve, EvaluationBudget.complete

        def reserve_then_revoke(ledger, purpose, maximum, **kwargs):
            token = reserve(ledger, purpose, maximum, **kwargs)
            self.approval_path.write_text(json.dumps({**self.approval, 'status': 'revoked'}), encoding='utf-8')
            return token

        def fail_nonstarted_settlement(ledger, token, **kwargs):
            if kwargs.get('status') == 'not_started':
                raise sqlite3.OperationalError('Synthetic settlement failure')
            return complete(ledger, token, **kwargs)

        with patch.object(EvaluationBudget, 'reserve', reserve_then_revoke), \
                patch.object(EvaluationBudget, 'complete', fail_nonstarted_settlement):
            with self.assertRaises(CommandError):
                self.run_smoke('reserve-settlement-failure')
        snapshot = self.ledger()
        self.assertEqual(self.events, [])
        self.assertEqual(len(snapshot['calls']), 1)
        self.assertEqual(snapshot['calls'][0]['status'], 'outcome_unknown')
        self.assertIsNone(snapshot['calls'][0]['cost'])
        self.assertEqual(snapshot['uncertain_reservations_usd'], '0.01')
        self.socket.assert_not_called()

    def test_timeout_or_invalid_judge_retains_reservation_and_stops_without_retry(self):
        for fault, purposes in [('generation-timeout', ['obfuscation', 'classification', 'generation']),
                                 ('malformed-judge', ['obfuscation', 'classification'])]:
            with self.subTest(fault=fault):
                self.fault = fault
                self.events = []
                before = len(self.ledger()['calls']) if self.ledger_path.exists() else 0
                with self.assertRaises(CommandError):
                    self.run_smoke(fault)
                self.assertEqual(self.events, purposes)
                snapshot = self.ledger()
                self.assertEqual(len(snapshot['calls']) - before, len(purposes))
                self.assertIsNone(snapshot['calls'][-1]['cost'])
                self.assertNotEqual(snapshot['calls'][-1]['status'], 'started')
                self.assertGreater(Decimal(snapshot['uncertain_reservations_usd']), 0)

    def test_mask_http_error_stops_before_jev_and_keeps_unknown_cost(self):
        self.fault = 'mask-http-error'
        with self.assertRaises(CommandError):
            self.run_smoke()
        self.assertEqual(self.events, ['obfuscation'])
        self.assertEqual(self.ledger()['uncertain_reservations_usd'], '0.01')

    def test_effective_model_drift_stops_before_further_egress(self):
        self.fault = 'model-drift'
        with self.assertRaises(CommandError):
            self.run_smoke()
        self.assertEqual(self.events, ['obfuscation', 'classification', 'generation'])
        self.assertEqual(self.ledger()['calls'][-1]['metadata']['model_effective'], 'unapproved-new-model')

    def test_restart_cannot_spend_unknown_previous_reservations(self):
        ledger = EvaluationBudget(self.ledger_path, '1.00', authorization_id=self.approval['authorization_id'],
                                  authorization_digest=evaluation.digest(self.approval))
        ledger.reserve('previous_interrupted_call', '.99')
        with self.assertRaises(CommandError):
            self.run_smoke()
        self.assertEqual(self.events, ['obfuscation'])
        self.assertEqual(self.ledger()['budget_exposure_usd'], '1.00')
        self.sdk.assert_not_called()
