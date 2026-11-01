"""Explicit new data scope must share the old budget and cannot replay a run."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from . import evaluation
from .evaluation_budget import BudgetExceeded, EvaluationBudget
from .test_smoke import SmokeHarness


class ApprovalExtensionBudgetTests(SimpleTestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'shared.sqlite3'
        self.old = EvaluationBudget(self.path, '1', authorization_id='old', authorization_digest='old-digest')
        token = self.old.reserve('generation', '.010858062')
        self.old.complete(token, cost='.0007', cost_kind='tariff_estimate')
        self.uncertain = self.old.reserve('classification', '.003')
        self.old.complete(self.uncertain, status='outcome_unknown')

    def extend(self, **overrides):
        args = dict(previous_id='old', previous_digest='old-digest', authorization_id='new',
            authorization_digest='new-digest', manifest_sha256='a' * 64,
            approval_reference='Synthetic test approval only', max_external_calls=44)
        args.update(overrides)
        return EvaluationBudget.extend_authorization(self.path, '1', **args)

    def fresh(self):
        return EvaluationBudget(self.path, '1', authorization_id='new', authorization_digest='new-digest')

    def test_explicit_extension_preserves_calls_cap_and_unknown_expense(self):
        before = self.old.snapshot()
        self.assertTrue(self.extend())
        current = self.fresh()
        self.assertEqual(current.snapshot(), before)
        self.assertEqual(before['budget_exposure_usd'], '0.013858062')
        self.assertEqual(before['uncertain_reservations_usd'], '0.003')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT * FROM approval').fetchall(), [('old', 'old-digest')])
        self.assertFalse(self.extend())  # Exact repetition is a no-op, never a new grant.
        self.assertEqual(current.snapshot(), before)

    def test_bad_parent_and_implicit_replacement_never_change_history(self):
        before = self.path.read_bytes()
        for overrides in ({'previous_id': 'other'}, {'previous_digest': 'file-bytes-instead-of-canonical'},
                          {'authorization_id': 'old'}, {'authorization_digest': 'old-digest'}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.extend(**overrides)
            self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            self.fresh()
        self.assertEqual(self.path.read_bytes(), before)

    def test_extension_cannot_create_a_missing_ledger_or_attach_anonymous_history(self):
        self.path = Path(self.temp.name) / 'missing.sqlite3'
        with self.assertRaises(ValueError):
            self.extend()
        self.assertFalse(self.path.exists())
        EvaluationBudget(self.path, '1').reserve('historical', '.01')
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.extend()
        self.assertEqual(self.path.read_bytes(), before)

    def test_old_handle_cannot_reserve_after_extension_but_can_settle_inflight_call(self):
        inflight = self.old.reserve('generation', '.05')
        self.extend()
        with self.assertRaises(ValueError):
            self.old.reserve('generation', '.05')
        self.old.complete(inflight, cost='.001')
        self.assertEqual(self.fresh().snapshot()['calls'][-1]['cost'], '0.001')
        with self.assertRaises(ValueError):
            EvaluationBudget(self.path, '1', authorization_id='old', authorization_digest='old-digest')

    def test_run_is_consumed_once_and_scope_metadata_cannot_be_forged(self):
        self.extend(max_external_calls=1)
        current = self.fresh()
        with self.assertRaises(ValueError):
            current.reserve('generation', '.05')
        with self.assertRaises(ValueError):
            current.claim_extension_run('b' * 64)
        current.claim_extension_run('a' * 64)
        token = current.reserve('generation', '.05', metadata={'authorization_id': 'fake',
            'authorization_digest': 'fake', 'manifest_sha256': 'fake', 'transport': 'local', 'scope_external_call': False})
        current.complete(token, cost='.001', metadata={'authorization_id': 'tampered', 'scope_external_call': False})
        call = current.snapshot()['calls'][-1]
        self.assertEqual(call['metadata']['authorization_id'], 'new')
        self.assertEqual(call['metadata']['authorization_digest'], 'new-digest')
        self.assertEqual(call['metadata']['manifest_sha256'], 'a' * 64)
        self.assertTrue(call['metadata']['scope_external_call'])
        with self.assertRaises(BudgetExceeded):
            current.reserve('generation', '.01')
        with self.assertRaises(ValueError):
            self.fresh().claim_extension_run('a' * 64)
        with self.assertRaises(ValueError):
            self.fresh().reserve('generation', '.01')

    def test_two_concurrent_extensions_cannot_fork_the_same_approval(self):
        def attempt(index):
            try:
                return self.extend(authorization_id=f'new-{index}', authorization_digest=f'digest-{index}')
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(attempt, range(2))), [False, True])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM approval_extensions').fetchone()[0], 1)

    def test_extension_does_not_expand_money_even_with_fresh_authorization(self):
        self.old.reserve('generation', '.95')
        self.extend()
        current = self.fresh()
        current.claim_extension_run('a' * 64)
        with self.assertRaises(BudgetExceeded):
            current.reserve('generation', '.05')
        self.assertEqual(current.snapshot()['budget_exposure_usd'], '0.963858062')

    def test_duplicate_with_changed_scope_and_cap_changes_are_rejected(self):
        self.extend()
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.extend(max_external_calls=45)
        with self.assertRaises(ValueError):
            EvaluationBudget(self.path, '.99', authorization_id='new', authorization_digest='new-digest')
        self.assertEqual(self.path.read_bytes(), before)

    def test_concurrent_run_claims_have_exactly_one_owner(self):
        self.extend()
        def claim(_):
            try:
                return bool(self.fresh().claim_extension_run('a' * 64))
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(claim, range(2))), [False, True])


class ApprovalExtensionCommandTests(SmokeHarness, TestCase):
    def extension_approval(self):
        self.use_local_mask()
        EvaluationBudget(self.ledger_path, self.manifest['maximum_usd'],
                         authorization_id='previous', authorization_digest='b' * 64)
        self.approval.update(approved=True, extends={'authorization_id': 'previous', 'authorization_digest': 'b' * 64},
            retain_existing_costs=True, execution_scope={'case_ids': [self.case['id']],
                'configurations': ['economy', 'strong', 'router'], 'max_runs': 1,
                'max_combinations': 3, 'max_external_calls': 11, 'repeat_uncertain_calls': False})
        self.save_approval()

    def extension_command(self, **kwargs):
        return call_command('extend_pilot_authorization', manifest=str(self.manifest_path),
            authorization=str(self.approval_path), stdout=StringIO(), **kwargs)

    def test_pending_scope_and_dry_run_do_not_mutate_ledger(self):
        self.extension_approval()
        before = self.ledger_path.read_bytes()
        self.extension_command()
        self.assertEqual(self.ledger_path.read_bytes(), before)
        for key, value in [('approved', False), ('status', 'pending')]:
            approval = deepcopy(self.approval)
            self.approval[key] = value
            self.save_approval()
            with self.assertRaises(CommandError):
                self.extension_command(apply=True)
            self.assertEqual(self.ledger_path.read_bytes(), before)
            self.approval = approval
        self.socket.assert_not_called()
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_registered_scope_can_run_once_but_cannot_replay_from_another_output(self):
        self.extension_approval()
        self.extension_command(apply=True)
        self.run_smoke('first')
        snapshot = self.ledger()
        with self.assertRaises((ValueError, CommandError)):
            self.run_smoke('second')
        self.assertEqual(self.ledger(), snapshot)
        self.assertEqual((len(self.judge_payloads), len(self.generation_payloads)), (6, 3))
        self.socket.assert_not_called()

    def test_invalid_frozen_scope_is_rejected_before_any_ledger_mutation(self):
        self.extension_approval()
        original = deepcopy(self.approval)
        before = self.ledger_path.read_bytes()
        invalid = [('maximum_usd', '.99'), ('retain_existing_costs', False),
            ('valid_until', '2000-01-01T00:00:00+00:00'), ('destinations', {'judge': 'https://example.invalid'}),
            ('manifest_sha256s', ['c' * 64]), ('execution_scope', {**original['execution_scope'], 'max_runs': 2}),
            ('execution_scope', {**original['execution_scope'], 'max_external_calls': 100}),
            ('execution_scope', {**original['execution_scope'], 'max_runs': True}),
            ('extends', {'authorization_id': 'wrong-parent', 'authorization_digest': 'b' * 64}),
            ('extends', {'authorization_id': 'previous', 'authorization_digest': 'c' * 64})]
        for key, value in invalid:
            self.approval = {**deepcopy(original), key: value}
            self.approval_path.write_text(json.dumps(self.approval), encoding='utf-8')
            with self.subTest(key=key, value=value), self.assertRaises(CommandError):
                self.extension_command(apply=True)
            self.assertEqual(self.ledger_path.read_bytes(), before)
        self.socket.assert_not_called()
        self.http.assert_not_called()
        self.sdk.assert_not_called()

    def test_approval_change_while_waiting_for_lock_cannot_register_another_digest(self):
        self.extension_approval()
        before = self.ledger_path.read_bytes()
        @contextmanager
        def change_during_lock_wait():
            self.approval['approval_reference'] = 'A different synthetic approval document'
            self.save_approval()
            yield
        with patch.object(evaluation, 'real_lock', change_during_lock_wait), self.assertRaisesMessage(
                CommandError, 'Authorization changed while waiting'):
            self.extension_command(apply=True)
        self.assertEqual(self.ledger_path.read_bytes(), before)
        self.http.assert_not_called()
        self.sdk.assert_not_called()
