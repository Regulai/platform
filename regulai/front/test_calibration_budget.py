"""Campaign money/window regression tests; every ledger is a temporary file."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier, Event
from unittest.mock import patch

from django.test import SimpleTestCase

from .evaluation_budget import BudgetExceeded, EvaluationBudget


class CalibrationBudgetTests(SimpleTestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'shared.sqlite3'
        self.now = datetime.now(timezone.utc)
        self.old = EvaluationBudget(self.path, '1', authorization_id='old', authorization_digest='old-digest')
        reported = self.old.reserve('generation', '.02')
        self.old.complete(reported, cost='.01')
        self.uncertain = self.old.reserve('classification', '.003')
        self.old.complete(self.uncertain, status='outcome_unknown')
        self.before = self.old.snapshot()['calls']
        self.args = dict(previous_id='old', previous_digest='old-digest', authorization_id='campaign',
            authorization_digest='campaign-digest', manifest_sha256='a' * 64,
            approval_reference='explicit synthetic campaign approval', max_external_calls=10,
            approved_ceiling_usd='1.66', approved_ceiling_eur='2',
            starts_at=(self.now - timedelta(minutes=1)).isoformat(),
            expires_at=(self.now + timedelta(hours=23)).isoformat(), margin='.35',
            fx_provenance={'rate_usd_per_eur': '1.1225', 'date': '2026-10-02',
                'source_url': 'https://www.ecb.europa.eu/example', 'sha256': 'b' * 64},
            price_provenance=[{'date': '2026-10-04', 'source_url': 'https://api-docs.deepseek.com/quick_start/pricing',
                               'sha256': 'c' * 64}])
        self.addCleanup(patch.stopall)
        patch('socket.socket.connect', side_effect=AssertionError('Budget tests forbid network')).start()

    def extend(self, **changes):
        return EvaluationBudget.extend_campaign_authorization(self.path, **{**self.args, **changes})

    def current(self):
        return EvaluationBudget(self.path, '1.66', authorization_id='campaign', authorization_digest='campaign-digest')

    def claimed(self):
        self.extend()
        ledger = self.current()
        ledger.claim_extension_run('a' * 64)
        return ledger

    def test_explicit_extension_preserves_anchor_history_and_uncertain_reservation(self):
        self.assertTrue(self.extend())
        self.assertFalse(self.extend())
        ledger = self.current()
        self.assertEqual(ledger.snapshot()['calls'], self.before)
        self.assertEqual(ledger.snapshot()['budget_exposure_usd'], '0.013')
        self.assertEqual(ledger.snapshot()['remaining_usd'], '1.647')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT cap FROM authorization').fetchall(), [('1',)])
            self.assertEqual(db.execute('SELECT id,digest FROM approval').fetchall(), [('old', 'old-digest')])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM campaign_terms').fetchone(), (1,))
        with self.assertRaises(ValueError):
            self.old.reserve('generation', '.001')
        with self.assertRaises(ValueError):
            self.extend(approved_ceiling_usd='1.65')

    def test_constructor_and_legacy_scope_cannot_enlarge_or_remove_campaign_terms(self):
        with self.assertRaises(ValueError):
            EvaluationBudget(self.path, '1.66', authorization_id='old', authorization_digest='old-digest')
        with self.assertRaises(ValueError):
            EvaluationBudget(Path(self.directory.name) / 'unapproved.sqlite3', '1.66')
        self.extend()
        with self.assertRaises(ValueError):
            EvaluationBudget.extend_authorization(self.path, '1', previous_id='campaign',
                previous_digest='campaign-digest', authorization_id='legacy-child', authorization_digest='child',
                manifest_sha256='d' * 64, approval_reference='cannot discard window', max_external_calls=2)

    def test_invalid_caps_windows_sources_and_missing_ledger_are_rejected(self):
        for changes in ({'approved_ceiling_eur': '2.01'}, {'approved_ceiling_usd': '1.67'},
                {'margin': '-.01'}, {'expires_at': (self.now + timedelta(hours=25)).isoformat()},
                {'starts_at': self.now.replace(tzinfo=None).isoformat()}, {'price_provenance': []},
                {'fx_provenance': {**self.args['fx_provenance'], 'sha256': ''}},
                {'previous_digest': 'stale'}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, ArithmeticError)):
                self.extend(**changes)
        with self.assertRaises((ValueError, sqlite3.Error)):
            EvaluationBudget.extend_campaign_authorization(Path(self.directory.name) / 'missing.sqlite3', **self.args)
        self.assertFalse((Path(self.directory.name) / 'missing.sqlite3').exists())
        self.assertEqual(self.old.snapshot()['calls'], self.before)

    def test_two_competing_reservations_cannot_overspend_shared_cap(self):
        ledger = self.claimed()
        ready = Barrier(2)
        def reserve():
            ready.wait(timeout=5)
            try:
                return ledger.reserve('generation', '1')
            except BudgetExceeded:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(reserve) for _ in range(2)]
            tokens = [future.result(timeout=10) for future in futures]
        self.assertEqual(sum(value is not None for value in tokens), 1)
        self.assertEqual(ledger.snapshot()['budget_exposure_usd'], '1.013')

    def test_authorization_callback_runs_with_writer_lock_held(self):
        ledger = self.claimed()
        observations = []
        def authorize():
            db = sqlite3.connect(self.path, timeout=0)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute('BEGIN IMMEDIATE')
                observations.append('locked')
            finally:
                db.close()
        ledger.reserve('generation', '.01', authorize=authorize)
        self.assertEqual(observations, ['locked'])

    def test_revocation_while_waiting_for_lock_creates_no_reservation(self):
        ledger = self.claimed()
        blocker = sqlite3.connect(self.path)
        blocker.execute('BEGIN IMMEDIATE')
        connecting, revoked = Event(), Event()
        real_connect = sqlite3.connect
        def connect(*args, **kwargs):
            connecting.set()
            return real_connect(*args, **kwargs)
        def authorize():
            if revoked.is_set():
                raise BudgetExceeded('Approval was revoked while waiting')
        with ThreadPoolExecutor(max_workers=1) as pool, patch('front.evaluation_budget.sqlite3.connect', side_effect=connect):
            future = pool.submit(ledger.reserve, 'generation', '.1', authorize=authorize)
            try:
                self.assertTrue(connecting.wait(timeout=5))
                revoked.set()
            finally:
                blocker.rollback()
                blocker.close()
            with self.assertRaises(BudgetExceeded):
                future.result(timeout=10)
        self.assertEqual(ledger.snapshot()['calls'], self.before)

    def test_expiry_is_rechecked_after_wait_and_settlement_remains_possible(self):
        ledger = self.claimed()
        interrupted = ledger.reserve('generation', '.4')
        class ExpiredDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.fromisoformat(self.args['expires_at'])
        with patch('front.evaluation_budget.datetime', ExpiredDateTime):
            with self.assertRaises(BudgetExceeded):
                ledger.reserve('verification', '.01')
            # Recording an already incurred result must remain possible after expiry.
            ledger.complete(interrupted, status='outcome_unknown')
        fresh = self.current()
        self.assertEqual(fresh.snapshot()['uncertain_reservations_usd'], '0.403')
        with self.assertRaises(ValueError):
            fresh.claim_extension_run('a' * 64)
        with self.assertRaises(ValueError):
            fresh.reserve('generation', '.01')

    def test_window_expiring_while_waiting_for_writer_lock_prevents_reservation(self):
        ledger = self.claimed()
        blocker = sqlite3.connect(self.path)
        blocker.execute('BEGIN IMMEDIATE')
        connecting, clock = Event(), [self.now]
        real_connect = sqlite3.connect
        class AdvancingDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock[0]
        def connect(*args, **kwargs):
            connecting.set()
            return real_connect(*args, **kwargs)
        with ThreadPoolExecutor(max_workers=1) as pool, \
                patch('front.evaluation_budget.sqlite3.connect', side_effect=connect), \
                patch('front.evaluation_budget.datetime', AdvancingDateTime):
            future = pool.submit(ledger.reserve, 'verification', '.01')
            try:
                self.assertTrue(connecting.wait(timeout=5))
                clock[0] = datetime.fromisoformat(self.args['expires_at'])
            finally:
                blocker.rollback()
                blocker.close()
            with self.assertRaises(BudgetExceeded):
                future.result(timeout=10)
        self.assertEqual(ledger.snapshot()['calls'], self.before)

    def test_callback_interrupt_rolls_back_but_interrupted_transport_retains_exposure(self):
        ledger = self.claimed()
        def interrupt():
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            ledger.reserve('generation', '.1', authorize=interrupt)
        self.assertEqual(ledger.snapshot()['calls'], self.before)
        token = ledger.reserve('generation', '.2')
        fresh = self.current()
        row = next(call for call in fresh.snapshot()['calls'] if call['id'] == token)
        self.assertEqual((row['status'], row['cost']), ('started', None))
        self.assertEqual(fresh.snapshot()['budget_exposure_usd'], '0.213')
        ledger.complete(token, cost='.001', cost_kind='tariff_estimate')
        self.assertEqual(ledger.snapshot()['budget_exposure_usd'], '0.213')
