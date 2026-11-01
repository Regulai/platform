from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from .evaluation_budget import BudgetExceeded, EvaluationBudget


class BudgetTests(SimpleTestCase):
    def test_estimated_cost_does_not_release_conservative_reservation(self):
        with TemporaryDirectory() as directory:
            ledger = EvaluationBudget(Path(directory) / 'budget.sqlite3', '1')
            token = ledger.reserve('generation', '.7')
            ledger.complete(token, cost='.01', cost_kind='tariff_estimate')
            self.assertEqual(ledger.snapshot()['tariff_estimated_usd'], '0.01')
            self.assertEqual(ledger.snapshot()['budget_exposure_usd'], '0.7')
            with self.assertRaises(BudgetExceeded):
                ledger.reserve('classification', '.31')

    def test_zero_mask_and_proven_nonstarted_call_are_recorded_without_expense(self):
        with TemporaryDirectory() as directory:
            ledger = EvaluationBudget(Path(directory) / 'budget.sqlite3', '1')
            with self.assertRaises(ValueError):
                ledger.reserve('generation', '0')
            zero = ledger.reserve('obfuscation', '0', zero_cost=True)
            ledger.complete(zero, cost='0', cost_kind='configured_zero')
            denied = ledger.reserve('generation', '.8')
            ledger.complete(denied, status='not_started', cost='0', cost_kind='not_incurred')
            self.assertEqual(len(ledger.snapshot()['calls']), 2)
            self.assertEqual(ledger.snapshot()['budget_exposure_usd'], '0')
            ledger.reserve('generation', '1')

    def test_approval_identity_cannot_be_reused_or_attached_to_historical_calls(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.sqlite3'
            ledger = EvaluationBudget(path, '1', authorization_id='new-approval', authorization_digest='frozen')
            ledger.reserve('classification', '.01')
            for parameters in ({}, {'authorization_id': 'other', 'authorization_digest': 'frozen'},
                               {'authorization_id': 'new-approval', 'authorization_digest': 'changed'}):
                with self.assertRaises(ValueError):
                    EvaluationBudget(path, '1', **parameters)
            historical = Path(directory) / 'historical.sqlite3'
            EvaluationBudget(historical, '1').reserve('historical', '.03')
            with self.assertRaises(ValueError):
                EvaluationBudget(historical, '1', authorization_id='new-approval', authorization_digest='frozen')

    def test_excess_charge_is_retained_and_stops_future_calls(self):
        with TemporaryDirectory() as directory:
            ledger = EvaluationBudget(Path(directory) / 'budget.sqlite3', '1')
            token = ledger.reserve('verification', '.01')
            with self.assertRaises(BudgetExceeded):
                ledger.complete(token, cost='.02', cost_kind='provider_reported')
            self.assertEqual(ledger.snapshot()['provider_reported_usd'], '0.02')
            self.assertEqual(ledger.snapshot()['calls'][0]['status'], 'bound_exceeded')
            with self.assertRaises(BudgetExceeded):
                ledger.reserve('generation', '.01')

    def test_concurrent_reservation_and_restart_never_release_unknown_expense(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.sqlite3'
            ledger = EvaluationBudget(path, '1')
            def reserve(_):
                try:
                    return ledger.reserve('synthetic', '.3')
                except BudgetExceeded:
                    return None
            with ThreadPoolExecutor(max_workers=4) as executor:
                ids = [value for value in executor.map(reserve, range(4)) if value]
            self.assertEqual(len(ids), 3)
            ledger.complete(ids[0], cost='.01')
            ledger.complete(ids[1], status='outcome_unknown')
            fresh = EvaluationBudget(path, '1')
            self.assertEqual(fresh.snapshot()['uncertain_reservations_usd'], '0.6')
            with self.assertRaises(BudgetExceeded):
                fresh.reserve('too much', '.4')
            fresh.reserve('last permitted', '.39')
            with self.assertRaises(BudgetExceeded):
                fresh.reserve('over cap', '.00001')
            with self.assertRaises(ValueError):
                fresh.complete(ids[0], cost='0')
            with self.assertRaises(ValueError):
                EvaluationBudget(path, '2')
