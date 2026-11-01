"""Offline checks for the real-provider evaluation's strict USD cap."""

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ops.agent_chat.p0_eval_budget import BudgetBreach, BudgetError, BudgetExceeded, BudgetGuard, BudgetHalted


def reserve_in_process(path):
    try:
        return BudgetGuard(path).reserve("generation", "model-test", 1_000_000, 0, "1", "0")
    except BudgetExceeded:
        return None


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "budget.json"
        self.guard = BudgetGuard(self.path)

    def reserve(self, guard=None, **kwargs):
        values = dict(kind="generation", model="model/test", max_input_tokens=1_000_000,
                      max_output_tokens=1_000_000, input_price_per_million="1",
                      output_price_per_million="1", metadata={"case_id": "case-01"})
        values.update(kwargs)
        return (guard or self.guard).reserve(**values)

    def test_exact_five_dollars_allowed_next_call_denied(self):
        identifier = self.reserve(input_price_per_million="2", output_price_per_million="3")
        self.assertEqual(Decimal(self.guard.snapshot()["committed_usd"]), Decimal("5"))
        with self.assertRaises(BudgetExceeded):
            self.reserve(max_input_tokens=1, max_output_tokens=0)
        self.guard.settle(identifier, input_tokens=500_000, output_tokens=500_000)
        self.reserve(input_price_per_million="1.2", output_price_per_million="1.3")
        self.assertEqual(Decimal(self.guard.snapshot()["committed_usd"]), Decimal("5"))

    def test_unknown_usage_retains_bound_and_can_be_resolved(self):
        identifier = self.reserve()
        self.guard.settle(identifier)
        snapshot = BudgetGuard(self.path).snapshot()
        self.assertTrue(snapshot["halted"])
        self.assertIsNone(snapshot["reservations"][identifier]["cost_usd"])
        self.assertEqual(Decimal(snapshot["reserved_usd"]), Decimal("2"))
        with self.assertRaises(BudgetHalted):
            self.reserve()
        self.guard.settle(identifier, input_tokens=10, output_tokens=20)
        self.assertFalse(self.guard.snapshot()["halted"])
        self.reserve()

    def test_unknown_one_counter_is_not_zero_cost(self):
        identifier = self.reserve()
        self.guard.settle(identifier, input_tokens=10, cost_optional="0")
        snapshot = self.guard.snapshot()
        self.assertTrue(snapshot["halted"])
        self.assertEqual(snapshot["reservations"][identifier]["state"], "unknown")
        self.assertEqual(Decimal(snapshot["reserved_usd"]), Decimal("2"))

    def test_threads_and_multiple_instances_do_not_overreserve(self):
        guards = [BudgetGuard(self.path) for _ in range(20)]
        def reserve(guard):
            try:
                return self.reserve(guard, input_price_per_million="0.2", output_price_per_million="0.3")
            except BudgetExceeded:
                return None
        with ThreadPoolExecutor(max_workers=20) as executor:
            identifiers = list(executor.map(reserve, guards))
        self.assertEqual(sum(identifier is not None for identifier in identifiers), 10)
        self.assertEqual(Decimal(self.guard.snapshot()["committed_usd"]), Decimal("5"))

    def test_processes_share_one_budget(self):
        with ProcessPoolExecutor(max_workers=8) as executor:
            identifiers = list(executor.map(reserve_in_process, [self.path] * 8))
        self.assertEqual(sum(identifier is not None for identifier in identifiers), 5)
        self.assertEqual(Decimal(self.guard.snapshot()["committed_usd"]), Decimal("5"))

    def test_invalid_amounts_counters_and_metadata_rejected_before_write(self):
        for value in (None, True, 0.1, "NaN", "Infinity", "-0.01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.reserve(input_price_per_million=value)
        for value in (True, -1, 1.2, "2"):
            with self.subTest(count=value), self.assertRaises(ValueError):
                self.reserve(max_input_tokens=value)
        with self.assertRaises(ValueError):
            self.reserve(metadata={"prompt": "private text"})
        with self.assertRaises(ValueError):
            self.reserve(metadata={"case_id": "Bearer secret"})
        self.assertEqual(self.guard.snapshot()["reservation_count"], 0)

    def test_token_and_actual_cost_breaches_persist_before_stop(self):
        for index, values in enumerate(({"input_tokens": 1_000_001, "output_tokens": 0},
                                        {"input_tokens": 1, "output_tokens": 1, "cost_optional": "2.01"})):
            guard = BudgetGuard(Path(self.directory.name) / f"breach-{index}.json")
            identifier = self.reserve(guard)
            with self.assertRaises(BudgetBreach):
                guard.settle(identifier, **values)
            snapshot = BudgetGuard(guard.path).snapshot()
            self.assertEqual(snapshot["breached_reservations"], [identifier])
            with self.assertRaises(BudgetHalted):
                self.reserve(guard)

    def test_settlement_idempotent_conflict_does_not_mutate(self):
        identifier = self.reserve()
        receipt = self.guard.settle(identifier, 100, 200, duration_ms=123)
        self.assertEqual(receipt, self.guard.settle(identifier, 100, 200, duration_ms=999))
        with self.assertRaises(BudgetError):
            self.guard.settle(identifier, 100, 201)
        self.assertEqual(receipt, self.guard.snapshot()["reservations"][identifier])

    def test_invalid_provider_usage_halts_without_losing_reservation(self):
        identifier = self.reserve()
        with self.assertRaises(BudgetHalted):
            self.guard.settle(identifier, -1, 10)
        self.assertEqual(Decimal(self.guard.snapshot()["reserved_usd"]), Decimal("2"))
        with self.assertRaises(BudgetHalted):
            self.reserve()

    def test_sub_microdollar_amounts_survive_persistence_exactly(self):
        identifier = self.reserve(max_input_tokens=1, max_output_tokens=0,
                                  input_price_per_million="0.000000000000000001")
        self.guard.settle(identifier, 1, 0)
        self.assertEqual(Decimal(BudgetGuard(self.path).snapshot()["known_cost_usd"]), Decimal("1e-24"))

    def test_failed_atomic_write_leaves_valid_ledger_and_releases_lock(self):
        original = self.path.read_bytes()
        with patch("ops.agent_chat.p0_eval_budget.os.replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.reserve()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])
        self.reserve()
        self.assertEqual(self.guard.snapshot()["reservation_count"], 1)

    def test_corrupt_ledger_or_changed_limit_fails_closed(self):
        with self.assertRaises(BudgetError):
            BudgetGuard(self.path, limit=Decimal("4"))
        self.path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(BudgetError):
            self.reserve()
        with self.assertRaises(ValueError):
            BudgetGuard(Path(self.directory.name) / "too-much.json", limit="5.01")

    def test_ledger_has_safe_telemetry_only_and_exact_decimal_cost(self):
        identifier = self.reserve(max_input_tokens=100, max_output_tokens=100,
                                  input_price_per_million="0.1", output_price_per_million="0.2")
        self.guard.settle(identifier, 10, 20, duration_ms=0)
        ledger = json.loads(self.path.read_text(encoding="utf-8"))
        receipt = ledger["reservations"][identifier]
        self.assertEqual(Decimal(receipt["cost_usd"]), Decimal("0.000005"))
        self.assertEqual(receipt["duration_ms"], 0)
        self.assertIn("+00:00", receipt["reserved_at"])
        self.assertNotIn("prompt", self.path.read_text(encoding="utf-8"))

    def test_explicit_unknown_cap_consumes_full_bound_and_allows_only_remaining_budget(self):
        identifier = self.reserve(input_price_per_million="0.30", output_price_per_million="0.0098304",
            metadata={"execution_id": "run-10", "call_id": "failed-final"})
        self.guard.settle(identifier)
        self.guard.cap_unknown(identifier, reason="http_error_without_usage", evidence_id="http-400-receipt")
        snapshot = BudgetGuard(self.path).snapshot()
        self.assertFalse(snapshot["halted"])
        self.assertEqual(snapshot["unknown_reservations"], [identifier])
        self.assertIsNone(snapshot["reservations"][identifier]["cost_usd"])
        self.assertEqual(Decimal(snapshot["known_cost_usd"]), Decimal("0"))
        self.assertEqual(Decimal(snapshot["capped_unknown_usd"]), Decimal("0.3098304"))
        self.reserve(input_price_per_million="4.6901696", output_price_per_million="0",
            metadata={"execution_id": "new-run", "call_id": "new-call"})
        self.assertEqual(Decimal(self.guard.snapshot()["committed_usd"]), Decimal("5"))
        with self.assertRaises(BudgetExceeded):
            self.reserve(max_input_tokens=1, max_output_tokens=0,
                metadata={"execution_id": "another-run", "call_id": "another-call"})

    def test_capped_unknown_is_immutable_idempotent_and_cannot_redispatch(self):
        metadata = {"execution_id": "run-10", "call_id": "failed-final"}
        identifier = self.reserve(metadata=metadata)
        with self.assertRaises(BudgetError):
            self.guard.cap_unknown(identifier, reason="http_error_without_usage", evidence_id="http-400")
        self.guard.settle(identifier)
        receipt = self.guard.cap_unknown(identifier, reason="http_error_without_usage", evidence_id="http-400")
        self.assertEqual(receipt,
            self.guard.cap_unknown(identifier, reason="http_error_without_usage", evidence_id="http-400"))
        for operation in (lambda: self.guard.settle(identifier, 0, 0, cost_optional="0"),
                          lambda: self.guard.settle(identifier),
                          lambda: self.guard.cap_unknown(identifier, reason="http_error_without_usage", evidence_id="changed"),
                          lambda: self.reserve(metadata=metadata),
                          lambda: self.reserve()):
            with self.assertRaises(BudgetError):
                operation()
        snapshot = BudgetGuard(self.path).snapshot()
        self.assertEqual(snapshot["reservations"][identifier], receipt)
        self.assertEqual(Decimal(snapshot["committed_usd"]), Decimal("2"))
        self.assertEqual(snapshot["reservation_count"], 1)


if __name__ == "__main__":
    unittest.main()
