from dataclasses import replace
from decimal import Decimal

from django.test import SimpleTestCase

from .routing import Candidate, RoutingError, actual_cost, route


def candidate(**changes):
    return replace(Candidate(
        company_engine_id=1, model_pk=1, model_id="economy-v1",
        connector_type="openai", level="economy", context_window=10000,
        max_tokens=1000, input_price=Decimal("2"), output_price=Decimal("6"),
        currency="USD", price_date="2026-10-02", supports_vision=False,
        supports_json=True, quality=0.8,
    ), **changes)


class RoutingTests(SimpleTestCase):
    def test_known_cost_and_price_snapshot_are_exact(self):
        decision = route([candidate()], ["hola"], allowed_destinations={"engine:1"},
                         max_output_tokens=100, overhead_tokens=16)
        self.assertEqual(decision.input_tokens_bound, 20)
        self.assertEqual(decision.estimated_cost, Decimal("0.00064"))
        self.assertEqual(actual_cost(decision.price_snapshot, 1000, 500), Decimal("0.005"))

    def test_filters_permission_capability_and_quality_before_cost(self):
        rows = [candidate(company_engine_id=2, input_price=Decimal("0")),
                candidate(model_pk=2, supports_vision=False, input_price=Decimal("0")),
                candidate(model_pk=3, supports_vision=True, quality=0.2, input_price=Decimal("0")),
                candidate(model_pk=4, supports_vision=True),
                candidate(model_pk=5, supports_vision=True)]
        decision = route(rows[::-1], ["hello"], allowed_destinations={"engine:1"},
                         min_quality=0.7, needs_vision=True)
        self.assertEqual(decision.candidate.model_pk, 4)

    def test_unknown_price_budget_and_capacity_have_distinct_errors(self):
        cases = [([candidate(input_price=None)], {"budget": "1"}, "unknown_price"),
                 ([candidate()], {"budget": "0"}, "budget_exhausted"),
                 ([candidate(context_window=None)], {}, "unknown_capacity"),
                 ([candidate(context_window=100)], {}, "context_overflow"),
                 ([candidate(company_engine_id=2)], {}, "no_authorized_candidates")]
        for rows, kwargs, code in cases:
            with self.subTest(code=code), self.assertRaises(RoutingError) as error:
                route(rows, ["x"], allowed_destinations={"engine:1"}, **kwargs)
            self.assertEqual(error.exception.code, code)

    def test_missing_usage_is_not_a_zero_invoice_and_prices_are_snapshotted(self):
        decision = route([candidate(input_price=None)], ["x"], allowed_destinations={"engine:1"})
        self.assertIsNone(decision.estimated_cost)
        self.assertIsNone(actual_cost(decision.price_snapshot, 1, 1))
        known = route([candidate()], ["x"], allowed_destinations={"engine:1"})
        self.assertIsNone(actual_cost(known.price_snapshot, None, 1))
        self.assertIsNone(actual_cost(known.price_snapshot, True, 1))

    def test_multimodal_input_and_invalid_budget_fail_closed(self):
        for messages, kwargs, code in [([{"content": [{"type": "image_url"}]}], {}, "unbounded_input"),
                                       (["x"], {"budget": "NaN"}, "invalid_budget")]:
            with self.subTest(code=code), self.assertRaises(RoutingError) as error:
                route([candidate()], messages, allowed_destinations={"engine:1"}, **kwargs)
            self.assertEqual(error.exception.code, code)

    def test_each_message_and_role_count_toward_context_bound(self):
        decision = route([candidate()], [{"role": "user", "content": "ñ"}, "ab"],
                         allowed_destinations={"engine:1"}, overhead_tokens=10)
        self.assertEqual(decision.input_tokens_bound, 28)

    def test_budget_equality_is_allowed_and_other_currencies_are_not_compared(self):
        decision = route([candidate()], ["hola"], allowed_destinations={"engine:1"},
                         max_output_tokens=100, overhead_tokens=16, budget="0.00064")
        self.assertEqual(decision.estimated_cost, Decimal("0.00064"))
        with self.assertRaises(RoutingError) as error:
            route([candidate(currency="EUR")], ["hola"], allowed_destinations={"engine:1"})
        self.assertEqual(error.exception.code, "currency_mismatch")

    def test_escalation_requires_strictly_higher_configured_quality(self):
        rows = [candidate(), candidate(model_pk=2, quality=0.9, output_price=Decimal("10"))]
        decision = route(rows, ["x"], allowed_destinations={"engine:1"},
                         min_quality=0.8, min_quality_exclusive=True)
        self.assertEqual(decision.candidate.model_pk, 2)
