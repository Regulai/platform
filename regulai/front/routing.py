"""Pure route decisions over an already company-authorized, active catalogue."""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import math


class RoutingError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Candidate:
    company_engine_id: int
    model_pk: int
    model_id: str
    connector_type: str
    level: str
    context_window: int | None
    max_tokens: int | None
    input_price: Decimal | None
    output_price: Decimal | None
    currency: str
    price_date: str | None
    supports_vision: bool
    supports_json: bool
    quality: float


@dataclass(frozen=True)
class RouteDecision:
    candidate: Candidate
    input_tokens_bound: int
    max_output_tokens: int | None
    estimated_cost: Decimal | None
    price_snapshot: dict


def _nonnegative_decimal(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        number = Decimal(str(value))
        return number if number.is_finite() and number >= 0 else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def actual_cost(price_snapshot, input_tokens, output_tokens):
    """Known input/output categories only; missing usage or prices stay unknown."""
    if any(type(tokens) is not int or tokens < 0 for tokens in (input_tokens, output_tokens)):
        return None
    prices = [_nonnegative_decimal(price_snapshot.get(key)) for key in ("input_price", "output_price")]
    if None in prices:
        return None
    return (prices[0] * input_tokens + prices[1] * output_tokens) / Decimal(1_000_000)


def route(candidates, messages, *, allowed_destinations, min_quality=0,
          needs_vision=False, needs_json=False, max_output_tokens=1000,
          budget=None, overhead_tokens=256, budget_currency="USD",
          manual_company_engine_id=None, min_quality_exclusive=False, extra_input_bytes=None,
          require_quality=True, provider_managed=False):
    """UTF-8 bytes conservatively bound text tokens plus per-message overhead.

    messages may be strings, ChatMessage objects, or role/content dictionaries.
    Multimodal inputs require a provider-specific bound and are rejected here.
    No credentials or ORM lookup occur here: the caller supplies authorized rows.
    """
    if (type(require_quality) is not bool or (not require_quality and (min_quality or min_quality_exclusive))
            or type(provider_managed) is not bool
            or (not provider_managed and (type(max_output_tokens) is not int or max_output_tokens <= 0))
            or (provider_managed and max_output_tokens is not None)
            or type(overhead_tokens) is not int or overhead_tokens < 0
            or isinstance(min_quality, bool) or not isinstance(min_quality, (int, float))
            or not math.isfinite(min_quality) or not 0 <= min_quality <= 1):
        raise RoutingError("invalid_route_limits")
    limit = _nonnegative_decimal(budget)
    if budget is not None and limit is None:
        raise RoutingError("invalid_budget")
    input_bound = 0
    for message in messages:
        content = message if isinstance(message, str) else (
            message.get("content") if isinstance(message, dict) else getattr(message, "content", None))
        if not isinstance(content, str):
            raise RoutingError("unbounded_input")
        role = "" if isinstance(message, str) else (
            message.get("role", "") if isinstance(message, dict) else getattr(message, "role", ""))
        if not isinstance(role, str):
            raise RoutingError("unbounded_input")
        input_bound += len(content.encode("utf-8")) + len(role.encode("utf-8")) + overhead_tokens
    input_bound = max(input_bound, overhead_tokens)
    extra_input_bytes = {} if extra_input_bytes is None else extra_input_bytes
    if not isinstance(extra_input_bytes, dict) or any(type(value) is not int or value < 0 for value in extra_input_bytes.values()):
        raise RoutingError('unbounded_input')
    candidates = [candidate for candidate in candidates
                  if f"engine:{candidate.company_engine_id}" in allowed_destinations
                  and (manual_company_engine_id is None
                       or candidate.company_engine_id == manual_company_engine_id)]
    if not candidates:
        raise RoutingError("no_authorized_candidates")
    eligible, reasons = [], set()
    for candidate in candidates:
        candidate_input_bound = input_bound + extra_input_bytes.get((candidate.company_engine_id, candidate.model_pk), 0)
        if ((needs_vision and not candidate.supports_vision)
                or (needs_json and not candidate.supports_json)):
            reasons.add("capability_unavailable")
            continue
        quality = candidate.quality
        if require_quality and (isinstance(quality, bool) or not isinstance(quality, (int, float))
                or not math.isfinite(quality) or not 0 <= quality <= 1
                or quality < min_quality or (min_quality_exclusive and quality == min_quality)):
            reasons.add("quality_unavailable")
            continue
        if provider_managed and candidate.connector_type not in ('openai', 'openai_compatible', 'vercel_gateway'):
            reasons.add('capability_unavailable')
            continue
        if not provider_managed and any(type(value) is not int or value <= 0
               for value in (candidate.context_window, candidate.max_tokens)):
            reasons.add("unknown_capacity")
            continue
        if not provider_managed and (max_output_tokens > candidate.max_tokens
                or candidate_input_bound + max_output_tokens > candidate.context_window):
            reasons.add("context_overflow")
            continue
        snapshot = {
            "input_price": str(candidate.input_price) if candidate.input_price is not None else None,
            "output_price": str(candidate.output_price) if candidate.output_price is not None else None,
            "currency": candidate.currency,
            "price_date": str(candidate.price_date) if candidate.price_date is not None else None,
        }
        cost = actual_cost(snapshot, candidate_input_bound, max_output_tokens)
        if candidate.currency != budget_currency:
            reasons.add("currency_mismatch")
            continue
        if limit is not None and cost is None:
            reasons.add("unknown_price")
            continue
        if limit is not None and cost > limit:
            reasons.add("budget_exhausted")
            continue
        eligible.append(RouteDecision(candidate, candidate_input_bound, max_output_tokens, cost, snapshot))
    if not eligible:
        # Costs are checked after mandatory permission/capacity/quality filters.
        for reason in ("budget_exhausted", "unknown_price", "currency_mismatch",
                       "context_overflow", "unknown_capacity", "quality_unavailable", "capability_unavailable"):
            if reason in reasons:
                raise RoutingError(reason)
        raise RoutingError("no_authorized_candidates")
    return min(eligible, key=lambda decision: (
        decision.estimated_cost is None, decision.estimated_cost or Decimal(0),
        decision.candidate.model_pk, decision.candidate.company_engine_id))
