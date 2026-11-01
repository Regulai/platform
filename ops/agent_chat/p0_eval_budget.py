"""Fail-closed USD budget for the P0 evaluation; no network calls or retries.

Reserve immediately before each provider request, using conservative token bounds
and prices (USD per million tokens), then settle from that response's usage. On
any ambiguous transport failure call ``settle(reservation_id)``: its full bound
stays committed and further reservations stop. A later, confirmed usage receipt
can settle that unknown reservation. Alternatively, an explicit ``cap_unknown``
irreversibly consumes its entire pre-dispatch bound without claiming a known
cost. Only new, identified calls may then use the remaining budget. A usage/cost
breach stops the run permanently.

Example::

    guard = BudgetGuard("private-output/budget.json")
    reservation = guard.reserve("generation", "model-id", 8000, 2048,
                                Decimal("0.3"), Decimal("0.5"),
                                {"case_id": "case-01", "turn_id": "1"})
    # Make exactly one network attempt here; disable the SDK's automatic retries.
    guard.settle(reservation, input_tokens=1234, output_tokens=567)

One ledger must cover ALL paid calls in the evaluation, including protection,
compaction, and generation. This guard cannot make prices or token bounds true;
the transport caller must supply documented upper bounds before dispatch. JSON
contains only IDs, counts, times and decimal money strings, never request bodies.
OS file locking serializes processes; a shared lock also serializes local threads.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, localcontext
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from uuid import uuid4


class BudgetError(RuntimeError):
    """The request must not be dispatched."""


class BudgetExceeded(BudgetError):
    pass


class BudgetHalted(BudgetError):
    pass


class BudgetBreach(BudgetError):
    """Observed use exceeded the pre-dispatch bound; the receipt is saved."""


_locks = {}
_locks_lock = threading.Lock()
_ID = re.compile(r"[A-Za-z0-9_.:/@+-]{1,160}\Z")
_META_IDS = {"case_id", "conversation_id", "turn_id", "call_id", "execution_id",
             "provider_id", "route_id", "phase"}
_META_COUNTS = {"attempt", "request_bytes"}
_MILLION = Decimal(1_000_000)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _money(value, name, *, derived=False):
    if isinstance(value, (bool, float)) or not isinstance(value, (Decimal, int, str)):
        raise ValueError(f"{name} must be a finite non-negative Decimal, int or string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"{name} must be a decimal amount") from exc
    if not result.is_finite() or result < 0 or result.adjusted() > (32 if derived else 18):
        raise ValueError(f"{name} must be finite, non-negative and at most 10^19")
    if (len(result.as_tuple().digits) > (64 if derived else 28)
            or result.as_tuple().exponent < (-32 if derived else -18)):
        raise ValueError(f"{name} supports up to 28 digits and 18 decimal places")
    return result


def _count(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10**12:
        raise ValueError(f"{name} must be an integer between 0 and 10^12")
    return value


def _identifier(value, name):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name} must be an identifier of 1-160 safe characters")
    return value


def _metadata(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - (_META_IDS | _META_COUNTS):
        raise ValueError("metadata accepts only documented IDs and counters")
    return {key: (_count(item, key) if key in _META_COUNTS else _identifier(item, key))
            for key, item in value.items()}


def _cost(input_tokens, output_tokens, input_price, output_price):
    with localcontext() as context:
        context.prec = 64
        context.rounding = ROUND_CEILING
        return (Decimal(input_tokens) * input_price + Decimal(output_tokens) * output_price) / _MILLION


class BudgetGuard:
    def __init__(self, path, limit=Decimal("5")):
        self.path = Path(path).resolve()
        self.limit = _money(limit, "limit")
        if not 0 < self.limit <= Decimal("5"):
            raise ValueError("This evaluation requires a USD limit greater than zero and at most 5")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _locks_lock:
            self._lock = _locks.setdefault(str(self.path), threading.RLock())
        with self._locked():
            if self.path.exists():
                self._read()
            else:
                self._write({"schema": 1, "currency": "USD", "limit_usd": str(self.limit),
                             "created_at": _now(), "reservations": {}})

    @contextmanager
    def _locked(self):
        with self._lock, self.path.with_suffix(self.path.suffix + ".lock").open("a+b") as stream:
            if os.name == "nt":
                import msvcrt
                if os.fstat(stream.fileno()).st_size == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _read(self):
        try:
            ledger = json.loads(self.path.read_text(encoding="utf-8"))
            if (ledger["schema"] != 1 or ledger["currency"] != "USD"
                    or _money(ledger["limit_usd"], "saved limit") != self.limit
                    or not isinstance(ledger["reservations"], dict)):
                raise ValueError("Unexpected budget ledger or changed limit")
            self._summary(ledger)
            return ledger
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise BudgetError("Budget ledger cannot be verified; no request may be dispatched") from exc

    def _write(self, ledger):
        ledger["updated_at"] = _now()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                             prefix=self.path.name + ".", suffix=".tmp",
                                             dir=self.path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                json.dump(ledger, stream, ensure_ascii=True, indent=2, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _summary(self, ledger):
        known, reserved, capped = Decimal(0), Decimal(0), Decimal(0)
        unknown, unsealed, capped_ids, breached = [], [], [], []
        with localcontext() as context:
            context.prec = 64
            for identifier, item in ledger["reservations"].items():
                state = item["state"]
                bound = _money(item["bound_usd"], "saved bound", derived=True)
                if state in {"reserved", "unknown"}:
                    reserved += bound
                    if state == "unknown":
                        unknown.append(identifier)
                        unsealed.append(identifier)
                elif state == "capped_unknown":
                    if item["cost_usd"] is not None:
                        raise ValueError("Capped unknown usage must retain an unknown actual cost")
                    capped += bound
                    unknown.append(identifier)
                    capped_ids.append(identifier)
                elif state in {"settled", "breached"}:
                    known += _money(item["cost_usd"], "saved cost", derived=True)
                    if state == "breached":
                        breached.append(identifier)
                else:
                    raise ValueError("Unknown budget reservation state")
            committed = known + reserved + capped
            return {"limit_usd": str(self.limit), "known_cost_usd": str(known),
                    "reserved_usd": str(reserved), "capped_unknown_usd": str(capped),
                    "committed_usd": str(committed),
                    "available_usd": str(max(Decimal(0), self.limit - committed)),
                    "halted": bool(unsealed or breached or committed > self.limit),
                    "unknown_reservations": unknown, "breached_reservations": breached,
                    "capped_unknown_reservations": capped_ids,
                    "reservation_count": len(ledger["reservations"])}

    def snapshot(self):
        """Return the current summary and safe, independently copied receipts."""
        with self._locked():
            ledger = self._read()
            return {**self._summary(ledger), "reservations": ledger["reservations"]}

    def cap_unknown(self, identifier, *, reason, evidence_id):
        """Irreversibly consume an unknown call's entire bound, never its cost.

        This is an explicit decision after inspecting the failure, not automatic
        recovery. The original price/token bounds must cover the whole request.
        Actual usage and cost remain unknown; settlement can never free this
        amount later. Execution/call IDs prevent redispatch of the sealed call.
        """
        if reason not in {"http_error_without_usage", "transport_finished_without_usage"}:
            raise ValueError("A documented completed-transport reason is required")
        evidence_id = _identifier(evidence_id, "evidence_id")
        with self._locked():
            ledger = self._read()
            item = ledger["reservations"][identifier]
            if item["state"] == "capped_unknown":
                if item["cap_reason"] != reason or item["cap_evidence_id"] != evidence_id:
                    raise BudgetError("The sealed unknown receipt is immutable")
                return dict(item)
            if item["state"] != "unknown":
                raise BudgetError("Only an unknown usage receipt can consume its bound permanently")
            if not item["metadata"].get("execution_id") or not item["metadata"].get("call_id"):
                raise BudgetError("Sealing unknown usage requires execution and call IDs")
            item.update(state="capped_unknown", cost_usd=None, cost_source="unknown",
                        capped_at=_now(), cap_reason=reason, cap_evidence_id=evidence_id)
            self._write(ledger)
            return dict(item)

    def reserve(self, kind, model, max_input_tokens, max_output_tokens,
                input_price_per_million, output_price_per_million, metadata=None):
        """Commit the maximum call cost before dispatch or raise BudgetError."""
        item = {"kind": _identifier(kind, "kind"), "model": _identifier(model, "model"),
                "max_input_tokens": _count(max_input_tokens, "max_input_tokens"),
                "max_output_tokens": _count(max_output_tokens, "max_output_tokens"),
                "input_price_per_million": str(_money(input_price_per_million, "input price")),
                "output_price_per_million": str(_money(output_price_per_million, "output price")),
                "metadata": _metadata(metadata), "state": "reserved", "reserved_at": _now()}
        bound = _cost(max_input_tokens, max_output_tokens,
                      Decimal(item["input_price_per_million"]), Decimal(item["output_price_per_million"]))
        item["bound_usd"] = str(bound)
        item["cost_usd"] = None
        with self._locked():
            ledger = self._read()
            summary = self._summary(ledger)
            if summary["halted"]:
                raise BudgetHalted("Evaluation stopped: unresolved usage or an exceeded request bound")
            capped = [ledger["reservations"][key] for key in summary["capped_unknown_reservations"]]
            if capped:
                if not item["metadata"].get("execution_id") or not item["metadata"].get("call_id"):
                    raise BudgetError("Calls after capped unknown usage require execution and new call IDs")
                if any(previous["metadata"]["call_id"] == item["metadata"]["call_id"] for previous in capped):
                    raise BudgetHalted("A capped unknown call must never be retried")
            with localcontext() as context:
                context.prec = 64
                if Decimal(summary["committed_usd"]) + bound > self.limit:
                    raise BudgetExceeded("The next call's upper bound would exceed the USD evaluation limit")
            identifier = str(uuid4())
            ledger["reservations"][identifier] = item
            self._write(ledger)
            return identifier

    def settle(self, identifier, input_tokens=None, output_tokens=None, cost_optional=None,
               duration_ms=None):
        """Persist usage; unknown usage retains the bound and halts new calls.

        Cost is derived conservatively from usage and reserved price caps unless
        an actual USD cost is supplied. Replaying an identical receipt is safe;
        conflicting final receipts fail. Breaches are saved before raising.
        """
        try:
            input_tokens = None if input_tokens is None else _count(input_tokens, "input_tokens")
            output_tokens = None if output_tokens is None else _count(output_tokens, "output_tokens")
            cost = None if cost_optional is None else _money(cost_optional, "actual cost")
            duration_ms = None if duration_ms is None else _count(duration_ms, "duration_ms")
        except ValueError as exc:
            # A malformed provider receipt cannot silently free or leave usable
            # capacity after a request may already have incurred a charge.
            self.settle(identifier)
            raise BudgetHalted("Invalid usage receipt; its full reservation is retained") from exc
        breached = False
        with self._locked():
            ledger = self._read()
            item = ledger["reservations"][identifier]
            if item["state"] == "capped_unknown":
                raise BudgetError("The sealed unknown receipt is immutable; its bound cannot be released")
            known_usage = input_tokens is not None and output_tokens is not None
            if known_usage and cost is None:
                cost = _cost(input_tokens, output_tokens,
                             Decimal(item["input_price_per_million"]), Decimal(item["output_price_per_million"]))
            if item["state"] in {"settled", "breached"}:
                if (item["input_tokens"] != input_tokens or item["output_tokens"] != output_tokens
                        or cost is None or Decimal(item["cost_usd"]) != cost):
                    raise BudgetError("Conflicting usage receipt; the saved settlement is unchanged")
                return dict(item)
            breached = known_usage and (input_tokens > item["max_input_tokens"]
                                       or output_tokens > item["max_output_tokens"]
                                       or cost > Decimal(item["bound_usd"]))
            item.update({"state": "breached" if breached else "settled" if known_usage else "unknown",
                         "input_tokens": input_tokens, "output_tokens": output_tokens,
                         "cost_usd": str(cost) if known_usage else None,
                         "cost_source": "provider" if cost_optional is not None else "price_caps" if known_usage else "unknown",
                         "settled_at": _now(), "duration_ms": duration_ms})
            self._write(ledger)
            receipt = dict(item)
        if breached:
            raise BudgetBreach("Provider usage or cost exceeded the reserved bound; evaluation stopped")
        return receipt
