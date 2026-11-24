"""
Helpers for compiling and testing YARA rules stored in the database.

All rules are compiled with one namespace per rule (``rule_<id>``) so that a
match can always be traced back to its ``Rule`` row via ``match.namespace``,
regardless of the identifier used inside the YARA source.
"""

import logging
from typing import Dict, Iterable, List, Optional, Tuple

import yara

logger = logging.getLogger(__name__)

# Upper bound for the sample text used when testing a rule from the UI.
MAX_TEST_TEXT_LENGTH = 100_000
# Upper bound for the number of string matches returned to the UI.
MAX_REPORTED_MATCHES = 50


def rule_namespace(rule) -> str:
    return f"rule_{rule.id}"


def rule_id_from_namespace(namespace: str) -> Optional[int]:
    try:
        return int(namespace.split("_", 1)[1])
    except (IndexError, ValueError):
        return None


def check_source(source: str) -> Optional[str]:
    """Return None if the YARA source compiles, or the error message otherwise."""
    if not source or not source.strip():
        return "The YARA rule is empty."
    try:
        yara.compile(source=source)
    except yara.Error as e:
        return str(e)
    return None


def compile_rules(rules: Iterable) -> Tuple[Optional[yara.Rules], List[Tuple[object, str]]]:
    """
    Compile several Rule objects into one ``yara.Rules``.

    Each rule is checked on its own first, so a single broken rule is skipped
    (and reported) instead of breaking validation for every other rule.

    Returns (compiled_rules_or_None, [(rule, error_message), ...]).
    """
    sources: Dict[str, str] = {}
    invalid: List[Tuple[object, str]] = []

    for rule in rules:
        error = check_source(rule.yara_rule)
        if error:
            invalid.append((rule, error))
            logger.error("Skipping YARA rule %s (%r): %s", rule.id, rule.name, error)
            continue
        sources[rule_namespace(rule)] = rule.yara_rule

    if not sources:
        return None, invalid

    try:
        return yara.compile(sources=sources), invalid
    except yara.Error as e:
        # Should not happen once every rule compiled individually (e.g. two
        # namespaces cannot collide), but never let it disable all rules.
        logger.error("Error compiling combined YARA rules: %s", e)
        return None, invalid


def byte_to_char_offset(data: bytes, byte_offset: int) -> int:
    """Convert a byte offset in UTF-8 ``data`` into a str character offset."""
    return len(data[:byte_offset].decode("utf-8", errors="ignore"))


def test_source(source: str, test_text: str = "") -> dict:
    """
    Compile a YARA source and optionally run it against a sample text.

    Returns a JSON-serializable dict:
        {
          "ok": bool,               # compiles
          "error": str | None,      # compilation error
          "rules": [str],           # YARA rule identifiers declared in the source
          "tested": bool,           # a sample text was provided
          "matched": bool,          # at least one rule matched the sample
          "matches": [{"rule", "identifier", "data", "offset"}],
          "truncated": bool,        # more matches than MAX_REPORTED_MATCHES
        }
    """
    result = {
        "ok": False,
        "error": None,
        "rules": [],
        "tested": bool(test_text),
        "matched": False,
        "matches": [],
        "truncated": False,
    }

    error = check_source(source)
    if error:
        result["error"] = error
        return result

    compiled = yara.compile(source=source)
    result["ok"] = True
    result["rules"] = [r.identifier for r in compiled]

    if not test_text:
        return result

    data = test_text[:MAX_TEST_TEXT_LENGTH].encode("utf-8")
    try:
        yara_matches = compiled.match(data=data, timeout=5)
    except yara.Error as e:
        result["error"] = f"Error running rule: {e}"
        return result

    result["matched"] = bool(yara_matches)
    for match in yara_matches:
        for string_match in match.strings:
            for instance in string_match.instances:
                if len(result["matches"]) >= MAX_REPORTED_MATCHES:
                    result["truncated"] = True
                    return result
                result["matches"].append({
                    "rule": match.rule,
                    "identifier": string_match.identifier,
                    "data": instance.matched_data.decode("utf-8", errors="replace"),
                    "offset": byte_to_char_offset(data, instance.offset),
                })
    return result
