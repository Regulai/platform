"""
Obfuscation Service for RegulAI

Integrates YARA rules with obfuscation to detect and mask sensitive data.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import yara

from .models import Rule, Conversation
from .yara_utils import byte_to_char_offset, compile_rules, rule_id_from_namespace

logger = logging.getLogger(__name__)

DEFAULT_TOKEN_TEMPLATE = "[{name}_{n}]"


@dataclass
class ObfuscationMatch:
    """A single obfuscation match."""
    rule_name: str
    original: str
    token: str
    start: int
    end: int


@dataclass
class ObfuscationResult:
    """Result of obfuscation process."""
    text: str  # Obfuscated text
    matches: List[ObfuscationMatch]
    context: Dict[str, str]  # Token -> original mapping


def compile_yara_rules(rules: List[Rule]) -> Optional[yara.Rules]:
    """
    Compile rules into a single Rules object, one namespace per rule
    (``rule_<id>``). Rules that do not compile are skipped and logged.
    """
    if not rules:
        return None
    compiled, _invalid = compile_rules(rules)
    return compiled


def get_obfuscation_rules(company_id: int) -> List[Rule]:
    """Get active obfuscation rules for a company."""
    return list(Rule.objects.filter(
        rules_group__company_id=company_id,
        action="obfuscate",
        active=True
    ).select_related('rules_group'))


def extract_matches_from_yara(yara_matches, data: bytes, rules: List[Rule]) -> List[dict]:
    """
    Extract match positions from YARA results.

    Matches are mapped back to their Rule through the compile namespace
    (``rule_<id>``), not through the YARA identifier, which is free text
    written by the user and usually differs from ``Rule.name``.

    YARA reports byte offsets over the UTF-8 encoded text; they are converted
    to character offsets so they can be used to slice the original ``str``.
    Leading/trailing whitespace captured by a pattern is left out of the match.
    """
    matches = []
    rules_by_id = {r.id: r for r in rules}

    for match in yara_matches:
        rule = rules_by_id.get(rule_id_from_namespace(match.namespace))
        if not rule:
            continue

        for string_match in match.strings:
            for instance in string_match.instances:
                original = instance.matched_data.decode('utf-8', errors='replace')
                start = byte_to_char_offset(data, instance.offset)

                stripped = original.strip()
                if not stripped:
                    continue
                start += len(original) - len(original.lstrip())

                matches.append({
                    'rule_name': rule.name,
                    'rule': rule,
                    'original': stripped,
                    'start': start,
                    'end': start + len(stripped),
                })

    return matches


def _remove_overlaps(raw_matches: List[dict]) -> List[dict]:
    """Keep the earliest (and, on ties, longest) match among overlapping ones."""
    raw_matches.sort(key=lambda x: (x['start'], -(x['end'] - x['start'])))
    filtered = []
    last_end = -1
    for match in raw_matches:
        if match['start'] >= last_end:
            filtered.append(match)
            last_end = match['end']
    return filtered


def _build_token(rule: Rule, n: int) -> str:
    token_type = rule.name.upper().replace(" ", "_")
    template = rule.obfuscate_token or DEFAULT_TOKEN_TEMPLATE
    try:
        return template.format(name=token_type, n=n)
    except (KeyError, IndexError, ValueError):
        return DEFAULT_TOKEN_TEMPLATE.format(name=token_type, n=n)


def _token_for(rule: Rule, original: str, context: Dict[str, str], counters: Dict[int, int]) -> str:
    """
    Return the token for ``original``: the existing one if this value was
    already masked in the conversation, otherwise the next free token for the
    rule. A token already mapped to a different value is never reused.
    """
    for token, value in context.items():
        if value == original:
            return token

    n = counters.get(rule.id, 0)
    while True:
        n += 1
        token = _build_token(rule, n)
        if token not in context:
            break
    counters[rule.id] = n
    context[token] = original
    return token


def obfuscate_text(
    text: str,
    company_id: int,
    existing_context: Optional[Dict[str, str]] = None
) -> ObfuscationResult:
    """
    Obfuscate sensitive data in text using YARA rules.

    Args:
        text: Text to obfuscate
        company_id: Company ID to get rules for
        existing_context: Existing obfuscation context to append to (tokens
            already used in the conversation are reused/never overwritten)

    Returns:
        ObfuscationResult with obfuscated text and the full (existing + new) context
    """
    context = dict(existing_context) if existing_context else {}

    if not text:
        return ObfuscationResult(text="", matches=[], context=context)

    rules = get_obfuscation_rules(company_id)
    if not rules:
        return ObfuscationResult(text=text, matches=[], context=context)

    compiled_rules = compile_yara_rules(rules)
    if not compiled_rules:
        return ObfuscationResult(text=text, matches=[], context=context)

    data = text.encode('utf-8')
    try:
        yara_matches = compiled_rules.match(data=data)
    except yara.Error as e:
        logger.error("YARA obfuscation scan failed: %s", e)
        return ObfuscationResult(text=text, matches=[], context=context)

    filtered_matches = _remove_overlaps(extract_matches_from_yara(yara_matches, data, rules))
    if not filtered_matches:
        return ObfuscationResult(text=text, matches=[], context=context)

    # Assign tokens in reading order so numbering follows the text
    counters: Dict[int, int] = {}
    obfuscation_matches = []
    for match in filtered_matches:
        token = _token_for(match['rule'], match['original'], context, counters)
        obfuscation_matches.append(ObfuscationMatch(
            rule_name=match['rule_name'],
            original=match['original'],
            token=token,
            start=match['start'],
            end=match['end'],
        ))

    # Replace from the end so earlier offsets stay valid
    result_text = text
    for m in reversed(obfuscation_matches):
        result_text = result_text[:m.start] + m.token + result_text[m.end:]

    return ObfuscationResult(text=result_text, matches=obfuscation_matches, context=context)


def deobfuscate_text(text: str, context: Dict[str, str]) -> str:
    """
    Restore original values in text using context.

    Args:
        text: Text with obfuscation tokens
        context: Mapping of tokens to original values

    Returns:
        Text with tokens replaced by original values
    """
    if not context:
        return text

    result = text
    # Longest tokens first so e.g. [EMAIL_1] never clobbers part of [EMAIL_10]
    for token in sorted(context, key=len, reverse=True):
        result = result.replace(token, context[token])

    return result


def obfuscate_message(
    content: str,
    conversation: Conversation,
    company_id: int
) -> Tuple[str, bool, List[str]]:
    """
    Obfuscate a message and update conversation context.

    Args:
        content: Message content to obfuscate
        conversation: Conversation to store context in
        company_id: Company ID for rules

    Returns:
        Tuple of (obfuscated_text, is_obfuscated, list_of_entity_types)
    """
    existing_context = conversation.get_obfuscation_context()

    result = obfuscate_text(content, company_id, existing_context)

    if result.matches:
        # Update conversation context
        conversation.set_obfuscation_context(result.context)
        conversation.save(update_fields=['obfuscation_context'])

        entity_types = list(set(m.rule_name for m in result.matches))
        return result.text, True, entity_types

    return content, False, []


def deobfuscate_response(response: str, conversation: Conversation) -> str:
    """
    Deobfuscate an AI response using conversation context.

    Args:
        response: AI response text
        conversation: Conversation with obfuscation context

    Returns:
        Deobfuscated text for display
    """
    context = conversation.get_obfuscation_context()
    return deobfuscate_text(response, context)
