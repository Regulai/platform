"""
Obfuscation Service for RegulAI

Integrates YARA rules with obfuscation to detect and mask sensitive data.
"""

import re
import yara
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from .models import Rule, Conversation


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
    """Compile multiple YARA rules into a single Rules object."""
    if not rules:
        return None

    combined_source = "\n".join(rule.yara_rule for rule in rules)

    try:
        return yara.compile(source=combined_source)
    except yara.SyntaxError as e:
        # If combined fails, try compiling individually
        valid_sources = []
        for rule in rules:
            try:
                yara.compile(source=rule.yara_rule)
                valid_sources.append(rule.yara_rule)
            except yara.SyntaxError:
                continue

        if valid_sources:
            return yara.compile(source="\n".join(valid_sources))
        return None


def get_obfuscation_rules(company_id: int) -> List[Rule]:
    """Get active obfuscation rules for a company."""
    return list(Rule.objects.filter(
        rules_group__company_id=company_id,
        action="obfuscate",
        active=True
    ).select_related('rules_group'))


def extract_matches_from_yara(yara_matches, text: str, rules: List[Rule]) -> List[dict]:
    """Extract match positions from YARA results."""
    matches = []
    rule_map = {r.name: r for r in rules}

    for match in yara_matches:
        rule_name = match.rule
        rule = rule_map.get(rule_name)

        if not rule:
            continue

        for string_match in match.strings:
            for instance in string_match.instances:
                matches.append({
                    'rule_name': rule_name,
                    'rule': rule,
                    'original': instance.matched_data.decode('utf-8', errors='replace'),
                    'start': instance.offset,
                    'end': instance.offset + instance.matched_length,
                })

    return matches


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
        existing_context: Existing obfuscation context to append to

    Returns:
        ObfuscationResult with obfuscated text and context
    """
    if not text:
        return ObfuscationResult(text="", matches=[], context={})

    # Get active obfuscation rules
    rules = get_obfuscation_rules(company_id)

    if not rules:
        return ObfuscationResult(text=text, matches=[], context=existing_context or {})

    # Compile YARA rules
    compiled_rules = compile_yara_rules(rules)

    if not compiled_rules:
        return ObfuscationResult(text=text, matches=[], context=existing_context or {})

    # Run YARA scan
    try:
        yara_matches = compiled_rules.match(data=text.encode('utf-8'))
    except Exception:
        return ObfuscationResult(text=text, matches=[], context=existing_context or {})

    # Extract matches
    raw_matches = extract_matches_from_yara(yara_matches, text, rules)

    if not raw_matches:
        return ObfuscationResult(text=text, matches=[], context=existing_context or {})

    # Sort by position (start) and remove overlaps
    raw_matches.sort(key=lambda x: (x['start'], -(x['end'] - x['start'])))
    filtered_matches = []
    covered_ranges = []

    for match in raw_matches:
        start, end = match['start'], match['end']
        is_overlapping = any(
            (start >= r[0] and start < r[1]) or (end > r[0] and end <= r[1])
            for r in covered_ranges
        )
        if not is_overlapping:
            filtered_matches.append(match)
            covered_ranges.append((start, end))

    # Generate tokens and build context
    context = dict(existing_context) if existing_context else {}
    counters = {}
    obfuscation_matches = []

    # Count existing tokens to continue numbering
    for token in context.keys():
        # Parse token like [EMAIL_1] to get type and number
        match = re.match(r'\[([A-Z_]+)_(\d+)\]', token)
        if match:
            token_type = match.group(1)
            token_num = int(match.group(2))
            counters[token_type] = max(counters.get(token_type, 0), token_num)

    # Sort by position descending for replacement
    filtered_matches.sort(key=lambda x: x['start'], reverse=True)

    result_text = text
    for match in filtered_matches:
        rule = match['rule']
        original = match['original']

        # Check if this exact value is already in context
        existing_token = None
        for token, value in context.items():
            if value == original:
                existing_token = token
                break

        if existing_token:
            token = existing_token
        else:
            # Generate new token
            token_template = rule.obfuscate_token or "[{name}_{n}]"
            token_type = rule.name.upper().replace(" ", "_")

            counters[token_type] = counters.get(token_type, 0) + 1
            token = token_template.format(name=token_type, n=counters[token_type])

            context[token] = original

        # Replace in text
        result_text = result_text[:match['start']] + token + result_text[match['end']:]

        obfuscation_matches.append(ObfuscationMatch(
            rule_name=rule.name,
            original=original,
            token=token,
            start=match['start'],
            end=match['end']
        ))

    return ObfuscationResult(
        text=result_text,
        matches=list(reversed(obfuscation_matches)),
        context=context
    )


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
    for token, original in context.items():
        result = result.replace(token, original)

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
