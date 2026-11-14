"""
Local Obfuscation Module for RegulAI

Detects and masks sensitive information (PII) using regex patterns.
No external service required.
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class ObfuscationResult:
    """Result of obfuscation process."""
    masked_text: str
    context: Dict[str, str]  # Maps tokens like [EMAIL_1] to original values
    entities_found: List[Dict[str, str]]  # List of {type, original, masked, start, end}


# Entity patterns - order matters (more specific patterns first)
PATTERNS = {
    # Credit cards (with or without spaces/dashes)
    'CREDIT_CARD': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b|'
                   r'\b(?:\d{4}[-\s]?){3}\d{4}\b',

    # IBAN (International Bank Account Number)
    'IBAN': r'\b[A-Z]{2}\d{2}(?:\s?\d{4}){5,7}\b|\b[A-Z]{2}\d{22,30}\b',

    # Spanish DNI/NIE
    'DNI': r'\b[0-9]{8}[A-Za-z]\b|\b[XYZxyz][0-9]{7}[A-Za-z]\b',

    # Spanish NIF (company tax ID)
    'NIF': r'\b[A-HJ-NP-SUVWa-hj-np-suvw][0-9]{7}[0-9A-Ja-j]\b',

    # Passport numbers (generic)
    'PASSPORT': r'\b[A-Z]{1,2}[0-9]{6,9}\b',

    # Social Security Number (US format)
    'SSN': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',

    # Phone numbers (international and local formats)
    'PHONE': r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{0,4}\b',

    # Email addresses
    'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',

    # IP addresses (IPv4)
    'IP_ADDRESS': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',

    # IP addresses (IPv6) - simplified
    'IP_V6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',

    # URLs with potential sensitive data (API keys, tokens in query params)
    'API_KEY_URL': r'(?:api[_-]?key|token|secret|password|auth|bearer)[=:]\s*[A-Za-z0-9_\-]{16,}',

    # Generic API keys/tokens (long alphanumeric strings that look like secrets)
    'API_KEY': r'\b(?:sk|pk|api|key|token|secret)[-_]?[A-Za-z0-9]{20,}\b',

    # AWS Access Keys
    'AWS_KEY': r'\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b',

    # Private keys (partial detection)
    'PRIVATE_KEY': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',

    # Dates of birth (common formats) - be careful, can have false positives
    'DATE_BIRTH': r'\b(?:0?[1-9]|[12][0-9]|3[01])[-/.](?:0?[1-9]|1[012])[-/.](?:19|20)\d{2}\b',

    # Spanish postal codes
    'POSTAL_CODE_ES': r'\b(?:0[1-9]|[1-4][0-9]|5[0-2])\d{3}\b',

    # Generic numbers that might be account numbers (8+ digits)
    'ACCOUNT_NUMBER': r'\b\d{8,12}\b',
}

# Patterns to exclude (reduce false positives)
EXCLUDE_PATTERNS = [
    r'\b\d{4}\b',  # Years alone
    r'\b(?:19|20)\d{2}\b',  # Years
    r'\b\d{1,2}:\d{2}\b',  # Times
]


def compile_patterns() -> Dict[str, re.Pattern]:
    """Compile all regex patterns."""
    compiled = {}
    for name, pattern in PATTERNS.items():
        try:
            compiled[name] = re.compile(pattern, re.IGNORECASE if name not in ['AWS_KEY', 'PRIVATE_KEY'] else 0)
        except re.error as e:
            print(f"Error compiling pattern {name}: {e}")
    return compiled


COMPILED_PATTERNS = compile_patterns()


def should_exclude(text: str, match_text: str) -> bool:
    """Check if a match should be excluded (false positive)."""
    # Exclude very short matches
    if len(match_text) < 4:
        return True

    # Exclude common words that might match patterns
    common_words = {'http', 'https', 'www', 'com', 'org', 'net', 'gmail', 'yahoo', 'hotmail'}
    if match_text.lower() in common_words:
        return True

    return False


def obfuscate_local(
    text: str,
    detect_types: Optional[List[str]] = None,
    exclude_types: Optional[List[str]] = None
) -> ObfuscationResult:
    """
    Obfuscate sensitive information in text using local regex patterns.

    Args:
        text: The text to obfuscate
        detect_types: List of entity types to detect (None = all)
        exclude_types: List of entity types to exclude

    Returns:
        ObfuscationResult with masked text and context mapping
    """
    if not text:
        return ObfuscationResult(masked_text=text, context={}, entities_found=[])

    # Determine which patterns to use
    patterns_to_use = COMPILED_PATTERNS.copy()

    if detect_types:
        patterns_to_use = {k: v for k, v in patterns_to_use.items() if k in detect_types}

    if exclude_types:
        patterns_to_use = {k: v for k, v in patterns_to_use.items() if k not in exclude_types}

    # Find all matches
    all_matches = []
    for entity_type, pattern in patterns_to_use.items():
        for match in pattern.finditer(text):
            match_text = match.group()
            if not should_exclude(text, match_text):
                all_matches.append({
                    'type': entity_type,
                    'original': match_text,
                    'start': match.start(),
                    'end': match.end(),
                })

    # Sort by position (descending) to replace from end to start
    all_matches.sort(key=lambda x: x['start'], reverse=True)

    # Remove overlapping matches (keep the first/longer one)
    filtered_matches = []
    covered_ranges = []

    for match in sorted(all_matches, key=lambda x: (x['start'], -(x['end'] - x['start']))):
        start, end = match['start'], match['end']
        is_overlapping = any(
            (start >= r[0] and start < r[1]) or (end > r[0] and end <= r[1])
            for r in covered_ranges
        )
        if not is_overlapping:
            filtered_matches.append(match)
            covered_ranges.append((start, end))

    # Sort again for replacement (descending position)
    filtered_matches.sort(key=lambda x: x['start'], reverse=True)

    # Generate masked text and context
    masked_text = text
    context = {}
    entities_found = []
    counters = {}

    for match in filtered_matches:
        entity_type = match['type']
        original = match['original']

        # Generate token
        counters[entity_type] = counters.get(entity_type, 0) + 1
        token = f"[{entity_type}_{counters[entity_type]}]"

        # Replace in text
        masked_text = masked_text[:match['start']] + token + masked_text[match['end']:]

        # Store in context
        context[token] = original

        # Add to entities found
        entities_found.append({
            'type': entity_type,
            'original': original,
            'masked': token,
            'start': match['start'],
            'end': match['end'],
        })

    return ObfuscationResult(
        masked_text=masked_text,
        context=context,
        entities_found=list(reversed(entities_found))  # Restore original order
    )


def deobfuscate(masked_text: str, context: Dict[str, str]) -> str:
    """
    Restore original text from masked text using context.

    Args:
        masked_text: Text with tokens like [EMAIL_1]
        context: Mapping of tokens to original values

    Returns:
        Original text with all tokens replaced
    """
    if not context:
        return masked_text

    result = masked_text
    for token, original in context.items():
        result = result.replace(token, original)
    return result


def deobfuscate_response(response_text: str, context: Dict[str, str]) -> Tuple[str, List[str]]:
    """
    Restore original values in AI response, with tracking of what was restored.

    Args:
        response_text: AI response that may contain obfuscation tokens
        context: Mapping of tokens to original values

    Returns:
        Tuple of (restored_text, list_of_restored_tokens)
    """
    if not context:
        return response_text, []

    restored = []
    result = response_text

    for token, original in context.items():
        if token in result:
            result = result.replace(token, original)
            restored.append(token)

    return result, restored


# Convenience function for common PII types
def obfuscate_pii(text: str) -> ObfuscationResult:
    """Obfuscate common PII (emails, phones, IDs, etc.)."""
    pii_types = ['EMAIL', 'PHONE', 'DNI', 'NIF', 'PASSPORT', 'SSN', 'CREDIT_CARD', 'IBAN']
    return obfuscate_local(text, detect_types=pii_types)


def obfuscate_secrets(text: str) -> ObfuscationResult:
    """Obfuscate secrets (API keys, tokens, private keys)."""
    secret_types = ['API_KEY', 'API_KEY_URL', 'AWS_KEY', 'PRIVATE_KEY']
    return obfuscate_local(text, detect_types=secret_types)


def obfuscate_all(text: str) -> ObfuscationResult:
    """Obfuscate all detectable sensitive information."""
    return obfuscate_local(text)


# Example entity types for UI
ENTITY_TYPE_INFO = {
    'EMAIL': {'label': 'Email', 'icon': 'solar:letter-bold', 'color': '#e91e63'},
    'PHONE': {'label': 'Phone', 'icon': 'solar:phone-bold', 'color': '#9c27b0'},
    'DNI': {'label': 'DNI/NIE', 'icon': 'solar:card-bold', 'color': '#673ab7'},
    'NIF': {'label': 'NIF', 'icon': 'solar:buildings-bold', 'color': '#3f51b5'},
    'PASSPORT': {'label': 'Passport', 'icon': 'solar:passport-bold', 'color': '#2196f3'},
    'SSN': {'label': 'SSN', 'icon': 'solar:shield-user-bold', 'color': '#00bcd4'},
    'CREDIT_CARD': {'label': 'Credit Card', 'icon': 'solar:card-bold', 'color': '#009688'},
    'IBAN': {'label': 'IBAN', 'icon': 'solar:wallet-bold', 'color': '#4caf50'},
    'IP_ADDRESS': {'label': 'IP Address', 'icon': 'solar:server-bold', 'color': '#8bc34a'},
    'API_KEY': {'label': 'API Key', 'icon': 'solar:key-bold', 'color': '#ff9800'},
    'AWS_KEY': {'label': 'AWS Key', 'icon': 'solar:cloud-bold', 'color': '#ff5722'},
    'PRIVATE_KEY': {'label': 'Private Key', 'icon': 'solar:lock-bold', 'color': '#f44336'},
}
