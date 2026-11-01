"""Offline masking by explicit patterns; never infer private data from prose."""
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
import threading
import time
import unicodedata

DETECTOR_VERSION = 'regulai-local-v6-patterns'
MAX_BATCH_BYTES = 512_000
MAX_SEGMENTS = 4096
_LOCK = threading.Lock()
_PLACEHOLDER = re.compile(r'\[\[REGULAI_(?:PERSON|LOCATION|ORGANIZATION|EMAIL|PHONE|ID|ACCOUNT|CARD|SECRET)\]\]')
_SECRET_KEY = re.compile(r'^(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|contrase[ñn]a|secret(?:[_ -]?key)?|authorization|private[_ -]?key)$', re.I)
_SOURCE_ALIAS = re.compile(r'[SF][1-9]\d{0,3}')
_STRUCTURAL_KEYS = frozenset({'claims', 'text', 'citations', 'source_id', 'alias', 'quote', 'answer',
                            'abstain', 'reason', 'sources', 'id', 'locator', 'excerpt', 'role', 'content'})
_PATTERNS = [
    ('EMAIL', re.compile(r'(?<![\w.+-])[\w.!#$%&\'*+/=?^`{|}~-]{1,64}@[\w-]+(?:\.[\w-]+)+', re.I)),
    # Word addresses are ambiguous in free prose. Require an explicit contact
    # field and a bounded local part/domain rather than masking "at" or "dot".
    ('EMAIL', re.compile(r'\b(?:correo|e-?mail|contacto)(?:[ \t]+[\w-]{1,24}){0,2}[ \t]*:[ \t]*'
        r'(?P<value>[\w.+-]{1,64}(?:[ \t]+[\w.+-]{1,64}){0,3}[ \t]+(?:arroba|at)[ \t]+'
        r'[\w-]{1,63}(?:[ \t]+(?:punto|dot)[ \t]+[\w-]{1,63}){1,4})(?![\w-])', re.I)),
    ('ID', re.compile(r'\b(?:\d(?:[ \t.-]?\d){7}[ \t.-]?[A-Z]|[XYZKLM][ \t.-]?\d(?:[ \t.-]?\d){6}[ \t.-]?[A-Z]|[ABCDEFGHJNPQRSUVW][ \t.-]?\d(?:[ \t.-]?\d){6}[ \t.-]?[0-9A-J])\b', re.I)),
    ('ACCOUNT', re.compile(r'\b[A-Z]{2}\d{2}(?:[ \t]?\d){10,30}\b')),
    ('PHONE', re.compile(r'(?<!\w)(?:\+34[ .-]?)?[6789]\d{2}[ .-]?\d{3}[ .-]?\d{3}(?!\w)')),
    ('PHONE', re.compile(r'(?<!\w)\+\d{1,3}[ .-]?(?:\(\d{1,4}\)[ .-]?)?\d(?:[ .-]?\d){7,13}(?!\w)')),
    ('CARD', re.compile(r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)')),
    ('SECRET', re.compile(r'-----BEGIN (?:[A-Z0-9 ]{0,32})PRIVATE KEY-----[\s\S]{0,16000}?-----END (?:[A-Z0-9 ]{0,32})PRIVATE KEY-----')),
    ('SECRET', re.compile(r'\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{12,512}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|(?:AKIA|ASIA)[A-Z0-9]{16})\b')),
    ('SECRET', re.compile(r'\beyJ[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,2048}\b')),
    ('SECRET', re.compile(r'\bBearer\s+(?P<value>[A-Za-z0-9._~+/=-]{8,4096})', re.I)),
    ('SECRET', re.compile(r'\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|contrase[ñn]a|secret(?:[_ -]?key)?)\s*[=:]\s*[\"\']?(?P<value>[^\s,;\"\'{}]{3,4096})', re.I)),
    ('SECRET', re.compile(r'\b[a-z][a-z0-9+.-]{1,16}://(?P<value>[^/\s:@]{1,128}:[^/\s@]{1,512})@', re.I)),
    ('PERSON', re.compile(r'\b(?:nombre(?: completo)?|full name|name|titular|cliente)\s*:\s*(?P<value>[^\W\d_]+(?:[ \t]+[^\W\d_]+){0,3})', re.I)),
]


def detector_metadata():
    """Fingerprint the rules actually used, without loading a statistical model."""
    patterns = [(category, pattern.pattern, pattern.flags) for category, pattern in _PATTERNS]
    patterns.extend((name, pattern.pattern, pattern.flags) for name, pattern in
                    (('secret_key', _SECRET_KEY), ('placeholder', _PLACEHOLDER), ('source_alias', _SOURCE_ALIAS)))
    digest = sha256(json.dumps(patterns, ensure_ascii=False).encode('utf-8')).hexdigest()
    return {'backend': 'local', 'detector_version': DETECTOR_VERSION,
            'detection': 'explicit_patterns', 'patterns_sha256': digest}


def _luhn(value):
    digits = [int(char) for char in value if char.isdigit() and char.isascii()]
    if len(digits) < 13 or len(set(digits)) == 1:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        doubled = digit * 2 if index % 2 else digit
        total += doubled - 9 if doubled > 9 else doubled
    return total % 10 == 0


def _matching_view(text):
    """Normalize pattern input only, retaining offsets into the untouched text."""
    normalized, offsets = [], []
    for index, char in enumerate(text):
        if char in '\u200b\u200c\u200d\u2060\ufeff':
            continue
        for token in unicodedata.normalize('NFKC', char):
            if token.isdecimal():
                token = str(unicodedata.decimal(token))
            elif token in '\u2010\u2011\u2012\u2013\u2014\u2015\u2212':
                token = '-'
            normalized.append(token)
            offsets.append(index)
    return ''.join(normalized), offsets


def detect_spans(text, view=None):
    """Raw offsets the detector replaces in plain text (before merging).

    Shared by masking and by incremental delivery, so both use one detector.
    ``view`` may pass a precomputed ``_matching_view(text)``.
    """
    spans = []
    matching, offsets = view or _matching_view(text)
    # Normalization can introduce delimiters inside a secret. Keep the original
    # matches as well so a normalized view can only add to their masked extent.
    views = [(text, None)] + ([(matching, offsets)] if matching != text else [])
    for candidate, mapping in views:
        for category, pattern in _PATTERNS:
            for match in pattern.finditer(candidate):
                start, end = match.span('value') if 'value' in pattern.groupindex else match.span()
                if category == 'CARD' and not _luhn(candidate[start:end]):
                    continue
                if mapping is not None:
                    start, end = mapping[start], mapping[end - 1] + 1
                spans.append((start, end, category))
    return spans


def _mask_plain(text, deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('Local masking deadline exceeded.')
    protected = [match.span() for match in _PLACEHOLDER.finditer(text)]
    spans = detect_spans(text)
    # A statistical entity label is not evidence of private data. In particular,
    # it confused task variables and ordinary words with people and locations.
    # Only explicit pattern matches above may change the user's text.
    if time.monotonic() >= deadline:
        raise TimeoutError('Local masking deadline exceeded.')
    merged = []
    for start, end, category in sorted(spans, key=lambda item: (item[0], -item[1])):
        # Protect only our exact fixed markers, never arbitrary bracketed input.
        if any(start >= left and end <= right for left, right in protected):
            continue
        if merged and start < merged[-1][1]:
            previous = merged[-1]
            merged[-1] = (previous[0], max(end, previous[1]), previous[2])
        else:
            merged.append((start, end, category))
    for start, end, category in reversed(merged):
        text = text[:start] + f'[[REGULAI_{category}]]' + text[end:]
    return text


class _Pairs(list):
    """JSON object preserving duplicate keys, unlike an ordinary dict."""


class _Number(str):
    """JSON numeric token preserving precision and spelling."""


def _reject_json_constant(value):
    raise ValueError('Nonfinite JSON')


def _mask_segment(text, deadline):
    if not text.lstrip().startswith(('{', '[')):
        return _mask_plain(text, deadline)
    try:
        value = json.loads(text, object_pairs_hook=_Pairs, parse_int=_Number, parse_float=_Number,
                           parse_constant=_reject_json_constant)
    except (ValueError, RecursionError):
        return _mask_plain(text, deadline)

    def encode(value):
        if isinstance(value, _Pairs):
            pairs = []
            for key, item in value:
                masked_key = key if key in _STRUCTURAL_KEYS else _mask_plain(key, deadline)
                if _SECRET_KEY.fullmatch(key):
                    encoded = json.dumps('[[REGULAI_SECRET]]')
                elif key in {'id', 'source_id', 'alias'} and isinstance(item, str) and _SOURCE_ALIAS.fullmatch(item):
                    # Only the short, fixed citation-alias grammar is structural.
                    # Arbitrary data stored under these keys still goes through detection.
                    encoded = json.dumps(item)
                else:
                    encoded = encode(item)
                pairs.append(json.dumps(masked_key, ensure_ascii=False) + ':' + encoded)
            return '{' + ','.join(pairs) + '}'
        if isinstance(value, _Number):
            # JSON type is not a privacy exemption. Inspect the exact token and
            # its integer value so exponent notation cannot hide a phone/card.
            # Bound normalization before formatting; 1e100000000 must not expand.
            candidates = [str(value)]
            try:
                number = Decimal(value)
                if (0 <= number.adjusted() <= 30
                        and number == number.to_integral_value()):
                    candidates.append(format(number.to_integral_value(), 'f'))
            except InvalidOperation as error:
                raise ValueError('Unsupported JSON numeric token for local masking.') from error
            for candidate in dict.fromkeys(candidates):
                masked = _mask_plain(candidate, deadline)
                if masked != candidate:
                    # A sensitive number becomes a JSON marker string. Partial
                    # replacement would leave an invalid or misleading number.
                    marker = _PLACEHOLDER.search(masked)
                    if marker is None:
                        raise ValueError('Invalid local masking numeric result.')
                    return json.dumps(marker.group())
            return str(value)
        if isinstance(value, str):
            return json.dumps(_mask_plain(value, deadline), ensure_ascii=False)
        if isinstance(value, list):
            return '[' + ','.join(encode(item) for item in value) + ']'
        return json.dumps(value, allow_nan=False)

    return encode(value)


def mask_local_texts(texts, *, language='', timeout=10):
    """Transform a complete batch or raise; callers must stop on every failure."""
    if language not in ('', 'es', 'en'):
        raise ValueError('Local masking currently supports Spanish and English inputs only.')
    if (not isinstance(texts, list) or not texts or len(texts) > MAX_SEGMENTS
            or any(not isinstance(text, str) for text in texts)):
        raise ValueError('Invalid local masking batch.')
    if sum(len(text.encode('utf-8')) for text in texts) > MAX_BATCH_BYTES:
        raise ValueError('Local masking batch is too large; no truncation is permitted.')
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise TimeoutError('Local masking deadline exceeded.')
    deadline = time.monotonic() + timeout
    if not _LOCK.acquire(timeout=timeout):
        raise TimeoutError('Local masking capacity deadline exceeded.')
    try:
        result = [_mask_segment(text, deadline) for text in texts]
        if time.monotonic() >= deadline:
            raise TimeoutError('Local masking deadline exceeded.')
        return result
    finally:
        _LOCK.release()
