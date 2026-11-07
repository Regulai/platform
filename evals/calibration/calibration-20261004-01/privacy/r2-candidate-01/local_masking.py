"""Offline CPU masking. Detection is bounded and fallible; never downloads a model."""
from functools import lru_cache
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from importlib import metadata, util
import json
from pathlib import Path
import re
import threading
import time
import unicodedata

DETECTOR_VERSION = 'regulai-local-v4'
SPACY_VERSION = '3.8.16'
MODEL_NAME = 'xx_ent_wiki_sm'
MODEL_VERSION = '3.8.0'
MODEL_ARTIFACT_SHA256 = '6f3c4b853852ea9e9d2dc76cc950dddb10a7e4c42d813308caefe6c5e8be2f0a'
MAX_BATCH_BYTES = 512_000
MAX_SEGMENTS = 4096
_LOCK = threading.Lock()
_PLACEHOLDER = re.compile(r'\[\[REGULAI_(?:PERSON|LOCATION|ORGANIZATION|EMAIL|PHONE|ID|ACCOUNT|CARD|SECRET)\]\]')
_SECRET_KEY = re.compile(r'^(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|contrase[ñn]a|secret(?:[_ -]?key)?|authorization|private[_ -]?key)$', re.I)
_SOURCE_ALIAS = re.compile(r'[SF][1-9]\d{0,3}')
_FIELD_LABEL = re.compile(r'^(?:correo|email|dni|nie|iban|tel[eé]fono|tarjeta|nombre(?: completo)?|full name|name|titular|cliente)\s*:\s*', re.I | re.M)
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
    """Observe installed versions and model data without importing/loading spaCy."""
    try:
        spacy_version, model_version = metadata.version('spacy'), metadata.version(MODEL_NAME)
        spec = util.find_spec(MODEL_NAME)
        if spacy_version != SPACY_VERSION or model_version != MODEL_VERSION or not spec or not spec.origin:
            raise RuntimeError('Local masking requires the pinned runtime and model.')
        data = Path(spec.origin).parent / f'{MODEL_NAME}-{MODEL_VERSION}'
        files = sorted(path for path in data.rglob('*') if path.is_file() and '__pycache__' not in path.parts)
        if not files or not (data / 'ner' / 'model').is_file():
            raise RuntimeError('Local masking model data is unavailable.')
        digest = sha256()
        for path in files:
            digest.update(path.relative_to(data).as_posix().encode('utf-8') + b'\0')
            digest.update(sha256(path.read_bytes()).digest())
        return {'backend': 'local', 'detector_version': DETECTOR_VERSION,
                'spacy_version': spacy_version, 'model_name': MODEL_NAME, 'model_version': model_version,
                'model_artifact_sha256': MODEL_ARTIFACT_SHA256, 'model_files_sha256': digest.hexdigest()}
    except (metadata.PackageNotFoundError, OSError, ImportError) as error:
        raise RuntimeError('Local masking dependencies are unavailable; install the pinned requirements.') from error


@lru_cache(maxsize=1)
def _load_model():
    import xx_ent_wiki_sm
    identity = detector_metadata()
    nlp = xx_ent_wiki_sm.load()
    if nlp.meta.get('version') != MODEL_VERSION or nlp.pipe_names != ['ner']:
        raise RuntimeError('Incompatible local masking model.')
    nlp.max_length = MAX_BATCH_BYTES
    return nlp, identity


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


def _mask_plain(text, nlp, deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('Local masking deadline exceeded.')
    protected = [match.span() for match in _PLACEHOLDER.finditer(text)]
    spans = []
    matching, offsets = _matching_view(text)
    for category, pattern in _PATTERNS:
        for match in pattern.finditer(matching):
            start, end = match.span('value') if 'value' in pattern.groupindex else match.span()
            if category == 'CARD' and not _luhn(matching[start:end]):
                continue
            spans.append((offsets[start], offsets[end - 1] + 1, category))
    labels = {'PER': 'PERSON', 'PERSON': 'PERSON', 'LOC': 'LOCATION', 'GPE': 'LOCATION', 'ORG': 'ORGANIZATION'}
    field_labels = [match.span() for match in _FIELD_LABEL.finditer(text)]
    for entity in nlp(text).ents:
        if entity.label_ in labels:
            start, end = entity.start_char, entity.end_char
            for left, right in field_labels:
                if left <= start < right:
                    start = min(end, right)
            if start < end:
                spans.append((start, end, labels[entity.label_]))
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


def _mask_segment(text, nlp, deadline):
    if not text.lstrip().startswith(('{', '[')):
        return _mask_plain(text, nlp, deadline)
    try:
        value = json.loads(text, object_pairs_hook=_Pairs, parse_int=_Number, parse_float=_Number,
                           parse_constant=_reject_json_constant)
    except (ValueError, RecursionError):
        return _mask_plain(text, nlp, deadline)

    def encode(value):
        if isinstance(value, _Pairs):
            pairs = []
            for key, item in value:
                masked_key = key if key in _STRUCTURAL_KEYS else _mask_plain(key, nlp, deadline)
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
                masked = _mask_plain(candidate, nlp, deadline)
                if masked != candidate:
                    # A sensitive number becomes a JSON marker string. Partial
                    # replacement would leave an invalid or misleading number.
                    marker = _PLACEHOLDER.search(masked)
                    if marker is None:
                        raise ValueError('Invalid local masking numeric result.')
                    return json.dumps(marker.group())
            return str(value)
        if isinstance(value, str):
            return json.dumps(_mask_plain(value, nlp, deadline), ensure_ascii=False)
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
        nlp, loaded_identity = _load_model()
        if detector_metadata() != loaded_identity:
            raise RuntimeError('Local masking model changed; restart and review the frozen configuration.')
        result = [_mask_segment(text, nlp, deadline) for text in texts]
        if time.monotonic() >= deadline:
            raise TimeoutError('Local masking deadline exceeded.')
        return result
    finally:
        _LOCK.release()
