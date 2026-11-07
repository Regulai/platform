"""Conversation scoped value aliases, not entity recognition or identity linkage."""
import hashlib
import hmac
import re
import secrets
import time
import unicodedata

from django.conf import settings
from front.local_masking import _PATTERNS, _PLACEHOLDER, _matching_view, _luhn
from front.models import ConversationAlias

TOKEN = re.compile(r'\[\[R_[A-Z]+_[a-f0-9]{32}\]\]')


def preserve_aliases(texts, protect):
    """Known aliases have already been authorized; shield random digit runs from D2.

    Sentinels contain letters only (no ID/card/phone patterns). They are local to
    one transform and never enter model context or the correspondence registry.
    An HTTP masker that changes/removes one fails closed instead of losing IDs.
    """
    substitutions = {}
    joined = '\n'.join(texts)
    for token in set(TOKEN.findall(joined)):
        while True:
            sentinel = '[[REGULAY_ALIAS_' + ''.join(chr(65 + int(c, 16)) for c in secrets.token_hex(16)) + ']]'
            if sentinel not in joined and sentinel not in substitutions.values():
                break
        substitutions[token] = sentinel
    safe = texts
    for token, sentinel in substitutions.items():
        safe = [value.replace(token, sentinel) for value in safe]
    result = protect(safe)
    for token, sentinel in substitutions.items():
        if sum(value.count(sentinel) for value in result) != sum(value.count(sentinel) for value in safe):
            raise ValueError('Masker changed a protected reference')
        result = [value.replace(sentinel, token) for value in result]
    return result


def normalize(kind, value):
    # Names are exact NFC values. No case folding, accent removal, fuzzy match or
    # linkage between a name and an identifier. Equal strings are NOT one person.
    if kind in ('PERSON', 'FIELD'):
        return unicodedata.normalize('NFC', value)
    value = _matching_view(value)[0].strip()
    if kind == 'EMAIL':
        value = re.sub(r'\s+(arroba|at)\s+', '@', value, flags=re.I)
        value = re.sub(r'\s+(punto|dot)\s+', '.', value, flags=re.I)
        local, at, domain = value.rpartition('@')
        return local + at + domain.lower()  # Do not assume local parts ignore case.
    if kind in ('ID', 'ACCOUNT', 'CARD', 'PHONE'):
        return re.sub(r'[\s.()\-]', '', value).upper()
    raise ValueError('Unsupported alias type')


def alias_value(execution, kind, original):
    if not isinstance(original, str) or len(original.encode()) > 512_000:
        raise ValueError('Invalid alias value')
    if _PLACEHOLDER.fullmatch(original):
        return original
    if kind == 'SECRET' or any(pattern.search(value) for value in (original, _matching_view(original)[0])
                               for category, pattern in _PATTERNS if category == 'SECRET'):
        return '[[REGULAI_SECRET]]'  # Secrets never enter the reversible registry.
    prompt = execution.prompt
    if TOKEN.fullmatch(original):
        if not ConversationAlias.objects.filter(company_id=prompt.company_id, user_id=prompt.user_id,
                conversation_id=prompt.conversation_id, kind=kind, token=original).exists():
            raise ValueError('Reference unavailable in this conversation')
        return original
    normalized = normalize(kind, original)
    scope = f'{prompt.company_id}:{prompt.user_id}:{prompt.conversation_id}:{kind}:1:'
    lookup = hmac.new(settings.SECRET_KEY.encode(), (scope + normalized).encode(), hashlib.sha256).hexdigest()
    row, _ = ConversationAlias.objects.get_or_create(company_id=prompt.company_id,
        user_id=prompt.user_id, conversation_id=prompt.conversation_id, kind=kind,
        version=1, lookup_digest=lookup, defaults={
            'token': f'[[R_{kind}_{secrets.token_hex(16)}]]', 'original': original})
    return row.token


def alias_text(execution, text):
    if not isinstance(text, str) or len(text.encode()) > 512_000:
        raise ValueError('Invalid alias input')
    references = list(TOKEN.finditer(text))
    tokens = {match.group() for match in references}
    prompt = execution.prompt
    known = set(ConversationAlias.objects.filter(company_id=prompt.company_id, user_id=prompt.user_id,
        conversation_id=prompt.conversation_id, token__in=tokens).values_list('token', flat=True))
    if tokens != known:
        raise ValueError('Reference unavailable in this conversation')
    protected = [match.span() for match in references]
    matching, offsets = _matching_view(text)
    spans = []
    deadline = time.monotonic() + 10
    for candidate, mapping in [(text, None)] + ([(matching, offsets)] if matching != text else []):
        for category, pattern in _PATTERNS:
            for match in pattern.finditer(candidate):
                start, end = match.span('value') if 'value' in pattern.groupindex else match.span()
                if category == 'CARD' and not _luhn(candidate[start:end]):
                    continue
                if mapping is not None:
                    start, end = mapping[start], mapping[end - 1] + 1
                if not any(start >= left and end <= right for left, right in protected):
                    spans.append((start, end, category))
            if time.monotonic() > deadline:
                raise ValueError('Alias input deadline')
    merged = []
    for start, end, category in sorted(spans, key=lambda item: (item[0], -item[1])):
        if merged and start < merged[-1][1]:
            left, right, previous = merged[-1]
            merged[-1] = (left, max(end, right), 'SECRET' if 'SECRET' in (category, previous) else previous)
        else:
            merged.append((start, end, category))
    for start, end, category in reversed(merged):
        text = text[:start] + alias_value(execution, category, text[start:end]) + text[end:]
    return text


def resolve_for_operation(execution, tokens, *, operation):
    """Application-only resolution; no HTTP/tool/sandbox entry point exports it."""
    if operation != 'local_document_fields':
        raise ValueError('Untrusted reference operation')
    from .service import _context, AgentDenied
    from front.models import AgentExecution
    from django.utils import timezone
    current = AgentExecution.objects.get(pk=execution.pk)
    if (current.status != 'active' or current.attempt != execution.attempt
            or current.expires_at <= timezone.now()
            or current.authorization_digest != _context(execution.prompt, execution.profile_id)[-1]):
        raise AgentDenied()
    prompt = execution.prompt
    rows = list(ConversationAlias.objects.filter(company_id=prompt.company_id,
        user_id=prompt.user_id, conversation_id=prompt.conversation_id, token__in=tokens))
    if len(rows) != len(set(tokens)) or any(not row.original for row in rows):
        raise ValueError('Reference unavailable in this conversation')
    return {row.token: row.original for row in rows}
