"""Strict transport contract for the mandatory company privacy barrier."""
import json
from decimal import Decimal
from urllib.parse import urlsplit

import requests

from .policy import digest


def mask_identity(config):
    return digest([config.backend, config.api_url, config.detect, config.language])


def valid_masks(masks):
    """An empty or malformed chain cannot be treated as an identity transform."""
    try:
        return bool(masks) and all(
            config.active and config.detect == 'both' and (
                (config.backend == 'local' and config.language in {'', 'es', 'en'}) or (
                    config.backend == 'http'
                    and urlsplit(config.api_url).scheme in {'http', 'https'}
                    and bool(urlsplit(config.api_url).netloc)
                    and not urlsplit(config.api_url).username and not urlsplit(config.api_url).password))
            for config in masks
        )
    except ValueError:
        return False


def mask_cost_bounds(masks, max_call_cost):
    """API exposure per transform; a local-only chain requires an explicit zero."""
    bound = Decimal(max_call_cost) if max_call_cost is not None else None
    if masks and all(config.backend == 'local' for config in masks) and bound != 0:
        raise ValueError('Local masking requires an explicit zero API cost bound')
    return {config.pk: Decimal(0) if config.backend == 'local' else bound for config in masks}


def mask_local_texts(texts, *, language='', timeout=10):
    # Local pattern errors propagate; they never select an HTTP fallback.
    from .local_masking import mask_local_texts as local
    return local(texts, language=language, timeout=timeout)


def mask_texts(texts, masks, before_call=None, after_call=None, *, timeout=10):
    """Mask a structured batch atomically; never guess segment boundaries."""
    if not isinstance(texts, list) or not texts or any(not isinstance(text, str) for text in texts):
        raise ValueError('Invalid masking input')
    if not valid_masks(masks):
        raise ValueError('Required masking is not configured')
    current = texts
    for config in masks:
        value = json.dumps(current, ensure_ascii=False)
        seconds = before_call(config, value) if before_call else timeout
        if config.backend == 'local':
            masked = mask_local_texts(current, language=config.language, timeout=seconds)
        else:
            payload = {'text': value, 'detect': ['pii', 'secrets']}
            if config.language:
                payload['language'] = config.language
            response = requests.post(config.api_url.rstrip('/') + '/api/mask', json=payload,
                                     timeout=seconds, allow_redirects=False)
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or not isinstance(result.get('masked'), str):
                raise ValueError('Invalid masking response')
            masked = json.loads(result['masked'])
        if not isinstance(masked, list) or len(masked) != len(current) or any(not isinstance(text, str) for text in masked):
            raise ValueError('Invalid masking segments')
        if after_call:
            after_call(config)
        current = masked
    return current
