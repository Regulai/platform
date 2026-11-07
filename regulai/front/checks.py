"""Reject public template keys without storing or displaying their values."""
from hashlib import sha256

from django.conf import settings
from django.core.checks import Error, Tags, register


PUBLIC_KEY_HASHES = {
    'SECRET_KEY': 'aef52ed18752c7b7f0e97f6e0debb70bee30f70471a454d52d19512602a2a980',
    'ENCRYPTION_KEY': '72766c4f5dfbb6080b34186f85c1127883648d1b07aa512e12382bcc9257b7dd',
}


@register(Tags.security)
def reject_public_keys(app_configs, **kwargs):
    errors = []
    for name, known_hash in PUBLIC_KEY_HASHES.items():
        values = [getattr(settings, name, None), *getattr(settings, name + '_FALLBACKS', ())]
        if any(isinstance(value, (str, bytes)) and sha256(
                value.encode() if isinstance(value, str) else value).hexdigest() == known_hash for value in values):
            errors.append(Error(f'A public template key is configured for {name} or its fallbacks.',
                hint='Replace public keys and remove them from fallback settings.', id='front.E001'))
    return errors
