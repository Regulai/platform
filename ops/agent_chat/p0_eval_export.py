"""Export one authorized connection privately for the isolated P0 evaluation.

Run in an ephemeral copy of the installed web image. Its original private
settings are mounted read-only at /run/private; the destination is a different
private directory. Never write a provider credential to stdout or argv.
"""
import argparse
import json
import os
from pathlib import Path
import sys


def export(destination, profile_id):
    # This module loads the current installation, never the evaluation settings.
    sys.path.insert(0, '/app')
    import ops.setup.server  # noqa: F401
    from django.conf import settings
    from django.db import connection, transaction
    from django.db.models import Q, Count
    from front.models import AgentAccessGrant, AgentModelProfile, ObfuscationConfig, Rule
    from front.policy import AIConfig

    target = Path(destination)
    if target.parent.resolve() != Path('/eval-private') or target.name != 'connection.json':
        raise RuntimeError('Export destination must be the dedicated private mount.')
    if target.exists() or target.is_symlink():
        raise RuntimeError('Private connection export already exists; refusing to overwrite.')
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute('SET TRANSACTION READ ONLY')
        profile = AgentModelProfile.objects.select_related('connection__engine', 'model', 'company').get(pk=profile_id)
        credential, model = profile.connection, profile.model
        grant = AgentAccessGrant.objects.select_related('user__profile').filter(
            profile=profile, company_id=profile.company_id, enabled=True,
            user__is_active=True, user__profile__company_id=profile.company_id).order_by('pk').first()
        if not (getattr(settings, 'REGULAY_AGENT_ENABLED', False) and profile.enabled and
                profile.professional and grant and credential.active and credential.api_key and
                credential.company_id == profile.company_id and model.active and
                model.engine_id == credential.engine_id):
            raise RuntimeError('Source connection, model or explicit account grant is not authorized.')
        cfg = AIConfig.model_validate(profile.company.ai_config)
        masks = list(ObfuscationConfig.objects.filter(company_id=profile.company_id, active=True)
                     .values('backend', 'detect', 'language'))
        rules = Rule.objects.filter(active=True).filter(
            Q(rules_group__company_id=profile.company_id) | Q(rules_group__user_id=grant.user_id) |
            Q(rules_group__company__isnull=True, rules_group__user__isnull=True))
        payload = {
            'format': 'p0-evaluation-connection-v1',
            'engine': {name: getattr(credential.engine, name) for name in
                       ('name', 'provider', 'connector_type', 'base_url', 'default_model')},
            'model': {name: getattr(model, name) for name in
                      ('name', 'model_id', 'max_tokens', 'context_window', 'supports_vision',
                       'supports_json', 'reasoning', 'input_price', 'output_price', 'currency', 'price_date')},
            'api_key': credential.api_key,
            'source_authorization': {
                'profile_id': profile.pk, 'company_id': profile.company_id,
                'connection_id': credential.pk, 'model_id': model.pk, 'grant_id': grant.pk,
                'grant_version': grant.version, 'account_id': grant.user_id,
                'enabled': True, 'profile_enabled': True, 'grant_enabled': True,
                'professional': True, 'account_active': True,
                'connection_active': True, 'model_active': True, 'model_bound': True,
            },
            'controls': {
                'jev_configured': bool(profile.company.jev_api_key),
                'classification': cfg.classification, 'verification_mode': cfg.verification.mode,
                'masks': masks,
                'rule_counts': list(rules.values('action', 'applies_to').annotate(count=Count('pk'))),
                'source_limits': profile.limits,
            },
        }
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False, default=str)
    # Only flags/counts and IDs, never credentials, URLs or rule contents.
    print(json.dumps({'private_export_written': True, 'profile_id': profile_id,
                      'controls': payload['controls']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile-id', type=int, default=1)
    parser.add_argument('--destination', default='/eval-private/connection.json')
    args = parser.parse_args()
    export(args.destination, args.profile_id)
