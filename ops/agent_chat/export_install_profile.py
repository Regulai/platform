"""Export account/configuration only; stdout is never used for credentials.

Run inside the real web container after loading its settings, passing an output
path outside Git. The result contains real API keys: transfer it privately.
"""
import json
import os
from pathlib import Path

MODELS = ('auth.user', 'front.company', 'front.role', 'front.department',
          'front.engine', 'front.enginemodel', 'front.companyengine',
          'front.obfuscationconfig', 'front.profile', 'front.rulesgroup',
          'front.rule', 'front.agentmodelprofile', 'front.agentaccessgrant')


def export(destination):
    from django.apps import apps
    from django.core import serializers
    from django.contrib.auth.models import User
    from django.db import transaction
    from django.contrib.auth.hashers import make_password
    path = Path(destination)
    with transaction.atomic():
        admin = User.objects.get(username='admin', is_superuser=True, is_active=True)
        objects = [obj for label in MODELS for obj in apps.get_model(label).objects.order_by('pk')]
        rows = json.loads(serializers.serialize('json', objects))
        for row in rows:
            if row['model'] == 'auth.user' and row['pk'] == admin.pk:
                row['fields']['password'] = make_password('admin')
            if row['model'] == 'auth.user':
                # Permissions are provisioned by role; no environment-specific IDs.
                row['fields']['groups'] = []
                row['fields']['user_permissions'] = []
        payload = {'format': 'regulai-private-install-v1', 'admin_id': admin.pk, 'objects': rows}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False)
    print('Private installation profile exported (accounts/configuration only, no conversations).')
