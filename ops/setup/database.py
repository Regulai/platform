"""Initialize only an empty database; subsequent starts never reset accounts."""
import json
from pathlib import Path
import runpy

runpy.run_path('/app/ops/setup/server.py', run_name='configure')
from django.core.management import call_command
from django.core import serializers
from django.db import connection, transaction
from django.apps import apps
from django.contrib.auth.models import User
from django.core.management.color import no_style
from front.models import AgentModelProfile, Conversation
from front.agents.capabilities import profile_for

call_command('migrate', interactive=False, verbosity=0)
marker = Path('/run/private/initialized')
if not marker.exists():
    if User.objects.exists():
        raise RuntimeError('Database contains accounts without installation marker; refusing to overwrite them.')
    data = json.loads(Path('/run/private/import.json').read_text(encoding='utf-8'))
    if data.get('format') != 'regulai-private-install-v1':
        raise RuntimeError('Unsupported private installation profile.')
    MODELS = runpy.run_path('/app/ops/agent_chat/export_install_profile.py')['MODELS']
    if any(row['model'] not in MODELS for row in data['objects']):
        raise RuntimeError('Import contains data outside the account/configuration allowlist.')
    with transaction.atomic():
        # These tables contain migration-seeded catalogue entries only. There
        # are no accounts yet. Import preserves referenced IDs and policy URLs.
        for label in reversed(MODELS):
            apps.get_model(label).objects.all().delete()
        for obj in serializers.deserialize('json', json.dumps(data['objects'])):
            obj.save()
        models = [apps.get_model(label) for label in MODELS]
        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(no_style(), models):
                cursor.execute(sql)
        admin = User.objects.get(pk=data['admin_id'], username='admin', is_superuser=True, is_active=True)
        admin.set_password('admin')
        admin.save(update_fields=['password'])
        profile = AgentModelProfile.objects.get(pk=profile_for(admin))
        if not profile.professional or not profile.connection.api_key:
            raise RuntimeError('The admin has no real enabled professional connection.')
        assert not Conversation.objects.exists()
    marker.write_text('Accounts imported; never reset passwords on restart.\n')
else:
    print('Existing accounts preserved; the supplied profile is not reimported.')
print('PostgreSQL migrated; real admin/profile configured; no conversations imported.')
