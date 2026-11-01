"""Exercise the hash-verified frozen P0 ORM on an expanded P1 test schema."""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
evidence = ROOT / 'output/p1-20261016/e1'
frozen = evidence / 'frozen'
manifest = json.loads((evidence / 'p0-manifest.json').read_text(encoding='utf-8'))
for item in manifest['files']:
    assert hashlib.sha256((frozen / item['path']).read_bytes()).hexdigest() == item['sha256'], item['path']
values = json.loads(sys.argv[1])
assert values['database'] in ('test_regulai_p1_security', 'test_regulai_p1_integration'), 'Only the owned disposable test DBs are authorized.'
sys.path.insert(0, str(frozen / 'regulai'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'regulai.ci_settings'
from django.conf import settings
settings.DATABASES['default']['PORT'] = '55468'
settings.DATABASES['default']['NAME'] = values['database']
assert settings.DATABASES['default']['HOST'] == '127.0.0.1'
import django
django.setup()
from front.models import AgentEvent, AgentInput, Conversation, Prompt
assert 'auto_skills' not in {field.name for field in Conversation._meta.fields}
assert 'public_text' not in {field.name for field in AgentEvent._meta.fields}
prompt = Prompt.objects.get(pk=values['prompt'])
assert prompt.decision['total'] == {'known_cost': '0.031', 'complete': False}
asset = AgentInput.objects.get(pk=values['asset'])
assert asset.original == values['input']
conversation = Conversation.objects.create(user_id=values['user'], title='P0 writer on P1 schema')
event = AgentEvent.objects.create(execution_id=values['execution'], kind='progress', data={'source': 'frozen_p0'})
existing = Conversation.objects.get(pk=values['conversation'])
existing.title = 'P0 update retains P1 preference'
existing.save(update_fields=['title'])
assert Prompt.objects.get(pk=values['prompt']).decision['total'] == prompt.decision['total']
print(json.dumps({'conversation_id': conversation.pk, 'event_id': event.pk,
    'source_archive_sha256': manifest['archive_sha256'], 'provider_calls': 0}))
