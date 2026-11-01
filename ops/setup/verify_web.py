"""Readiness checks without inference or password resets."""
import json
from pathlib import Path
import runpy
import urllib.request

runpy.run_path('/app/ops/setup/server.py', run_name='configure')
from django.conf import settings
from django.db import connection
from django.contrib.auth.models import User
from front.agents.capabilities import profile_for
from front.models import AgentModelProfile

assert connection.vendor == 'postgresql'
admin = User.objects.get(pk=settings.PLATFORM_ADMIN_USER_IDS[0], username='admin', is_superuser=True, is_active=True)
profile = AgentModelProfile.objects.select_related('connection__engine', 'model').get(pk=profile_for(admin))
assert profile.professional and profile.connection.active and profile.connection.api_key
assert profile.model.active
assert not settings.REGULAY_AGENT_DEVELOPMENT
assert 'invalid' not in (profile.connection.engine.base_url or '')
token = json.loads(Path('/run/private/server.json').read_text())['worker_token']
request = urllib.request.Request('http://127.0.0.1:31058/internal/agents/checkpoints/', data=b'{}',
    headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
with urllib.request.urlopen(request, timeout=15) as response:
    assert response.status == 200 and 'keep' in json.load(response)
print('PostgreSQL, admin grant, real connection and authenticated worker endpoint verified.')
