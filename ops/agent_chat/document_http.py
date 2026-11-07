"""Real HTTP authorization and byte equality for synthetic DOCX/PDF artifacts."""
import hashlib
import json
import os
from pathlib import Path
import uuid

import httpx
from lab_server import prepare
prepare()
from django.contrib.auth.models import User
from front.models import AgentArtifact, Profile

client = httpx.Client(base_url='http://127.0.0.1:31049', follow_redirects=False, timeout=30)


def login(target, user='agent-synthetic-ui'):
    target.get('/login/').raise_for_status()
    response = target.post('/login/', data={'username': user, 'password': 'synthetic-task50-only',
        'csrfmiddlewaretoken': target.cookies['csrftoken']})
    assert response.status_code == 302


login(client)
report = {'downloads': [], 'failed_drafts_inaccessible': [], 'stale_revision': False, 'cross_user': False}
artifacts = list(AgentArtifact.objects.exclude(format='xlsx').filter(
    execution__conversation_id__gte=int(os.environ.get('REGULAY_DOCUMENT_FIRST_CHAT', '0'))).order_by('created_at'))
for artifact in artifacts:
    url = f'/chat/agent/artifacts/{artifact.pk}/download/'
    response = client.get(url)
    if artifact.status == 'verified' and artifact.execution.status == 'completed':
        assert response.status_code == 200
        assert hashlib.sha256(response.content).hexdigest() == artifact.sha256
        assert response.headers['cache-control'] == 'private, no-store'
        report['downloads'].append({'id': str(artifact.pk), 'sha256': artifact.sha256})
    else:
        assert response.status_code == 404
        report['failed_drafts_inaccessible'].append(str(artifact.pk))

first = next(row for row in artifacts if row.status == 'verified')
response = client.post(f'/chat/{first.execution.conversation_id}/send/', data={'mode': 'agent',
    'prompt': 'Cambia el título de una versión antigua', 'request_id': str(uuid.uuid4()),
    'artifact_id': str(first.logical_id), 'base_revision': str(first.pk)},
    headers={'X-CSRFToken': client.cookies['csrftoken']})
assert response.status_code == 409, response.text
report['stale_revision'] = True

user = User.objects.get(username='agent-synthetic-ui')
outsider = User.objects.create_user('agent-synthetic-doc-other-' + uuid.uuid4().hex[:8], password='synthetic-task50-only')
Profile.objects.create(user=outsider, company=user.profile.company)
with httpx.Client(base_url=str(client.base_url), follow_redirects=False, timeout=30) as other:
    login(other, outsider.username)
    for path in (f'/chat/agent/artifacts/{first.pk}/pages/1/', f'/chat/agent/artifacts/{first.pk}/download/'):
        assert other.get(path).status_code == 404
    response = other.post(f'/chat/agent/artifacts/{first.pk}/review/', json={},
        headers={'X-CSRFToken': other.cookies['csrftoken']})
    assert response.status_code == 409
report['cross_user'] = True
client.close()
case = os.environ.get('REGULAY_DOCUMENT_CASE', 'document-runs')
assert case in ('document-runs', 'presentation-runs')
(Path('/evidence') / case / 'http.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report))
