"""HTTP/PostgreSQL/official graph/real E2B; external Drive/model are fixtures."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid
import httpx

sys.path.insert(0, str(Path(__file__).parent))
from mcp_lab_server import prepare


def main():
    prepare()
    from django.contrib.auth.models import User
    from front.models import AgentExecution, AgentExport, AgentDocumentConnection, Company, Profile
    root = Path('/evidence')
    output = root / 'task54-live'
    output.mkdir(exist_ok=False)
    controls = root / 'task54-controls.json'
    remote_path = root / 'task54-drive.json'
    report = {'passed': False, 'checks': [], 'paid_calls': 0, 'real_external_writes': 0}
    client = httpx.Client(base_url='http://127.0.0.1:31049', timeout=30, follow_redirects=True)
    def login(target, username='agent-synthetic-ui'):
        target.get('/login/').raise_for_status()
        target.post('/login/', data={'username': username, 'password': 'synthetic-task50-only',
            'csrfmiddlewaretoken': target.cookies['csrftoken']}).raise_for_status()
    login(client)
    def post(url, data=None, payload=None, file=None):
        return client.post(url, data=data, json=payload, files={'file': file} if file else None,
            headers={'X-CSRFToken': client.cookies['csrftoken']})
    def state(run):
        response = client.get(run['status_url']); response.raise_for_status(); return response.json()
    def wait(run, predicate, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = state(run)
            if predicate(current): return current
            time.sleep(.25)
        raise AssertionError(current)
    def finish(run, expected='completed'):
        current = wait(run, lambda data: data['run']['status'] not in ('queued','active','outcome_unknown'))
        assert current['run']['status'] == expected, current
        return current
    def remote():
        return json.loads(remote_path.read_text()) if remote_path.exists() else {'uploads':0,'files':{}}
    def export(artifact, conversation, name, url=None):
        response = post(url or f'/chat/{conversation}/send/', data={'mode':'agent','prompt':'Guarda la revisión verificada',
            'content':'Guarda la revisión verificada', 'request_id':str(uuid.uuid4()),'conversation_id':conversation,
            'artifact_id':artifact['logical_id'],'base_revision':artifact['id'],'export_name':name})
        assert response.status_code == 202, response.text
        run = response.json()['agent']
        current = wait(run, lambda data: bool(data['export']) or data['run']['status'] in ('failed','interrupted'))
        assert current['export']['status'] == 'pending', current
        return run, current['export']
    def approve(proposal):
        response = post(proposal['decision_url'], payload={'binding':proposal['binding'],'decision':'approve'})
        assert response.status_code == 200, response.text
    try:
        controls.write_text('{}')
        response = post('/chat/send/', data={'mode':'agent','prompt':'Crea Excel','request_id':str(uuid.uuid4())},
            file=('synthetic.csv', b'item,amount_cents\nNombre: Private Synthetic Marker,125\nB,250\nC,375\n'))
        assert response.status_code == 202, response.text
        created = response.json()
        artifact = finish(created['agent'])['artifacts'][-1]
        conversation = created['conversation_id']
        original = client.get(artifact['download_url']); original.raise_for_status()
        assert hashlib.sha256(original.content).hexdigest() == artifact['sha256']
        (output/'verified.xlsx').write_bytes(original.content)
        before = remote()['uploads']
        run, proposal = export(artifact, conversation, 'approved.xlsx')
        old_attempt = AgentExecution.objects.get(pk=run['id']).attempt
        assert remote()['uploads'] == before
        (output/'proposal.json').write_text(json.dumps({'run':run,'proposal':proposal}, indent=2, ensure_ascii=False))
        with client.stream('GET',run['events_url']) as stream:
            cursor = next(int(line[4:]) for line in stream.iter_lines() if line.startswith('id: '))
        with client.stream('GET',run['events_url'],headers={'Last-Event-ID':str(cursor)}) as stream:
            next_cursor = next(int(line[4:]) for line in stream.iter_lines() if line.startswith('id: '))
        assert next_cursor > cursor
        (output/'restart-request').write_text(run['id'])
        wait(run, lambda data: AgentExecution.objects.get(pk=run['id']).events.filter(kind='claimed').count() == 2
            and data['run']['status'] == 'active')
        assert AgentExecution.objects.get(pk=run['id']).attempt != old_attempt
        assert remote()['uploads'] == before
        approve(proposal)
        repeated = post(proposal['decision_url'], payload={'binding':proposal['binding'],'decision':'approve'})
        assert repeated.status_code in (200,409)
        completed = finish(run)
        row = AgentExport.objects.get(execution_id=run['id'])
        assert row.status == 'completed' and row.intent_at and row.finished_at
        assert remote()['uploads'] == before + 1
        saved = remote()['files'][row.remote_id]
        assert hashlib.sha256(base64.b64decode(saved['base64'])).hexdigest() == artifact['sha256']
        report['checks'].append({'real_executor_killed_after_official_interrupt_and_resumed':True,
            'execution':run['id'],'claims':2,'uploads':1,'sse_cursor':cursor,'reconnected_cursor':next_cursor})

        controls.write_text(json.dumps({'timeout_after_write':True}))
        uncertain, proposal2 = export(artifact, conversation, 'timeout.xlsx', '/api/chat/send/')
        approve(proposal2)
        finish(uncertain,'interrupted')
        assert AgentExport.objects.get(execution_id=uncertain['id']).status == 'uncertain'
        uploads = remote()['uploads']
        assert post(f"/chat/agent/runs/{uncertain['id']}/recover-export/").status_code == 200
        finish(uncertain)
        assert remote()['uploads'] == uploads
        report['checks'].append({'timeout_after_simulated_remote_effect_reconciled_without_new_upload':True,
            'execution':uncertain['id']})
        controls.write_text('{}')

        cancelled, pending = export(artifact,conversation,'cancelled.xlsx',f'/chat/{conversation}/')
        assert post(cancelled['cancel_url']).status_code == 200
        finish(cancelled,'cancelled')
        assert post(pending['decision_url'],payload={'binding':pending['binding'],'decision':'approve'}).status_code == 409
        assert remote()['uploads'] == uploads
        report['checks'].append({'cancel_pending_approval_no_effect':True})

        revoked, pending = export(artifact,conversation,'revoked.xlsx')
        grant = AgentDocumentConnection.objects.get(user__username='agent-synthetic-ui')
        grant.write_enabled = False; grant.version += 1; grant.save()
        finish(revoked,'failed')
        assert post(pending['decision_url'],payload={'binding':pending['binding'],'decision':'approve'}).status_code == 409
        assert remote()['uploads'] == uploads
        grant.write_enabled = True; grant.save()
        report['checks'].append({'grant_revocation_cuts_next_step':True})

        other = User.objects.create_user('agent-synthetic-task54-other',password='synthetic-task50-only')
        Profile.objects.create(user=other,company=Company.objects.create(name='Task54 other synthetic company'))
        with httpx.Client(base_url=str(client.base_url),timeout=20,follow_redirects=True) as foreign:
            login(foreign,other.username)
            for path in (run['status_url'],run['events_url'],artifact['download_url']):
                assert foreign.get(path).status_code == 404
            assert foreign.post(proposal['decision_url'],json={'binding':proposal['binding'],'decision':'approve'},
                headers={'X-CSRFToken':foreign.cookies['csrftoken']}).status_code == 409
        report['checks'].append({'two_users_two_companies_denied_state_sse_download_approval':True})

        controls.write_text(json.dumps({'mode_disabled':True})); time.sleep(.3)
        blocked = post('/chat/send/',data={'mode':'agent','prompt':'Crea Excel','request_id':str(uuid.uuid4())},
            file=('synthetic.csv',b'item,amount_cents\nA,1\nB,2\nC,3\n'))
        assert blocked.status_code == 403, blocked.text
        assert client.get(run['status_url']).status_code == 200
        assert client.get(artifact['download_url']).status_code == 200
        controls.write_text('{}'); time.sleep(.3)
        report['checks'].append({'mode_off_blocks_new_work_preserves_authorized_history_and_download':True})

        AgentExecution.objects.get(pk=run['id']).conversation.delete()
        assert not AgentExport.objects.filter(execution_id=run['id']).exists()
        assert client.get(artifact['download_url']).status_code == 404
        assert remote()['uploads'] == uploads and len(remote()['files']) == uploads
        (output/'retention-request').write_text(run['id'])
        report['checks'].append({'retention_deleted_private_artifacts_ledger_and_access_no_remote_delete':True})
        report['passed'] = True
    finally:
        controls.write_text('{}')
        (output/'report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False))
        client.close()
    print(json.dumps(report))


if __name__ == '__main__':
    main()
