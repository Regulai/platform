"""Synthetic end-to-end HTTP checks, inside the application lab container.

The host harness kills/restarts the separate executor on a marker. No provider
transport, Docker socket or database credential is given to that executor.
"""
import io
import json
import os
from pathlib import Path
import sys
import time
import uuid
import zipfile

import httpx
from openpyxl import Workbook

sys.path.insert(0, str(Path(__file__).parent))
from lab_server import prepare


def main():
    prepare()
    from django.contrib.auth.models import User
    from front.models import AgentExecution, AgentArtifact, Profile, AgentModelProfile
    root = Path(os.environ.get('REGULAY_LIVE_EVIDENCE_DIR', '/evidence'))
    client = httpx.Client(base_url='http://127.0.0.1:31049', follow_redirects=True, timeout=90)
    def login(target, username='agent-synthetic-ui'):
        target.get('/login/').raise_for_status()
        target.post('/login/', data={'username': username, 'password': 'synthetic-task50-only',
            'csrfmiddlewaretoken': target.cookies['csrftoken']}).raise_for_status()
    login(client)
    report = {'passed': False, 'checks': []}
    csv = b'item,amount_cents\nNombre: Private Synthetic Marker,125\n<script>alert(1)</script>,250\n=HYPERLINK("invalid"),375\n'
    def post(path, data, file=None):
        return client.post(path, data=data, files={'file': file} if file else None,
            headers={'X-CSRFToken': client.cookies['csrftoken']})
    def send(*, content='Crea Excel', file=('synthetic.csv', csv), previous=None, url='/chat/send/', request_id=None):
        data = {'mode': 'agent', 'content': content, 'prompt': content, 'request_id': str(request_id or uuid.uuid4())}
        if previous:
            data.update(artifact_id=previous['logical_id'], base_revision=previous['id'])
        started = time.monotonic()
        response = post(url, data, file)
        if response.status_code != 202:
            raise AssertionError((response.status_code, response.text))
        result = response.json()
        report['checks'].append({'accepted_ms': round((time.monotonic()-started)*1000, 2), 'url': url})
        return result
    def state(run):
        response = client.get(run['status_url'])
        response.raise_for_status()
        return response.json()
    def finish(run, expected='completed', timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data = state(run)
            if data['run']['status'] not in ('queued', 'active', 'outcome_unknown'):
                assert data['run']['status'] == expected, data
                return data
            time.sleep(.3)
        raise AssertionError('Run did not finish: ' + str(data))
    def active_inference(run):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            row = AgentExecution.objects.get(pk=run['id'])
            if row.status == 'active' and row.active_call:
                return row
            time.sleep(.1)
        raise AssertionError('No active provider call')
    try:
        request_id = uuid.uuid4()
        first = send(request_id=request_id)
        replay = send(request_id=request_id)
        assert first['agent']['id'] == replay['agent']['id']
        run = first['agent']
        # Real streaming TCP response, closed before completion.
        with client.stream('GET', run['events_url']) as response:
            assert response.headers['content-type'].startswith('text/event-stream')
            cursor = next(int(line[4:]) for line in response.iter_lines() if line.startswith('id: '))
        with client.stream('GET', run['events_url'], headers={'Last-Event-ID': str(cursor)}) as response:
            ids = []
            for line in response.iter_lines():
                if line.startswith('id: '):
                    ids.append(int(line[4:]))
                if line == 'event: terminal':
                    break
        assert ids and all(value > cursor for value in ids) and len(ids) == len(set(ids))
        data = finish(run)
        first_artifact = data['artifacts'][-1]
        content = client.get(first_artifact['download_url']).content
        (root / 'live-csv.xlsx').write_bytes(content)
        conversation_id = AgentExecution.objects.get(pk=run['id']).conversation_id
        assert AgentExecution.objects.filter(prompt__request_id=request_id).count() == 1
        report['checks'].append({'duplicate_and_sse_reconnect_once': True, 'cursor': cursor, 'following': ids})

        revision = send(content='Cambia el título a Ventas revisadas', file=None, previous=first_artifact,
                        url=f'/chat/{conversation_id}/send/')
        changed = finish(revision['agent'])['artifacts'][-1]
        revised = client.get(changed['download_url']).content
        (root / 'live-renamed.xlsx').write_bytes(revised)
        with zipfile.ZipFile(io.BytesIO(content)) as old, zipfile.ZipFile(io.BytesIO(revised)) as new:
            assert old.namelist() == new.namelist()
            assert [name for name in old.namelist() if old.read(name) != new.read(name)] == ['xl/worksheets/sheet1.xml']
        assert changed['logical_id'] == first_artifact['logical_id'] and changed['revision'] > first_artifact['revision']
        stale = post(f'/chat/{conversation_id}/send/', {'mode':'agent','prompt':'Título viejo',
            'request_id':str(uuid.uuid4()),'artifact_id':first_artifact['logical_id'],'base_revision':first_artifact['id']})
        assert stale.status_code == 409, stale.text
        report['checks'].append({'immutable_title_revision_and_stale_rejection': True, 'artifact': changed})

        book = Workbook()
        book.active.append(['item','amount_cents'])
        for item, cents in [('A',-125),('B',0),('C',500)]: book.active.append([item,cents])
        buffer = io.BytesIO()
        book.save(buffer)
        xlsx_run = send(file=('synthetic.xlsx',buffer.getvalue()),url='/api/chat/send/')
        xlsx = finish(xlsx_run['agent'])['artifacts'][-1]
        assert xlsx['preview']['total_cents'] == 375
        (root / 'live-xlsx-input.xlsx').write_bytes(client.get(xlsx['download_url']).content)
        report['checks'].append({'xlsx_input_negative_zero_and_total':True})

        cancelled = send(content='SYNTHETIC_PAUSE cancela antes de calcular',url='/chat/')
        row = active_inference(cancelled['agent'])
        assert post(cancelled['agent']['cancel_url'],{}).status_code == 200
        time.sleep(12)
        finish(cancelled['agent'],'cancelled')
        assert not row.events.filter(kind__in=['input','calculate','verified']).exists()
        assert not row.artifacts.exists()
        report['checks'].append({'cancel_active_inference_no_new_step':True})

        revoked = send(content='SYNTHETIC_PAUSE revocación sintética')
        row = active_inference(revoked['agent'])
        profile = AgentModelProfile.objects.get(pk=row.profile_id)
        try:
            profile.enabled = False
            profile.save(update_fields=['enabled'])
            assert client.get(revoked['agent']['status_url']).status_code == 404
            assert client.get(revoked['agent']['events_url']).status_code == 404
            assert client.get(changed['download_url']).status_code == 404
            time.sleep(12)
            assert not row.artifacts.exists()
            assert not row.events.filter(kind='calculate').exists()
        finally:
            profile.enabled = True
            profile.save(update_fields=['enabled'])
        post(revoked['agent']['cancel_url'],{})
        report['checks'].append({'revocation_blocks_sse_state_download_and_steps':True})

        outsider = User.objects.create_user('agent-synthetic-other-' + uuid.uuid4().hex[:8], password='synthetic-task50-only')
        Profile.objects.create(user=outsider,company=profile.company)
        with httpx.Client(base_url=str(client.base_url),follow_redirects=True,timeout=20) as other:
            login(other,outsider.username)
            for path in (run['status_url'],run['events_url'],changed['download_url']):
                assert other.get(path).status_code == 404
        report['checks'].append({'cross_user_state_sse_download_denied':True})

        restart = send(content='SYNTHETIC_PAUSE muerte del proceso ejecutor')
        row = active_inference(restart['agent'])
        attempt = row.attempt
        (root / 'restart-request').write_text(str(row.pk))
        interrupted = finish(restart['agent'],'interrupted',timeout=100)
        row.refresh_from_db()
        assert row.attempt == attempt and row.events.filter(kind='claimed').count() == 1
        assert not row.events.filter(kind='calculate').exists() and not row.artifacts.exists()
        report['checks'].append({'process_killed_and_restart_interrupted_without_replay':True,'execution':str(row.pk)})
        report['passed'] = True
    finally:
        client.close()
        (root / 'live-cases.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print(json.dumps({'passed': report['passed'], 'checks':len(report['checks'])}))


if __name__ == '__main__':
    main()
