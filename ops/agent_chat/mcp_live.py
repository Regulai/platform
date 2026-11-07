"""Real HTTP + E2B path, fixture Drive transport. Review only after inspecting PNGs."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import uuid
import httpx

parser = argparse.ArgumentParser()
parser.add_argument('stage', choices=['begin', 'review'])
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
with httpx.Client(base_url='http://127.0.0.1:8500', timeout=30, follow_redirects=False) as client:
    client.get('/login/').raise_for_status()
    response = client.post('/login/', data={'username': 'agent-synthetic-ui', 'password': 'synthetic-task50-only',
        'csrfmiddlewaretoken': client.cookies['csrftoken']})
    assert response.status_code == 302
    headers = {'X-CSRFToken': client.cookies['csrftoken']}
    path = args.output / 'http.json'
    if args.stage == 'begin':
        assert not path.exists()
        search = client.post('/chat/agent/documents/search/', json={'query': 'synthetic'}, headers=headers)
        search.raise_for_status()
        reference = search.json()['documents'][0]['reference']
        response = client.post('/chat/send/', data={'prompt': 'Crea un informe Word DOCX desde la entrada autorizada',
            'mode': 'agent', 'document_reference': reference, 'request_id': str(uuid.uuid4())}, headers=headers)
        assert response.status_code == 202, response.text
        run = response.json()['agent']
        path.write_text(json.dumps({'run': run, 'reference': reference}, indent=2))
    else:
        record = json.loads(path.read_text())
        run = record['run']
        artifact = record['artifact']
        result = client.post(artifact['review_url'], json={'sha256': artifact['sha256'],
            'page_sha256': artifact['page_sha256'], 'checks': artifact['review_checks']}, headers=headers)
        result.raise_for_status()
    for _ in range(120):
        response = client.get(run['status_url'])
        response.raise_for_status()
        value = response.json()
        if args.stage == 'begin' and value['artifacts']:
            artifact = value['artifacts'][-1]
            for number, url in enumerate(artifact['preview']['pages'], 1):
                image = client.get(url)
                image.raise_for_status()
                (args.output / f'page-{number}.png').write_bytes(image.content)
            record = {'run': run, 'reference': reference, 'artifact': artifact, 'events': value['events'],
                'transport': 'Real MCP + simulated Drive HTTPS + real E2B + simulated model', 'paid_calls': 0}
            path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')
            print(json.dumps({'status': 'visual_review_pending', 'pages': len(artifact['preview']['pages'])}))
            break
        if args.stage == 'review' and value['run']['status'] == 'completed':
            artifact = value['artifacts'][-1]
            downloaded = client.get(artifact['download_url'])
            downloaded.raise_for_status()
            assert hashlib.sha256(downloaded.content).hexdigest() == artifact['sha256']
            (args.output / 'report.docx').write_bytes(downloaded.content)
            record.update(artifact=artifact, events=value['events'], download_hash=artifact['sha256'], completed=True)
            path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')
            print(json.dumps({'status': 'completed', 'sha256': artifact['sha256']}))
            break
        if value['run']['status'] in ('failed', 'interrupted', 'cancelled'):
            raise RuntimeError('Fixture run failed: ' + value['run']['status'])
        time.sleep(1)
    else:
        raise RuntimeError('Fixture run deadline reached')
