"""Export only this isolated laboratory's synthetic document evidence."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from lab_server import prepare
prepare()
from front.models import AgentExecution, AgentToolResult
from front.agents import jobs, document_contract

case = os.environ.get('REGULAY_DOCUMENT_CASE', 'document-runs')
assert case in ('document-runs', 'presentation-runs')
root = Path('/evidence') / case
root.mkdir(exist_ok=False)
report = {'synthetic_only': True, 'paid_calls': 0, 'runs': []}
requests = Path('/evidence/model-requests.json').read_text()
for marker in ('Synthetic Private Marker', '<script>alert', 'synthetic.invalid',
               'Piñón español', 'iVBORw0KGgo', 'JVBERi0', 'UEsDB'):
    assert marker not in requests, marker
report['originals_and_renders_absent_from_model'] = True
for run in AgentExecution.objects.filter(conversation__id__gte=int(os.environ.get('REGULAY_DOCUMENT_FIRST_CHAT', '0'))).order_by('created_at'):
    row = {'id': str(run.pk), 'conversation': run.conversation_id, 'status': run.status,
           'request': run.prompt.content, 'logical_id': run.job['logical_id'],
           'events': list(run.events.values('id', 'kind', 'created_at')), 'artifacts': []}
    for artifact in run.artifacts.order_by('revision'):
        output = root / str(artifact.pk)
        output.mkdir()
        raw = jobs._bytes(artifact)
        record = {'id': str(artifact.pk), 'logical_id': str(artifact.logical_id),
                  'revision': artifact.revision, 'format': artifact.format, 'status': artifact.status,
                  'sha256': artifact.sha256, 'verification': artifact.verification}
        if artifact.render_bundle:
            bundle = {name: base64.b64decode(value) for name, value in json.loads(artifact.render_bundle).items()}
            assert hashlib.sha256(bundle['final.' + artifact.format]).hexdigest() == artifact.sha256
            for name, content in bundle.items():
                assert '/' not in name and '\\' not in name
                (output / name).write_bytes(content)
        else:
            (output / ('candidate.' + (artifact.format if artifact.status == 'verified' else 'draft'))).write_bytes(raw)
        (output / 'artifact.json').write_text(json.dumps(record, indent=2, ensure_ascii=False))
        row['artifacts'].append(record)
    row['tool_results'] = [{'id': str(r.pk), 'call_id': r.call_id, 'model_view': r.view,
        'raw': json.loads(r.raw)} for r in AgentToolResult.objects.filter(execution=run)]
    report['runs'].append(row)
(root / 'audit.json').write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str))
print(json.dumps({'runs': len(report['runs']), 'privacy': True}))
