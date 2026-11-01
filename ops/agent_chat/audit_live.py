"""Read-only evidence from the synthetic application database and model transport."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from lab_server import prepare
prepare()
from front.models import AgentExecution, AgentInference, AgentArtifact, AgentToolResult
from front.agents.jobs import _bytes

root = Path('/evidence')
requests = json.loads((root / 'model-requests.json').read_text())
serialized = json.dumps(requests)
for marker in ('Private Synthetic Marker', 'Synthetic Private Marker', '<script>alert', 'synthetic.invalid',
               'spreadsheet_program.py', 'base64', 'synthetic-provider-key'):
    assert marker not in serialized, marker
report = {'model_calls':len(requests),'originals_and_raw_logs_absent_from_model':True,'runs':[]}
for run in AgentExecution.objects.filter(conversation__isnull=False).order_by('created_at'):
    events = [{'id':e.pk,'kind':e.kind,'time':e.created_at.isoformat()} for e in run.events.all()]
    files = []
    for asset in run.artifacts.all():
        assert asset.status == 'verified'
        assert hashlib.sha256(_bytes(asset)).hexdigest() == asset.verification['sha256']
        files.append({'id':str(asset.pk),'logical_id':str(asset.logical_id),'revision':asset.revision,
                      'sha256':asset.sha256,'verification':asset.verification})
    report['runs'].append({'id':str(run.pk),'conversation':run.conversation_id,'status':run.status,
        'queue_seconds':(run.started_at-run.created_at).total_seconds() if run.started_at else None,
        'execution_seconds':(run.finished_at-run.started_at).total_seconds() if run.finished_at and run.started_at else None,
        'events':events,'files':files,
        'inferences':list(AgentInference.objects.filter(execution=run).values('status','call_id')),
        'raw_results_stored_privately':AgentToolResult.objects.filter(execution=run).count()})
(root/'audit.json').write_text(json.dumps(report,default=str,indent=2))
print(json.dumps({'runs':len(report['runs']),'model_calls':len(requests),'privacy_verified':True}))
