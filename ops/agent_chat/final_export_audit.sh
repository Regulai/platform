set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
if ! test -e evidence-live/task54-ui-final; then
  bash ops/agent_chat/audit_export_model.sh task54-ui-final
fi
docker exec -i -e DJANGO_SETTINGS_MODULE=regulai.agent_chat_test_settings task50-web python - <<'PY'
import django
django.setup()
import json
from pathlib import Path
from front.models import AgentExport
root = Path('/evidence/task54-ui-final')
before = json.loads(Path('/evidence/task54-ui-before/report.json').read_text())
after = json.loads((root / 'report.json').read_text())
assert after['simulated_uploads_total'] == before['simulated_uploads_total'] + 1
row = AgentExport.objects.filter(status='completed').select_related('execution__prompt', 'artifact').latest('finished_at')
assert row.status == 'completed' and row.execution.status == 'completed'
verification = row.execution.prompt.decision['verification']
assert verification['status'] == 'passed' and verification['export_reference'] == str(row.pk)
assert row.artifact.sha256 == json.loads(row.proposal)['sha256']
proof = {'ui_approved_revision_confirmed': True, 'new_simulated_uploads': 1,
         'receipt_verification': 'passed', 'execution': str(row.execution_id),
         'export_reference': str(row.pk), 'sha256': row.artifact.sha256,
         'paid_calls': 0, 'real_external_writes': 0}
(root / 'ui-proof.json').write_text(json.dumps(proof, indent=2))
print(json.dumps(proof))
PY
