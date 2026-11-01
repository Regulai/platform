#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker logs --tail 10 task50-worker
docker exec -i task50-web python - <<'PY'
from ops.agent_chat.lab_server import prepare
prepare()
from front.models import AgentExecution, AgentToolResult
import json
for run in AgentExecution.objects.order_by('-created_at')[:3]:
    print(json.dumps({'run':str(run.pk),'status':run.status,'events':list(run.events.values('kind','data')),
        'artifacts':list(run.artifacts.values('status','format','verification'))},ensure_ascii=False))
    for result in AgentToolResult.objects.filter(execution=run):
        print(result.raw[:10000])
PY
