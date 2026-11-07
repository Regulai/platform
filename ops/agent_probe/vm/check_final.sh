#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 1000:1000 --memory 512m --cpus 1 --pids-limit 64 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  regulay-task48-executor:local python /app/ops/agent_probe/test_probe.py
docker run --rm -i --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
  --user 1000:1000 --mount type=bind,src=/home/probe/task48/.runtime,dst=/run/task48,readonly \
  regulay-task48-executor:local python - <<'PY'
import sys, json
sys.path.insert(0, '/app/ops/agent_probe')
from run_e2b import options
from e2b import Sandbox
page = Sandbox.list(**options(json.load(open('/run/task48/template.json'))))
remaining = []
while page.has_next:
    remaining.extend(item.sandbox_id for item in page.next_items())
assert not remaining, 'Unexpected sandbox still present in disposable E2B account'
print(json.dumps({'remaining_e2b_sandboxes': 0}))
PY
dpkg-query -W docker.io docker-compose-v2 docker-buildx
docker image inspect regulay-task48-executor:local regulay-task48-sandbox:local --format '{{.Id}}'
