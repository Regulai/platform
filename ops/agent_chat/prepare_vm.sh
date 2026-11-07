#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
mkdir -p /home/probe/task50
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
if docker ps --format '{{.Names}}' | grep -qx task50-worker; then docker stop -t 30 task50-worker; fi
docker build -t regulay-task50-executor:local -f ops/agent_chat/Dockerfile.executor .
docker build -t regulay-task50-web:local -f ops/agent_chat/Dockerfile.web .
docker build -t regulay-task50-spreadsheet:local -f ops/agent_chat/Dockerfile.spreadsheet .
docker save regulay-task50-spreadsheet:local -o /home/probe/task50/spreadsheet-image.tar
# Snapshot construction briefly overlaps two 1 GiB mappings. Reserve 3 GiB,
# also sufficient for the warm slot and the independent isolation probe.
sysctl -w vm.nr_hugepages=1536
python3 ops/agent_chat/local_image.py /home/probe/task50/spreadsheet-image.tar > /home/probe/task50/image-server.log 2>&1 &
image_server=$!
trap 'kill "$image_server" || true' EXIT
for iteration in $(seq 1 60); do
  if curl --silent --fail http://127.0.0.1:5000/v2/ >/dev/null; then break; fi
  sleep 1
done
mkdir -p /home/probe/task50/.runtime
docker compose --project-directory /home/probe/e2b exec -T --interactive=false ready cat /run/e2b/team-api-key > .runtime/e2b-key </dev/null
chown 1000:1000 .runtime/e2b-key
chmod 0400 .runtime/e2b-key
python3 - <<'PY'
from pathlib import Path
import json
Path('.runtime/template.json').write_text(json.dumps({'api_url':'http://127.0.0.1:3000',
    'sandbox_url':'http://127.0.0.1:3002', 'api_key_file':'/run/task50/e2b-key', 'template':'task50-excel',
    'image':'localhost:5000/task50-sheet@sha256:' + Path('image-manifest.sha256').read_text().strip()}))
PY
docker run --rm --network host --mount type=bind,src=/home/probe/task50/.runtime,dst=/run/task50,readonly \
  regulay-task50-executor:local python /app/ops/agent_chat/build_template.py /run/task50/template.json
