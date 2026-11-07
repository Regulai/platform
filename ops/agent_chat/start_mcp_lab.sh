#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
if docker inspect task50-web >/dev/null 2>&1; then
  test "$(docker inspect task50-web --format '{{index .Config.Labels "regulay.task"}}')" = 50
  docker stop -t 30 task50-web
  docker rm task50-web 2>/dev/null || true
fi
docker build -t regulay-task50-web:local -f ops/agent_chat/Dockerfile.web .
echo 1536 > /proc/sys/vm/nr_hugepages
docker run -d --name task50-web --label regulay.task=50 --network host \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50/evidence-live,dst=/evidence \
  regulay-task50-web:local python ops/agent_chat/mcp_lab_server.py --host 0.0.0.0 --port 31049 --evidence /evidence/task54-model.json
sleep 3
docker logs --tail 30 task50-web
