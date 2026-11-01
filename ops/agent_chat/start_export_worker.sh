set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker build -t regulay-task50-executor:local -f ops/agent_chat/Dockerfile.executor .
if docker inspect task50-worker >/dev/null 2>&1; then
  test "$(docker inspect task50-worker --format '{{index .Config.Labels "regulay.task"}}')" = 50
  docker stop -t 30 task50-worker
fi
bash ops/agent_chat/start_worker.sh
sleep 3
docker logs --tail 20 task50-worker
