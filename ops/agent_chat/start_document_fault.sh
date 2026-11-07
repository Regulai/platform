set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
if docker ps --format '{{.Names}}' | grep -qx task50-worker; then
  test "$(docker inspect task50-worker --format '{{index .Config.Labels "regulay.task"}}')" = 50
  docker stop -t 30 task50-worker
fi
docker run -d --rm --name task51-fault-worker --label regulay.task=51 --network task50-exec \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --dns 127.0.0.1 \
  --memory 768m --cpus 1 --pids-limit 128 --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50/.runtime,dst=/run/task50,readonly \
  --mount type=bind,src=/home/probe/task50/ops/agent_chat/document_fault_worker.py,dst=/fault.py,readonly \
  regulay-task50-executor:local python /fault.py
