set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker build -t regulay-task50-executor:local -f ops/agent_chat/Dockerfile.executor .
docker build -t regulay-task50-web:local -f ops/agent_chat/Dockerfile.web .
for name in task50-worker task50-web; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    test "$(docker inspect "$name" --format '{{index .Config.Labels "regulay.task"}}')" = 50
    docker stop -t 30 "$name"
    docker rm "$name" 2>/dev/null || true
    for iteration in $(seq 1 60); do
      if ! docker inspect "$name" >/dev/null 2>&1; then break; fi
      sleep 1
    done
  fi
done
docker run -d --rm --name task50-web --label regulay.task=50 --network host \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50/evidence-live,dst=/evidence \
  regulay-task50-web:local python ops/agent_chat/lab_server.py --host 0.0.0.0 --port 31049 --evidence /evidence/model-requests.json
bash ops/agent_chat/start_worker.sh
