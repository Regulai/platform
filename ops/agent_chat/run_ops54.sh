set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
test ! -e evidence-live/task54-ops
install -d -o 1000 -g 1000 evidence-live/task54-ops
(
  for iteration in $(seq 1 240); do
    if test -e evidence-live/task54-ops/restart-request; then
      docker kill --signal KILL task50-worker
      for retry in $(seq 1 30); do
        if ! docker inspect task50-worker >/dev/null 2>&1; then break; fi
        sleep 1
      done
      bash ops/agent_chat/start_worker.sh
      exit
    fi
    sleep 1
  done
  exit 1
) &
controller=$!
trap 'kill "$controller" 2>/dev/null || true' EXIT
sed 's/from lab_server import prepare/from mcp_lab_server import prepare/' ops/agent_chat/live_cases.py |
  docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai \
    -e REGULAY_LIVE_EVIDENCE_DIR=/evidence/task54-ops task50-web python -
wait "$controller"
test "$(docker inspect task50-worker --format '{{index .Config.Labels "regulay.task"}}')" = 50
docker stop -t 30 task50-worker
docker run --rm -i --label regulay.task=54 --network task50-exec --user 1000:1000 --read-only \
  --cap-drop ALL --security-opt no-new-privileges --dns 127.0.0.1 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50/.runtime,dst=/run/task50,readonly \
  regulay-task50-executor:local python - < ops/agent_chat/pool_live.py
bash ops/agent_chat/start_worker.sh
