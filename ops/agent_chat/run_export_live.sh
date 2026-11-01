set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
test ! -e evidence-live/task54-live
(
  for iteration in $(seq 1 240); do
    if test -e evidence-live/task54-live/restart-request; then
      test "$(docker inspect task50-worker --format '{{index .Config.Labels "regulay.task"}}')" = 50
      docker logs task50-worker > evidence-live/task54-worker-before-kill.log
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
docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai task50-web python - < ops/agent_chat/export_live.py
wait "$controller"
sleep 3
docker exec task50-worker python -c 'import sqlite3; conn=sqlite3.connect("/state/checkpoints.sqlite"); assert conn.execute("SELECT count(*) FROM checkpoints").fetchone()[0] == 0; print("Retained graph checkpoints pruned after conversation deletion")'
docker logs task50-worker > evidence-live/task54-worker.log
