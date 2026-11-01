set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
test ! -e evidence-live/restart-request
(
  for iteration in $(seq 1 240); do
    if test -e evidence-live/restart-request; then
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
docker exec task50-web python ops/agent_chat/live_cases.py </dev/null
wait "$controller"
docker logs task50-worker
