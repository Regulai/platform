#!/bin/bash
set -euo pipefail
cd /opt/regulai/source
sysctl -w vm.nr_hugepages=1536
docker compose --project-directory /home/probe/e2b run --rm --no-deps host-setup
docker compose --project-directory /home/probe/e2b up -d --no-deps --wait --wait-timeout 600 postgres redis clickhouse vector orchestrator api dashboard-api client-proxy dashboard ready
bash ops/setup/network.sh
docker start regulai-v2-postgres regulai-v2-web
for attempt in $(seq 1 60); do
    if curl --fail --silent --output /dev/null http://127.0.0.1:31058/; then break; fi
    sleep 1
done
curl --fail --silent --output /dev/null http://127.0.0.1:31058/
docker exec regulai-v2-web python /app/ops/setup/verify_web.py
# Do not interrupt an in-flight document when opening another local tunnel.
if [ "$(docker inspect --format '{{.State.Running}}' regulai-v2-worker)" = true ]; then
    echo 'Existing worker retained; no active request interrupted.'
    exit 0
fi
docker run --rm --network regulai-v2-exec --user 1000:1000 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --dns 127.0.0.1 --memory 512m --pids-limit 64 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/opt/regulai/worker,dst=/run/task50,readonly \
  --mount type=bind,src=/opt/regulai/source/ops/setup/verify_sandbox.py,dst=/verify.py,readonly \
  regulai-v2-worker:local python /verify.py
docker start regulai-v2-worker
echo 'Web, PostgreSQL, worker and real E2B renderer are ready.'
