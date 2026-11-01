set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
# Read-only test code runs in the synthetic application, never the executor.
docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai task50-web python - < ops/agent_chat/audit_live.py
docker logs task50-worker > evidence-live/worker.log 2>&1
