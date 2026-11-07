set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai task50-web python - < ops/agent_chat/document_audit.py
docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai task50-web python - < ops/agent_chat/document_http.py
