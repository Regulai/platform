set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
for script in document_audit.py document_http.py; do
  docker exec -i -e PYTHONPATH=/app/ops/agent_chat:/app/regulai \
    -e REGULAY_DOCUMENT_CASE=presentation-runs -e REGULAY_DOCUMENT_FIRST_CHAT=7 \
    task50-web python - < "ops/agent_chat/$script"
done
