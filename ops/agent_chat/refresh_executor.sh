set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker build -t regulay-task50-executor:local -f ops/agent_chat/Dockerfile.executor .
if docker ps --format '{{.Names}}' | grep -qx task50-worker; then docker stop -t 30 task50-worker; fi
python3 ops/agent_chat/network_live.py
