set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
python3 ops/agent_chat/network_live.py
