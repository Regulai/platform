set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
REGULAY_LIVE_TASK=52 bash ops/agent_chat/run_document_regressions.sh
