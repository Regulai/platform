set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
bash ops/agent_chat/audit_export_model.sh task54-ui-before
bash ops/agent_chat/start_mcp_lab.sh
