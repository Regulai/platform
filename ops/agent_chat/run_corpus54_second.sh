set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
REGULAY_CORPUS_NAME=task54-corpus2 bash ops/agent_chat/run_corpus54.sh
