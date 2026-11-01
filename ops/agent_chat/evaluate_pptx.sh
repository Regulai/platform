set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task52-eval
tar -xf /home/probe/task52-evaluation.tar
install -d -o 1000 -g 1000 evidence
docker run --rm --name task52-officecli-eval --label regulay.task=52 --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task52-eval/evidence,dst=/evidence \
  --mount type=bind,src=/home/probe/task52-eval/ops/agent_chat/evaluate_pptx.py,dst=/evaluate.py,readonly \
  regulay-task52-pptx-evaluation:local python /evaluate.py
