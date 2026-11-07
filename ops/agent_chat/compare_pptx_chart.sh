set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task52-eval/evidence,dst=/evidence \
  --mount type=bind,src=/home/probe/task50/ops/agent_chat/compare_pptx_chart.py,dst=/compare.py,readonly \
  regulay-task52-pptx-evaluation:local python /compare.py
