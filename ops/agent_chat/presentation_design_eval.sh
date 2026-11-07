set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
install -d -o 1000 -g 1000 /home/probe/task52-eval/evidence
docker run --rm --name task52-design --label regulay.task=52 --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task52-eval/evidence,dst=/evidence \
  --mount type=bind,src=/home/probe/task50,dst=/lab,readonly \
  regulay-task52-pptx-evaluation:local python /lab/ops/agent_chat/presentation_design_eval.py
