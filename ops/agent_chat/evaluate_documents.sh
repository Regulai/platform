#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
mkdir -p /home/probe/task51-eval
cd /home/probe/task51-eval
tar -xf /home/probe/task51-evaluation.tar
docker build -t regulay-task51-docx-evaluation:local -f ops/agent_chat/Dockerfile.docx-evaluation .
mkdir -p evidence
chown 1000:1000 evidence
docker run --rm --name task51-branddocs-eval --label regulay.task=51 --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 128 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task51-eval/evidence,dst=/evidence \
  regulay-task51-docx-evaluation:local python ops/agent_chat/evaluate_branddocs.py /evidence/branddocs
