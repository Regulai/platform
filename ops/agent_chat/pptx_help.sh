set -euo pipefail
test "$(hostname)" = task48-e2b-vm
mkdir -p /home/probe/task52-eval
cd /home/probe/task52-eval
tar -xf /home/probe/task52-evaluation.tar
docker build --network none -t regulay-task52-pptx-evaluation:local -f ops/agent_chat/Dockerfile.pptx-evaluation .
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000 \
  regulay-task52-pptx-evaluation:local officecli --version
for item in shape slide table chart /; do
  docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000 \
    regulay-task52-pptx-evaluation:local officecli help pptx "$item" --json
done
