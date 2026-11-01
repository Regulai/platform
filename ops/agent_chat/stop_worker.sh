set -euo pipefail
test "$(hostname)" = task48-e2b-vm
test "$(docker inspect task50-worker --format '{{index .Config.Labels "regulay.task"}}')" = 50
docker stop -t 30 task50-worker
