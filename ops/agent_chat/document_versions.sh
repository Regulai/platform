set -euo pipefail
test "$(hostname)" = task48-e2b-vm
docker image inspect regulay-task50-spreadsheet:local --format '{{.Id}}'
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges regulay-task50-spreadsheet:local \
  dpkg-query -W libreoffice-writer libreoffice-calc poppler-utils fonts-liberation
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges regulay-task50-spreadsheet:local python -m pip list --format json
