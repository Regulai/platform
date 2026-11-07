set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
bash ops/agent_chat/document_versions.sh
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges regulay-task50-spreadsheet:local \
  dpkg-query -W libreoffice-impress
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges regulay-task50-spreadsheet:local \
  officecli --version
docker run --rm --network none --read-only --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges regulay-task50-spreadsheet:local \
  sha256sum /usr/local/bin/officecli /skills/corporate.pptx /skills/corporate.docx
