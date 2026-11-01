set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
name=${REGULAY_CORPUS_NAME:-task54-corpus}
case "$name" in task54-corpus|task54-corpus2) ;; *) exit 2 ;; esac
test ! -e "evidence-live/$name"
docker run --rm --label regulay.task=54 --network none --user 1000:1000 --cap-drop ALL \
  --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50,dst=/source,readonly \
  --mount type=bind,src=/home/probe/task50/evidence-live,dst=/evidence \
  -e XDG_CACHE_HOME=/tmp/cache -e DCONF_PROFILE=/dev/null \
  regulay-task50-spreadsheet:local python /source/ops/agent_chat/document_corpus.py run "/evidence/$name"
