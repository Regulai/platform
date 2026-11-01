#!/bin/bash
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
cd /home/probe/task50
tar -xf /home/probe/task50-source.tar
docker build -t regulay-task50-executor:local -f ops/agent_chat/Dockerfile.executor .
docker build -t regulay-task50-web:local -f ops/agent_chat/Dockerfile.web .
docker run -d --rm --name task50-postgres --label regulay.task=50 \
  -p 127.0.0.1:55450:5432 -e POSTGRES_USER=lab -e POSTGRES_PASSWORD=synthetic-task50-only \
  -e POSTGRES_DB=regulai_task50 postgres:17-alpine
docker network create --internal --ipv6 --subnet 172.30.50.0/24 --subnet fd50:50::/64 \
  --opt com.docker.network.bridge.name=br-task50 --label regulay.task=50 task50-exec
iptables -N TASK50_EXEC
iptables -A TASK50_EXEC -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A TASK50_EXEC -p tcp -m multiport --dports 3000,3002,31049 -j ACCEPT
iptables -A TASK50_EXEC -j REJECT --reject-with icmp-admin-prohibited
iptables -I INPUT 1 -i br-task50 -j TASK50_EXEC
ip6tables -I INPUT 1 -i br-task50 -j REJECT
mkdir -p evidence-live
chmod 0777 evidence-live
docker run -d --rm --name task50-web --label regulay.task=50 --network host \
  --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
  --mount type=bind,src=/home/probe/task50/evidence-live,dst=/evidence \
  regulay-task50-web:local python ops/agent_chat/lab_server.py --host 0.0.0.0 --port 31049 --evidence /evidence/model-requests.json
python3 - <<'PY'
from pathlib import Path
import json, time, urllib.request
for i in range(60):
    try:
        urllib.request.urlopen('http://127.0.0.1:31049/login/',timeout=2).close()
        break
    except Exception:
        time.sleep(1)
else:
    raise RuntimeError('Synthetic ASGI server did not start')
Path('.runtime/worker-token').write_text('synthetic-task50-worker-key-32-characters')
Path('.runtime/config.json').write_text(json.dumps({'api_url':'http://172.30.50.1:3000',
    'sandbox_url':'http://172.30.50.1:3002','api_key_file':'/run/task50/e2b-key', 'template':'task50-excel',
    'internal_endpoint':'http://172.30.50.1:31049/internal/agents/', 'worker_token_file':'/run/task50/worker-token'}))
PY
bash ops/agent_chat/start_worker.sh
echo 'Synthetic ASGI service and fenced worker ready'
