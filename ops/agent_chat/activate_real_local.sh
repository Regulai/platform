#!/bin/bash
# Explicit local upgrade of the existing Javi stack. Keep old containers and DB backup.
set -euo pipefail
test "$(hostname)" = task48-e2b-vm
base=/home/probe/regulai-javi-real
release=/home/probe/regulai-real-20261014
test -s "$base/private/before-professional-20261014.dump"
docker image inspect regulai-real-web:20261014 >/dev/null
docker image inspect regulai-real-worker:20261014 >/dev/null
if docker container inspect regulai-javi-real-web-before-professional >/dev/null 2>&1; then
    echo 'Initial migration already applied. Use start_real_local.py for normal startup.' >&2
    exit 1
fi
docker stop -t 30 regulai-javi-real-worker regulai-javi-real-web
docker run --rm -i --network host --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
 --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=1000,gid=1000 \
 --mount type=bind,src="$base/private",dst=/run/private,readonly \
 --mount type=bind,src="$release/ops/agent_chat/real_server.py",dst=/run/server.py,readonly \
 regulai-real-web:20261014 python - <<'PY'
import runpy
runpy.run_path('/run/server.py', run_name='configure')
from django.core.management import call_command
from django.db import transaction
from django.contrib.auth.models import User
from front.models import AgentAccessGrant, AgentModelProfile, Role
from front.agents.capabilities import GENERAL
call_command('migrate', interactive=False, verbosity=1)
with transaction.atomic():
    actor = User.objects.get(pk=1, profile__company_id=3)
    actor.username = 'admin'
    actor.is_staff = actor.is_superuser = True
    actor.save(update_fields=['username', 'is_staff', 'is_superuser'])
    actor.profile.role = Role.objects.get_or_create(name='Admin')[0]
    actor.profile.save(update_fields=['role'])
    profile = AgentModelProfile.objects.select_for_update().get(company_id=actor.profile.company_id, name='Documentos con DeepSeek real')
    profile.professional = profile.enabled = True
    profile.tools = sorted(GENERAL)
    profile.limits = {'model_calls': 48, 'tool_calls': 120, 'run_seconds': 1800}
    profile.save(update_fields=['professional', 'enabled', 'tools', 'limits'])
    AgentAccessGrant.objects.update_or_create(company_id=profile.company_id, user=actor, defaults={'profile': profile, 'enabled': True})
    company = actor.profile.company
    for level in ('public', 'internal'):
        destinations = company.ai_config['destinations'][level]
        for target in ('research:web', 'research:packages'):
            if target not in destinations:
                destinations.append(target)
    company.ai_config['revision'] += 1
    company.save(update_fields=['ai_config'])
print('Existing real account configured; credentials unchanged.')
PY
test -f "$base/worker/config-before-professional.json" || cp -p "$base/worker/config.json" "$base/worker/config-before-professional.json"
python3 - <<'PY'
from pathlib import Path
import json
path = Path('/home/probe/regulai-javi-real/worker/config.json')
config = json.loads(path.read_text())
config['template'] = 'regulai-professional-20261014'
path.write_text(json.dumps(config))
PY
docker rename regulai-javi-real-web regulai-javi-real-web-before-professional
docker rename regulai-javi-real-worker regulai-javi-real-worker-before-professional
docker run -d --name regulai-javi-real-web --label regulay.purpose=javi-real --network host \
 --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges \
 --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000 \
 --mount type=bind,src="$base/private",dst=/run/private,readonly \
 --mount type=bind,src="$release/ops/agent_chat/real_server.py",dst=/run/server.py,readonly \
 regulai-real-web:20261014 python /run/server.py
docker run -d --name regulai-javi-real-worker --label regulay.purpose=javi-real --network task50-exec \
 --user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges --dns 127.0.0.1 \
 --memory 1024m --cpus 1 --pids-limit 128 --tmpfs /tmp:rw,nosuid,nodev,size=128m,uid=1000,gid=1000 \
 --mount type=bind,src="$base/worker",dst=/run/task50,readonly \
 --mount type=bind,src="$base/checkpoints",dst=/state regulai-real-worker:20261014
