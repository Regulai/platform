"""Restore the exact idle worker which exited when its web claim endpoint stopped."""
import hashlib
import json
import shlex
import subprocess

import p1_activate_local as activation

ROOT = activation.ROOT
OUT = ROOT / 'output/p1-skills-ux-20261016'


def main():
    activation.owner_check()
    helper = (ROOT / 'ops/agent_chat/p1_activation_remote.py').read_text(encoding='utf-8')
    code = '''import json,hashlib,time
from pathlib import Path
ns={'__name__':'recovery_helpers','_ACTIVATION_SOURCE':HELPER}
exec(compile(HELPER,'recovery_helpers.py','exec'),ns)
stage=Path('/opt/regulai/updates/p1-20261016-skills-ux-a1')
read=ns['read_json'];inspect=ns['inspect'];docker=ns['docker']
original=read(stage/'original-containers.json')
names=('regulai-v2-web','regulai-v2-worker','regulai-v2-postgres')
rows={name:inspect(name) for name in names}
assert ns['original_identity'](rows)==ns['original_identity'](original),'original_configuration_changed'
worker=rows['regulai-v2-worker']
assert worker['Id']=='4db24e54101297114ab2a036fd16c20a0683b749f66b6aa7b3bb00ff5886fb36'
assert not worker['State']['Running'] and worker['State']['ExitCode']==1
assert worker['State']['FinishedAt']=='2026-10-16T21:56:56.615064383Z'
assert worker['Config']['Cmd']==['python','-m','front.agents.worker','--config','/run/task50/config.json'] and worker['Config']['Entrypoint'] is None
assert rows['regulai-v2-web']['State']['Running'] and rows['regulai-v2-postgres']['State']['Running']
assert ns['source_manifest']()==read(stage/'before-source.json'),'original_web_source_changed'
metadata=ns['require_idle'](current=True)
expected=read(stage/'before-apply-data.json')
before=ns['web_exec']('fingerprint',current=True,payload=expected)
ns['equal_fingerprints'](expected,before)
docker('start',worker['Id'])
started=inspect(worker['Id'])
for sample in range(6):
 current=inspect(worker['Id'])
 assert current['State']['Running'] and current['State']['ExitCode']==0 and current['RestartCount']==0
 assert current['State']['StartedAt']==started['State']['StartedAt']
 assert ns['original_identity']({'worker':current})==ns['original_identity']({'worker':worker})
 if sample<5:time.sleep(2)
after=ns['web_exec']('fingerprint',current=True,payload=before)
ns['equal_fingerprints'](before,after)
assert ns['require_idle'](current=True)==metadata
for name in ('regulai-v2-web','regulai-v2-postgres'):
 current=inspect(name)
 assert current['State']['StartedAt']==rows[name]['State']['StartedAt'] and current['Id']==rows[name]['Id']
print(json.dumps({'worker_id':worker['Id'],'old_started_at':worker['State']['StartedAt'],'new_started_at':started['State']['StartedAt'],'observed_exit_before_recovery':1,'code_image_configuration_unchanged':True,'data_and_money_fingerprints_unchanged':True,'web_and_postgres_lifetime_unchanged_during_recovery':True,'stable_seconds':10,'metadata':metadata,'provider_requests':0}))
'''.replace('HELPER', repr(helper))
    result = subprocess.run([*activation.SSH, 'sudo python3 -'], input=code.encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError('exact_idle_worker_recovery_failed:' + str(result.returncode))
    value = json.loads(result.stdout)
    value['recovery_script_sha256'] = hashlib.sha256(__import__('pathlib').Path(__file__).read_bytes()).hexdigest()
    (OUT / 'worker-recovery.json').write_text(json.dumps(value, indent=2), encoding='utf-8')
    print(json.dumps(value, indent=2))


if __name__ == '__main__':
    main()
