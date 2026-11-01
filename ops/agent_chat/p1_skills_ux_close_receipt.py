"""Read-only closeout after the Windows launcher waited on inherited handles."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import urllib.request

import p1_activate_local as activation
import p1_skills_ux_finish_update as finish


def main():
    activation.owner_check()
    root = activation.ROOT; out = root / 'output/p1-skills-ux-20261016'
    source = (root / 'ops/agent_chat/p1_skills_ux_finish_update.py').read_text(encoding='utf-8')
    assert hashlib.sha256(source.encode()).hexdigest() == '8009394a6345df83826444b8f8063c327e8b2e420a0839ea20f2f0a1281d390b'
    request = {'action': 'verify-terminal',
        'helper': (root / 'ops/agent_chat/p1_activation_remote.py').read_text(encoding='utf-8'),
        'ux': (root / 'ops/agent_chat/p1_skills_ux_update_remote.py').read_text(encoding='utf-8')}
    loader = '''import sys,json,io,contextlib
from pathlib import Path
request=json.loads(sys.stdin.buffer.readline());source=sys.stdin.buffer.read().decode()
ns={'__name__':'readonly_closeout','REQUEST':request};exec(compile(source,'coordinated.py','exec'),ns)
captured=io.StringIO()
with contextlib.redirect_stdout(captured):ns['guest']()
terminal=json.loads(captured.getvalue());stage=ns['STAGE'];state=json.loads((stage/ns['STATE']).read_text())
assert state['phase']=='applied' and terminal['safe_to_reopen_owned_tunnel']
before=json.loads((stage/'coordinated-before-data.json').read_text());helper=ns['helper']
helper['equal_fingerprints'](before,helper['web_exec']('fingerprint',current=True,payload=before))
expected=json.loads((stage/'before-source.json').read_text())|json.loads((stage/'state.json').read_text())['hashes']
assert helper['source_manifest']()==expected
print(json.dumps({'state':state,'terminal':terminal,'final_source_and_data_rechecked':True}))
'''
    result = subprocess.run([*activation.SSH, 'sudo python3 -c ' + shlex.quote(loader)],
        input=json.dumps(request).encode() + b'\n' + source.encode(), capture_output=True, timeout=40)
    if result.returncode: raise RuntimeError('readonly_terminal_closeout_failed')
    value = json.loads(result.stdout)
    code = "$connections=@(Get-NetTCPConnection -LocalPort 8800 | ForEach-Object { @{address=$_.LocalAddress;port=$_.LocalPort;state=[string]$_.State;pid=$_.OwningProcess} }); $process=Get-CimInstance Win32_Process -Filter 'ProcessId = 48888'; @{connections=$connections;pid=$process.ProcessId;command=$process.CommandLine} | ConvertTo-Json -Compress -Depth 5"
    tunnel = json.loads(subprocess.check_output(['rtk', 'proxy', 'powershell', '-NoProfile', '-Command', code]))
    finish.validate_ingress(tunnel, expected_pid=48888, idle=False)
    assert urllib.request.urlopen('http://127.0.0.1:8800/static/js/skills.js', timeout=10).status == 200
    receipt = {**value['state'], 'read_only_closeout': True, 'final_source_and_data_rechecked': True,
        'launcher_note': 'Guest apply and terminal verification succeeded. Windows RTK launcher waited after its PowerShell exited; only that completed launcher was stopped. No apply was repeated.'}
    (out / 'coordinated-apply.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    (out / 'tunnel-restored.json').write_text(json.dumps({'pid':48888,'port':8800,'loopback':True,
        'same_command':True,'hidden':True,'asset_status':200}, indent=2), encoding='utf-8')
    print(json.dumps({'phase':receipt['phase'],'candidate_id':receipt['candidate_id'],
        'worker_new_started_at':receipt['worker_new_started_at'],'source_and_data_rechecked':True,
        'tunnel_pid':48888,'asset_status':200,'provider_requests':0}))


if __name__ == '__main__':
    main()
