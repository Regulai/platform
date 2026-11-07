"""Close only this task's isolated lab and unused Windows launch wrapper."""
import json
from pathlib import Path
import subprocess
import urllib.request

import p1_activate_local as activation
import p1_skills_ux_auto_update as update
import p1_skills_ux_finish_update as guards
import p1_skills_ux_lab as lab
import p1_skills_ux_close_lab as lab_close

OUT=lab.OUT/'auto'


def powershell(code):
    return subprocess.check_output(['rtk','proxy','powershell','-NoProfile','-Command',code]).decode('utf-8-sig').strip()


def main():
    activation.owner_check();lab.owner_check()
    applied=json.loads((OUT/'apply.json').read_text(encoding='utf-8'))
    tunnel=json.loads((OUT/'tunnel-restored.json').read_text(encoding='utf-8'))
    live=json.loads((OUT/'browser-live.json').read_text(encoding='utf-8'))
    if applied['phase']!='applied' or not live['persistent_data_unchanged_except_temporary_session']:
        raise RuntimeError('verified_live_update_required_before_lab_cleanup')
    guards.validate_ingress(update.snapshot(),expected_pid=tunnel['pid'],idle=False)
    server=json.loads(powershell("$c=Get-NetTCPConnection -LocalPort 8873 -State Listen; if ($c.OwningProcess -ne 46184) { throw 'owned_lab_listener_changed' }; Get-CimInstance Win32_Process -Filter 'ProcessId = 46184' | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"))
    if server['CommandLine']!='"C:\\Users\\javi\\AppData\\Roaming\\uv\\python\\cpython-3.12-windows-x86_64-none\\python.exe"  ops/agent_chat/p1_skills_ux_lab.py serve':
        raise RuntimeError('owned_lab_command_changed')
    powershell("$p=Get-CimInstance Win32_Process -Filter 'ProcessId = 46184'; if ($p.CommandLine -ne '\"C:\\Users\\javi\\AppData\\Roaming\\uv\\python\\cpython-3.12-windows-x86_64-none\\python.exe\"  ops/agent_chat/p1_skills_ux_lab.py serve') { throw 'owned_lab_command_changed' }; Stop-Process -Id 46184")
    lab_close.main()
    subprocess.run(['rtk','proxy','docker','stop','--time','30',lab.PG_ID],check=True,stdout=subprocess.DEVNULL)
    pg=json.loads(subprocess.check_output(['rtk','proxy','docker','inspect',lab.PG_ID]))[0]
    if pg['State']['Running']:raise RuntimeError('owned_lab_postgres_not_stopped')
    # The launcher owns no tunnel process; its only permitted residual child is
    # its console host. Match the complete command before stopping the wrapper.
    reopen="Start-Process -FilePath 'rtk' -ArgumentList @('proxy','C:/Users/javi/AppData/Local/Programs/Python/Python314/python.exe','ops/agent_chat/p1_activate_local.py','tunnel','--port','8800') -WorkingDirectory 'C:/Users/javi/Documents/Codex/regulai-platform' -WindowStyle Hidden -RedirectStandardOutput '"+(OUT/'tunnel.log').as_posix()+"' -RedirectStandardError '"+(OUT/'tunnel-error.log').as_posix()+"' | Out-Null"
    process=json.loads(powershell("Get-CimInstance Win32_Process -Filter 'ProcessId = 46076' | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress") or 'null')
    wrapper_closed=False
    if process:
        if tunnel['launcher_pid']!=46076 or process['CommandLine']!='rtk proxy powershell -NoProfile -Command "'+reopen+'"':
            raise RuntimeError('owned_wrapper_command_changed')
        children=json.loads(powershell("@(Get-CimInstance Win32_Process | Where-Object {$_.ParentProcessId -eq 46076} | Select-Object ProcessId,CommandLine) | ConvertTo-Json -Compress") or '[]')
        if isinstance(children,dict):children=[children]
        if any(row['CommandLine']!='\\??\\C:\\WINDOWS\\system32\\conhost.exe 0x4' for row in children):
            raise RuntimeError('wrapper_has_unexpected_children')
        powershell('Stop-Process -Id 46076');wrapper_closed=True
    guards.validate_ingress(update.snapshot(),expected_pid=tunnel['pid'],idle=False)
    with urllib.request.urlopen('http://127.0.0.1:8800/static/js/skills.js',timeout=5) as response:
        if response.status!=200:raise RuntimeError('preserved_tunnel_not_healthy')
    code='''import json,subprocess
names=['regulai-v2-web','regulai-v2-worker','regulai-v2-postgres','regulai-v2-web-before-p1-20261017-skills-auto-a1','regulai-v2-web-before-p1-20261016-skills-ux-a1']
rows=json.loads(subprocess.check_output(['docker','inspect',*names]))
print(json.dumps({r['Name'].lstrip('/'):{'id':r['Id'],'image':r['Image'],'running':r['State']['Running'],'started_at':r['State']['StartedAt'],'exit_code':r['State']['ExitCode']} for r in rows}))
'''
    result=subprocess.run([*activation.SSH,'sudo python3 -'],input=code.encode(),capture_output=True,check=True)
    services=json.loads(result.stdout)
    if (services[update.WEB]['id']!=applied['candidate_id'] or services[update.WEB]['image']!=applied['image_id']
            or services[update.WORKER]['id']!=update.WORKER_ID or services[update.WORKER]['started_at']!=applied['worker_new_started_at']
            or services[update.PG]['id']!=update.PG_ID or services[update.PG]['started_at']!=applied['started_at'][update.PG]
            or any(not services[name]['running'] for name in (update.WEB,update.WORKER,update.PG))):
        raise RuntimeError('final_live_service_identity_changed')
    receipt={'lab_server_closed':True,'lab_database_removed':lab.DATABASE,'lab_postgres_stopped':lab.PG_ID,
        'lab_volume_retained':True,'private_browser_state_removed':not (lab.OUT/'private/browser-state.json').exists(),
        'idle_launcher_closed':wrapper_closed,'tunnel_pid':tunnel['pid'],'tunnel_http_status':200,
        'services':services,'provider_requests':0}
    (OUT/'cleanup.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':
    main()
