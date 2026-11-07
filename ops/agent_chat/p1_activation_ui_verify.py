"""Inspect the activated local v2 UI without sending a prompt or altering grants.

Uses a temporary authenticated browser session, revoked in finally. Authentication
material travels over stdin/private storage, never command-line arguments or logs.
"""
import json
from pathlib import Path
import subprocess
import tempfile

import p1_activate_local as activation
import p1_stream_browser_latency as ui

OUT = activation.ROOT / 'output/p1-activation-20261016'
BASE = 'http://127.0.0.1:8800'


def remote(action, session=None):
    activation.owner_check()
    code = '''import importlib,json,sys,hashlib
sys.path.insert(0,'/run/p1')
from p1_activation_remote import _configure
settings=_configure()
from django.contrib.auth import get_user_model
from django.db import connection
from front.agents.skills import actor_profile,installation_view
from front.models import AgentSkillInstallation
SessionStore=importlib.import_module(settings.SESSION_ENGINE).SessionStore
request=REQUEST
actor=get_user_model().objects.get(pk=settings.PLATFORM_ADMIN_USER_IDS[0],is_active=True)
if request['action']=='session':
 session=SessionStore()
 session['_auth_user_id']=str(actor.pk)
 session['_auth_user_backend']='django.contrib.auth.backends.ModelBackend'
 session['_auth_user_hash']=actor.get_session_auth_hash()
 session.set_expiry(3600)
 session.save()
 print(json.dumps({'name':settings.SESSION_COOKIE_NAME,'value':session.session_key}))
elif request['action']=='revoke':
 SessionStore(session_key=request['session']).delete()
 print(json.dumps({'revoked':True}))
elif request['action']=='verify':
 _,profile=actor_profile(actor)
 rows=AgentSkillInstallation.objects.filter(owner=actor,source_identity='github:leonxlnx/taste-skill/skills/taste-skill',tombstoned_at__isnull=True)
 assert rows.count()==1
 installed=installation_view(rows.get(),profile)
 assert installed['enabled'] and installed['availability']['available']
 with connection.cursor() as cursor:
  cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'django_session' ORDER BY table_name")
  tables=[row[0] for row in cursor.fetchall()]
  invariants={}
  for table in tables:
   quoted=connection.ops.quote_name(table)
   cursor.execute('SELECT md5(row_to_json(t)::text) FROM '+quoted+' t ORDER BY 1')
   rows=cursor.fetchall()
   invariants[table]={'count':len(rows),'sha256':hashlib.sha256('\\n'.join(row[0] for row in rows).encode()).hexdigest()}
 print(json.dumps({'installation':installed,'invariants':invariants}))
else:
 raise RuntimeError('unknown_ui_action')
'''.replace('REQUEST', repr({'action': action, 'session': session}))
    command = [*activation.SSH, 'sudo docker exec -i regulai-v2-web python -']
    result = subprocess.run(command, input=code.encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError('live_ui_metadata_failed:' + action)
    return json.loads(result.stdout)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ui.OUT, ui.SESSION = OUT, 'p1-activation-live'
    before = remote('verify')
    credential = remote('session')
    try:
        # TemporaryDirectory owns only this new folder; it contains no user files.
        with tempfile.TemporaryDirectory(prefix='regulai-p1-ui-') as directory:
            state = Path(directory) / 'browser-state.json'
            state.write_text(json.dumps({'cookies': [{**credential, 'domain': '127.0.0.1',
                'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False,
                'sameSite': 'Lax'}], 'origins': []}), encoding='utf-8')
            ui.cli('open', BASE + '/login/')
            ui.cli('state-load', str(state))
            ui.browser('''async page=>{
              await page.route('**/*',route=>['GET','HEAD'].includes(route.request().method())?route.continue():route.abort('blockedbyclient'));
              return {mutatingRequestsBlocked:true};
            }''')
            ui.cli('goto', BASE + '/skills/')
            (OUT / 'live-library-snapshot.txt').write_text(ui.cli('snapshot'), encoding='utf-8')
            result = ui.browser('''async page=>{
              const errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));
              page.on('request',request=>{if(request.method()!=='GET')requests.push({method:request.method(),path:new URL(request.url()).pathname});});
              const rows=[];
              for(const width of [360,768,1440]){
                await page.setViewportSize({width,height:900});
                await page.goto(BASE+'/skills/');
                await page.locator('#skillsInstalled').click();
                await page.getByRole('heading',{name:'design-taste-frontend',exact:true}).waitFor();
                const library=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,runtimeNotice:!document.getElementById('skillRuntimeStatus').hidden}));
                await page.screenshot({path:DIR+'/p1-live-skills-'+width+'.png'});
                await page.goto(BASE+'/skills/installations/'+ID+'/');
                const detail=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,useEnabled:!document.getElementById('skillInstall').disabled,canDisable:[...document.querySelectorAll('button')].some(b=>b.textContent==='Deshabilitar'),canUpdate:[...document.querySelectorAll('button')].some(b=>b.textContent==='Actualizar paquete')}));
                await page.screenshot({path:DIR+'/p1-live-taste-'+width+'.png'});
                await page.locator('#skillInstall').click();
                await page.waitForURL('**/chat/');
                await page.waitForFunction(()=>document.querySelector('#skillChips')?.textContent.includes('design-taste-frontend'));
                const chat=await page.evaluate(()=>({overflow:document.documentElement.scrollWidth>innerWidth,pickerEnabled:!document.getElementById('skillPickerButton').disabled,autoEnabled:!document.getElementById('skillAuto').disabled,autoChecked:document.getElementById('skillAuto').checked,selected:window.regulaySkills.capture().selected.length}));
                /* The off-canvas sidebar still has a bounding box on mobile.
                   Screenshot-only visibility hides titles without placing a
                   mask over the visible composer at narrow widths. */
                await page.screenshot({path:DIR+'/p1-live-chat-'+width+'.png',style:'#threadList { visibility: hidden !important; }'});
                rows.push({width,library,detail,chat});
              }
              return {rows,errors,mutatingRequests:requests};
            }'''.replace('BASE', json.dumps(BASE)).replace('ID', json.dumps(before['installation']['id']))
                .replace('DIR', json.dumps((activation.ROOT / 'output/playwright').as_posix())))
            if result['errors'] or result['mutatingRequests']:
                raise RuntimeError('live_ui_errors_or_unexpected_mutations:' + json.dumps(result))
            for row in result['rows']:
                assert row['library'] == {'overflow': False, 'runtimeNotice': False}, row
                assert row['detail'] == {'overflow': False, 'useEnabled': True, 'canDisable': True, 'canUpdate': True}, row
                assert row['chat'] == {'overflow': False, 'pickerEnabled': True, 'autoEnabled': True, 'autoChecked': True, 'selected': 1}, row
            after = remote('verify')
            assert before == after, 'live_ui_changed_persistent_data'
            report = {'instance': 'regulai-v2', 'url': BASE, 'fixture': False,
                'provider_requests': 0, 'persistent_data_unchanged_except_session': True,
                'conversation_titles_masked_in_screenshots': True,
                'redaction_mode': 'screenshot-only thread-list visibility; no overlay',
                'installation': before['installation'], **result}
            (OUT / 'live-ui.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
            print(json.dumps(report))
    finally:
        try:
            ui.cli('close')
        finally:
            remote('revoke', credential['value'])


if __name__ == '__main__':
    main()
