"""Visual availability checks in the retained isolated browser fixture; no generation."""
import argparse
import json
import uuid

import p1_stream_browser_latency as ui


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--runtime',choices=('on','off'),required=True)
    args=parser.parse_args()
    import p1_ui_lab  # configuration only, never main()
    from django.conf import settings
    settings.DATABASES['default']['NAME']='test_regulai_p1_browser'
    import django
    django.setup()
    from django.db import connection
    from django.contrib.auth.models import User
    from django.test import Client
    from front.models import AgentSkillInstallation,Profile
    lab=json.loads((ui.ROOT/'output/p1-20261016/ui-lab.json').read_text(encoding='utf-8'))
    assert lab['fixture'] and connection.settings_dict['NAME']==lab['database']=='test_regulai_p1_browser'
    assert connection.settings_dict['HOST']=='127.0.0.1' and str(connection.settings_dict['PORT'])=='55468'
    actor=User.objects.get(username='p1-ui')
    installed=AgentSkillInstallation.objects.filter(owner=actor,enabled=True,tombstoned_at__isnull=True).first()
    assert installed is not None
    outsider=User.objects.create_user('p1-ui-no-skills-'+uuid.uuid4().hex[:8])
    Profile.objects.create(user=outsider,company=actor.profile.company)
    client=Client();client.force_login(outsider)
    no_grant_cookie=client.cookies[settings.SESSION_COOKIE_NAME].value
    url='http://127.0.0.1:8872'
    ui.SESSION='p1-skills-activation'
    capture=ui.ROOT/'output/playwright'
    try:
        ui.cli('open',url)
        cookies=[{'name':lab['cookie_name'],'value':lab['session_cookie'],'url':url}]
        results=ui.browser('''async page=>{
          await page.context().addCookies(COOKIES);
          const errors=[];page.on('pageerror',error=>errors.push(error.message));
          const rows=[];
          for(const width of [360,768,1440]){
            await page.setViewportSize({width,height:900});
            await page.goto(BASE+'/skills/');await page.locator('#skillsInstalled').click();
            await page.waitForFunction(()=>document.querySelector('#skillGrid button')?.textContent==='Usar en chat');
            const library=await page.evaluate(()=>({use:[...document.querySelectorAll('#skillGrid button')].filter(b=>b.textContent==='Usar en chat').map(b=>b.disabled),notice:!document.getElementById('skillRuntimeStatus').hidden,overflow:document.documentElement.scrollWidth>innerWidth}));
            await page.screenshot({path:DIR+'/p1-skills-runtime-'+MODE+'-library-'+width+'.png'});
            await page.goto(BASE+'/skills/installations/'+ID+'/');
            const detail=await page.evaluate(()=>({useDisabled:document.getElementById('skillInstall').disabled,canUpdate:[...document.querySelectorAll('button')].some(b=>b.textContent==='Actualizar paquete'&&!b.disabled),notice:!!document.getElementById('skillRuntimeStatus'),overflow:document.documentElement.scrollWidth>innerWidth}));
            await page.screenshot({path:DIR+'/p1-skills-runtime-'+MODE+'-detail-'+width+'.png'});
            await page.goto(BASE+'/chat/');await page.waitForFunction(()=>window.regulaySkills);
            const chat=await page.evaluate(()=>({pickerDisabled:document.getElementById('skillPickerButton').disabled,autoDisabled:document.getElementById('skillAuto').disabled,selectionOmitted:window.regulaySkills.capture()===undefined,notice:!!document.getElementById('skillRuntimeStatus'),overflow:document.documentElement.scrollWidth>innerWidth}));
            await page.screenshot({path:DIR+'/p1-skills-runtime-'+MODE+'-chat-'+width+'.png'});
            rows.push({width,library,detail,chat});
          }
          await page.context().addCookies(NO_GRANT);
          await page.goto(BASE+'/chat/');
          const hidden=await page.locator('a[title="Skills"]').count()===0;
          const response=await page.goto(BASE+'/skills/');
          await page.screenshot({path:DIR+'/p1-skills-no-grant-'+MODE+'.png'});
          return {rows,errors,no_grant:{menuHidden:hidden,status:response.status(),html:response.headers()['content-type'].includes('text/html'),actionable:await page.getByText('Volver al chat').count()===1}};
        }'''.replace('COOKIES',json.dumps(cookies)).replace('NO_GRANT',json.dumps([{'name':lab['cookie_name'],'value':no_grant_cookie,'url':url}])).replace('BASE',json.dumps(url)).replace('DIR',json.dumps(capture.as_posix())).replace('MODE',json.dumps(args.runtime)).replace('ID',json.dumps(str(installed.pk))))
        disabled=args.runtime=='off'
        assert not results['errors'],results
        for row in results['rows']:
            assert row['library']['use'] and all(value==disabled for value in row['library']['use']),row
            assert row['library']['notice']==disabled and not row['library']['overflow'],row
            assert row['detail']['useDisabled']==disabled and row['detail']['canUpdate'] and not row['detail']['overflow'],row
            assert row['chat']['pickerDisabled']==row['chat']['autoDisabled']==row['chat']['selectionOmitted']==disabled,row
            assert row['chat']['notice']==disabled and not row['chat']['overflow'],row
        assert results['no_grant']=={'menuHidden':True,'status':403,'html':True,'actionable':True},results
        report={'fixture':True,'provider_requests':0,'runtime':args.runtime,**results}
        (ui.ROOT/f'output/p1-20261016/e8/skills-activation-ui-{args.runtime}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report))
    finally:
        ui.cli('close');connection.close()


if __name__=='__main__':main()
