"""Read-only actual automatic Skills UX, temporary session revoked in finally."""
import json
from pathlib import Path
import tempfile

import p1_activation_ui_verify as activation_ui
import p1_skills_ux_browser as runner
import p1_skills_ux_lab as lab
import p1_stream_browser_latency as ui

OUT = lab.OUT / 'auto'
BASE = 'http://127.0.0.1:8800'


def main():
    ui.OUT, ui.SESSION, runner.OUT = OUT, 'p1-skills-ux-auto-live', OUT
    captures=OUT/'live-screenshots';captures.mkdir(exist_ok=True)
    before=activation_ui.remote('verify')
    credential=activation_ui.remote('session')
    try:
        with tempfile.TemporaryDirectory(prefix='regulai-auto-live-') as temporary:
            state=Path(temporary)/'browser-state.json'
            state.write_text(json.dumps({'cookies':[{**credential,'domain':'127.0.0.1','path':'/',
                'expires':-1,'httpOnly':True,'secure':False,'sameSite':'Lax'}],'origins':[]}),encoding='utf-8')
            ui.cli('open',BASE+'/static/js/skills.js');ui.cli('state-load',str(state))
            result=runner.browser(r'''async page=>{
              const base=BASE,id=ID,name=NAME,dir=DIR,errors=[],mutations=[],requests=[],rows=[];
              const check=(ok,label)=>{if(!ok)throw Error(label);};
              await page.route('**/*',route=>['GET','HEAD'].includes(route.request().method())?route.continue():route.abort('blockedbyclient'));
              page.on('pageerror',e=>errors.push(e.message));
              page.on('request',r=>{requests.push(r.url());if(!['GET','HEAD'].includes(r.method()))mutations.push(new URL(r.url()).pathname);});
              const ready=async()=>page.waitForFunction(()=>window.regulaySkills);
              const loaded=async()=>page.waitForFunction(()=>document.getElementById('skillOptions')?.getAttribute('aria-busy')==='false');
              const shot=async(key,width)=>{
                if(width<992)await page.waitForFunction(()=>getComputedStyle(document.getElementById('threads')).visibility==='hidden');
                check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow:'+key+width);
                await page.screenshot({path:dir+'/'+key+'-'+width+'.png',style:'#threadList { visibility: hidden !important; }'});
              };
              for(const width of [360,768,1440]){
                await page.setViewportSize({width,height:900});await page.goto(base+'/skills/');
                await page.getByRole('heading',{name,exact:true}).waitFor();
                await page.screenshot({path:dir+'/library-'+width+'.png'});
                await page.goto(base+'/skills/installations/'+id+'/');check(!await page.locator('#skillInstall').isDisabled(),'taste_ready');
                await page.screenshot({path:dir+'/taste-'+width+'.png'});
                await page.evaluate(()=>sessionStorage.clear());
                const before=requests.filter(url=>url===base+'/skills/?format=json').length;
                await page.goto(base+'/chat/');await ready();await page.locator('input[name="conversation_mode"][value="agent"]').check();
                check(requests.filter(url=>url===base+'/skills/?format=json').length===before,'no_initial_catalogue');
                check(await page.locator('#skillChips button').count()===0,'no_default_chip');
                check(await page.locator('.rg-skill-activation').count()===0,'no_invented_activation');
                const box=await page.locator('#skillPickerButton').boundingBox();check(box.width>=44&&box.height>=44,'slash_target');
                await shot('chat',width);await page.locator('#prompt').press('/');await loaded();
                await page.locator('#skillPickerSearch').fill('taste');await page.keyboard.press('ArrowDown');
                check(await page.locator('#skillPickerSearch').getAttribute('aria-activedescendant')==='skill-option-'+id,'keyboard_taste');
                await shot('picker',width);await page.keyboard.press('Escape');
                check(await page.locator('#prompt').inputValue()==='/','escape_retains_slash');
                check(await page.locator('#prompt').evaluate(n=>document.activeElement===n),'escape_focus');
                await page.locator('#prompt').fill('');await page.locator('#prompt').press('/');await loaded();
                await page.locator('#skillPickerSearch').fill('taste');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
                check(await page.locator('#prompt').inputValue()==='','choice_consumes_slash');
                check((await page.locator('#skillChips').innerText()).includes(name),'trusted_name_chip');
                check(await page.locator('.rg-skill-activation').count()===0,'selection_not_activation');
                await page.locator('#skillPickerButton').click();await loaded();
                await page.locator('.rg-skill-preferences summary').click();await page.locator('#skillAuto').uncheck();
                check((await page.evaluate(()=>window.regulaySkills.capture())).auto===false,'auto_false');
                await page.keyboard.press('Escape');await shot('manual',width);
                rows.push({width,blank_catalogue_requests:0,slash_44px:true,taste_available:true,
                    keyboard:true,escape:true,manual_choice:true,auto_false:true,activation_not_invented:true,overflow:false});
              }
              check(errors.length===0,'javascript_errors');check(mutations.length===0,'unexpected_mutations');
              return {rows,errors,mutations};
            }'''.replace('BASE',json.dumps(BASE)).replace('ID',json.dumps(before['installation']['id']))
                .replace('NAME',json.dumps(before['installation']['display_name'])).replace('DIR',json.dumps(captures.as_posix())), 'browser-auto-live')
            if before!=activation_ui.remote('verify'):
                raise RuntimeError('persistent_state_changed_during_readonly_verification')
            result.update(fixture=False,instance='regulai-v2',provider_requests=0,generation_requests=0,
                persistent_data_unchanged_except_temporary_session=True,session_revoked_in_finally=True,
                conversation_titles_hidden_only_in_chat_screenshots=True)
            (OUT/'browser-live.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
            print(json.dumps(result,indent=2))
    finally:
        try:ui.cli('close')
        finally:activation_ui.remote('revoke',credential['value'])


if __name__=='__main__':
    main()
