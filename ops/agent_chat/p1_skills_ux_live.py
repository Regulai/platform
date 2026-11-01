"""Read-only actual v2 Skills UX check; every non-GET browser request is blocked."""
import json
from pathlib import Path
import tempfile

import p1_activation_ui_verify as activation_ui
import p1_stream_browser_latency as ui
import p1_skills_ux_browser as browser_runner

OUT = browser_runner.OUT
BASE = 'http://127.0.0.1:8800'


def main():
    ui.OUT, ui.SESSION = OUT, 'p1-skills-ux-live'
    capture = OUT / 'live-screenshots'
    capture.mkdir(exist_ok=True)
    before = activation_ui.remote('verify')
    credential = activation_ui.remote('session')
    try:
        with tempfile.TemporaryDirectory(prefix='regulai-skills-ux-live-') as temporary:
            state = Path(temporary) / 'browser-state.json'
            state.write_text(json.dumps({'cookies': [{**credential, 'domain': '127.0.0.1',
                'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}],
                'origins': []}), encoding='utf-8')
            ui.cli('open', BASE + '/static/js/skills.js')
            ui.cli('state-load', str(state))
            result = browser_runner.browser(r'''async page=>{
              const base=BASE,id=ID,name=NAME,dir=DIR,errors=[],mutatingRequests=[],rows=[];
              const check=(ok,label)=>{if(!ok)throw Error(label);};
              await page.route('**/*',route=>['GET','HEAD'].includes(route.request().method())?route.continue():route.abort('blockedbyclient'));
              page.on('pageerror',error=>errors.push(error.message));
              page.on('request',request=>{if(!['GET','HEAD'].includes(request.method()))mutatingRequests.push(new URL(request.url()).pathname);});
              const shot=async(pageName,width)=>{
                check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow:'+pageName+':'+width);
                await page.screenshot({path:dir+'/'+pageName+'-'+width+'.png',style:'#threadList { visibility: hidden !important; }'});
              };
              for(const width of [360,768,1440]){
                await page.setViewportSize({width,height:900});await page.goto(base+'/skills/');
                await page.getByRole('heading',{name,exact:true}).waitFor();
                check(await page.locator('#skillsInstalled').getAttribute('aria-selected')==='true','installed_default');
                await shot('library',width);
                await page.goto(base+'/skills/installations/'+id+'/');
                check(!await page.locator('#skillInstall').isDisabled(),'taste_available');
                check(await page.locator('details[open]').count()===0,'technical_information_collapsed');
                await shot('taste',width);await page.locator('#skillInstall').click();await page.waitForURL('**/chat/');
                await page.waitForFunction(id=>window.regulaySkills?.capture()?.selected.includes(id),id);
                check((await page.locator('#skillChips').innerText()).includes(name),'display_name_chip');
                await page.locator('#skillAuto').uncheck();
                check((await page.evaluate(()=>window.regulaySkills.capture())).auto===false,'manual_taste_only');
                await shot('chat',width);await page.locator('#skillPickerButton').click();
                await page.waitForFunction(()=>document.getElementById('skillOptions')?.getAttribute('aria-busy')==='false');
                await page.locator('#skillPickerSearch').fill('taste');
                await page.keyboard.press('ArrowDown');
                check(await page.locator('#skillPickerSearch').getAttribute('aria-activedescendant')==='skill-option-'+id,'keyboard_picker');
                await shot('picker',width);await page.keyboard.press('Escape');
                check(await page.locator('#skillPickerButton').evaluate(n=>document.activeElement===n),'focus_restored');
                rows.push({width,overflow:false,taste_available:true,taste_selected:true,auto_off:true,keyboard:true});
              }
              check(errors.length===0,'javascript_errors');check(mutatingRequests.length===0,'unexpected_mutations');
              return {rows,errors,mutatingRequests};
            }'''.replace('BASE', json.dumps(BASE)).replace('ID', json.dumps(before['installation']['id']))
                .replace('NAME', json.dumps(before['installation']['display_name']))
                .replace('DIR', json.dumps(capture.as_posix())), 'browser-live')
            after = activation_ui.remote('verify')
            if before != after:
                raise RuntimeError('live_persistent_state_changed_during_readonly_ui_check')
            result.update(instance='regulai-v2', fixture=False, provider_requests=0,
                generation_requests=0, persistent_data_unchanged_except_temporary_session=True,
                session_revoked_in_finally=True, conversation_titles_hidden_only_in_screenshots=True)
            (OUT / 'browser-live.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(json.dumps(result, indent=2))
    finally:
        try:
            ui.cli('close')
        finally:
            activation_ui.remote('revoke', credential['value'])


if __name__ == '__main__':
    main()
