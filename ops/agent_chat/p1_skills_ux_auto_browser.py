"""Actual browser checks for quiet automatic Skills UX; synthetic lab only.

The activation event and exceptional catalogue responses are labelled browser
fixtures. They do not demonstrate provider performance or trigger generation.
"""
import json

import p1_skills_ux_browser as runner
import p1_skills_ux_lab as lab
import p1_stream_browser_latency as ui

OUT = lab.OUT / 'auto'


def main():
    lab.owner_check()
    report = json.loads((lab.OUT / 'lab.json').read_text(encoding='utf-8'))
    assert report['fixture'] and report['generation_blocked'] and report['database'] == lab.DATABASE
    taste = report['installations']['design-taste-frontend']['installation_id']
    OUT.mkdir(exist_ok=True)
    captures = OUT / 'screenshots'
    captures.mkdir(exist_ok=True)
    ui.OUT, ui.SESSION, runner.OUT = OUT, 'p1-skills-ux-auto-lab', OUT
    try:
        ui.cli('open', lab.BASE + '/static/js/skills.js')
        ui.cli('state-load', str(lab.OUT / 'private/browser-state.json'))
        result = runner.browser(r'''async page=>{
          const base=BASE,taste=TASTE,dir=DIR,normal=NORMAL,errors=[],requests=[],rows=[];
          const check=(ok,label)=>{if(!ok)throw Error(label);};
          page.on('pageerror',e=>errors.push(e.message));
          page.on('request',r=>requests.push({method:r.method(),url:r.url()}));
          const ready=async()=>page.waitForFunction(()=>window.regulaySkills&&window.regulayAgent);
          const loaded=async()=>page.waitForFunction(()=>document.getElementById('skillOptions')?.getAttribute('aria-busy')==='false');
          const clean=async()=>{await page.goto(base+'/chat/');await ready();await page.evaluate(()=>sessionStorage.clear());await page.reload();await ready();};
          const agent=async()=>page.locator('input[name="conversation_mode"][value="agent"]').check();
          const shot=async(name,width)=>{check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow:'+name+':'+width);await page.screenshot({path:dir+'/'+name+'-'+width+'.png'});};
          const catalogue=()=>requests.filter(r=>r.url===base+'/skills/?format=json').length;
          for(const width of [360,768,1440]){
            await page.setViewportSize({width,height:900});
            await page.goto(base+'/skills/');await page.getByRole('heading',{name:'Taste v2 · Frontend',exact:true}).waitFor();await shot('library',width);
            await page.locator('#skillsInstalled').focus();await page.keyboard.press('ArrowLeft');
            check(await page.locator('#skillsAvailable').getAttribute('aria-selected')==='true','library_arrow');
            await page.keyboard.press('End');check(await page.locator('#skillsInstalled').getAttribute('aria-selected')==='true','library_end');
            await page.goto(base+'/skills/installations/'+taste+'/');check(!await page.locator('#skillInstall').isDisabled(),'taste_ready');await shot('taste',width);
            await clean();await agent();const before=catalogue();await page.reload();await ready();await agent();
            check(catalogue()===before,'blank_chat_no_catalogue_request');
            check(await page.locator('#skillPickerButton').innerText()==='/','quiet_slash_button');
            const box=await page.locator('#skillPickerButton').boundingBox();check(box.width>=44&&box.height>=44,'slash_touch_target');
            check(await page.locator('#skillAuto').isHidden(),'auto_not_permanent');
            check(await page.locator('#skillChips button').count()===0,'no_default_manual_chip');
            check(await page.locator('.rg-skill-activation').count()===0,'no_invented_activation');
            await shot('chat',width);
            await page.locator('#prompt').fill('Borrador / completo');check(await page.locator('#skillPicker').isHidden(),'slash_in_draft_not_command');
            await page.locator('#prompt').fill('');
            await page.locator('#prompt').evaluate(n=>{n.value='/';n.setSelectionRange(1,1);n.dispatchEvent(new InputEvent('input',{bubbles:true,isComposing:true}));});
            check(await page.locator('#skillPicker').isHidden(),'composition_not_command');
            await page.locator('#prompt').evaluate(n=>{n.setSelectionRange(0,0);n.dispatchEvent(new InputEvent('input',{bubbles:true}));});
            check(await page.locator('#skillPicker').isHidden(),'wrong_caret_not_command');
            await page.locator('#prompt').fill('');await page.locator('#prompt').press('/');await loaded();
            check(await page.locator('#skillPicker').isVisible(),'slash_opens_picker');await page.keyboard.press('Escape');
            check(await page.locator('#prompt').inputValue()==='/','escape_preserves_slash');
            check(await page.locator('#prompt').evaluate(n=>n===document.activeElement),'escape_focus_prompt');
            await page.locator('#prompt').fill('');await page.locator('#prompt').press('/');await loaded();
            await page.locator('#skillPickerSearch').fill('taste');await page.keyboard.press('ArrowDown');
            check(await page.locator('#skillPickerSearch').getAttribute('aria-activedescendant')==='skill-option-'+taste,'keyboard_selection');
            await shot('picker',width);await page.keyboard.press('Enter');
            check(await page.locator('#prompt').inputValue()==='','selection_consumes_only_command');
            check(await page.locator('#prompt').evaluate(n=>n===document.activeElement),'selection_focus_prompt');
            check((await page.locator('#skillChips').innerText()).includes('Taste v2 · Frontend'),'manual_chip_human_name');
            check(await page.locator('.rg-skill-activation').count()===0,'selection_is_not_activation');
            await page.locator('#prompt').fill('Borrador conservado; no enviar.');
            await page.locator('#skillPickerButton').click();await loaded();
            await page.locator('.rg-skill-preferences summary').click();await page.locator('#skillAuto').uncheck();
            const checkbox=await page.locator('#skillAuto').boundingBox();check(checkbox.width===16&&checkbox.height===16,'natural_checkbox_size');
            if(width===360)await shot('options',width);
            await page.locator('#skillExplore').click();await page.goto(base+'/skills/installations/'+taste+'/');await page.locator('#skillInstall').click();
            await page.waitForURL('**/chat/');await ready();await loaded();
            check(await page.locator('#prompt').inputValue()==='Borrador conservado; no enviar.','draft_retained');
            check((await page.evaluate(()=>window.regulaySkills.capture())).auto===false,'auto_false_retained');
            await shot('manual',width);
            await page.locator('#skillPickerButton').click();await loaded();await page.locator('#skillPickerSearch').fill('taste');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
            check(await page.locator('#prompt').inputValue()==='Borrador conservado; no enviar.','button_choice_preserves_noncommand');
            check(await page.locator('#skillChips button').count()===0,'manual_toggle_removes_chip');
            rows.push({width,blank_catalogue_requests:0,button_44px:true,slash:true,composition_guard:true,caret_guard:true,escape:true,keyboard:true,draft:true,auto_false:true,overflow:false});
          }
          await page.goto(base+'/chat/'+normal+'/');await ready();await page.locator('#prompt').fill('');await page.locator('#prompt').press('/');
          check(await page.locator('#skillPicker').isHidden(),'normal_chat_no_slash_command');
          await clean();await agent();
          const blocked=await page.evaluate(async()=>{const rows=[];for(const path of ['/chat/send/','/chat/1/send/','/api/chat/send/']){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({prompt:'synthetic blocked'})});rows.push({path,status:r.status,code:(await r.json()).code});}return rows;});
          check(blocked.every(r=>r.status===503&&r.code==='real_generation_not_configured'),'three_entries_blocked');
          check(errors.length===0,'javascript_errors:'+JSON.stringify(errors));
          return {rows,blocked,errors,provider_requests:0,generation_requests_dispatched:0};
        }'''.replace('BASE',json.dumps(lab.BASE)).replace('TASTE',json.dumps(taste)).replace('DIR',json.dumps(captures.as_posix())).replace('NORMAL',str(report['normal_chat_id'])), 'browser-auto-main')
        (OUT/'browser-main.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        scenarios = runner.browser(r'''async page=>{
          const base=BASE,dir=DIR,endpoint=base+'/skills/?format=json';const check=(ok,label)=>{if(!ok)throw Error(label);};
          const clean=async()=>{await page.goto(base+'/chat/');await page.evaluate(()=>sessionStorage.clear());await page.reload();await page.waitForFunction(()=>window.regulaySkills);await page.locator('input[name="conversation_mode"][value="agent"]').check();};
          await clean();await page.route(endpoint,r=>r.fulfill({status:503,contentType:'application/json',body:'{"code":"synthetic_unavailable"}'}));
          await page.locator('#skillPickerButton').click();await page.locator('#skillPickerRetry').waitFor({state:'visible'});check((await page.locator('#skillPickerStatus').innerText()).includes('No se pudo'),'lazy_error');
          await page.unroute(endpoint);await page.locator('#skillPickerRetry').click();await page.waitForFunction(()=>document.getElementById('skillOptions').children.length===2);check(await page.locator('#skillPickerRetry').isHidden(),'retry_recovers');
          await page.locator('#skillPickerSearch').fill('no-synthetic-match');check((await page.locator('#skillPickerStatus').innerText()).includes('No hay skills'),'no_results');
          await page.keyboard.press('Escape');await page.route(endpoint,r=>r.fulfill({status:200,contentType:'application/json',body:'{"runtime_enabled":true,"installations":[],"catalog":[]}'}));
          await page.locator('#skillPickerButton').click();await page.waitForFunction(()=>document.getElementById('skillPickerStatus').textContent.includes('Aún no tienes'));await page.unroute(endpoint);await page.keyboard.press('Escape');
          let release;const waiting=new Promise(r=>release=r);await page.route(endpoint,async r=>{await waiting;await r.continue();});
          await page.locator('#skillPickerButton').click();check(await page.locator('#skillOptions').getAttribute('aria-busy')==='true','loading_busy');check((await page.locator('#skillPickerStatus').innerText()).includes('Cargando'),'loading_message');release();
          await page.waitForFunction(()=>document.getElementById('skillOptions').getAttribute('aria-busy')==='false');await page.unroute(endpoint);await page.keyboard.press('Escape');
          await page.route(base+'/synthetic-activation-status/',r=>r.fulfill({status:200,contentType:'application/json',body:JSON.stringify({run:{id:'synthetic-activation',status:'completed'},events:[]})}));
          const event=await page.evaluate(async()=>{
            const host=document.createElement('article');host.dataset.fixture='synthetic-activation';document.getElementById('chatContainer').append(host);
            const label=document.createElement('p');label.textContent='Fixture visual sintético: evento de activación, sin proveedor.';host.before(label);
            const watcher=window.regulayAgent.mount(host,{id:'synthetic-activation',status:'completed',status_url:'/synthetic-activation-status/'});
            while(!watcher.loaded)await new Promise(r=>setTimeout(r,10));
            const before=host.querySelectorAll('.rg-skill-activation').length;
            const value={id:1,kind:'skill.activated',data:{revision_id:'synthetic-revision',display_name:'Taste v2 · Frontend',alias:'design-taste-frontend'}};
            watcher.addEvent({id:0,kind:'skill.selected',data:value.data});
            const afterSelection=host.querySelectorAll('.rg-skill-activation').length;
            watcher.addEvent(value);watcher.addEvent({...value,id:2});watcher.apply({run:watcher.run,events:[value,{...value,id:3}]});
            return {before,afterSelection,count:host.querySelectorAll('.rg-skill-activation').length,text:host.querySelector('.rg-skill-activation').textContent};
          });
          check(event.before===0&&event.afterSelection===0&&event.count===1&&event.text==='Taste v2 · Frontend · activada','activation_event_only_deduplicated');
          for(const width of [360,768,1440]){
            await page.setViewportSize({width,height:900});
            if(await page.locator('#chatApp').evaluate(n=>n.classList.contains('is-drawer-open')))await page.keyboard.press('Escape');
            if(width<992)await page.waitForFunction(()=>getComputedStyle(document.getElementById('threads')).visibility==='hidden');
            await page.evaluate(async()=>{await Promise.all(document.getAnimations().filter(a=>a.effect.getTiming().iterations!==Infinity).map(a=>a.finished.catch(()=>{})));});
            await page.waitForFunction(()=>document.getElementById('composerBox').getBoundingClientRect().right<=innerWidth);
            await page.locator('.rg-skill-activation').scrollIntoViewIfNeeded();
            check(await page.locator('.rg-skill-activation').evaluate(n=>{const r=n.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&n.contains(document.elementFromPoint(r.left+r.width/2,r.top+r.height/2));}),'activation_visible_not_occluded');
            check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'activation_overflow');
            await page.screenshot({path:dir+'/activation-fixture-'+width+'.png'});
          }
          await page.unroute(base+'/synthetic-activation-status/');
          return {synthetic_browser_fixtures:['503_error','empty_catalogue','held_network_loading','skill.activated_event'],retry:true,no_results:true,activation:event,provider_requests:0};
        }'''.replace('BASE',json.dumps(lab.BASE)).replace('DIR',json.dumps(captures.as_posix())), 'browser-auto-fixtures')
        result.update(fixture=True,scenarios=scenarios,real_provider_quality_or_performance=False)
        (OUT/'browser-lab.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
        print(json.dumps(result,indent=2))
    finally:
        ui.cli('close')


if __name__ == '__main__':
    main()
