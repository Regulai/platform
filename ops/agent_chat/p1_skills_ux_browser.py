"""Exercise Skills UX against the labelled isolated lab; no real generation."""
import json
from pathlib import Path

import p1_stream_browser_latency as ui
import p1_skills_ux_lab as lab

OUT = lab.OUT


def browser(code, name):
    # CLI supports file input, avoiding Windows' command-line length limit.
    path = OUT / (name + '.cjs')
    path.write_text(code, encoding='utf-8')
    result = ui.cli('run-code', '--filename', str(path))
    return json.loads(result.split('### Result\n', 1)[1].split('\n### Ran', 1)[0])


def main():
    lab.owner_check()
    report = json.loads((OUT / 'lab.json').read_text(encoding='utf-8'))
    assert report['fixture'] and report['database'] == lab.DATABASE and report['generation_blocked']
    taste = report['installations']['design-taste-frontend']['installation_id']
    captures = OUT / 'screenshots'
    captures.mkdir(exist_ok=True)
    ui.OUT, ui.SESSION = OUT, 'p1-skills-ux-lab'
    try:
        ui.cli('open', lab.BASE + '/static/js/skills.js')
        ui.cli('state-load', str(OUT / 'private/browser-state.json'))
        result = browser(r'''async page=>{
          const check=(ok,label)=>{if(!ok)throw Error(label);};
          const errors=[],requests=[];
          page.on('pageerror',error=>errors.push(error.message));
          page.on('request',request=>{if(request.method()==='POST')requests.push(new URL(request.url()).pathname);});
          const base=BASE,taste=TASTE,dir=DIR,normal=NORMAL,rows=[];
          const ready=async()=>{await page.waitForFunction(()=>window.regulaySkills&&document.getElementById('skillOptions').getAttribute('aria-busy')==='false');};
          const shot=async(name,width)=>{check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'overflow:'+name+':'+width);await page.screenshot({path:dir+'/'+name+'-'+width+'.png'});};
          await page.goto(base+'/skills/');
          await page.locator('#skillsInstalled').focus();await page.keyboard.press('ArrowLeft');
          check(await page.locator('#skillsAvailable').getAttribute('aria-selected')==='true','tabs_arrow_navigation');
          check(await page.locator('#skillsAvailable').evaluate(n=>n===document.activeElement),'tabs_roving_focus');
          await page.keyboard.press('End');check(await page.locator('#skillsInstalled').getAttribute('aria-selected')==='true','tabs_end');
          await page.locator('#skillSearch').fill('no-result-ux-987');await page.locator('#skillEmpty').waitFor({state:'visible'});
          await page.locator('#skillClear').click();check(await page.locator('#skillSearch').inputValue()==='','search_reset');
          await page.locator('#skillImportOpen').click();check(await page.locator('#skillImport').evaluate(n=>n.open),'import_open');
          await page.keyboard.press('Escape');check(!await page.locator('#skillImport').evaluate(n=>n.open),'import_escape');
          check(await page.locator('#skillImportOpen').evaluate(n=>n===document.activeElement),'import_focus_restore');
          await page.locator('#skillImportOpen').click();await page.locator('[data-cancel-import]').click();
          for(const width of [360,768,1440]){
            await page.setViewportSize({width,height:900});
            await page.goto(base+'/skills/');await page.getByRole('heading',{name:'Taste v2 · Frontend',exact:true}).waitFor();
            check(await page.locator('#skillsInstalled').getAttribute('aria-selected')==='true','installed_default');
            await shot('library',width);
            await page.goto(base+'/skills/installations/'+taste+'/');
            check(await page.locator('#skillInstall').textContent()==='Usar en chat','taste_use_label');
            check(!await page.locator('#skillInstall').isDisabled(),'taste_use_enabled');
            check(await page.locator('details[open]').count()===0,'technical_details_collapsed');
            await shot('taste',width);
            await page.goto(base+'/chat/');await ready();
            await page.evaluate(()=>{sessionStorage.removeItem('regulai.skills.selection.new');});
            await page.reload();await ready();
            await page.locator('#skillAuto').uncheck();
            await page.locator('#prompt').fill('Diseña una página clara con Taste. Borrador de interfaz, sin envío.');
            await page.locator('[data-skill-explore]').first().click();
            await page.goto(base+'/skills/installations/'+taste+'/');await page.locator('#skillInstall').click();
            await page.waitForURL('**/chat/');await ready();
            const retained=await page.evaluate(()=>({draft:document.getElementById('prompt').value,auto:document.getElementById('skillAuto').checked,selected:window.regulaySkills.capture().selected}));
            check(retained.draft.includes('Borrador de interfaz'),'draft_retained');check(retained.auto===false,'auto_off_retained');check(retained.selected.includes(taste),'taste_selected');
            check((await page.locator('#skillChips').innerText()).includes('Taste v2 · Frontend'),'human_readable_taste_chip');
            await shot('chat',width);
            await page.locator('#skillPickerButton').click();await ready();
            await page.locator('#skillPickerSearch').fill('taste');
            await page.keyboard.press('ArrowDown');
            check(await page.locator('#skillPickerSearch').getAttribute('aria-activedescendant')==='skill-option-'+taste,'picker_arrow_active');
            await shot('picker',width);
            await page.keyboard.press('Escape');check(await page.locator('#skillPicker').isHidden(),'picker_escape');
            check(await page.locator('#skillPickerButton').evaluate(n=>n===document.activeElement),'picker_focus_restored');
            rows.push({width,overflow:false,draft_retained:true,auto_off_retained:true,taste_selected:true,keyboard:true});
          }
          await page.goto(base+'/chat/'+normal+'/');await ready();
          await page.locator('#prompt').fill('Borrador original de conversación Chat.');
          await page.locator('a[href="/skills/"]').filter({visible:true}).first().click();
          await page.goto(base+'/skills/installations/'+taste+'/');await page.locator('#skillInstall').click();
          await page.waitForURL('**/chat/');await ready();
          check(await page.locator('input[name="conversation_mode"][value="agent"]').isChecked(),'normal_chat_to_new_agent');
          check((await page.evaluate(()=>window.regulaySkills.capture().selected)).includes(taste),'new_agent_taste_selected');
          check((await page.locator('#skillSelectionStatus').innerText()).includes('borrador'),'normal_chat_preserved_notice');
          check(await page.evaluate(id=>sessionStorage.getItem('regulai.skills.draft.'+id),String(normal))==='Borrador original de conversación Chat.','original_chat_draft_preserved');
          await page.goto(base+'/skills/installations/'+taste+'/');
          await page.getByRole('button',{name:'Deshabilitar',exact:true}).click();
          await page.getByRole('button',{name:'Habilitar',exact:true}).waitFor();
          check(await page.locator('#skillInstall').isDisabled(),'disable_cta_updates');
          check((await page.locator('#skillInstallStatus').innerText()).includes('Deshabilitada'),'disable_status_updates');
          await page.goto(base+'/chat/');await ready();
          await page.evaluate(id=>{sessionStorage.setItem('regulai.skills.selection.new',JSON.stringify([id,'00000000-0000-4000-8000-000000000099']));sessionStorage.setItem('regulai.skills.pending',id);},taste);
          await page.reload();await ready();
          check((await page.evaluate(()=>window.regulaySkills.capture().selected)).length===0,'stale_selection_removed_from_payload');
          check(await page.locator('#skillChips button').count()===0,'stale_chip_removed');
          check((await page.locator('#skillSelectionStatus').innerText()).includes('no está disponible'),'stale_selection_notice');
          await page.goto(base+'/skills/installations/'+taste+'/');await page.getByRole('button',{name:'Habilitar',exact:true}).click();
          await page.getByRole('button',{name:'Deshabilitar',exact:true}).waitFor();
          check(!await page.locator('#skillInstall').isDisabled(),'enable_cta_updates');
          await page.goto(base+'/chat/');await ready();
          const blocked=await page.evaluate(async()=>{
            const rows=[];for(const path of ['/chat/send/','/chat/1/send/','/api/chat/send/']){
              const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({prompt:'fixture blocked'})});
              const value=await response.json();rows.push({path,status:response.status,code:value.code});
            }return rows;
          });
          check(blocked.every(row=>row.status===503&&row.code==='real_generation_not_configured'),'three_generation_entries_blocked');
          check(errors.length===0,'unexpected_javascript_errors:'+JSON.stringify(errors));
          return {rows,errors,requests,blocked,keyboard_tabs:true,search_empty_reset:true,import_cancel_escape_focus:true,
            disable_enable_actual_lab_api:true,stale_selection_pruned:true,normal_chat_new_agent_preserves_original_draft:true,provider_requests:0};
        }'''.replace('BASE', json.dumps(lab.BASE)).replace('TASTE', json.dumps(taste)).replace('NORMAL', str(report['normal_chat_id'])).replace('DIR', json.dumps(captures.as_posix())), 'browser-main')
        (OUT / 'browser-main.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        scenarios = browser(r'''async page=>{
          const check=(ok,label)=>{if(!ok)throw Error(label);},base=BASE;
          const endpoint=base+'/skills/?format=json';
          await page.route(endpoint,route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({runtime_enabled:true,installations:[],catalog:[]})}));
          await page.goto(base+'/chat/');await page.waitForFunction(()=>document.getElementById('skillPickerStatus')?.textContent.includes('Aún no tienes'));
          await page.locator('#skillPickerButton').click();await page.waitForFunction(()=>document.getElementById('skillPickerStatus')?.textContent.includes('Aún no tienes'));check((await page.locator('#skillPickerStatus').innerText()).includes('Aún no tienes'),'empty_message');
          await page.unroute(endpoint);
          await page.route(endpoint,route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({code:'fixture_unavailable'})}));
          await page.reload();await page.locator('#skillPickerButton').click();await page.locator('#skillPickerRetry').waitFor({state:'visible'});
          check((await page.locator('#skillPickerStatus').innerText()).includes('No se pudo'),'error_message');
          await page.unroute(endpoint);
          await page.locator('#skillPickerRetry').click();await page.waitForFunction(()=>document.getElementById('skillOptions')?.children.length===2);
          check(await page.locator('#skillPickerRetry').isHidden(),'retry_recovers');
          await page.locator('#skillPickerSearch').fill('no-match-ux');check((await page.locator('#skillPickerStatus').innerText()).includes('No hay skills'),'picker_no_results');
          await page.unroute(endpoint);
          let release;const pending=new Promise(resolve=>release=resolve);
          await page.route(endpoint,async route=>{await pending;await route.continue();});
          await page.reload();await page.locator('#skillPickerButton').click();
          check((await page.locator('#skillPickerStatus').innerText()).includes('Cargando'),'loading_status');
          check(await page.locator('#skillOptions').getAttribute('aria-busy')==='true','loading_busy');release();
          await page.waitForFunction(()=>document.getElementById('skillOptions')?.children.length===2);await page.unroute(endpoint);
          return {fixture_browser_responses:['empty','503_error'],'loading_network_held_then_released':true,empty:true,error:true,retry:true,no_results:true,loading:true};
        }'''.replace('BASE', json.dumps(lab.BASE)), 'browser-fixture-states')
        result.update(fixture=True, runtime_capability_fixture=True, scenarios=scenarios,
            real_provider_quality_or_performance=False)
        (OUT / 'browser-lab.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
    finally:
        ui.cli('close')


if __name__ == '__main__':
    main()
