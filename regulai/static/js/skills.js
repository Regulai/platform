/* Account skills library and one-message selection; no model calls. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const el = (tag, text, cls) => { const node = document.createElement(tag); if (text) node.textContent = text; if (cls) node.className = cls; return node; };
  const csrf = () => document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
  const codes = {license_missing:'Falta una licencia en el paquete. Añádela y vuelve a revisar.',
    path_denied:'El paquete incluye una ruta o enlace no permitido. Revisa el ZIP.',
    skill_expanded_limit:'El ZIP supera los límites al expandirse. Elige un paquete más pequeño.',
    skill_compressed_limit:'El paquete supera 10 MiB. Elige un ZIP más pequeño.',
    source_conflict:'Ya existe ese alias. Elige uno distinto; la instalación anterior se conserva.',
    invalid_skill:'SKILL.md no tiene metadatos válidos. Revisa nombre, descripción y formato YAML.',
    skill_dependency_unavailable:'Faltan herramientas o un runtime comprobado. Consulta los requisitos.',
    skill_install_interrupted:'La instalación se interrumpió. Puedes reintentar con el mismo paquete.',
    skill_download_policy_denied:'La política no permite descargar desde ese destino. Puedes importar un ZIP.',
    skill_network_local_policy_required:'Esta política necesita revisión externa para la descarga. Importa un ZIP.',
    skill_github_path_required:'Indica la URL de una carpeta concreta: github.com/autor/repo/tree/revisión/carpeta.',
    skill_request_conflict:'Esta petición ya corresponde a otro paquete. Vuelve a revisar el paquete.'};
  const message = data => codes[data.code] || `No se pudo completar (${data.code || 'conexión interrumpida'}). Revisa el paquete o consulta el estado.`;
  async function request(url, data) {
    const options = data ? {method:'POST', headers:{'X-CSRFToken':csrf()}, body:data instanceof FormData ? data : JSON.stringify(data)} : {};
    if (data && !(data instanceof FormData)) options.headers['Content-Type'] = 'application/json';
    let response, value;
    try { response = await fetch(url, {...options, credentials:'same-origin'}); }
    catch (_) { throw new Error('Se interrumpió la conexión. Recarga para consultar el estado o reintenta con el mismo paquete.'); }
    try { value = await response.json(); }
    catch (_) { throw new Error('El servidor no pudo completar la petición. Recarga para consultar el estado antes de reintentar.'); }
    if (!response.ok) { const error = new Error(message(value)); error.data = value; throw error; }
    return value;
  }
  function button(text, action, cls='rg-btn') { const b=el('button',text,cls); b.type='button'; b.addEventListener('click',action); return b; }
  const returnPath = () => { const value=sessionStorage.getItem('regulai.skills.return'); return /^\/chat\/(?:\d+\/)?$/.test(value || '') ? value : '/chat/'; };
  document.querySelectorAll('[data-skill-return]').forEach(link=>{link.href=returnPath();});
  const displayName = row => row.display_name || row.alias || row.name || 'Skill';
  const summary = row => row.summary || row.description || '';
  const requirements = row => (row.availability?.requirement_labels || row.availability?.requirements || []).join(', ');
  let runtimeEnabled = false;
  const agentNote='Las skills se usan en modo Agente. Se ha abierto un chat nuevo; el borrador del chat anterior se conserva.';
  function useSkill(row) {
    if(!ready(row))return;
    sessionStorage.setItem('regulai.skills.pending',row.id);
    const path=returnPath(), needsNew=path!=='/chat/'&&sessionStorage.getItem('regulai.skills.return_mode')==='chat';
    if(needsNew)sessionStorage.setItem('regulai.skills.pending_note',agentNote);
    location.assign(needsNew?'/chat/':path);
  }
  function ready(row) { return runtimeEnabled && row.enabled && row.availability?.available; }
  function stateLabel(row) { return row.enabled === false ? 'Deshabilitada' : !row.availability?.available ? 'Requiere configuración' : row.installed ? (runtimeEnabled?'Habilitada':'Ejecución desactivada') : 'Lista para instalar'; }
  const rememberOperation = key => sessionStorage.setItem('regulai.skills.operation', key);
  function operationStatus(value) {
    return value.state === 'installed' ? 'Instalada. Ya puedes consultar sus requisitos.'
      : value.state === 'downloading' ? 'Descargando paquete…'
      : value.state === 'validating' ? 'Comprobando estructura y recursos…' : message(value);
  }
  async function waitOperation(key, value, status) {
    const deadline = Date.now() + 65000;
    while (!['installed', 'failed'].includes(value.state) && Date.now() < deadline) {
      status.textContent = operationStatus(value);
      await new Promise(resolve => setTimeout(resolve, 600));
      value = await request(`/skills/operations/${key}/`);
    }
    status.textContent = operationStatus(value);
    if (value.state !== 'installed') throw new Error(message(value));
    sessionStorage.removeItem('regulai.skills.operation');
    return value;
  }
  async function restoreOperation(status, refresh) {
    const key = sessionStorage.getItem('regulai.skills.operation');
    if (!key || !/^[0-9a-f-]{36}$/.test(key)) return;
    try { await waitOperation(key, await request(`/skills/operations/${key}/`), status); await refresh(); }
    catch(error) { status.textContent = error.message; }
  }
  async function install(candidate, status, action, key) {
    key ||= crypto.randomUUID(); action.disabled=true;
    rememberOperation(key);
    let polling=true;
    const poll = async () => { while(polling) { await new Promise(resolve=>setTimeout(resolve,600)); if (!polling) break;
      try { const data=await request(`/skills/operations/${key}/`); status.textContent=data.state==='downloading'?'Descargando paquete…':data.state==='validating'?'Comprobando estructura y recursos…':data.state==='installed'?'Instalada':message(data); } catch (_) { /* POST may not have recorded its intention yet. */ }
    }};
    poll();
    try { status.textContent='Comprobando paquete…'; const result=await request('/skills/installations/',{source:'catalog',candidate,request_id:key}); return await waitOperation(key,result,status); }
    finally { polling=false; action.disabled=false; }
  }

  if (byId('skillsLibrary')) {
    let data=JSON.parse(byId('skills-data').textContent);
    let tab=data.installations.length?'installed':'available';
    runtimeEnabled=data.runtime_enabled===true;
    const grid=byId('skillGrid'), status=byId('skillStatus');
    function refreshCategories(){const select=byId('skillCategory'), prior=select.value;const categories=[...new Set([...data.catalog,...data.installations].map(row=>row.category).filter(Boolean))].sort();select.replaceChildren(Object.assign(el('option','Todas'),{value:''}),...categories.map(value=>Object.assign(el('option',value),{value})));select.value=categories.includes(prior)?prior:'';}
    refreshCategories();
    async function reload() { data=await request('/skills/?format=json'); runtimeEnabled=data.runtime_enabled===true;refreshCategories();paint(); }
    function paint() {
      byId('skillRuntimeStatus').hidden=runtimeEnabled;
      const search=byId('skillSearch').value.toLocaleLowerCase(), category=byId('skillCategory').value, filter=byId('skillAvailability').value;
      const rows=(tab==='available'?data.catalog:data.installations).filter(row=>
        `${displayName(row)} ${row.alias || row.name} ${summary(row)} ${row.publisher || row.source_identity}`.toLocaleLowerCase().includes(search)
        && (!category || row.category===category) && (!filter || Boolean(row.availability.available)===(filter==='ready')));
      grid.replaceChildren(); byId('skillEmpty').hidden=rows.length>0;
      byId('skillEmptyText').textContent=tab==='installed'&&!data.installations.length?'Aún no tienes skills. Explora las disponibles para empezar.':'Prueba con otro nombre o ajusta los filtros.';
      byId('skillsInstalled').textContent=`Instaladas (${data.installations.length})`;
      document.querySelectorAll('[data-skill-tab]').forEach(node=>{const current=node.dataset.skillTab===tab;node.setAttribute('aria-selected',String(current));node.tabIndex=current?0:-1;});
      byId('skillResults').setAttribute('aria-labelledby',tab==='installed'?'skillsInstalled':'skillsAvailable');
      rows.forEach(row=>{ const installed=tab==='available'?data.installations.find(item=>item.source_identity===row.source_identity):null;
        const card=el('article',null,'rg-skill-card'); const title=el('h2',displayName(row)); card.append(title,el('p',summary(row),'rg-skill-card-summary'),el('small',row.publisher || 'Paquete de tu cuenta'),el('span',installed&&installed.catalog_revision===false?'Otra revisión instalada':stateLabel(installed||row),'rg-skill-badge'));
        if (tab==='available') { const link=el('a',installed?'Ver instalación':'Ver detalle','rg-btn'); link.href=installed?`/skills/installations/${installed.id}/`:`/skills/catalog/${row.id}/`; card.append(link); }
        else { const actions=el('div',null,'rg-skill-actions'); const use=button('Usar en chat',()=>useSkill(row)); use.disabled=!ready(row); actions.append(use);
          const detail=el('a','Ver detalle','rg-btn');detail.href=`/skills/installations/${row.id}/`;actions.append(detail);
          const menu=el('details'); menu.append(el('summary','Gestionar')); const details=el('div',null,'rg-skill-actions');
          const mutate=async(action,body={})=>{details.querySelectorAll('button').forEach(b=>{b.disabled=true;});try{await request(`/skills/installations/${row.id}/${action}/`,body); await reload(); status.textContent=action==='uninstall'?'Skill desinstalada.':`${displayName(row)}: instalación actualizada.`;}catch(error){status.textContent=error.message;details.querySelectorAll('button').forEach(b=>{b.disabled=false;});}};
          details.append(button(row.enabled?'Deshabilitar':'Habilitar',()=>mutate('enabled',{enabled:!row.enabled})),button('Desinstalar',()=>{if(window.confirm(`¿Desinstalar ${displayName(row)}? Puedes volver a instalarla después.`))mutate('uninstall');}));
          if(row.previous_revision_id) details.append(button('Volver a revisión anterior',()=>mutate('rollback')));
          menu.append(details);actions.append(menu); card.append(actions);
          if(!row.availability.available)card.append(el('p',requirements(row),'rg-skill-requirements'));
        } grid.append(card); });
    }
    let timer; byId('skillSearch').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(paint,100);});
    ['skillCategory','skillAvailability'].forEach(id=>byId(id).addEventListener('change',paint));
    const tabs=[...document.querySelectorAll('[data-skill-tab]')];
    tabs.forEach((node,index)=>{node.addEventListener('click',()=>{tab=node.dataset.skillTab;paint();});node.addEventListener('keydown',event=>{let next;if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;else if(event.key==='ArrowRight')next=(index+1)%tabs.length;else if(event.key==='ArrowLeft')next=(index+tabs.length-1)%tabs.length;else return;event.preventDefault();tabs[next].click();tabs[next].focus();});});
    byId('skillClear').addEventListener('click',()=>{byId('skillSearch').value=byId('skillCategory').value=byId('skillAvailability').value='';byId('skillsAvailable').click();});
    paint();
    restoreOperation(status,reload);
    const dialog=byId('skillImport'), form=byId('skillImportForm'), review=byId('skillImportReview'), next=byId('skillImportNext');
    let reviewed=false, identity=null;
    const resetReview=()=>{reviewed=false;identity=null;review.hidden=true;next.textContent='Revisar paquete';};
    function openImport(target) {
      form.reset();resetReview();byId('skillImportStatus').textContent='';byId('skillFolder').replaceChildren();byId('skillFolderLabel').hidden=true;
      if(target)form.dataset.updateTarget=target;else delete form.dataset.updateTarget;
      byId('skillImportTitle').textContent=target?'Actualizar paquete instalado':'Importar una skill';dialog.showModal();
    }
    const updateTarget=sessionStorage.getItem('regulai.skills.update');
    if(updateTarget){sessionStorage.removeItem('regulai.skills.update');openImport(updateTarget);}
    byId('skillImportOpen').addEventListener('click',()=>openImport());
    dialog.querySelector('[data-close-dialog]').addEventListener('click',()=>dialog.close());
    dialog.querySelector('[data-cancel-import]').addEventListener('click',()=>dialog.close());
    form.addEventListener('input',event=>{resetReview();if(['url','file'].includes(event.target.name)){byId('skillFolder').replaceChildren();byId('skillFolderLabel').hidden=true;}});
    form.addEventListener('submit',async event=>{event.preventDefault();next.disabled=true;const state=byId('skillImportStatus');
      const controls=[...form.querySelectorAll('input,select')];
      try { const body=new FormData(form), file=body.get('file'), urlValue=String(body.get('url') || '').trim(), isZIP=file?.size>0;
        if(isZIP&&urlValue)throw new Error('Elige un solo origen: carpeta de GitHub o archivo ZIP.');
        if(!isZIP&&!urlValue)throw new Error('Añade una carpeta de GitHub o selecciona un archivo ZIP.');
        controls.forEach(control=>{control.disabled=true;});
        if(!reviewed) { review.replaceChildren();
          if(isZIP) { const info=await request('/skills/import/inspect/',body);
            if(!info.metadata){const select=byId('skillFolder');select.replaceChildren(...info.folders.map(path=>{const o=el('option',path);o.value=path;return o;}));byId('skillFolderLabel').hidden=false;state.textContent='Elige una carpeta y vuelve a revisar.';return;}
            body.set('subpath',info.subpath);byId('skillFolder').replaceChildren(Object.assign(el('option',info.subpath),{value:info.subpath}));
            review.append(el('h3',info.metadata.name),el('p',info.metadata.description),el('p',`${info.manifest.length} archivos · licencia incluida`));
          } else { let url;try{url=new URL(urlValue);}catch(_){throw new Error(codes.skill_github_path_required);}if(url.protocol!=='https:'||url.hostname!=='github.com'||url.username||url.password||url.port||!/^\/[^/]+\/[^/]+\/tree\/[^/]+\/.+/.test(url.pathname))throw new Error(codes.skill_github_path_required);
            review.append(el('h3','Carpeta de GitHub'),el('p',url.href),el('p','Se fijará el commit y se comprobarán recursos, licencia y requisitos. No se ejecuta el paquete.')); }
          reviewed=true;identity=crypto.randomUUID();review.hidden=false;next.textContent=form.dataset.updateTarget?'Comprobar y actualizar':'Comprobar e instalar';state.textContent=isZIP?'Revisa el contenido antes de instalar.':'Confirma el origen. El contenido se descargará y comprobará al instalar.';
        } else { body.set('source',file?.size?'zip':'github');body.set('request_id',identity); rememberOperation(identity);state.textContent=file?.size?'Comprobando paquete…':'Descargando y comprobando…';
          const target=form.dataset.updateTarget;
          const result=await request(target?`/skills/installations/${target}/update/`:'/skills/installations/',body);
          await waitOperation(identity,result,state);resetReview();delete form.dataset.updateTarget;await reload();byId('skillsInstalled').click();status.textContent='Paquete instalado. Consulta sus requisitos o úsalo en el chat.';dialog.close();byId('skillsInstalled').focus(); }
      } catch(error){state.textContent=error.message;} finally{controls.forEach(control=>{control.disabled=false;});next.disabled=false;}
    });
  }
  if(byId('skillDetail')) {
    const data=JSON.parse(byId('skill-data').textContent), action=byId('skillInstall'), status=byId('skillInstallStatus');let installed=data.installation, identity=null;
    runtimeEnabled=data.runtime_enabled===true;
    const otherRevision=()=>data.is_catalog_detail&&installed&&installed.catalog_revision===false;
    let busy=false;
    async function manage(work) {if(busy)return;busy=true;action.disabled=true;byId('skillRevisionActions').querySelectorAll('button').forEach(b=>{b.disabled=true;});try{await work();update();}catch(error){update();status.textContent=error.message;}finally{busy=false;}}
    function update() { action.textContent=otherRevision()?'Ver instalación':installed?'Usar en chat':'Instalar';action.disabled=Boolean(installed&&!ready(installed)&&!otherRevision());const area=byId('skillRevisionActions');area.replaceChildren();
      if(installed){status.textContent=!runtimeEnabled?'Instalada · ejecución desactivada':!installed.enabled?'Deshabilitada. Habilítala para usarla en el chat.':!installed.availability.available?`Requiere: ${requirements(installed)}.`:'Habilitada · lista para el próximo mensaje.';
        area.append(button(installed.enabled?'Deshabilitar':'Habilitar',()=>manage(async()=>{installed=await request(`/skills/installations/${installed.id}/enabled/`,{enabled:!installed.enabled});})));
        if(installed.previous_revision_id)area.append(button('Volver a revisión anterior',()=>manage(async()=>{await request(`/skills/installations/${installed.id}/rollback/`,{});location.reload();})));
        area.append(button('Actualizar paquete',async()=>{if(!data.id){sessionStorage.setItem('regulai.skills.update',installed.id);location.assign('/skills/');return;}
          await manage(async()=>{const key=crypto.randomUUID();rememberOperation(key);await waitOperation(key,await request(`/skills/installations/${installed.id}/update/`,{source:'catalog',candidate:data.id,request_id:key}),status);location.reload();});}));
        area.append(button('Desinstalar',()=>{if(window.confirm(`¿Desinstalar ${displayName(installed)}? Puedes volver a instalarla después.`))manage(async()=>{await request(`/skills/installations/${installed.id}/uninstall/`,{});location.assign('/skills/');});}));}}
    action.addEventListener('click',async()=>{if(otherRevision()){location.assign(`/skills/installations/${installed.id}/`);return;}if(installed){useSkill(installed);return;}try{identity ||= crypto.randomUUID();const result=await install(data.id,status,action,identity);const library=await request('/skills/?format=json');installed=library.installations.find(r=>r.id===result.installation_id);update();}catch(error){status.textContent=error.message;}});update();
    restoreOperation(status,async()=>{const library=await request('/skills/?format=json');installed=library.installations.find(row=>row.source_identity===data.source_identity);update();});
  }

  if(byId('skillPicker')) {
    const picker=byId('skillPicker'), trigger=byId('skillPickerButton'), list=byId('skillOptions'), search=byId('skillPickerSearch'), chips=byId('skillChips'), auto=byId('skillAuto');
    const status=byId('skillPickerStatus'), notice=byId('skillSelectionStatus'), retry=byId('skillPickerRetry');
    const prompt=byId('prompt'), app=byId('chatApp');
    runtimeEnabled=document.querySelector('[data-skills-runtime]')?.dataset.skillsRuntime==='true';
    trigger.disabled=auto.disabled=!runtimeEnabled;
    let rows=[],selected=[],active=-1,loading=false,loaded=false,inflight=null;
    let returnFocus=trigger, slashCommand=false;
    const conversation=byId('chatApp')?.dataset.conversation || 'new';
    const storage='regulai.skills.selection.'+conversation;
    try{selected=JSON.parse(sessionStorage.getItem(storage)||'[]');}catch(_){selected=[];}
    selected=Array.isArray(selected)?[...new Set(selected.filter(id=>typeof id==='string'))].slice(0,3):[];
    const autoStorage='regulai.skills.auto.'+conversation;
    if(conversation==='new'&&['true','false'].includes(sessionStorage.getItem(autoStorage)))auto.checked=sessionStorage.getItem(autoStorage)==='true';
    const save=()=>sessionStorage.setItem(storage,JSON.stringify(selected));
    function prepareAgent(){
      if(conversation!=='new')return;
      const activate=()=>{const radio=document.querySelector('input[name="conversation_mode"][value="agent"]');if(radio){radio.checked=true;radio.dispatchEvent(new Event('change',{bubbles:true}));}};
      if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',activate,{once:true});else activate();
    }
    function autoHelp(){byId('skillAutoHelp').textContent=auto.checked?'El agente puede cargar las instrucciones que necesite para tu tarea.':'La selección automática está desactivada en este chat. Puedes elegir una skill con /.';}
    auto.addEventListener('change',async()=>{
      autoHelp();if(!runtimeEnabled)return;
      if(conversation==='new'){sessionStorage.setItem(autoStorage,String(auto.checked));return;}
      auto.disabled=true;try{await request(`/skills/conversations/${conversation}/preference/`,{auto:auto.checked});}
      catch(error){auto.checked=!auto.checked;autoHelp();notice.textContent=error.message;}finally{auto.disabled=!runtimeEnabled;}
    });
    function paint(){
      chips.replaceChildren();selected.forEach(id=>{const row=rows.find(r=>r.id===id), name=row?displayName(row):'Skill seleccionada';const b=button(`${name} ×`,()=>{selected=selected.filter(v=>v!==id);save();paint();},'rg-skill-chip');b.setAttribute('aria-label',`Quitar skill ${name} del próximo mensaje`);chips.append(b);});
      list.replaceChildren();const matches=rows.filter(row=>`${displayName(row)} ${row.alias} ${summary(row)}`.toLocaleLowerCase().includes(search.value.toLocaleLowerCase()));
      matches.forEach(row=>{const option=el('div',null,'rg-skill-option');option.append(el('strong',displayName(row)),el('span',ready(row)?summary(row):`${stateLabel(row)}${requirements(row)?': '+requirements(row):''}`));option.id='skill-option-'+row.id;option.setAttribute('role','option');option.setAttribute('aria-selected',String(selected.includes(row.id)));option.setAttribute('aria-disabled',String(!ready(row)));option.tabIndex=-1;option.addEventListener('click',()=>choose(row));list.append(option);});
      active=-1;search.removeAttribute('aria-activedescendant');
      if(loading)status.textContent='Cargando tus skills…';
      else if(loaded)status.textContent=!rows.length?'Aún no tienes skills instaladas. Encuentra una en la biblioteca.':!matches.length?'No hay skills con ese nombre. Prueba otra búsqueda.':'Se usará en el próximo mensaje.';
    }
    function choose(row){
      if(!ready(row))return;
      if(selected.includes(row.id))selected=selected.filter(id=>id!==row.id);else if(selected.length<3)selected.push(row.id);else{status.textContent='Puedes seleccionar hasta tres skills. Quita una para elegir otra.';return;}
      if(slashCommand&&prompt.value==='/'){prompt.value='';prompt.dispatchEvent(new Event('input'));}
      notice.textContent='';save();paint();close(false);prompt.focus();
    }
    function close(focus=true){picker.hidden=true;trigger.setAttribute('aria-expanded','false');slashCommand=false;if(focus)returnFocus.focus();}
    function open(fromPrompt=false){
      if(!runtimeEnabled)return;
      returnFocus=fromPrompt?prompt:trigger;slashCommand=fromPrompt&&prompt.value==='/';
      picker.hidden=false;trigger.setAttribute('aria-expanded','true');search.value='';load();search.focus();
    }
    async function load(){
      if(inflight)return inflight;
      loading=true;retry.hidden=true;list.setAttribute('aria-busy','true');paint();
      inflight=(async()=>{try{
        const data=await request('/skills/?format=json');
        if(!Array.isArray(data.installations)||data.installations.some(row=>!row||typeof row.id!=='string'))throw new Error('No se ha podido leer la lista de skills. Vuelve a cargarla.');
        rows=data.installations;loaded=true;
        runtimeEnabled=data.runtime_enabled===true;trigger.disabled=auto.disabled=!runtimeEnabled;
        if(runtimeEnabled){
          const prior=selected;selected=selected.filter(id=>rows.some(row=>row.id===id&&ready(row)));
          if(prior.length!==selected.length)notice.textContent='Se han quitado de este mensaje las skills que ya no están disponibles. Revisa tu selección.';
          const pending=sessionStorage.getItem('regulai.skills.pending');
          if(pending){const row=rows.find(item=>item.id===pending);
            if(!row||!ready(row)){notice.textContent='Esta skill ya no está disponible. Revisa su instalación en la biblioteca.';sessionStorage.removeItem('regulai.skills.pending');sessionStorage.removeItem('regulai.skills.pending_note');}
            else if(conversation!=='new'&&byId('chatApp')?.dataset.mode!=='agent'){
              sessionStorage.setItem('regulai.skills.draft.'+conversation,byId('prompt').value);
              sessionStorage.setItem('regulai.skills.pending_note',agentNote);location.assign('/chat/');return;
            }
            else if(selected.includes(pending)||selected.length<3){
              if(!selected.includes(pending))selected.push(pending);prepareAgent();sessionStorage.removeItem('regulai.skills.pending');
              const note=sessionStorage.getItem('regulai.skills.pending_note');if(note){notice.textContent=note;sessionStorage.removeItem('regulai.skills.pending_note');}
            }
            else {prepareAgent();notice.textContent=`Ya has elegido tres skills. Quita una y vuelve a elegir ${displayName(row)}.`;}
          }
        }
        save();loading=false;paint();
      }catch(error){loading=false;status.textContent=error.message;retry.hidden=false;}
      finally{list.setAttribute('aria-busy','false');inflight=null;}})();return inflight;
    }
    trigger.addEventListener('click',()=>{if(picker.hidden)open();else close();});
    byId('skillPickerClose').addEventListener('click',()=>close());retry.addEventListener('click',load);
    picker.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();close();}});
    search.addEventListener('input',paint);search.addEventListener('keydown',event=>{const options=[...list.children];if(['ArrowDown','ArrowUp'].includes(event.key)&&options.length){event.preventDefault();active=active<0?(event.key==='ArrowDown'?0:options.length-1):(active+(event.key==='ArrowDown'?1:-1)+options.length)%options.length;search.setAttribute('aria-activedescendant',options[active].id);options.forEach((o,i)=>o.classList.toggle('is-active',i===active));options[active].scrollIntoView({block:'nearest'});}else if(event.key==='Enter'){event.preventDefault();options[active]?.click();}});
    document.addEventListener('click',event=>{if(!picker.hidden&&!picker.contains(event.target)&&!trigger.contains(event.target))close(false);});
    document.querySelectorAll('a[href="/skills/"]').forEach(link=>link.addEventListener('click',()=>{sessionStorage.setItem('regulai.skills.return',location.pathname);sessionStorage.setItem('regulai.skills.return_mode',conversation==='new'?(document.querySelector('input[name="conversation_mode"]:checked')?.value || byId('chatApp')?.dataset.mode):byId('chatApp')?.dataset.mode);sessionStorage.setItem('regulai.skills.draft.'+conversation,byId('prompt').value);if(conversation==='new')sessionStorage.setItem(autoStorage,String(auto.checked));save();}));
    // Omit disabled selection so an ordinary send preserves the conversation's
    // stored automatic preference and pending selections for later activation.
    window.regulaySkills={capture:()=>runtimeEnabled?{selected:[...selected],auto:auto.checked}:undefined,accepted:()=>{if(!runtimeEnabled)return;selected=[];save();sessionStorage.removeItem(autoStorage);notice.textContent='';paint();},restore:load};
    const draft=sessionStorage.getItem('regulai.skills.draft.'+conversation);if(draft&&!byId('prompt').value){byId('prompt').value=draft;byId('prompt').dispatchEvent(new Event('input'));sessionStorage.removeItem('regulai.skills.draft.'+conversation);}
    prompt.addEventListener('input',event=>{
      const mode=conversation==='new'?(document.querySelector('input[name="conversation_mode"]:checked')?.value || app?.dataset.mode):app?.dataset.mode;
      if(!event.isComposing&&mode==='agent'&&prompt.value==='/'&&prompt.selectionStart===1&&prompt.selectionEnd===1)open(true);
    });
    autoHelp();paint();
    // Automatic activation uses the server's catalogue in the normal inference.
    // The browser fetches installations only for a manual action or saved intent.
    if(selected.length||sessionStorage.getItem('regulai.skills.pending'))load();
  }
})();
