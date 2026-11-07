"""Authorized artifact publication -> actual browser card paint, isolated P1 lab only."""
import argparse
from datetime import timedelta
import json
import platform
import random
import time
import uuid

import p1_stream_browser_latency as ui


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:8871')
    parser.add_argument('--label', default='before')
    args = parser.parse_args()
    if args.url not in ('http://127.0.0.1:8871', 'http://127.0.0.1:8872'):
        raise ValueError('isolated_loopback_required')
    import p1_ui_lab  # config only, never its destructive main()
    from django.conf import settings
    settings.DATABASES['default']['NAME'] = 'test_regulai_p1_browser'
    import django
    django.setup()
    from django.contrib.auth.models import User
    from django.db import connection, transaction
    from django.utils import timezone
    from front.models import AgentExecution, Conversation
    from front.agents import jobs, delivery, file_continuity
    from front.agents.event_store import append_event
    from front.agents.professional_artifacts import inspect_file
    from front.agents.service import _context
    lab = json.loads((ui.ROOT/'output/p1-20261016/ui-lab.json').read_text(encoding='utf-8'))
    assert lab['fixture'] and connection.settings_dict['NAME'] == lab['database'] == 'test_regulai_p1_browser'
    assert connection.settings_dict['HOST'] == '127.0.0.1' and str(connection.settings_dict['PORT']) == '55468'
    user = User.objects.get(username='p1-ui')
    conversation = Conversation.objects.get(pk=lab['conversation'], user=user)
    prompt = 'Crea archivos HTML sintéticos para comprobar las tarjetas.'
    for stale in AgentExecution.objects.filter(conversation=conversation, prompt__content=prompt, status__in=['queued','active']):
        jobs.cancel(user, stale.pk)
    result = jobs.enqueue(user, {}, conversation, prompt, uuid.uuid4())
    assert result.http_status == 202, result.data
    run = AgentExecution.objects.get(pk=result.data['agent']['id'])
    run.status, run.attempt, run.active_call = 'active', uuid.uuid4(), None
    run.started_at, run.expires_at = timezone.now(), timezone.now()+timedelta(minutes=10)
    run.save(update_fields=['status', 'attempt', 'active_call', 'started_at', 'expires_at'])
    append_event(run, 'tool.started', name='publish_artifact', operation_id=str(uuid.uuid4()))
    artifacts = []
    for index in range(1, 21):
        filename = f'tarjeta_{index:02d}_{str(run.pk)[:8]}.html'
        raw = f'<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Muestra {index}</title></head><body><h1>Madrid {index}</h1><p>Artefacto sintético autorizado.</p></body></html>'.encode()
        proof, _, _ = inspect_file(raw, 'html', budget=run.job['limits'])
        artifact = file_continuity.persist_revision(run, '/workspace/output/'+filename, raw, proof, purpose='deliverable', status='draft')
        artifacts.append(artifact)
    file_continuity.write_manifest(run, [(a, '/workspace/output/'+a.filename, []) for a in artifacts])
    ui.SESSION = 'p1-artifact-review'
    cookies = [{'name':lab['cookie_name'],'value':lab['session_cookie'],'url':args.url}]
    publications = []
    try:
        ui.cli('open', args.url)
        ready = ui.browser('''async page=>{
          await page.context().addCookies(COOKIES);
          await page.setViewportSize({width:1440,height:900});
          await page.goto(URL);
          await page.waitForFunction(id=>window.regulayAgent?.watchers.get(id)?.loaded,RUN);
          await page.waitForTimeout(400);
          await page.locator('#chatScroll').hover();await page.mouse.wheel(0,-2500);await page.waitForTimeout(500);
          return await page.evaluate(id=>{
            const watcher=window.regulayAgent.watchers.get(id),scroll=document.getElementById('chatScroll');
            if(!watcher.stream)throw Error('Real watcher SSE missing');
            const state={rows:[],events:[],seen:new Set(),longTasks:[],history:[...document.querySelectorAll('#chatContainer article')].slice(0,200),scrollTop:scroll.scrollTop,status_url:watcher.run.status_url};
            watcher.stream.addEventListener('progress',message=>{const event=JSON.parse(message.data);if(event.kind==='artifact.available')state.events.push({event_id:event.id,event_received_ms:performance.timeOrigin+performance.now()});});
            state.performanceObserver=new PerformanceObserver(list=>state.longTasks.push(...list.getEntries().map(x=>x.duration)));
            state.performanceObserver.observe({type:'longtask'});
            state.observer=new MutationObserver(()=>{
              for(const match of watcher.deliverables.textContent.matchAll(/tarjeta_(\\d{2})_/g)){
                const sample=Number(match[1]);if(state.seen.has(sample))continue;state.seen.add(sample);
                const mutation=performance.timeOrigin+performance.now();
                requestAnimationFrame(()=>requestAnimationFrame(()=>state.rows.push({sample,dom_ms:mutation,paint_ms:performance.timeOrigin+performance.now(),scrollTop:scroll.scrollTop})));
              }
            });
            state.observer.observe(watcher.deliverables,{childList:true,subtree:true,characterData:true});
            window.__p1ArtifactLatency=state;
            return {history_nodes:state.history.length,scrollTop:scroll.scrollTop,distance:scroll.scrollHeight-scroll.clientHeight-scroll.scrollTop,visibility:document.visibilityState};
          },RUN);
        }'''.replace('COOKIES',json.dumps(cookies)).replace('URL',json.dumps(args.url+'/chat/'+str(conversation.pk)+'/')).replace('RUN',json.dumps(str(run.pk))))
        assert ready['visibility']=='visible' and ready['distance']>500, ready
        schedule = random.Random(20261017)
        context = _context(run.prompt, run.profile_id)
        for index, artifact in enumerate(artifacts, 1):
            time.sleep(schedule.uniform(.65,.95))
            jobs.authorized_run(user, run.pk)
            start = time.time_ns()/1_000_000
            with transaction.atomic():
                AgentExecution.objects.select_for_update().get(pk=run.pk)
                artifact.status = 'verified'
                artifact.save(update_fields=['status'])
                run.prompt.decision['delivery'] = delivery.receipt(run, artifacts[:index], context)
                run.prompt.save(update_fields=['decision'])
                event = append_event(run, 'artifact.available', artifact_id=str(artifact.pk), revision=artifact.revision,
                    event_key='browser-artifact:'+str(artifact.pk))
            committed = time.time_ns()/1_000_000
            publications.append({'sample':index,'artifact_id':str(artifact.pk),'event_id':event.pk,'before_authorized_publication_ms':start,'committed_ms':committed})
        rendered = ui.browser('''async page=>{
          await page.waitForFunction(()=>window.__p1ArtifactLatency.rows.length===20,{},{timeout:5000});
          const before=await page.evaluate(()=>{
            const state=window.__p1ArtifactLatency;state.observer.disconnect();state.performanceObserver.disconnect();
            const jump=document.getElementById('jumpToEnd');
            return {rows:state.rows,events:state.events,snapshot_requests:performance.getEntriesByType('resource').filter(r=>r.name.endsWith(state.status_url)).map(r=>({start_ms:performance.timeOrigin+r.startTime,duration_ms:r.duration})),history_stable:state.history.every((node,i)=>node===document.querySelectorAll('#chatContainer article')[i]),long_tasks_ms:state.longTasks,
              scrollTop:document.getElementById('chatScroll').scrollTop,jump_visible:!jump.hidden,jump_text:jump.textContent};
          });
          await page.screenshot({path:SCREENSHOT});
          await page.locator('#jumpToEnd').click();
          await page.waitForTimeout(1000);
          return {...before,after_jump:await page.evaluate(()=>{
            const scroll=document.getElementById('chatScroll'),count=document.querySelector('.rg-jump-count');
            return {distance:scroll.scrollHeight-scroll.clientHeight-scroll.scrollTop,hidden:document.getElementById('jumpToEnd').hidden,count:count.textContent};
          })};
        }'''.replace('SCREENSHOT',json.dumps(str(ui.ROOT/f'output/playwright/p1-manual-scroll-{args.label}.png'))))
        rows=[]
        for item in publications:
            paint=next(p for p in rendered['rows'] if p['sample']==item['sample'])
            event=next((e for e in rendered['events'] if e['event_id']==item['event_id']),{})
            rows.append({**item,**paint,'commit_to_dom_ms':paint['dom_ms']-item['committed_ms'],
                'commit_to_paint_ms':paint['paint_ms']-item['committed_ms'],
                **event,
                'authorized_publication_to_paint_ms':paint['paint_ms']-item['before_authorized_publication_ms']})
        summary={'fixture':True,'provider_requests':0,'platform':platform.platform(),'url':args.url,
            'scope':'20 different HTML revisions: inspect bytes and current run authorization -> encrypted artifact and server-owned verified delivery receipt + artifact.available transaction -> real ASGI loopback SSE -> real AgentWatcher authorized GET -> card DOM -> two rAFs.',
            'clock':'Same Windows host: Python time.time_ns and browser performance.timeOrigin+performance.now; commit timestamp immediately after transaction returns.',
            'load':'One Chromium page/SSE consumer, at least 200 history articles, 20 cumulative artifact cards; active run in tool phase with active_call=None; real mouse.wheel moves 2500px up before publication.',
            'limitations':['Synthetic authorized artifacts; no provider, queue, tool-execution or preview-opening latency.','Two rAFs approximate a paint opportunity, not monitor photon time.','Shared local P1 verification environment, no production-throughput claim.'],
            'run':str(run.pk),'ready':ready,'rendered':rendered,'samples':rows,
            'commit_to_paint':ui.stats([row['commit_to_paint_ms'] for row in rows]),
            'authorized_publication_to_paint':ui.stats([row['authorized_publication_to_paint_ms'] for row in rows])}
        summary['gates']={'card_commit_to_paint_p95_lte_350_ms':summary['commit_to_paint']['p95_ms']<=350,
            'history_stable':ready['history_nodes']==200 and rendered['history_stable'],
            'manual_scroll_stable':all(abs(row['scrollTop']-ready['scrollTop'])<2 for row in rows),
            'one_updated_message_count':rendered['jump_visible'] and '1 mensaje actualizado' in rendered['jump_text'],
            'jump_returns_and_clears':rendered['after_jump']['distance']<72 and rendered['after_jump']['hidden'] and rendered['after_jump']['count']==''}
        (ui.OUT/f'artifact-browser-latency-{args.label}.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
        print(json.dumps({key:summary[key] for key in ('commit_to_paint','authorized_publication_to_paint','gates')},ensure_ascii=False))
        return 0 if all(summary['gates'].values()) else 1
    except Exception:
        print(ui.browser('async page=>({url:page.url(),state:await page.evaluate(()=>({title:document.title,watchers:[...(window.regulayAgent?.watchers||[])].map(([id,w])=>({id,loaded:w.loaded,unavailable:w.unavailable,status:w.run.status}))}))})'))
        raise
    finally:
        jobs.cancel(user,run.pk)
        ui.cli('close')
        connection.close()


if __name__=='__main__':
    raise SystemExit(main())
