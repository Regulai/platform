"""Actual HTTP admission -> first durable state visibly rendered; no worker/provider."""
import json
import uuid

import p1_stream_browser_latency as ui


def main():
    import p1_ui_lab  # configure, never invoke destructive fixture main
    from django.conf import settings
    settings.DATABASES['default']['NAME'] = 'test_regulai_p1_browser'
    import django
    django.setup()
    from django.db import connection
    from django.contrib.auth.models import User
    from front.models import AgentExecution, Conversation, Message
    from front.agents import jobs
    lab=json.loads((ui.ROOT/'output/p1-20261016/ui-lab.json').read_text(encoding='utf-8'))
    assert lab['fixture'] and connection.settings_dict['NAME']==lab['database']=='test_regulai_p1_browser'
    assert connection.settings_dict['HOST']=='127.0.0.1' and str(connection.settings_dict['PORT'])=='55468'
    user=User.objects.get(username='p1-ui')
    conversation=Conversation.objects.create(user=user,mode='agent',title='P1 accepted-state fixture '+str(uuid.uuid4())[:8])
    Message.objects.bulk_create([Message(conversation=conversation,role='user' if i%2==0 else 'assistant',content=f'Contexto sintético de admisión {i}.') for i in range(200)])
    ui.SESSION='p1-accepted-latency'
    url='http://127.0.0.1:8872'
    try:
        ui.cli('open',url)
        cookies=[{'name':lab['cookie_name'],'value':lab['session_cookie'],'url':url}]
        results=ui.browser('''async page=>{
          await page.context().addCookies(COOKIES);await page.setViewportSize({width:1440,height:900});
          await page.goto(URL);await page.waitForFunction(()=>window.regulayAgent?.watchers);
          await page.evaluate(()=>{
            const state={rows:[],seen:new Set(),longTasks:[],history:[...document.querySelectorAll('#chatContainer article')].slice(0,200)};
            state.performanceObserver=new PerformanceObserver(list=>state.longTasks.push(...list.getEntries().map(e=>e.duration)));
            state.performanceObserver.observe({type:'longtask'});
            state.observer=new MutationObserver(()=>{
              for(const [id,w] of window.regulayAgent.watchers){
                if(state.seen.has(id)||!w.loaded||w.title.textContent!=='En cola'||!w.events.some(e=>e.kind==='queued'))continue;
                state.seen.add(id);const dom_ms=performance.timeOrigin+performance.now();
                requestAnimationFrame(()=>requestAnimationFrame(()=>state.rows.push({id,dom_ms,paint_ms:performance.timeOrigin+performance.now(),text:w.title.textContent})));
              }
            });state.observer.observe(document.getElementById('chatContainer'),{childList:true,characterData:true,subtree:true});
            window.__p1AcceptedLatency=state;
          });
          const rows=[];
          for(let i=1;i<=20;i++){
            await page.locator('#prompt').fill('P1 accepted-state fixture '+i+': explica Madrid con texto breve.');
            const pending=page.waitForResponse(r=>r.request().method()==='POST'&&r.url().endsWith('/send/'));
            await page.locator('#sendButton').click();const response=await pending;
            const body=await response.json();if(response.status()!==202)throw Error(JSON.stringify({status:response.status(),body}));
            const accepted_ms=Number(response.headers()['x-p1-accepted-ms']);if(!accepted_ms)throw Error('Missing post-commit acceptance timestamp');
            const id=body.agent.id;
            await page.waitForFunction(id=>window.__p1AcceptedLatency.rows.some(r=>r.id===id),id,{timeout:5000});
            const rendered=await page.evaluate(id=>window.__p1AcceptedLatency.rows.find(r=>r.id===id),id);
            rows.push({sample:i,...rendered,accepted_ms,created_ms:Date.parse(body.agent.created_at),accepted_to_paint_ms:rendered.paint_ms-accepted_ms});
            await page.evaluate(async id=>{await window.regulayAgent.watchers.get(id).cancel();},id);
            await page.waitForFunction(id=>window.regulayAgent.watchers.get(id).run.status==='cancelled',id);
          }
          return await page.evaluate(rows=>{
            const state=window.__p1AcceptedLatency;state.observer.disconnect();state.performanceObserver.disconnect();
            return {rows,history_nodes:state.history.length,history_stable:state.history.every((node,i)=>node===document.querySelectorAll('#chatContainer article')[i]),long_tasks_ms:state.longTasks};
          },rows);
        }'''.replace('COOKIES',json.dumps(cookies)).replace('URL',json.dumps(url+'/chat/'+str(conversation.pk)+'/')))
        metrics=ui.stats([row['accepted_to_paint_ms'] for row in results['rows']])
        report={'fixture':True,'provider_requests':0,'conversation':conversation.pk,
            'scope':'20 real composer submissions -> production /chat/<conversation>/send/ agent admission transaction -> fixture post-commit response header -> real client mount + authorized snapshot -> durable queued event/state En cola -> two rAFs.',
            'clock':'Same host Python epoch timestamp immediately after admission view returns and browser performance.timeOrigin+performance.now.',
            'load':'200 existing history articles; one Chromium page; each admitted run cancelled through its normal authorized endpoint before next sample.',
            'limitations':['No worker, inference or paid provider calls. Each prompt is admitted then cancelled, not represented as completed.','Excludes pre-admission policy/queue request processing; measures accepted durable request to first rendered durable state, as distinct from connection-to-first-SSE-frame.','Loopback fixture, no production-throughput or provider-quality claim.'],
            **results,'accepted_to_paint':metrics,
            'gates':{'accepted_to_first_durable_state_max_lte_500_ms':metrics['max_ms']<=500,'history_stable':results['history_nodes']==200 and results['history_stable']}}
        (ui.OUT/'accepted-browser-latency.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps({'accepted_to_paint':metrics,'gates':report['gates']}))
        return 0 if all(report['gates'].values()) else 1
    except Exception:
        print(ui.browser('async page=>({url:page.url(),state:await page.evaluate(()=>({title:document.title,body:document.body.innerText.slice(0,500),watchers:[...(window.regulayAgent?.watchers||[])].map(([id,w])=>({id,loaded:w.loaded,unavailable:w.unavailable,status:w.run.status}))}))})'))
        raise
    finally:
        for run in AgentExecution.objects.filter(conversation=conversation,status__in=['queued','active']):jobs.cancel(user,run.pk)
        ui.cli('close');connection.close()


if __name__=='__main__':
    raise SystemExit(main())
