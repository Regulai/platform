"""Measure durable authorized text publication to browser paint in the existing isolated UI lab."""
from datetime import timedelta
import json
from pathlib import Path
import platform
import random
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/e8'
SESSION = 'p1-stream-latency'


def cli(*args):
    command = ['rtk', 'proxy', 'npx', '--yes', '--package', '@playwright/cli',
        'playwright-cli', '-s=' + SESSION, *args]
    # On Windows the persistent browser daemon can inherit an open stdout pipe.
    # A file sink lets CLI open() return without waiting for that daemon to exit.
    if args[0] == 'open':
        OUT.mkdir(parents=True, exist_ok=True)
        target = OUT/'stream-browser-open.log'
        with target.open('w', encoding='utf-8') as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=60)
        output = target.read_text(encoding='utf-8')
    else:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=60)
        output = result.stdout+result.stderr
    if result.returncode or '### Error' in output:
        raise RuntimeError(output)
    return output


def browser(code):
    result = cli('run-code', code.replace('\n', ' '))
    return json.loads(result.split('### Result\n', 1)[1].split('\n### Ran', 1)[0])


def stats(values):
    ordered = sorted(values)
    return {'n': len(values), 'p50_ms': (ordered[9]+ordered[10])/2,
        'p95_ms': ordered[18], 'max_ms': max(values), 'samples_ms': values}


def main():
    # Import only configuration; do not call its destructive fixture main().
    import p1_ui_lab
    from django.conf import settings
    settings.DATABASES['default']['NAME'] = 'test_regulai_p1_browser'
    import django
    django.setup()
    from django.db import connection
    from django.utils import timezone
    from django.contrib.auth.models import User
    from front.models import AgentExecution, Conversation
    from front.agents import jobs
    from front.agents.event_store import append_event
    lab = json.loads((ROOT/'output/p1-20261016/ui-lab.json').read_text(encoding='utf-8'))
    assert lab['fixture'] and lab['database'] == 'test_regulai_p1_browser'
    assert connection.settings_dict['NAME'] == lab['database']
    assert connection.settings_dict['HOST'] == '127.0.0.1' and str(connection.settings_dict['PORT']) == '55468'
    user = User.objects.get(username='p1-ui')
    conversation = Conversation.objects.get(pk=lab['conversation'], user=user)
    result = jobs.enqueue(user, {}, conversation, 'Explica brevemente Madrid en el chat.', uuid.uuid4())
    assert result.http_status == 202, result.data
    run = AgentExecution.objects.get(pk=result.data['agent']['id'])
    call_id = uuid.uuid4()
    run.status, run.attempt, run.active_call = 'active', uuid.uuid4(), call_id
    run.started_at, run.expires_at = timezone.now(), timezone.now()+timedelta(minutes=10)
    run.save(update_fields=['status', 'attempt', 'active_call', 'started_at', 'expires_at'])
    append_event(run, 'inference.started', call_id=str(call_id), purpose='generation', mode='streamed', reason=None)
    cookies = [{'name': lab['cookie_name'], 'value': lab['session_cookie'], 'url': lab['url']}]
    published = []
    try:
        cli('open', lab['url'])
        ready = browser('''async page => {
          await page.context().addCookies(COOKIES);
          await page.setViewportSize({width:1440,height:900});
          await page.goto(URL);
          await page.waitForFunction(id=>window.regulayAgent?.watchers.get(id)?.loaded,RUN);
          return await page.evaluate(async id=>{
            const watcher=window.regulayAgent.watchers.get(id);
            if(!watcher.stream)throw Error('Real watcher SSE not active');
            const first=[];
            for(let i=0;i<20;i++)first.push(await new Promise((resolve,reject)=>{
              const started=performance.now(),source=new EventSource(watcher.run.events_url+'?cursor=0');
              const timeout=setTimeout(()=>{source.close();reject(Error('first event timeout'));},3000);
              source.addEventListener('progress',()=>{clearTimeout(timeout);source.close();resolve(performance.now()-started);},{once:true});
              source.onerror=()=>{clearTimeout(timeout);source.close();reject(Error('first event unavailable'));};
            }));
            const state={first,rows:[],seen:new Set(),longTasks:[],history:[...document.querySelectorAll('#chatContainer article')].slice(0,200)};
            state.performanceObserver=new PerformanceObserver(list=>state.longTasks.push(...list.getEntries().map(x=>x.duration)));
            state.performanceObserver.observe({type:'longtask'});
            state.observer=new MutationObserver(()=>{
              for(const match of watcher.answerSlot.textContent.matchAll(/Muestra (\\d{2})/g)){
                const sample=Number(match[1]);if(state.seen.has(sample))continue;state.seen.add(sample);
                const mutation=performance.timeOrigin+performance.now();
                requestAnimationFrame(()=>requestAnimationFrame(()=>state.rows.push({sample,dom_ms:mutation,paint_ms:performance.timeOrigin+performance.now()})));
              }
            });
            state.observer.observe(watcher.answerSlot,{childList:true,subtree:true,characterData:true});
            window.__p1StreamLatency=state;
            return {first,history_nodes:state.history.length,visibility:document.visibilityState};
          },RUN);
        }'''.replace('COOKIES', json.dumps(cookies)).replace('URL', json.dumps(lab['url']+'/chat/'+str(conversation.pk)+'/')).replace('RUN', json.dumps(str(run.pk))))
        assert ready['visibility'] == 'visible', ready
        offset = 0
        schedule = random.Random(20261016)
        for index in range(1, 21):
            # Vary phase relative to the 150ms poll, not synchronized best cases.
            time.sleep(schedule.uniform(.23, .47))
            jobs.authorized_run(user, run.pk)
            text = f'Muestra {index:02d} · Texto sintético autorizado de Madrid, acentos y 😀.\n\n'
            begin = time.time_ns()/1_000_000
            row = append_event(run, 'text.delta', event_key=f'browser:{call_id}:{index}', public_text=text,
                inference_id=str(call_id), message_id=f'inference:{call_id}', offset=offset)
            committed = time.time_ns()/1_000_000
            offset += len(text.encode())
            published.append({'sample': index, 'event_id': row.pk, 'before_append_ms': begin, 'committed_ms': committed})
        rendered = browser('''async page=>{
          await page.waitForFunction(()=>window.__p1StreamLatency.rows.length===20,{},{timeout:5000});
          return await page.evaluate(()=>{
            const state=window.__p1StreamLatency;state.observer.disconnect();state.performanceObserver.disconnect();
            return {rows:state.rows,history_stable:state.history.every((node,i)=>node===document.querySelectorAll('#chatContainer article')[i]),long_tasks_ms:state.longTasks};
          });
        }''')
        rows = []
        for sample in published:
            paint = next(value for value in rendered['rows'] if value['sample'] == sample['sample'])
            rows.append({**sample, **paint, 'commit_to_dom_ms': paint['dom_ms']-sample['committed_ms'],
                'commit_to_paint_ms': paint['paint_ms']-sample['committed_ms'],
                'append_to_paint_ms': paint['paint_ms']-sample['before_append_ms']})
        summary = {'fixture': True, 'provider_requests': 0, 'platform': platform.platform(),
            'scope': '20 text.delta publications: authorized run -> encrypted PostgreSQL append/commit -> real ASGI loopback SSE -> AgentWatcher -> Markdown DOM -> two requestAnimationFrames.',
            'clock': 'Python time.time_ns and browser performance.timeOrigin+performance.now, same Windows host; publication time read immediately after append transaction returns.',
            'load': 'One Chromium page/SSE consumer, 200 prior message articles, 1440x900; isolated shared P1 database, other local verification may run concurrently.',
            'limitations': ['Synthetic pre-authorized public text; excludes inference, protection, queue and provider latency.',
                'Two rAFs conservatively approximate a paint opportunity, not physical monitor photon time.',
                'First-event probes are sequential fresh SSE requests, completed before the 20 publication samples.',
                'This measures streamed text, not artifact-card publication or preview opening.'],
            'run': str(run.pk), 'history_nodes': ready['history_nodes'], 'history_stable': rendered['history_stable'],
            'first_event': stats(ready['first']), 'commit_to_dom': stats([row['commit_to_dom_ms'] for row in rows]),
            'commit_to_paint': stats([row['commit_to_paint_ms'] for row in rows]),
            'append_to_paint': stats([row['append_to_paint_ms'] for row in rows]),
            'long_tasks_ms': rendered['long_tasks_ms'], 'samples': rows}
        summary['gates'] = {'first_event_max_lte_500_ms': summary['first_event']['max_ms']<=500,
            'text_commit_to_paint_p95_lte_350_ms': summary['commit_to_paint']['p95_ms']<=350,
            'stable_200_history_nodes': ready['history_nodes']==200 and rendered['history_stable']}
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT/'stream-browser-latency.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
        print(json.dumps({key: summary[key] for key in ('first_event','commit_to_paint','append_to_paint','gates')},ensure_ascii=False))
        return 0 if all(summary['gates'].values()) else 1
    finally:
        jobs.cancel(user, run.pk)
        cli('close')
        connection.close()


if __name__=='__main__':
    raise SystemExit(main())
