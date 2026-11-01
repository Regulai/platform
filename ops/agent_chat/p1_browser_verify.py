"""Run bounded browser measurements in the already inspected synthetic UI lab."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/e8'


def run(code):
    result = subprocess.run(['rtk', 'proxy', 'npx', '--yes', '--package', '@playwright/cli',
        'playwright-cli', '-s=p1', 'run-code', code.replace('\n', ' ')], cwd=ROOT, capture_output=True, text=True, encoding='utf-8')
    if result.returncode or '### Error' in result.stdout:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads(result.stdout.split('### Result\n', 1)[1].split('\n### Ran', 1)[0])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    results = {'fixture': True, 'provider_requests': 0}
    results['catalog'] = run(r'''async page => {
      await page.goto('http://127.0.0.1:8871/skills/');
      return await page.evaluate(async()=>{
        const http=[], filter=[];
        for(let i=0;i<20;i++){ const start=performance.now(); const r=await fetch('/skills/?format=json');
          if(!r.ok)throw Error('catalog unavailable');await r.json();http.push(performance.now()-start); }
        const input=document.getElementById('skillSearch'), grid=document.getElementById('skillGrid');
        for(let i=0;i<20;i++){
          filter.push(await new Promise((resolve,reject)=>{const started=performance.now();
            const timer=setTimeout(()=>{observer.disconnect();reject(Error('filter timeout'));},2000);
            const observer=new MutationObserver(()=>{observer.disconnect();clearTimeout(timer);resolve(performance.now()-started);});
            observer.observe(grid,{childList:true});input.value=i%2?'':'frontend';input.dispatchEvent(new Event('input'));
          }));
        }
        const summarize=a=>({n:a.length,median_ms:[...a].sort((x,y)=>x-y)[10],p95_ms:[...a].sort((x,y)=>x-y)[18],max_ms:Math.max(...a),samples_ms:a});
        return {http:summarize(http),local_filter:summarize(filter)};
      });
    }''')
    results['renderer'] = run(r'''async page => {
      await page.goto('http://127.0.0.1:8871/chat/1/');
      await page.getByRole('button',{name:'Vista previa',exact:true}).waitFor();
      return await page.evaluate(async()=>{
        const history=[...document.querySelectorAll('#chatContainer article')].slice(0,200);
        const root=document.createElement('div');root.className='rg-md';document.getElementById('chatContainer').append(root);
        const source=('Texto público sintético con **énfasis** y tabla.\n\n|A|B|\n|---|---|\n|1|2|\n\n```js\nconst value = 42;\n```\n\n').repeat(230).slice(0,20000);
        const times=[],longTasks=[];const observer=new PerformanceObserver(list=>longTasks.push(...list.getEntries().map(x=>x.duration)));
        observer.observe({type:'longtask'});
        let first;
        for(let offset=200;offset<=source.length;offset+=200){
          const start=performance.now();window.RegulayMarkdown.render(root,source.slice(0,offset),{streaming:true,animate:false});times.push(performance.now()-start);
          if(!first)first=root.firstElementChild;
          if(root.firstElementChild!==first)throw Error('closed block replaced');
          await new Promise(requestAnimationFrame);
        }
        await new Promise(requestAnimationFrame);observer.disconnect();
        const stable=history.length===200&&history.every((node,i)=>node===document.querySelectorAll('#chatContainer article')[i]);
        root.remove();
        if(!stable)throw Error('historical DOM changed');
        return {history_nodes:history.length,response_characters:source.length,renders:times.length,stable_history:stable,stable_closed_block:true,
          render_p95_ms:[...times].sort((a,b)=>a-b)[94],render_max_ms:Math.max(...times),long_tasks_ms:longTasks,samples_ms:times};
      });
    }''')
    results['preview'] = run(r'''async page => {
      const requests=[];const track=request=>{if(request.frame().parentFrame())requests.push(request.url());};page.on('request',track);
      const samples=[];
      for(let i=0;i<20;i++){
        const begin=Date.now();await page.getByRole('button',{name:'Vista previa',exact:true}).click();
        await page.getByRole('tab',{name:'Vista previa',exact:true}).waitFor();
        await page.locator('#artifactPreview').contentFrame().getByRole('heading',{name:'Una ciudad para descubrir.'}).waitFor();
        samples.push(Date.now()-begin);
        if(i<19)await page.getByRole('button',{name:'Volver al chat'}).click();
      }
      const isolation=await page.locator('#artifactPreview').contentFrame().locator('body').evaluate(()=>{
        let parentDenied=false,cookiesDenied=false;try{void parent.document.body;}catch(_){parentDenied=true;}
        try{void document.cookie;}catch(_){cookiesDenied=true;}
        return {parentDenied,cookiesDenied,scriptCount:document.scripts.length};
      });
      const escaped=await page.evaluate(()=>Boolean(window.__p1PreviewEscape));
      const responsive=[];
      for(const width of [1440,768,360]){await page.setViewportSize({width,height:900});
        responsive.push(await page.locator('.rg-artifact-drawer').evaluate(node=>({width:innerWidth,modal:node.matches(':modal'),open:node.open})));
        await page.screenshot({path:'output/playwright/p1-preview-final-'+width+'.png',animations:'disabled'});}
      await page.getByRole('button',{name:'Volver al chat'}).click();
      const focusRestored=await page.getByRole('button',{name:'Vista previa',exact:true}).evaluate(node=>document.activeElement===node);
      page.off('request',track);
      if(escaped||!isolation.parentDenied||!isolation.cookiesDenied||isolation.scriptCount||requests.length||!focusRestored)throw Error('preview boundary failed');
      return {n:samples.length,open_to_render_p95_ms:[...samples].sort((a,b)=>a-b)[18],samples_ms:samples,
        isolation,escaped,iframe_requests:requests,responsive,focusRestored};
    }''')
    (OUT/'browser-metrics.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key,value in results.items()}, ensure_ascii=False))


if __name__ == '__main__':
    main()
