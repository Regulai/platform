"""Static preview authorization and incremental chat rendering; synthetic artifacts."""
import base64
import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from front.agents.artifact_preview import static_html, CSP
from front.offline_browser import OfflineBrowser
from front.test_agent_files import FileFixture
from front.test_agent_frontend import AGENT
from front.test_chat_flow import ChatFixture
from front.models import AgentOperation, AgentToolResult


class StaticProjectionTests(SimpleTestCase):
    def test_html_svg_drop_active_and_network_surfaces_but_keep_static_content(self):
        source = '''<!doctype html><html><head><meta http-equiv="refresh" content="0;url=https://evil.invalid">
          <base href="https://evil.invalid"><link rel="stylesheet" href="https://evil.invalid/x.css">
          <style>@import "https://evil.invalid/y.css";body{background:url(https://evil.invalid/z);color:blue}</style></head>
          <body onload="parent.document.cookie"><h1>Madrid</h1><script>fetch('https://evil.invalid')</script>
          <a href="javascript:alert(1)" target="_top" ping="https://evil.invalid">Link</a>
          <form action="https://evil.invalid"><input name="secret"></form><img src="https://evil.invalid/p" onerror="alert(1)">
          <iframe src="https://evil.invalid"></iframe><svg viewBox="0 0 20 20"><rect width="20" height="20"/>
          <foreignObject><p>Active HTML</p></foreignObject><a href="https://evil.invalid"><text x="0" y="10">safe</text></a>
          <use href="https://evil.invalid/a.svg#x"/></svg></body></html>'''
        result = static_html(source)
        for forbidden in ('evil.invalid', 'script>', 'onload', 'onerror', 'javascript:', 'target=', 'ping=',
                          '<form', '<input', '<iframe', '<foreignobject', 'Active HTML'):
            self.assertNotIn(forbidden, result)
        self.assertIn('Madrid', result)
        self.assertIn('color:blue', result)
        self.assertIn('<rect width="20" height="20">', result)
        self.assertIn('Content-Security-Policy', result)
        self.assertIn("default-src &#x27;none&#x27;", result)


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_ARTIFACT_PREVIEW=True, DEBUG=False)
class ArtifactPreviewTests(FileFixture, TestCase):
    def test_operation_details_exclude_commands_raw_results_and_worker_paths(self):
        run = self.queued('Calcula 3 + 4')
        row = AgentOperation.objects.create(execution=run, call_id='projection', name='execute',
            request_digest='a'*64, request=json.dumps({'command': 'echo private-secret'}),
            result='private-secret', status='completed', completed_at=timezone.now())
        AgentToolResult.objects.create(execution=run, call_id=row.call_id, request_digest='b'*64,
            raw='private-secret', protected_view=json.dumps({'exit_code': 0, 'succeeded': True,
                'output': 'private-secret', 'stderr': '/workspace/private', 'arguments': {'command': 'private-secret'}}))
        response = self.client.get(f'/chat/agent/runs/{run.pk}/operations/{row.pk}/')
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['result'], {'status': 'completed', 'exit_code': 0, 'succeeded': True})
        self.assertNotIn('private', response.content.decode())
        self.assertNotIn('arguments', response.json())
        self.assertEqual(self.requests, [])

    def test_preview_is_separate_from_download_and_preserves_revision_bytes_without_provider(self):
        raw = b'<html><h1>Madrid</h1><script>window.top.location="https://evil.invalid"</script></html>'
        artifact = self.make_artifact(raw=raw)
        url = f'/chat/agent/artifacts/{artifact.pk}/preview/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content)
        data = response.json()
        self.assertEqual(data['code'].encode(), raw)
        self.assertNotIn('<script', data['html'])
        self.assertEqual(data['sha256'], artifact.sha256)
        self.assertEqual(data['revision'], artifact.revision)
        self.assertIn('application/json', response['Content-Type'])
        self.assertIn('no-store', response['Cache-Control'])
        downloaded = self.client.get(data['download_url'])
        self.assertEqual(downloaded.content, raw)
        artifact.refresh_from_db()
        self.assertEqual(base64.b64decode(artifact.content), raw)
        self.assertEqual(self.requests, [])

    def test_preview_reauthorizes_other_user_disabled_grant_and_flag(self):
        artifact = self.make_artifact()
        url = f'/chat/agent/artifacts/{artifact.pk}/preview/'
        state_url = f'/chat/agent/runs/{artifact.execution_id}/'
        self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(self.client.get(state_url).status_code, 200)
        other = User.objects.create_user('other-preview', password='synthetic')
        self.client.force_login(other)
        self.assertIn(self.client.get(url).status_code, (403, 404))
        self.assertEqual(self.client.get(state_url).status_code, 404)
        self.client.force_login(self.user)
        self.grant.enabled = False
        self.grant.save(update_fields=['enabled'])
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.get(state_url).status_code, 404)
        with override_settings(REGULAY_ARTIFACT_PREVIEW=False):
            self.assertEqual(self.client.get(url).status_code, 404)


class IncrementalAgentUITests(OfflineBrowser, ChatFixture):
    def agent(self, checks):
        return self.browse(AGENT + checks, self.client.get('/chat/'))

    def test_initial_hydration_does_not_count_as_unread_but_new_delta_does(self):
        self.agent(r'''
const followed=[];
window.regulayChat.follow=key=>followed.push(key);
const run=runAt('unread-hydration',{status:'active',professional:true});
const {watcher}=await mount(run,snapshot(run,{text_segments:[{message_id:'call',inference_id:'call',offset:0,text:'Existing.'}]}));
await tick(20);
assert.ok(followed.every(key=>!key),'Initial snapshot was counted as a new update');
sources.at(-1).emit('progress',{id:2,kind:'text.delta',data:{message_id:'call',inference_id:'call',offset:9,text:' Updated.'}});
await tick(20);
assert.equal(followed.at(-1),run.id);
watcher.close();
''')

    def test_utf8_deltas_keep_prior_dom_stable_and_reconcile_final_once(self):
        self.agent(r'''
const run = runAt('incremental', {status:'active', professional:true});
const initial = snapshot(run, {events:[{id:1,kind:'inference.started',data:{call_id:'call',mode:'streamed'}}]});
const {host,watcher} = await mount(run,initial);
const prior = document.createElement('article'); prior.textContent='200 historical messages remain untouched';
$('#chatContainer').prepend(prior);
const step = $('.rg-step',host), activity = $('.rg-activity',host);
const source = sources.at(-1), requests = net.requests.length;
source.emit('progress',{id:2,kind:'text.delta',data:{inference_id:'call',message_id:'inference:call',offset:0,text:'Hola 😀.\n\n'}});
await tick(20);
const first = $('.rg-stream-segment .rg-md p',host);
const width = new TextEncoder().encode('Hola 😀.\n\n').length;
source.emit('progress',{id:3,kind:'text.delta',data:{inference_id:'call',message_id:'inference:call',offset:width,text:'Segundo bloque.'}});
await tick(20);
assert.ok($('.rg-step',host)===step,'A text delta rebuilt activity');
assert.ok($('.rg-activity',host)===activity,'A text delta rebuilt the activity host');
assert.ok($('#chatContainer').firstElementChild===prior,'A text delta rebuilt old messages');
assert.ok($('.rg-stream-segment .rg-md p',host)===first,'A closed paragraph was rebuilt');
assert.equal(net.requests.length,requests);
source.emit('progress',{id:3,kind:'text.delta',data:{inference_id:'call',message_id:'inference:call',offset:width,text:'Segundo bloque.'}});
await tick(20);
assert.equal(text($('.rg-stream-segment .rg-md',host)).split('Segundo bloque.').length,2);
watcher.apply(snapshot({...run,status:'completed'}, {high_watermark:4,events:[{id:4,kind:'inference.finished',data:{message_id:'inference:call',tool_count:0,status:'completed'}}],result:{assistant_message:{content:'Hola 😀.\n\nSegundo bloque.'}}}));
await tick(20);
assert.equal($$('.rg-agent-answer .rg-md',host).length,1);
assert.ok($('.rg-stream-segment .rg-md p',host)===first,'Final reconciliation rebuilt a stable paragraph');
watcher.revoke(); await tick(20);
assert.equal($$('.rg-stream-segment',host).length,0);
assert.equal(text($('.rg-agent-answer',host)),'');
assert.equal(watcher.segments.size,0);
''')

    def test_snapshot_cursor_gap_recovers_by_get_only_and_tools_text_moves_to_activity(self):
        self.agent(r'''
const run = runAt('recover-stream',{status:'active',professional:true});
const {host,watcher} = await mount(run,snapshot(run));
const saved = snapshot(run,{high_watermark:7,text_segments:[{message_id:'inference:call',inference_id:'call',offset:12,text:'Recuperado 😀'}],events:[{id:7,kind:'inference.finished',data:{message_id:'inference:call',tool_count:1,status:'completed'}}]});
net.on('GET '+run.status_url,()=>net.json(saved));
sources.at(-1).emit('progress',{id:5,kind:'text.delta',data:{message_id:'inference:call',inference_id:'call',offset:8,text:'gap'}});
await flush(); await tick(20);
assert.equal(watcher.cursor,7);
assert.match(text($('.rg-public-activity',host)),/Recuperado/);
assert.equal($$('.rg-agent-answer .rg-md',host).length,0);
assert.ok(net.requests.every(call=>call.method==='GET'));
sources.at(-1).emit('progress',{id:8,kind:'text.snapshot',data:{snapshot_required:true,expired:true}});
await flush();
assert.ok(net.requests.every(call=>call.method==='GET'));
''')
