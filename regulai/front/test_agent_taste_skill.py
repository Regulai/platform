"""Taste v2 installation and complete context at the simulated HTTP boundary."""
import json
import uuid
from decimal import Decimal

from django.test import TestCase, override_settings

from front.models import AgentAccessGrant, AgentSkillInstallation, AgentInput, ConversationAlias
from front.test_agent_inference import AgentFixture
from front.offline_browser import OfflineBrowser
from front.test_agent_frontend import AGENT
from front.agents import skill_installation
from front.agents.service import _context
from front.agents.skills import curated_bundle, freeze_selection
from front.agents.skill_bundles import SkillError, revision_files, validate_bundle


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True,
                   REGULAY_SKILLS_RUNTIME=True, REGULAY_AGENT_TEXT_STREAM=False,
                   REGULAY_SKILL_RUNTIME_CAPABILITIES={})
class TasteSkillTests(OfflineBrowser, AgentFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.professional = True
        self.agent.tools = ['read_file', 'execute', 'write_file', 'publish_artifact']
        self.agent.save()
        AgentAccessGrant.objects.create(company=self.company, user=self.user,
                                       profile=self.agent, enabled=True)
        self.client.force_login(self.user)

    def install(self):
        response = self.client.post('/skills/installations/', data=json.dumps({
            'request_id': str(uuid.uuid4()), 'source': 'catalog',
            'candidate': 'design-taste-frontend'}), content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        value = response.json()
        self.assertEqual(value['state'], 'installed', value)
        return AgentSkillInstallation.objects.select_related('current_revision').get(
            pk=value['installation_id'])

    def test_install_preserves_complete_package_and_waits_for_verified_runtime(self):
        row = self.install()
        self.assertFalse(row.enabled)
        files = revision_files(row.current_revision)
        expected = validate_bundle(curated_bundle('design-taste-frontend')[0])
        self.assertEqual(files, expected['files'])
        self.assertEqual(len(files), 31)
        self.assertIn('scripts/draw.mjs', files)
        self.assertIn('scripts/inspect.mjs', files)
        self.assertIn('library/directions.json', files)
        self.assertIn('MIT License', files['LICENSE'].decode())
        with self.assertRaisesRegex(SkillError, 'skill_dependency_unavailable'):
            skill_installation.change(self.user, row.pk, 'enabled', enabled=True)
        self.assertFalse(self.requests)
        self.assertEqual(self.agent.tools, ['read_file', 'execute', 'write_file', 'publish_artifact'])
        self.assertEqual(AgentAccessGrant.objects.filter(user=self.user).count(), 1)

    @override_settings(REGULAY_SKILL_RUNTIME_CAPABILITIES={'node': '24.21.0'})
    def test_explicit_first_http_request_has_complete_body_and_local_constraints(self):
        row = self.install()
        self.assertTrue(row.enabled)
        self.execution.job = {'skills': freeze_selection(self.user, self.agent,
            {'selected': [str(row.pk)], 'auto': True})}
        self.execution.save()
        self.execution.authorization_digest = _context(self.prompt, self.agent.pk)[-1]
        self.execution.save()
        request = self.request(messages=[{'role': 'user', 'content': 'Crea una landing de Madrid.'}])
        result = self.infer(request)
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(self.requests), 1)
        messages = self.requests[0]['messages']
        content = '\n'.join(str(message.get('content', '')) for message in messages)
        self.assertEqual(content.count('# tasteskill v2'), 1)
        # Inspect the actual protected HTTP body, resolving only this synthetic
        # conversation's local aliases for the full-body integrity assertion.
        restored = content
        for alias in ConversationAlias.objects.filter(company=self.company,
                                                      conversation=self.conversation):
            restored = restored.replace(alias.token, alias.original)
        canonical = revision_files(row.current_revision)['SKILL.md'].decode('utf-8')
        self.assertEqual(restored.replace('\r\n', '\n').count(canonical.replace('\r\n', '\n')), 1)
        self.assertIn('Adaptación de regulAI para Taste v2', content)
        self.assertIn('No añadas paquetes ni hagas solicitudes de red desde scripts', content)
        self.assertEqual(AgentInput.objects.filter(execution=self.execution,
                                                  kind='skill_activation').count(), 1)
        # Render the real event emitted after the mocked provider HTTP gate.
        # A confirmed activation identifies the skill without claiming quality.
        from front.agents.views import _events
        events = _events(self.execution.events.filter(kind='skill.activated'))
        self.assertEqual(len(events), 1)
        self.browse(AGENT + r'''
const run=runAt('taste-http-receipt');
const {host}=await mount(run,snapshot(run,{events:EVENTS}));
assert.match(text(host),/Taste v2/);
assert.match(text(host),/Taste v2 · Frontend · activada/);
'''.replace('EVENTS', json.dumps(events)), self.client.get('/chat/'))

    @override_settings(REGULAY_SKILL_RUNTIME_CAPABILITIES={'node': '24.21.0'})
    def test_automatic_context_activates_taste_from_the_normal_provider_tool_call(self):
        from front.agents.data_views import authorize_tool, tool_result
        from front.agents.general_tools import begin
        from front.agents.views import _events
        row = self.install()
        self.execution.job = {'skills': freeze_selection(self.user, self.agent,
            {'selected': [], 'auto': True})}
        self.execution.save()
        self.execution.authorization_digest = _context(self.prompt, self.agent.pk)[-1]
        self.execution.save()
        call = {'id': 'context-taste', 'name': 'read_file',
                'args': {'file_path': '/skills/design-taste-frontend/SKILL.md'}}
        self.reply_calls = [call]
        first_request = self.request(tools=['read_file'], messages=[
            {'role': 'user', 'content': 'Crea una landing de Madrid con dirección visual propia.'}])
        first = self.infer(first_request)
        self.assertEqual(first['status'], 'completed', first)
        self.assertEqual(first['tool_calls'], [call])
        self.assertEqual(self.infer(first_request), first)
        self.assertEqual(len(self.requests), 1)
        self.assertIn('/skills/design-taste-frontend/SKILL.md', json.dumps(self.requests[0]))
        self.assertNotIn('# tasteskill v2', json.dumps(self.requests[0]))
        self.assertFalse(self.execution.events.filter(kind='skill.activated').exists())
        run, context, typed = authorize_tool(self.token, self.execution.attempt, call)
        begin(run, context, typed)
        view = tool_result(self.token, self.execution.attempt, {'call': call, 'raw': 'FORGED_BODY'})
        self.assertTrue(view['complete'])
        self.assertEqual(tool_result(self.token, self.execution.attempt,
            {'call': call, 'raw': 'FORGED_BODY'}), view)
        events = _events(self.execution.events.filter(kind='skill.activated'))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['data']['reason'], 'instructions_read')
        self.assertEqual(events[0]['data']['display_name'], 'Taste v2 · Frontend')
        self.assertEqual(events[0]['data']['revision_id'], str(row.current_revision_id))
        self.browse(AGENT + r'''
const run=runAt('taste-auto-receipt',{status:'active'});
const {host,watcher}=await mount(run,snapshot(run));
assert.equal($$('.rg-skill-activation',host).length,0);
const source=sources.at(-1), event=EVENTS[0];
source.emit('progress',event); await flush();
assert.equal($$('.rg-skill-activation',host).length,1);
assert.match(text($('.rg-skill-activation',host)),/Taste v2 · Frontend · activada/);
source.emit('progress',event);
source.emit('progress',{...event,id:event.id+1,data:{...event.data,reason:'context_restored'}});
await flush();
assert.equal($$('.rg-skill-activation',host).length,1);
net.on('GET '+run.status_url,()=>net.json({},{status:503}));
await watcher.refresh();
assert.equal($$('.rg-skill-activation',host).length,0);
net.on('GET '+run.status_url,()=>net.json(snapshot(run,{events:[event]})));
await watcher.refresh();
assert.equal($$('.rg-skill-activation',host).length,1);
await watcher.refresh();
assert.equal($$('.rg-skill-activation',host).length,1);
'''.replace('EVENTS', json.dumps(events)), self.client.get('/chat/'))
        self.reply_calls = []
        second_request = self.request(messages=[
            {'role': 'assistant', 'content': '', 'tool_calls': [call]},
            {'role': 'tool', 'name': 'read_file', 'tool_call_id': call['id'],
             'content': json.dumps(view, sort_keys=True, ensure_ascii=False)}])
        second = self.infer(second_request)
        self.assertEqual(second['status'], 'completed', second)
        self.assertEqual(self.infer(second_request), second)
        self.assertEqual(len(self.requests), 2)  # Normal tool roundtrip, no classifier call.
        content = '\n'.join(str(message.get('content', '')) for message in self.requests[-1]['messages'])
        for alias in ConversationAlias.objects.filter(company=self.company, conversation=self.conversation):
            content = content.replace(alias.token, alias.original)
        canonical = revision_files(row.current_revision)['SKILL.md'].decode('utf-8')
        self.assertEqual(content.replace('\r\n', '\n').count(canonical.replace('\r\n', '\n')), 1)
        self.assertNotIn('FORGED_BODY', content)
        self.prompt.refresh_from_db()
        self.assertEqual(self.prompt.decision['total']['attempts'], 2)
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00028'))
