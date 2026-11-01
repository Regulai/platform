"""Skill presentation and selection boundaries, without live provider calls."""
import json
import uuid
from unittest.mock import patch

from django.test import TestCase, override_settings

from front.models import AgentSkillInstallation
from front.agents import skills, skill_installation
from front.offline_browser import OfflineBrowser
from front.test_agent_skills_install import SkillFixture, bundle


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True,
    REGULAY_SKILLS_RUNTIME=True, REGULAY_SKILL_RUNTIME_CAPABILITIES={'node': '24.21.0'})
class SkillUXTests(OfflineBrowser, SkillFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.tools.append('execute')
        self.agent.save(update_fields=['tools'])
        result = skill_installation.install(self.user, uuid.uuid4(),
            {'source': 'catalog', 'candidate': 'design-taste-frontend'})
        self.assertEqual(result['state'], 'installed', result)
        self.row = AgentSkillInstallation.objects.select_related('current_revision').get(
            pk=result['installation_id'])

    def script(self, checks, **options):
        with patch('front.offline_browser.SCRIPTS', ('js/skills.js',)):
            return self.browse(checks, self.client.get('/chat/'), **options)

    def test_curated_presentation_preserves_canonical_provider_metadata(self):
        view = skills.installation_view(self.row, self.agent)
        self.assertTrue(view['catalog_revision'])
        self.assertEqual(view['display_name'], 'Taste v2 · Frontend')
        self.assertLess(len(view['summary']), 160)
        self.assertEqual(view['description'], self.row.current_revision.metadata['description'])
        self.assertNotEqual(view['summary'], view['description'])
        self.assertTrue(view['examples'])
        frozen = skills.freeze_selection(self.user, self.agent,
            {'selected': [str(self.row.pk)], 'auto': False})
        self.assertEqual(frozen['catalog'][0]['metadata'], self.row.current_revision.metadata)
        installed = self.client.get(f'/skills/installations/{self.row.pk}/?format=json').json()
        self.assertEqual(installed['examples'], view['examples'])
        self.assertEqual(installed['display_name'], view['display_name'])
        self.assertFalse(installed['is_catalog_detail'])
        self.assertFalse(self.requests)

    def test_zip_update_cannot_inherit_catalogue_presentation_or_availability(self):
        result = skill_installation.install(self.user, uuid.uuid4(), {'source': 'zip'},
            raw=bundle(name='design-taste-frontend', extra={
                'design-taste-frontend/scripts/custom.mjs': b'console.log("synthetic")'}),
            installation_id=self.row.pk)
        self.assertEqual(result['state'], 'installed', result)
        self.row.refresh_from_db()
        view = skills.installation_view(self.row, self.agent)
        self.assertEqual(view['candidate'], 'design-taste-frontend')
        self.assertFalse(view['catalog_revision'])
        self.assertEqual(view['display_name'], self.row.alias)
        self.assertEqual(view['summary'], 'Synthetic test instructions.')
        self.assertEqual(view['examples'], [])
        self.assertEqual(view['publisher'], 'Paquete importado')
        self.assertEqual(skills.revision_display_name(self.row.current_revision, self.row.alias), self.row.alias)
        page = self.client.get('/skills/catalog/design-taste-frontend/?format=json').json()
        self.assertTrue(page['is_catalog_detail'])
        self.assertEqual(page['availability'], view['availability'])
        self.assertFalse(page['availability']['available'])
        self.assertFalse(page['installation']['catalog_revision'])
        self.assertContains(self.client.get('/skills/catalog/design-taste-frontend/'),
                            'Tu instalación usa otra revisión')
        skill_installation.change(self.user, self.row.pk, 'rollback')
        self.row.refresh_from_db()
        self.assertTrue(skills.installation_view(self.row, self.agent)['catalog_revision'])
        self.assertNotContains(self.client.get('/skills/catalog/design-taste-frontend/'),
                               'Tu instalación usa otra revisión')
        self.assertFalse(self.requests)

    def test_provenance_gate_requires_origin_commit_and_digest(self):
        revision = self.row.current_revision
        for field, replacement in [('origin', 'user_package'),
                                    ('resolved_commit', 'f' * 40),
                                    ('folder_sha256', '0' * 64)]:
            with self.subTest(field=field):
                previous = getattr(revision, field)
                setattr(revision, field, replacement)
                self.assertFalse(skills.installation_view(self.row, self.agent)['catalog_revision'])
                self.assertEqual(skills.revision_display_name(revision, self.row.alias), self.row.alias)
                setattr(revision, field, previous)
        self.assertTrue(skills.installation_view(self.row, self.agent)['catalog_revision'])

    def test_removed_or_disabled_skill_is_not_sent_as_an_invisible_selection(self):
        data = self.client.get('/skills/?format=json').json()
        self.script(r'''
await flush();
await click($('#skillPickerButton')); await flush();
await click($('#skillOptions').children[0]);
assert.equal(window.regulaySkills.capture().selected.length,1);
net.on('GET /skills/?format=json',()=>net.json({installations:[],catalog:[],runtime_enabled:true}));
await window.regulaySkills.restore();
assert.deepEqual(window.regulaySkills.capture().selected,[]);
assert.equal($('#skillChips').children.length,0);
assert.match($('#skillSelectionStatus').textContent,/quitado/);
''', routes=[{'method': 'GET', 'url': '/skills/?format=json', 'json': data}])

    def test_automatic_default_is_quiet_and_does_not_fetch_manual_catalogue(self):
        self.script(r'''
await flush();
assert.deepEqual(window.regulaySkills.capture(),{selected:[],auto:true});
assert.equal(net.find('GET','/skills/?format=json').length,0);
assert.equal($('#skillPicker').hidden,true);
assert.equal($('#skillChips').children.length,0);
assert.equal($('#skillSelectionStatus').textContent,'');
assert.equal($('#skillPickerButton').textContent.trim(),'/');
assert.equal($('#skillSelectionCount'),null);
assert.equal($('#skillAuto').closest('details').hasAttribute('open'),false);
''')

    def test_slash_escape_preserves_literal_and_choice_returns_to_empty_draft(self):
        data = self.client.get('/skills/?format=json').json()
        self.script(r'''
const prompt=$('#prompt'); $('#chatApp').dataset.mode='agent';
prompt.value='/'; prompt.selectionStart=prompt.selectionEnd=1;
prompt.dispatchEvent(new Event('input')); await flush();
assert.equal($('#skillPicker').hidden,false);
assert.equal(net.find('GET','/skills/?format=json').length,1);
assert.equal(document.activeElement,$('#skillPickerSearch'));
$('#skillPickerSearch').dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
assert.equal($('#skillPicker').hidden,true);
assert.equal(prompt.value,'/'); assert.equal(document.activeElement,prompt);
prompt.dispatchEvent(new Event('input')); await flush();
await click($('#skillOptions').children[0]);
assert.equal(prompt.value,''); assert.equal(document.activeElement,prompt);
assert.equal($('#skillPicker').hidden,true);
assert.deepEqual(window.regulaySkills.capture().selected,[ROW_ID]);
assert.equal($('.rg-skill-activation'),null);
'''.replace('ROW_ID', json.dumps(str(self.row.pk))),
            routes=[{'method': 'GET', 'url': '/skills/?format=json', 'json': data}])

    def test_literal_paths_composition_and_normal_chat_do_not_open_slash_picker(self):
        self.script(r'''
const prompt=$('#prompt'); $('#chatApp').dataset.mode='agent';
for(const value of ['/tmp/project','usa / para dividir']){
  prompt.value=value; prompt.selectionStart=prompt.selectionEnd=value.length;
  prompt.dispatchEvent(new Event('input')); await flush();
  assert.equal($('#skillPicker').hidden,true);
}
prompt.value='/'; prompt.selectionStart=prompt.selectionEnd=1;
const composing=new Event('input'); composing.isComposing=true;
prompt.dispatchEvent(composing); await flush();
assert.equal($('#skillPicker').hidden,true);
$('#chatApp').dataset.mode='chat';
$$('input[name="conversation_mode"]').forEach(radio=>{radio.checked=radio.value==='chat';});
prompt.dispatchEvent(new Event('input')); await flush();
assert.equal($('#skillPicker').hidden,true);
assert.equal(net.find('GET','/skills/?format=json').length,0);
assert.equal(prompt.value,'/');
''')

    def test_malformed_success_does_not_erase_selection_or_break_the_picker(self):
        data = self.client.get('/skills/?format=json').json()
        self.script(r'''
await flush(); await click($('#skillPickerButton')); await flush();
await click($('#skillOptions').children[0]);
const selected=window.regulaySkills.capture().selected;
net.on('GET /skills/?format=json',()=>net.json({runtime_enabled:true}));
await window.regulaySkills.restore();
assert.deepEqual(window.regulaySkills.capture().selected,selected);
assert.equal($('#skillChips').children.length,1);
assert.equal($('#skillPickerRetry').hidden,false);
$('#skillPickerSearch').value='Taste';
$('#skillPickerSearch').dispatchEvent(new Event('input'));
assert.equal($('#skillOptions').children.length,1);
''', routes=[{'method': 'GET', 'url': '/skills/?format=json', 'json': data}])

    def test_disabled_selection_is_removed_after_successful_refresh(self):
        data = self.client.get('/skills/?format=json').json()
        changed = json.loads(json.dumps(data))
        changed['installations'][0]['enabled'] = False
        self.script(r'''
await flush(); await click($('#skillPickerButton')); await flush();
await click($('#skillOptions').children[0]);
net.on('GET /skills/?format=json',()=>net.json(CHANGED));
await window.regulaySkills.restore();
assert.deepEqual(window.regulaySkills.capture().selected,[]);
assert.equal($('#skillOptions').children[0].getAttribute('aria-disabled'),'true');
assert.match($('#skillOptions').children[0].textContent,/Deshabilitada/);
'''.replace('CHANGED', json.dumps(changed)),
            routes=[{'method': 'GET', 'url': '/skills/?format=json', 'json': data}])

    def test_failed_refresh_preserves_visible_selection_until_a_valid_catalogue(self):
        data = self.client.get('/skills/?format=json').json()
        self.script(r'''
await flush(); await click($('#skillPickerButton')); await flush();
await click($('#skillOptions').children[0]);
const selected=window.regulaySkills.capture().selected;
net.on('GET /skills/?format=json',()=>net.json({code:'temporary_error'},{status:503}));
await window.regulaySkills.restore();
assert.deepEqual(window.regulaySkills.capture().selected,selected);
assert.equal($('#skillChips').children.length,1);
''', routes=[{'method': 'GET', 'url': '/skills/?format=json', 'json': data}])
