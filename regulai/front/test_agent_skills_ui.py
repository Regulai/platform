"""Feature availability in the real templates/scripts, without provider calls."""
import json
import uuid
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from front.models import AgentAccessGrant, AgentSkillInstallation
from front.offline_browser import OfflineBrowser
from front.test_agent_skills_install import SkillFixture


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_SKILLS_CATALOG=True, REGULAY_SKILLS_RUNTIME=True)
class SkillAvailabilityUITests(OfflineBrowser, SkillFixture, TestCase):
    def setUp(self):
        super().setUp()
        result=self.install()
        self.installation=AgentSkillInstallation.objects.get(pk=result['installation_id'])

    def script(self, checks, path, **options):
        with patch('front.offline_browser.SCRIPTS', ('js/skills.js',)):
            return self.browse(checks, self.client.get(path), **options)

    def test_menu_and_html_navigation_do_not_offer_a_library_without_access(self):
        self.assertContains(self.client.get('/chat/'), 'title="Skills"')
        AgentAccessGrant.objects.filter(user=self.user).update(enabled=False)
        self.assertNotContains(self.client.get('/chat/'), 'title="Skills"')
        page=self.client.get('/skills/', HTTP_ACCEPT='text/html')
        self.assertContains(page, 'Consulta al administrador', status_code=403)
        self.assertIn('text/html', page['Content-Type'])
        api=self.client.get('/skills/?format=json', HTTP_ACCEPT='text/html')
        self.assertEqual(api.status_code,403)
        self.assertEqual(api.json()['code'],'agent_access_denied')
        other=User.objects.create_user('skills-no-profile')
        self.client.force_login(other)
        self.assertContains(self.client.get('/skills/', HTTP_ACCEPT='text/html'), 'Volver al chat', status_code=403)
        self.assertFalse(self.requests)

    @override_settings(REGULAY_SKILLS_RUNTIME=False)
    def test_runtime_off_preserves_packages_and_the_three_send_guards(self):
        data=self.client.get('/skills/?format=json').json()
        self.assertFalse(data['runtime_enabled'])
        self.assertTrue(data['installations'][0]['enabled'])
        for path in ('/skills/catalog/frontend-design/',f'/skills/installations/{self.installation.pk}/'):
            self.assertFalse(self.client.get(path+'?format=json').json()['runtime_enabled'])
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(url=url):
                response=self.client.post(url,{'mode':'agent','prompt':'Texto sintético', 'content':'Texto sintético',
                    'request_id':str(uuid.uuid4()),'skills':json.dumps({'selected':[str(self.installation.pk)],'auto':False})})
                self.assertEqual(response.status_code,409,response.content)
                self.assertIn('skills_runtime_unavailable',response.content.decode())
        self.installation.refresh_from_db()
        self.assertTrue(self.installation.enabled)
        self.assertIsNotNone(self.installation.current_revision_id)
        self.assertFalse(self.requests)

    @override_settings(REGULAY_SKILLS_RUNTIME=False)
    def test_runtime_off_library_keeps_management_but_disables_use(self):
        self.script(r'''
await click($('#skillsInstalled'));
const named=name=>$$('button').find(b=>b.textContent===name);
assert.equal(named('Usar en chat').disabled,true);
assert.equal(named('Deshabilitar').disabled,false);
assert.equal(named('Desinstalar').disabled,false);
assert.equal($('#skillImportOpen').disabled,false);
assert.equal($('#skillRuntimeStatus').hidden,false);
await click(named('Usar en chat'));
assert.equal(location.pathname,'/skills/');
assert.equal(net.requests.length,0);
''','/skills/')

    @override_settings(REGULAY_SKILLS_RUNTIME=False)
    def test_runtime_off_detail_can_manage_or_install_without_claiming_use(self):
        self.script(r'''
assert.equal($('#skillInstall').textContent,'Usar en chat');
assert.equal($('#skillInstall').disabled,true);
assert.ok($$('button').some(b=>b.textContent==='Actualizar paquete'&&!b.disabled));
assert.ok($$('button').some(b=>b.textContent==='Deshabilitar'&&!b.disabled));
assert.ok($('#skillRuntimeStatus'));
''',f'/skills/installations/{self.installation.pk}/')
        self.script(r'''
assert.equal($('#skillInstall').textContent,'Instalar');
assert.equal($('#skillInstall').disabled,false);
''','/skills/catalog/frontend-design/')

    @override_settings(REGULAY_SKILLS_RUNTIME=False)
    def test_runtime_off_composer_omits_selection_without_consuming_saved_intent(self):
        data=self.client.get('/skills/?format=json').json()
        self.script(r'''
await flush();
assert.equal($('#skillPickerButton').disabled,true);
assert.equal($('#skillAuto').disabled,true);
assert.equal(window.regulaySkills.capture(),undefined);
sessionStorage.setItem('regulai.skills.pending','keep-until-enabled');
await window.regulaySkills.restore();window.regulaySkills.accepted();
assert.equal(sessionStorage.getItem('regulai.skills.pending'),'keep-until-enabled');
$('#skillAuto').dispatchEvent(new Event('change'));
await flush();
assert.ok(net.requests.every(r=>r.method==='GET'));
''','/chat/',routes=[{'method':'GET','url':'/skills/?format=json','json':data}])

    def test_runtime_on_can_select_for_one_message(self):
        data=self.client.get('/skills/?format=json').json()
        self.script(r'''
await flush();
assert.equal($('#skillPickerButton').disabled,false);
assert.equal($('#skillAuto').disabled,false);
await click($('#skillPickerButton'));await flush();
await click($('#skillOptions').children[0]);
assert.equal(window.regulaySkills.capture().selected.length,1);
assert.equal(window.regulaySkills.capture().auto,true);
window.regulaySkills.accepted();
assert.equal(window.regulaySkills.capture().selected.length,0);
''','/chat/',routes=[{'method':'GET','url':'/skills/?format=json','json':data}])
