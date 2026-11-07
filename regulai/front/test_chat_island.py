"""The React chat island: one frontend per page, the built manifest and a public
bootstrap that is an explicit allowlist (tasks 79 and 81)."""
import json
import re
import uuid
from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse

from front import chat_assets
from front.models import Conversation, Message, Prompt
from front.test_chat_flow import ChatFixture

BOOT = re.compile(r'<script id="regulai-chat-bootstrap" type="application/json">(.*?)</script>', re.S)


def bootstrap(page):
    return json.loads(BOOT.search(page.content.decode())[1])


class ChatIslandTests(ChatFixture):
    def setUp(self):
        super().setUp()
        chat_assets._cache.clear()
        self.addCleanup(chat_assets._cache.clear)

    def conversation(self, mode='chat'):
        return Conversation.objects.create(user=self.user, title='Conversación sintética', mode=mode)

    def prompt(self, conversation, text, status, file_name='', **decision):
        message = Message.objects.create(conversation=conversation, role='user', content=text, file_name=file_name)
        return Prompt.objects.create(user=self.user, company=self.company, conversation=conversation, user_message=message,
                                     content=text, request_id=uuid.uuid4(), status=status, file_name=file_name,
                                     decision={'schema_version': 1, 'calls': [], **decision})

    def test_the_page_links_the_built_manifest_and_only_local_resources(self):
        page = self.client.get('/chat/')
        self.assertTemplateUsed(page, 'chat/app.html')
        self.assertTemplateNotUsed(page, 'chat/chat.html')
        html = page.content.decode()
        files = chat_assets.assets()
        self.assertTrue(files['script'].startswith('/static/chat-app/assets/'))
        self.assertIn(f'<script type="module" src="{files["script"]}"></script>', html)
        for href in files['css']:
            self.assertIn(f'<link rel="stylesheet" href="{href}">', html)
        for href in files['preload']:
            self.assertIn(f'<link rel="modulepreload" href="{href}">', html)
        self.assertEqual(html.count('<script type="module"'), 1)
        self.assertEqual(html.count('id="regulai-chat-root"'), 1)
        for url in re.findall(r'(?:src|href)="([^"]+)"', html):
            self.assertFalse(url.startswith(('http:', 'https:', '//')), url)
        # One frontend per page: none of the legacy chat scripts or styles.
        for legacy in ('js/chat.js', 'js/agent-chat.js', 'js/skills.js', 'css/chat.css', 'jquery', 'bootstrap.bundle'):
            self.assertNotIn(legacy, html)

    def test_every_chunk_of_the_build_exists_including_on_demand_ones(self):
        manifest = chat_assets._manifest()
        entry = manifest[chat_assets.ENTRY]
        self.assertTrue(entry['isEntry'])
        lazy = [manifest[key]['file'] for key in entry.get('dynamicImports', [])]
        self.assertTrue(lazy, 'viewers and pickers load on demand')
        for chunk in manifest.values():
            for name in [chunk['file'], *chunk.get('css', [])]:
                self.assertTrue(chat_assets.finders.find(f'chat-app/{name}'), name)

    def test_a_missing_or_incomplete_build_serves_the_legacy_chat(self):
        real = chat_assets.finders.find
        with patch.object(chat_assets.finders, 'find', side_effect=lambda path, *a, **k: None if path.endswith('manifest.json') else real(path, *a, **k)):
            with self.assertLogs('front.chat_assets', 'ERROR'):
                page = self.client.get('/chat/')
        self.assertTemplateUsed(page, 'chat/chat.html')
        missing = next(iter(chat_assets._manifest()[chat_assets.ENTRY]['dynamicImports']))
        lazy_file = chat_assets._manifest()[missing]['file']
        chat_assets._cache.clear()
        with patch.object(chat_assets.finders, 'find', side_effect=lambda path, *a, **k: None if path.endswith(lazy_file) else real(path, *a, **k)):
            with self.assertLogs('front.chat_assets', 'ERROR'):
                page = self.client.get('/chat/')
        self.assertTemplateUsed(page, 'chat/chat.html')

    @override_settings(REGULAI_CHAT_FRONTEND='legacy')
    def test_the_rollback_setting_serves_only_the_legacy_chat(self):
        page = self.client.get('/chat/')
        self.assertTemplateUsed(page, 'chat/chat.html')
        self.assertNotContains(page, 'chat-app/')
        self.assertNotContains(page, 'regulai-chat-bootstrap')

    def test_other_pages_never_load_the_island(self):
        # The skills library answers with its own "unavailable" page without agent access.
        for name, status in (('front:home', 200), ('front:skills_library', 403), ('front:profile', 200)):
            with self.subTest(page=name):
                page = self.client.get(reverse(name), follow=True, HTTP_ACCEPT='text/html')
                self.assertEqual(page.status_code, status)
                self.assertTrue(page['Content-Type'].startswith('text/html'))
                self.assertNotContains(page, 'chat-app/', status_code=status)
                self.assertNotContains(page, 'regulai-chat-bootstrap', status_code=status)

    def test_bootstrap_is_an_explicit_allowlist_without_secrets(self):
        conversation = self.conversation()
        self.prompt(conversation, 'Pregunta', 'completed')
        page = self.client.get(f'/chat/{conversation.pk}/')
        boot = bootstrap(page)
        self.assertEqual(set(boot), {'version', 'csrf_token', 'urls', 'user', 'navigation', 'alerts', 'demo', 'setup',
                                     'conversation', 'threads', 'composer', 'models', 'turns', 'runs'})
        self.assertEqual(set(boot['user']), {'name', 'initial', 'company', 'avatar_url'})
        self.assertEqual(set(boot['conversation']), {'id', 'title', 'mode', 'auto_skills'})
        self.assertEqual(set(boot['composer']), {'modes', 'mode', 'professional', 'agent_available', 'accept', 'max_bytes',
                                                 'placeholders', 'suggestions', 'inference_profiles', 'drive', 'skills'})
        self.assertEqual(set(boot['models']), {'engines', 'models', 'engine_id', 'model_id', 'automatic', 'difficulty', 'provider_limits'})
        self.assertEqual(set(boot['turns'][0]), {'request_id', 'status', 'run_id', 'legacy', 'live', 'user', 'notice', 'answer',
                                                 'assistant_file', 'receipt_url', 'evidence_url'})
        for engine in boot['models']['engines']:
            self.assertEqual(set(engine), {'id', 'name', 'detail'})
        for url in boot['urls'].values():
            self.assertTrue(url.startswith('/'), url)
        self.assertNotContains(page, self.credential.api_key)
        self.assertNotIn('password', json.dumps(boot))

    def test_the_consent_token_is_offered_only_when_nothing_must_be_attached_again(self):
        conversation = self.conversation()
        policy = {'rules': [{'name': 'Datos de cliente'}]}
        self.prompt(conversation, 'Sin archivo', 'pending_consent', consent_token='token-texto', policy=policy)
        self.prompt(conversation, 'Con archivo', 'pending_consent', file_name='acta.pdf', consent_token='token-archivo', policy=policy)
        notices = [turn['notice'] for turn in bootstrap(self.client.get(f'/chat/{conversation.pk}/'))['turns']]
        self.assertEqual((notices[0]['kind'], notices[0]['token'], notices[0]['file_name']), ('consent', 'token-texto', None))
        self.assertEqual((notices[1]['token'], notices[1]['file_name']), (None, 'acta.pdf'))
        self.assertNotContains(self.client.get(f'/chat/{conversation.pk}/'), 'token-archivo')

    def test_a_block_without_a_matching_rule_carries_the_policy_reason(self):
        conversation = self.conversation()
        self.prompt(conversation, 'Sin regla', 'blocked', error_type='destination_not_allowed', policy={'status': 'block', 'rules': []})
        self.prompt(conversation, 'Con regla', 'blocked', error_type='local_rule_block', policy={'status': 'block', 'rules': [{'name': 'Claves'}]})
        first, second = (turn['notice'] for turn in bootstrap(self.client.get(f'/chat/{conversation.pk}/'))['turns'])
        self.assertEqual(first['detail'], 'La política no autoriza enviar este contenido al destino seleccionado.')
        self.assertEqual(second['rules'], ['Claves'])
        self.assertNotIn('detail', second)

    def test_navigation_matches_the_server_rendered_menu_for_each_role(self):
        def legacy_links():
            with override_settings(REGULAI_CHAT_FRONTEND='legacy'):
                html = self.client.get('/chat/').content.decode()
            menu = re.search(r'<ul class="rg-rail-nav">(.*?)</ul>', html, re.S)[1]
            return re.findall(r'href="([^"]+)"', menu)

        for role in ('member', 'staff', 'superuser'):
            with self.subTest(role=role):
                self.user.is_staff = role in ('staff', 'superuser')
                self.user.is_superuser = role == 'superuser'
                self.user.save()
                boot = bootstrap(self.client.get('/chat/'))
                links = [item['href'] for group in boot['navigation'] for item in group['items']]
                self.assertEqual(links, legacy_links())
