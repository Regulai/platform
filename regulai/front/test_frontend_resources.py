"""Offline resource and browser behavior regressions."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import tempfile
from unittest.mock import patch
import io

from django.test import SimpleTestCase
from django.template.loader import render_to_string
from django.urls import reverse
from front.test_chat_flow import ChatFixture

ROOT = Path(__file__).resolve().parents[2]
NAVIGATION = {
    'https://platform.deepseek.com/api_keys',
    'https://vercel.com/docs/ai-gateway/authentication-and-byok/api-keys',
    'https://aistudio.google.com/api-keys',
    'https://console.mistral.ai/api-keys',
    'https://platform.openai.com/api-keys',
    'https://console.anthropic.com/settings/keys',
    'https://platform.deepseek.com/api_keys',
    'https://yara.readthedocs.io/en/stable/writingrules.html',
}


class ResourceTests(SimpleTestCase):
    def test_git_checkout_preserves_every_pinned_asset_with_autocrlf(self):
        git = shutil.which('git')
        self.assertIsNotNone(git, 'Git is required to validate checkout byte preservation.')
        with tempfile.TemporaryDirectory() as directory:
            source, checkout = Path(directory) / 'source', Path(directory) / 'checkout'
            source.mkdir()
            shutil.copytree(ROOT / 'regulai/static/vendor', source / 'regulai/static/vendor')
            (source / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/vendor_assets.py', source / 'scripts/vendor_assets.py')
            if (ROOT / '.gitattributes').exists():
                shutil.copyfile(ROOT / '.gitattributes', source / '.gitattributes')
            commands = [
                [git, 'init', str(source)],
                [git, '-C', str(source), 'config', 'core.autocrlf', 'true'],
                [git, '-C', str(source), 'add', '.'],
                [git, '-C', str(source), '-c', 'user.name=Offline checkout',
                    '-c', 'user.email=offline@example.invalid', 'commit', '-m', 'Pin offline fixture'],
                [git, 'clone', '--local', '-c', 'core.autocrlf=true', str(source), str(checkout)],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([__import__('sys').executable, str(checkout / 'scripts/vendor_assets.py'), '--check'],
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('Verified 7 local UI assets.', result.stdout)

    def test_bad_download_hash_preserves_every_existing_asset(self):
        namespace = runpy.run_path(str(ROOT / 'scripts/vendor_assets.py'))
        main = namespace['main']
        with tempfile.TemporaryDirectory() as directory:
            vendor = Path(directory)
            manifest = {name: {'source': 'https://assets.invalid/' + name,
                'sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}
                for name in ('first.js', 'second.js')}
            (vendor / 'manifest.json').write_text(json.dumps(manifest))
            for name in manifest:
                (vendor / name).write_bytes(b'original')
            with patch.dict(main.__globals__, {'ROOT': vendor}), patch('sys.argv', ['vendor_assets.py']), \
                 patch.dict(main.__globals__, {'urlopen': lambda url, **kwargs: io.BytesIO(
                     b'abc' if url.endswith('first.js') else b'changed-source')}):
                with self.assertRaisesRegex(ValueError, 'Checksum mismatch for second.js'):
                    main()
            self.assertEqual([(vendor / name).read_bytes() for name in manifest], [b'original', b'original'])

    def test_registered_icons_cover_template_names_and_dynamic_toggle_states(self):
        manifest = json.loads((ROOT / 'regulai/static/vendor/manifest.json').read_text())
        expected = {'solar': {'pause-bold', 'play-bold', 'pen-bold', 'add-circle-bold', 'check-circle-bold'},
                    'simple-icons': set()}
        for path in (ROOT / 'regulai/front/templates').rglob('*.html'):
            for prefix, name in re.findall(r'(solar|simple-icons):([a-z0-9-]+)', path.read_text(encoding='utf-8')):
                expected[prefix].add(name)
        self.assertTrue(expected['solar'].issubset(manifest['solar-icons.js']['icons']))
        self.assertTrue(expected['simple-icons'].issubset(manifest['brand-icons.js']['icons']))

    def test_templates_and_styles_load_only_local_resources(self):
        violations = []

        class Tags(HTMLParser):
            def handle_starttag(self, tag, attrs):
                for key, value in attrs:
                    if key in {'href', 'src', 'srcset', 'action', 'poster', 'data'} and value and re.match(r'^(?:https?:)?//', value):
                        if not (tag == 'a' and key == 'href' and value in NAVIGATION):
                            violations.append(value)

        for path in (ROOT / 'regulai/front/templates').rglob('*.html'):
            Tags().feed(path.read_text(encoding='utf-8'))
        for path in (ROOT / 'regulai/static/css').rglob('*.css'):
            text = re.sub(r'/\*.*?\*/', '', path.read_text(encoding='utf-8'), flags=re.S)
            violations.extend(re.findall(r'(?:url\(\s*[\"\']?|@import\s+[\"\'])(?:https?:)?//[^)\"\'\s]+', text))
        self.assertEqual(violations, [])

    def test_pinned_assets_verify_without_network(self):
        result = subprocess.run([__import__('sys').executable, str(ROOT / 'scripts/vendor_assets.py'), '--check'],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Verified', result.stdout)

    def test_icons_are_registered_locally_and_network_is_disabled(self):
        node = shutil.which('node')
        self.assertIsNotNone(node)
        harness = r"""
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
let fetcher = 'enabled'; const collections = [];
const icon = {_api: {setFetch: value => {fetcher = value}}, addCollection: value => collections.push(value)};
const context = {customElements: {get: () => icon}};
vm.createContext(context);
for (const file of process.argv.slice(1)) vm.runInContext(fs.readFileSync(file, 'utf8'), context);
assert.equal(fetcher, undefined);
assert.equal(collections.length, 2);
assert.ok(collections.find(c => c.prefix === 'solar').icons['chat-round-dots-bold']);
assert.ok(collections.find(c => c.prefix === 'simple-icons').icons.openai);
"""
        result = subprocess.run([node, '-e', harness, str(ROOT / 'regulai/static/vendor/solar-icons.js'),
                                 str(ROOT / 'regulai/static/vendor/brand-icons.js')],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


class BrowserPolicyTests(ChatFixture):
    def test_historical_audit_logs_show_label_without_delete_action(self):
        log = {'pk': 91, 'id': 91, 'historical': True, 'company_id': None,
               'action': 'Historical synthetic', 'details': '{}', 'user': None}
        url = reverse('front:auditlog_delete', args=[91])
        for template, context in [('auditlogs/list.html', {'logs': [log]}),
                                  ('auditlogs/detail.html', {'log': log})]:
            html = render_to_string(template, {'user': self.user, **context})
            self.assertIn('Histórico', html)
            self.assertTrue(url not in html, template + ' offers deletion of a historical record')
        log.update(historical=False, company_id=self.company.pk)
        html = render_to_string('auditlogs/detail.html', {'user': self.user, 'log': log})
        self.assertIn(url, html)

    def test_initial_policy_generation_is_a_separate_csrf_draft_action(self):
        html = render_to_string('policy_simulator.html', {'user': self.user,
            'can_manage_company_policy': True, 'csrf_token': 'synthetic-csrf'})
        self.assertIn('name="action" value="bootstrap"', html)
        self.assertIn('Generar política inicial', html)
        self.assertIn('name="csrfmiddlewaretoken" value="synthetic-csrf"', html)

    def test_company_admin_keeps_engine_controls_without_operator_model_controls(self):
        self.user.is_superuser = True
        self.user.is_staff = True
        html = render_to_string('engines/list.html', {'user': self.user,
            'company_engines': [self.credential], 'is_platform_operator': False})
        self.assertIn(reverse('front:engine_toggle', args=[self.credential.pk]), html)
        self.assertNotIn('Add Model', html)
        self.assertNotIn(reverse('front:model_toggle', args=[self.model.pk]), html)
        self.assertNotIn('Admin Panel', html)

    def test_operator_model_actions_are_post_forms_with_csrf(self):
        html = render_to_string('engines/list.html', {'user': self.user,
            'company_engines': [self.credential], 'is_platform_operator': True,
            'csrf_token': 'synthetic-csrf'})
        for action in ('engine_toggle', 'model_toggle', 'model_delete'):
            pk = self.credential.pk if action == 'engine_toggle' else self.model.pk
            url = reverse('front:' + action, args=[pk])
            self.assertIn('method="post" action="' + url + '"', html)
            self.assertNotIn('href="' + url + '"', html)
        self.assertIn('name="csrfmiddlewaretoken" value="synthetic-csrf"', html)

    def test_csp_declares_only_self_and_existing_inline_ui(self):
        response = self.client.get('/chat/')
        self.assertEqual(response.status_code, 200)
        policy = response.headers.get('Content-Security-Policy-Report-Only', '')
        self.assertIn("default-src 'self'", policy)
        self.assertIn("connect-src 'self'", policy)
        self.assertIn("script-src 'self' 'unsafe-inline'", policy)
        self.assertNotIn('Content-Security-Policy', response.headers)
