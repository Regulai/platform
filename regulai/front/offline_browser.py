"""Run the chat page's scripts offline against a rendered page (see offline_browser.cjs).

Tests pass the HTML returned by Django's test client (or nothing, for a blank
page) and a block of JavaScript checks. The page is parsed here with the
standard library, then node loads chat-markdown.js, chat.js and agent-chat.js in
order, fires DOMContentLoaded and runs the checks. There is no network: every
request the scripts make must be answered by the checks through ``net.on``.
"""
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import subprocess

STATIC = Path(__file__).resolve().parents[1] / 'static'
HARNESS = Path(__file__).with_name('offline_browser.cjs')
SCRIPTS = ('js/chat-markdown.js', 'js/chat.js', 'js/agent-chat.js')
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr'}


class _Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = ['#document', {}, []]
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = [tag, {name: '' if value is None else value for name, value in attrs}, []]
        self.stack[-1][2].append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1][2].append([tag, {name: '' if value is None else value for name, value in attrs}, []])

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return

    def handle_data(self, data):
        self.stack[-1][2].append(data)


def parse(html):
    tree = _Tree()
    tree.feed(html.decode() if isinstance(html, bytes) else html)
    tree.close()
    return tree.root


def run(checks, html=None, *, timeout=30, **options):
    node = shutil.which('node')
    if not node:
        raise RuntimeError('node is required for the offline browser tests')
    payload = {'tree': parse(html) if html is not None else None, 'checks': checks, 'options': options,
               'scripts': [{'name': name, 'source': (STATIC / name).read_text(encoding='utf-8')} for name in SCRIPTS]}
    return subprocess.run([node, str(HARNESS)], input=json.dumps(payload), capture_output=True,
                          text=True, encoding='utf-8', timeout=timeout)


class OfflineBrowser:
    """TestCase mixin: ``self.browse(checks, page)`` fails with node's error output.

    Options: ``media`` ({'desktop', 'reducedMotion', 'finePointer'}), ``storage``
    (initial localStorage), ``routes`` (JSON replies needed while the page loads:
    [{'method', 'url', 'status', 'json'}]) and ``path``. Returns the completed
    process, so checks may print JSON for the test to send to the server.
    """

    @classmethod
    def setUpClass(cls):
        # These scripts belong to the legacy page (the local rollback of task 79);
        # the React island has its own browser tests in frontend/chat.
        from django.test import override_settings
        cls._legacy_chat = override_settings(REGULAI_CHAT_FRONTEND='legacy')
        cls._legacy_chat.enable()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls._legacy_chat.disable()

    def browse(self, checks, page=None, **options):
        if page is not None and hasattr(page, 'content'):
            self.assertEqual(page.status_code, 200)
            options.setdefault('path', page.wsgi_request.path if hasattr(page, 'wsgi_request') else '/chat/')
            page = page.content
        result = run(checks, page, **options)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        return result
