"""Operations checks at the HTTP audit and emitted-log interfaces."""
import json
import logging
import io
import uuid
import runpy
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager

from django.contrib.auth.models import User
from django.db import DatabaseError
from django.conf import settings
from django.test import Client, TestCase, SimpleTestCase, override_settings
from django.urls import include, path

from front.models import Company, Profile


SENTINEL = 'SYNTHETIC_SECRET_document_token_987654'


def sensitive_failure(request, value):
    raise RuntimeError(SENTINEL)


urlpatterns = [
    path('crash/<str:value>/', sensitive_failure, name='operation-crash'),
    path('api/', include('api.urls')),
]


@contextmanager
def captured_logs():
    stream = io.StringIO()
    handlers = {handler for name in ('', 'django', 'django.server', 'gunicorn.error')
                for handler in logging.getLogger(name).handlers}
    previous = {handler: handler.setStream(stream) for handler in handlers}
    try:
        yield stream
    finally:
        for handler, old_stream in previous.items():
            handler.setStream(old_stream)


@override_settings(ROOT_URLCONF=__name__, DEBUG=False)
class ExceptionAuditHTTPTests(TestCase):
    def setUp(self):
        self.company = Company.objects.create(name='Synthetic operations company')
        self.actor = User.objects.create_user('operations', is_staff=True)
        Profile.objects.create(user=self.actor, company=self.company)
        self.client = Client(raise_request_exception=False)
        self.client.force_login(self.actor)

    def test_http_exception_audit_omits_content_query_and_path_values(self):
        response = self.client.get('/crash/' + SENTINEL + '/?token=' + SENTINEL)
        self.assertEqual(response.status_code, 500)
        rows = self.client.get('/api/audit-logs/').json()['results']
        self.assertEqual(len(rows), 1)
        self.assertNotIn(SENTINEL, json.dumps(rows))
        details = json.loads(rows[0]['details'])
        self.assertEqual(details['code'], 'unhandled_exception')
        self.assertEqual(details['exception_type'], 'RuntimeError')
        self.assertEqual(details['path'], 'crash/<str:value>/')
        self.assertEqual(set(details), {'code', 'exception_type', 'request_id', 'path'})
        uuid.UUID(details['request_id'])
        from front.models import AuditLog
        self.assertEqual(AuditLog.objects.get().company_id, self.company.pk)

    def test_failed_audit_is_logged_without_exception_or_request_content(self):
        self.assertIn('safe_json', settings.LOGGING.get('formatters', {}))
        with captured_logs() as stream:
            with patch('front.middleware.AuditLog.objects.create', side_effect=DatabaseError(SENTINEL)):
                response = self.client.get('/crash/' + SENTINEL + '/?token=' + SENTINEL)
            self.assertEqual(response.status_code, 500)
        emitted = stream.getvalue()
        self.assertNotIn(SENTINEL, emitted)
        events = [json.loads(line) for line in emitted.splitlines()]
        event = next(item for item in events if item['logger'] == 'front.middleware')
        self.assertEqual(event['code'], 'audit_write_failed')
        self.assertEqual(event['exception_type'], 'DatabaseError')
        uuid.UUID(event['request_id'])
        self.assertEqual(next(item for item in events if item['logger'] == 'django.request')['request_id'], event['request_id'])


class SafeLoggingTests(TestCase):
    def test_logger_exception_omits_messages_locals_and_arbitrary_extras(self):
        self.assertIn('safe_json', settings.LOGGING.get('formatters', {}))
        logger = logging.getLogger('front.operations')
        request_id = str(uuid.uuid4())
        with captured_logs() as stream:
            try:
                raise RuntimeError(SENTINEL)
            except RuntimeError:
                logger.exception(SENTINEL + ' %s', SENTINEL, extra={
                    'request_id': request_id, 'code': 'pipeline_error',
                    'document': SENTINEL, 'provider': {'token': SENTINEL},
                    'url': '/?token=' + SENTINEL,
                }, stack_info=True)
        self.assertNotIn(SENTINEL, stream.getvalue())
        event = json.loads(stream.getvalue())
        self.assertEqual(event['request_id'], request_id)
        self.assertEqual(event['code'], 'pipeline_error')
        self.assertEqual(event['exception_type'], 'RuntimeError')
        self.assertEqual(event['level'], 'ERROR')
        self.assertEqual(event['logger'], 'front.operations')
        self.assertEqual(set(event), {'timestamp', 'level', 'logger', 'request_id', 'code', 'exception_type'})

    def test_untrusted_metadata_is_discarded_without_stringifying_objects(self):
        class Unserializable:
            def __str__(self):
                raise AssertionError('Logging must never stringify content')
        with captured_logs() as stream:
            logging.getLogger('front.operations').error(Unserializable(), extra={
                'request_id': SENTINEL, 'code': SENTINEL, 'provider': Unserializable(),
            })
        event = json.loads(stream.getvalue())
        self.assertEqual(event['code'], 'unclassified_event')
        self.assertIsNone(event['request_id'])
        self.assertNotIn(SENTINEL, stream.getvalue())


class RuntimeConfigTests(SimpleTestCase):
    def test_gunicorn_allows_the_maximum_pipeline_deadline_with_threads(self):
        config_path = Path(__file__).resolve().parents[2] / 'gunicorn.conf.py'
        self.assertTrue(config_path.is_file(), 'A deployable Gunicorn config is required')
        config = runpy.run_path(str(config_path))
        self.assertEqual(config['worker_class'], 'gthread')
        self.assertGreaterEqual(config['threads'], 2)
        self.assertGreater(config['timeout'], 180)
        self.assertGreaterEqual(config['graceful_timeout'], config['timeout'])
        self.assertIsNone(config['accesslog'])

    def test_ci_declares_the_five_local_gates_and_complete_git_history(self):
        workflow_path = Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml'
        self.assertTrue(workflow_path.is_file(), 'An executable CI workflow is required')
        # JSON is a YAML subset; the stdlib validates syntax without a parser dependency.
        workflow = json.loads(workflow_path.read_text(encoding='utf-8'))
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        steps = workflow['jobs']['quality']['steps']
        checkout = next(step for step in steps if step.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['fetch-depth'], 0)
        self.assertTrue(any(step.get('uses', '').startswith('actions/setup-node@') for step in steps))
        commands = '\n'.join(step.get('run', '') for step in steps)
        for gate in ('check --settings=regulai.test_settings', 'python scripts/run_ci_tests.py',
                     'makemigrations --check --dry-run --settings=regulai.test_settings',
                     'evaluate_ai --settings=regulai.test_settings', 'pip-audit==2.10.1'):
            self.assertIn(gate, commands)
        self.assertIn('mktemp -d', commands)
        self.assertIn('postgres', workflow['jobs']['quality']['services'])

    def test_public_tunnel_trusts_only_one_named_https_origin(self):
        from regulai.public_origin import tunnel_settings
        self.assertEqual(tunnel_settings(''), ([], []))
        self.assertEqual(tunnel_settings('https://demo-name.trycloudflare.com'),
                         (['demo-name.trycloudflare.com'], ['https://demo-name.trycloudflare.com']))
        for origin in ('http://demo.trycloudflare.com', 'https://*.trycloudflare.com', 'https://*',
                       'https://demo.trycloudflare.com:8443', 'https://user@demo.trycloudflare.com',
                       'https://demo.trycloudflare.com/admin', 'https://localhost'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                tunnel_settings(origin)
