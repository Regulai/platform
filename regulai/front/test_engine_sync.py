"""Models are synced automatically when an engine API key is added or changed."""
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .connectors import ModelInfo
from .models import Company, CompanyEngine, Engine, EngineModel, Profile


def fake_connector(models=None, error=None):
    connector = mock.Mock()
    connector.client = None
    if error:
        connector.list_models.side_effect = error
    else:
        connector.list_models.return_value = models or []
    return connector


MODELS = [
    ModelInfo(model_id='gpt-4o', name='gpt-4o', description='OpenAI gpt-4o', supports_vision=True, max_tokens=4096),
    ModelInfo(model_id='gpt-4o-mini', name='gpt-4o-mini', description='OpenAI gpt-4o-mini', supports_vision=True, max_tokens=4096),
]


class EngineAutoSyncTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Tenant')
        self.admin = User.objects.create_superuser('root', 'root@test.local', 'x')
        Profile.objects.create(user=self.admin, company=self.company)
        self.engine = Engine.objects.create(name='Test Provider', provider='Test', connector_type='openai')
        self.client.force_login(self.admin)

    def messages_text(self, response):
        return ' | '.join(str(m) for m in get_messages(response.wsgi_request))

    def create_engine(self, api_key='sk-new'):
        return self.client.post(reverse('front:engine_create'), {
            'engine': self.engine.pk, 'name': '', 'api_key': api_key, 'active': 'on',
        })

    @mock.patch('front.connectors.get_connector')
    def test_create_engine_syncs_models(self, get_connector):
        get_connector.return_value = fake_connector(MODELS)

        response = self.create_engine('sk-new')

        self.assertEqual(response.status_code, 302)
        get_connector.assert_called_once_with(connector_type='openai', api_key='sk-new', base_url=None)
        self.assertEqual(
            sorted(EngineModel.objects.filter(engine=self.engine).values_list('model_id', flat=True)),
            ['gpt-4o', 'gpt-4o-mini'],
        )
        self.assertIn('Synced 2 models from Test Provider automatically', self.messages_text(response))

    @mock.patch('front.connectors.get_connector')
    def test_sync_failure_keeps_engine_and_warns(self, get_connector):
        get_connector.return_value = fake_connector(error=RuntimeError('boom'))

        response = self.create_engine()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(CompanyEngine.objects.filter(company=self.company).count(), 1)
        self.assertIn('could not be synced automatically', self.messages_text(response))

    @mock.patch('front.connectors.get_connector')
    def test_no_models_returned_warns(self, get_connector):
        get_connector.return_value = fake_connector([])

        response = self.create_engine()

        self.assertIn('No models returned from Test Provider', self.messages_text(response))
        self.assertFalse(EngineModel.objects.filter(engine=self.engine).exists())

    @mock.patch('front.connectors.get_connector')
    def test_edit_syncs_only_when_api_key_changes(self, get_connector):
        get_connector.return_value = fake_connector(MODELS)
        company_engine = CompanyEngine.objects.create(company=self.company, engine=self.engine, api_key='sk-old')
        url = reverse('front:engine_edit', args=[company_engine.pk])

        self.client.post(url, {'name': 'Renamed', 'api_key': 'sk-old', 'active': 'on'})
        get_connector.assert_not_called()

        self.client.post(url, {'name': 'Renamed', 'api_key': 'sk-rotated', 'active': 'on'})
        get_connector.assert_called_once_with(connector_type='openai', api_key='sk-rotated', base_url=None)
        self.assertEqual(EngineModel.objects.filter(engine=self.engine).count(), 2)

    @mock.patch('front.connectors.get_connector')
    def test_sync_does_not_reactivate_disabled_models(self, get_connector):
        get_connector.return_value = fake_connector(MODELS)
        EngineModel.objects.create(engine=self.engine, model_id='gpt-4o', name='old', active=False)

        self.create_engine()

        disabled = EngineModel.objects.get(engine=self.engine, model_id='gpt-4o')
        self.assertFalse(disabled.active)
        self.assertEqual(disabled.name, 'gpt-4o')  # metadata refreshed
        self.assertTrue(EngineModel.objects.get(engine=self.engine, model_id='gpt-4o-mini').active)
