"""HTTP regressions for the shared chat flow; every provider is synthetic."""
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase

from front.connectors import ChatResponse
from front.models import Alert, Company, CompanyEngine, Engine, EngineModel, Message, ObfuscationConfig, Profile, Prompt, Rule, RulesGroup


def mask_response(url, **kwargs):
    if not url.endswith('/api/mask'):
        raise AssertionError('Unexpected external HTTP')
    return SimpleNamespace(raise_for_status=lambda: None,
        json=lambda: {'masked': kwargs['json']['text']})


class ChatFixture(TestCase):
    requires_mask = True

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('chat-user', password='synthetic-password')
        self.company = Company.objects.create(name='Chat synthetic')
        self.profile = Profile.objects.create(user=self.user, company=self.company)
        self.engine = Engine.objects.create(name='Synthetic chat', connector_type='openai')
        self.model = EngineModel.objects.create(engine=self.engine, name='Synthetic model', model_id='synthetic-v1', context_window=32768)
        self.credential = CompanyEngine.objects.create(company=self.company, engine=self.engine, api_key='synthetic-key')
        self.company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
                                  'destinations': {'internal': [f'engine:{self.credential.pk}']}}
        if self.requires_mask:
            self.required_mask = ObfuscationConfig.objects.create(company=self.company,
                name='Required synthetic mask', api_url='https://mask.invalid')
            self.company.ai_config['destinations']['internal'].append(f'obfuscation:{self.required_mask.pk}')
            self.company.ai_config['masking'] = {'max_call_cost': '0'}
        self.company.save()
        self.group = RulesGroup.objects.create(name='Synthetic security', company=self.company)
        self.rule = Rule.objects.create(name='Fake secret', rules_group=self.group,
            yara_rule='rule SyntheticSecret { strings: $s = "SYNTHETIC_SECRET" condition: $s }')
        self.client.force_login(self.user)
        self.client.raise_request_exception = False
        self.provider = self.enterContext(patch('front.connectors.OpenAIConnector.chat',
            return_value=ChatResponse('Hola', 10, 'synthetic-v1', 'stop')))
        self.http = self.enterContext(patch('requests.post', side_effect=mask_response))

    def send(self, path, content='Hola', **extra):
        data = {'content' if path.startswith('/api/') else 'prompt': content,
                'request_id': str(uuid.uuid4()), **extra}
        return self.client.post(path, data)


class ChatFlowTests(ChatFixture):
    def test_invalid_rule_fails_closed_on_all_three_entries(self):
        Rule.objects.filter(pk=self.rule.pk).update(yara_rule='invalid YARA source')
        ObfuscationConfig.objects.create(company=self.company, name='Synthetic mask', api_url='https://example.invalid')
        for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
            with self.subTest(path=path):
                response = self.send(path)
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()['error_type'], 'security_check_failed')
                self.provider.assert_not_called()
                self.http.assert_not_called()

    def test_authorized_request_is_sent_once_and_duplicate_replays(self):
        request_id = str(uuid.uuid4())
        first = self.send('/chat/send/', request_id=request_id)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()['status'], 'completed')
        second = self.send('/api/chat/send/', request_id=request_id)
        self.assertEqual(second.json()['assistant_message'], first.json()['assistant_message'])
        self.assertEqual(self.provider.call_count, 1)
        self.assertEqual(Message.objects.count(), 2)
        conflict = self.send('/chat/send/', 'Different', request_id=request_id)
        self.assertEqual(conflict.status_code, 409)

    def test_blocked_and_unlinked_messages_never_enter_history(self):
        first = self.send('/chat/send/', 'SYNTHETIC_SECRET')
        self.assertEqual(first.status_code, 403)
        conversation = first.json()['conversation_id']
        Message.objects.create(conversation_id=conversation, role='assistant', content='UNAUTHORIZED')
        good = self.send(f'/chat/{conversation}/send/', 'Hello again')
        self.assertEqual(good.json()['status'], 'completed')
        payload = str(self.provider.call_args)
        self.assertNotIn('SYNTHETIC_SECRET', payload)
        self.assertNotIn('UNAUTHORIZED', payload)
        self.assertEqual(Alert.objects.count(), 1)

    def test_consent_requires_signed_proof_and_keeps_same_message(self):
        self.rule.action = 'consent'
        self.rule.save()
        request_id = str(uuid.uuid4())
        first = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id, consent_confirmed='true')
        self.assertEqual(first.json()['status'], 'pending_consent')
        self.provider.assert_not_called()
        bad = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id, consent_token='forged')
        self.assertEqual(bad.status_code, 409)
        confirmed = self.send('/api/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id,
                              consent_token=first.json()['consent_token'])
        self.assertEqual(confirmed.json()['status'], 'completed')
        self.assertEqual(confirmed.json()['user_message']['id'], first.json()['user_message']['id'])
        self.assertEqual(Message.objects.filter(role='user').count(), 1)
        self.assertEqual(self.provider.call_count, 1)

    def test_changed_policy_invalidates_consent(self):
        self.rule.action = 'consent'
        self.rule.save()
        request_id = str(uuid.uuid4())
        first = self.send('/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id)
        self.company.ai_config['revision'] = 2
        self.company.save()
        response = self.send('/chat/send/', 'SYNTHETIC_SECRET', request_id=request_id,
                             consent_token=first.json()['consent_token'])
        self.assertEqual(response.status_code, 409)
        self.provider.assert_not_called()

    def test_timeout_is_not_automatically_retried(self):
        self.provider.side_effect = TimeoutError('sensitive provider details')
        request_id = str(uuid.uuid4())
        first = self.send('/chat/send/', request_id=request_id)
        second = self.send('/chat/send/', request_id=request_id)
        self.assertEqual(first.json()['status'], 'outcome_unknown')
        self.assertEqual(second.json()['status'], 'outcome_unknown')
        self.assertEqual(self.provider.call_count, 1)
        self.assertNotIn('sensitive provider details', str(first.json()))

    def test_unconfigured_policy_and_mask_destination_fail_closed(self):
        ObfuscationConfig.objects.create(company=self.company, name='Synthetic mask', api_url='https://example.invalid')
        response = self.send('/chat/send/')
        self.assertEqual(response.json()['error_type'], 'destination_not_allowed')
        self.company.ai_config = {}
        self.company.save()
        response = self.send('/api/chat/send/')
        self.assertEqual(response.json()['error_type'], 'policy_configuration_invalid')
        self.provider.assert_not_called()
        self.http.assert_not_called()
