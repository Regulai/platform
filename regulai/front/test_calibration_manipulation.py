"""Manipulation-only policy limits; HTTP replies are fixtures, not model quality."""
from dataclasses import asdict
from hashlib import sha256
import importlib.util
import json
import math
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import requests
from django.core.cache import cache
from django.test import SimpleTestCase

from front import test_pipeline
from front.classification import decide
from front.models import Prompt, Response
from front.policy import AIConfig
from front.test_chat_flow import ChatFixture
from front.test_classification import answers


ROOT = Path(__file__).resolve().parents[2]
REQUESTS_POST = requests.post
SPEC = importlib.util.spec_from_file_location(
    'r4_offline_harness', ROOT / 'scripts/run_adversarial_community.py')
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


class ManipulationPolicyTests(SimpleTestCase):
    def test_omitted_and_null_override_keep_the_legacy_shared_limit(self):
        self.assertIsNone(AIConfig().classification_policy.manipulation_threshold)
        for policy in ({'signal_threshold': .3},
                       {'signal_threshold': .3, 'manipulation_threshold': None}):
            config = AIConfig.model_validate({'classification_policy': policy})
            for score, expected in ((math.nextafter(.3, 0), None),
                                    (.3, 'classification_manipulation')):
                with self.subTest(policy=policy, score=score):
                    signals = answers()
                    signals['manipulation']['noul'] = score
                    self.assertEqual(decide(signals, config, 'internal').stop_code, expected)

    def test_override_is_optional_strict_finite_and_in_positive_unit_interval(self):
        for value in (0, -.01, 1.01, float('nan'), float('inf'), '0.4', True):
            with self.subTest(invalid=value), self.assertRaises(ValueError):
                AIConfig.model_validate({'classification_policy': {'manipulation_threshold': value}})
        for value in (.4, 1.0):
            with self.subTest(valid=value):
                config = AIConfig.model_validate({'classification_policy': {'manipulation_threshold': value}})
                self.assertEqual(config.classification_policy.manipulation_threshold, value)

    def test_manipulation_only_limit_is_inclusive_without_an_epsilon(self):
        config = AIConfig.model_validate({'classification_policy': {'manipulation_threshold': .4}})
        for score, expected in ((math.nextafter(.4, 0), None),
                                (.4, 'classification_manipulation'),
                                (math.nextafter(.4, 1), 'classification_manipulation')):
            with self.subTest(score=score):
                signals = answers()
                signals['manipulation']['noul'] = score
                self.assertEqual(decide(signals, config, 'internal').stop_code, expected)

    def test_override_preserves_every_other_signal_and_unknown_restricted_floors(self):
        for threshold in (.4, 1.0):
            config = AIConfig.model_validate({'classification_policy': {'manipulation_threshold': threshold}})
            for key in ('personal_data', 'business_confidential', 'credentials',
                        'ambiguous', 'insufficient_evidence'):
                for score in (math.nextafter(.2, 0), .2, math.nextafter(.2, 1)):
                    with self.subTest(threshold=threshold, signal=key, score=score):
                        signals = answers()
                        signals[key]['noul'] = score
                        self.assertEqual(asdict(decide(signals, config, 'internal')),
                                         asdict(decide(signals, AIConfig(), 'internal')))
            for floor, sensitivity, stop in (('unknown', 'confidential', None),
                                              ('restricted', 'restricted', 'restricted_content')):
                with self.subTest(threshold=threshold, floor=floor):
                    decision = decide(answers(), config, floor)
                    self.assertEqual((decision.sensitivity, decision.stop_code), (sensitivity, stop))
            signals = answers()
            signals['category'].update(choice='unknown', confidence=1.0,
                probabilities={'public': 0.0, 'internal': 0.0, 'confidential': 0.0,
                               'restricted': 0.0, 'unknown': 1.0})
            decision = decide(signals, config, 'internal')
            self.assertEqual((decision.sensitivity, decision.notices),
                             ('confidential', ['classification_ambiguous']))


class ManipulationHttpBoundaryTests(ChatFixture):
    configure = test_pipeline.PipelineTests.configure

    def setUp(self):
        super().setUp()
        self.guards = self.enterContext(HARNESS.deny_network())
        self.required_mask.backend = 'local'
        self.required_mask.api_url = ''
        self.required_mask.language = 'es'
        self.required_mask.save()
        # Restricted content must also stay away from an authorized private destination.
        self.engine.base_url = 'http://127.0.0.1:8099/v1'
        self.engine.save()
        self.configure(classification_policy={'manipulation_threshold': .4}, destinations={
            level: [f'engine:{self.credential.pk}', 'jev']
            for level in ('internal', 'confidential', 'restricted')})
        self.enterContext(patch('requests.post', REQUESTS_POST))
        self.enterContext(patch('front.connectors.OpenAIConnector.chat', test_pipeline.OPENAI_CHAT))
        session_init = requests.sessions.Session.__init__

        def no_environment_credentials(session):
            session_init(session)
            session.trust_env = False

        self.enterContext(patch('requests.sessions.Session.__init__', no_environment_credentials))

    def test_three_entries_keep_sensitive_limits_while_only_benign_manipulation_passes(self):
        observations, active = [], {}

        def record(purpose, raw, url):
            if isinstance(raw, str):
                raw = raw.encode('utf-8')
            item = dict(case=active['name'], entry=active['entry'], purpose=purpose,
                url=url, body_utf8=raw.decode('utf-8'), body_sha256=sha256(raw).hexdigest(),
                response_origin='synthetic_transport_fixture', real_network=False)
            observations.append(item)
            return item

        def jev_transport(adapter, request, **kwargs):
            self.assertEqual(request.url, 'https://ai-gateway.vercel.sh/typesafe/v1/systemone')
            body = json.loads(request.body)
            purpose = 'classification' if 'category' in body['questions'] else 'verification'
            observation = record(purpose, request.body, request.url)
            signals = {}
            for key, question in body['questions'].items():
                if question['type'] == 'choice':
                    chosen = dict(category='internal', task='general', difficulty='economy')[key]
                    signals[key] = dict(type='choice', choice=chosen, confidence=1.0,
                        probabilities={option: float(option == chosen) for option in question['criteria']})
                else:
                    signals[key] = dict(type='noul', noul=active['signals'].get(key, 0.0)
                                       if purpose == 'classification' else 0.0)
            observation['response'] = dict(model=body['model'], answers=signals,
                                          usage=dict(input_tokens=100, output_tokens=20))
            response = requests.Response()
            response.status_code, response._content_consumed = 200, True
            response._content = json.dumps(observation['response']).encode('utf-8')
            response.request, response.url = request, request.url
            return response

        def generation_transport(request):
            self.assertEqual(str(request.url), 'http://127.0.0.1:8099/v1/chat/completions')
            observation = record('generation', request.content, str(request.url))
            observation['response'] = dict(id='synthetic-r4', object='chat.completion',
                created=0, model='synthetic-v1', choices=[dict(index=0,
                    message=dict(role='assistant', content='La lluvia cae despacio.'), finish_reason='stop')],
                usage=dict(prompt_tokens=20, completion_tokens=10, total_tokens=30))
            return httpx.Response(200, json=observation['response'])

        self.enterContext(patch('requests.adapters.HTTPAdapter.send', jev_transport))
        self.enterContext(patch('openai.DefaultHttpxClient', side_effect=lambda **kwargs:
            httpx.Client(transport=httpx.MockTransport(generation_transport), trust_env=False, **kwargs)))
        cases = (
            ('benign', {'manipulation': .36}, 'completed', 'internal', None),
            ('attack', {'manipulation': .96}, 'blocked', None, 'classification_manipulation'),
            ('credentials', {'manipulation': .36, 'credentials': .2}, 'blocked', None, 'restricted_content'),
            ('pii', {'manipulation': .36, 'personal_data': .2}, 'completed', 'confidential', None),
        )
        for name, signals, status, sensitivity, error in cases:
            for entry in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(case=name, entry=entry):
                    cache.clear()
                    active.update(name=name, entry=entry, signals=signals)
                    offset = len(observations)
                    response = self.send(entry, 'Escribe una frase corta sobre la lluvia.')
                    prompt = Prompt.objects.latest('pk')
                    self.assertEqual(prompt.status, status, prompt.decision)
                    self.assertEqual(response.status_code,
                        (302 if entry == '/chat/' else 200) if status == 'completed' else 403)
                    current = observations[offset:]
                    self.assertEqual([item['purpose'] for item in current],
                        ['classification', 'generation', 'verification'] if status == 'completed'
                        else ['classification'])
                    self.assertEqual(Response.objects.filter(prompt=prompt).exists(), status == 'completed')
                    if status == 'completed':
                        self.assertEqual(prompt.decision['policy']['sensitivity'], sensitivity)
                        self.assertEqual(prompt.decision['verification']['status'], 'passed')
                        self.assertEqual(json.loads(current[0]['body_utf8'])['state']['request'],
                                         json.loads(current[2]['body_utf8'])['state']['request'])
                    else:
                        self.assertEqual(response.json()['error_type'], error)
        self.assertEqual({name: guard.call_count for name, guard in self.guards.items()},
                         {name: 0 for name in self.guards})
        target = os.environ.get('REGULAI_R4_CAPTURE')
        if target:
            path = Path(target).resolve()
            self.assertTrue(path.is_relative_to(
                ROOT / 'evals/calibration/calibration-20261004-01/privacy/r4'))
            with path.open('x', encoding='utf-8') as stream:
                json.dump(observations, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
