"""Inclusive semantic limits exercised through real decisions, with synthetic transports."""
import json
import math
import uuid

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase

from front import test_classification, test_pipeline
from front.classification import decide
from front.connectors import ChatResponse
from front.models import EngineModel, Prompt, Response
from front.policy import AIConfig
from front.test_chat_flow import ChatFixture


class SemanticThresholdBoundaryTests(ChatFixture):
    configure = test_pipeline.PipelineTests.configure

    def test_document_scores_below_at_and_above_limit_on_all_three_entries(self):
        self.configure()
        text = ('The approved period is seventeen days.\n'
                'The listed fee is one hundred twenty euros.')

        def document_answer(messages, **kwargs):
            source = json.loads(messages[-1].content.split('Sources:\n', 1)[1])[0]
            claims = [{'text': statement, 'citations': [{'id': source['id'], 'quote': statement}]}
                      for statement in text.splitlines()]
            return ChatResponse(json.dumps({'claims': claims}), 30, 'synthetic-v1', 'stop', 20, 10)

        self.provider.side_effect = document_answer
        # DOC-01/strong's observed judge scores were .03, .03, .13 and .20.
        # Adjacent floats prevent an epsilon from silently relaxing the boundary.
        for omission, expected in ((math.nextafter(.2, 0), 'completed'),
                                   (.2, 'completed'),
                                   (math.nextafter(.2, 1), 'failed')):
            self.http.side_effect = test_pipeline.jev_http(choices={'task': 'document_question'},
                failures={'claim_1': .03, 'claim_2': .03,
                          'failure_contradiction': .13, 'failure_omission': omission})
            for path in ('/chat/send/', '/api/chat/send/', '/chat/'):
                with self.subTest(omission=omission, path=path):
                    self.provider.reset_mock()
                    request_id = str(uuid.uuid4())
                    response = self.send(path, 'What are the approved period and listed fee?',
                        request_id=request_id, file=SimpleUploadedFile('terms.txt', text.encode()))
                    prompt = Prompt.objects.get(request_id=request_id)
                    checks = prompt.decision['verification']
                    self.assertEqual(checks['local_status'], 'passed')
                    self.assertEqual(prompt.status, expected)
                    self.assertEqual(checks['status'], 'passed' if expected == 'completed' else 'failed')
                    self.assertEqual(checks['checks'][-1]['status'], checks['status'])
                    self.assertEqual(response.status_code,
                        (302 if path == '/chat/' else 200) if expected == 'completed' else 502)
                    self.assertEqual(Response.objects.filter(prompt=prompt).exists(), expected == 'completed')
                    self.assertEqual(self.provider.call_count, 1)
                    judge_call = next(call for call in prompt.decision['calls'] if call['purpose'] == 'verification')
                    self.assertAlmostEqual(judge_call['threshold'], .8)
                    self.assertEqual(set(judge_call['signals']),
                        {'claim_1', 'claim_2', 'failure_contradiction', 'failure_omission'})

    def test_retry_instructions_only_name_scores_strictly_above_limit(self):
        self.configure()
        stronger = EngineModel.objects.create(engine=self.engine, name='Strong', model_id='synthetic-strong',
            context_window=32768, input_price=2, output_price=3)
        self.company.ai_config['routing'] = {'mode': 'manual', 'candidates': [
            {'company_engine_id': self.credential.pk, 'model_id': self.model.pk,
             'level': 'economy', 'quality': {'general': .5}},
            {'company_engine_id': self.credential.pk, 'model_id': stronger.pk,
             'level': 'strong', 'quality': {'general': .9}}]}
        self.company.save()
        self.http.side_effect = test_pipeline.jev_http(failures={
            'failure_omission': .2, 'failure_contradiction': math.nextafter(.2, 1)})
        result = self.send('/api/chat/send/').json()
        self.assertEqual(result['status'], 'failed', result)
        self.assertEqual(self.provider.call_count, 2)
        correction = self.provider.call_args.args[0][-1].content
        self.assertIn('failure_contradiction', correction)
        self.assertNotIn('failure_omission', correction)


class ClassificationThresholdBoundaryTests(SimpleTestCase):
    def test_ordinal_tail_does_not_accept_any_mass_above_inclusive_limit(self):
        for mass, expected in ((math.nextafter(.2, 0), 'public'),
                               (.2, 'public'), (math.nextafter(.2, 1), 'confidential')):
            with self.subTest(mass=mass):
                signals = test_classification.answers()
                signals['category'].update(choice='public', confidence=.8,
                    probabilities={'public': .8, 'internal': 0.0, 'confidential': 0.0,
                                   'restricted': 0.0, 'unknown': mass})
                decision = decide(signals, AIConfig(), 'public')
                self.assertIsNone(decision.stop_code)
                self.assertEqual(decision.sensitivity, expected)

    def test_direct_signal_and_confidence_comparisons_keep_their_boundaries(self):
        for signal, expected in ((math.nextafter(.2, 0), 'public'),
                                 (.2, 'confidential'), (math.nextafter(.2, 1), 'confidential')):
            with self.subTest(signal=signal):
                signals = test_classification.answers()
                signals['category'].update(choice='public', confidence=1.0,
                    probabilities={'public': 1.0, 'internal': 0.0, 'confidential': 0.0,
                                   'restricted': 0.0, 'unknown': 0.0})
                signals['personal_data']['noul'] = signal
                self.assertEqual(decide(signals, AIConfig(), 'public').sensitivity, expected)
        for confidence, ambiguous in ((math.nextafter(.8, 0), True),
                                      (.8, False), (math.nextafter(.8, 1), False)):
            with self.subTest(confidence=confidence):
                signals = test_classification.answers()
                signals['task'].update(confidence=confidence, choice='summary',
                    probabilities={'summary': 1.0, 'extraction': 0.0,
                                   'document_question': 0.0, 'general': 0.0})
                self.assertEqual('task_ambiguous' in decide(signals, AIConfig(), 'public').notices, ambiguous)
