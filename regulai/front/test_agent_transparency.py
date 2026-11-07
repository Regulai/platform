"""Real application/provider parsers over simulated HTTP; no external API calls."""
from decimal import Decimal
import json
from unittest.mock import patch

import requests
from django.test import TestCase, override_settings

from front import jev
from front.agents.service import AgentDenied, begin_execution
from front.connectors import ChatResponse
from front.models import AgentExecution, AgentInference, CompanyEngine
from front.test_agent_inference import AgentFixture


def classification_answers(**choices):
    selected = {'category': 'internal', 'task': 'general', 'difficulty': 'strong', **choices}
    answers = {}
    for name, question in {**jev.classification_questions(), **jev.task_questions()}.items():
        if question['type'] == 'noul':
            answers[name] = {'type': 'noul', 'noul': float(selected.get(name, 0))}
        else:
            answers[name] = {'type': 'choice', 'choice': selected[name], 'confidence': 1.0,
                'probabilities': {key: float(key == selected[name]) for key in question['criteria']}}
    return answers


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentTransparencyTests(AgentFixture, TestCase):
    def configure(self, *, classification='required', credential=True, confidential=True, **config):
        self.company.ai_config.update(classification=classification, **config)
        self.company.ai_config['destinations']['internal'].append('jev')
        if confidential:
            self.company.ai_config['destinations']['confidential'] = list(
                self.company.ai_config['destinations']['internal'])
        self.company.jev_api_key = 'synthetic-jev-key' if credential else ''
        self.company.save()
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.prompt.refresh_from_db()
        self.prompt.decision = {'calls': []}
        self.prompt.save(update_fields=['decision'])
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)

    def simulated_jev(self, *, answers=None, error=None, http_status=200, after_request=None, cost='0.002'):
        captured = []
        payload = {'model': 'typesafe-ai/jev', 'answers': answers or classification_answers(),
            'usage': {'input_tokens': 80, 'output_tokens': 30},
            'providerMetadata': {'gateway': {'cost': cost, 'routing': {'finalProvider': 'typesafe-ai'}}}}

        class Response:
            status_code = http_status
            headers = {'x-request-id': 'synthetic-jev-request'}

            def iter_content(self, chunk_size):
                yield json.dumps(payload).encode()

            def close(self):
                pass

        def http(url, **kwargs):
            captured.append({'url': url, 'payload': json.loads(kwargs['data'])})
            if after_request:
                after_request()
            if error:
                raise error
            return Response()

        self.enterContext(patch('front.jev.requests.post', side_effect=http))
        return captured

    def receipt(self):
        self.prompt.refresh_from_db()
        return self.prompt.decision

    def test_local_policy_never_claims_jev_approval_and_disabled_is_explicit(self):
        self.assertEqual(self.receipt()['jev']['status'], 'disabled')
        self.assertFalse(self.receipt()['jev']['consulted'])
        self.configure(classification='local')
        captured = self.simulated_jev()
        self.assertEqual(self.infer()['status'], 'completed')
        meta = self.receipt()
        self.assertEqual(captured, [])
        self.assertEqual(meta['jev']['status'], 'not_consulted')
        self.assertIsNone(meta['jev']['decision'])
        self.assertEqual(meta['jev']['reason_codes'], ['classification_local'])
        self.assertEqual(meta['policy']['source'], 'local_policy')
        self.assertEqual(meta['policy']['reason_codes'], ['local_policy_allowed'])

    def test_required_jev_uses_authorized_gateway_masked_state_and_real_signals(self):
        self.configure()
        captured = self.simulated_jev()
        request = self.request(messages=[{'role': 'user',
            'content': 'Summarize for ana@example.invalid. api_key=sk-synthetic-secret-value'}])
        result = self.infer(request)
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]['url'], jev.VERCEL_ENDPOINT)
        self.assertEqual(captured[0]['payload']['providerOptions']['gateway']['only'], ['typesafe-ai'])
        sent = json.dumps(captured[0]['payload']['state'])
        self.assertNotIn('ana@example.invalid', sent)
        self.assertNotIn('sk-synthetic-secret-value', sent)
        meta = self.receipt()
        receipt = meta['jev']
        self.assertEqual(receipt['status'], 'consulted')
        self.assertEqual(receipt['decision'], {'category': 'internal', 'task': 'general', 'difficulty': 'strong'})
        self.assertEqual(receipt['signals'], classification_answers())
        self.assertEqual(receipt['reasons'], [])
        self.assertEqual(receipt['recommendations'], [])
        self.assertFalse(receipt['explanation_available'])
        self.assertEqual(receipt['effect'], 'continue')
        self.assertTrue(receipt['consulted_at'])
        self.assertEqual(receipt['policy']['source'], 'regulay_policy')
        self.assertEqual(meta['policy']['inputs'], ['local_policy', 'jev_signals'])
        judge = next(call for call in meta['calls'] if call['purpose'] == 'classification')
        self.assertEqual(judge['jev'], receipt)
        self.assertEqual(judge['provider_name'], 'vercel_gateway')
        self.assertEqual(judge['route']['upstream_provider'], 'typesafe-ai')
        self.assertEqual(judge['cost_kind'], 'provider_reported')
        self.assertEqual(Decimal(meta['total']['cost']), Decimal('0.00214'))
        self.assertNotIn('synthetic-jev-key', json.dumps(meta))
        self.assertNotIn('synthetic-provider-key', json.dumps(meta))

    def test_local_policy_applies_signal_block_before_any_generator_call(self):
        self.configure()
        self.simulated_jev(answers=classification_answers(credentials=1))
        result = self.infer()
        self.assertEqual(result, {'status': 'rejected', 'code': 'restricted_content'})
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['jev']['decision']['category'], 'internal')
        self.assertEqual(meta['jev']['applied']['sensitivity'], 'restricted')
        self.assertEqual(meta['jev']['effect'], 'block')
        self.assertEqual(meta['policy']['status'], 'block')
        self.assertEqual(Decimal(meta['total']['cost']), Decimal('0.002'))

    def test_higher_sensitivity_rechecks_real_destinations_and_cannot_grant_access(self):
        self.configure(confidential=False)
        self.simulated_jev(answers=classification_answers(category='confidential'))
        result = self.infer()
        self.assertEqual(result['status'], 'rejected')
        self.assertEqual(result['code'], 'destination_not_allowed')
        self.assertEqual(self.requests, [])
        self.assertEqual(self.receipt()['jev']['effect'], 'block')

    def test_required_but_unconfigured_is_disabled_without_any_provider_call(self):
        self.configure(credential=False)
        captured = self.simulated_jev()
        self.assertEqual(self.infer(), {'status': 'rejected', 'code': 'jev_unavailable'})
        self.assertEqual(captured, [])
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['calls'], [])
        self.assertEqual(meta['jev']['status'], 'disabled')
        self.assertFalse(meta['jev']['consulted'])
        self.assertEqual(meta['jev']['effect'], 'block')

    def test_jev_http_failure_remains_distinct_from_no_response(self):
        self.configure()
        captured = self.simulated_jev(http_status=403)
        request = self.request()
        result = self.infer(request)
        self.assertEqual(result, {'status': 'rejected', 'code': 'jev_failed'})
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(captured), 1)
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['jev']['status'], 'failed')
        self.assertEqual(meta['jev']['reason_codes'], ['http_403'])
        self.assertIsNone(meta['total']['cost'])
        self.assertFalse(meta['total']['complete'])

    def test_jev_timeout_is_uncertain_never_replayed_or_priced_as_zero(self):
        self.configure()
        captured = self.simulated_jev(error=requests.ReadTimeout('private@example.invalid'))
        request = self.request()
        result = self.infer(request)
        self.assertEqual(result['status'], 'outcome_unknown')
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(captured), 1)
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['jev']['status'], 'no_response')
        self.assertEqual(meta['jev']['reason_codes'], ['timeout'])
        self.assertIsNone(meta['total']['cost'])
        self.assertFalse(meta['total']['complete'])
        self.assertNotIn('private@example.invalid', json.dumps(meta))
        self.execution.refresh_from_db()
        self.assertEqual(self.execution.status, 'outcome_unknown')

    def test_policy_revocation_during_jev_withholds_generation_but_preserves_cost(self):
        self.configure()
        self.simulated_jev(after_request=lambda: CompanyEngine.objects.filter(pk=self.credential.pk).update(active=False))
        self.assertEqual(self.infer()['status'], 'rejected')
        self.assertEqual(self.requests, [])
        self.assertEqual(Decimal(self.receipt()['total']['cost']), Decimal('0.002'))

    def test_cancellation_during_jev_preserves_its_receipt_and_stops_generation(self):
        self.configure()
        self.simulated_jev(after_request=lambda: AgentExecution.objects.filter(pk=self.execution.pk).update(status='cancelled'))
        self.assertEqual(self.infer()['status'], 'rejected')
        self.assertEqual(self.requests, [])
        self.assertEqual(self.receipt()['jev']['status'], 'consulted')
        self.execution.refresh_from_db()
        self.assertEqual(self.execution.status, 'cancelled')

    def test_bounded_unknown_jev_price_blocks_before_provider_dispatch(self):
        self.configure(limits={'budget': '1'})
        captured = self.simulated_jev()
        result = self.infer()
        self.assertEqual(result, {'status': 'rejected', 'code': 'unknown_price'})
        self.assertEqual(captured, [])
        self.assertEqual(self.requests, [])
        self.assertEqual(self.receipt()['jev']['status'], 'not_consulted')
        self.assertFalse(self.receipt()['jev']['consulted'])

    def test_jev_reported_cost_exceeding_bound_is_retained_and_blocks_generator(self):
        self.configure(limits={'budget': '1'}, jev={'input_price': '1', 'output_price': '2', 'max_call_cost': '0.001'})
        self.simulated_jev(cost='0.002')
        result = self.infer()
        self.assertEqual(result, {'status': 'rejected', 'code': 'budget_bound_exceeded'})
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['jev']['status'], 'consulted')
        self.assertEqual(meta['jev']['effect'], 'block')
        self.assertEqual(meta['jev']['reason_codes'], ['budget_bound_exceeded'])
        self.assertEqual(Decimal(meta['total']['cost']), Decimal('0.002'))

    def test_malformed_jev_answers_are_withheld_and_never_displayed_as_explanations(self):
        self.configure()
        answers = classification_answers()
        answers['category']['reasoning'] = 'private@example.invalid'
        self.simulated_jev(answers=answers)
        self.assertEqual(self.infer()['status'], 'outcome_unknown')
        self.assertEqual(self.requests, [])
        meta = self.receipt()
        self.assertEqual(meta['jev']['status'], 'failed')
        self.assertEqual(meta['jev']['reason_codes'], ['invalid_response'])
        self.assertEqual(meta['jev']['signals'], {})
        self.assertNotIn('private@example.invalid', json.dumps(meta))

    def test_all_effective_models_and_purposes_are_retained_without_invented_fallback(self):
        def response(model):
            return ChatResponse(content='Approved response', model=model, input_tokens=100, output_tokens=20,
                finish_reason='stop', usage={'prompt_tokens': 100, 'completion_tokens': 20})

        with patch('front.connectors.OpenAIConnector.chat', side_effect=[response('effective-a'), response('effective-b')]):
            first = self.infer()
            second = self.infer(self.request(purpose='compaction'))
        self.assertEqual(first['status'], 'completed')
        self.assertEqual(second['status'], 'completed')
        meta = self.receipt()
        calls = [call for call in meta['calls'] if call['purpose'] in ('generation', 'compaction')]
        self.assertEqual([call['model_requested'] for call in calls], ['agent-pinned-v1'] * 2)
        self.assertEqual([call['model_effective'] for call in calls], ['effective-a', 'effective-b'])
        self.assertEqual([call['purpose'] for call in calls], ['generation', 'compaction'])
        self.assertEqual([call['sequence'] for call in meta['calls']], list(range(1, len(meta['calls']) + 1)))
        self.assertTrue(all(call['fallback']['status'] == 'not_used' for call in calls))
        self.assertTrue(all(call['route']['mode'] == 'agent_profile' for call in calls))
        self.assertTrue(all(call['started_at'] and call['completed_at'] and call['duration_ms'] >= 0 for call in calls))
        self.assertEqual(first['inference']['model_effective'], 'effective-a')
        self.assertEqual(second['inference']['model_effective'], 'effective-b')
        self.assertEqual(self.prompt.model_used, 'effective-b')
        self.assertEqual(AgentInference.objects.count(), 2)

    def test_each_inference_retains_its_own_jev_evaluation(self):
        self.configure()
        captured = self.simulated_jev()
        self.assertEqual(self.infer()['status'], 'completed')
        self.assertEqual(self.infer(self.request(purpose='compaction'))['status'], 'completed')
        meta = self.receipt()
        calls = [call for call in meta['calls'] if call['purpose'] == 'classification']
        self.assertEqual(len(captured), 2)
        self.assertEqual(len(calls), 2)
        self.assertNotEqual(calls[0]['call_id'], calls[1]['call_id'])
        self.assertEqual(calls[0]['jev']['signals'], classification_answers())
        self.assertEqual(calls[1]['jev']['signals'], classification_answers())

    def test_provider_metadata_cannot_smuggle_secrets_into_receipts(self):
        result = ChatResponse(content='Approved response', model='sk-secret-provider-value',
            provider_request_id='private@example.invalid', input_tokens=10, output_tokens=5,
            finish_reason='stop', usage={'private@example.invalid': 1, 'prompt_tokens': 10})
        with patch('front.connectors.OpenAIConnector.chat', return_value=result):
            self.assertEqual(self.infer()['status'], 'completed')
        meta = self.receipt()
        call = next(call for call in meta['calls'] if call['purpose'] == 'generation')
        self.assertIsNone(call['model_effective'])
        self.assertIsNone(call['provider_request_id'])
        self.assertNotIn('private@example.invalid', json.dumps(meta))
        self.assertNotIn('sk-secret-provider-value', json.dumps(meta))

    def test_json_text_with_secret_at_end_remains_valid_after_masking(self):
        content = json.dumps({'status': 'approved', 'excerpt': 'Public research. api_key=sk-synthetic-secret-value'})
        result = self.infer(self.request(messages=[{'role': 'user', 'content': content}]))
        self.assertEqual(result['status'], 'completed', result)
        sent = self.requests[0]['messages'][-1]['content']
        self.assertNotIn('sk-synthetic-secret-value', sent)
        self.assertIsInstance(json.loads(sent), dict)
        self.assertIn('Public research.', sent)

    def test_jev_configuration_change_revokes_existing_execution(self):
        self.configure()
        self.company.jev_api_key = 'rotated-synthetic-key'
        self.company.save()
        with self.assertRaises(AgentDenied):
            self.infer()
        self.assertEqual(self.requests, [])
