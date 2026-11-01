"""Three real HTTP adapters through claim/bootstrap and the simulated SDK wire."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
from threading import Event
from unittest import skipUnless
from unittest.mock import patch
import uuid

import httpx
from openai import OpenAI
from django.db import close_old_connections, connection
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from front.connectors import get_connector
from front.models import AgentAccessGrant, AgentExecution, AgentInference, AgentOperation, Response
from front.test_agent_inference import AgentFixture


class WorkLimitsFixture(AgentFixture):
    def setUp(self):
        super().setUp()
        self.execution.status = 'completed'
        self.execution.save(update_fields=['status'])
        self.user.username = 'work-limits-synthetic'
        self.user.save()
        from front.agents.capabilities import GENERAL
        self.agent.professional, self.agent.tools = True, sorted(GENERAL)
        self.agent.limits = {'work_profiles': True, 'inference': {'dialect': 'deepseek',
            'model_id': self.model.model_id, 'profiles': ['legacy', 'quick', 'reasoned'],
            'thinking_modes': ['off', 'on'], 'efforts': ['high']}}
        self.agent.save()
        self.model.engine.connector_type = 'openai_compatible'
        self.model.engine.save(update_fields=['connector_type'])
        self.company.ai_config['routing'] = {'max_output_tokens': 8192}
        self.company.save()
        self.grant = AgentAccessGrant.objects.create(company=self.company, user=self.user,
            profile=self.agent, enabled=True)
        self.worker_token = 'work-limits-synthetic-worker-key-32-characters'
        self.enterContext(override_settings(REGULAY_AGENT_WORKER_TOKEN=self.worker_token))
        self.client.force_login(self.user)
        self.include_usage = True
        self.timeouts = []

        def http(request):
            self.requests.append(json.loads(request.content))
            self.timeouts.append(request.extensions.get('timeout', {}))
            if self.provider_error:
                raise self.provider_error
            if self.after_request:
                self.after_request()
            message = {'role': 'assistant', 'content': None if self.reply_calls else 'Madrid es la capital de España.',
                'reasoning_content': 'PRIVATE_THINKING_SENTINEL', 'reasoning': 'PRIVATE_THINKING_SENTINEL',
                'reasoning_details': [{'signature': 'PRIVATE_SIGNATURE_SENTINEL'}]}
            if self.reply_calls:
                message['tool_calls'] = [{'id': call['id'], 'type': 'function', 'function': {
                    'name': call['name'], 'arguments': json.dumps(call['args'])}} for call in self.reply_calls]
            return httpx.Response(200, json={'id': 'synthetic-work-profile', 'object': 'chat.completion',
                'created': 1, 'model': self.model.model_id, 'choices': [{'index': 0, 'message': message,
                    'finish_reason': 'tool_calls' if self.reply_calls else 'stop'}],
                **({'usage': {'prompt_tokens': 20, 'completion_tokens': 10, 'total_tokens': 30}} if self.include_usage else {})})

        def connector(kind, key, base_url):
            result = get_connector(kind, key, base_url)
            result.client.close()
            result.client = OpenAI(api_key='synthetic-key', base_url='https://provider.invalid/v1', max_retries=0,
                http_client=httpx.Client(transport=httpx.MockTransport(http), follow_redirects=False))
            self.addCleanup(result.client.close)
            return result
        self.enterContext(patch('front.agents.service.get_connector', side_effect=connector))
        self.enterContext(patch('socket.create_connection', side_effect=AssertionError('Unmocked sockets forbidden')))

    def send(self, url='/chat/send/', selection='quick', *, identity=None, text='Dime la capital de España'):
        response = self.client.post(url, {'prompt': text, 'content': text, 'mode': 'agent',
            'request_id': str(identity or uuid.uuid4()), 'inference_profile': selection})
        self.assertEqual(response.status_code, 202, response.content)
        return AgentExecution.objects.get(pk=response.json()['agent']['id'])

    def start(self, run, *, expected_model_calls=3, expected_tool_calls=4):
        response = self.client.post('/internal/agents/claim/', json.dumps({'worker_id': str(uuid.uuid4()),
            'claim_id': str(uuid.uuid4()), 'worker_protocol': 2}), content_type='application/json', HTTP_AUTHORIZATION='Bearer ' + self.worker_token)
        self.assertEqual(response.status_code, 200, response.content)
        value = response.json()
        self.assertEqual(value.get('execution'), str(run.pk), value)
        run.refresh_from_db()
        self.execution, self.token = run, value['token']
        boot = self.internal('run/bootstrap', {})
        self.assertEqual(boot.status_code, 200, boot.content)
        self.assertEqual(boot.json()['limits']['model_calls'], expected_model_calls)
        self.assertEqual(boot.json()['limits']['tool_calls'], expected_tool_calls)

    def internal(self, endpoint, payload):
        return self.client.post('/internal/agents/' + endpoint + '/', json.dumps(payload),
            content_type='application/json', HTTP_AUTHORIZATION='Bearer ' + self.token,
            HTTP_X_REGULAY_ATTEMPT=str(self.execution.attempt))

    def ask(self, *, tools=None, messages=None, identity=None):
        payload = {'call_id': str(identity or uuid.uuid4()), 'tools': tools or [],
            'messages': messages or [{'role': 'user', 'content': 'Dime la capital de España'}]}
        response = self.internal('inference', payload)
        self.assertEqual(response.status_code, 200, response.content)
        return payload, response.json()


@skipUnless(connection.vendor == 'postgresql', 'The real worker claim requires PostgreSQL')
@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_CAPACITY={'provider': 2})
class WorkLimitsHTTPTests(WorkLimitsFixture, TestCase):
    def test_all_three_entries_preserve_selection_through_sdk_complete_and_replay(self):
        original = deepcopy(self.company.ai_config)
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            for selection in ('quick', 'reasoned'):
                with self.subTest(url=url, selection=selection):
                    identity = uuid.uuid4()
                    run = self.send(url, selection, identity=identity)
                    self.assertEqual(self.send(url, selection, identity=identity).pk, run.pk)
                    self.start(run)
                    payload, reply = self.ask()
                    self.assertEqual(reply['status'], 'completed', reply)
                    wire = self.requests[-1]
                    self.assertEqual(wire['thinking'], {'type': 'disabled' if selection == 'quick' else 'enabled'})
                    self.assertEqual(wire['max_tokens'], 4096 if selection == 'quick' else 8000)
                    self.assertNotIn('max_completion_tokens', wire)
                    self.assertEqual(wire.get('reasoning_effort'), None if selection == 'quick' else 'high')
                    count = len(self.requests)
                    self.assertEqual(self.internal('inference', payload).json(), reply)
                    result = self.internal('run/complete', {'final_call_id': payload['call_id']})
                    self.assertEqual(result.status_code, 200, result.content)
                    self.assertTrue(result.json()['completed'])
                    again = self.internal('run/complete', {'final_call_id': payload['call_id']})
                    self.assertEqual(again.status_code, 200, again.content)
                    self.assertEqual(len(self.requests), count)
                    self.assertEqual(Response.objects.filter(prompt=run.prompt).count(), 1)
                    run.refresh_from_db()
                    run.prompt.refresh_from_db()
                    self.assertNotIn('PRIVATE_', json.dumps([run.job, run.prompt.decision,
                        list(run.agentinference_set.values_list('response', flat=True)), run.prompt.response.content]))
                    self.assertEqual(reply['inference']['inference_options']['observed_thinking_mode'], 'unknown')
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config, original)

    def test_reasoned_tools_use_quick_then_reasoned_conclusion(self):
        run = self.send(selection='reasoned')
        self.start(run)
        call = {'id': 'ls-one', 'name': 'ls', 'args': {'path': '/workspace'}}
        self.reply_calls = [call]
        _, reply = self.ask(tools=['ls'])
        self.assertEqual(reply['status'], 'completed', reply)
        self.assertEqual(self.requests[-1]['thinking'], {'type': 'disabled'})
        granted = self.internal('authorize-tool', call)
        self.assertEqual(granted.status_code, 200, granted.content)
        result = self.internal('tool-results', {'call': call, 'raw': {'content': 'empty'}, 'failed': False})
        self.assertEqual(result.status_code, 200, result.content)
        self.reply_calls = []
        _, final = self.ask(messages=[{'role': 'assistant', 'content': '', 'tool_calls': [call]},
            {'role': 'tool', 'name': 'ls', 'tool_call_id': call['id'],
                'content': json.dumps(result.json(), sort_keys=True, ensure_ascii=False)}])
        self.assertEqual(final['status'], 'completed', final)
        self.assertEqual(self.requests[-1]['thinking'], {'type': 'enabled'})
        self.assertNotIn('tools', self.requests[-1])

    def test_three_entries_reject_unapproved_selection_and_idempotency_changes_before_network(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(url=url):
                identity = uuid.uuid4()
                self.send(url, 'quick', identity=identity)
                changed = self.client.post(url, {'prompt': 'Dime la capital de España',
                    'content': 'Dime la capital de España', 'mode': 'agent', 'request_id': str(identity),
                    'inference_profile': 'reasoned'})
                self.assertEqual(changed.status_code, 409, changed.content)
                invalid = self.client.post(url, {'prompt': 'Dime la capital de España',
                    'content': 'Dime la capital de España', 'mode': 'agent', 'request_id': str(uuid.uuid4()),
                    'inference_profile': 'unapproved'})
                self.assertEqual(invalid.status_code, 403, invalid.content)
        self.assertEqual(self.requests, [])

    def test_model_ceiling_strips_last_tools_and_interrupts_without_fourth_call(self):
        self.start(self.send())
        for index in range(3):
            payload, result = self.ask(tools=['ls'])
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual('tools' in self.requests[-1], index < 2)
        self.assertEqual(AgentInference.objects.filter(execution=self.execution).count(), 3)
        _, stopped = self.ask()
        self.assertIn(stopped['status'], ('interrupted', 'failed'))
        self.assertEqual(len(self.requests), 3)
        self.execution.refresh_from_db()
        self.execution.prompt.refresh_from_db()
        self.assertEqual(self.execution.status, 'interrupted')
        self.assertFalse(self.execution.prompt.decision.get('history_eligible', False))

    def test_tool_ceiling_and_replay_do_not_add_operations(self):
        self.start(self.send())
        self.reply_calls = [{'id': 'ls-' + str(n), 'name': 'ls', 'args': {'path': '/workspace'}} for n in range(5)]
        _, result = self.ask(tools=['ls'])
        self.assertEqual(result['status'], 'completed', result)
        for call in result['tool_calls'][:4]:
            self.assertEqual(self.internal('authorize-tool', call).status_code, 200)
            finished = self.internal('tool-results', {'call': call, 'raw': {'content': 'empty'}, 'failed': False})
            self.assertEqual(finished.status_code, 200, finished.content)
            replay = self.internal('authorize-tool', call)
            self.assertEqual(replay.status_code, 200, replay.content)
            self.assertIn('replay', replay.json())
        denied = self.internal('authorize-tool', result['tool_calls'][4])
        self.assertEqual(denied.status_code, 403, denied.content)
        self.assertEqual(denied.json()['code'], 'agent_tool_budget_exhausted')
        self.assertEqual(AgentOperation.objects.filter(execution=self.execution).count(), 4)

    def test_time_reserve_and_hard_deadline_apply_with_provider_managed(self):
        self.start(self.send())
        AgentExecution.objects.filter(pk=self.execution.pk).update(started_at=timezone.now() - timedelta(seconds=52))
        _, result = self.ask(tools=['ls'])
        self.assertEqual(result['status'], 'completed', result)
        self.assertNotIn('tools', self.requests[-1])
        self.assertLessEqual(self.timeouts[-1]['read'], 8)
        AgentExecution.objects.filter(pk=self.execution.pk).update(started_at=timezone.now() - timedelta(seconds=61))
        _, stopped = self.ask()
        self.assertIn(stopped['status'], ('interrupted', 'failed'))
        self.assertEqual(len(self.requests), 1)

    def test_missing_usage_cancel_replay_preserve_unknown_cost_and_release_physical_slot(self):
        self.start(self.send())
        self.include_usage = False
        terminal = {}
        def cancel():
            response = self.client.post('/chat/agent/runs/' + str(self.execution.pk) + '/cancel/')
            self.assertEqual(response.status_code, 200, response.content)
            prompt = AgentExecution.objects.select_related('prompt').get(pk=self.execution.pk).prompt
            terminal['delivery'] = deepcopy(prompt.decision['delivery'])
            terminal['response_id'] = prompt.response.pk
            terminal['response_content'] = prompt.response.content
            terminal['evidence'] = deepcopy(prompt.response.evidence)
        self.after_request = cancel
        payload, result = self.ask()
        self.assertNotEqual(result['status'], 'completed')
        self.execution.prompt.refresh_from_db()
        total = deepcopy(self.execution.prompt.decision['total'])
        self.assertEqual(self.execution.prompt.decision.get('delivery'), terminal['delivery'])
        self.assertIs(self.execution.prompt.decision.get('history_eligible'), False)
        self.assertEqual(self.execution.prompt.decision.get('error_type'), 'cancelled_by_user')
        partial = Response.objects.get(prompt=self.execution.prompt)
        self.assertEqual((partial.pk, partial.content, partial.evidence),
            (terminal['response_id'], terminal['response_content'], terminal['evidence']))
        self.assertTrue(partial.evidence['partial'])
        self.assertIsNone(total['cost'])
        self.assertFalse(total['complete'])
        row = AgentInference.objects.get(execution=self.execution)
        self.assertEqual(row.response['_capacity']['state'], 'released')
        self.assertEqual(self.internal('inference', payload).status_code, 403)
        self.assertEqual(len(self.requests), 1)
        self.execution.prompt.refresh_from_db()
        self.assertEqual(self.execution.prompt.decision['total'], total)


@skipUnless(connection.vendor == 'postgresql', 'The real concurrent claims require PostgreSQL')
@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_CAPACITY={'provider': 2})
class CapacityHTTPConcurrencyTests(WorkLimitsFixture, TransactionTestCase):
    def test_three_entries_short_http_turn_finishes_while_simulation_provider_is_held(self):
        for url in ('/chat/', '/chat/send/', '/api/chat/send/'):
            with self.subTest(url=url):
                long_run = self.send(url, text='Simula una distribución con Monte Carlo y responde en el chat')
                short_run = self.send(url)
                self.start(long_run, expected_model_calls=8, expected_tool_calls=16)
                long_token, long_attempt = self.token, self.execution.attempt
                reservation = str(uuid.uuid4())
                reserve = self.internal('run/sandbox', {'action': 'reserve', 'reservation_id': reservation})
                self.assertEqual(reserve.status_code, 200, reserve.content)
                self.assertTrue(reserve.json()['available'])
                attached = self.internal('run/sandbox', {'action': 'attach', 'reservation_id': reservation,
                    'sandbox_id': 'synthetic-vm-' + reservation, 'ttl_seconds': 180})
                self.assertEqual(attached.status_code, 200, attached.content)
                self.start(short_run)
                short_token, short_attempt = self.token, self.execution.attempt
                entered, release = Event(), Event()
                before = len(self.requests)

                def hold_first():
                    if len(self.requests) == before + 1:
                        entered.set()
                        if not release.wait(20):
                            raise AssertionError('Short request failed to finish before release.')
                self.after_request = hold_first
                long_call, short_call = str(uuid.uuid4()), str(uuid.uuid4())

                def inference(token, attempt, call_id):
                    close_old_connections()
                    try:
                        response = Client().post('/internal/agents/inference/', json.dumps({
                            'call_id': call_id, 'messages': [{'role': 'user', 'content': 'Dime la capital de España'}],
                            'tools': []}), content_type='application/json', HTTP_AUTHORIZATION='Bearer ' + token,
                            HTTP_X_REGULAY_ATTEMPT=str(attempt))
                        return response.status_code, response.json()
                    finally:
                        close_old_connections()

                with ThreadPoolExecutor(max_workers=2) as pool:
                    pending = pool.submit(inference, long_token, long_attempt, long_call)
                    self.assertTrue(entered.wait(15))
                    try:
                        short = pool.submit(inference, short_token, short_attempt, short_call).result(15)
                        self.assertEqual(short[0], 200, short)
                        self.assertEqual(short[1]['status'], 'completed', short)
                        complete = self.internal('run/complete', {'final_call_id': short_call})
                        self.assertEqual(complete.status_code, 200, complete.content)
                        self.assertTrue(complete.json()['completed'])
                        self.assertFalse(pending.done())
                        self.assertEqual(AgentExecution.objects.filter(job__sandbox_reservation__state='active').count(), 1)
                        self.assertEqual(Response.objects.filter(prompt=short_run.prompt).count(), 1)
                    finally:
                        release.set()
                    result = pending.result(15)
                    self.assertEqual(result[1]['status'], 'completed', result)
                self.after_request = None
                self.execution, self.token = long_run, long_token
                self.execution.attempt = long_attempt
                done = self.internal('run/complete', {'final_call_id': long_call})
                self.assertEqual(done.status_code, 200, done.content)
                long_run.refresh_from_db()
                cleanup = self.client.post('/internal/agents/sandbox-cleanup/', json.dumps({
                    'execution': str(long_run.pk), 'attempt': str(long_attempt),
                    'worker_id': str(long_run.worker_id), 'reservation_id': reservation,
                    'sandbox_id': 'synthetic-vm-' + reservation, 'destroyed': True}),
                    content_type='application/json', HTTP_AUTHORIZATION='Bearer ' + self.worker_token)
                self.assertEqual(cleanup.status_code, 200, cleanup.content)
