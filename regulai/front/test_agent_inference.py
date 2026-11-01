"""Task 49: actual OpenAI SDK, simulated provider HTTP; private application API."""
import base64
import json
from pathlib import Path
import subprocess
import uuid
from decimal import Decimal
from unittest.mock import patch

import httpx
from openai import OpenAI
from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase, LiveServerTestCase, override_settings
from django.utils import timezone

from front.connectors import OpenAIConnector
from front.models import (AgentExecution, AgentInference, AgentInput, AgentModelProfile, AgentToolResult,
    Company, CompanyEngine, Conversation, ConversationAlias, Engine, EngineModel, ObfuscationConfig, Profile, Prompt, Rule, RulesGroup)
from front.policy import digest
from front.agents.aliases import alias_text, alias_value, resolve_for_operation
from front.agents.data_views import grant_csv, render_approved_view, tool_result
from front.agents.service import AgentDenied, begin_execution, infer

CSV = 'item,amount_cents\nsynthetic-a,125\nsynthetic-b,250\nsynthetic-c,375\n'
CALL = {'id': 'task49-csv-1', 'name': 'csv_totals', 'args': {'input_path': '/workspace/input/numbers.csv'}}


class AgentFixture:
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('agent-synthetic', password='synthetic')
        self.company = Company.objects.create(name='Task49 synthetic')
        self.profile = Profile.objects.create(user=self.user, company=self.company)
        self.conversation = Conversation.objects.create(user=self.user)
        engine = Engine.objects.create(name='Task49', connector_type='openai', base_url='https://provider.invalid/v1')
        self.model = EngineModel.objects.create(engine=engine, name='Explicit agent model', model_id='agent-pinned-v1',
            context_window=200000, max_tokens=8000, input_price='1', output_price='2', supports_vision=True)
        self.credential = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-provider-key')
        self.mask = ObfuscationConfig.objects.create(company=self.company, name='Local', backend='local', detect='both')
        self.company.ai_config = {'version': 1, 'local_sensitivity': 'internal', 'allow_empty_rules': True,
            'masking': {'max_call_cost': '0'}, 'destinations': {'internal': [
                f'engine:{self.credential.pk}', f'obfuscation:{self.mask.pk}']}, 'limits': {'provider_managed': True}}
        self.company.save()
        self.agent = AgentModelProfile.objects.create(company=self.company, name='Task49 explicit', enabled=True,
            connection=self.credential, model=self.model, tools=['csv_totals', 'inspect_csv', 'read_file', 'execute',
                'ls', 'glob', 'grep', 'write_file', 'edit_file', 'write_todos'])
        self.prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=self.conversation,
            status='processing', content='Sum the authorized CSV', decision={'calls': []})
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)
        self.asset = grant_csv(self.execution, path='/workspace/input/numbers.csv', content=CSV)
        self.requests = []
        self.reply_calls = []
        self.after_request = None
        self.provider_error = None

        def http(request):
            self.requests.append(json.loads(request.content))
            if self.provider_error:
                raise self.provider_error
            if self.after_request:
                self.after_request()
            calls = self.reply_calls
            message = {'role': 'assistant', 'content': None if calls else 'Approved synthetic answer.'}
            if calls:
                message['tool_calls'] = [{'id': c['id'], 'type': 'function', 'function': {
                    'name': c['name'], 'arguments': json.dumps(c['args'])}} for c in calls]
            return httpx.Response(200, json={'id': 'synthetic-provider-request', 'object': 'chat.completion',
                'created': 1, 'model': 'agent-pinned-v1', 'choices': [{'index': 0, 'message': message,
                    'finish_reason': 'tool_calls' if calls else 'stop'}],
                'usage': {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120}})

        def connector(*args):
            result = OpenAIConnector(*args[1:])
            result.client.close()
            result.client = OpenAI(api_key='synthetic-provider-key', base_url='https://provider.invalid/v1',
                max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(http), follow_redirects=False))
            self.addCleanup(result.client.close)
            return result
        self.enterContext(patch('front.agents.service.get_connector', side_effect=connector))

    def request(self, **extra):
        return {'call_id': str(uuid.uuid4()), 'messages': [{'role': 'user', 'content': 'Authorized task'}], **extra}

    def infer(self, request=None):
        return infer(self.token, self.execution.attempt, request or self.request())

    def issue_tool(self, call=CALL):
        self.reply_calls = [call]
        result = self.infer(self.request(tools=[call['name']]))
        self.assertEqual(result['status'], 'completed', result)
        self.reply_calls = []
        return call


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentInferenceTests(AgentFixture, TestCase):
    def test_native_roundtrip_replay_and_single_charge(self):
        self.reply_calls = [CALL]
        request = self.request(tools=['csv_totals'])
        first = self.infer(request)
        self.assertEqual(first['status'], 'completed', first)
        self.assertEqual(first, self.infer(request))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0]['model'], 'agent-pinned-v1')
        self.assertNotIn('max_tokens', self.requests[0])
        self.assertNotIn('max_completion_tokens', self.requests[0])
        view = tool_result(self.token, self.execution.attempt, {'call': CALL,
            'raw': {'content': '{"rows":3,"total_cents":750}', 'stderr': 'Nombre: Sintetico Privado'}})
        self.assertEqual(view, {'status': 'approved', 'rows': 3, 'total_cents': 750})
        self.reply_calls = []
        second = self.request(messages=[{'role': 'assistant', 'content': '', 'tool_calls': [CALL]},
            {'role': 'tool', 'name': 'csv_totals', 'tool_call_id': CALL['id'], 'content': json.dumps(view, sort_keys=True)}])
        self.assertEqual(self.infer(second)['status'], 'completed')
        self.assertEqual(self.requests[-1]['messages'][-1]['tool_call_id'], CALL['id'])
        self.assertNotIn('Sintetico', json.dumps(self.requests))
        self.prompt.refresh_from_db()
        self.assertEqual(self.prompt.decision['total']['attempts'], 2)
        self.assertTrue(all(c['execution_id'] == str(self.execution.pk) for c in self.prompt.decision['calls']))
        self.assertEqual(self.prompt.model_used, 'agent-pinned-v1')
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00028'))
        self.assertEqual(AgentInference.objects.count(), 2)
        with self.assertRaises(AgentDenied):
            self.infer({**request, 'purpose': 'compaction'})

    def test_provider_uncertainty_never_resends_or_invents_zero_cost(self):
        self.provider_error = httpx.ReadTimeout('Nombre: Sintetico Privado')
        request = self.request()
        result = self.infer(request)
        self.assertEqual(result['status'], 'outcome_unknown')
        self.assertEqual(self.infer(request), result)
        self.assertEqual(len(self.requests), 1)
        self.prompt.refresh_from_db()
        self.assertIsNone(self.prompt.decision['total']['cost'])
        self.assertFalse(self.prompt.decision['total']['complete'])
        with self.assertRaises(AgentDenied):
            self.infer()

    def test_revocation_between_steps_and_during_call(self):
        self.assertEqual(self.infer()['status'], 'completed')
        CompanyEngine.objects.filter(pk=self.credential.pk).update(active=False)
        with self.assertRaises(AgentDenied):
            self.infer()
        self.assertEqual(len(self.requests), 1)
        CompanyEngine.objects.filter(pk=self.credential.pk).update(active=True)
        self.after_request = lambda: User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.infer()['status'], 'rejected')
        self.prompt.refresh_from_db()
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00028'))

    def test_credentials_attempt_and_identity_cannot_be_supplied_in_body(self):
        for token, attempt in [('', self.execution.attempt), (self.token, uuid.uuid4())]:
            with self.assertRaises(AgentDenied):
                infer(token, attempt, self.request())
        for field in ('model', 'base_url', 'user_id', 'company_id', 'permissions', 'conversation_id', 'execution_id'):
            response = self.client.post('/internal/agents/inference/', json.dumps(self.request(**{field: 'chosen'})),
                content_type='application/json', HTTP_AUTHORIZATION='Bearer ' + self.token,
                HTTP_X_REGULAY_ATTEMPT=str(self.execution.attempt))
            self.assertEqual(response.status_code, 400, field)
        self.assertEqual(len(self.requests), 0)
        AgentExecution.objects.filter(pk=self.execution.pk).update(expires_at=timezone.now())
        with self.assertRaises(AgentDenied):
            self.infer()

    def test_profiles_are_explicit_and_feature_off_by_default(self):
        self.agent.enabled = False
        self.agent.save()
        with self.assertRaises(AgentDenied):
            self.infer()
        with override_settings(REGULAY_AGENT_ENABLED=False):
            with self.assertRaises(AgentDenied):
                begin_execution(self.prompt, self.agent.pk)
        self.assertEqual(len(self.requests), 0)

    def test_aliases_are_stable_typed_encrypted_and_scoped(self):
        a = alias_text(self.execution, 'Nombre: Ana López; ana@example.COM; 12345678-Z')
        b = alias_text(AgentExecution.objects.get(pk=self.execution.pk), 'Nombre: Ana López; ana@example.com; 12345678Z')
        self.assertEqual(a, b)
        self.assertNotIn('Ana López', a)
        self.assertEqual(alias_text(self.execution, 'Tengo A y B en Madrid'), 'Tengo A y B en Madrid')
        self.assertNotEqual(alias_value(self.execution, 'PERSON', 'Ana López'), alias_value(self.execution, 'PERSON', 'ana lopez'))
        other = Conversation.objects.create(user=self.user)
        prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=other, content='other', status='processing')
        execution, _ = begin_execution(prompt, self.agent.pk)
        self.assertNotEqual(a, alias_text(execution, 'Nombre: Ana López; ana@example.com; 12345678Z'))
        token = alias_value(self.execution, 'PERSON', 'Ana López')
        with self.assertRaises(ValueError):
            resolve_for_operation(execution, [token], operation='local_document_fields')
        with self.assertRaises(ValueError):
            alias_text(execution, token)
        with connection.cursor() as cursor:
            cursor.execute('SELECT original FROM front_conversationalias WHERE token = %s', [token])
            raw = cursor.fetchone()[0]
        self.assertNotIn('Ana', raw)
        self.assertEqual(resolve_for_operation(self.execution, [token], operation='local_document_fields')[token], 'Ana López')
        before = ConversationAlias.objects.count()
        self.assertIn('[[REGULAI_SECRET]]', alias_text(self.execution, 'api_key=sk-syntheticsecrethere'))
        self.assertEqual(ConversationAlias.objects.count(), before)

    def test_tool_views_withhold_raw_files_logs_exceptions_and_forged_aggregates(self):
        for index, name in enumerate(['read_file', 'execute', 'csv_totals']):
            args = {'file_path': '/workspace/input/numbers.csv'} if name == 'read_file' else (
                {'command': 'python synthetic.py'} if name == 'execute' else CALL['args'])
            call = {'id': f'raw-{index}', 'name': name, 'args': args}
            self.issue_tool(call)
            payload = {'call': call, 'raw': {'content': '{"rows":3,"total_cents":999}',
                'stdout': 'ana@example.com', 'stderr': 'Nombre: Ana López', 'artifact': {'data': 'base64-original'}},
                'failed': name == 'execute'}
            view = tool_result(self.token, self.execution.attempt, payload)
            self.assertEqual(view['status'], 'withheld')
            self.assertNotIn('Ana', json.dumps(view))
            self.assertEqual(view, tool_result(self.token, self.execution.attempt, payload))
            self.assertIn('Ana López', AgentToolResult.objects.get(call_id=call['id']).raw)
        request = self.request(messages=[{'role': 'tool', 'content': 'ana@example.com',
            'name': 'read_file', 'tool_call_id': 'raw-0'}])
        self.assertEqual(self.infer(request)['status'], 'rejected')
        self.assertEqual(len(self.requests), 3)

    def test_small_groups_and_unapproved_images_are_denied(self):
        self.agent.min_group_size = 4
        self.agent.save()
        with self.assertRaises(AgentDenied):
            self.infer()  # Profile edit revokes the attempt.
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)
        grant_csv(self.execution, path='/workspace/input/numbers.csv', content=CSV)
        self.issue_tool()
        view = tool_result(self.token, self.execution.attempt, {'call': CALL,
            'raw': {'content': '{"rows":3,"total_cents":750}'}})
        self.assertEqual(view['code'], 'aggregate_group_too_small')
        with self.assertRaises(AgentDenied):
            render_approved_view(self.execution, AgentToolResult.objects.get(execution=self.execution, call_id=CALL['id']))

    def test_yara_runs_before_alias_replacement_on_each_surface(self):
        group = RulesGroup.objects.create(name='Agent YARA', company=self.company)
        Rule.objects.create(name='Block explicit email', rules_group=group,
            yara_rule='rule Synthetic { strings: $s = "blocked@example.invalid" condition: $s }')
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)
        for purpose in ('generation', 'compaction'):
            result = self.infer(self.request(purpose=purpose, messages=[{'role': 'user', 'content': 'blocked@example.invalid'}]))
            self.assertEqual(result['status'], 'rejected')
        self.assertEqual(len(self.requests), 0)
        self.assertEqual(ConversationAlias.objects.count(), 0)

    def test_context_company_and_mandatory_policy_changes_revoke(self):
        self.company.system_prompt = 'New mandatory instructions'
        self.company.save()
        with self.assertRaises(AgentDenied):
            self.infer()
        self.company.system_prompt = ''
        self.company.ai_config['classification'] = 'required'
        self.company.save()
        with self.assertRaises(AgentDenied) as error:
            self.infer()
        self.assertEqual(error.exception.code, 'agent_policy_denied')
        self.assertEqual(len(self.requests), 0)

    def test_structure_and_explicit_fields_have_stable_references(self):
        call = {**CALL, 'name': 'inspect_csv'}
        self.issue_tool(call)
        view = tool_result(self.token, self.execution.attempt, {'call': call, 'raw': {'content': 'synthetic-a'}})
        self.assertEqual(view['status'], 'approved')
        self.assertEqual(view['rows'], 3)
        self.assertNotIn('synthetic-a', json.dumps(view))
        self.assertTrue(all(c['reference'].startswith('[[R_FIELD_') for c in view['columns']))
        from front.agents.service import _protect_tree
        protected = _protect_tree(self.execution, {'nombre': 'Ana Lopez', 'api_key': 'synthetic-secret'})
        self.assertEqual(protected['nombre'], alias_value(self.execution, 'PERSON', 'Ana Lopez'))
        self.assertEqual(protected['api_key'], '[[REGULAI_SECRET]]')
        self.assertEqual(_protect_tree(self.execution, protected), protected)
        before = ConversationAlias.objects.count()
        self.assertEqual(alias_value(self.execution, 'PERSON', 'sk-syntheticsecrethere'), '[[REGULAI_SECRET]]')
        self.assertEqual(ConversationAlias.objects.count(), before)

    def test_reapplying_d2_preserves_alias_even_when_random_digits_match_card(self):
        token = alias_value(self.execution, 'EMAIL', 'a@example.invalid')
        token_with_card = '[[R_EMAIL_4111111111111111aaaaaaaaaaaaaaaa]]'
        ConversationAlias.objects.filter(token=token).update(token=token_with_card)
        request = self.request(messages=[{'role': 'user', 'content': token_with_card}])
        self.assertEqual(self.infer(request)['status'], 'completed')
        self.assertIn(token_with_card, json.dumps(self.requests))
        self.assertNotIn('REGULAY_ALIAS_', json.dumps(self.requests))

    def test_compaction_and_approved_vision_use_same_government(self):
        request = self.request(purpose='compaction', messages=[{'role': 'user', 'content': 'Resumen: ana@example.com'}])
        self.assertEqual(self.infer(request)['status'], 'completed')
        self.assertNotIn('ana@example', json.dumps(self.requests))
        self.agent.vision = True
        self.agent.save()
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)
        grant_csv(self.execution, path='/workspace/input/numbers.csv', content=CSV)
        self.issue_tool()
        tool_result(self.token, self.execution.attempt, {'call': CALL, 'raw': {'content': '{"rows":3,"total_cents":750}'}})
        image = render_approved_view(self.execution, AgentToolResult.objects.get(execution=self.execution, call_id=CALL['id']))
        request = self.request(purpose='vision', messages=[{'role': 'user', 'content': [
            {'type': 'text', 'text': 'Review'}, {'type': 'image_ref', 'reference': str(image.pk)}]}])
        self.assertEqual(self.infer(request)['status'], 'completed')
        self.assertEqual(self.requests[-1]['messages'][-1]['content'][-1]['type'], 'image_url')
        request['call_id'] = str(uuid.uuid4())
        # A numeric-looking opaque reference must not be masked as card/phone data.
        request['messages'][0]['content'][-1]['reference'] = '12345678-1234-1234-1234-123456789012'
        self.assertEqual(self.infer(request)['status'], 'rejected')
        self.assertEqual(len(self.requests), 3)

    def protection(self, call_id):
        """Masking calls for one inference's request messages (its reply is always masked too)."""
        self.prompt.refresh_from_db()
        calls = [c for c in self.prompt.decision['calls'] if c.get('call_id') == call_id]
        generation = next(c for c in calls if c['purpose'] == 'generation')
        return sum(c['purpose'] == 'obfuscation' for c in calls) - 1, generation['protection']

    def test_protected_history_is_reused_and_only_new_messages_are_masked(self):
        history = [{'role': 'user', 'content': 'Contacto: ana@example.com, teléfono 612 345 678'},
                   {'role': 'assistant', 'content': 'Entendido.'}]
        first = self.request(messages=history)
        self.assertEqual(self.infer(first)['status'], 'completed')
        self.assertEqual(self.protection(first['call_id']), (2, {'reused': 0, 'protected': 2}))
        second = self.request(messages=history + [{'role': 'user', 'content': 'Sigue con ana@example.com'}])
        self.assertEqual(self.infer(second)['status'], 'completed')
        self.assertEqual(self.protection(second['call_id']), (1, {'reused': 2, 'protected': 1}))
        # The provider sees exactly the same protected history, never the original values.
        self.assertEqual(self.requests[1]['messages'][:2], self.requests[0]['messages'][:2])
        sent = json.dumps(self.requests, ensure_ascii=False)
        self.assertNotIn('ana@example', sent)
        self.assertNotIn('612 345 678', sent)

    def test_changed_history_message_is_protected_again(self):
        first = self.request(messages=[{'role': 'user', 'content': 'Contacto: ana@example.com'}])
        self.assertEqual(self.infer(first)['status'], 'completed')
        changed = self.request(messages=[{'role': 'user', 'content': 'Contacto: luis@example.com'}])
        self.assertEqual(self.infer(changed)['status'], 'completed')
        self.assertEqual(self.protection(changed['call_id']), (1, {'reused': 0, 'protected': 1}))
        self.assertNotIn('luis@example', json.dumps(self.requests))

    def test_new_content_is_still_checked_when_history_is_reused(self):
        group = RulesGroup.objects.create(name='Agent YARA', company=self.company)
        Rule.objects.create(name='Block explicit email', rules_group=group,
            yara_rule='rule Synthetic { strings: $s = "blocked@example.invalid" condition: $s }')
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)
        history = [{'role': 'user', 'content': 'Resume el informe'}]
        self.assertEqual(self.infer(self.request(messages=history))['status'], 'completed')
        blocked = self.request(messages=history + [{'role': 'user', 'content': 'blocked@example.invalid'}])
        self.assertEqual(self.infer(blocked)['status'], 'rejected')
        self.assertEqual(len(self.requests), 1)

    def test_policy_or_mask_change_during_a_step_stops_it_even_with_reused_history(self):
        from front.agents import service
        history = [{'role': 'user', 'content': 'Resume el informe'}]
        self.assertEqual(self.infer(self.request(messages=history))['status'], 'completed')
        group = RulesGroup.objects.create(name='Mid-step', company=self.company)
        changes = {
            'new rule': (lambda: Rule.objects.create(name='New rule', rules_group=group,
                yara_rule='rule MidStep { strings: $s = "never-present-token" condition: $s }'),
                lambda: Rule.objects.filter(rules_group=group).delete()),
            'mask change': (lambda: ObfuscationConfig.objects.filter(pk=self.mask.pk).update(language='en'),
                lambda: ObfuscationConfig.objects.filter(pk=self.mask.pk).update(language=self.mask.language)),
        }
        original = service._classify
        for name, (change, undo) in changes.items():
            # Every message comes from the cache: only the generation check can notice.
            def classify(*args, change=change):
                change()
                return original(*args)
            request = self.request(messages=history)
            with self.subTest(change=name), patch('front.agents.service._classify', side_effect=classify):
                result = self.infer(request)
                self.assertEqual(result['status'], 'rejected')
                self.assertIn(result['code'], ('agent_authorization_changed', 'authorization_changed', 'security_check_failed'))
                self.prompt.refresh_from_db()
                self.assertFalse([c for c in self.prompt.decision['calls']
                                  if c.get('call_id') == request['call_id'] and c['purpose'] == 'obfuscation'])
            undo()
        self.assertEqual(len(self.requests), 1)

    def test_protection_key_separates_runs_attempts_authorizations_and_content(self):
        from types import SimpleNamespace
        from front.agents.protocol import WireMessage
        from front.agents.service import _protection_key
        def key(pk='e1', attempt='a1', binding='b1', fingerprint='f1', mask='m1', content='x'):
            return _protection_key(SimpleNamespace(pk=pk, attempt=attempt), ('context', binding),
                SimpleNamespace(decision=SimpleNamespace(fingerprint=fingerprint), mask_identities={1: mask}),
                WireMessage(role='user', content=content))
        base = key()
        self.assertEqual(base, key())
        for change in ({'pk': 'e2'}, {'attempt': 'a2'}, {'binding': 'b2'}, {'fingerprint': 'f2'},
                       {'mask': 'm2'}, {'content': 'y'}):
            with self.subTest(change=change):
                self.assertNotEqual(base, key(**change))

    def test_protected_history_is_bounded_and_forgets_finished_runs(self):
        from front.agents.service import ProtectedHistory
        history = ProtectedHistory(10)
        history.put(('e1', 'a'), '12345')
        history.put(('e1', 'b'), '12345')
        history.put(('e2', 'c'), '1234')
        self.assertIsNone(history.get(('e1', 'a')))  # Least recently used goes first.
        self.assertEqual((history.size, history.get(('e2', 'c'))), (9, '1234'))
        history.put(('e2', 'big'), 'x' * 11)
        self.assertIsNone(history.get(('e2', 'big')))
        history.forget('e1')
        self.assertEqual((list(history.items), history.size), ([('e2', 'c')], 4))


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentSDKHTTPTests(AgentFixture, LiveServerTestCase):
    def run_sdk(self, scenario='normal'):
        self.reply_calls = [CALL]
        def next_reply():
            if any(m['role'] == 'tool' for m in self.requests[-1]['messages']):
                self.reply_calls = []
        self.after_request = next_reply
        root = Path(__file__).resolve().parents[2]
        python = root / 'ops/agent_probe/.venv' / ('Scripts/python.exe' if __import__('os').name == 'nt' else 'bin/python')
        result = subprocess.run([str(python), str(root / 'ops/agent_probe/verify_governed_sdk.py')],
            input=json.dumps({'endpoint': self.live_server_url + '/internal/agents/', 'token': self.token,
                'attempt': str(self.execution.attempt), 'scenario': scenario}), text=True, capture_output=True, timeout=90, cwd=root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout[result.stdout.index('{'):])

    def test_pinned_sdk_graph_uses_application_http_and_replays_lost_response(self):
        report = self.run_sdk()
        self.assertEqual(report['tool_call_id'], CALL['id'])
        self.assertEqual(report['view'], {'status': 'approved', 'rows': 3, 'total_cents': 750})
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(AgentInference.objects.count(), 2)

    def test_sdk_revocation_after_tool_step_prevents_second_inference(self):
        def revoke(*args):
            view = tool_result(*args)
            CompanyEngine.objects.filter(pk=self.credential.pk).update(active=False)
            return view
        with patch('front.agents.views.tool_result', side_effect=revoke):
            self.assertTrue(self.run_sdk('revoked')['revocation_stopped'])
        self.assertEqual(len(self.requests), 1)

    def test_sdk_tool_exception_is_archived_but_not_in_model_context(self):
        report = self.run_sdk('tool-error')
        self.assertEqual(report['view'], {'status': 'withheld', 'code': 'tool_failed'})
        self.assertNotIn('error@example.invalid', json.dumps(self.requests))
        self.assertIn('error@example.invalid', AgentToolResult.objects.get(execution=self.execution).raw)
