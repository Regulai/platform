"""Research provenance and real HTTP/client controls with simulated boundaries."""
from copy import deepcopy
import json
import socket
import uuid
from unittest.mock import patch

import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from front.agents import research
from front.agents.data_views import tool_result
from front.agents.service import AgentDenied, authenticate, begin_execution
from front.governance import PipelineStop
from front.models import AgentExecution, AgentInput, Company, Rule, RulesGroup
from front.policy import AIConfig
from front.test_agent_inference import AgentFixture


CATALOG = {'primary-one': {'title': 'Synthetic primary publication', 'publisher': 'Synthetic Institute',
    'url': 'https://primary.example.org/publication'},
    'primary-two': {'title': 'Second synthetic publication', 'publisher': 'Synthetic Institute',
    'url': 'https://primary.example.org/second'}}
PUBLIC_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]
TEXT = ('This is synthetic primary-source text for a retrieval test. It describes a migration assessment '
        'and distinguishes published results from implementation recommendations. No real-world conclusion is asserted.')
CALL = {'id': 'research-synthetic-one', 'name': 'research_sources', 'args': {'ids': ['primary-one']}}


@override_settings(REGULAY_AGENT_RESEARCH_CATALOG=CATALOG)
class ResearchTransportTests(SimpleTestCase):
    def setUp(self):
        self.requests = []
        self.enterContext(patch.object(research.socket, 'getaddrinfo', return_value=PUBLIC_DNS))

    def fetch(self, response):
        def boundary(request):
            self.requests.append(request)
            return response
        return research.fetch_source(CATALOG['primary-one'], transport=httpx.MockTransport(boundary))

    def test_exact_public_get_has_pinned_ip_and_hostname_tls_without_credentials(self):
        value = self.fetch(httpx.Response(200, headers={'content-type': 'text/html; charset=utf-8'},
            text='<nav>Ignore navigation</nav><main><h1>Primary text</h1><p>' + TEXT +
                '</p><script>exfiltrate()</script><p hidden>Hidden secrets</p></main>'))
        request = self.requests[0]
        self.assertEqual(str(request.url), 'https://93.184.216.34/publication')
        self.assertEqual(request.headers['host'], 'primary.example.org')
        self.assertEqual(request.extensions['sni_hostname'], 'primary.example.org')
        self.assertEqual(request.method, 'GET')
        self.assertNotIn('authorization', request.headers)
        self.assertNotIn('cookie', request.headers)
        self.assertNotIn('referer', request.headers)
        self.assertEqual(request.content, b'')
        self.assertIn(TEXT, value['text'])
        self.assertNotIn('exfiltrate', value['text'])
        self.assertNotIn('Hidden secrets', value['text'])
        self.assertNotIn('navigation', value['text'])
        self.assertEqual(len(value['sha256']), 64)

    def test_unreviewed_ids_arbitrary_urls_and_private_dns_are_rejected(self):
        for values in ([], ['primary-one'] * 2, ['missing'], ['https://localhost'], [True],
                ['primary-one', 'primary-two', 'x', 'y', 'z']):
            with self.subTest(values=values), self.assertRaises(AgentDenied):
                research.validate_ids(values)
        for url in ('http://primary.example.org/a', 'https://127.0.0.1/a', 'https://[::1]/a',
                'https://primary.example.org/a?api_key=secret', 'https://a:b@primary.example.org/a',
                'https://primary.example.org:8443/a', 'https://primary.example.org/a#x',
                'https://primary.example.org/a%0d%0aAuthorization:test', 'https://primary.local/a'):
            with self.subTest(url=url), self.assertRaises(AgentDenied):
                research._url(url)
        for address in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1', '224.0.0.1', 'ff00::1'):
            rows = PUBLIC_DNS + [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]
            with self.subTest(address=address), patch.object(research.socket, 'getaddrinfo', return_value=rows):
                with self.assertRaisesMessage(AgentDenied, 'research_address_denied'):
                    self.fetch(httpx.Response(200, headers={'content-type': 'text/plain'}, text=TEXT))
        self.assertEqual(self.requests, [])

    def test_redirect_media_size_encoding_and_insufficient_text_fail_closed(self):
        cases = [httpx.Response(302, headers={'Location': 'http://169.254.169.254/latest/meta-data/'}),
            httpx.Response(403, text='api_key=synthetic-sensitive-provider-error'),
            httpx.Response(200, headers={'content-type': 'application/pdf'}, content=b'%PDF'),
            httpx.Response(200, headers={'content-type': 'text/plain', 'content-length': str(research.MAX_BYTES + 1)}),
            httpx.Response(200, headers={'content-type': 'text/plain'}, content=b'a' * (research.MAX_BYTES + 1)),
            httpx.Response(200, headers={'content-type': 'text/html'}, text='<div>' * 130 + TEXT),
            httpx.Response(200, headers={'content-type': 'text/plain'}, text='tiny')]
        for response in cases:
            with self.subTest(status=response.status_code), self.assertRaises(AgentDenied) as error:
                self.fetch(response)
            self.assertNotIn('synthetic-sensitive', str(error.exception))
        self.assertEqual(len(self.requests), len(cases))

    def test_policy_accepts_explicit_catalog_ids_without_widening_other_destinations(self):
        config = AIConfig(destinations={'public': ['research:primary-one', 'engine:1', 'jev']})
        self.assertIn('research:primary-one', config.destinations['public'])
        for destination in ('research:https://example.org', 'research:*', 'research:', 'https://example.org'):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                AIConfig(destinations={'public': [destination]})

    def test_reviewed_html_region_excludes_boilerplate_and_missing_region_fails(self):
        entry = {**CATALOG['primary-one'], 'content_id': 'publication-body'}
        response = httpx.Response(200, headers={'content-type': 'text/html; charset=utf-8'},
            text='<div>Navigation and boilerplate</div><div id="publication-body">NIST\u2019s ' + TEXT + '</div>')
        value = research.fetch_source(entry, transport=httpx.MockTransport(lambda _: response))
        self.assertTrue(value['text'].startswith('NIST\u2019s '))
        self.assertNotIn('boilerplate', value['text'])
        self.assertNotIn('\ufffd', value['text'])
        for body in ('<main>' + TEXT + '</main>',
                '<div id="publication-body">' + TEXT + '</div><div id="publication-body">' + TEXT + '</div>'):
            with self.subTest(body=body[:30]), self.assertRaisesMessage(AgentDenied, 'research_content_region_unavailable'):
                research.fetch_source(entry, transport=httpx.MockTransport(lambda _: httpx.Response(200,
                    headers={'content-type': 'text/html; charset=utf-8'}, text=body)))
        with self.assertRaisesMessage(AgentDenied, 'research_text_insufficient'):
            research.fetch_source(entry, transport=httpx.MockTransport(lambda _: httpx.Response(200,
                headers={'content-type': 'text/html; charset=utf-8'},
                text=TEXT + '<div id="publication-body" hidden>Hidden content</div>')))


@override_settings(REGULAY_AGENT_ENABLED=True, REGULAY_AGENT_RESEARCH_ENABLED=True,
    REGULAY_AGENT_RESEARCH_CATALOG=CATALOG)
class ResearchExecutionTests(AgentFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.agent.tools = ['research_sources']
        self.agent.save()
        self.company.ai_config['destinations']['internal'] += ['research:primary-one', 'research:primary-two']
        self.company.save()
        self.reset_execution()
        self.fetches = []
        self.html = '<main>' + TEXT + '</main>'
        self.after_fetch = None
        self.real_fetch = research.fetch_source
        self.enterContext(patch.object(research.socket, 'getaddrinfo', return_value=PUBLIC_DNS))

        def boundary(request):
            self.fetches.append(request)
            if self.after_fetch:
                self.after_fetch()
            return httpx.Response(200, headers={'content-type': 'text/html; charset=utf-8'}, text=self.html)

        self.enterContext(patch.object(research, 'fetch_source', side_effect=lambda entry, **kwargs:
            self.real_fetch(entry, transport=httpx.MockTransport(boundary), **kwargs)))

    def reset_execution(self):
        AgentExecution.objects.filter(pk=self.execution.pk).delete()
        self.execution, self.token = begin_execution(self.prompt, self.agent.pk)

    def run_research(self, call=None):
        call = self.issue_tool(deepcopy(call or CALL))
        result = research.execute(self.token, self.execution.attempt, {'call': call})
        payload = {'call': call, 'raw': {'content': json.dumps({'reference': result['reference']})}}
        view = tool_result(self.token, self.execution.attempt, payload)
        return result, view, payload

    def test_retrieval_provenance_real_gateway_masks_and_replay_never_refetches(self):
        self.html = '<main>' + TEXT + ' api_key=sk-synthetic-source-secret</main>'
        result, view, payload = self.run_research()
        self.assertEqual(view['research_status'], 'completed')
        self.assertEqual(view['sources'][0]['id'], 'primary-one')
        self.assertEqual(view['sources'][0]['url'], CATALOG['primary-one']['url'])
        self.assertEqual(view['sources'][0]['factual_verification'], 'not_performed')
        self.assertEqual(view['sources'][0]['trust'], 'untrusted_source_text')
        self.assertNotIn('sk-synthetic-source-secret', json.dumps(view))
        self.assertEqual(result, research.execute(self.token, self.execution.attempt, {'call': CALL}))
        self.assertEqual(view, tool_result(self.token, self.execution.attempt, payload))
        self.assertEqual(len(self.fetches), 1)
        self.assertEqual(research.consulted_sources(self.execution)['primary-one'], view['sources'][0])
        self.reply_calls = []
        followup = self.request(messages=[{'role': 'assistant', 'content': '', 'tool_calls': [CALL]},
            {'role': 'tool', 'name': 'research_sources', 'tool_call_id': CALL['id'],
                'content': json.dumps(view, sort_keys=True, ensure_ascii=False)}])
        self.assertEqual(self.infer(followup)['status'], 'completed')
        self.assertNotIn('sk-synthetic-source-secret', json.dumps(self.requests))
        self.prompt.refresh_from_db()
        reads = [call for call in self.prompt.decision['calls'] if call['purpose'] == 'research']
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0]['status'], 'completed')
        self.assertEqual(reads[0]['cost'], '0')
        self.assertEqual(reads[0]['provider_name'], 'public_https')
        self.assertEqual(reads[0]['route']['mode'], 'primary_source_read')
        self.assertIn('duration_ms', reads[0])

    def test_disabled_denied_and_fetch_failed_are_honest_and_have_no_sources(self):
        with override_settings(REGULAY_AGENT_RESEARCH_ENABLED=False):
            _, view, _ = self.run_research()
        self.assertEqual(view['research_status'], 'disabled')
        self.assertEqual(view['sources'], [])
        self.assertFalse(self.fetches)
        self.company.ai_config['destinations']['internal'] = [item for item in
            self.company.ai_config['destinations']['internal'] if not item.startswith('research:')]
        self.company.save()
        self.reset_execution()
        _, view, _ = self.run_research()
        self.assertEqual(view['research_status'], 'denied')
        self.assertFalse(self.fetches)
        self.company.ai_config['destinations']['internal'].append('research:primary-one')
        self.company.save()
        self.reset_execution()
        with patch.object(research, 'fetch_source', side_effect=httpx.ReadTimeout('credential-sensitive-error')):
            _, view, _ = self.run_research()
        self.assertEqual(view['research_status'], 'failed')
        self.assertEqual(view['sources'], [])
        self.assertNotIn('credential-sensitive', json.dumps(view))
        self.assertEqual(research.consulted_sources(self.execution), {})

    def test_current_policy_and_cancellation_after_http_withhold_all_source_data(self):
        for revoke in (lambda: AgentExecution.objects.filter(pk=self.execution.pk).update(status='cancelled'),
                lambda: Company.objects.filter(pk=self.company.pk).update(ai_config={})):
            with self.subTest(revoke=revoke):
                self.after_fetch = revoke
                self.issue_tool(deepcopy(CALL))
                with self.assertRaises((AgentDenied, PipelineStop)):
                    research.execute(self.token, self.execution.attempt, {'call': CALL})
                self.assertEqual(research.consulted_sources(self.execution), {})
                self.company.save()
                self.reset_execution()

    def test_file_yara_scans_whole_source_before_truncation_and_aliasing(self):
        group = RulesGroup.objects.create(name='Research rules', company=self.company)
        Rule.objects.create(name='Block source marker', rules_group=group, applies_to='files',
            yara_rule='rule Source { strings: $s = "blocked@example.invalid" condition: $s }')
        self.reset_execution()
        self.html = '<main>' + TEXT * 40 + ' blocked@example.invalid</main>'
        self.issue_tool(deepcopy(CALL))
        with self.assertRaisesMessage(AgentDenied, 'security_check_failed'):
            research.execute(self.token, self.execution.attempt, {'call': CALL})
        self.assertEqual(research.consulted_sources(self.execution), {})

    def test_receipt_is_bound_to_call_execution_and_content_not_executor_claims(self):
        result, view, payload = self.run_research()
        from front.agents.protocol import ToolCall
        call = ToolCall.model_validate(CALL)
        forged = research.approved_view(self.execution, call, {'content': json.dumps({'reference': str(uuid.uuid4()),
            'sources': [{'id': 'invented', 'url': 'https://fake.invalid'}]})})
        self.assertEqual(forged['status'], 'withheld')
        from front.models import Conversation, Prompt
        conversation = Conversation.objects.create(user=self.user)
        prompt = Prompt.objects.create(user=self.user, company=self.company, conversation=conversation,
            content='Second private run', status='processing')
        other, _ = begin_execution(prompt, self.agent.pk)
        self.assertEqual(research.approved_view(other, call, payload['raw'])['status'], 'withheld')
        self.assertEqual(research.consulted_sources(other), {})
        AgentInput.objects.filter(pk=result['reference']).update(original='{}')
        with self.assertRaisesMessage(AgentDenied, 'research_receipt_invalid'):
            research.consulted_sources(self.execution)

    def test_busy_or_unissued_calls_cannot_open_network_and_bootstrap_is_metadata_only(self):
        info = research.available(authenticate(self.token, self.execution.attempt)[1])
        self.assertEqual(info['status'], 'available')
        self.assertEqual({item['id'] for item in info['sources']}, set(CATALOG))
        self.assertNotIn('excerpt', json.dumps(info))
        with self.assertRaisesMessage(AgentDenied, 'unissued_tool_call'):
            research.execute(self.token, self.execution.attempt, {'call': CALL})
        self.issue_tool(deepcopy(CALL))
        AgentExecution.objects.filter(pk=self.execution.pk).update(active_call=uuid.uuid4())
        with self.assertRaisesMessage(AgentDenied, 'execution_busy_or_uncertain'):
            research.execute(self.token, self.execution.attempt, {'call': CALL})
        self.assertFalse(self.fetches)

    def test_an_id_has_one_immutable_consultation_per_run_across_tool_calls(self):
        _, first, _ = self.run_research()
        self.html = '<main>Changed primary publication. ' + TEXT + '</main>'
        _, second, _ = self.run_research({**CALL, 'id': 'research-synthetic-second'})
        self.assertEqual(first['sources'], second['sources'])
        self.assertEqual(len(self.fetches), 1)

    def test_catalog_change_after_dispatch_withholds_sources_and_releases_claim(self):
        self.issue_tool(deepcopy(CALL))
        changed = deepcopy(CATALOG)
        changed['primary-one']['url'] = 'https://primary.example.org/changed'
        with override_settings(REGULAY_AGENT_RESEARCH_CATALOG=CATALOG):
            self.after_fetch = lambda: setattr(research.settings, 'REGULAY_AGENT_RESEARCH_CATALOG', changed)
            with self.assertRaisesMessage(AgentDenied, 'research_authorization_changed'):
                research.execute(self.token, self.execution.attempt, {'call': CALL})
        self.assertEqual(research.consulted_sources(self.execution), {})
        self.execution.refresh_from_db()
        self.assertIsNone(self.execution.active_call)

    def test_partial_failure_names_only_sources_actually_consulted(self):
        call = {**CALL, 'args': {'ids': ['primary-one', 'primary-two']}}
        original = research.fetch_source
        def fetch(entry, **kwargs):
            if entry['url'].endswith('/second'):
                raise AgentDenied('research_http_failed')
            return original(entry, **kwargs)
        with patch.object(research, 'fetch_source', side_effect=fetch):
            _, view, _ = self.run_research(call)
        self.assertEqual(view['research_status'], 'partial')
        self.assertEqual([source['id'] for source in view['sources']], ['primary-one'])
        self.assertEqual(view['limitations'], [{'id': 'primary-two', 'code': 'research_http_failed'}])
        self.assertEqual(set(research.consulted_sources(self.execution)), {'primary-one'})

    def test_private_http_operation_authenticates_and_never_accepts_a_caller_url(self):
        self.issue_tool(deepcopy(CALL))
        endpoint = '/internal/agents/run/research/'
        headers = {'HTTP_AUTHORIZATION': 'Bearer ' + self.token,
            'HTTP_X_REGULAY_ATTEMPT': str(self.execution.attempt)}
        anonymous = self.client.post(endpoint, json.dumps({'call': CALL}), content_type='application/json')
        self.assertEqual(anonymous.status_code, 403)
        foreign = self.client.post(endpoint, json.dumps({'call': CALL, 'url': 'https://internal.local'}),
            content_type='application/json', **headers)
        self.assertEqual(foreign.status_code, 403)
        self.assertFalse(self.fetches)
        success = self.client.post(endpoint, json.dumps({'call': CALL}), content_type='application/json', **headers)
        self.assertEqual(success.status_code, 200, success.content)
        self.assertEqual(success.json()['status'], 'completed')
        self.assertNotIn('excerpt', success.json())
        self.assertEqual(len(self.fetches), 1)
        repeated = self.client.post(endpoint, json.dumps({'call': CALL}), content_type='application/json', **headers)
        self.assertEqual(repeated.json(), success.json())
        self.assertEqual(len(self.fetches), 1)
