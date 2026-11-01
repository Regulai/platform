import json
import requests
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from front.models import Alert, AuditLog, Company, Conversation, Engine, CompanyEngine, EngineModel, Message, ObfuscationConfig, Profile, Prompt, Response, Rule, RulesGroup
from front.test_chat_flow import mask_response


def jev_response(category='internal'):
    answers = {}
    for key, choices, selected in (
        ('category', ['public', 'internal', 'confidential', 'restricted', 'unknown'], category),
        ('task', ['extraction', 'summary', 'document_question', 'general'], 'general'),
        ('difficulty', ['economy', 'balanced', 'strong'], 'economy'),
    ):
        answers[key] = {'type': 'choice', 'choice': selected, 'confidence': 0.95,
            'probabilities': {choice: 1 - 0.01 * (len(choices) - 1) if choice == selected else 0.01 for choice in choices}}
    for key in ('credentials', 'personal_data', 'business_confidential', 'manipulation', 'ambiguous', 'insufficient_evidence'):
        answers[key] = {'type': 'noul', 'noul': 0.0}

    class ProviderResponse:
        status_code = 200
        headers = {'x-request-id': 'synthetic-request'}
        def iter_content(self, chunk_size):
            yield json.dumps({'model': 'typesafe-ai/jev', 'answers': answers,
                'usage': {'input_tokens': 10, 'output_tokens': 20}}).encode()
        def close(self):
            pass
    return ProviderResponse()


def simulation_transport(category='internal'):
    def transport(*args, **kwargs):
        url = kwargs.pop('url')
        return mask_response(url, **kwargs) if url.endswith('/api/mask') else jev_response(category)
    return transport


class PolicySimulatorTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user('simulator-admin', is_superuser=True)
        self.company = Company.objects.create(name='Simulator company', ai_config={
            'version': 1, 'revision': 1, 'allow_empty_rules': True,
            'local_sensitivity': 'internal', 'destinations': {'internal': ['jev']},
        })
        self.mask = ObfuscationConfig.objects.create(company=self.company, name='Simulator mask', api_url='https://mask.invalid')
        self.company.ai_config['destinations']['internal'].append(f'obfuscation:{self.mask.pk}')
        self.company.ai_config['masking'] = {'max_call_cost': '0'}
        self.company.save()
        Profile.objects.create(user=self.admin, company=self.company)
        self.employee = User.objects.create_user('simulator-employee')
        Profile.objects.create(user=self.employee, company=self.company)
        self.url = reverse('front:policy_simulator')
        self.activate_url = reverse('front:policy_simulator_activate')
        self.client.force_login(self.admin)

    def command(self, **changes):
        command = {'proposed_config': json.dumps(self.company.ai_config),
            'sample': 'Synthetic public report', 'signal_sensitivity': '',
            'signal_task': 'general', 'signal_level': 'economy', 'mode': 'local'}
        command.update(changes)
        return command

    def test_local_comparison_reuses_policy_without_operational_or_network_effects(self):
        proposed = dict(self.company.ai_config, local_sensitivity='restricted')
        with patch('requests.sessions.Session.request') as network:
            response = self.client.post(self.url, self.command(proposed_config=json.dumps(proposed)))
        self.assertEqual(response.status_code, 200)
        result = response.context['comparison']
        self.assertEqual(result['current']['policy']['status'], 'allow')
        self.assertEqual(result['proposed']['policy']['status'], 'block')
        self.assertEqual(result['proposed']['policy']['reason_codes'], ['restricted_content'])
        self.assertEqual(result['signals']['origin'], 'synthetic')
        self.assertEqual(result['semantic']['status'], 'not_evaluated')
        self.assertEqual(result['calls'], [])
        network.assert_not_called()
        for model in (Conversation, Message, Prompt, Response, Alert, AuditLog):
            self.assertEqual(model.objects.count(), 0)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config['revision'], 1)

    def test_yara_false_positive_can_be_compared_with_a_temporary_correction(self):
        group = RulesGroup.objects.create(company=self.company, name='Company rules')
        rule = Rule.objects.create(rules_group=group, name='Overbroad public match',
            yara_rule='rule broad { strings: $word="public" condition: $word }')
        draft = 'rule corrected { strings: $secret="synthetic secret" condition: $secret }'
        result = self.client.post(self.url, self.command(rule_id=rule.pk, rule_source=draft,
            rule_action='block', rule_active='on'))
        self.assertEqual(result.status_code, 200)
        comparison = result.context['comparison']
        self.assertEqual(comparison['current']['policy']['status'], 'block')
        self.assertEqual(comparison['proposed']['policy']['status'], 'allow')
        rule.refresh_from_db()
        self.assertIn('public', rule.yara_rule)
        invalid = self.client.post(self.url, self.command(rule_id=rule.pk, rule_source='not yara'))
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(Rule.objects.get(pk=rule.pk).yara_rule, rule.yara_rule)

    def test_activation_is_separate_version_guarded_and_keeps_safe_rollback_config(self):
        command = self.command(proposed_config=json.dumps(dict(self.company.ai_config, local_sensitivity='restricted')))
        comparison = self.client.post(self.url, command)
        command['activation_token'] = comparison.context['activation_token']
        activated = self.client.post(self.activate_url, command)
        self.assertEqual(activated.status_code, 200)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config['revision'], 2)
        self.assertEqual(self.company.ai_config['local_sensitivity'], 'restricted')
        audit = AuditLog.objects.get(action='policy_activate')
        detail = json.loads(audit.details)
        self.assertEqual(detail['previous_config']['local_sensitivity'], 'internal')
        self.assertEqual(detail['new_config']['revision'], 2)
        self.assertNotIn('Synthetic public report', audit.details)
        self.assertNotIn('api_key', audit.details)
        self.assertEqual(self.client.post(self.activate_url, command).status_code, 409)

    def test_rule_activation_retains_tenant_scoped_rollback_source_without_sample(self):
        group = RulesGroup.objects.create(company=self.company, name='Rollback rules')
        original_source = 'rule original { strings: $s="synthetic old marker" condition: $s }'
        proposed_source = 'rule replacement { strings: $s="synthetic new marker" condition: $s }'
        rule = Rule.objects.create(rules_group=group, name='Rollback rule', yara_rule=original_source)
        command = self.command(rule_id=rule.pk, rule_source=proposed_source,
            rule_action='consent', rule_active='on', sample='Unique synthetic sample not for audit')
        response = self.client.post(self.url, command)
        command['activation_token'] = response.context['activation_token']
        self.assertEqual(self.client.post(self.activate_url, command).status_code, 200)
        audit = AuditLog.objects.get(action='policy_activate')
        detail = json.loads(audit.details)
        self.assertEqual(audit.company_id, self.company.pk)
        self.assertEqual(detail['rule_before']['yara_rule'], original_source)
        self.assertEqual(detail['rule_after']['yara_rule'], proposed_source)
        self.assertEqual(detail['rule_before']['action'], 'block')
        self.assertEqual(detail['rule_after']['action'], 'consent')
        self.assertNotIn(command['sample'], audit.details)

    def test_unauthorized_or_foreign_destinations_cannot_be_activated(self):
        self.client.force_login(self.employee)
        self.assertEqual(self.client.get(self.url).status_code, 403)
        self.assertEqual(self.client.post(self.activate_url, self.command()).status_code, 403)
        self.client.force_login(self.admin)
        foreign_company = Company.objects.create(name='Foreign simulator company')
        engine = Engine.objects.create(name='Foreign simulator engine')
        foreign_engine = CompanyEngine.objects.create(company=foreign_company, engine=engine, api_key='synthetic-key')
        bad = dict(self.company.ai_config, destinations={'internal': [f'engine:{foreign_engine.pk}']})
        self.assertEqual(self.client.post(self.url, self.command(proposed_config=json.dumps(bad))).status_code, 400)

    def test_configured_route_uses_synthetic_signals_and_real_catalogue_prices(self):
        engine = Engine.objects.create(name='Simulator route engine')
        company_engine = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        cheap = EngineModel.objects.create(engine=engine, name='Economy', model_id='synthetic-economy',
            context_window=20_000, max_tokens=2000, input_price='1', output_price='2')
        strong = EngineModel.objects.create(engine=engine, name='Strong', model_id='synthetic-strong',
            context_window=20_000, max_tokens=2000, input_price='10', output_price='20')
        self.company.ai_config.update(destinations={'internal': [f'engine:{company_engine.pk}', f'obfuscation:{self.mask.pk}']},
            routing={'mode': 'auto', 'candidates': [
                {'company_engine_id': company_engine.pk, 'model_id': cheap.pk, 'level': 'economy', 'quality': {'general': 0.9}},
                {'company_engine_id': company_engine.pk, 'model_id': strong.pk, 'level': 'strong', 'quality': {'general': 0.99}},
            ]})
        self.company.save()
        result = self.client.post(self.url, self.command())
        self.assertEqual(result.status_code, 200)
        route = result.context['comparison']['current']['route']
        self.assertEqual(route['model'], 'synthetic-economy')
        self.assertEqual(route['origin'], 'synthetic_signals')
        self.assertEqual(route['max_output_tokens'], 1000)

    def test_permissive_draft_cannot_authorize_semantics_against_current_policy(self):
        self.company.ai_config['destinations'] = {'internal': []}
        self.company.save()
        proposed = dict(self.company.ai_config, destinations={'internal': ['jev']})
        with patch('requests.sessions.Session.request') as network:
            result = self.client.post(self.url, self.command(mode='semantic', proposed_config=json.dumps(proposed)))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.context['comparison']['semantic']['status'], 'not_authorized')
        self.assertEqual(result.context['comparison']['calls'], [])
        network.assert_not_called()

    def test_authorized_semantics_records_one_bounded_call_without_generation(self):
        self.company.ai_config.update(jev={'input_price': '1', 'output_price': '1',
            'max_call_cost': '0.001'}, limits={'budget': '0.002'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        with patch('requests.sessions.Session.request', side_effect=simulation_transport()) as network:
            response = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(response.status_code, 200)
        result = response.context['comparison']
        self.assertEqual(result['semantic']['status'], 'completed')
        self.assertEqual(result['signals']['origin'], 'jev')
        self.assertEqual(len(result['calls']), 2)
        self.assertEqual(result['calls'][-1]['purpose'], 'simulation_classification')
        self.assertEqual(result['calls'][-1]['cost'], '0.00003')
        self.assertEqual(network.call_count, 2)
        self.assertEqual(network.call_args.kwargs['url'], 'https://ai-gateway.vercel.sh/typesafe/v1/systemone')
        audit = AuditLog.objects.filter(action='policy_simulate').latest('pk')
        self.assertNotIn('Synthetic public report', audit.details)
        self.assertNotIn('synthetic-key', audit.details)
        for model in (Conversation, Message, Prompt, Response, Alert):
            self.assertEqual(model.objects.count(), 0)

    def test_semantic_budget_and_unknown_outcome_are_explicit(self):
        self.company.ai_config.update(jev={'input_price': '1', 'output_price': '1',
            'max_call_cost': '0.002'}, limits={'budget': '0.001'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        with patch('requests.sessions.Session.request') as network:
            no_budget = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(no_budget.context['comparison']['semantic']['reason_codes'], ['budget_exhausted'])
        network.assert_not_called()
        self.company.ai_config['limits']['budget'] = '0.003'
        self.company.save()
        def timeout_transport(*args, **kwargs):
            url = kwargs.pop('url')
            if url.endswith('/api/mask'):
                return mask_response(url, **kwargs)
            raise requests.ReadTimeout()
        with patch('requests.sessions.Session.request', side_effect=timeout_transport) as network:
            timeout = self.client.post(self.url, self.command(mode='semantic'))
        comparison = timeout.context['comparison']
        self.assertEqual(comparison['semantic']['status'], 'unavailable')
        self.assertEqual(comparison['calls'][-1]['cost'], None)
        self.assertEqual(comparison['calls'][-1]['cost_bound'], '0.002')
        self.assertTrue(comparison['calls'][-1]['outcome_unknown'])
        self.assertEqual(json.loads(AuditLog.objects.filter(action='policy_simulate').latest('pk').details)['call']['status'], 'failed')
        self.assertEqual(network.call_count, 2)

    def test_concurrent_rule_edit_and_modified_draft_invalidate_activation(self):
        group = RulesGroup.objects.create(company=self.company, name='Guarded rules')
        rule = Rule.objects.create(rules_group=group, name='Existing rule',
            yara_rule='rule existing { strings: $secret="synthetic secret" condition: $secret }')
        command = self.command()
        response = self.client.post(self.url, command)
        command['activation_token'] = response.context['activation_token']
        Rule.objects.filter(pk=rule.pk).update(action='consent')
        self.assertEqual(self.client.post(self.activate_url, command).status_code, 409)
        self.assertEqual(AuditLog.objects.count(), 0)
        response = self.client.post(self.url, self.command())
        changed = self.command(proposed_config=json.dumps(dict(self.company.ai_config, local_sensitivity='public')),
            activation_token=response.context['activation_token'])
        self.assertEqual(self.client.post(self.activate_url, changed).status_code, 409)
        self.company.refresh_from_db()
        self.assertEqual(self.company.ai_config['revision'], 1)

    def test_template_exposes_separate_actions_and_escapes_untrusted_data(self):
        response = self.client.post(self.url, self.command(sample='<script>fixture</script>'))
        self.assertContains(response, '&lt;script&gt;fixture&lt;/script&gt;')
        self.assertNotContains(response, '<script>fixture</script>')
        self.assertContains(response, 'name="rule_source"')
        self.assertContains(response, 'name="signal_task"')
        self.assertContains(response, 'value="semantic"')
        self.assertContains(response, f'action="{self.activate_url}"')
        self.assertContains(response, 'Policy simulator')
        duplicate = '{"version":1,"version":1}'
        self.assertEqual(self.client.post(self.url, self.command(proposed_config=duplicate)).status_code, 400)

    def test_semantic_signals_apply_each_policy_threshold_and_restricted_blocks(self):
        self.company.ai_config.update(classification='required', jev={'input_price': '1', 'output_price': '1',
            'max_call_cost': '0.001'}, limits={'budget': '0.002'})
        self.company.jev_api_key = 'synthetic-key'
        self.company.save()
        proposed = dict(self.company.ai_config, classification_policy={'on_ambiguity': 'stop'},
            jev=dict(self.company.ai_config['jev'], threshold=0.99))
        with patch('requests.sessions.Session.request', side_effect=simulation_transport()):
            response = self.client.post(self.url, self.command(mode='semantic', proposed_config=json.dumps(proposed)))
        self.assertEqual(response.context['comparison']['current']['policy']['status'], 'allow')
        self.assertEqual(response.context['comparison']['proposed']['policy']['status'], 'unavailable')
        self.assertEqual(response.context['comparison']['proposed']['policy']['reason_codes'], ['classification_ambiguous'])
        with patch('requests.sessions.Session.request', side_effect=simulation_transport('restricted')):
            response = self.client.post(self.url, self.command(mode='semantic'))
        self.assertEqual(response.context['comparison']['current']['policy']['status'], 'block')
        self.assertEqual(response.context['comparison']['current']['policy']['reason_codes'], ['restricted_content'])

    def test_synthetic_signals_cannot_lower_local_sensitivity(self):
        for sensitivity in ('confidential', 'restricted'):
            with self.subTest(sensitivity=sensitivity):
                self.company.ai_config.update(local_sensitivity=sensitivity,
                    destinations={'public': ['jev', f'obfuscation:{self.mask.pk}'],
                        sensitivity: ['jev', f'obfuscation:{self.mask.pk}']})
                self.company.save()
                response = self.client.post(self.url, self.command(signal_sensitivity='public'))
                policy = response.context['comparison']['current']['policy']
                self.assertEqual(policy['sensitivity'], sensitivity)
                self.assertEqual(policy['status'], 'block' if sensitivity == 'restricted' else 'allow')

    def test_simulated_route_reserves_required_classification_and_verification(self):
        engine = Engine.objects.create(name='Budget simulator engine')
        credential = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-key')
        model = EngineModel.objects.create(engine=engine, name='Budget model', model_id='synthetic-budget',
            context_window=20_000, max_tokens=2000, input_price='0', output_price='0.5')
        self.company.ai_config.update(classification='required', verification={'mode': 'enforce'},
            destinations={'internal': [f'engine:{credential.pk}', 'jev', f'obfuscation:{self.mask.pk}']},
            jev={'input_price': '1', 'output_price': '1', 'max_call_cost': '0.001'},
            limits={'budget': '0.0015'}, routing={'mode': 'manual', 'candidates': [
                {'company_engine_id': credential.pk, 'model_id': model.pk,
                 'level': 'economy', 'quality': {'general': 0.9}}]})
        self.company.save()
        with patch('requests.sessions.Session.request') as network:
            response = self.client.post(self.url, self.command())
            route = response.context['comparison']['current']['route']
            self.assertEqual(route['status'], 'unavailable')
            self.assertEqual(route['reason_codes'], ['budget_exhausted'])
            self.company.ai_config['limits']['budget'] = '0.003'
            self.company.save()
            response = self.client.post(self.url, self.command())
            self.assertEqual(response.context['comparison']['current']['route']['status'], 'selected')
            self.company.ai_config['jev'].pop('max_call_cost')
            self.company.save()
            response = self.client.post(self.url, self.command())
            self.assertEqual(response.context['comparison']['current']['route']['reason_codes'], ['unknown_price'])
        network.assert_not_called()
