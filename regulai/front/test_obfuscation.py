"""YARA-based obfuscation, rule validation resilience and rule compile endpoints."""
import importlib
import json

from django.apps import apps as django_apps
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from . import obfuscation_service as svc
from .models import Company, Conversation, Profile, Rule, RulesGroup

seed_migration = importlib.import_module('front.migrations.0031_seed_obfuscation_rules')
fix_migration = importlib.import_module('front.migrations.0032_fix_seeded_aws_key_rule')

BROKEN_AWS_RULE = '''rule aws_key {
    strings:
        $access = /AKIA[A-Z0-9]{16}/
        $secret = /[A-Za-z0-9\\/+=]{40}/
    condition:
        $access
}'''

DNI_RULE = '''rule dni_nie_spain {
    strings:
        $dni = /[0-9]{8}[A-Za-z]/
    condition:
        $dni
}'''


class SeededRulesTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Tenant')
        seed_migration.seed_obfuscation_rules(django_apps, None)
        self.user = User.objects.create_user('analyst', password='x', is_staff=True)
        Profile.objects.create(user=self.user, company=self.company)


class SeedRulesTests(SeededRulesTestCase):
    def test_all_seeded_rules_compile(self):
        from .yara_utils import check_source
        for rule in Rule.objects.filter(rules_group__company=self.company):
            with self.subTest(rule=rule.name):
                self.assertIsNone(check_source(rule.yara_rule))

    def test_fix_migration_repairs_broken_aws_rule(self):
        rule = Rule.objects.get(rules_group__company=self.company, name='AWS_Key')
        Rule.objects.filter(pk=rule.pk).update(yara_rule=BROKEN_AWS_RULE)

        fix_migration.fix_aws_key_rules(django_apps, None)

        rule.refresh_from_db()
        self.assertNotIn('$secret', rule.yara_rule)
        self.assertIn('$access', rule.yara_rule)


class ObfuscationServiceTests(SeededRulesTestCase):
    def test_masks_values_matched_by_yara_identifier(self):
        """Matches map to the Rule via namespace even though YARA ids differ from Rule.name."""
        result = svc.obfuscate_text(
            'mail juan@example.com dni 44593648Y iban ES9121000418450200051332',
            self.company.id,
        )
        self.assertEqual(result.text, 'mail [EMAIL_1] dni [DNI_1] iban [IBAN_1]')
        self.assertEqual(result.context, {
            '[EMAIL_1]': 'juan@example.com',
            '[DNI_1]': '44593648Y',
            '[IBAN_1]': 'ES9121000418450200051332',
        })

    def test_non_ascii_text_before_match(self):
        result = svc.obfuscate_text('Hola José, ñandú: ana@example.com', self.company.id)
        self.assertEqual(result.text, 'Hola José, ñandú: [EMAIL_1]')

    def test_surrounding_whitespace_is_not_masked(self):
        result = svc.obfuscate_text('tlf 612345678 ok', self.company.id)
        self.assertEqual(result.text, 'tlf [PHONE_1] ok')
        self.assertEqual(result.context['[PHONE_1]'], '612345678')

    def test_existing_tokens_are_never_overwritten(self):
        existing = {'[EMAIL_1]': 'uno@a.com', '[PHONE_1]': '699999999'}
        result = svc.obfuscate_text('dos@b.com y 611111111', self.company.id, existing)
        self.assertEqual(result.text, '[EMAIL_2] y [PHONE_2]')
        self.assertEqual(result.context['[EMAIL_1]'], 'uno@a.com')
        self.assertEqual(result.context['[PHONE_1]'], '699999999')
        self.assertEqual(result.context['[EMAIL_2]'], 'dos@b.com')

    def test_repeated_value_reuses_token(self):
        result = svc.obfuscate_text('otra vez uno@a.com', self.company.id, {'[EMAIL_1]': 'uno@a.com'})
        self.assertEqual(result.text, 'otra vez [EMAIL_1]')
        self.assertEqual(len(result.context), 1)

    def test_numbering_follows_reading_order(self):
        result = svc.obfuscate_text('a@a.com b@b.com', self.company.id)
        self.assertEqual(result.text, '[EMAIL_1] [EMAIL_2]')

    def test_broken_rule_does_not_disable_obfuscation(self):
        group = RulesGroup.objects.get(company=self.company, name='Obfuscation Rules')
        Rule.objects.create(name='Broken', rules_group=group, action='obfuscate', yara_rule=BROKEN_AWS_RULE)
        result = svc.obfuscate_text('mail juan@example.com', self.company.id)
        self.assertEqual(result.text, 'mail [EMAIL_1]')

    def test_deobfuscate_round_trip(self):
        result = svc.obfuscate_text('mail juan@example.com dni 44593648Y', self.company.id)
        self.assertEqual(svc.deobfuscate_text(result.text, result.context), 'mail juan@example.com dni 44593648Y')


class ViewObfuscateTextTests(SeededRulesTestCase):
    def test_conversation_context_prevents_token_collisions(self):
        from .views import obfuscate_text
        text1, ctx1 = obfuscate_text('email uno@a.com', self.company)
        conversation = Conversation.objects.create(user=self.user)
        conversation.set_obfuscation_context(ctx1)

        text2, ctx2 = obfuscate_text('email dos@b.com', self.company,
                                     existing_context=conversation.get_obfuscation_context())

        self.assertEqual(text1, 'email [EMAIL_1]')
        self.assertEqual(text2, 'email [EMAIL_2]')
        # Only the tokens used in this message are returned
        self.assertEqual(ctx2, {'[EMAIL_2]': 'dos@b.com'})

    def test_nothing_to_mask_returns_none(self):
        from .views import obfuscate_text
        self.assertEqual(obfuscate_text('hola', self.company), ('hola', None))


class ValidatePromptResilienceTests(TestCase):
    def setUp(self):
        company = Company.objects.create(name='Tenant')
        self.user = User.objects.create_user('u')
        Profile.objects.create(user=self.user, company=company)
        group = RulesGroup.objects.create(name='G', company=company)
        Rule.objects.create(name='Broken', rules_group=group, yara_rule=BROKEN_AWS_RULE)
        Rule.objects.create(name='DNI_NIE', rules_group=group, action='block', yara_rule=DNI_RULE)

    def test_invalid_rule_is_skipped_and_valid_rules_still_match(self):
        from .views import validate_prompt
        _matches, matched = validate_prompt(self.user, 'mi dni 44593648Y')
        self.assertEqual([r['name'] for r in matched], ['DNI_NIE'])
        self.assertEqual(matched[0]['action'], 'block')


class RuleCompileEndpointTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Tenant')
        self.user = User.objects.create_user('analyst', is_staff=True)
        Profile.objects.create(user=self.user, company=self.company)
        self.group = RulesGroup.objects.create(name='G', company=self.company)
        self.good = Rule.objects.create(name='DNI', rules_group=self.group, yara_rule=DNI_RULE)
        self.bad = Rule.objects.create(name='Broken', rules_group=self.group, yara_rule=BROKEN_AWS_RULE)
        self.client.force_login(self.user)

    def post(self, url, data=None):
        response = self.client.post(url, data or {})
        self.assertEqual(response.status_code, 200)
        return json.loads(response.content)

    def test_compile_valid_rule(self):
        data = self.post(reverse('front:rule_compile', args=[self.good.pk]))
        self.assertTrue(data['ok'])
        self.assertEqual(data['rules'], ['dni_nie_spain'])
        self.assertFalse(data['tested'])

    def test_compile_invalid_rule_reports_error(self):
        data = self.post(reverse('front:rule_compile', args=[self.bad.pk]))
        self.assertFalse(data['ok'])
        self.assertIn('unreferenced string "$secret"', data['error'])

    def test_compile_with_sample_text(self):
        url = reverse('front:rule_compile', args=[self.good.pk])
        hit = self.post(url, {'test_text': 'José, mi dni 44593648Y'})
        self.assertTrue(hit['matched'])
        self.assertEqual(hit['matches'][0]['data'], '44593648Y')
        self.assertEqual(hit['matches'][0]['offset'], len('José, mi dni '))
        miss = self.post(url, {'test_text': 'nothing here'})
        self.assertTrue(miss['tested'])
        self.assertFalse(miss['matched'])

    def test_validate_unsaved_source(self):
        url = reverse('front:rule_validate')
        self.assertTrue(self.post(url, {'yara_rule': DNI_RULE})['ok'])
        self.assertFalse(self.post(url, {'yara_rule': 'rule x { condition: }'})['ok'])
        self.assertFalse(self.post(url, {'yara_rule': ''})['ok'])
        self.assertEqual(Rule.objects.count(), 2)  # nothing saved

    def test_get_not_allowed(self):
        response = self.client.get(reverse('front:rule_compile', args=[self.good.pk]))
        self.assertEqual(response.status_code, 405)

    def test_other_company_rule_not_accessible(self):
        other_group = RulesGroup.objects.create(name='G', company=Company.objects.create(name='Other'))
        other_rule = Rule.objects.create(name='X', rules_group=other_group, yara_rule=DNI_RULE)
        response = self.client.post(reverse('front:rule_compile', args=[other_rule.pk]))
        self.assertEqual(response.status_code, 404)

    def test_non_staff_forbidden(self):
        plain = User.objects.create_user('plain')
        Profile.objects.create(user=plain, company=self.company)
        self.client.force_login(plain)
        response = self.client.post(reverse('front:rule_validate'), {'yara_rule': DNI_RULE})
        self.assertEqual(response.status_code, 403)


class RuleFormObfuscateTests(TestCase):
    def setUp(self):
        cache.clear()
        company = Company.objects.create(name='Tenant')
        self.user = User.objects.create_user('analyst', is_staff=True)
        Profile.objects.create(user=self.user, company=company)
        self.group = RulesGroup.objects.create(name='G', company=company)
        self.rule = Rule.objects.create(name='DNI', rules_group=self.group, yara_rule=DNI_RULE,
                                        action='obfuscate', obfuscate_token='[DNI_{n}]')
        self.client.force_login(self.user)

    def form_data(self, **overrides):
        data = {
            'name': 'DNI', 'yara_rule': DNI_RULE, 'rules_group': self.group.pk,
            'severity': 'high', 'applies_to': 'both', 'action': 'obfuscate',
            'obfuscate_token': '[DNI_{n}]', 'active': 'on',
        }
        data.update(overrides)
        return data

    def test_edit_form_offers_and_keeps_obfuscate_action(self):
        response = self.client.get(reverse('front:rule_edit', args=[self.rule.pk]))
        self.assertContains(response, 'value="obfuscate" selected')

        response = self.client.post(reverse('front:rule_edit', args=[self.rule.pk]),
                                    self.form_data(obfuscate_token='<DNI-{n}>'))
        self.assertEqual(response.status_code, 302)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.action, 'obfuscate')
        self.assertEqual(self.rule.obfuscate_token, '<DNI-{n}>')

    def test_invalid_token_and_action_rejected(self):
        url = reverse('front:rule_edit', args=[self.rule.pk])
        for overrides in ({'obfuscate_token': '[DNI]'}, {'obfuscate_token': '[{foo}_{n}]'}, {'action': 'nope'}):
            with self.subTest(**overrides):
                response = self.client.post(url, self.form_data(**overrides))
                self.assertEqual(response.status_code, 200)
                self.rule.refresh_from_db()
                self.assertEqual(self.rule.action, 'obfuscate')
                self.assertEqual(self.rule.obfuscate_token, '[DNI_{n}]')


class ChatShowsObfuscationTests(SeededRulesTestCase):
    def test_conversation_page_shows_original_and_masked_text(self):
        from .models import Message
        conversation = Conversation.objects.create(user=self.user)
        conversation.set_obfuscation_context({'[IP_1]': '8.8.8.8'})
        conversation.save()
        Message.objects.create(conversation=conversation, role='user', content='mi ip es [IP_1]',
                               is_obfuscated=True, obfuscated_entities=['IP'])
        self.client.force_login(self.user)

        response = self.client.get(reverse('front:chat_conversation', args=[conversation.id]))

        self.assertContains(response, '<div class="content-original">mi ip es 8.8.8.8</div>', html=True)
        self.assertContains(response, 'mi ip es [IP_1]')
        self.assertContains(response, 'Sent to AI')
