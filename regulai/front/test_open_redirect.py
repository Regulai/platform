"""State-changing views honour ?next= only for same-host URLs."""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .models import Alert, Company, Profile, Rule, RulesGroup

MALICIOUS_NEXT = ('//evil.example', 'https://evil.example/x', '/\\evil.example', 'javascript:alert(1)')


class OpenRedirectTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('analyst', is_staff=True)
        company = Company.objects.create(name='Tenant')
        Profile.objects.create(user=self.user, company=company)
        self.group = RulesGroup.objects.create(name='Group', company=company)
        self.rule = Rule.objects.create(name='Rule', rules_group=self.group,
                                        yara_rule='rule r { condition: false }')
        self.alert = Alert.objects.create(company=company, rule=self.rule, severity='low', description='d')
        self.client.force_login(self.user)

    def endpoints(self):
        group_detail = reverse('front:rulesgroup_detail', args=[self.group.pk])
        return (
            (reverse('front:rulesgroup_activate_all', args=[self.group.pk]), group_detail),
            (reverse('front:rulesgroup_deactivate_all', args=[self.group.pk]), group_detail),
            (reverse('front:rule_toggle', args=[self.rule.pk]), reverse('front:rules_list')),
            (reverse('front:alert_resolve', args=[self.alert.pk]), reverse('front:alerts_list')),
            (reverse('front:alert_unresolve', args=[self.alert.pk]), reverse('front:alerts_list')),
        )

    def test_external_next_falls_back_to_default(self):
        for url, fallback in self.endpoints():
            for target in MALICIOUS_NEXT:
                with self.subTest(url=url, next=target):
                    response = self.client.post(url, {}, QUERY_STRING=f'next={target}')
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response['Location'], fallback)

    def test_local_next_is_kept(self):
        for url, _ in self.endpoints():
            with self.subTest(url=url):
                response = self.client.post(f'{url}?next=/alerts/?page=2')
                self.assertEqual(response['Location'], '/alerts/?page=2')

    def test_missing_next_uses_default(self):
        for url, fallback in self.endpoints():
            with self.subTest(url=url):
                self.assertEqual(self.client.post(url)['Location'], fallback)
