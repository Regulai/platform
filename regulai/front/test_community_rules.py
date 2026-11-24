"""Community rules: recommended action from YARA meta, sync resilience and configure."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from .models import Company, Profile, Rule, RulesGroup
from .views import parse_yara_file

CONSENT_RULE = '''rule Confidential_Marking : confidentiality
{
    meta:
        description = "Marked as confidential"
        severity = "medium"
        action = "consent"
    strings:
        $a = "strictly confidential" nocase
    condition:
        $a
}
'''

NO_ACTION_RULE = '''rule Private_Key
{
    meta:
        description = "Private key"
        severity = "CRITICAL"
    strings:
        $a = "-----BEGIN PRIVATE KEY-----"
    condition:
        $a
}
'''

BAD_META_RULE = '''rule Weird_Meta
{
    meta:
        severity = "urgent"
        action = "nuke"
    strings:
        $a = "x"
    condition:
        $a
}
'''

BROKEN_RULE = '''rule Broken_One
{
    strings:
        $a = "x"
        $b = "y"
    condition:
        $a
}
'''


class ParseYaraFileTests(TestCase):
    def test_reads_action_and_normalizes_severity(self):
        rules = {r['name']: r for r in parse_yara_file(CONSENT_RULE + NO_ACTION_RULE + BAD_META_RULE, 'f')}
        self.assertEqual(rules['Confidential_Marking']['action'], 'consent')
        self.assertEqual(rules['Private_Key']['action'], 'block')
        self.assertEqual(rules['Private_Key']['severity'], 'critical')
        self.assertEqual(rules['Weird_Meta']['action'], 'block')
        self.assertEqual(rules['Weird_Meta']['severity'], 'medium')


def fake_github(files):
    """files: {name: content}. Returns a requests.get replacement."""
    def get(url, timeout=None):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        if url.endswith('/contents'):
            response.json.return_value = [
                {'type': 'file', 'name': name, 'download_url': f'https://raw.test/{name}'} for name in files
            ]
        else:
            response.text = files[url.rsplit('/', 1)[1]]
        return response
    return get


class CommunitySyncTests(TestCase):
    def setUp(self):
        cache.clear()
        company = Company.objects.create(name='Tenant')
        self.admin = User.objects.create_superuser('root', 'root@test.local', 'x')
        Profile.objects.create(user=self.admin, company=company)
        self.client.force_login(self.admin)

    def sync(self, files):
        with mock.patch('front.views.requests.get', side_effect=fake_github(files)):
            response = self.client.post(reverse('front:rules_community_sync'))
        return json.loads(response.content)

    def community_rule(self, name):
        return Rule.objects.get(rules_group__company__isnull=True, rules_group__user__isnull=True, name=name)

    def test_sync_stores_action_and_skips_rules_that_do_not_compile(self):
        data = self.sync({'Markings': CONSENT_RULE, 'Mixed': NO_ACTION_RULE + BROKEN_RULE})

        self.assertTrue(data['success'])
        self.assertEqual(data['rules_added'], 2)
        self.assertEqual(self.community_rule('Confidential_Marking').action, 'consent')
        self.assertEqual(self.community_rule('Private_Key').action, 'block')
        self.assertFalse(Rule.objects.filter(name='Broken_One').exists())
        self.assertTrue(any('Broken_One' in e for e in data['errors']))

    def test_resync_updates_when_only_action_changes(self):
        self.sync({'Markings': CONSENT_RULE})
        data = self.sync({'Markings': CONSENT_RULE.replace('action = "consent"', 'action = "block"')})

        self.assertEqual(data['rules_updated'], 1)
        self.assertEqual(self.community_rule('Confidential_Marking').action, 'block')

        data = self.sync({'Markings': CONSENT_RULE.replace('action = "consent"', 'action = "block"')})
        self.assertEqual(data['rules_skipped'], 1)


class CommunityConfigureTests(TestCase):
    def setUp(self):
        cache.clear()
        self.company = Company.objects.create(name='Tenant')
        self.user = User.objects.create_user('analyst', is_staff=True)
        Profile.objects.create(user=self.user, company=self.company)
        group = RulesGroup.objects.create(name='Community')
        self.community_rule = Rule.objects.create(
            name='Confidential_Marking', rules_group=group, yara_rule=CONSENT_RULE,
            severity='medium', action='consent',
        )
        self.client.force_login(self.user)

    def test_configure_copies_recommended_action_inactive(self):
        response = self.client.post(reverse('front:rule_community_configure', args=[self.community_rule.pk]))

        self.assertTrue(json.loads(response.content)['success'])
        copy = Rule.objects.get(rules_group__company=self.company, name='Confidential_Marking')
        self.assertEqual(copy.action, 'consent')
        self.assertFalse(copy.active)
